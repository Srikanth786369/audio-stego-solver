"""
SSTV (Slow Scan TV) analysis pipeline for Audio Stego Solver v3.1.

v3.1 rewrite: the previous version's VIS detection and "decoders" called
`multimon-ng -a SSTV` and `qsstv -r <wav> -o <dir>`. Neither works:
  - multimon-ng's demodulator list (verified via `multimon-ng` with no args)
    is POCSAG/FLEX/EAS/AFSK/FSK9600/DTMF/ZVEI/EEA/EIA/CCIR/MORSE_CW/X10/SCOPE
    — there has never been an SSTV demodulator in multimon-ng.
  - qsstv's own man page SYNOPSIS is just `qsstv` — it takes no command-line
    arguments at all and is a GUI application that captures live audio from
    a soundcard; there is no headless/batch decode mode to invoke.
Both calls would have silently failed (or hung waiting for a GUI) in
production. This rewrite replaces them with:
  1. A real Goertzel-based VIS (Vertical Interval Signalling) code detector,
     implemented and round-trip tested against synthesized VIS tone
     sequences — this identifies the SSTV mode from genuine signal analysis
     instead of a non-existent external demodulator.
  2. Honest handling of qsstv/multimon-ng: reported as unusable for headless
     batch decoding rather than silently invoked.
  3. rx_sstv kept as a best-effort external decoder (gated on tool
     availability; its exact CLI contract could not be verified against a
     real binary in this environment, so failures are logged, not assumed).

Full pixel-level image reconstruction from the audio (actually rendering the
picture) is NOT implemented in this pass — every documented SSTV mode has
its own scanline/color-encoding scheme, and shipping a per-mode decoder
without reference test vectors to verify against would risk exactly the
"confidently wrong" output this project is trying to eliminate. VIS/mode
identification is real and tested; see CHANGELOG for what's still open.
"""

from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .artifact_store import ArtifactStore
from .findings import Finding, Severity, cap_severity
from .logger import get_logger
from .utils import run_command, save_text, tool_available
from . import sstv_decode

logger = get_logger("audio_stego.sstv")

# SSTV VIS codes -> mode names.
#
# v4.5.2: CRITICAL FIX — Robot 72 was wired to VIS 0x44, which is not a real
# SSTV VIS code at all. Cross-checked against two independent, real
# open-source SSTV codec implementations that agree exactly with each
# other: windytan/slowrx's modespec.c VISmap table (Robot Color 72 at
# index 0x0C) and rimio/libsstv's mode enum (SSTV_MODE_ROBOT_C72 = 12,
# i.e. 0x0C once the parity bit in bit 7 is masked off). Both sources also
# independently confirm every other code already in this table (Martin
# M1/M2, Scottie S1/S2/DX all match exactly) and PD90/PD120 (also
# unaffected), which is what surfaced that PD240 and PD290 were *also*
# wrong — transposed with the unwired PD160/PD180 — while investigating
# Robot 72. All four are corrected together, and PD50/PD160/PD180 are now
# wired for the first time using the same doubly-verified codes.
VIS_CODES: Dict[int, str] = {
    0x0C: "Robot 72",
    0x28: "Martin M2",
    0x2C: "Martin M1",
    0x38: "Scottie S2",
    0x3C: "Scottie S1",
    0x4C: "Scottie DX",
    0x5D: "PD50",
    0x5E: "PD290",
    0x5F: "PD120",
    0x60: "PD180",
    0x61: "PD240",
    0x62: "PD160",
    0x63: "PD90",
    0x37: "Wraase SC-2 180",
    0x3F: "Wraase SC-2 120",
    0x71: "Pasokon P3",
    0x72: "Pasokon P5",
    0x73: "Pasokon P7",
    0x02: "Robot 8 B/W",
}

# VIS timing (seconds), per the SSTV VIS specification
_LEADER_S = 0.300
_BREAK_S = 0.010
_START_BIT_S = 0.030
_DATA_BIT_S = 0.030
_LEADER_HZ = 1900.0
_SYNC_HZ = 1200.0
_BIT0_HZ = 1300.0
_BIT1_HZ = 1100.0

# Total VIS preamble duration: leader + break + leader + start bit +
# 7 data bits + 1 parity bit + stop bit. This is where the real image
# content (first line sync) begins, and where the custom decoder
# (sstv_decode.py) is anchored from.
_VIS_PREAMBLE_DURATION_S = 2 * _LEADER_S + _BREAK_S + _START_BIT_S + 8 * _DATA_BIT_S + _START_BIT_S


@dataclass
class VISDetection:
    found: bool
    vis_code: Optional[int] = None
    mode: Optional[str] = None
    confidence: float = 0.0
    reason: str = ""
    start_time_s: float = 0.0
    parity_ok: bool = False


def _goertzel_power_batch(frames: "Any", sr: int, freqs: List[float]):
    """
    Vectorized Goertzel-equivalent: for a 2D array of (n_windows, win_len)
    sample frames, compute the power at each target frequency for every
    window in one matrix multiply instead of a per-sample Python loop.
    """
    import numpy as np
    win_len = frames.shape[1]
    n = np.arange(win_len)
    # basis: (n_freqs, win_len) complex exponentials
    basis = np.exp(-2j * np.pi * np.outer(freqs, n) / sr)
    # (n_windows, win_len) @ (win_len, n_freqs) -> (n_windows, n_freqs)
    coeffs = frames @ basis.T
    return (np.abs(coeffs) ** 2) / (win_len ** 2)


def detect_vis_code(samples, sr: int, window_s: float = 0.010) -> VISDetection:
    """
    Real VIS detector: classifies short windows across the whole signal by
    dominant tone among {1900 (leader), 1200 (sync/break/start/stop), 1300
    (bit=0), 1100 (bit=1)}, then searches the resulting tone sequence for the
    VIS preamble (leader / break / leader / start bit / 8 data bits with
    parity / stop bit) and decodes the 7-bit code + parity check.
    """
    import numpy as np

    win_len = max(int(sr * window_s), 8)
    n_windows = len(samples) // win_len
    if n_windows < 20:
        return VISDetection(False, reason="Audio too short for VIS analysis")

    frames = samples[:n_windows * win_len].reshape(n_windows, win_len).astype(np.float64)
    freqs = [_LEADER_HZ, _SYNC_HZ, _BIT0_HZ, _BIT1_HZ]
    powers = _goertzel_power_batch(frames, sr, freqs)   # (n_windows, 4)

    # Classify each window by whichever of the 4 tones has the most power,
    # but require it to actually dominate the window's total energy —
    # silence/noise/music should not be forced into one of the 4 buckets.
    #
    # Regression: running the full pipeline against a real MP3 (not a
    # synthetic test signal) in this repo produced a spurious "VIS detected"
    # at 80% confidence from ordinary music. A real, single-tone VIS window
    # (verified against the round-trip test encoder) has a Goertzel-power /
    # total-energy ratio of a very consistent ~0.50 clean, dropping only to
    # ~0.28-0.40 even under a severe 3-6dB SNR — the previous 0.15 threshold
    # left more than 2x headroom below every real measurement, wide enough
    # for broadband music (which routinely puts >15% of a 10ms window's
    # energy near any one of these four specific frequencies just from
    # ordinary harmonic/vocal content) to be misclassified as a VIS tone.
    # Raised to 0.30 — still comfortably below the worst real-signal
    # measurement at 6dB SNR (0.365 minimum observed).
    total_energy = np.sum(frames.astype(np.float64) ** 2, axis=1) / win_len
    best = np.argmax(powers, axis=1)
    best_power = powers[np.arange(n_windows), best]
    dominant = best_power > np.maximum(total_energy * 0.30, 1e-12)
    labels = np.where(dominant, np.array(["L", "S", "0", "1"])[best], "?")

    win_s = win_len / sr
    windows_per = lambda seconds: max(1, round(seconds / win_s))
    leader_wins = windows_per(_LEADER_S)
    break_wins = max(1, windows_per(_BREAK_S))
    start_wins = windows_per(_START_BIT_S)
    bit_wins = windows_per(_DATA_BIT_S)

    def _run_matches(start: int, length: int, label: str, min_frac: float = 0.7) -> bool:
        if start < 0 or start + length > n_windows:
            return False
        seg = labels[start:start + length]
        return (seg == label).mean() >= min_frac

    # Search for: leader run -> break -> leader run -> start bit
    # Tolerant of a few windows of slop by scanning candidate leader starts.
    min_leader = max(3, int(leader_wins * 0.6))
    i = 0
    while i < n_windows - (2 * min_leader + break_wins + start_wins + 9 * bit_wins):
        if labels[i] == "L":
            run_len = 0
            j = i
            while j < n_windows and labels[j] == "L":
                run_len += 1
                j += 1
            if run_len >= min_leader:
                # Expect: break, second leader, start bit, then 8 data bits + parity + stop
                pos = j
                if _run_matches(pos, break_wins, "S", 0.5):
                    pos2 = pos + break_wins
                    k = pos2
                    run2 = 0
                    while k < n_windows and labels[k] == "L":
                        run2 += 1
                        k += 1
                    if run2 >= min_leader and _run_matches(k, start_wins, "S", 0.5):
                        bits_start = k + start_wins
                        bits = []
                        ok = True
                        pos3 = bits_start
                        for _ in range(8):   # 7 data bits + 1 parity bit
                            seg = labels[pos3:pos3 + bit_wins]
                            ones = int((seg == "1").sum())
                            zeros = int((seg == "0").sum())
                            # Regression: a single classified window used to
                            # be enough to decide an entire bit period even
                            # when the other windows in that period were
                            # unclassified ("?") — e.g. 1 window "1" + 2
                            # windows "?" counted as a clean bit=1. Found via
                            # a real MP3 spuriously matching a full VIS
                            # preamble at 80% confidence. Now requires the
                            # winning label to actually cover a majority of
                            # the bit period, the same standard already
                            # applied to leader/break/start-bit runs.
                            if max(ones, zeros) / bit_wins < 0.5:
                                ok = False
                                break
                            bits.append(1 if ones >= zeros else 0)
                            pos3 += bit_wins
                        if ok:
                            data_bits = bits[:7]
                            parity_bit = bits[7]
                            code = 0
                            for idx, b in enumerate(data_bits):
                                code |= (b << idx)   # LSB-first per VIS spec
                            expected_parity = sum(data_bits) % 2
                            parity_ok = (expected_parity == parity_bit)
                            mode = VIS_CODES.get(code)
                            # Regression: an *unrecognized* VIS code (not one
                            # of the ~10 real, standardized codes this
                            # project's VIS_CODES table knows) previously
                            # still got up to 0.80 confidence just from
                            # parity matching — but parity is a single bit,
                            # a coincidental match has a 50% chance on its
                            # own, and an unrecognized code can never be
                            # decoded into an image anyway (no actionable
                            # follow-through). Running the full pipeline
                            # against real MP3 music (not synthetic test
                            # signals) found this exact case twice — two
                            # different unrecognized codes, both with
                            # matching parity, both reported at 80%
                            # confidence/HIGH severity despite producing no
                            # image. A recognized code keeps the original,
                            # unchanged confidence scale; an unrecognized one
                            # is capped well below the report's "verified"
                            # tier threshold.
                            if mode is not None:
                                confidence = 0.55 + (0.25 if parity_ok else 0.0) + 0.10
                            else:
                                confidence = 0.20 + (0.15 if parity_ok else 0.0)
                            return VISDetection(
                                True, vis_code=code, mode=mode or f"Unknown (VIS 0x{code:02X})",
                                confidence=min(confidence, 0.90),
                                reason=(f"VIS decoded: code=0x{code:02X}, parity "
                                        f"{'OK' if parity_ok else 'MISMATCH'}"),
                                start_time_s=round(i * win_s, 3),
                                parity_ok=parity_ok,
                            )
            i = j
        else:
            i += 1

    return VISDetection(False, reason="No VIS leader/preamble pattern found")


class SSTVAnalyzer:
    """SSTV VIS/mode detection pipeline (see module docstring for scope)."""

    def __init__(self, store: ArtifactStore, config):
        self.store  = store
        self.config = config
        self._samples = None
        self._sr = 0
        self._detection: Optional[VISDetection] = None
        self.results: Dict[str, Any] = {
            "vis_detected":  False,
            "vis_code":      None,
            "mode":          None,
            "decoded_image": None,
            "decoded_bw_image": None,
            "decoder_selected": None,
            "postprocess_steps": [],
            "sstv_variant_selected": None,
            "sstv_variant_scores": {},
            "sstv_image_quality_scores": {},
            "decoded_image_upscaled": None,
            "decoded_image_dimensions": None,
            "raw_image":     None,
            "image_metadata": None,
            "ocr_text":      None,
            "qr_data":       None,
            "barcode_type":  None,
            "markers":       [],
            "confidence":    0.0,
            "decoders_tried": [],
            "validation":    None,
            "rejected":      False,
            "rejected_reasons": [],
            "findings":      [],
            "warnings":      [],
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audio_path: str, wav_path: Optional[str] = None) -> Dict[str, Any]:
        logger.info(f"SSTV analysis: {audio_path}")
        wav = wav_path or audio_path
        _start = time.monotonic()

        self._detect_vis_real(wav)

        # Decoder priority: try every decoder that's actually available/
        # applicable (rx_sstv external tool, then the custom FM-scanline
        # decoder — qsstv/multimon-ng cannot participate, see
        # _note_gui_only_tools for why), then keep whichever candidate has
        # the highest *validated* confidence instead of a first-match-wins
        # policy. Either decoder alone can produce a plausible-looking but
        # wrong image; comparing when both ran is strictly more accurate
        # than trusting a fixed priority order.
        candidates: List[Tuple[str, str, float]] = []  # (source, path, confidence)

        rx_result = self._try_rx_sstv(wav)
        if rx_result:
            candidates.append(("rx_sstv", rx_result[0], rx_result[1]))

        custom_result = self._try_custom_decoder()
        if custom_result:
            candidates.append(("custom_decoder", custom_result[0], custom_result[1]))

        self._note_gui_only_tools()

        if candidates:
            self._select_best_decode(candidates)

        if self.results["decoded_image"] and os.path.exists(self.results["decoded_image"]):
            self._postprocess_image(self.results["decoded_image"])
            self._analyze_decoded_image(self.results["decoded_image"])
            self._detect_markers(self.results["decoded_image"])

        self.results["decode_time_s"] = round(time.monotonic() - _start, 2)
        self._write_report(audio_path)
        return self.results

    def _select_best_decode(self, candidates: List[Tuple[str, str, float]]):
        """Pick the highest-confidence decode among every decoder that
        actually produced one, and record the choice/finding for it. Never
        double-reports: only the winner gets a "SSTV Image Decoded" finding."""
        source, path, confidence = max(candidates, key=lambda c: c[2])
        self.results["decoded_image"] = path
        self.results["confidence"] = max(self.results["confidence"], confidence)
        self.results["decoder_selected"] = source
        mode = self.results.get("mode") or "Unknown"

        if len(candidates) > 1:
            others = ", ".join(f"{s} ({c:.0%})" for s, _, c in candidates if s != source)
            logger.info(f"SSTV: multiple decoders succeeded — selected {source} "
                        f"({confidence:.0%}) over {others}")
            self.results["warnings"].append(
                f"Multiple SSTV decoders produced an image; selected {source} "
                f"(confidence {confidence:.0%}) as the higher-confidence result over {others}"
            )
        else:
            logger.info(f"SSTV decoded via {source} (confidence={confidence:.0%})")

        # Only the winning candidate gets a "SSTV Image Decoded" finding —
        # appended here (not inside each decoder method) so a decoder that
        # succeeded but lost the comparison never leaves a stale finding
        # pointing at an image that isn't the one actually in the report.
        if source == "custom_decoder":
            validation_metrics = self.results.get("validation") or {}
            self.results["findings"].append(Finding(
                module="sstv",
                title=f"SSTV Image Decoded — {mode}",
                severity=cap_severity(Severity.HIGH, confidence),
                confidence=confidence,
                value=mode,
                evidence=(
                    f"sync_regularity={validation_metrics.get('sync_regularity', 0):.2f}, "
                    f"entropy={validation_metrics.get('entropy_bits', 0):.2f} bits, "
                    f"line_continuity={validation_metrics.get('line_continuity', 0):.2f}"
                ),
                reason="Custom FM-scanline decoder output passed independent structural "
                       "validation (dimensions, sync timing, entropy, continuity, saturation)",
                false_positive_risk="Low — validated on multiple independent signal metrics",
            ).to_dict())
        elif source == "rx_sstv":
            self.results["findings"].append(Finding(
                module="sstv",
                title=f"SSTV Image Decoded — {mode} (rx_sstv)",
                severity=cap_severity(Severity.HIGH, confidence),
                confidence=confidence,
                value=mode,
                evidence=f"rx_sstv exited 0 and produced an image file: {os.path.basename(path)}",
                reason="External rx_sstv decoder produced an image; not independently "
                       "structure-validated the way the custom decoder's output is "
                       "(no sync/entropy/continuity metrics available for a third-party tool's output)",
                false_positive_risk="Medium — rx_sstv's own decode correctness could not be "
                                     "independently verified in this environment",
            ).to_dict())

    # ------------------------------------------------------------------
    # Real VIS detection (replaces the non-functional multimon-ng call)
    # ------------------------------------------------------------------

    def _load_samples(self, wav_path: str):
        import numpy as np
        try:
            import soundfile as sf
            data, sr = sf.read(wav_path, always_2d=False)
            if data.ndim > 1:
                data = data[:, 0]
            return data.astype(np.float64), sr
        except Exception:
            pass
        try:
            import wave
            with wave.open(wav_path, "rb") as wf:
                sr = wf.getframerate()
                n_ch = wf.getnchannels()
                sw = wf.getsampwidth()
                raw = wf.readframes(wf.getnframes())
            dtype = {1: np.int8, 2: np.int16, 4: np.int32}.get(sw, np.int16)
            samples = np.frombuffer(raw, dtype=dtype).astype(np.float64)
            if n_ch > 1:
                samples = samples.reshape(-1, n_ch)[:, 0]
            if sw:
                samples /= (2 ** (sw * 8 - 1))
            return samples, sr
        except Exception as e:
            self.results["warnings"].append(f"Could not load audio for VIS analysis: {e}")
            return None, 0

    def _detect_vis_real(self, wav_path: str):
        try:
            import numpy as np  # noqa: F401
        except ImportError:
            self.results["warnings"].append("numpy not installed — VIS detection skipped")
            return

        samples, sr = self._load_samples(wav_path)
        if samples is None or sr == 0:
            return
        self._samples = samples
        self._sr = sr

        detection = detect_vis_code(samples, sr)
        self._detection = detection
        save_text(str(self.store.tools / "sstv_vis_detection.txt"),
            f"=== VIS DETECTION ===\nFound: {detection.found}\n"
            f"VIS code: {detection.vis_code}\nMode: {detection.mode}\n"
            f"Confidence: {detection.confidence:.0%}\nReason: {detection.reason}\n"
        )

        if detection.found:
            self.results["vis_detected"] = True
            self.results["vis_code"] = detection.vis_code
            self.results["mode"] = detection.mode
            self.results["confidence"] = max(self.results["confidence"], detection.confidence)
            logger.info(f"SSTV VIS detected: mode={detection.mode} (0x{detection.vis_code:02X})")

            self.results["findings"].append(Finding(
                module="sstv",
                title=f"SSTV VIS Code Detected — {detection.mode}",
                severity=Severity.HIGH if detection.confidence >= 0.70 else Severity.MEDIUM,
                confidence=detection.confidence,
                value=f"VIS 0x{detection.vis_code:02X} ({detection.mode})",
                evidence=detection.reason,
                reason="Decoded via Goertzel-based tone classification against the real "
                       "VIS timing spec (leader/break/leader/start-bit/7 data bits/parity/stop)",
                false_positive_risk="Low if parity matched; medium otherwise",
            ).to_dict())
        else:
            logger.info(f"SSTV VIS: {detection.reason}")

    # ------------------------------------------------------------------
    # Decoder: rx_sstv (best effort — CLI contract unverified in this env)
    # ------------------------------------------------------------------

    def _try_rx_sstv(self, wav_path: str) -> Optional[Tuple[str, float]]:
        """Returns (image_path, confidence) if rx_sstv produced an image,
        else None. Does not set self.results directly — the caller compares
        this against every other decoder's candidate and picks the best."""
        if not tool_available("rx_sstv"):
            return None

        out_dir = str(self.store.sstv_dir)
        rc, out, err = run_command(["rx_sstv", wav_path, out_dir], timeout=self.config.timeout * 3)
        self.results["decoders_tried"].append("rx_sstv")
        save_text(str(self.store.tools / "sstv_rx_sstv.txt"),
                  f"rx_sstv\n{'='*60}\nrc={rc}\n{out}\nSTDERR:\n{err}")

        if rc != 0:
            self.results["warnings"].append(f"rx_sstv exited {rc} — decode not confirmed: {err[:200]}")
            return None

        try:
            images = [f for f in os.listdir(out_dir) if f.lower().endswith((".png", ".jpg", ".bmp", ".ppm"))]
        except OSError:
            images = []
        if images:
            dest = str(self.store.sstv_dir / images[0])
            logger.info(f"rx_sstv produced image: {dest}")
            confidence = self._rx_sstv_confidence(dest)
            return dest, confidence
        else:
            self.results["warnings"].append("rx_sstv exited 0 but produced no image file")
            return None

    def _rx_sstv_confidence(self, image_path: str) -> float:
        """
        Confidence for an rx_sstv output, derived from objective image
        properties instead of a fixed guess.

        Previously this was a hardcoded 0.70 regardless of what rx_sstv
        actually produced. Since _select_best_decode picks the candidate
        with the *higher* confidence, a fixed placeholder meant a garbled
        rx_sstv image could out-rank a genuinely well-validated
        custom_decoder result whenever the custom decoder's real,
        evidence-based confidence happened to be below 0.70 (its floor is
        0.55) — "confidence" was not comparable evidence on both sides of
        that comparison.

        A first attempt at this fix used only _pp_quality_score's sharpness
        (Laplacian variance) + contrast + entropy — but verified directly
        against a synthetic pure-noise image, that scored *higher* than a
        real coherent gradient image (raw score 98.4, tanh-normalized to a
        saturated 1.000, vs a real image's 2.3-2.4 / ~0.52), because random
        noise is by construction high-frequency and high-entropy, which is
        exactly what that metric rewards. It was designed to compare
        processing variants of an *already-confirmed-real* decoded image,
        not to distinguish a real image from garbage in the first place —
        that distinction is what the custom decoder's validate_decoded_image
        gets from independent sync/structural checks rx_sstv's output has no
        equivalent for. Multiplying in the same pixel-to-pixel smoothness
        signal used there (real image 0.998 vs pure noise 0.560, verified
        directly) as smoothness**4 — a continuous penalty rather than a hard
        cutoff, since a real image degraded by ordinary noise should lose
        confidence gradually, not fall off a cliff — fixes this: pure noise
        (0.560**4 ≈ 0.10) is now pulled down to ~0.36 despite its inflated
        sharpness score, while real coherent images (0.998**4 ≈ 0.99) are
        barely affected.
        """
        try:
            from PIL import Image as ImageModule
        except ImportError:
            return 0.70
        try:
            import numpy as np
        except ImportError:
            return 0.70
        try:
            import cv2
        except ImportError:
            cv2 = None

        try:
            img = ImageModule.open(image_path).convert("RGB")
        except Exception:
            return 0.70

        gray = np.array(img.convert("L"), dtype=np.float64)
        if gray.shape[1] >= 2:
            col_diffs = np.abs(np.diff(gray, axis=1))
            pixel_smoothness = float(1.0 - np.clip(col_diffs.mean() / 128.0, 0, 1))
        else:
            pixel_smoothness = 1.0

        score = self._pp_quality_score(img, np, cv2)
        # tanh squashes the unbounded quality score into a smooth [0, 1)
        # curve; 4.0 is the empirical midpoint (a typical well-exposed,
        # reasonably sharp photo scores roughly in the 2-6 range on this
        # metric — see _pp_quality_score's own normalization comment).
        normalized = math.tanh(score / 4.0) * (pixel_smoothness ** 4)
        return float(max(0.30, min(0.90, 0.30 + 0.60 * normalized)))

    def _note_gui_only_tools(self):
        """qsstv is GUI-only (verified: its man page SYNOPSIS takes no
        arguments) and multimon-ng has no SSTV demodulator (verified: its
        own --help demodulator list does not include SSTV). PySSTV (PyPI)
        is a real, importable Python package but is encode-only — it has no
        audio-to-image decode function at all, so it was never a viable
        decoder candidate despite being on the original priority list.
        Report all three honestly instead of pretending to invoke them."""
        if tool_available("qsstv"):
            self.results["warnings"].append(
                "qsstv is installed but is a GUI-only application with no batch/CLI "
                "decode mode — cannot be used in this headless pipeline")
        if tool_available("multimon-ng"):
            self.results["warnings"].append(
                "multimon-ng is installed but has no SSTV demodulator — "
                "VIS detection is performed by this tool's own Goertzel-based analysis instead")
        try:
            import pysstv  # noqa: F401
            self.results["warnings"].append(
                "pysstv is installed but is encode-only (image -> audio) — it cannot "
                "decode audio to an image, so it is not used as a decoder")
        except ImportError:
            pass

    # ------------------------------------------------------------------
    # Custom decoder (v4.1) — primary, always-available decode path.
    # See audio_stego/sstv_decode.py for the full algorithm and the honest
    # accounting of which modes are auto-dispatched here vs. implemented
    # but pending a verified VIS code.
    # ------------------------------------------------------------------

    def _try_custom_decoder(self) -> Optional[Tuple[str, float]]:
        """Returns (image_path, confidence) if the decode passed independent
        validation, else None (including the rejected case — a rejection is
        still recorded as its own Finding here, but is never a candidate for
        "the decoded image"). Does not set self.results["decoded_image"]
        directly — see _select_best_decode."""
        mode = self.results.get("mode")
        if not mode or mode not in sstv_decode.MODES:
            if mode:
                self.results["warnings"].append(
                    f"Mode '{mode}' has no custom decoder wired to this VIS code yet "
                    f"(see sstv_decode.py module docstring) — image not decoded"
                )
            return None
        if self._samples is None or self._sr == 0 or self._detection is None:
            return None

        self.results["decoders_tried"].append("custom_decoder")
        spec = sstv_decode.MODES[mode]
        vis_end_sample = int(round(
            (self._detection.start_time_s + _VIS_PREAMBLE_DURATION_S) * self._sr
        ))

        try:
            image, sync_positions, _freq = sstv_decode.decode_image(
                self._samples, self._sr, mode, vis_end_sample
            )
        except sstv_decode.SSTVDecodeError as e:
            self.results["warnings"].append(f"Custom SSTV decoder failed for {mode}: {e}")
            return None
        except Exception as e:
            logger.exception("Unexpected error in custom SSTV decoder")
            self.results["warnings"].append(f"Custom SSTV decoder raised an unexpected error: {e}")
            return None

        validation = sstv_decode.validate_decoded_image(
            image, spec, sync_positions, self._sr, vis_parity_ok=self._detection.parity_ok
        )
        self.results["validation"] = validation.metrics

        raw_path = str(self.store.sstv_debug / "raw.png")
        try:
            from PIL import Image
            Image.fromarray(image).save(raw_path)
            self.results["raw_image"] = raw_path
        except Exception as e:
            self.results["warnings"].append(f"Could not save raw SSTV decode: {e}")

        if not validation.accepted:
            self.results["rejected"] = True
            self.results["rejected_reasons"] = validation.reasons
            logger.info(f"SSTV decode for {mode} REJECTED: {'; '.join(validation.reasons)}")
            self.results["findings"].append(Finding(
                module="sstv",
                title=f"Rejected SSTV — {mode}",
                severity=Severity.INFO,
                confidence=0.0,
                value=mode,
                evidence="; ".join(validation.reasons),
                reason="Decoded image failed independent validation (sync regularity, "
                       "pixel entropy, line-to-line continuity, saturation, or VIS parity)",
                false_positive_risk="N/A — rejected, not reported as a finding of substance",
                tags=["rejected"],
            ).to_dict())
            return None

        decoded_path = str(self.store.sstv_dir / "decoded.png")
        try:
            from PIL import Image
            Image.fromarray(image).save(decoded_path)
        except Exception as e:
            self.results["warnings"].append(f"Could not save decoded SSTV image: {e}")
            return None

        logger.info(f"SSTV decoded and validated: {mode} (confidence={validation.confidence:.0%})")
        # The "SSTV Image Decoded" Finding is appended by _select_best_decode
        # only if this candidate is actually chosen — see there for why.
        return decoded_path, validation.confidence

    # ------------------------------------------------------------------
    # Post-processing (v4.1/v4.2): a real enhancement pipeline run on the
    # accepted image before OCR/QR/marker detection — auto-crop, denoise,
    # gamma correction, color balance, contrast/histogram equalization,
    # sharpening, then adaptive threshold + morphological cleanup for the
    # separate black/white variant. OpenCV is used where it materially
    # improves a step (denoising, morphology) if installed; every step has
    # a pure PIL/numpy/scipy fallback and is individually try/excepted so a
    # missing optional dependency degrades that one step, never the scan.
    #
    # "Deskew" and "perspective correction" are deliberately NOT implemented
    # here, for the same reason in both cases: an SSTV image is reconstructed
    # scanline-by-scanline directly into an axis-aligned raster from audio
    # timing, not photographed or scanned — there is no camera geometry, lens
    # distortion, or physical rotation for either technique to correct.
    # Applying them anyway would silently warp a structurally-validated
    # decode based on a premise that doesn't hold for this data, which is
    # exactly the kind of fabricated processing this project avoids.
    # ------------------------------------------------------------------

    def _pp_autocrop(self, img, np):
        """Trim genuinely blank/near-uniform border rows and columns (left
        over from leading/trailing sync-pulse regions), without touching a
        real low-variance image content area. Returns (image, cropped_bool)."""
        arr = np.array(img.convert("L"))
        row_std = arr.std(axis=1)
        col_std = arr.std(axis=0)
        thresh = 3.0
        rows = np.where(row_std > thresh)[0]
        cols = np.where(col_std > thresh)[0]
        if rows.size == 0 or cols.size == 0:
            return img, False
        top, bottom = int(rows[0]), int(rows[-1])
        left, right = int(cols[0]), int(cols[-1])
        if top == 0 and left == 0 and bottom == arr.shape[0] - 1 and right == arr.shape[1] - 1:
            return img, False
        cropped = img.crop((left, top, right + 1, bottom + 1))
        # Guard against an over-aggressive crop swallowing most of the image
        # (e.g. a genuinely low-contrast but valid decode).
        if cropped.size[0] < img.size[0] * 0.5 or cropped.size[1] < img.size[1] * 0.5:
            return img, False
        return cropped, True

    def _pp_line_align(self, img, np):
        """Horizontal line alignment: SSTV audio timing drift can shift an
        individual scanline left/right by a few pixels relative to its
        neighbors ("row jitter"), unlike whole-image skew/perspective (which
        do not apply here — see the class docstring above). Cross-correlates
        each row against the previous (already-aligned) row and rolls it by
        whichever small shift maximizes agreement, which straightens jittery
        rows without assuming any global geometric distortion."""
        arr = np.array(img.convert("RGB")).astype(np.float64)
        gray = arr.mean(axis=2)
        h, w = gray.shape
        max_shift = min(4, w // 20 or 1)
        aligned = arr.copy()
        prev_row = gray[0]
        for y in range(1, h):
            row = gray[y]
            best_shift, best_score = 0, -np.inf
            for shift in range(-max_shift, max_shift + 1):
                shifted = np.roll(row, shift)
                score = -np.sum((shifted - prev_row) ** 2)
                if score > best_score:
                    best_score, best_shift = score, shift
            if best_shift != 0:
                aligned[y] = np.roll(aligned[y], best_shift, axis=0)
            prev_row = np.roll(row, best_shift) if best_shift else row
        from PIL import Image
        return Image.fromarray(np.clip(aligned, 0, 255).astype(np.uint8))

    def _pp_quality_score(self, img, np, cv2) -> float:
        """Objective, reference-free image-quality score used to pick the
        best of several processed variants: sharpness (variance of the
        Laplacian — a standard focus/blur metric) + contrast (pixel stddev)
        + entropy (information content), each normalized to a comparable
        0-1ish range and summed. Higher is better. Pure numpy fallback for
        the Laplacian when cv2 isn't installed."""
        gray = np.array(img.convert("L"), dtype=np.float64)
        if cv2 is not None:
            lap = cv2.Laplacian(gray, cv2.CV_64F)
        else:
            # 4-neighbor discrete Laplacian, equivalent kernel to cv2's default
            lap = (
                -4 * gray
                + np.roll(gray, 1, axis=0) + np.roll(gray, -1, axis=0)
                + np.roll(gray, 1, axis=1) + np.roll(gray, -1, axis=1)
            )
        sharpness = float(lap.var())
        contrast = float(gray.std())
        hist, _ = np.histogram(gray, bins=256, range=(0, 255), density=True)
        hist = hist[hist > 0]
        entropy = float(-(hist * np.log2(hist)).sum())

        # Empirical normalization constants (typical ranges for 8-bit
        # images) so no single term dominates the sum by scale alone.
        return (sharpness / 500.0) + (contrast / 64.0) + (entropy / 8.0)

    def _pp_clahe(self, img, np, cv2):
        """Contrast Limited Adaptive Histogram Equalization — operates on
        local tiles instead of the whole image (unlike the global
        ImageOps.equalize used elsewhere in this pipeline), which corrects
        uneven lighting/contrast across a frame that a single global
        histogram transform can't. cv2's real CLAHE when available; a
        genuine (if simpler) per-tile min-max stretch as the numpy-only
        fallback, not a no-op placeholder."""
        from PIL import Image as ImageModule
        if cv2 is not None:
            arr = np.array(img.convert("RGB"))
            lab = cv2.cvtColor(arr, cv2.COLOR_RGB2LAB)
            l_chan, a_chan, b_chan = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            l_chan = clahe.apply(l_chan)
            merged = cv2.merge((l_chan, a_chan, b_chan))
            rgb = cv2.cvtColor(merged, cv2.COLOR_LAB2RGB)
            return ImageModule.fromarray(rgb)

        arr = np.array(img.convert("RGB")).astype(np.float64)
        gray = arr.mean(axis=2)
        h, w = gray.shape
        tile = max(8, min(h, w) // 8)
        stretched = gray.copy()
        for y0 in range(0, h, tile):
            for x0 in range(0, w, tile):
                y1, x1 = min(y0 + tile, h), min(x0 + tile, w)
                block = gray[y0:y1, x0:x1]
                lo, hi = float(block.min()), float(block.max())
                if hi > lo:
                    stretched[y0:y1, x0:x1] = (block - lo) / (hi - lo) * 255.0
        ratio = np.divide(stretched, gray, out=np.ones_like(stretched), where=gray > 1e-6)
        arr = np.clip(arr * ratio[..., None], 0, 255)
        return ImageModule.fromarray(arr.astype(np.uint8))

    def _pp_bilateral(self, img, np, cv2):
        """Edge-preserving smoothing: unlike the median-filter/NLM denoise
        step, a bilateral filter only blends pixels that are both spatially
        close AND similar in value, so it smooths sensor/decode noise
        without blurring across real scanline edges the way a plain
        blur/median filter can. cv2's real bilateral filter when available;
        the numpy fallback is a genuine (if small-window) weighted-average
        bilateral implementation, vectorized across shifted copies of the
        image rather than a per-pixel Python loop."""
        from PIL import Image as ImageModule
        if cv2 is not None:
            arr = cv2.bilateralFilter(np.array(img.convert("RGB")), 5, 50, 50)
            return ImageModule.fromarray(arr)

        arr = np.array(img.convert("RGB")).astype(np.float64)
        radius, sigma_space, sigma_color = 2, 2.0, 30.0
        accum = np.zeros_like(arr)
        weight_sum = np.zeros(arr.shape[:2] + (1,))
        for dy in range(-radius, radius + 1):
            for dx in range(-radius, radius + 1):
                shifted = np.roll(np.roll(arr, dy, axis=0), dx, axis=1)
                spatial_w = math.exp(-(dy * dy + dx * dx) / (2 * sigma_space ** 2))
                diff = shifted - arr
                range_w = np.exp(-(diff ** 2).sum(axis=2, keepdims=True) / (2 * sigma_color ** 2))
                w = spatial_w * range_w
                accum += shifted * w
                weight_sum += w
        result = accum / np.clip(weight_sum, 1e-6, None)
        return ImageModule.fromarray(np.clip(result, 0, 255).astype(np.uint8))

    def _pp_apply_pipeline(self, img, np, cv2, *, denoise: bool, gamma: float,
                            color_balance: bool, line_align: bool, sharpen_amount: int,
                            use_bilateral: bool = False, use_clahe: bool = False):
        """Applies one recipe (a specific subset/strength of steps) to a
        starting image and returns (image, steps_applied). Multiple recipes
        run through this to produce the variants compared in
        _postprocess_image — see that method for the objective selection."""
        from PIL import Image as ImageModule, ImageOps, ImageFilter
        steps: List[str] = []

        if line_align and np is not None:
            try:
                img = self._pp_line_align(img, np)
                steps.append("line-align")
            except Exception as e:
                self.results["warnings"].append(f"SSTV line alignment failed: {e}")

        if use_bilateral and np is not None:
            try:
                img = self._pp_bilateral(img, np, cv2)
                steps.append("bilateral-filter")
            except Exception as e:
                self.results["warnings"].append(f"SSTV bilateral filter failed: {e}")
        elif denoise:
            try:
                if cv2 is not None and np is not None:
                    img = ImageModule.fromarray(
                        cv2.fastNlMeansDenoisingColored(np.array(img), None, 5, 5, 7, 21))
                else:
                    img = img.filter(ImageFilter.MedianFilter(size=3))
                steps.append("denoise")
            except Exception as e:
                self.results["warnings"].append(f"SSTV denoise failed: {e}")

        if gamma and gamma != 1.0:
            try:
                inv_gamma = 1.0 / gamma
                lut = [int((i / 255.0) ** inv_gamma * 255) for i in range(256)] * 3
                img = img.point(lut)
                steps.append("gamma-correction")
            except Exception as e:
                self.results["warnings"].append(f"SSTV gamma correction failed: {e}")

        if color_balance and np is not None:
            try:
                arr = np.array(img).astype(np.float64)
                means = arr.reshape(-1, 3).mean(axis=0)
                overall = means.mean()
                for c in range(3):
                    if means[c] > 1e-6:
                        arr[:, :, c] *= (overall / means[c])
                img = ImageModule.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
                steps.append("color-balance")
            except Exception as e:
                self.results["warnings"].append(f"SSTV color balance failed: {e}")

        if use_clahe and np is not None:
            try:
                img = self._pp_clahe(img, np, cv2)
                steps.append("clahe")
            except Exception as e:
                self.results["warnings"].append(f"SSTV CLAHE failed: {e}")
        else:
            try:
                img = ImageOps.autocontrast(img, cutoff=1)
                img = ImageOps.equalize(img)
                steps.append("contrast+histogram-eq")
            except Exception as e:
                self.results["warnings"].append(f"SSTV contrast/histogram enhancement failed: {e}")

        if sharpen_amount:
            try:
                # Adaptive sharpening: measure blur first (low Laplacian
                # variance = blurrier) and scale the unsharp-mask strength
                # up for blurrier input instead of a fixed amount for every
                # image — a already-sharp decode gets a lighter touch.
                amount = sharpen_amount
                if np is not None:
                    gray = np.array(img.convert("L"), dtype=np.float64)
                    lap_var = float((
                        -4 * gray + np.roll(gray, 1, 0) + np.roll(gray, -1, 0)
                        + np.roll(gray, 1, 1) + np.roll(gray, -1, 1)
                    ).var())
                    if lap_var < 50:
                        amount = min(150, int(sharpen_amount * 1.8))
                    elif lap_var > 300:
                        amount = max(20, int(sharpen_amount * 0.6))
                img = img.filter(ImageFilter.UnsharpMask(radius=2, percent=amount, threshold=3))
                steps.append(f"adaptive-sharpen({amount}%)")
            except Exception as e:
                self.results["warnings"].append(f"SSTV sharpen failed: {e}")

        return img, steps

    def _postprocess_image(self, img_path: str):
        try:
            from PIL import Image as ImageModule
        except ImportError:
            self.results["warnings"].append("Pillow not installed — SSTV post-processing skipped")
            return
        try:
            import numpy as np
        except ImportError:
            np = None
        try:
            import cv2
        except ImportError:
            cv2 = None

        try:
            base_img = ImageModule.open(img_path).convert("RGB")
        except Exception as e:
            self.results["warnings"].append(f"SSTV post-processing could not open decoded image: {e}")
            return

        autocrop_steps: List[str] = []
        if np is not None:
            try:
                base_img, cropped = self._pp_autocrop(base_img, np)
                if cropped:
                    autocrop_steps.append("auto-crop")
            except Exception as e:
                self.results["warnings"].append(f"SSTV auto-crop failed: {e}")

        # Multiple recipes applied to the same auto-cropped base image
        # (v4.3/v4.4): rather than one fixed sequential pipeline, generate
        # several different variants — including one using CLAHE (tiled
        # adaptive histogram eq) + bilateral filtering (edge-preserving
        # denoise) instead of the other recipes' global equalize + median/NLM
        # denoise — and pick the best by an objective metric instead of
        # assuming heavier processing is always better.
        recipes = {
            "standard":        dict(denoise=True,  gamma=1.15, color_balance=True,
                                     line_align=True, sharpen_amount=60),
            "high_contrast":   dict(denoise=True,  gamma=1.35, color_balance=True,
                                     line_align=True, sharpen_amount=80),
            "minimal":         dict(denoise=False, gamma=1.0,  color_balance=False,
                                     line_align=True, sharpen_amount=50),
            "clahe_bilateral": dict(denoise=False, gamma=1.10, color_balance=True,
                                     line_align=True, sharpen_amount=70,
                                     use_bilateral=True, use_clahe=True),
        }

        # Composite scoring (v4.4): OCR/QR success is direct, real evidence
        # that a variant is legible, weighted on top of the purely visual
        # sharpness/contrast/entropy score — a "sharp-looking" variant that
        # neither tesseract nor zbarimg can read is less useful in practice
        # than a slightly softer one that decodes cleanly.
        _OCR_SCORE_WEIGHT = 2.0
        _QR_SCORE_BONUS = 3.0

        variants: Dict[str, Any] = {}
        for name, params in recipes.items():
            try:
                v_img, v_steps = self._pp_apply_pipeline(base_img.copy(), np, cv2, **params)
                img_score = self._pp_quality_score(v_img, np, cv2) if np is not None else 0.0

                vpath = str(self.store.sstv_variants / f"variant_{name}.png")
                v_img.save(vpath)

                ocr_text, ocr_conf = self._pp_probe_ocr(vpath)
                qr_found = self._pp_probe_qr_readonly(vpath)
                composite = img_score
                if ocr_conf > 0:
                    composite += (ocr_conf / 100.0) * _OCR_SCORE_WEIGHT
                if qr_found:
                    composite += _QR_SCORE_BONUS

                variants[name] = {
                    "image": v_img, "path": vpath,
                    "steps": autocrop_steps + v_steps,
                    "image_score": img_score, "score": composite,
                    "ocr_text": ocr_text, "ocr_conf": ocr_conf, "qr_found": qr_found,
                }
            except Exception as e:
                self.results["warnings"].append(f"SSTV variant '{name}' failed: {e}")

        if not variants:
            self.results["warnings"].append("SSTV post-processing produced no usable variant")
            return

        best_name = max(variants, key=lambda n: variants[n]["score"])
        best = variants[best_name]
        best_image = best["image"]

        # Automatic rotation (v4.4) — a real, tool-verified signal from
        # tesseract's own orientation-and-script-detection pass, applied
        # only to the already-selected winner (never a blind geometric
        # guess, and never applied to every candidate pre-selection, which
        # would multiply the OCR/QR probing cost above for no benefit).
        rotated = self._pp_auto_rotate(best["path"])
        if rotated is not None:
            best_image, rotate_deg = rotated
            best["steps"] = best["steps"] + [f"auto-rotate({rotate_deg}deg)"]

        try:
            best_image.save(img_path)
            best_image.save(str(self.store.sstv_dir / "decoded_best.png"))
        except Exception as e:
            self.results["warnings"].append(f"Could not save enhanced SSTV image: {e}")
            return

        try:
            try:
                resample = ImageModule.Resampling.LANCZOS
            except AttributeError:
                resample = ImageModule.LANCZOS
            upscale_factor = 2
            upscaled = best_image.resize(
                (best_image.width * upscale_factor, best_image.height * upscale_factor), resample)
            upscaled_path = str(self.store.sstv_dir / "decoded_best_upscaled.png")
            upscaled.save(upscaled_path)
            self.results["decoded_image_upscaled"] = upscaled_path
        except Exception as e:
            self.results["warnings"].append(f"Could not save upscaled SSTV image: {e}")

        self.results["postprocess_steps"] = best["steps"]
        self.results["sstv_variant_selected"] = best_name
        self.results["sstv_variant_scores"] = {n: round(v["score"], 3) for n, v in variants.items()}
        self.results["sstv_image_quality_scores"] = {n: round(v["image_score"], 3) for n, v in variants.items()}
        self.results["sstv_variant_paths"] = {n: v["path"] for n, v in variants.items()}
        self.results["decoded_image_dimensions"] = list(best_image.size)

        # Best OCR text / first QR hit found across every variant (not just
        # the winner) — reuses the probes already computed above instead of
        # re-running tesseract/zbarimg a second time.
        self._merge_ocr_qr_from_probed_variants(variants)

        if np is not None:
            try:
                gray = np.array(best_image.convert("L"), dtype=np.float64)
                try:
                    from scipy import ndimage
                    local_mean = ndimage.uniform_filter(gray, size=max(3, min(gray.shape) // 20 or 3))
                except ImportError:
                    local_mean = np.full_like(gray, gray.mean())
                bw = gray > (local_mean - 10)

                if cv2 is not None:
                    kernel = np.ones((3, 3), np.uint8)
                    bw_u8 = cv2.morphologyEx((bw * 255).astype(np.uint8), cv2.MORPH_OPEN, kernel)
                    bw_u8 = cv2.morphologyEx(bw_u8, cv2.MORPH_CLOSE, kernel)
                else:
                    try:
                        from scipy import ndimage as _ndi
                        bw = _ndi.binary_closing(_ndi.binary_opening(bw))
                    except ImportError:
                        pass
                    bw_u8 = (bw * 255).astype(np.uint8)

                bw_path = str(self.store.sstv_dir / "decoded_bw.png")
                ImageModule.fromarray(bw_u8).save(bw_path)
                self.results["decoded_bw_image"] = bw_path
            except Exception as e:
                self.results["warnings"].append(f"SSTV adaptive threshold failed: {e}")

    def _merge_ocr_qr_from_probed_variants(self, variants: Dict[str, Dict]):
        """Keeps the best OCR text (longest/highest-confidence) and the
        first QR/barcode hit found across every already-probed variant
        (QR either decodes or it doesn't — there's no "better" partial QR
        read to compare). Reuses the read-only probes computed while
        scoring each variant in _postprocess_image instead of re-running
        tesseract/zbarimg a second time."""
        best_text, best_avg_conf, best_name = "", -1.0, None
        for name, v in variants.items():
            if v["ocr_text"] and v["ocr_conf"] > best_avg_conf:
                best_text, best_avg_conf, best_name = v["ocr_text"], v["ocr_conf"], name
            if v["qr_found"] and not self.results.get("qr_data"):
                self._pp_probe_qr(v["path"])

        if best_text:
            self.results["ocr_text"] = best_text
            save_text(str(self.store.sstv_dir / "ocr.txt"),
                      f"OCR (confidence {best_avg_conf:.0f}%, best of {len(variants)} variants, "
                      f"variant='{best_name}'):\n{best_text}\n")
            logger.info(f"SSTV OCR (best variant='{best_name}'): {len(best_text)} chars, conf={best_avg_conf:.0f}%")

    def _pp_probe_ocr(self, img_path: str):
        """Read-only tesseract probe: returns (text, avg_confidence), never
        mutates self.results — the caller decides what to keep."""
        if not tool_available("tesseract"):
            return "", -1.0
        rc, out, err = run_command(["tesseract", img_path, "stdout", "--psm", "6", "tsv"], timeout=30)
        if rc != 0 or not out:
            return "", -1.0
        words: List[str] = []
        confs: List[float] = []
        for line in out.splitlines()[1:]:
            cols = line.split("\t")
            if len(cols) >= 12:
                try:
                    conf = float(cols[10])
                    if conf >= 0:
                        confs.append(conf)
                        if cols[11].strip():
                            words.append(cols[11].strip())
                except ValueError:
                    pass
        if not words:
            return "", -1.0
        return " ".join(words), (sum(confs) / len(confs) if confs else 0.0)

    def _pp_probe_qr(self, img_path: str):
        """Read-only zbarimg probe; sets self.results directly on a hit
        since QR/barcode data is binary (found or not), not a score to
        compare across variants like OCR text length/confidence is."""
        if not tool_available("zbarimg"):
            return
        rc, out, err = run_command(["zbarimg", img_path], timeout=20)
        if rc != 0 or not out.strip():
            return
        first_line = out.strip().splitlines()[0]
        symbology, _, value = first_line.partition(":")
        self.results["qr_data"] = out.strip()
        self.results["barcode_type"] = symbology if value else "unknown"
        save_text(str(self.store.sstv_dir / "qr.txt"), out)
        logger.info(f"SSTV barcode/QR ({symbology}): {out.strip()[:80]}")
        self.results["findings"].append(Finding(
            module="sstv",
            title=f"{symbology or 'Barcode'} Detected in SSTV Image",
            severity=Severity.CRITICAL,
            confidence=0.99,
            value=out.strip()[:200],
            evidence=f"zbarimg decoded {symbology or 'a barcode'} from the SSTV-decoded image",
            reason="Directly decoded machine-readable data",
            false_positive_risk="Very low",
        ).to_dict())

    def _pp_probe_qr_readonly(self, img_path: str) -> bool:
        """Read-only zbarimg presence check (True/False only, no side
        effects) used purely for composite variant scoring in
        _postprocess_image — the real decode + Finding append still only
        happens once, via _pp_probe_qr on the winning variant."""
        if not tool_available("zbarimg"):
            return False
        rc, out, err = run_command(["zbarimg", img_path], timeout=20)
        return rc == 0 and bool(out.strip())

    def _pp_auto_rotate(self, img_path: str):
        """Real, tool-verified rotation check via tesseract's own
        orientation-and-script-detection pass (--psm 0) — never a blind
        geometric guess. Returns (rotated_image, degrees) if tesseract is
        available, reports a rotation, and its own orientation confidence
        clears a minimum bar; otherwise None (including whenever tesseract
        itself is unavailable — no fallback heuristic is used, since there
        is no other reliable signal for "which way is up" on a freshly
        reconstructed SSTV frame)."""
        if not tool_available("tesseract"):
            return None
        rc, out, err = run_command(["tesseract", img_path, "stdout", "--psm", "0"], timeout=20)
        if rc != 0 or not out:
            return None
        rotate_deg, conf = 0, 0.0
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Rotate:"):
                try:
                    rotate_deg = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("Orientation confidence:"):
                try:
                    conf = float(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
        # Tesseract's own OSD confidence is unbounded but empirically
        # unreliable below ~2.0 — only act on a rotation it reports with
        # reasonable certainty.
        if not rotate_deg or conf < 2.0:
            return None
        try:
            from PIL import Image as ImageModule
            img = ImageModule.open(img_path)
            rotated = img.rotate(-rotate_deg, expand=True)
            return rotated, rotate_deg
        except Exception as e:
            self.results["warnings"].append(f"SSTV auto-rotate failed to apply: {e}")
            return None

    # ------------------------------------------------------------------
    # Optional marker detection (ArUco/AprilTag) — soft dependencies,
    # gracefully skipped if not installed (same pattern as every other
    # optional tool in this project).
    # ------------------------------------------------------------------

    def _detect_markers(self, img_path: str):
        try:
            import cv2
            img = cv2.imread(img_path)
            if img is not None:
                aruco_dict = cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)
                detector = cv2.aruco.ArucoDetector(aruco_dict)
                corners, ids, _rejected = detector.detectMarkers(img)
                if ids is not None and len(ids):
                    self.results["markers"].append({"type": "ArUco", "ids": ids.flatten().tolist()})
                    logger.info(f"SSTV image: {len(ids)} ArUco marker(s) detected")
        except ImportError:
            self.results["warnings"].append("opencv (cv2) not installed — ArUco marker detection skipped")
        except Exception as e:
            logger.debug(f"ArUco detection failed: {e}")

        try:
            import pupil_apriltags
            from PIL import Image
            import numpy as np
            detector = pupil_apriltags.Detector()
            gray = np.array(Image.open(img_path).convert("L"))
            tags = detector.detect(gray)
            if tags:
                self.results["markers"].append({"type": "AprilTag", "ids": [t.tag_id for t in tags]})
                logger.info(f"SSTV image: {len(tags)} AprilTag(s) detected")
        except ImportError:
            self.results["warnings"].append("pupil_apriltags not installed — AprilTag detection skipped")
        except Exception as e:
            logger.debug(f"AprilTag detection failed: {e}")

        if self.results["markers"]:
            self.results["findings"].append(Finding(
                module="sstv",
                title="Fiducial Marker(s) Detected in SSTV Image",
                severity=Severity.HIGH,
                confidence=0.95,
                value=", ".join(f"{m['type']}:{m['ids']}" for m in self.results["markers"]),
                evidence=f"{len(self.results['markers'])} marker group(s) detected",
                reason="Directly detected via cv2.aruco/pupil_apriltags on the decoded image",
                false_positive_risk="Low",
            ).to_dict())

    # ------------------------------------------------------------------
    # Post-decode: OCR + QR/barcode + metadata on decoded image
    # ------------------------------------------------------------------

    def _analyze_decoded_image(self, img_path: str):
        """Runs on the final winning image after post-processing. OCR/QR
        merging is monotonic — never overwrites a better result the
        multi-variant probe in _postprocess_image already found (see
        _merge_ocr_qr_across_variants) — so this is a correct fallback on
        its own (e.g. if Pillow/post-processing was unavailable) and a
        no-op re-check otherwise, never a regression."""
        text, avg_conf = self._pp_probe_ocr(img_path)
        if text and len(text) > len(self.results.get("ocr_text") or ""):
            self.results["ocr_text"] = text
            save_text(str(self.store.sstv_dir / "ocr.txt"), f"OCR (confidence {avg_conf:.0f}%):\n{text}\n")
            logger.info(f"SSTV OCR: {len(text)} chars, conf={avg_conf:.0f}%")

        if not self.results.get("qr_data"):
            self._pp_probe_qr(img_path)

        if tool_available("exiftool"):
            rc, out, err = run_command(["exiftool", "-j", img_path], timeout=15)
            if rc == 0 and out.strip():
                import json as _json
                try:
                    meta = _json.loads(out)
                    self.results["image_metadata"] = meta[0] if meta else None
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _write_report(self, audio_path: str):
        markers_str = ", ".join(
            "{}:{}".format(m["type"], m["ids"]) for m in self.results["markers"]
        ) or "None"
        lines = [
            "=== SSTV ANALYSIS REPORT ===",
            f"File       : {audio_path}",
            f"VIS code   : {'0x{:02X} — {}'.format(self.results['vis_code'], self.results['mode']) if self.results['vis_code'] else 'Not detected'}",
            f"Mode       : {self.results['mode'] or 'Unknown'}",
            f"Confidence : {self.results['confidence']:.0%}",
            f"Decoders   : {', '.join(self.results['decoders_tried']) or 'None available/applicable'}",
            f"Image      : {self.results['decoded_image'] or 'Not decoded'}",
            f"OCR text   : {self.results['ocr_text'][:200] if self.results['ocr_text'] else 'None'}",
            f"QR/Barcode : {self.results['qr_data'][:200] if self.results['qr_data'] else 'None'}",
            f"Markers    : {markers_str}",
        ]
        if not self.results["vis_detected"]:
            lines += ["", "Status: No SSTV VIS signal detected",
                       f"Confidence: {self.results['confidence']:.0%}"]
        if self.results["warnings"]:
            lines += ["", "--- Warnings ---"] + [f"  {w}" for w in self.results["warnings"]]
        save_text(str(self.store.sstv_dir / "sstv_report.txt"), "\n".join(lines))
