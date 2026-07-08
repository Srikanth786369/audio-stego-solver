"""
Digital modes decoding module for Audio Stego Solver.
Handles DTMF, Morse code, SSTV, multimon-ng, and minimodem decoding.

FIXED (v1.1):
  - Eliminated Morse/DTMF/SSTV/minimodem false positives
  - Added confidence scoring to every result
  - multimon-ng banner lines are now filtered
  - minimodem output is validated for printability + minimum decoded length
  - Morse decoded text validated: rejects results with >40% unknown chars
  - DTMF requires at least 3 valid digit characters to report
  - Removed duplicate DTMF run (was run twice via _detect_dtmf + _run_multimon)
  - Temp WAV file cleanup added
"""

import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .findings import EvidenceLevel, Finding, Severity, cap_severity, confidence_for_evidence
from .logger import get_logger
from .utils import run_command, save_text, tool_available

logger = get_logger("audio_stego.digital")

# Morse code lookup table
MORSE_TO_CHAR = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'",
    "-.-.--": "!", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
    ".-...": "&", "---...": ":", "-.-.-.": ";", "-...-": "=",
    ".-.-.": "+", "-....-": "-", "..--.-": "_", ".-..-.": '"',
    "...-..-": "$", ".--.-.": "@", "...---...": "SOS",
}

# multimon-ng startup banner lines to ignore.
#
# CRITICAL FIX: "DTMF:" and "MORSE_CW:" were previously listed here as
# "banner prefixes" — but those are not banner text at all, they are the
# exact literal prefix multimon-ng puts on every single real decoded line
# ("DTMF: 7", "MORSE_CW: SOS ..."). _filter_multimon_output() checks the
# banner-prefix list *before* checking whether the line contains the
# decode marker, so every genuine DTMF/Morse decode line was being
# discarded as "banner" before ever reaching the marker check — verified
# by generating a real DTMF tone sequence (dual-tone 1-3-3-7), confirming
# multimon-ng itself decodes it correctly ("DTMF: 1", "DTMF: 3", "DTMF: 3",
# "DTMF: 7" with no such lines at startup on a silent/empty input), and
# then confirming the *pipeline* reported zero digits found — the DTMF and
# Morse detectors could never produce a result, on any input, ever.
_MULTIMON_BANNER_PREFIXES = (
    "multimon-ng", "Available demodulators:", "Enabled decoders:",
    "Enabled demodulators:", "Use of", "(C)", "This program",
    "Found ", "X: Unable to open",
    "unixinput.c:", "child process",
)

# Selective-call standards decode one digit per sustained tone frequency
# with no frame/CRC structure at all — the most false-positive-prone
# demodulator family multimon-ng has (see _run_multimon_allmode for the
# concrete tone sweep that found this). A real address is always several
# digits; a single stray digit is just a held musical note.
_SELCALL_MODES = {"ZVEI1", "ZVEI2", "ZVEI3", "DZVEI", "PZVEI", "EEA", "EIA", "CCIR"}
_MIN_SELCALL_DIGITS = 4

# Minimum meaningful decoded output lengths
_MIN_DTMF_DIGITS = 3       # At least 3 DTMF digits to be reportable
# v4.3: raised from 2 — a 2-alphanumeric-char decode is too easily produced
# by chance from non-Morse dot/dash-like text; 3 still allows the canonical
# "...---..." -> "SOS" test signal through (SOS is exactly 3 characters).
_MIN_MORSE_CHARS = 3       # At least 3 decoded Morse characters
_MIN_MINIMODEM_PRINTABLE = 8  # At least 8 printable chars from minimodem
# minimodem's own reported confidence= value below which a decode is
# rejected regardless of how printable the text looks. Calibrated by
# sweeping minimodem across every baud mode against white noise, silence,
# single tones at 8 frequencies (220Hz-2200Hz), a 3-note chord, a chirp,
# and pink noise: the highest confidence any noise/music input produced
# while still passing the printable-ratio filter was 1.832 (a chirp
# misread as RTTY as "LIIIWWWWWW"); the lowest confidence any genuine
# minimodem-encoded round-trip signal produced (Bell103/202, RTTY, TDD,
# SAME, at both full and 1%-of-full volume) was 2.283. 2.0 sits in that
# gap with margin on both sides.
_MIN_MINIMODEM_CONFIDENCE = 2.0
_MORSE_MAX_UNKNOWN_RATIO = 0.4  # Reject if >40% of decoded chars are '?'

# ---------------------------------------------------------------------------
# v4.1: application-layer structural validation for multimon-ng protocols.
#
# multimon-ng's demodulators already do real signal-level framing/error
# detection before printing a line at all (AFSK1200 is HDLC-framed with an
# FCS/CRC-16 check; POCSAG is BCH(31,21)-protected) — a printed line is never
# "random noise happening to look like text." What was missing was checking
# that the *application-layer* fields inside that line are themselves
# well-formed, which is the extra structural-validation step this project's
# confidence engine rewards with a higher evidence level (CHECKSUM_VALID,
# since it mirrors "a checksum/consistency check inside the artifact was
# verified" — here, the artifact is the decoded frame/message).
# ---------------------------------------------------------------------------

# AX.25 callsigns: up to 6 alphanumeric chars, '-' + SSID 0-15 (AX.25 spec:
# SSID is a 4-bit field). Matches multimon-ng's "fm CALL-N to CALL-N" style
# AFSK1200 output as well as any callsign appearing in the info field.
_CALLSIGN_SSID_RE = re.compile(r"\b([A-Z0-9]{1,6})-(\d{1,2})\b")

# multimon-ng's POCSAG output format: "POCSAGxxxx: Address: N  Function: N  ..."
_POCSAG_FIELDS_RE = re.compile(r"Address:\s*(\d+)\s+Function:\s*(\d+)", re.IGNORECASE)


def _validate_ax25_callsigns(line: str) -> bool:
    """True if `line` contains at least one well-formed AX.25 callsign-SSID pair."""
    for _call, ssid in _CALLSIGN_SSID_RE.findall(line):
        if 0 <= int(ssid) <= 15:
            return True
    return False


def _validate_pocsag_message(line: str) -> bool:
    """True if `line` has a POCSAG Address/Function pair within valid ranges
    (21-bit address per the POCSAG spec, 2-bit function code)."""
    m = _POCSAG_FIELDS_RE.search(line)
    if not m:
        return False
    address, function = int(m.group(1)), int(m.group(2))
    return 0 <= address <= 2_097_151 and 0 <= function <= 3


# minimodem's own stderr trailer line looks like:
#   ### NOCARRIER ndata=26 confidence=16.421 ampl=0.980 bps=45.45 (0.0% slow) ###
# — a real signal-correlation confidence value from the demodulator itself,
# not re-derived from the decoded text. Previously discarded entirely (err
# was captured but never parsed), even though it's strong independent
# evidence: e.g. feeding an RTTY-encoded (45.45 baud, 1.5 stopbits) signal
# through the TDD baudmode (45.45 baud, 2.0 stopbits — same nominal rate,
# mismatched framing) produced 11 chars of 100%-printable garbage
# ("_BVUGKMKWPQ") that passed the printable-ratio filter below with the
# same ~0.9 confidence as the genuine RTTY decode, at minimodem's own
# confidence=8.246 vs the real RTTY decode's confidence=16.421 — nearly 2x
# lower, a real and usable signal the old code threw away.
_MINIMODEM_TRAILER_RE = re.compile(
    r"confidence=([0-9.]+)\s+ampl=([0-9.]+)\s+bps=([0-9.]+)"
)

# rtty/tdd are the same nominal 45.45-baud physical signal, differing only
# in stop-bit framing (1.5 vs 2.0) — never two independent detections, so
# when both "succeed" against the same audio it is one real signal being
# interpreted two ways, and only the higher-confidence framing should be
# reported (see _MINIMODEM_TRAILER_RE comment above for the concrete case
# this fixes).
_MINIMODEM_BAUD_FAMILY: Dict[Any, str] = {"rtty": "45.45-baud", "tdd": "45.45-baud"}


def _parse_minimodem_trailer(stderr: str) -> Optional[Tuple[float, float, float]]:
    """Extract (confidence, amplitude, bps) from minimodem's NOCARRIER trailer
    line, or None if the tool didn't print one (e.g. no carrier detected at all)."""
    m = _MINIMODEM_TRAILER_RE.search(stderr)
    if not m:
        return None
    return float(m.group(1)), float(m.group(2)), float(m.group(3))


# Baud/mode -> honest protocol label for minimodem results. Bell103/Bell202
# are not separate minimodem baudmode arguments (verified against
# minimodem's own usage text — see _run_minimodem) but are simply the named
# protocols that operate at 300 and 1200 baud respectively, so the numeric
# baud rate IS the protocol identifier here.
_MINIMODEM_PROTOCOL_LABELS: Dict[Any, str] = {
    300:  "300 baud (Bell 103 compatible)",
    1200: "1200 baud (Bell 202 compatible)",
    "rtty": "RTTY (Baudot/ITA2, 45.45 baud)",
    "tdd":  "TDD (Baudot, 45.45 baud)",
    "same": "SAME (Emergency Alert System header)",
}


class DigitalModesAnalyzer:
    """
    Decodes digital modes hidden in audio files.

    Every result includes:
      - confidence (0.0–1.0)
      - evidence string
      - reason for the confidence score
      - raw_output from the tool
      - false_positive_risk description
    """

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.tools_dir = os.path.join(output_dir, "tools")
        os.makedirs(self.tools_dir, exist_ok=True)
        self._temp_wav: Optional[str] = None  # track temp file for cleanup
        self.results: Dict[str, Any] = {
            "morse":     [],
            "dtmf":      [],
            "sstv":      [],
            "multimon":  {},
            "minimodem": [],
            "warnings":  [],
            "findings":  [],   # List[Finding.to_dict()]
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audio_path: str) -> Dict[str, Any]:
        """Run all digital mode decoders and return structured results."""
        logger.info(f"Starting digital modes analysis for: {audio_path}")
        wav_path = self._ensure_wav(audio_path)

        try:
            if self.config.getbool("analysis", "run_morse", True):
                self._detect_morse(audio_path, wav_path)
            if self.config.getbool("analysis", "run_dtmf", True):
                self._detect_dtmf(wav_path)
            # SSTV detection lives in sstv.py::SSTVAnalyzer (real Goertzel-based
            # VIS decoding, gated by the same "run_sstv" config key — see
            # scanner.py). It used to also be attempted here via
            # `multimon-ng -a SSTV`, which was dead code: multimon-ng has no
            # SSTV demodulator at all (verified against its own --help output),
            # so this branch could never produce a result.
            if self.config.getbool("analysis", "run_multimon", True):
                self._run_multimon_allmode(wav_path)
            if self.config.getbool("analysis", "run_minimodem", True):
                self._run_minimodem(wav_path)
            self._check_advanced_mode_tools()
        finally:
            self._cleanup_temp_wav()

        logger.info("Digital modes analysis complete")
        return self.results

    # ------------------------------------------------------------------
    # WAV conversion
    # ------------------------------------------------------------------

    def _ensure_wav(self, path: str) -> Optional[str]:
        """Return a WAV version of the audio; convert with ffmpeg if needed."""
        ext = os.path.splitext(path)[1].lower()
        if ext == ".wav":
            return path
        if not tool_available("ffmpeg"):
            logger.warning("ffmpeg not available for WAV conversion")
            return None

        wav_path = os.path.join(self.output_dir, "_converted_digital.wav")
        if os.path.exists(wav_path):
            return wav_path

        cmd = ["ffmpeg", "-i", path, "-ar", "44100", "-ac", "1",
               "-acodec", "pcm_s16le", wav_path, "-y"]
        rc, _, err = run_command(cmd, timeout=120)
        if rc == 0 and os.path.exists(wav_path):
            self._temp_wav = wav_path
            return wav_path
        logger.warning(f"WAV conversion failed: {err[:200]}")
        return None

    def _cleanup_temp_wav(self):
        """Remove temp WAV file if we created it."""
        if self._temp_wav and os.path.exists(self._temp_wav):
            try:
                os.remove(self._temp_wav)
            except OSError:
                pass
            self._temp_wav = None

    # ------------------------------------------------------------------
    # Morse detection
    # ------------------------------------------------------------------

    def _detect_morse(self, audio_path: str, wav_path: Optional[str]):
        """Detect Morse code — validates decoded output before reporting."""
        results = []

        # --- multimon-ng MORSE_CW ---
        if tool_available("multimon-ng") and wav_path:
            rc, out, err = run_command(
                ["multimon-ng", "-t", "wav", "-a", "MORSE_CW", wav_path],
                timeout=self.config.timeout,
            )
            # CRITICAL FIX: unlike DTMF/POCSAG, multimon-ng's CW demodulator
            # does not prefix its output with a "MORSE_CW:" marker at all —
            # verified by generating real Morse audio (SOS/HELLO/WORLD,
            # HELP) and observing multimon-ng print the bare decoded text
            # ("SOS HELLO WORL") with no per-line tag. The old code required
            # `"MORSE_CW:" in l` before accepting a line as decoded text,
            # which could never be true, so real Morse audio could never
            # produce a finding — a complete decoder outage regardless of
            # input, not merely a false-positive issue. Since this
            # invocation runs MORSE_CW as the sole demodulator, every
            # remaining non-banner, non-empty line already *is* the decode.
            morse_lines = [
                l.strip() for l in out.splitlines()
                if l.strip() and not any(l.strip().startswith(p) for p in _MULTIMON_BANNER_PREFIXES)
            ]
            if morse_lines:
                raw_decoded = " ".join(morse_lines)
                confidence, reason = self._score_morse_output(raw_decoded, morse_lines)
                if confidence >= 0.30:
                    f = Finding(
                        module="morse",
                        title="Morse Code (multimon-ng)",
                        severity=Severity.MEDIUM if confidence >= 0.60 else Severity.LOW,
                        confidence=confidence,
                        value=raw_decoded[:300],
                        evidence=f"{len(morse_lines)} decoded line(s) from multimon-ng",
                        reason=reason,
                        raw_output="\n".join(morse_lines[:10]),
                        false_positive_risk="Low — multimon-ng CW decoder requires actual tones",
                    )
                    results.append(f.to_dict())
                    self.results["findings"].append(f.to_dict())
                    logger.info(f"Morse (multimon-ng) confidence={confidence:.0%}: {raw_decoded[:60]}")
                else:
                    logger.info(f"Morse multimon-ng output rejected — confidence={confidence:.0%}: {reason}")

        # --- text-based Morse pattern in strings ---
        strings_path = os.path.join(self.tools_dir, "strings.txt")
        if os.path.exists(strings_path):
            with open(strings_path, encoding="utf-8", errors="replace") as fh:
                content = fh.read(200_000)
            text_findings = self._find_morse_in_text(content)
            results.extend(text_findings)

        self.results["morse"] = results

        if results:
            lines = ["=== MORSE CODE RESULTS ==="]
            for r in results:
                lines.append(f"\nSource: {r.get('title', 'unknown')}")
                lines.append(f"Confidence: {r.get('confidence_pct', '?')}")
                lines.append(f"Value: {r.get('value', '')}")
                lines.append(f"Reason: {r.get('reason', '')}")
            out_path = os.path.join(self.output_dir, "morse.txt")
            save_text(out_path, "\n".join(lines))
        else:
            save_text(
                os.path.join(self.output_dir, "morse.txt"),
                "=== MORSE CODE RESULTS ===\nStatus: No valid Morse code detected\n"
                "Confidence: 0%\nReason: No valid CW decoded lines from multimon-ng; "
                "no Morse patterns in extracted strings.",
            )

    def _find_morse_in_text(self, text: str) -> List[Dict]:
        """
        Search extracted strings for Morse-like patterns.

        Strict validation: only reports if decoded text has <= 40% unknown chars
        AND contains >= 3 decoded characters that are alphanumeric.
        """
        findings = []
        # Match sequences of dots/dashes with spaces; require at least 5 tokens
        morse_pattern = re.compile(
            r"(?:(?:[.\-]{1,6})\s){4,}(?:[.\-]{1,6})"
        )
        for match in morse_pattern.finditer(text):
            morse_str = match.group().strip()
            decoded = self._decode_morse(morse_str)
            if not decoded:
                continue
            unknown_ratio = decoded.count("?") / max(len(decoded), 1)
            alnum_count = sum(1 for c in decoded if c.isalnum())
            if unknown_ratio > _MORSE_MAX_UNKNOWN_RATIO or alnum_count < _MIN_MORSE_CHARS:
                continue
            confidence = max(0.30, 0.90 - unknown_ratio)
            f = Finding(
                module="morse",
                title="Morse Pattern in Strings",
                severity=Severity.LOW,
                confidence=confidence,
                value=decoded,
                evidence=f"Pattern '{morse_str[:80]}' in extracted strings",
                reason=f"Decoded {len(decoded)} chars, {unknown_ratio:.0%} unknown",
                false_positive_risk="Medium — dot/dash patterns can appear in non-Morse data",
            )
            findings.append(f.to_dict())
        return findings

    def _decode_morse(self, morse: str) -> str:
        """Decode a Morse code string to text."""
        words = re.split(r"\s*/\s*|\s{3,}", morse.strip())
        decoded_words = []
        for word in words:
            chars = word.split()
            decoded_word = "".join(MORSE_TO_CHAR.get(c, "?") for c in chars if c)
            if decoded_word:
                decoded_words.append(decoded_word)
        return " ".join(decoded_words)

    def _score_morse_output(self, decoded: str, lines: List[str]) -> Tuple[float, str]:
        """Return (confidence, reason) for a Morse decode result."""
        if not decoded.strip():
            return 0.05, "multimon-ng returned no decoded text"
        alnum = sum(1 for c in decoded if c.isalnum())
        unknown = decoded.count("?")
        total = max(len(decoded), 1)
        if alnum < _MIN_MORSE_CHARS:
            return 0.10, f"Too few alphanumeric chars decoded ({alnum})"
        ratio = unknown / total
        if ratio > _MORSE_MAX_UNKNOWN_RATIO:
            return 0.15, f"Too many unknown characters ({ratio:.0%} '?' in decoded output)"
        conf = 0.85 - ratio * 0.5
        reason = f"Decoded {alnum} alphanumeric chars; {ratio:.0%} unknown"
        return conf, reason

    # ------------------------------------------------------------------
    # DTMF detection
    # ------------------------------------------------------------------

    def _detect_dtmf(self, wav_path: Optional[str]):
        """
        Detect DTMF tones.

        Validation: requires >= 3 valid DTMF digit characters in the decoded
        output to avoid reporting noise or banner lines as DTMF.
        """
        if not wav_path:
            return

        results = []

        if not tool_available("multimon-ng"):
            self.results["warnings"].append("Tool not found: multimon-ng (DTMF)")
            return

        rc, out, err = run_command(
            ["multimon-ng", "-t", "wav", "-a", "DTMF", wav_path],
            timeout=self.config.timeout,
        )
        dtmf_lines = self._filter_multimon_output(out, marker="DTMF:")
        raw_digits = "".join(
            re.findall(r"DTMF:\s*([0-9A-D*#])", "\n".join(dtmf_lines))
        )

        if len(raw_digits) >= _MIN_DTMF_DIGITS:
            confidence = min(0.95, 0.50 + len(raw_digits) * 0.05)
            f = Finding(
                module="dtmf",
                title="DTMF Tones Detected",
                severity=Severity.MEDIUM,
                confidence=confidence,
                value=raw_digits,
                evidence=f"{len(raw_digits)} DTMF digit(s) decoded by multimon-ng",
                reason=f"Digits: {raw_digits}  |  {len(dtmf_lines)} tone event(s)",
                raw_output="\n".join(dtmf_lines[:20]),
                false_positive_risk="Low — multimon-ng DTMF requires specific tone pairs",
            )
            results.append(f.to_dict())
            self.results["findings"].append(f.to_dict())
            logger.info(f"DTMF detected: '{raw_digits}' (confidence={confidence:.0%})")
        else:
            logger.info(
                f"DTMF: {len(raw_digits)} digit(s) found — below threshold "
                f"({_MIN_DTMF_DIGITS} required), not reporting"
            )

        self.results["dtmf"] = results

        dtmf_report = "=== DTMF RESULTS ===\n"
        if results:
            dtmf_report += f"Status: DTMF tones detected\n"
            for r in results:
                dtmf_report += f"Digits: {r['value']}\nConfidence: {r['confidence_pct']}\n"
        else:
            dtmf_report += (
                f"Status: No valid DTMF digits detected\n"
                f"Confidence: {max(0, len(raw_digits)) * 5}%\n"
                f"Reason: Only {len(raw_digits)} digit(s) found "
                f"(minimum {_MIN_DTMF_DIGITS} required)\n"
                f"Raw output lines: {len(dtmf_lines)}"
            )
        save_text(os.path.join(self.output_dir, "dtmf.txt"), dtmf_report)

    # ------------------------------------------------------------------
    # SSTV detection
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # multimon-ng (all modes — for non-DTMF/non-Morse protocols)
    # ------------------------------------------------------------------

    def _run_multimon_allmode(self, wav_path: Optional[str]):
        """
        Run multimon-ng with pager / radio modes (NOT DTMF or MORSE —
        those have dedicated methods to avoid duplicate runs).
        """
        if not tool_available("multimon-ng"):
            self.results["warnings"].append("Tool not found: multimon-ng")
            return
        if not wav_path:
            return

        # DTMF and MORSE_CW are intentionally excluded here (dedicated methods).
        # SCOPE/DUMPCSV are debug-only demodulators, not real protocols, and
        # X10 requires a specific power-line carrier that never appears in
        # audio files, so all three are excluded to avoid noise.
        modes = [
            "POCSAG512", "POCSAG1200", "POCSAG2400",   # pager protocols
            "FLEX", "FLEX_NEXT",                       # FLEX pager
            "EAS",                                     # Emergency Alert System
            "UFSK1200", "CLIPFSK", "FMSFSK",
            "AFSK1200", "AFSK2400", "AFSK2400_2", "AFSK2400_3",
            "HAPN4800", "FSK9600",                     # generic FSK/AFSK rates
            "ZVEI1", "ZVEI2", "ZVEI3", "DZVEI", "PZVEI",  # selective-call tones
            "EEA", "EIA", "CCIR",                       # selective-call standards
        ]
        mode_args = []
        for m in modes:
            mode_args += ["-a", m]

        rc, out, err = run_command(
            ["multimon-ng", "-t", "wav"] + mode_args + [wav_path],
            timeout=self.config.timeout * 2,
        )

        # Filter banner and empty lines
        meaningful = [
            l for l in out.splitlines()
            if ":" in l and len(l) > 10
            and not any(l.strip().startswith(p) for p in _MULTIMON_BANNER_PREFIXES)
        ]

        # Break results down per protocol so the report can show
        # "FLEX: 3 lines / POCSAG1200: 0 lines" instead of one undifferentiated
        # blob. multimon-ng prefixes each decoded line with the mode name
        # (e.g. "FLEX: ...", "POCSAG1200: Address: ...", "ZVEI1: ...").
        per_mode: Dict[str, List[str]] = {}
        for line in meaningful:
            prefix = line.split(":", 1)[0].strip()
            matched = next((m for m in modes if prefix.upper().startswith(m)), None)
            key = matched or prefix
            per_mode.setdefault(key, []).append(line)

        # AFSK1200 (Bell 202, 1200 baud) is the actual physical layer used by
        # AX.25 packet radio / APRS — labeled explicitly so a hit reads as
        # "AX.25/APRS packet detected" rather than an opaque demodulator name.
        _MODE_LABELS = {"AFSK1200": "AFSK1200 (AX.25/APRS packet layer)"}

        for mode, lines in per_mode.items():
            if not lines:
                continue
            # Selective-call standards (ZVEI/DZVEI/PZVEI/EEA/CCIR) identify a
            # digit purely by which single tone frequency is sustained for a
            # brief window — they have no frame/CRC structure to validate at
            # all, so a single ordinary held musical note is enough to
            # produce one "decoded digit". Verified directly: 6 of 8 plain
            # sine tones swept from 220Hz-2200Hz each triggered a one-digit
            # "decode" on one or more of these modes at confidence up to
            # 0.59. A real selective-call address is always a multi-digit
            # sequence (5 tones for ZVEI-style, more for EEA/CCIR) — require
            # several digits from the same protocol before reporting, same
            # principle as _MIN_DTMF_DIGITS for DTMF.
            if mode in _SELCALL_MODES and len(lines) < _MIN_SELCALL_DIGITS:
                logger.debug(
                    f"{mode}: only {len(lines)} digit(s) decoded — below the "
                    f"selective-call minimum ({_MIN_SELCALL_DIGITS}), a single "
                    f"held tone is not a real address — skip"
                )
                continue
            label = _MODE_LABELS.get(mode, mode)

            # Application-layer structural validation (v4.1) — only defined
            # for protocols with a well-documented, verifiable field format.
            if mode == "AFSK1200":
                structural_hits = sum(1 for l in lines if _validate_ax25_callsigns(l))
                structural_desc = "AX.25 callsign-SSID"
            elif mode.startswith("POCSAG"):
                structural_hits = sum(1 for l in lines if _validate_pocsag_message(l))
                structural_desc = "POCSAG Address/Function"
            else:
                structural_hits = 0
                structural_desc = None

            if structural_hits:
                confidence = confidence_for_evidence(EvidenceLevel.CHECKSUM_VALID)
                title = f"Digital mode verified: {label}"
                reason = (
                    f"{structural_hits} of {len(lines)} line(s) have a well-formed "
                    f"{structural_desc} field, in addition to multimon-ng's own "
                    f"frame-level error checking (HDLC/FCS or BCH depending on protocol)"
                )
                fp_risk = "Very low — application-layer fields independently validated"
            else:
                # multimon-ng still performed real signal-level framing/error
                # detection before printing anything (this is not a random
                # text match), but no independent structural parser exists
                # for this protocol yet — kept at a moderate confidence
                # rather than fabricating a validation step.
                confidence = min(0.65, 0.35 + 0.08 * len(lines))
                title = f"Digital mode decoded: {label}"
                reason = (
                    f"{len(lines)} line(s) from multimon-ng's {mode} demodulator "
                    f"(signal-level framing only — no application-layer structural "
                    f"parser implemented for this protocol)"
                )
                fp_risk = (
                    "Low — multimon-ng demodulators require matching tone/"
                    "shift-key patterns; unlikely to trigger on generic noise"
                )

            f = Finding(
                module="multimon",
                title=title,
                severity=cap_severity(Severity.HIGH if structural_hits else Severity.MEDIUM, confidence),
                confidence=confidence,
                value=lines[0][:200],
                evidence=f"{len(lines)} line(s) from multimon-ng {mode} decoder",
                reason=reason,
                false_positive_risk=fp_risk,
            )
            self.results["findings"].append(f.to_dict())

        self.results["multimon"] = {
            "output": out,
            "meaningful_lines": meaningful,
            "per_mode": {k: v for k, v in per_mode.items()},
            "modes_scanned": modes,
            "stderr": err[:500],
        }
        out_path = os.path.join(self.tools_dir, "multimon.txt")
        save_text(out_path, f"multimon-ng (pager/radio modes)\n{'='*60}\n{out}\nSTDERR:\n{err}")
        if meaningful:
            logger.info(
                f"multimon-ng decoded {len(meaningful)} meaningful line(s) "
                f"across {len(per_mode)} mode(s): {', '.join(per_mode.keys())}"
            )

    # ------------------------------------------------------------------
    # minimodem
    # ------------------------------------------------------------------

    def _run_minimodem(self, wav_path: Optional[str]):
        """
        Run minimodem for modem signal decoding.

        Validation:
          - Requires >= 8 printable characters in decoded output
          - Rejects outputs that are pure noise (< 60% printable chars)
          - Reports confidence blending printable ratio/length with
            minimodem's own signal-correlation confidence value (parsed
            from its stderr trailer) — real demodulator-level evidence,
            not just a property of the decoded text
          - Same-nominal-baud-rate framings (rtty vs tdd, both 45.45 baud)
            are the same physical signal interpreted two ways; only the
            higher-confidence framing is kept, not both
        """
        if not tool_available("minimodem"):
            self.results["warnings"].append("Tool not found: minimodem")
            return
        if not wav_path:
            return

        # "BELL103"/"BELL202" were previously in this list but are not real
        # minimodem baudmode arguments (verified against `minimodem`'s own
        # usage text) — they're just the descriptive names for baud rates
        # 300/1200, which are already covered numerically below. Every scan
        # was wasting two guaranteed-to-fail decode attempts on them.
        baud_rates = [300, 600, 1200, 2400, 4800, 9600, "rtty", "tdd", "same"]
        candidates: List[Dict[str, Any]] = []   # pre-Finding dicts, one per passing baud

        for baud in baud_rates:
            rc, out, err = run_command(
                ["minimodem", "--rx", str(baud), "-f", wav_path],
                timeout=25,
            )
            if rc != 0 or not out.strip():
                continue

            decoded = out.strip()
            printable_count = sum(
                1 for c in decoded if 0x20 <= ord(c) < 0x7F or c in "\t\n\r"
            )
            printable_ratio = printable_count / max(len(decoded), 1)

            if printable_count < _MIN_MINIMODEM_PRINTABLE:
                logger.debug(
                    f"minimodem @{baud}: only {printable_count} printable chars — skip"
                )
                continue
            if printable_ratio < 0.60:
                logger.debug(
                    f"minimodem @{baud}: printable ratio {printable_ratio:.0%} — skip"
                )
                continue

            trailer = _parse_minimodem_trailer(err)
            mm_confidence = trailer[0] if trailer else None

            # Reject regardless of how printable the text looks if minimodem's
            # own signal-correlation confidence is below the noise floor
            # established empirically (see _MIN_MINIMODEM_CONFIDENCE) — this
            # is what catches e.g. a plain 440Hz tone decoding as "FJFJJJFJFFJ"
            # or a frequency chirp decoding as "LIIIWWWWWW", both 100%
            # printable but not real data.
            if mm_confidence is not None and mm_confidence < _MIN_MINIMODEM_CONFIDENCE:
                logger.debug(
                    f"minimodem @{baud}: confidence={mm_confidence} below noise floor "
                    f"({_MIN_MINIMODEM_CONFIDENCE}) — skip"
                )
                continue

            # Reject decodes dominated by one repeated character. Found by
            # running the full pipeline against a real MP3 (not synthetic
            # test tones): minimodem locked onto a carrier-like segment of
            # ordinary music and decoded "T _____________________T" — 100%
            # printable, minimodem confidence=3.162 (comfortably above the
            # noise floor above), but 21 of its 24 characters (88%) are the
            # same idle/fill character, the signature of a demodulator lock
            # onto a sustained tone with no real data modulated on it rather
            # than an actual message. Genuine decodes in this pipeline's own
            # test signals never exceed ~26% for any single character.
            dominant_ratio = max(Counter(decoded).values()) / len(decoded)
            if dominant_ratio > 0.60:
                logger.debug(
                    f"minimodem @{baud}: {dominant_ratio:.0%} of decoded text is one "
                    f"repeated character — looks like a carrier lock on non-data, skip"
                )
                continue

            confidence = min(0.90, 0.40 + printable_ratio * 0.50 + min(len(decoded), 100) * 0.002)
            candidates.append({
                "baud": baud, "decoded": decoded,
                "printable_count": printable_count, "printable_ratio": printable_ratio,
                "mm_confidence": mm_confidence, "confidence": confidence,
            })

        # Resolve same-nominal-baud-rate conflicts (rtty vs tdd): keep only
        # the framing with the higher minimodem-native confidence — the
        # loser is the wrong-framing artifact of the winner's real signal,
        # not an independent detection.
        by_family: Dict[str, List[Dict[str, Any]]] = {}
        standalone: List[Dict[str, Any]] = []
        for c in candidates:
            family = _MINIMODEM_BAUD_FAMILY.get(c["baud"])
            if family:
                by_family.setdefault(family, []).append(c)
            else:
                standalone.append(c)
        resolved = list(standalone)
        for family, members in by_family.items():
            if len(members) == 1:
                resolved.append(members[0])
                continue
            members.sort(key=lambda c: c["mm_confidence"] or 0.0, reverse=True)
            best = members[0]
            resolved.append(best)
            for loser in members[1:]:
                logger.info(
                    f"minimodem: {loser['baud']} decode of the same {family} signal "
                    f"superseded by {best['baud']} (confidence {loser['mm_confidence']} "
                    f"vs {best['mm_confidence']}) — not reported separately"
                )

        results = []
        for c in resolved:
            baud, decoded = c["baud"], c["decoded"]
            protocol_label = _MINIMODEM_PROTOCOL_LABELS.get(baud, f"{baud} baud")
            mm_conf_note = (f", minimodem confidence={c['mm_confidence']}"
                             if c["mm_confidence"] is not None else "")
            f = Finding(
                module="minimodem",
                title=f"Modem Signal Decoded ({protocol_label})",
                severity=Severity.MEDIUM,
                confidence=c["confidence"],
                value=decoded[:500],
                evidence=f"{c['printable_count']} printable chars at {baud} baud{mm_conf_note}",
                reason=f"Printable ratio: {c['printable_ratio']:.0%}, length: {len(decoded)}{mm_conf_note}",
                raw_output=decoded[:500],
                false_positive_risk=(
                    "Medium — minimodem can match noise at wrong baud rates; "
                    "verify with expected protocol"
                ),
            )
            results.append(f.to_dict())
            self.results["findings"].append(f.to_dict())
            logger.info(f"minimodem @{baud}: {c['printable_count']} printable chars (confidence={c['confidence']:.0%})")

        self.results["minimodem"] = results

        mm_path = os.path.join(self.tools_dir, "minimodem.txt")
        if results:
            lines = ["=== MINIMODEM RESULTS ==="]
            for r in results:
                lines.append(f"\nBaud: {r['title']}  Confidence: {r['confidence_pct']}")
                lines.append(f"Decoded: {r['value'][:300]}")
            save_text(mm_path, "\n".join(lines))
        else:
            save_text(
                mm_path,
                "=== MINIMODEM RESULTS ===\n"
                f"Status: No modem protocol detected\n"
                f"Reason: Tried {len(baud_rates)} baud rates; "
                f"no output met printable threshold ({_MIN_MINIMODEM_PRINTABLE} chars, 60% printable)\n",
            )

    # ------------------------------------------------------------------
    # Advanced modes (PSK31/Olivia/Hellschreiber/FT8/JT65) — honest
    # tool-availability reporting, not a fabricated decode path
    # ------------------------------------------------------------------

    def _check_advanced_mode_tools(self):
        """
        PSK31, Olivia, and Hellschreiber are normally decoded via fldigi;
        FT8/JT65 via wsjt-x/jt9. None of these expose a simple one-shot CLI
        batch-decode contract the way multimon-ng/minimodem do — fldigi's
        only scriptable interface is its XML-RPC server (a stateful,
        session-based protocol, not a "run once on a file" call), and
        wsjt-x/jt9 expect very specific framing (15-second-aligned windows)
        that would need real validation against reference recordings to
        implement correctly.

        Rather than guess at an integration this project can't verify works
        (the same mistake the old SSTV code made with multimon-ng/qsstv),
        this reports tool presence/absence honestly so a user knows what
        would need to be run manually, per "gracefully skip unavailable
        tools." AX.25/APRS is NOT in this list — that mode's physical layer
        (Bell 202 AFSK1200) is already decoded for real via multimon-ng
        above.

        NOAA APT (weather-satellite image transmission) is the same
        situation: no code anywhere in this project attempts it, and no
        image-producing decoder (wxtoimg/noaa-apt/aptdec) is wired in.
        Previously that meant it was simply absent from the report with no
        indication whether that was a deliberate scope decision or an
        oversight. Reported the same honest way as PSK31/FT8/JT65 rather
        than silently missing.
        """
        advanced = {
            "fldigi": "PSK31 / Olivia / Hellschreiber",
            "wsjt-x": "FT8 / JT65 (best effort)",
            "jt9":    "FT8 / JT65 (best effort)",
            "noaa-apt": "NOAA APT weather-satellite image decoding",
            "wxtoimg":  "NOAA APT weather-satellite image decoding",
        }
        for tool, modes in advanced.items():
            if tool_available(tool):
                self.results["warnings"].append(
                    f"{tool} is installed ({modes}) but has no batch-decode CLI contract "
                    "this pipeline integrates with yet — not run automatically"
                )
            else:
                self.results["warnings"].append(
                    f"{tool} not found — {modes} decoding skipped"
                )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_multimon_output(out: str, marker: str) -> List[str]:
        """
        Return only lines that contain the given marker AND are not
        multimon-ng startup banner lines.
        """
        lines = []
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if any(stripped.startswith(p) for p in _MULTIMON_BANNER_PREFIXES):
                continue
            if marker in line:
                lines.append(line)
        return lines
