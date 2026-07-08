"""
Test-only reference SSTV encoder (NOT shipped in audio_stego/).

Used purely to generate synthetic WAV test vectors so audio_stego.sstv_decode
can be verified by round-trip (encode a known test image -> decode -> compare)
instead of assumed correct — this project has no hardware-recorded SSTV
files to test against, so this is the actual correctness check for the
decoder engine. Mirrors the exact per-family segment structure the decoder
in audio_stego/sstv_decode.py assumes (same constants, same segment order),
so a round-trip failure here means a real decoder bug, not a mismatched
test fixture.
"""

from __future__ import annotations

from typing import Tuple

import numpy as np

from audio_stego.sstv_decode import (
    BLACK_HZ,
    SYNC_HZ,
    WHITE_HZ,
    MODES,
    ModeSpec,
    _MARTIN_GAP_MS,
    _MARTIN_SYNC_MS,
    _PD_PORCH_MS,
    _PD_SYNC_MS,
    _ROBOT_PORCH_MS,
    _ROBOT_SEP_MS,
    _ROBOT_SYNC_MS,
    _SCOTTIE_SEP_MS,
    _SCOTTIE_SYNC_MS,
    _WRAASE_PORCH_MS,
    _WRAASE_SYNC_MS,
    _PASOKON_PORCH_MS,
    _PASOKON_SEP_MS,
    _PASOKON_SYNC_MS,
    _ROBOT8BW_SYNC_MS,
)

# VIS preamble timing — identical constants to audio_stego.sstv's real
# Goertzel-based VIS detector, so a VIS code embedded by this encoder is
# actually detectable by the production detect_vis_code() function.
_LEADER_S = 0.300
_BREAK_S = 0.010
_START_BIT_S = 0.030
_DATA_BIT_S = 0.030
_LEADER_HZ = 1900.0
_VIS_SYNC_HZ = 1200.0
_BIT0_HZ = 1300.0
_BIT1_HZ = 1100.0


def make_test_image(width: int, height: int) -> np.ndarray:
    """Deterministic gradient/checker test image — has real spatial
    structure (entropy + line-to-line continuity) unlike flat noise."""
    x = np.linspace(0, 255, width)
    y = np.linspace(0, 255, height)
    xv, yv = np.meshgrid(x, y)
    r = xv
    g = yv
    b = (xv + yv) / 2.0
    # Add a coarse checker pattern so channels aren't perfectly correlated.
    checker = (((xv // 32).astype(int) + (yv // 32).astype(int)) % 2) * 40
    r = np.clip(r + checker, 0, 255)
    return np.stack([r, g, b], axis=-1).astype(np.uint8)


def _tone(freq_hz: float, n: int) -> np.ndarray:
    return np.full(max(n, 0), freq_hz, dtype=np.float64)


def _scan(levels: np.ndarray, px_dur_s: float, sr: int) -> np.ndarray:
    """
    Render one channel-scan segment. Allocates the segment's TOTAL sample
    count once (from the segment's total nominal duration) and distributes
    pixels evenly across it, rather than rounding each pixel's duration
    independently and repeating — the latter compounds rounding error across
    every pixel in the segment (e.g. at low sample rates a ~0.23ms/pixel
    dwell time can round up to a whole extra sample per pixel, inflating the
    *entire segment* by ~9%, which then throws off the decoder's sync-to-sync
    period prediction). This keeps total segment duration matched to what
    the decoder expects regardless of sample rate.
    """
    n_pixels = len(levels)
    total_n = max(n_pixels, int(round(sr * px_dur_s * n_pixels)))
    freqs = BLACK_HZ + (np.clip(levels, 0, 255) / 255.0) * (WHITE_HZ - BLACK_HZ)
    edges = np.linspace(0, total_n, n_pixels + 1).astype(int)
    out = np.empty(total_n, dtype=np.float64)
    for i in range(n_pixels):
        a, b = edges[i], edges[i + 1]
        if b <= a:
            b = a + 1
        out[a:min(b, total_n)] = freqs[i]
    return out


def _ms_n(ms: float, sr: int) -> int:
    return max(1, int(round(sr * ms / 1000.0)))


def build_vis_preamble_freqs(vis_code: int, sr: int) -> np.ndarray:
    bits = [(vis_code >> i) & 1 for i in range(7)]
    parity = sum(bits) % 2
    segs = [
        _tone(_LEADER_HZ, _ms_n(_LEADER_S * 1000, sr)),
        _tone(_VIS_SYNC_HZ, _ms_n(_BREAK_S * 1000, sr)),
        _tone(_LEADER_HZ, _ms_n(_LEADER_S * 1000, sr)),
        _tone(_VIS_SYNC_HZ, _ms_n(_START_BIT_S * 1000, sr)),
    ]
    for b in bits:
        segs.append(_tone(_BIT1_HZ if b else _BIT0_HZ, _ms_n(_DATA_BIT_S * 1000, sr)))
    segs.append(_tone(_BIT1_HZ if parity else _BIT0_HZ, _ms_n(_DATA_BIT_S * 1000, sr)))
    segs.append(_tone(_VIS_SYNC_HZ, _ms_n(_START_BIT_S * 1000, sr)))
    return np.concatenate(segs)


def _rgb_to_ycbcr(r, g, b):
    y = 0.299 * r + 0.587 * g + 0.114 * b
    cb = 128.0 - 0.168736 * r - 0.331264 * g + 0.5 * b
    cr = 128.0 + 0.5 * r - 0.418688 * g - 0.081312 * b
    return y, cb, cr


def _encode_martin(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    ct_ms = (spec.line_time_ms - _MARTIN_SYNC_MS - 4 * _MARTIN_GAP_MS) / 3.0
    px_dur = ct_ms / 1000.0 / spec.width
    sync_n, gap_n = _ms_n(_MARTIN_SYNC_MS, sr), _ms_n(_MARTIN_GAP_MS, sr)
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        segs += [_tone(SYNC_HZ, sync_n), _tone(BLACK_HZ, gap_n),
                 _scan(g, px_dur, sr), _tone(BLACK_HZ, gap_n),
                 _scan(b, px_dur, sr), _tone(BLACK_HZ, gap_n),
                 _scan(r, px_dur, sr), _tone(BLACK_HZ, gap_n)]
    return np.concatenate(segs)


def _encode_scottie(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    ct_ms = (spec.line_time_ms - _SCOTTIE_SYNC_MS - 2 * _SCOTTIE_SEP_MS) / 3.0
    px_dur = ct_ms / 1000.0 / spec.width
    sync_n, sep_n = _ms_n(_SCOTTIE_SYNC_MS, sr), _ms_n(_SCOTTIE_SEP_MS, sr)
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        segs += [_scan(g, px_dur, sr), _tone(BLACK_HZ, sep_n),
                 _scan(b, px_dur, sr), _tone(SYNC_HZ, sync_n),
                 _scan(r, px_dur, sr), _tone(BLACK_HZ, sep_n)]
    return np.concatenate(segs)


def _encode_robot36(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    half_w = spec.width // 2
    px_dur_y = 0.088 / spec.width
    px_dur_c = 0.044 / half_w
    sync_n, porch_n, sep_n = (_ms_n(_ROBOT_SYNC_MS, sr), _ms_n(_ROBOT_PORCH_MS, sr),
                              _ms_n(_ROBOT_SEP_MS, sr))
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        y, cb, cr = _rgb_to_ycbcr(r, g, b)
        chroma = cr if row % 2 == 0 else cb
        chroma_half = chroma.reshape(half_w, 2).mean(axis=1)
        segs += [_tone(SYNC_HZ, sync_n), _tone(BLACK_HZ, porch_n),
                 _scan(y, px_dur_y, sr), _tone(BLACK_HZ, sep_n),
                 _scan(chroma_half, px_dur_c, sr)]
    return np.concatenate(segs)


def _encode_robot72(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    half_w = spec.width // 2
    px_dur_y = 0.138 / spec.width
    px_dur_c = 0.069 / half_w
    sync_n, porch_n, sep_n = (_ms_n(_ROBOT_SYNC_MS, sr), _ms_n(_ROBOT_PORCH_MS, sr),
                              _ms_n(_ROBOT_SEP_MS, sr))
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        y, cb, cr = _rgb_to_ycbcr(r, g, b)
        cr_half = cr.reshape(half_w, 2).mean(axis=1)
        cb_half = cb.reshape(half_w, 2).mean(axis=1)
        segs += [_tone(SYNC_HZ, sync_n), _tone(BLACK_HZ, porch_n),
                 _scan(y, px_dur_y, sr), _tone(BLACK_HZ, sep_n),
                 _scan(cr_half, px_dur_c, sr), _tone(BLACK_HZ, sep_n),
                 _scan(cb_half, px_dur_c, sr)]
    return np.concatenate(segs)


def _encode_pd(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    seg_ms = (spec.line_time_ms - _PD_SYNC_MS - _PD_PORCH_MS) / 4.0
    px_dur = seg_ms / 1000.0 / spec.width
    sync_n, porch_n = _ms_n(_PD_SYNC_MS, sr), _ms_n(_PD_PORCH_MS, sr)
    segs = []
    for pair in range(spec.height // 2):
        row0, row1 = pair * 2, pair * 2 + 1
        r0, g0, b0 = (img[row0, :, i].astype(np.float64) for i in range(3))
        r1, g1, b1 = (img[row1, :, i].astype(np.float64) for i in range(3))
        y1, _, _ = _rgb_to_ycbcr(r0, g0, b0)
        y2, _, _ = _rgb_to_ycbcr(r1, g1, b1)
        _, cb, cr = _rgb_to_ycbcr((r0 + r1) / 2, (g0 + g1) / 2, (b0 + b1) / 2)
        segs += [_tone(SYNC_HZ, sync_n), _tone(BLACK_HZ, porch_n),
                 _scan(y1, px_dur, sr), _scan(cr, px_dur, sr),
                 _scan(cb, px_dur, sr), _scan(y2, px_dur, sr)]
    return np.concatenate(segs)


def _encode_wraase(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    ct_ms = (spec.line_time_ms - _WRAASE_SYNC_MS - _WRAASE_PORCH_MS) / 3.0
    px_dur = ct_ms / 1000.0 / spec.width
    sync_n, porch_n = _ms_n(_WRAASE_SYNC_MS, sr), _ms_n(_WRAASE_PORCH_MS, sr)
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        segs += [_tone(SYNC_HZ, sync_n), _tone(BLACK_HZ, porch_n),
                 _scan(r, px_dur, sr), _scan(g, px_dur, sr), _scan(b, px_dur, sr)]
    return np.concatenate(segs)


def _encode_pasokon(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    sync_ms = _PASOKON_SYNC_MS[spec.name]
    porch_ms = _PASOKON_PORCH_MS[spec.name]
    sep_ms = _PASOKON_SEP_MS[spec.name]
    ct_ms = (spec.line_time_ms - sync_ms - 2 * porch_ms - 2 * sep_ms) / 3.0
    px_dur = ct_ms / 1000.0 / spec.width
    sync_n, porch_n, sep_n = _ms_n(sync_ms, sr), _ms_n(porch_ms, sr), _ms_n(sep_ms, sr)
    segs = []
    for row in range(spec.height):
        r, g, b = (img[row, :, i].astype(np.float64) for i in range(3))
        segs += [_tone(BLACK_HZ, porch_n), _scan(r, px_dur, sr), _tone(BLACK_HZ, sep_n),
                 _scan(g, px_dur, sr), _tone(BLACK_HZ, sep_n), _scan(b, px_dur, sr),
                 _tone(BLACK_HZ, porch_n), _tone(SYNC_HZ, sync_n)]
    return np.concatenate(segs)


def _encode_robot8bw(img: np.ndarray, spec: ModeSpec, sr: int) -> np.ndarray:
    y_ms = spec.line_time_ms - _ROBOT8BW_SYNC_MS
    px_dur = y_ms / 1000.0 / spec.width
    sync_n = _ms_n(_ROBOT8BW_SYNC_MS, sr)
    segs = []
    for pair in range(spec.height // 2):
        # Both duplicated output rows come from the same transmitted line —
        # use row0's luma (they're pixel-identical in a real line-doubled
        # source image, but average defensively in case the test image
        # generator ever produces non-identical row pairs).
        row0, row1 = pair * 2, pair * 2 + 1
        y = img[row0, :, :].astype(np.float64).mean(axis=-1)
        segs += [_tone(SYNC_HZ, sync_n), _scan(y, px_dur, sr)]
    return np.concatenate(segs)


_ENCODERS = {
    "martin": _encode_martin,
    "scottie": _encode_scottie,
    "robot36": _encode_robot36,
    "robot72": _encode_robot72,
    "pd": _encode_pd,
    "wraase": _encode_wraase,
    "pasokon": _encode_pasokon,
    "robot8bw": _encode_robot8bw,
}


def encode_sstv(img: np.ndarray, mode_name: str, sr: int = 8000) -> Tuple[np.ndarray, int]:
    """
    Encode `img` (must match the mode's exact HxWx3 shape) as continuous-
    phase FM audio for the given SSTV mode, prefixed with a real VIS
    preamble (using the mode's vis_code if wired, else a placeholder 0 —
    the round-trip test passes the mode name to the decoder explicitly and
    doesn't rely on VIS lookup for modes that aren't auto-dispatched yet).

    Returns (samples, vis_end_sample) — samples is a float64 waveform in
    [-1, 1]; vis_end_sample is the sample index where the VIS preamble ends
    (what audio_stego.sstv_decode.decode_image expects as its anchor).
    """
    spec = MODES[mode_name]
    if img.shape != (spec.height, spec.width, 3):
        raise ValueError(f"Test image shape {img.shape} != mode shape {(spec.height, spec.width, 3)}")

    vis_code = spec.vis_code if spec.vis_code is not None else 0
    lead_in = _tone(BLACK_HZ, int(sr * 0.1))
    vis_freqs = build_vis_preamble_freqs(vis_code, sr)
    line_freqs = _ENCODERS[spec.family](img, spec, sr)

    vis_end_sample = len(lead_in) + len(vis_freqs)
    freq_track = np.concatenate([lead_in, vis_freqs, line_freqs])
    phase = 2.0 * np.pi * np.cumsum(freq_track) / sr
    audio = 0.85 * np.sin(phase)
    return audio, vis_end_sample
