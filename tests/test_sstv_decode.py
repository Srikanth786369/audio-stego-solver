"""
Regression tests for audio_stego.sstv_decode — the custom SSTV image
decoder engine (v4.1).

Since no hardware-recorded SSTV WAV files are available in this
environment, correctness is verified by round-trip: a test-only reference
encoder (tests/sstv_test_vectors.py, NOT shipped in audio_stego/) generates
a synthetic WAV from a known test image per mode family, the real decoder
in audio_stego/sstv_decode.py decodes it, and the result is compared back
to the source image with a documented similarity threshold. A round-trip
failure here indicates an actual decoder bug.
"""

import numpy as np
import pytest

from audio_stego.sstv_decode import MODES, decode_image, validate_decoded_image
from tests.sstv_test_vectors import encode_sstv, make_test_image


def _mean_abs_error(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.mean(np.abs(a.astype(np.float64) - b.astype(np.float64))))


class TestSSTVDecodeRoundTrip:
    """One representative mode per family, kept at 320px width and a low
    (but still SSTV-valid — well above the 2300 Hz white level) 8 kHz
    sample rate to keep test runtime reasonable."""

    @pytest.mark.parametrize("mode_name", [
        "Martin M2", "Scottie S2", "Robot 36", "Robot 72", "PD90",
        "Wraase SC-2 120", "Wraase SC-2 180", "Pasokon P3", "Pasokon P5", "Pasokon P7",
        "Robot 8 B/W",
    ])
    def test_round_trip_reconstructs_recognizable_image(self, mode_name):
        spec = MODES[mode_name]
        sr = 8000
        img = make_test_image(spec.width, spec.height)
        compare_to = img
        if spec.family == "robot8bw":
            # Robot 8 B/W transmits luma only — compare against the
            # grayscale-broadcast source, not the full-color original, since
            # losing color entirely is the format's real behavior, not a
            # decoder bug. Real line-doubling also means both output rows
            # of each pair must come from the same transmitted line.
            img = img.copy()
            img[1::2] = img[0::2]
            gray = img.mean(axis=2, keepdims=True).astype(np.uint8)
            compare_to = np.repeat(gray, 3, axis=2)
        audio, vis_end = encode_sstv(img, mode_name, sr=sr)

        decoded, sync_positions, freq = decode_image(audio, sr, mode_name, vis_end)

        assert decoded.shape == (spec.height, spec.width, 3)

        err = _mean_abs_error(decoded, compare_to)
        # Direct-RGB families (Martin/Scottie/Wraase/Pasokon) should be
        # near-exact; YCbCr families and B/W-with-averaged-color-diff
        # comparisons lose some accuracy — both thresholds are well below
        # "unrecognizable" (127 = random guess).
        threshold = 20.0 if spec.family in ("martin", "scottie", "wraase", "pasokon") else 35.0
        assert err < threshold, f"{mode_name}: mean abs error {err:.1f} >= {threshold}"

        validation = validate_decoded_image(decoded, spec, sync_positions, sr, vis_parity_ok=True)
        assert validation.accepted, f"{mode_name}: decoded image rejected: {validation.reasons}"
        assert validation.confidence > 0.5

    def test_slant_correction_reduces_clock_drift_error(self):
        """
        Regression: the per-line sync locator re-anchors at the start of
        every line (correcting *where* each line begins even under clock
        drift), but each family decoder previously sampled *within* a line
        using the mode's fixed nominal millisecond durations regardless of
        the true playback rate — a constant clock-rate mismatch (e.g. a
        receiver's sample clock running a few percent off nominal) causes
        exactly the progressive intra-line skew classic SSTV tooling calls
        "slant", and it was not corrected at all. Verified directly: at 5%
        clock drift, Martin M2's mean abs error was 48.1/255 before adding
        _measure_rate_scale's global rate correction, dropped to <35/255
        after. This asserts the post-fix bound so a regression here is
        caught immediately.
        """
        from scipy.signal import resample
        mode_name = "Martin M2"
        spec = MODES[mode_name]
        sr = 8000
        img = make_test_image(spec.width, spec.height)
        audio, vis_end = encode_sstv(img, mode_name, sr=sr)

        factor = 1.05  # 5% clock-rate mismatch
        n_new = int(len(audio) / factor)
        drifted = resample(audio, n_new)
        vis_end_drift = int(vis_end / factor)

        decoded, sync_positions, _ = decode_image(drifted, sr, mode_name, vis_end_drift)
        err = _mean_abs_error(decoded, img)
        assert err < 35.0, f"Slant-corrected 5% drift MAE {err:.1f} regressed past the fixed bound"

    def test_measure_rate_scale_detects_drift(self):
        """Direct unit check on the rate-scale measurement itself."""
        from audio_stego.sstv_decode import _measure_rate_scale
        sr = 8000
        nominal_period_samples = sr * 0.4  # 400ms nominal line time
        # Syncs 5% further apart than nominal -> observed/expected = 1.05
        syncs = [int(i * nominal_period_samples * 1.05) for i in range(20)]
        scale = _measure_rate_scale(syncs, sr, line_time_ms=400.0)
        assert abs(scale - 1.05) < 0.01

    def test_measure_rate_scale_clamped_to_sane_bounds(self):
        """An absurd/garbage sync sequence must not produce an unbounded
        scale factor that could make the decode worse, not better."""
        from audio_stego.sstv_decode import _measure_rate_scale
        sr = 8000
        syncs = [0, sr * 100]  # wildly implausible single interval
        scale = _measure_rate_scale(syncs, sr, line_time_ms=400.0)
        assert 0.85 <= scale <= 1.15

    def test_round_trip_sync_regularity_is_high(self):
        """Sync positions found during decode must be evenly spaced —
        confirms the drift-tracking sync locator, not just the pixel values."""
        spec = MODES["Martin M2"]
        sr = 8000
        img = make_test_image(spec.width, spec.height)
        audio, vis_end = encode_sstv(img, "Martin M2", sr=sr)
        _, sync_positions, _ = decode_image(audio, sr, "Martin M2", vis_end)
        assert len(sync_positions) == spec.height
        intervals = np.diff(sync_positions)
        expected = sr * spec.line_time_ms / 1000.0
        rel_dev = np.abs(intervals - expected) / expected
        assert np.mean(rel_dev) < 0.05


class TestSSTVConfidenceReflectsQuality:
    def test_confidence_drops_with_additive_noise(self):
        """
        Regression: confidence was previously computed only from
        sync_regularity/line_continuity/saturation — all aggregate signals
        that additive per-pixel noise barely disturbs. Verified directly:
        sweeping SNR from clean down to 10dB (mean abs error against the
        source image rising from 3.8 to 45.6/255, a genuinely degraded
        image) left confidence pinned at a constant 0.95 throughout. A
        pixel_smoothness metric (within-row adjacent-pixel smoothness, the
        horizontal counterpart of the existing vertical line_continuity
        check) now must pull confidence down as noise increases.
        """
        mode_name = "Martin M2"
        spec = MODES[mode_name]
        sr = 8000
        img = make_test_image(spec.width, spec.height)
        audio, vis_end = encode_sstv(img, mode_name, sr=sr)

        rng = np.random.default_rng(1)
        sig_power = np.mean(audio ** 2)
        confidences = []
        for snr_db in [30, 10]:
            noise_power = sig_power / (10 ** (snr_db / 10))
            noisy = audio + rng.normal(0, np.sqrt(noise_power), len(audio))
            decoded, syncs, _ = decode_image(noisy, sr, mode_name, vis_end)
            v = validate_decoded_image(decoded, spec, syncs, sr, vis_parity_ok=True)
            confidences.append(v.confidence)

        assert confidences[1] < confidences[0], (
            f"Confidence must drop as noise increases, got {confidences} "
            f"for SNR=[30dB, 10dB]"
        )
        assert confidences[1] <= 0.90, (
            f"10dB-SNR (genuinely degraded) decode must not keep the same "
            f"near-max confidence as a clean decode, got {confidences[1]}"
        )


class TestSSTVValidation:
    def test_rejects_pure_noise(self):
        """A signal with no real SSTV structure at all must be rejected,
        never mistaken for a decoded (if noisy) image."""
        spec = MODES["Martin M2"]
        sr = 8000
        rng = np.random.default_rng(3)
        noise = rng.uniform(-1, 1, int(sr * 5))
        decoded, sync_positions, freq = decode_image(noise, sr, "Martin M2", vis_end_sample=0)
        validation = validate_decoded_image(decoded, spec, sync_positions, sr, vis_parity_ok=True)
        assert not validation.accepted
        assert validation.confidence == 0.0
        assert validation.reasons

    def test_rejects_on_failed_vis_parity(self):
        """Even a clean, well-formed image must be rejected if the VIS
        parity check failed upstream — mode identification itself is
        unreliable, so nothing downstream can be trusted either."""
        spec = MODES["Martin M2"]
        sr = 8000
        img = make_test_image(spec.width, spec.height)
        audio, vis_end = encode_sstv(img, "Martin M2", sr=sr)
        decoded, sync_positions, _ = decode_image(audio, sr, "Martin M2", vis_end)
        validation = validate_decoded_image(decoded, spec, sync_positions, sr, vis_parity_ok=False)
        assert not validation.accepted
        assert any("parity" in r.lower() for r in validation.reasons)

    def test_rejects_dimension_mismatch(self):
        spec = MODES["Martin M2"]
        bad_img = np.zeros((10, 10, 3), dtype=np.uint8)
        validation = validate_decoded_image(bad_img, spec, [0, 1000], 8000, vis_parity_ok=True)
        assert not validation.accepted
        assert "Dimension mismatch" in validation.reasons[0]

    def test_rejects_blank_image(self):
        """A uniform (blank/silent) image has near-zero pixel entropy and
        must not be reported as a decoded image."""
        spec = MODES["Martin M2"]
        blank = np.full((spec.height, spec.width, 3), 128, dtype=np.uint8)
        sync_positions = list(range(0, spec.height * 1000, 1000))
        validation = validate_decoded_image(blank, spec, sync_positions, 8000, vis_parity_ok=True)
        assert not validation.accepted
        assert any("entropy" in r.lower() for r in validation.reasons)


class TestSSTVModeTable:
    def test_all_spec_required_modes_present(self):
        """Every mode named in the v4.1 spec (Martin M1/M2, Scottie S1/S2/DX,
        Robot 36/72, PD50/90/120/160/180/240/290 = 14 modes) plus the v4.5.2
        additions (Wraase SC-2 120/180, Pasokon P3/P5/P7, Robot 8 B/W = 6
        modes) has a real decoder implementation."""
        expected = {
            "Martin M1", "Martin M2", "Scottie S1", "Scottie S2", "Scottie DX",
            "Robot 36", "Robot 72",
            "PD50", "PD90", "PD120", "PD160", "PD180", "PD240", "PD290",
            "Wraase SC-2 120", "Wraase SC-2 180",
            "Pasokon P3", "Pasokon P5", "Pasokon P7",
            "Robot 8 B/W",
        }
        assert expected == set(MODES.keys())

    def test_vis_wired_modes_have_codes_in_valid_range(self):
        for name, spec in MODES.items():
            if spec.vis_code is not None:
                assert 0 <= spec.vis_code <= 127, f"{name}: VIS code out of 7-bit range"

    def test_vis_codes_are_unique(self):
        codes = [spec.vis_code for spec in MODES.values() if spec.vis_code is not None]
        assert len(codes) == len(set(codes)), "Duplicate VIS code assigned to two different modes"

    def test_vis_codes_match_cross_verified_reference_table(self):
        """
        Regression (v4.5.2): Robot 72 was wired to VIS 0x44, which is not a
        real SSTV VIS code — corrected to 0x0C. PD240/PD290 were transposed
        with PD160/PD180's correct codes. All four (plus newly-wired PD50/
        PD160/PD180) are cross-verified against two independent, mutually
        agreeing open-source SSTV codec implementations: windytan/slowrx's
        modespec.c VISmap table and rimio/libsstv's mode enum (its values
        are VIS+parity; masking off bit 7 gives the raw 7-bit VIS code).
        """
        expected = {
            "Robot 72": 0x0C, "Martin M1": 0x2C, "Martin M2": 0x28,
            "Scottie S1": 0x3C, "Scottie S2": 0x38, "Scottie DX": 0x4C,
            "PD50": 0x5D, "PD90": 0x63, "PD120": 0x5F, "PD160": 0x62,
            "PD180": 0x60, "PD240": 0x61, "PD290": 0x5E,
        }
        for name, code in expected.items():
            assert MODES[name].vis_code == code, (
                f"{name}: expected VIS 0x{code:02X}, got "
                f"{MODES[name].vis_code and hex(MODES[name].vis_code)}"
            )
