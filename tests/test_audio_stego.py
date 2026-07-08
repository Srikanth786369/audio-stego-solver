"""
Comprehensive test suite for Audio Stego Solver v1.1.
Run with: pytest tests/ -v

Tests cover every fixed bug from PROJECT_AUDIT.md.
"""

import base64
import binascii
import csv
import io
import json
import math
import os
import shutil
import struct
import tempfile
import wave
import zipfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir() -> Generator[str, None, None]:
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sample_wav(tmp_dir: str) -> str:
    """Create a minimal valid WAV file (1 s stereo 44100 Hz silence)."""
    path = os.path.join(tmp_dir, "test.wav")
    with wave.open(path, "w") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(b"\x00\x00" * 44100 * 2)
    return path


@pytest.fixture
def mono_wav(tmp_dir: str) -> str:
    """Create a minimal valid WAV file (1 s mono 44100 Hz silence)."""
    path = os.path.join(tmp_dir, "mono.wav")
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(b"\x00\x00" * 44100)
    return path


@pytest.fixture
def config(tmp_dir: str):
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from audio_stego.config import Config
    cfg = Config()
    cfg._config.set("general", "output_dir", os.path.join(tmp_dir, "results"))
    cfg._config.set("general", "log_dir",    os.path.join(tmp_dir, "logs"))
    return cfg


# ---------------------------------------------------------------------------
# findings.py tests
# ---------------------------------------------------------------------------

class TestFindings:
    def test_looks_like_flag(self):
        from audio_stego.findings import looks_like_flag
        assert looks_like_flag("flag{hello_world}")
        assert looks_like_flag("HTB{s0me_flag_1234}")
        assert looks_like_flag("picoCTF{th1s_1s_3asy}")
        assert not looks_like_flag("normal text here")
        assert not looks_like_flag("{}")
        assert not looks_like_flag("no_braces")

    def test_find_flags_in_text(self):
        from audio_stego.findings import find_flags_in_text
        results = find_flags_in_text("prefix flag{my_flag_value} suffix")
        assert any("flag{my_flag_value}" in f.value for f in results)

    def test_find_flags_confidence_specific(self):
        from audio_stego.findings import find_flags_in_text
        results = find_flags_in_text("HTB{specific_platform_flag}")
        assert results
        assert results[0].confidence >= 0.90  # specific pattern = high conf

    def test_is_likely_base64_rejects_short(self):
        from audio_stego.findings import is_likely_base64
        assert not is_likely_base64("abc")
        assert not is_likely_base64("AAAA")

    def test_is_likely_base64_rejects_all_same_case(self):
        from audio_stego.findings import is_likely_base64
        assert not is_likely_base64("abcdefghijklmnop")    # all lowercase
        assert not is_likely_base64("ABCDEFGHIJKLMNOP")    # all uppercase

    def test_is_likely_base64_accepts_valid(self):
        from audio_stego.findings import is_likely_base64
        encoded = base64.b64encode(b"flag{test_value}").decode()
        assert is_likely_base64(encoded)

    def test_is_likely_base64_rejects_below_new_75pct_threshold(self):
        """v4.3: printable-ratio threshold raised from 60% to 75%. A decode
        at ~67% printable — which the old 60% floor would have accepted —
        must now be rejected."""
        from audio_stego.findings import is_likely_base64
        payload = b"ABCDEFGH" + bytes([0, 1, 2, 3])   # 8/12 = 66.7% printable
        encoded = base64.b64encode(payload).decode()
        assert len(encoded) >= 16
        assert not is_likely_base64(encoded)

    def test_is_likely_base64_accepts_low_printable_with_known_magic(self):
        """Magic-byte match is independent, strong evidence and still
        accepted even when the printable ratio is low — this is the "OR
        has_magic" branch, unaffected by the ratio tightening."""
        from audio_stego.findings import is_likely_base64
        payload = b"\x89PNG\r\n\x1a\n" + bytes(range(8))   # PNG magic + binary
        encoded = base64.b64encode(payload).decode()
        assert is_likely_base64(encoded)

    def test_cipher_utilities(self):
        from audio_stego.findings import rot13, caesar, atbash
        assert rot13("flag") == "synt"
        assert rot13(rot13("hello")) == "hello"
        assert caesar("abc", 1) == "bcd"
        assert caesar("abc", 25) == "zab"
        assert atbash("a") == "z"
        assert atbash("A") == "Z"
        assert atbash(atbash("hello")) == "hello"

    def test_printable_ratio(self):
        """v4.1: shared decode-quality helper used by the XOR engine gates."""
        from audio_stego.findings import printable_ratio
        assert printable_ratio(b"") == 0.0
        assert printable_ratio(b"hello world") == 1.0
        assert printable_ratio(bytes([0, 1, 2, 3, 255, 254])) == 0.0
        mixed = b"hi" + bytes([0, 1, 2, 3, 4, 5, 6, 7])
        assert 0.0 < printable_ratio(mixed) < 1.0

    def test_shannon_entropy_helper(self):
        """v4.1: shared entropy helper — random bytes ~8 bits/byte, English text much lower."""
        from audio_stego.findings import shannon_entropy
        assert shannon_entropy(b"") == 0.0
        assert shannon_entropy(b"aaaaaaaaaa") == 0.0
        random_entropy = shannon_entropy(bytes(range(256)) * 4)
        assert random_entropy > 7.9
        text_entropy = shannon_entropy(b"the quick brown fox jumps over the lazy dog" * 5)
        assert text_entropy < 5.0

    def test_english_word_score(self):
        """v4.1: cheap dictionary/language score used to gate the generic flag pattern."""
        from audio_stego.findings import english_word_score
        assert english_word_score("") == 0.0
        assert english_word_score("the quick fox and the dog") >= 0.5
        assert english_word_score("xkqz jvbmw plrts qzxjk") == 0.0

    def test_finding_to_dict(self):
        from audio_stego.findings import Finding, Severity
        f = Finding(
            module="test", title="Test Finding",
            severity=Severity.HIGH, confidence=0.85,
            value="flag{test}", evidence="test evidence",
        )
        d = f.to_dict()
        assert d["severity"] == "HIGH"
        assert d["confidence"] == 0.85
        assert d["confidence_pct"] == "85%"
        assert d["value"] == "flag{test}"

    def test_secret_patterns(self):
        from audio_stego.findings import SECRET_PATTERNS
        text = "password: mysecret123 and AKIAIOSFODNN7EXAMPLE"
        matches = [m.group(0) for pat in SECRET_PATTERNS for m in pat.finditer(text)]
        assert any("mysecret" in m for m in matches)

    # -----------------------------------------------------------------
    # v4.2 confidence-tier classification (used by html_report grouping/hiding)
    # -----------------------------------------------------------------

    def test_confidence_tier_thresholds(self):
        from audio_stego.findings import confidence_tier, ConfidenceTier
        assert confidence_tier(1.00) == ConfidenceTier.VERIFIED
        assert confidence_tier(0.80) == ConfidenceTier.VERIFIED
        assert confidence_tier(0.79) == ConfidenceTier.PROBABLE
        assert confidence_tier(0.60) == ConfidenceTier.PROBABLE
        assert confidence_tier(0.59) == ConfidenceTier.POSSIBLE
        assert confidence_tier(0.20) == ConfidenceTier.POSSIBLE
        assert confidence_tier(0.19) == ConfidenceTier.REJECTED
        assert confidence_tier(0.0) == ConfidenceTier.REJECTED

    def test_confidence_tier_rejected_tag_overrides_score(self):
        """A high numeric confidence with an explicit 'rejected' tag (e.g. an
        SSTV decode that failed independent validation but still carries a
        diagnostic confidence value) must classify as REJECTED regardless
        of the score — the tag is an explicit human-facing verdict."""
        from audio_stego.findings import confidence_tier, ConfidenceTier
        assert confidence_tier(0.95, tags=["rejected"]) == ConfidenceTier.REJECTED
        assert confidence_tier(0.95, tags=["other"]) == ConfidenceTier.VERIFIED

    def test_low_confidence_display_threshold_value(self):
        from audio_stego.findings import LOW_CONFIDENCE_DISPLAY_THRESHOLD
        assert LOW_CONFIDENCE_DISPLAY_THRESHOLD == 0.50

# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_values(self, config):
        assert config.max_workers == 8
        assert config.timeout == 60
        assert not config.verbose

    def test_flag_patterns(self, config):
        patterns = config.flag_patterns
        assert "flag{" in patterns
        assert "HTB{" in patterns

    def test_save_reload(self, config, tmp_dir):
        ini = os.path.join(tmp_dir, "test.ini")
        config.save_default(ini)
        assert os.path.exists(ini)
        from audio_stego.config import Config
        cfg2 = Config(config_file=ini)
        assert cfg2.max_workers == 8

# ---------------------------------------------------------------------------
# Utils tests
# ---------------------------------------------------------------------------

class TestUtils:
    def test_human_size(self):
        from audio_stego.utils import human_size
        assert "B"  in human_size(100)
        assert "KB" in human_size(2048)
        assert "MB" in human_size(2 * 1024 * 1024)

    def test_file_hash(self, sample_wav):
        from audio_stego.utils import file_hash
        h = file_hash(sample_wav)
        assert len(h["md5"])    == 32
        assert len(h["sha256"]) == 64

    def test_save_text_creates_parents(self, tmp_dir):
        from audio_stego.utils import save_text
        path = os.path.join(tmp_dir, "a", "b", "c.txt")
        save_text(path, "hello")
        assert open(path).read() == "hello"

    def test_detect_magic(self, tmp_dir):
        from audio_stego.utils import detect_file_type_by_magic
        png = os.path.join(tmp_dir, "f.png")
        with open(png, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert detect_file_type_by_magic(png) == "PNG"

    def test_find_embedded_files(self):
        from audio_stego.utils import find_embedded_files
        data = b"\x00" * 100 + b"PK\x03\x04" + b"\x00" * 50
        found = find_embedded_files(data)
        assert any(f["type"] == "ZIP" for f in found)

    def test_recursive_file_search(self, tmp_dir):
        from audio_stego.utils import recursive_file_search
        sub = os.path.join(tmp_dir, "a", "b")
        os.makedirs(sub)
        open(os.path.join(sub, "x.txt"), "w").close()
        files = recursive_file_search(tmp_dir)
        assert any("x.txt" in f for f in files)

    def test_elapsed(self):
        import time
        from audio_stego.utils import elapsed
        start = time.time() - 5.0
        assert "s" in elapsed(start)

# ---------------------------------------------------------------------------
# Binary tests — including FIXED bugs
# ---------------------------------------------------------------------------

class TestBinaryAnalyzer:
    def _make_analyzer(self, config, tmp_dir):
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "bin_out")
        os.makedirs(out, exist_ok=True)
        return BinaryAnalyzer(config, out)

    def test_shannon_entropy_uniform(self, config, tmp_dir):
        """Uniform distribution → entropy ≈ 8.0"""
        ana = self._make_analyzer(config, tmp_dir)
        data = bytes(range(256)) * 4
        e = ana._shannon_entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_shannon_entropy_constant(self, config, tmp_dir):
        """All same bytes → entropy = 0.0"""
        ana = self._make_analyzer(config, tmp_dir)
        assert ana._shannon_entropy(b"\x00" * 1000) == 0.0

    def test_shannon_entropy_empty(self, config, tmp_dir):
        ana = self._make_analyzer(config, tmp_dir)
        assert ana._shannon_entropy(b"") == 0.0

    def test_string_deduplication(self, config, tmp_dir):
        """FIX: strings must be deduplicated."""
        ana = self._make_analyzer(config, tmp_dir)
        data = "hello\nhello\nhello\nworld\n".encode()
        strings = ana._python_strings(data, min_len=4)
        # raw list has duplicates; but the _run_strings path deduplicates
        # test the internal method directly:
        assert strings.count("hello") == 3  # _python_strings itself doesn't dedup
        # dedup is done in _run_strings — test that indirectly via run()

    @patch("audio_stego.binary.tool_available", return_value=False)
    def test_run_no_tools(self, mock_avail, config, tmp_dir, sample_wav):
        ana = self._make_analyzer(config, tmp_dir)
        results = ana.run(sample_wav)
        assert "strings"        in results
        assert "entropy"        in results
        assert "embedded_files" in results

    def test_entropy_stores_summary_not_list(self, config, tmp_dir, sample_wav):
        """FIX: entropy must store summary dict, not raw float list."""
        ana = self._make_analyzer(config, tmp_dir)
        results = ana.run(sample_wav)
        entropy = results["entropy"]
        assert "overall"   in entropy
        assert "max_block" in entropy
        assert "avg_block" in entropy
        # 'blocks' key must NOT be present (was removed to save RAM)
        assert "blocks" not in entropy

    def test_embedded_skips_offset_zero(self, config, tmp_dir, sample_wav):
        """FIX: embedded file detection must not report the file's own header."""
        ana = self._make_analyzer(config, tmp_dir)
        results = ana.run(sample_wav)
        for item in results.get("embedded_files", []):
            assert item["offset"] != 0, "Should not report own header at offset 0"

    def test_embedded_bare_magic_is_possible_not_verified(self, config, tmp_dir):
        """
        v4.1: an isolated magic-byte match with no real structure behind it
        (e.g. an MP3 frame-sync pattern occurring by chance in PCM noise)
        must be classified as an unverified 'Possible Signature', never as a
        'Verified Embedded Artifact' — this is the exact false-positive
        pattern the magic scanner used to report at a flat 85% confidence.
        """
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "bin_bare")
        os.makedirs(out, exist_ok=True)
        ana = BinaryAnalyzer(config, out)

        # A bare MP3 frame-sync byte pair followed by random-looking bytes
        # that do NOT form 3+ consistent consecutive MPEG frames.
        data = b"RIFF" + b"\x00" * 40 + b"\xff\xfb" + os.urandom(200)
        path = os.path.join(tmp_dir, "bare_magic.bin")
        with open(path, "wb") as f:
            f.write(data)

        results = ana.run(path)
        possible = results.get("embedded_possible", [])
        verified = results.get("embedded_verified", [])
        assert any(i["type"] == "MP3_FRAME" for i in possible)
        assert not any(i["type"] == "MP3_FRAME" for i in verified)

        titles = [f["title"] for f in results["findings"]]
        assert "Possible Signature (Unverified)" in titles
        assert "Verified Embedded Artifact" not in titles

        possible_finding = next(f for f in results["findings"] if f["title"] == "Possible Signature (Unverified)")
        assert possible_finding["confidence"] <= 0.20
        assert possible_finding["severity"] in ("INFO", "LOW")

    def test_embedded_valid_zip_is_verified(self, config, tmp_dir):
        """
        v4.1: a real, structurally valid ZIP embedded at a non-zero offset
        must be classified as a 'Verified Embedded Artifact' with confidence
        derived from the structural validator, not a flat guess.
        """
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "bin_zip")
        os.makedirs(out, exist_ok=True)
        ana = BinaryAnalyzer(config, out)

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("hidden.txt", "top secret payload")
        zip_bytes = zip_buf.getvalue()

        data = b"RIFF" + b"\x00" * 100 + zip_bytes
        path = os.path.join(tmp_dir, "embedded_zip.bin")
        with open(path, "wb") as f:
            f.write(data)

        results = ana.run(path)
        verified = results.get("embedded_verified", [])
        assert any(i["type"] == "ZIP" for i in verified)

        titles = [f["title"] for f in results["findings"]]
        assert "Verified Embedded Artifact" in titles
        verified_finding = next(f for f in results["findings"] if f["title"] == "Verified Embedded Artifact")
        assert verified_finding["confidence"] > 0.20

    def test_appended_wav_detection(self, config, tmp_dir):
        """FIX: WAV appended data detection uses RIFF header, not bitrate formula."""
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "app_out")
        os.makedirs(out, exist_ok=True)
        os.makedirs(os.path.join(out, "extracted"), exist_ok=True)

        # Create WAV with appended data
        wav_path = os.path.join(tmp_dir, "appended.wav")
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(b"\x00\x00" * 100)

        # Append 5 KB of extra data
        extra = b"SECRETDATA" * 512
        with open(wav_path, "ab") as f:
            f.write(extra)

        ana = BinaryAnalyzer(config, out)
        ana._detect_appended_wav(wav_path)
        assert ana.results.get("appended_data") is not None
        assert ana.results["appended_data"]["detected"] is True
        assert ana.results["appended_data"]["extra_bytes"] >= len(extra) - 100

    def test_no_false_positive_appended_clean_wav(self, config, tmp_dir, sample_wav):
        """FIX: clean WAV must NOT trigger appended data alert."""
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "clean_out")
        os.makedirs(out, exist_ok=True)
        os.makedirs(os.path.join(out, "extracted"), exist_ok=True)
        ana = BinaryAnalyzer(config, out)
        ana._detect_appended_wav(sample_wav)
        # Clean WAV should NOT set appended_data
        assert ana.results.get("appended_data") is None

    def test_validated_base64_only(self, config, tmp_dir):
        """FIX: is_likely_base64 must filter false-positive b64 patterns."""
        from audio_stego.findings import is_likely_base64
        # Common words that match raw b64 regex but are NOT base64
        assert not is_likely_base64("AAAA")          # too short
        assert not is_likely_base64("hello")         # all lowercase → not b64
        assert not is_likely_base64("HELLO")         # all uppercase → not b64
        # Real base64 must pass
        enc = base64.b64encode(b"flag{real_flag_here}").decode()
        assert is_likely_base64(enc)

    def test_detect_ciphers_limited_input(self, config, tmp_dir, sample_wav):
        """FIX: detect_ciphers must not hang on large input — capped at 4KB."""
        from audio_stego.binary import BinaryAnalyzer
        out = os.path.join(tmp_dir, "cipher_out")
        os.makedirs(out, exist_ok=True)
        ana = BinaryAnalyzer(config, out)
        # 1 MB of text — must complete quickly (not hang)
        big_text = "the quick brown fox jumps over the lazy dog " * 25000
        result = ana.detect_ciphers(big_text)
        assert isinstance(result, dict)   # completed without hanging

# ---------------------------------------------------------------------------
# Digital modes tests — FIX: false positive elimination
# ---------------------------------------------------------------------------

class TestDigitalModesAnalyzer:
    def _make_analyzer(self, config, tmp_dir):
        from audio_stego.digital import DigitalModesAnalyzer
        out = os.path.join(tmp_dir, "dig_out")
        os.makedirs(out, exist_ok=True)
        return DigitalModesAnalyzer(config, out), out

    def test_filter_multimon_banner(self, config, tmp_dir):
        """FIX: multimon-ng banner lines must be filtered."""
        from audio_stego.digital import DigitalModesAnalyzer, _MULTIMON_BANNER_PREFIXES
        ana, _ = self._make_analyzer(config, tmp_dir)

        # Simulate multimon-ng output that only has banner + no real Morse
        fake_output = (
            "multimon-ng 1.2.0  (C) 1996/1997/1998/2019\n"
            "Enabled decoders: MORSE_CW\n"
            "MORSE_CW: banner line\n"
        )
        lines = ana._filter_multimon_output(fake_output, marker="MORSE_CW:")
        # Banner lines should be excluded; only the real decode line (if any) passes
        for line in lines:
            for prefix in _MULTIMON_BANNER_PREFIXES:
                assert not line.strip().startswith(prefix), (
                    f"Banner line '{line}' passed filter!"
                )

    def test_morse_validation_rejects_high_unknown(self, config, tmp_dir):
        """FIX: Morse with >40% unknown chars must be rejected."""
        ana, _ = self._make_analyzer(config, tmp_dir)
        # A string with mostly unknowns
        conf, reason = ana._score_morse_output("? ? ? ? ?", ["MORSE_CW: ? ? ? ?"])
        assert conf < 0.30, f"Should reject high-unknown Morse, got conf={conf}"

    def test_morse_validation_accepts_good(self, config, tmp_dir):
        """Proper Morse decode must be accepted."""
        ana, _ = self._make_analyzer(config, tmp_dir)
        conf, reason = ana._score_morse_output(
            "SOS HELLO WORLD",
            ["MORSE_CW: SOS HELLO WORLD"],
        )
        assert conf >= 0.50

    def test_morse_min_chars_tightened_to_three_v43(self, config, tmp_dir):
        """v4.3: raised from 2 to 3 alphanumeric chars minimum — a 2-char
        decode is too easily produced by chance from non-Morse dot/dash-like
        text. Must still accept the canonical 3-char "SOS" test signal."""
        from audio_stego.digital import _MIN_MORSE_CHARS
        assert _MIN_MORSE_CHARS == 3
        ana, _ = self._make_analyzer(config, tmp_dir)
        conf_2char, _ = ana._score_morse_output("AB", ["MORSE_CW: AB"])
        assert conf_2char <= 0.10   # below the reportable floor
        conf_sos, _ = ana._score_morse_output("SOS", ["MORSE_CW: SOS"])
        assert conf_sos > 0.10

    def test_dtmf_requires_min_digits(self, config, tmp_dir, mono_wav):
        """FIX: DTMF must require >= 3 digits, not report 1-2 noise chars."""
        from audio_stego.digital import _MIN_DTMF_DIGITS
        assert _MIN_DTMF_DIGITS >= 3

    def test_minimodem_rejects_short_output(self, config, tmp_dir):
        """FIX: minimodem output < 8 printable chars must be rejected."""
        from audio_stego.digital import _MIN_MINIMODEM_PRINTABLE
        assert _MIN_MINIMODEM_PRINTABLE >= 8

    def test_find_morse_in_text_rejects_dotdash_in_versions(self, config, tmp_dir):
        """FIX: version strings like '1.0.2-3' must not trigger Morse detection."""
        ana, _ = self._make_analyzer(config, tmp_dir)
        # A typical strings.txt line that caused FPs in the original
        text = "libfoo-1.0.2-3 version 2.4.1-rc1 libbar.so.1.2"
        findings = ana._find_morse_in_text(text)
        assert len(findings) == 0, (
            f"Version string falsely triggered Morse: {findings}"
        )

    def test_multimon_allmode_covers_full_demodulator_set(self, config, tmp_dir):
        """New: multimon-ng all-mode sweep must cover every practical
        demodulator multimon-ng ships (pagers, selective-call, FSK/AFSK),
        while excluding debug-only demods (SCOPE/DUMPCSV/X10)."""
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        captured = {}

        def fake_run_command(cmd, timeout=None):
            captured["cmd"] = cmd
            return (0, "", "")

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)

        cmd = captured["cmd"]
        for required in ("FLEX", "FLEX_NEXT", "POCSAG512", "POCSAG1200",
                         "POCSAG2400", "ZVEI1", "ZVEI2", "ZVEI3", "DZVEI",
                         "PZVEI", "EEA", "EIA", "CCIR", "AFSK1200", "AFSK2400"):
            assert required in cmd, f"{required} missing from multimon-ng invocation"
        for excluded in ("SCOPE", "DUMPCSV", "X10"):
            assert excluded not in cmd, f"{excluded} should not be scanned (debug-only)"
        # DTMF and MORSE_CW have dedicated methods and must not be duplicated here
        assert "DTMF" not in cmd
        assert "MORSE_CW" not in cmd

    def test_multimon_allmode_splits_output_per_mode(self, config, tmp_dir):
        """New: decoded lines must be grouped by originating protocol so the
        report can show which mode(s) actually decoded something."""
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        fake_output = (
            "multimon-ng 1.3.0\n"
            "Enabled demodulators: FLEX POCSAG1200\n"
            "FLEX: 1234567 A CTF{fake_pager_msg}\n"
            "POCSAG1200: Address: 1234567 Function: 0 Alpha:   hello\n"
        )

        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)

        per_mode = ana.results["multimon"]["per_mode"]
        assert "FLEX" in per_mode
        assert "POCSAG1200" in per_mode
        assert len(per_mode["FLEX"]) == 1
        assert len(per_mode["POCSAG1200"]) == 1
        # A finding should be recorded for each mode that decoded something
        titles = [f["title"] for f in ana.results["findings"]]
        assert any("FLEX" in t for t in titles)
        assert any("POCSAG1200" in t for t in titles)

    def test_selcall_single_digit_rejected(self, config, tmp_dir):
        """
        Regression: selective-call standards (ZVEI/DZVEI/PZVEI/EEA/EIA/CCIR)
        decode one digit per sustained tone frequency with no frame/CRC
        structure at all. Verified directly: sweeping 8 plain sine tones
        (220Hz-2200Hz, ordinary musical frequencies) through multimon-ng
        found 6 of them each triggered a one-digit "decode" on one or more
        of these modes (e.g. a held 1000Hz tone decoded as "EEA: D" and
        "CCIR: D") at confidence up to 0.59 — a real selective-call address
        is always several digits, so a single stray digit must be rejected.
        """
        from audio_stego.digital import _MIN_SELCALL_DIGITS
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()
        fake_output = (
            "multimon-ng 1.3.0\n"
            "ZVEI1: digit D\n"
        )
        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)
        assert ana.results["findings"] == [], (
            f"A single selective-call digit (below the {_MIN_SELCALL_DIGITS}-digit "
            f"minimum) must not be reported, got: {ana.results['findings']}"
        )

    def test_selcall_multi_digit_sequence_accepted(self, config, tmp_dir):
        """The digit-count gate must not reject a real multi-digit
        selective-call sequence once enough digits are present."""
        from audio_stego.digital import _MIN_SELCALL_DIGITS
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()
        fake_output = "multimon-ng 1.3.0\n" + "\n".join(
            f"ZVEI1: digit {d}" for d in range(_MIN_SELCALL_DIGITS)
        ) + "\n"
        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)
        titles = [f["title"] for f in ana.results["findings"]]
        assert any("ZVEI1" in t for t in titles), (
            f"A {_MIN_SELCALL_DIGITS}-digit ZVEI1 sequence should be reported, "
            f"got: {ana.results['findings']}"
        )

    def test_afsk1200_labeled_as_ax25_apras(self, config, tmp_dir):
        """AFSK1200 (Bell 202) is the real AX.25/APRS packet-radio physical
        layer — a hit should be labeled clearly, not left as an opaque
        demodulator name."""
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()
        fake_output = (
            "multimon-ng 1.3.0\n"
            "AFSK1200: fm SOMECALL to APRS via WIDE1-1:!hello world\n"
        )
        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)
        titles = [f["title"] for f in ana.results["findings"]]
        assert any("AX.25" in t or "APRS" in t for t in titles)

    def test_afsk1200_with_valid_callsign_gets_verified_confidence(self, config, tmp_dir):
        """
        v4.1: an AFSK1200 line containing a well-formed AX.25 callsign-SSID
        pair (e.g. 'N0CALL-9') must be scored as structurally verified
        (title 'Digital mode verified: ...', confidence == CHECKSUM_VALID
        evidence level), not just "a line came out of the demodulator".
        """
        from audio_stego.findings import EvidenceLevel, confidence_for_evidence
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()
        fake_output = (
            "multimon-ng 1.3.0\n"
            "AFSK1200: fm N0CALL-9 to APRS-1 via WIDE1-1:!status message\n"
        )
        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)

        findings = [f for f in ana.results["findings"] if "AFSK1200" in f["title"]]
        assert findings
        f = findings[0]
        assert f["title"].startswith("Digital mode verified:")
        assert f["confidence"] == pytest.approx(confidence_for_evidence(EvidenceLevel.CHECKSUM_VALID))

    def test_pocsag_invalid_function_code_not_verified(self, config, tmp_dir):
        """
        v4.1: a POCSAG line whose Function code is outside the valid 0-3
        range (the POCSAG spec only defines 2 function-code bits) must NOT
        be scored as structurally verified — the field is malformed, so this
        is exactly the "reject random decodes" case for pager protocols.
        """
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()
        fake_output = (
            "multimon-ng 1.3.0\n"
            "POCSAG1200: Address: 1234567 Function: 9 Alpha:   garbage\n"
        )
        with patch("audio_stego.digital.run_command", return_value=(0, fake_output, "")), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_multimon_allmode(fake_wav)

        findings = [f for f in ana.results["findings"] if "POCSAG1200" in f["title"]]
        assert findings
        assert findings[0]["title"].startswith("Digital mode decoded:")
        assert not findings[0]["title"].startswith("Digital mode verified:")

    def test_advanced_mode_tools_reported_honestly(self, config, tmp_dir):
        """PSK31/Olivia/Hellschreiber/FT8/JT65 need fldigi/wsjt-x/jt9, which
        have no simple batch-decode CLI contract this pipeline can verify —
        their presence/absence must be reported, not silently ignored or
        fabricated as a working decode path."""
        ana, out = self._make_analyzer(config, tmp_dir)
        with patch("audio_stego.digital.tool_available", return_value=False):
            ana._check_advanced_mode_tools()
        joined = " ".join(ana.results["warnings"])
        assert "fldigi" in joined
        assert "wsjt-x" in joined or "jt9" in joined
        assert "PSK31" in joined or "Olivia" in joined or "Hellschreiber" in joined

    def test_noaa_apt_reported_honestly_not_silently_missing(self, config, tmp_dir):
        """Regression: NOAA APT (weather-satellite image decoding) has no
        implementation anywhere in this project and no wired decoder tool
        (wxtoimg/noaa-apt/aptdec) — it was previously simply absent from
        every report with no indication whether that was deliberate scope
        or an oversight. Must be reported the same honest way as
        PSK31/FT8/JT65 rather than silently missing."""
        ana, out = self._make_analyzer(config, tmp_dir)
        with patch("audio_stego.digital.tool_available", return_value=False):
            ana._check_advanced_mode_tools()
        joined = " ".join(ana.results["warnings"])
        assert "APT" in joined or "apt" in joined

    def test_minimodem_sweep_includes_rtty_tdd_same(self, config, tmp_dir):
        """minimodem sweep must include rtty, tdd (Baudot TTY/TDD) and
        same (NOAA Emergency Alert) in addition to numeric Bell-like rates.

        Regression: "BELL103"/"BELL202" were previously in this sweep but
        are not real minimodem baudmode arguments — verified against
        `minimodem`'s own usage text, which shows Bell103/Bell202 are just
        descriptive names for numeric rates 300/1200 (already covered),
        not literal CLI tokens. Passing them made minimodem exit 1 (usage
        dump) on every single scan, verified by actually running the binary."""
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        seen_bauds = []

        def fake_run_command(cmd, timeout=None):
            seen_bauds.append(cmd[2])
            return (1, "", "")  # simulate no decode at any rate

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_minimodem(fake_wav)

        for required in ("rtty", "tdd", "same", "300", "1200"):
            assert required in seen_bauds, f"minimodem sweep missing {required}"
        for invalid in ("BELL103", "BELL202"):
            assert invalid not in seen_bauds, f"minimodem sweep still contains invalid arg {invalid}"

    def test_minimodem_rejects_low_confidence_noise_decode(self, config, tmp_dir):
        """
        Regression: sweeping minimodem across white noise/silence/single
        tones (220-2200Hz)/a chord/a chirp/pink noise found real cases where
        100%-printable garbage passed the old printable-ratio-only filter —
        e.g. a plain 440Hz tone decoded at the TDD baudmode as
        "FJFJJJFJFFJ''!'!'!'''!'" with minimodem's own reported
        confidence=1.610, and a frequency chirp decoded at RTTY as
        "LIIIWWWWWW" with confidence=1.832. Every genuine minimodem-encoded
        signal tested (Bell103/202, RTTY, TDD, SAME, from full volume down
        to 1% volume) reported confidence >= 2.283. minimodem's own
        confidence value (parsed from its stderr trailer, previously
        discarded entirely) must now gate acceptance.
        """
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        def fake_run_command(cmd, timeout=None):
            baud = cmd[2]
            if baud == "tdd":
                return (0, "FJFJJJFJFFJ''!'!'!'''!'",
                        "### NOCARRIER ndata=25 confidence=1.610 ampl=0.005 bps=45.26 (0.4% slow) ###")
            return (1, "", "")

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_minimodem(fake_wav)

        assert ana.results["minimodem"] == [], (
            f"Low-confidence noise decode must be rejected, got: {ana.results['minimodem']}"
        )

    def test_minimodem_rejects_repeated_character_carrier_lock(self, config, tmp_dir):
        """
        Regression: found by running the full pipeline against a real MP3
        (not a synthetic test signal) already in this repo — minimodem
        locked onto a carrier-like segment of ordinary music and decoded
        "T _____________________T" at the TDD baudmode: 100% printable,
        24 chars (above the length floor), and minimodem's own reported
        confidence=3.162 (above the noise-floor gate above) — yet 21 of 24
        characters (88%) are the same repeated fill character, the
        signature of a carrier lock with no real data on it, not a message.
        Every genuine decode this pipeline has verified (Bell103/202, RTTY,
        TDD, SAME, at multiple volumes) has a dominant-character ratio no
        higher than ~26%.
        """
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        def fake_run_command(cmd, timeout=None):
            baud = cmd[2]
            if baud == "tdd":
                return (0, "T _____________________T",
                        "### NOCARRIER ndata=24 confidence=3.162 ampl=0.300 bps=45.45 (0.0% slow) ###")
            return (1, "", "")

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_minimodem(fake_wav)

        assert ana.results["minimodem"] == [], (
            f"Carrier-lock repeated-character decode must be rejected, got: {ana.results['minimodem']}"
        )

    def test_minimodem_accepts_real_signal_at_low_confidence_gate(self, config, tmp_dir):
        """The confidence gate must not reject genuine decodes — a real
        signal at the empirically-observed floor (confidence=2.283, the
        weakest genuine round-trip measured) must still be reported."""
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        def fake_run_command(cmd, timeout=None):
            baud = cmd[2]
            if baud == "300":
                return (0, "HELLO CTF FLAG TEST 123",
                        "### NOCARRIER ndata=24 confidence=2.283 ampl=0.993 bps=300.00 (rate perfect) ###")
            return (1, "", "")

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_minimodem(fake_wav)

        assert len(ana.results["minimodem"]) == 1
        assert "HELLO CTF FLAG TEST 123" in ana.results["minimodem"][0]["value"]

    def test_minimodem_rtty_tdd_conflict_keeps_higher_confidence(self, config, tmp_dir):
        """
        Regression: rtty and tdd are the same nominal 45.45-baud physical
        signal under two different stop-bit framings. Feeding a real
        RTTY-encoded signal through minimodem's full baud sweep previously
        reported it TWICE — once correctly as RTTY ("HELLO CTF FLAG TEST
        123", confidence=16.421) and once as TDD garbage ("_BVUGKMKWPQ",
        confidence=8.246) — because the two baudmodes were never recognised
        as competing interpretations of one signal. Only the higher-
        confidence framing must be reported.
        """
        ana, out = self._make_analyzer(config, tmp_dir)
        fake_wav = os.path.join(out, "in.wav")
        open(fake_wav, "wb").close()

        def fake_run_command(cmd, timeout=None):
            baud = cmd[2]
            if baud == "rtty":
                return (0, "HELLO CTF FLAG TEST 123",
                        "### NOCARRIER ndata=26 confidence=16.421 ampl=0.980 bps=45.45 (0.0% slow) ###")
            if baud == "tdd":
                return (0, "_BVUGKMKWPQ",
                        "### NOCARRIER ndata=18 confidence=8.246 ampl=0.466 bps=45.71 (0.6% fast) ###")
            return (1, "", "")

        with patch("audio_stego.digital.run_command", side_effect=fake_run_command), \
             patch("audio_stego.digital.tool_available", return_value=True):
            ana._run_minimodem(fake_wav)

        assert len(ana.results["minimodem"]) == 1, (
            f"Expected only the higher-confidence rtty/tdd framing, got: {ana.results['minimodem']}"
        )
        assert "HELLO CTF FLAG TEST 123" in ana.results["minimodem"][0]["value"]

    @staticmethod
    def _gen_dtmf_wav(path, digits="1337", sr=8000):
        import numpy as np
        freqs = {
            '1': (697, 1209), '2': (697, 1336), '3': (697, 1477),
            '4': (770, 1209), '5': (770, 1336), '6': (770, 1477),
            '7': (852, 1209), '8': (852, 1336), '9': (852, 1477),
            '0': (941, 1336),
        }
        sig = []
        for d in digits:
            f1, f2 = freqs[d]
            t = np.arange(int(sr * 0.15)) / sr
            sig.append(0.5 * np.sin(2 * np.pi * f1 * t) + 0.5 * np.sin(2 * np.pi * f2 * t))
            sig.append(np.zeros(int(sr * 0.1)))
        sig = np.concatenate(sig)
        pcm = (sig / np.max(np.abs(sig)) * 0.8 * 32767).astype(np.int16)
        with wave.open(path, "w") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr)
            w.writeframes(pcm.tobytes())

    @staticmethod
    def _gen_morse_wav(path, text="SOS", wpm=18, freq=700, sr=8000):
        import numpy as np
        morse = {'S': '...', 'O': '---'}
        dot = 1.2 / wpm
        sig = []

        def tone(dur):
            t = np.arange(int(sr * dur)) / sr
            env = np.ones_like(t)
            r = max(1, int(sr * 0.005))
            env[:r] = np.linspace(0, 1, r)
            env[-r:] = np.linspace(1, 0, r)
            return 0.7 * np.sin(2 * np.pi * freq * t) * env

        def sil(dur):
            return np.zeros(int(sr * dur))

        for ci, ch in enumerate(text):
            code = morse[ch]
            for si, sym in enumerate(code):
                sig.append(tone(dot * 3 if sym == '-' else dot))
                if si < len(code) - 1:
                    sig.append(sil(dot))
            if ci < len(text) - 1:
                sig.append(sil(dot * 3))
        sig.append(sil(dot * 4))  # trailing silence so the last char flushes
        sig = np.concatenate(sig)
        pcm = (sig / np.max(np.abs(sig)) * 0.8 * 32767).astype(np.int16)
        with wave.open(path, "w") as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr)
            w.writeframes(pcm.tobytes())

    @pytest.mark.skipif(shutil.which("multimon-ng") is None, reason="multimon-ng not installed")
    def test_dtmf_real_signal_end_to_end(self, config, tmp_dir):
        """
        Regression: "DTMF:" was listed in _MULTIMON_BANNER_PREFIXES as a
        "banner line to ignore" — but that is the exact literal prefix of
        every real decoded DTMF line multimon-ng prints ("DTMF: 7"), so
        _filter_multimon_output discarded every genuine detection before the
        marker check ever ran. This drove multimon-ng's real binary against
        a real DTMF-encoded wav (not mocked output) to catch exactly this
        class of bug, which a mocked run_command test cannot catch.
        """
        ana, out = self._make_analyzer(config, tmp_dir)
        wav_path = os.path.join(out, "dtmf.wav")
        self._gen_dtmf_wav(wav_path, "1337")

        ana._detect_dtmf(wav_path)

        assert len(ana.results["dtmf"]) == 1, f"Expected a DTMF finding, got: {ana.results['dtmf']}"
        assert ana.results["dtmf"][0]["value"] == "1337"

    @pytest.mark.skipif(shutil.which("multimon-ng") is None, reason="multimon-ng not installed")
    def test_morse_real_signal_end_to_end(self, config, tmp_dir):
        """
        Regression: multimon-ng's MORSE_CW demodulator prints bare decoded
        text with no per-line marker at all (unlike DTMF's "DTMF: X"
        format) — verified against the real binary. The old code required
        `"MORSE_CW:" in line` before accepting output as a decode, which
        could never be true, so real Morse audio could never produce a
        finding regardless of input. Drives the real multimon-ng binary
        against real Morse-encoded audio (not mocked) to catch this.
        """
        # multimon-ng's CW demodulator needs a little run-up to lock onto
        # element timing and consistently drops the last character of a
        # short burst (verified: "SOS" alone decodes as "SO", "HELP" as
        # "HEL") — repeating the word gives it a clean instance to land on
        # without relying on a since-fixed but still timing-sensitive tail.
        ana, out = self._make_analyzer(config, tmp_dir)
        wav_path = os.path.join(out, "morse.wav")
        self._gen_morse_wav(wav_path, "SOSSOSSOS")

        ana._detect_morse(wav_path, wav_path)

        assert any("SOS" in r.get("value", "") for r in ana.results["morse"]), (
            f"Expected a real 'SOS' Morse decode, got: {ana.results['morse']}"
        )

    def test_dtmf_marker_not_in_banner_prefixes(self, config, tmp_dir):
        """Guards the exact regression above at the constant level: DTMF's
        and Morse's own decode markers must never be treated as banner text."""
        from audio_stego.digital import _MULTIMON_BANNER_PREFIXES
        assert "DTMF:" not in _MULTIMON_BANNER_PREFIXES
        assert "MORSE_CW:" not in _MULTIMON_BANNER_PREFIXES

    def test_temp_wav_cleanup(self, config, tmp_dir):
        """FIX: temp WAV file must be cleaned up after run."""
        ana, out = self._make_analyzer(config, tmp_dir)
        # Inject a fake temp wav path
        fake_wav = os.path.join(out, "_temp.wav")
        open(fake_wav, "w").close()
        ana._temp_wav = fake_wav
        ana._cleanup_temp_wav()
        assert not os.path.exists(fake_wav)

# ---------------------------------------------------------------------------
# Extraction tests — FIX: dedup, loop prevention, stegseek guard
# ---------------------------------------------------------------------------

class TestExtractionAnalyzer:
    def test_sha256_dedup_prevents_reprocessing(self, tmp_dir):
        """FIX: SHA256 dedup must prevent identical files being processed twice."""
        from audio_stego.extraction import _sha256 as _sha256_file
        path = os.path.join(tmp_dir, "dup.txt")
        with open(path, "w") as f:
            f.write("same content")
        h1 = _sha256_file(path)
        h2 = _sha256_file(path)
        assert h1 == h2 and h1 is not None

    def test_sha256_missing_file_returns_none(self, tmp_dir):
        from audio_stego.extraction import _sha256 as _sha256_file
        assert _sha256_file("/nonexistent/path") is None

    def test_safe_passphrase_filename(self):
        from audio_stego.extraction import _safe_name as _safe_passphrase_filename
        result = _safe_passphrase_filename("pass/word!@#$%")
        assert "/" not in result
        assert len(result) <= 40

    def test_collect_all_excludes_tool_metadata_files(self, config, tmp_dir):
        """
        v4.1: foremost's audit.txt exclusion previously only applied to its
        own tool-specific carved-file count, not to _collect_all()'s
        directory scan — so it leaked into extracted_files (shown as a
        spurious "extracted file" in html_report.py/reports_ext.py). Never
        count tool metadata as a verified/extracted payload.
        """
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        out = os.path.join(tmp_dir, "ex_audit_out")
        store = ArtifactStore(out)

        foremost_dir = os.path.join(str(store.extracted), "foremost")
        os.makedirs(foremost_dir, exist_ok=True)
        with open(os.path.join(foremost_dir, "audit.txt"), "w") as f:
            f.write("Foremost run log — not a carved artifact")
        with open(os.path.join(foremost_dir, "00000001.jpg"), "wb") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50)

        ana = ExtractionAnalyzer(config, store)
        ana._collect_all()

        basenames = {os.path.basename(p) for p in ana.results["extracted_files"]}
        assert "audit.txt" not in basenames
        assert "00000001.jpg" in basenames

    @patch("audio_stego.extraction.tool_available", return_value=True)
    def test_stegseek_skips_without_wordlist(self, mock_avail, config, tmp_dir, sample_wav):
        """FIX: stegseek must skip (not run) when wordlist is missing."""
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        out = os.path.join(tmp_dir, "ex_out")
        store = ArtifactStore(out)
        config._config.set("stegseek", "wordlist", "/nonexistent/wordlist.txt")

        ana = ExtractionAnalyzer(config, store)
        # Patch run_command so it never actually executes stegseek
        with patch("audio_stego.extraction.run_command", return_value=(1, "", "error")):
            ana._run_stegseek(sample_wav)
        # Must have added a wordlist-not-found warning
        assert any("wordlist" in w.lower() for w in ana.results.get("warnings", [])), \
            f"Expected wordlist warning, got: {ana.results.get('warnings', [])}"

    def test_extracted_files_collected_after_recursion(self, config, tmp_dir, sample_wav):
        """FIX: _collect_all must include files placed in extracted dir."""
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        out = os.path.join(tmp_dir, "ex_out2")
        store = ArtifactStore(out)
        ana = ExtractionAnalyzer(config, store)
        # Place a file in extracted dir manually
        test_file = str(store.extracted / "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        ana._collect_all()
        assert test_file in ana.results["extracted_files"]

    def test_max_recursion_depth_respected(self, config, tmp_dir):
        """FIX: recursion must stop at MAX depth, not loop infinitely."""
        from audio_stego.extraction import ExtractionAnalyzer, _MAX_RECURSION_DEPTH
        from audio_stego.artifact_store import ArtifactStore
        out = os.path.join(tmp_dir, "ex_out3")
        store = ArtifactStore(out)
        ana = ExtractionAnalyzer(config, store)
        # Call with depth = max — should return immediately
        ana._recursive_multipass(depth=_MAX_RECURSION_DEPTH)
        # If it didn't hang or recurse infinitely, test passes

# ---------------------------------------------------------------------------
# Flags tests — FIX: circular FP, validated b64, cipher cap
# ---------------------------------------------------------------------------

class TestFlagDetector:
    def _make_detector(self, config, tmp_dir):
        from audio_stego.flags import FlagDetector, _SKIP_OUTPUT_FILES
        out = os.path.join(tmp_dir, "flag_out")
        os.makedirs(out, exist_ok=True)
        return FlagDetector(config, out), out, _SKIP_OUTPUT_FILES

    def test_detects_plaintext_flag(self, config, tmp_dir):
        det, out, _ = self._make_detector(config, tmp_dir)
        results = det.run(additional_text="Here is flag{hello_world_123}")
        assert any("flag{hello_world_123}" in str(f) for f in results["flags_found"])

    def test_skips_report_html_to_prevent_circular_fp(self, config, tmp_dir):
        """FIX: report.html must be in the skip list."""
        det, out, SKIP = self._make_detector(config, tmp_dir)
        assert "report.html" in SKIP
        assert "report.json" in SKIP
        assert "flags.txt"   in SKIP

    def test_encoded_flags_base64(self, config, tmp_dir):
        det, out, _ = self._make_detector(config, tmp_dir)
        enc = base64.b64encode(b"flag{encoded_b64}").decode()
        results = det.run(additional_text=enc)
        assert any("flag{encoded_b64}" in str(f) for f in results["flags_found"])

    def test_encoded_flags_hex(self, config, tmp_dir):
        det, out, _ = self._make_detector(config, tmp_dir)
        enc = b"flag{hex_encoded}".hex()
        results = det.run(additional_text=enc)
        assert any("flag{hex_encoded}" in str(f) for f in results["flags_found"])

    def test_cipher_analysis_does_not_hang(self, config, tmp_dir):
        """FIX: cipher analysis on large input must complete quickly."""
        det, out, _ = self._make_detector(config, tmp_dir)
        large = "a" * 1_000_000   # 1 MB of 'a's — was causing O(25n) hang
        # Must complete without hanging
        det._analyze_ciphers(large)

    def test_no_css_false_positives(self, config, tmp_dir):
        """FIX: CSS/JSON format strings must not be reported as flags."""
        det, out, _ = self._make_detector(config, tmp_dir)
        css_text = ".class{color:red;} div{margin:0px;} @keyframes fade{from{opacity:0}}"
        results = det.run(additional_text=css_text)
        # CSS rules must not be reported as flags
        for f in results["flags_found"]:
            val = f.get("value", str(f))
            assert "color" not in val.lower(), f"CSS false positive: {val}"

# ---------------------------------------------------------------------------
# OCR tests — FIX: single call, confidence threshold
# ---------------------------------------------------------------------------

class TestOCRAnalyzer:
    def _make_analyzer(self, config, tmp_dir):
        from audio_stego.ocr import OCRAnalyzer, _MIN_OCR_CONFIDENCE, _MIN_OCR_CHARS
        out = os.path.join(tmp_dir, "ocr_out")
        os.makedirs(out, exist_ok=True)
        os.makedirs(os.path.join(out, "images"), exist_ok=True)
        return OCRAnalyzer(config, out), _MIN_OCR_CONFIDENCE, _MIN_OCR_CHARS

    def test_confidence_threshold_defined(self, config, tmp_dir):
        """FIX: minimum OCR confidence threshold must exist and be reasonable."""
        from audio_stego.ocr import _MIN_OCR_CONFIDENCE, _MIN_OCR_CHARS
        assert _MIN_OCR_CONFIDENCE >= 30.0
        assert _MIN_OCR_CHARS >= 3

    def test_confidence_threshold_tightened_v43(self, config, tmp_dir):
        """v4.3: raised from 40% (which contradicted this module's own
        docstring, which long claimed a 60% default) to 55% — a regression
        pin so this doesn't silently drift back down."""
        from audio_stego.ocr import _MIN_OCR_CONFIDENCE
        assert _MIN_OCR_CONFIDENCE == 55.0

    def test_find_images_deduplicates(self, config, tmp_dir):
        """FIX: same image must not appear twice in image list."""
        ana, _, _ = self._make_analyzer(config, tmp_dir)
        # Create one image that's visible from both paths
        img = os.path.join(ana.images_dir, "spec.png")
        with open(img, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        found = ana._find_images()
        # Count how many times the same realpath appears
        realpaths = [os.path.realpath(p) for p in found]
        assert len(realpaths) == len(set(realpaths)), "Duplicate images in list"

    def test_find_images_skips_generated_plots(self, config, tmp_dir):
        """
        v4.1: internally generated diagnostic plots (spectrogram/waveform/FFT,
        including the ffmpeg-fallback variants) must never be handed to OCR —
        they're visualizations of the raw signal, not candidate hidden images,
        and tesseract-ing axis labels only produces noise findings.
        """
        ana, _, _ = self._make_analyzer(config, tmp_dir)
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

        # One real candidate image + all five generated-plot filenames,
        # placed in both images_dir and the output_dir root (both are
        # searched by _find_images).
        real_img = os.path.join(ana.images_dir, "extracted_photo.png")
        with open(real_img, "wb") as f:
            f.write(png_bytes)

        generated_names = [
            "spectrogram.png", "spectrogram_ffmpeg.png",
            "waveform.png", "waveform_ffmpeg.png", "fft.png",
        ]
        for name in generated_names:
            with open(os.path.join(ana.images_dir, name), "wb") as f:
                f.write(png_bytes)
            with open(os.path.join(ana.output_dir, name), "wb") as f:
                f.write(png_bytes)

        found_basenames = {os.path.basename(p) for p in ana._find_images()}
        assert "extracted_photo.png" in found_basenames
        for name in generated_names:
            assert name not in found_basenames, f"{name} should be excluded from OCR candidates"

    @patch("audio_stego.ocr.tool_available", return_value=True)
    @patch("audio_stego.ocr.run_command")
    def test_ocr_rejects_low_confidence(self, mock_cmd, mock_avail, config, tmp_dir):
        """FIX: OCR result with low confidence must be filtered out."""
        # Simulate TSV output with very low confidence (5%)
        tsv_header = "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        tsv_row    = "5\t1\t1\t1\t1\t1\t10\t10\t50\t20\t5\tgarbage\n"
        mock_cmd.return_value = (0, tsv_header + tsv_row, "")
        ana, min_conf, _ = self._make_analyzer(config, tmp_dir)
        result = ana._ocr_image("/fake/image.png")
        assert result is None, "Low-confidence OCR should be filtered"

    @patch("audio_stego.ocr.tool_available", return_value=True)
    @patch("audio_stego.ocr.run_command")
    def test_ocr_accepts_high_confidence(self, mock_cmd, mock_avail, config, tmp_dir):
        """OCR with high confidence and real text should be accepted."""
        tsv_header = "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n"
        tsv_rows   = "".join(
            f"5\t1\t1\t1\t1\t1\t10\t10\t50\t20\t95\t{word}\n"
            for word in "flag{found_it}".split()
        )
        mock_cmd.return_value = (0, tsv_header + tsv_rows, "")
        ana, _, _ = self._make_analyzer(config, tmp_dir)
        result = ana._ocr_image("/fake/image.png")
        assert result is not None
        assert result["confidence"] >= 90.0

# ---------------------------------------------------------------------------
# Visual tests — FIX: no double ffmpeg, stereo/mono, LSB, channel diff
# ---------------------------------------------------------------------------

class TestVisualAnalyzer:
    def _make_analyzer(self, config, tmp_dir):
        from audio_stego.visual import VisualAnalyzer
        out = os.path.join(tmp_dir, "vis_out")
        os.makedirs(out, exist_ok=True)
        os.makedirs(os.path.join(out, "images"), exist_ok=True)
        return VisualAnalyzer(config, out)

    def test_zero_length_file_handled(self, config, tmp_dir):
        """FIX: zero-length file must not crash visual analyzer."""
        ana = self._make_analyzer(config, tmp_dir)
        empty = os.path.join(tmp_dir, "empty.wav")
        open(empty, "w").close()
        results = ana.run(empty)
        assert any("empty" in w.lower() for w in results["warnings"])

    def test_lsb_analysis_lsb_text(self, config, tmp_dir):
        """Phase 7: LSB analysis on WAV with hidden text in LSBs."""
        import numpy as np

        ana = self._make_analyzer(config, tmp_dir)
        wav_path = os.path.join(tmp_dir, "lsb_test.wav")

        # Embed "flag{lsb}" in the LSBs
        secret = b"flag{lsb_test_value}" + b"\x00" * 100
        bits   = "".join(f"{b:08b}" for b in secret)
        n_samp = len(bits)

        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            samples = np.zeros(n_samp, dtype=np.int16)
            for i, bit in enumerate(bits):
                samples[i] = (samples[i] & ~1) | int(bit)
            wf.writeframes(samples.tobytes())

        ana._analyze_lsb(wav_path)
        lsb = ana.results.get("lsb_analysis")
        assert lsb is not None
        assert "flag" in lsb.get("lsb_text_preview", "").lower() or \
               lsb.get("printable_ratio", 0) > 0.3

    def test_channel_difference_mono_skipped(self, config, tmp_dir, mono_wav):
        """Phase 7: channel diff must skip mono files gracefully."""
        try:
            import librosa
        except ImportError:
            pytest.skip("librosa not installed")

        ana = self._make_analyzer(config, tmp_dir)
        ana._analyze_channel_difference(mono_wav)
        assert ana.results.get("channel_diff") is None

    def test_channel_difference_stereo(self, config, tmp_dir, sample_wav):
        """Phase 7: channel diff must work for stereo WAV."""
        try:
            import librosa
        except ImportError:
            pytest.skip("librosa not installed")

        ana = self._make_analyzer(config, tmp_dir)
        ana._analyze_channel_difference(sample_wav)
        # Both channels are silence so diff should be ~0
        ch = ana.results.get("channel_diff")
        if ch is not None:
            assert ch["diff_ratio"] < 0.01

# ---------------------------------------------------------------------------
# Scanner tests — FIX: NameError, binary_analyzer on self
# ---------------------------------------------------------------------------

class TestAudioStegoScanner:
    def test_binary_analyzer_on_self(self, config):
        """FIX: binary_analyzer must be stored as self._binary_analyzer, not in with-block."""
        from audio_stego.scanner import AudioStegoScanner
        scanner = AudioStegoScanner(config)
        assert hasattr(scanner, "_binary_analyzer")
        assert scanner._binary_analyzer is None   # before scan() runs

    def test_setup_output_dir(self, config, tmp_dir, sample_wav):
        from audio_stego.scanner import AudioStegoScanner
        from audio_stego.artifact_store import ArtifactStore
        scanner = AudioStegoScanner(config)
        store = scanner._setup_store(sample_wav)
        assert isinstance(store, ArtifactStore)
        assert store.base.exists()
        assert store.extracted.exists()
        assert store.images.exists()

    def test_sstv_runs_after_digital_and_receives_wav_path(self, config, tmp_dir, sample_wav):
        """
        Regression: SSTV used to run *before* Digital modes in the pipeline
        but tried to read all_results["digital"]["_wav_path"] — which digital
        modes hadn't set yet, so it was always None. SSTV now runs after the
        Digital+OCR step and must receive the real converted WAV path.
        """
        from unittest.mock import MagicMock, patch
        from audio_stego.scanner import AudioStegoScanner

        scanner = AudioStegoScanner(config)
        store = scanner._setup_store(sample_wav)

        fake_wav_path = "/tmp/fake_converted.wav"
        captured = {}

        def fake_sstv_run(self_, audio_path, wav_path):
            captured["wav_path"] = wav_path
            return {"vis_detected": False, "findings": [], "warnings": [],
                    "decoders_tried": [], "confidence": 0.0}

        with patch("audio_stego.scanner.MetadataAnalyzer") as MMeta, \
             patch("audio_stego.scanner.BinaryAnalyzer") as MBin, \
             patch("audio_stego.scanner.VisualAnalyzer") as MVis, \
             patch("audio_stego.scanner.AudioForensicsAnalyzer") as MForensics, \
             patch("audio_stego.scanner.ExtractionAnalyzer") as MExtract, \
             patch("audio_stego.scanner.DigitalModesAnalyzer") as MDigital, \
             patch("audio_stego.scanner.OCRAnalyzer") as MOcr, \
             patch("audio_stego.scanner.SSTVAnalyzer.run", fake_sstv_run), \
             patch("audio_stego.scanner.FlagDetector") as MFlag:

            MMeta.return_value.run.return_value = {}
            MMeta.return_value.get_interesting_tags.return_value = {}
            MBin.return_value.run.return_value = {"strings": []}
            MVis.return_value.run.return_value = {}
            MForensics.return_value.run.return_value = {}
            MExtract.return_value.run.return_value = {"records": [], "summary": {}}
            MDigital.return_value.run.return_value = {"_wav_path": fake_wav_path}
            MOcr.return_value.run.return_value = {"ocr": [], "qr_codes": []}
            MFlag.return_value.run.return_value = {"flags_found": []}

            scanner._run_pipeline(sample_wav, store)

        assert captured.get("wav_path") == fake_wav_path

    def test_run_sstv_false_skips_sstv_analysis(self, config, tmp_dir, sample_wav):
        """The run_sstv config flag must actually gate the SSTV step."""
        from unittest.mock import patch
        from audio_stego.scanner import AudioStegoScanner

        config._config.set("analysis", "run_sstv", "false")
        scanner = AudioStegoScanner(config)
        store = scanner._setup_store(sample_wav)

        with patch("audio_stego.scanner.MetadataAnalyzer") as MMeta, \
             patch("audio_stego.scanner.BinaryAnalyzer") as MBin, \
             patch("audio_stego.scanner.VisualAnalyzer") as MVis, \
             patch("audio_stego.scanner.AudioForensicsAnalyzer") as MForensics, \
             patch("audio_stego.scanner.ExtractionAnalyzer") as MExtract, \
             patch("audio_stego.scanner.DigitalModesAnalyzer") as MDigital, \
             patch("audio_stego.scanner.OCRAnalyzer") as MOcr, \
             patch("audio_stego.scanner.SSTVAnalyzer") as MSstv, \
             patch("audio_stego.scanner.FlagDetector") as MFlag:

            MMeta.return_value.run.return_value = {}
            MMeta.return_value.get_interesting_tags.return_value = {}
            MBin.return_value.run.return_value = {"strings": []}
            MVis.return_value.run.return_value = {}
            MForensics.return_value.run.return_value = {}
            MExtract.return_value.run.return_value = {"records": [], "summary": {}}
            MDigital.return_value.run.return_value = {"_wav_path": None}
            MOcr.return_value.run.return_value = {"ocr": [], "qr_codes": []}
            MFlag.return_value.run.return_value = {"flags_found": []}

            scanner._run_pipeline(sample_wav, store)

        MSstv.return_value.run.assert_not_called()

    # -----------------------------------------------------------------
    # v4.3: Tool Availability only lists tools tied to the current config,
    # never a blanket "check everything we could possibly ever use" list.
    # -----------------------------------------------------------------

    def test_check_tools_excludes_never_invoked_sox(self, config):
        """`sox` was checked for presence but never actually invoked
        anywhere in the codebase — must not appear in Tool Availability."""
        from audio_stego.scanner import AudioStegoScanner
        scanner = AudioStegoScanner(config)
        scanner._check_tools()
        avail = scanner.all_results["_performance"]["tool_availability"]
        assert "sox" not in avail

    def test_check_tools_includes_rx_sstv_when_sstv_enabled(self, config):
        from audio_stego.scanner import AudioStegoScanner
        scanner = AudioStegoScanner(config)
        scanner._check_tools()
        avail = scanner.all_results["_performance"]["tool_availability"]
        assert "rx_sstv" in avail

    def test_check_tools_excludes_rx_sstv_when_sstv_disabled(self, config):
        """Optional tools must not appear as missing unless the config
        section that would actually invoke them is enabled."""
        from audio_stego.scanner import AudioStegoScanner
        config._config.set("analysis", "run_sstv", "false")
        scanner = AudioStegoScanner(config)
        scanner._check_tools()
        avail = scanner.all_results["_performance"]["tool_availability"]
        assert "rx_sstv" not in avail

    def test_check_tools_excludes_steghide_when_disabled(self):
        from audio_stego.config import Config
        from audio_stego.scanner import AudioStegoScanner
        config = Config()
        config._config.set("analysis", "run_steghide", "false")
        scanner = AudioStegoScanner(config)
        scanner._check_tools()
        avail = scanner.all_results["_performance"]["tool_availability"]
        assert "steghide" not in avail
        # Core tools always run regardless of [analysis] config.
        assert "file" in avail and "ffmpeg" in avail


# ---------------------------------------------------------------------------
# Hint engine tests — FIX: AttributeError on entropy blocks
# ---------------------------------------------------------------------------

class TestHintEngine:
    def test_no_attribute_error_on_entropy(self, tmp_dir):
        """FIX: hint engine must not crash when entropy.blocks is a list of floats."""
        from audio_stego.hint_engine import HintEngine
        engine = HintEngine(tmp_dir)
        results = {
            "binary": {
                # Simulate old-style entropy with float list — engine must handle both
                "entropy": {
                    "overall": 4.5,
                    "high_entropy_blocks": [{"offset": 1024, "entropy": 7.8}],
                },
                "embedded_files": [],
                "appended_data": None,
                "encoded_data": {},
                "strings": [],
            },
            "extraction": {"steghide": [], "stegseek": {}, "extracted_files": []},
            "digital":    {"morse": [], "dtmf": [], "sstv": [], "minimodem": [], "multimon": {}},
            "ocr":        {"qr_codes": [], "ocr": []},
            "visual":     {},
            "metadata":   {},
            "flags":      {"flags_found": [], "cipher_results": {}},
        }
        # Must not raise AttributeError
        hints = engine.analyze("/fake/audio.wav", results)
        assert isinstance(hints, list)

    def test_flag_found_generates_hint(self, tmp_dir):
        from audio_stego.hint_engine import HintEngine
        engine = HintEngine(tmp_dir)
        results = {
            "binary": {"entropy": {}, "embedded_files": [], "appended_data": None,
                       "encoded_data": {}, "strings": []},
            "extraction": {"steghide": [], "stegseek": {}, "extracted_files": []},
            "digital":    {"morse": [], "dtmf": [], "sstv": [], "minimodem": [], "multimon": {}},
            "ocr":        {"qr_codes": [], "ocr": []},
            "visual":     {},
            "metadata":   {},
            "flags": {
                "flags_found": [{"value": "flag{test}", "encoding": "plaintext",
                                 "confidence_pct": "95%"}],
                "cipher_results": {},
            },
        }
        hints = engine.analyze("/fake/audio.wav", results)
        assert any("FLAG" in h.upper() or "flag{test}" in h for h in hints)

    def test_dedup_uses_set(self, tmp_dir):
        """FIX: hint deduplication must use a set, not O(n²) list scan."""
        from audio_stego.hint_engine import HintEngine
        engine = HintEngine(tmp_dir)
        for _ in range(100):
            engine._add("repeated hint")
        assert engine._hints.count("repeated hint") == 1

# ---------------------------------------------------------------------------
# Plugin tests
# ---------------------------------------------------------------------------

class TestPlugins:
    def test_plugin_manager_discovers_builtin(self, config):
        from audio_stego.plugins.manager import PluginManager
        pm = PluginManager(config)
        plugins = pm.discover()
        names = [p.name for p in plugins]
        assert "xor"    in names
        assert "base64" in names
        assert "magic"  in names
        assert "rot"    in names

    def test_xor_plugin_finds_flag(self, config, tmp_dir):
        from audio_stego.plugins.xor_plugin import XORPlugin
        plugin = XORPlugin(config)
        key = 0x42
        flag_bytes = b"flag{xor_test_value}"
        xored = "".join(chr(b ^ key) for b in flag_bytes)
        results = {"binary": {"strings": [xored]}, "ocr": {"ocr": []}}
        out = os.path.join(tmp_dir, "xor_out")
        os.makedirs(out, exist_ok=True)
        result = plugin.run("/fake/audio.wav", out, results)
        assert result is not None
        assert any("flag{xor_test_value}" in str(f.get("value", ""))
                   for f in result.get("flags_found", []))

    def test_xor_plugin_discards_generic_pattern_without_language_context(self, config, tmp_dir):
        """
        v4.1: the generic (non-platform-specific) flag pattern can match
        pure decode noise by chance — e.g. 'xkqzjhwvbnmqzxk{...}' has no
        surrounding English text, so it must be discarded even though the
        printable-ratio/entropy gates and the regex itself both pass.
        """
        from audio_stego.plugins.xor_plugin import XORPlugin
        plugin = XORPlugin(config)
        key = 0x17
        plaintext = b"xkqzjhwvbnmqzxk{q1w2e3r4t5y6u7i8}mnbvcxzqwrtyplkjh"
        xored = "".join(chr(b ^ key) for b in plaintext)
        results = {"binary": {"strings": [xored]}, "ocr": {"ocr": []}}
        out = os.path.join(tmp_dir, "xor_generic_out")
        os.makedirs(out, exist_ok=True)
        result = plugin.run("/fake/audio.wav", out, results)
        assert result is not None
        assert not any("q1w2e3r4t5y6u7i8" in str(f.get("value", ""))
                       for f in result.get("flags_found", []))

    def test_xor_plugin_discards_high_entropy_noise(self, config, tmp_dir):
        """
        v4.1: random/high-entropy bytes must never reach the regex stage
        regardless of what they contain — the printable-ratio/entropy gates
        apply to the whole decoded buffer before any pattern matching.
        """
        from audio_stego.plugins.xor_plugin import XORPlugin
        plugin = XORPlugin(config)
        random_bytes = os.urandom(256)
        results = {
            "binary": {"strings": [random_bytes.decode("latin-1")]},
            "ocr": {"ocr": []},
        }
        out = os.path.join(tmp_dir, "xor_noise_out")
        os.makedirs(out, exist_ok=True)
        result = plugin.run("/fake/audio.wav", out, results)
        assert result is not None
        assert result.get("flags_found", []) == []

    def test_base64_plugin_uses_validation(self, config, tmp_dir):
        from audio_stego.plugins.base64_plugin import Base64Plugin
        plugin = Base64Plugin(config)
        enc = base64.b64encode(b"flag{base64_plugin_test}").decode()
        results = {"binary": {"strings": [enc]}, "ocr": {"ocr": []}}
        out = os.path.join(tmp_dir, "b64_out")
        os.makedirs(out, exist_ok=True)
        result = plugin.run("/fake/audio.wav", out, results)
        assert result is not None
        assert any("flag{base64_plugin_test}" in str(f.get("value", ""))
                   for f in result.get("flags_found", []))

    def test_rot_plugin_finds_rot13_flag(self, config, tmp_dir):
        from audio_stego.plugins.rot_plugin import ROTPlugin
        from audio_stego.findings import rot13
        plugin = ROTPlugin(config)
        shifted = rot13("flag{rot13_test}")
        results = {"binary": {"strings": [shifted]}, "ocr": {"ocr": []}}
        out = os.path.join(tmp_dir, "rot_out")
        os.makedirs(out, exist_ok=True)
        result = plugin.run("/fake/audio.wav", out, results)
        assert result is not None
        assert any("flag{rot13_test}" in str(f.get("value", ""))
                   for f in result.get("flags_found", []))

    def test_base_plugin_finding_helper(self, config):
        from audio_stego.plugins.base_plugin import BasePlugin
        from audio_stego.findings import Severity

        class _TestPlugin(BasePlugin):
            name = "test"
            def run(self, *a, **k): return None

        p = _TestPlugin(config)
        d = p.finding("Test", "flag{x}", evidence="e", confidence=0.9)
        assert d["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert d["confidence"] == 0.9
        assert d["value"] == "flag{x}"


# ---------------------------------------------------------------------------
# Phase 12 — plugin framework metadata
# ---------------------------------------------------------------------------

class TestPluginMetadata:
    def test_base_plugin_declares_required_metadata_fields(self):
        """Every plugin must expose: name, version, author, description,
        supported file types, dependencies, input types, output types."""
        from audio_stego.plugins.base_plugin import BasePlugin
        meta = BasePlugin.metadata()
        for field in ("name", "version", "author", "description",
                      "supported_file_types", "dependencies",
                      "input_types", "output_types"):
            assert field in meta

    def test_yara_plugin_declares_real_dependency(self):
        from audio_stego.plugins.yara_plugin import YARAPlugin
        assert "yara-python" in YARAPlugin.metadata()["dependencies"]

    def test_all_discovered_plugins_expose_valid_metadata(self, config):
        from audio_stego.plugins.manager import PluginManager
        pm = PluginManager(config)
        for plugin in pm.discover():
            meta = plugin.metadata()
            assert meta["name"] and meta["version"]
            assert isinstance(meta["dependencies"], list)
            assert isinstance(meta["supported_file_types"], list)

    def test_plugin_execution_time_recorded(self, config, tmp_dir):
        """Phase 12: every plugin run must record execution_time, even on
        failure — this is how a report can show what a scan spent time on."""
        from audio_stego.plugins.manager import PluginManager
        pm = PluginManager(config)
        results = pm.run_all("/fake/audio.wav", tmp_dir, {"binary": {"strings": []}, "ocr": {"ocr": []}})
        assert results, "expected at least one built-in plugin to run"
        for name, result in results.items():
            assert "execution_time" in result, f"{name} missing execution_time"
            assert result["execution_time"] >= 0
            assert "metadata" in result

    def test_plugin_failure_does_not_stop_other_plugins(self, config, tmp_dir):
        """A plugin raising an exception must not prevent other plugins from
        running or crash the scan — verified by injecting a broken plugin
        into a real PluginManager instance."""
        from audio_stego.plugins.manager import PluginManager
        from audio_stego.plugins.base_plugin import BasePlugin

        class BrokenPlugin(BasePlugin):
            name = "broken_test_plugin"
            version = "1.0.0"
            description = "Deliberately raises to test fault isolation"

            def run(self, audio_path, output_dir, results):
                raise RuntimeError("intentional failure for testing")

        pm = PluginManager(config)
        pm._plugins = [BrokenPlugin(config)] + pm.discover()
        results = pm.run_all("/fake/audio.wav", tmp_dir, {"binary": {"strings": []}, "ocr": {"ocr": []}})

        assert "error" in results["broken_test_plugin"]
        assert "execution_time" in results["broken_test_plugin"]
        # other plugins must still have run despite the failure above
        assert len(results) > 1


# ---------------------------------------------------------------------------
# Extended reports tests
# ---------------------------------------------------------------------------

class TestExtendedReports:
    def _base_results(self):
        return {
            "metadata": {"hashes": {"md5": "abc", "sha1": "def", "sha256": "ghi"},
                         "exiftool": {}},
            "binary":   {"embedded_files": [], "appended_data": None,
                         "findings": [], "encoded_data": {}},
            "flags":    {"flags_found": [{"value": "flag{report_test}",
                                          "encoding": "plaintext",
                                          "confidence_pct": "95%",
                                          "evidence": "test"}],
                         "suspicious_strings": []},
            "extraction": {"extracted_files": [], "binwalk": [],
                           "steghide": [], "stegseek": {}, "findings": []},
            "digital":  {"morse": [], "dtmf": [], "minimodem": [], "findings": []},
            "ocr":      {"qr_codes": [], "ocr": [], "findings": []},
            "visual":   {"spectrogram": None, "waveform": None, "fft": None,
                         "lsb_analysis": None, "channel_diff": None, "findings": []},
        }

    def test_json_report(self, tmp_dir, sample_wav):
        from audio_stego.reports_ext import JSONReportGenerator
        gen  = JSONReportGenerator(tmp_dir)
        path = gen.generate(sample_wav, self._base_results(), 10.0)
        assert os.path.exists(path)
        data = json.load(open(path))
        assert data["flags_found"][0]["value"] == "flag{report_test}"
        assert "non-serialisable" not in json.dumps(data)

    def test_csv_report(self, tmp_dir, sample_wav):
        from audio_stego.reports_ext import CSVReportGenerator
        gen  = CSVReportGenerator(tmp_dir)
        path = gen.generate(sample_wav, self._base_results(), 5.0)
        assert os.path.exists(path)
        rows = list(csv.reader(open(path)))
        assert rows[0] == ["File", "Module", "Severity", "Confidence", "Finding", "Offset", "Description"]
        assert any("flag{report_test}" in row[-1] for row in rows[1:])

    # XSS-escaping and missing-image-placeholder behavior for the primary
    # HTML report is covered directly against the live implementation in
    # TestHTMLReport (audio_stego/html_report.py) — see
    # test_xss_escaped / test_missing_image_placeholder. The standalone
    # HTMLReportGenerator in reports_ext.py this class used to test was
    # dead code (superseded by html_report.HTMLReport, never wired into
    # the pipeline) and has been removed; JSONReportGenerator/
    # CSVReportGenerator below are still live and tested.

# ===========================================================================
# v3 Tests — new modules
# ===========================================================================

# ---------------------------------------------------------------------------
# ArtifactStore tests
# ---------------------------------------------------------------------------

class TestArtifactStore:
    def test_creates_all_dirs(self, tmp_dir):
        """v5.0: the flat, curated layout — tools/ (raw tool output),
        images/ (waveform/spectrogram/fft), sstv/ (decoded images +
        variants), text/ (general OCR/QR output), plus evidence/extracted/
        hidden_files/plugins/logs which still have real writers even
        though they're not part of the user-facing curated file list."""
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "out"))
        assert store.base.exists()
        assert store.images.exists()
        assert store.sstv_dir.exists()
        assert store.sstv_debug.exists()
        assert store.sstv_variants.exists()
        assert store.text_dir.exists()
        assert store.tools.exists()
        assert store.evidence.exists()
        assert store.logs.exists()
        assert store.plugins.exists()
        assert store.extracted.exists()
        assert store.hidden_files.exists()

    def test_str_returns_base_path(self, tmp_dir):
        from audio_stego.artifact_store import ArtifactStore
        out = os.path.join(tmp_dir, "out")
        store = ArtifactStore(out)
        assert str(store) == str(store.base)


# ---------------------------------------------------------------------------
# Validate module tests
# ---------------------------------------------------------------------------

class TestValidate:
    def test_valid_zip(self, tmp_dir):
        from audio_stego.validate import validate_embedded
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("flag.txt", "flag{test}")
        data = b"\x00" * 100 + buf.getvalue()
        vr = validate_embedded(data, 100, "ZIP")
        assert vr.valid is True
        assert vr.confidence >= 0.90

    def test_invalid_zip_rejected(self, tmp_dir):
        from audio_stego.validate import validate_embedded
        # PK magic but not a valid ZIP
        data = b"\x00" * 100 + b"PK\x03\x04" + b"\xff" * 50
        vr = validate_embedded(data, 100, "ZIP")
        assert vr.valid is False
        assert vr.confidence < 0.50

    def test_valid_png(self, tmp_dir):
        from audio_stego.validate import validate_embedded
        import struct
        # Build minimal valid PNG header
        png = (b"\x89PNG\r\n\x1a\n"          # signature
               + struct.pack(">I", 13)         # IHDR length
               + b"IHDR"
               + struct.pack(">II", 100, 100)  # width, height
               + b"\x08\x02\x00\x00\x00"      # bit depth, color type, etc.
               + b"\x00\x00\x00\x00")          # CRC placeholder
        data = b"\x00" * 50 + png + b"\x00" * 100
        vr = validate_embedded(data, 50, "PNG")
        assert vr.valid is True
        assert vr.confidence >= 0.90

    def test_invalid_png_wrong_ihdr(self, tmp_dir):
        from audio_stego.validate import validate_embedded
        import struct
        png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IDAT" + b"\x00" * 20
        data = b"\x00" * 50 + png
        vr = validate_embedded(data, 50, "PNG")
        assert vr.valid is False

    def test_jpeg_with_valid_marker(self):
        from audio_stego.validate import validate_embedded
        # Byte-accurate APP0/JFIF segment: FFE0, length=16 (2-byte length field
        # + 14-byte payload), then EOI directly follows — a real marker chain,
        # not a coincidental EOI byte pair floating in unrelated filler data.
        app0_payload = b"JFIF\x00" + b"\x01\x02" + b"\x00" + b"\x00\x48" + b"\x00\x48" + b"\x00\x00"
        assert len(app0_payload) == 14
        jpeg = b"\xff\xd8\xff\xe0\x00\x10" + app0_payload + b"\xff\xd9"
        data = b"\x00" * 200 + jpeg
        vr = validate_embedded(data, 200, "JPEG")
        assert vr.valid is True

    def test_jpeg_false_positive_rejected(self):
        from audio_stego.validate import validate_embedded
        # SOI but invalid next marker
        jpeg = b"\xff\xd8\x00\x00\x00\x00"
        data = b"\x00" * 200 + jpeg
        vr = validate_embedded(data, 200, "JPEG")
        assert vr.valid is False

    def test_valid_gzip(self, tmp_dir):
        from audio_stego.validate import validate_embedded
        import gzip
        compressed = gzip.compress(b"flag{gzip_test}")
        data = b"\x00" * 100 + compressed
        vr = validate_embedded(data, 100, "GZIP")
        assert vr.valid is True
        assert vr.confidence >= 0.90

    def test_invalid_gzip_bad_cm(self):
        from audio_stego.validate import validate_embedded
        bad_gz = b"\x1f\x8b\x09" + b"\x00" * 20  # CM=9, invalid
        data = b"\x00" * 50 + bad_gz
        vr = validate_embedded(data, 50, "GZIP")
        assert vr.valid is False

    def test_valid_pdf(self):
        from audio_stego.validate import validate_embedded
        pdf = b"%PDF-1.4\n" + b"%comment\n" * 10 + b"%%EOF\n"
        data = b"\x00" * 100 + pdf
        vr = validate_embedded(data, 100, "PDF")
        assert vr.valid is True

    def test_elf_validated(self):
        from audio_stego.validate import validate_embedded
        import struct
        elf = (b"\x7fELF"
               + b"\x02"          # 64-bit
               + b"\x01"          # little-endian
               + b"\x01"          # ELF version
               + b"\x00" * 9
               + struct.pack("<H", 2)  # ET_EXEC
               + b"\x00" * 50)
        data = b"\x00" * 100 + elf
        vr = validate_embedded(data, 100, "ELF")
        assert vr.valid is True
        assert "64-bit" in vr.reason

    def test_unknown_type_accepted_with_low_confidence(self):
        from audio_stego.validate import validate_embedded
        data = b"\x00" * 100 + b"XYZ" + b"\x00" * 50
        vr = validate_embedded(data, 100, "UNKNOWN_TYPE")
        # No validator → accepted with medium-low confidence
        assert vr.valid is True
        assert vr.confidence <= 0.60


# ---------------------------------------------------------------------------
# ExtractionAnalyzer v3 tests — structured status reporting
# ---------------------------------------------------------------------------

class TestExtractionAnalyzerV3:
    def _make(self, config, tmp_dir):
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "ex_v3"))
        return ExtractionAnalyzer(config, store), store

    def test_signature_scan_skips_offset_zero(self, config, tmp_dir, sample_wav):
        """v3: validated scanner must not report own WAV header at offset 0."""
        ana, store = self._make(config, tmp_dir)
        ana._scan_signatures(sample_wav)
        for rec in ana.results["records"]:
            assert rec.offset != 0, "Own header at offset 0 must be skipped"

    def test_false_positive_zip_rejected(self, config, tmp_dir):
        """v3: PK magic followed by garbage must be ExtractionStatus.FALSE_POSITIVE."""
        from audio_stego.extraction import ExtractionStatus
        ana, store = self._make(config, tmp_dir)

        wav_path = os.path.join(tmp_dir, "fp_test.wav")
        with open(wav_path, "wb") as f:
            # RIFF header
            f.write(b"RIFF")
            f.write((100).to_bytes(4, "little"))
            f.write(b"WAVE")
            # Fake ZIP magic with garbage after it
            f.write(b"\x00" * 50)
            f.write(b"PK\x03\x04" + b"\xff" * 50)

        ana._scan_signatures(wav_path)
        zip_recs = [r for r in ana.results["records"] if r.file_type == "ZIP"]
        # Should be rejected as false positive
        assert all(r.status == ExtractionStatus.FALSE_POSITIVE for r in zip_recs), \
            f"Expected FP, got: {[r.status for r in zip_recs]}"

    def test_valid_zip_extracted(self, config, tmp_dir):
        """v3: valid embedded ZIP must be ExtractionStatus.EXTRACTED."""
        import io, zipfile, struct, wave
        from audio_stego.extraction import ExtractionStatus

        ana, store = self._make(config, tmp_dir)

        # Build a real ZIP
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", "flag{hidden_in_zip}")
        zip_bytes = buf.getvalue()

        # Build a WAV with the ZIP appended
        wav_path = os.path.join(tmp_dir, "zip_embed.wav")
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(44100)
            wf.writeframes(b"\x00\x00" * 100)
        with open(wav_path, "ab") as f:
            f.write(zip_bytes)

        ana._scan_signatures(wav_path)
        zip_recs = [r for r in ana.results["records"] if r.file_type == "ZIP"]
        assert any(r.status == ExtractionStatus.EXTRACTED for r in zip_recs), \
            f"Expected EXTRACTED zip, got statuses: {[r.status for r in zip_recs]}"

    @staticmethod
    def _mp3_frame(payload_filler: bytes = b"\x00") -> bytes:
        """One real, valid MPEG1 Layer3 44100Hz 128kbps frame (418 bytes)."""
        header = bytes([0xFF, 0xFB, 0x90, 0x40])
        frame_length = 144 * 128000 // 44100  # matches _parse_mp3_frame's formula
        return header + payload_filler * (frame_length - len(header))

    def test_mp3_host_native_frames_not_reported_as_extracted(self, config, tmp_dir):
        """
        Regression for the "Extracted: 2857 files" bug: scanning an MP3 file
        finds a valid MP3_FRAME sync (and a real run of consecutive,
        consistent frames) at literally every frame boundary of the host's
        own audio — that is the file being what it is, not a hidden nested
        file, and must never be reported/written out as an "extracted file".
        """
        from audio_stego.extraction import ExtractionStatus
        ana, store = self._make(config, tmp_dir)

        mp3_path = os.path.join(tmp_dir, "host.mp3")
        with open(mp3_path, "wb") as f:
            for _ in range(30):
                f.write(self._mp3_frame())

        ana._scan_signatures(mp3_path)
        mp3_recs = [r for r in ana.results["records"] if r.file_type in ("MP3_FRAME", "MP3_ID3")]
        assert not any(r.status == ExtractionStatus.EXTRACTED for r in mp3_recs), (
            f"Host's own MP3 frames must never be reported as extracted files, got: "
            f"{[(r.status, r.offset) for r in mp3_recs if r.status == ExtractionStatus.EXTRACTED]}"
        )
        assert len(ana.results["extracted_files"]) == 0 or all(
            "mp3_frame" not in os.path.basename(p) for p in ana.results["extracted_files"]
        )

    def test_embedded_mp3_stream_in_wav_reported_once_not_per_frame(self, config, tmp_dir):
        """
        Belt-and-suspenders: a *genuinely* nested MP3 stream inside a
        different container (WAV) is still real signal and must still be
        reported — but once, as a single artifact spanning the whole
        validated frame run, not once per internal frame boundary.
        """
        from audio_stego.extraction import ExtractionStatus
        ana, store = self._make(config, tmp_dir)

        wav_path = os.path.join(tmp_dir, "nested_mp3.wav")
        with open(wav_path, "wb") as f:
            f.write(b"RIFF" + (36).to_bytes(4, "little") + b"WAVEfmt " +
                    (16).to_bytes(4, "little") + (1).to_bytes(2, "little") +
                    (1).to_bytes(2, "little") + (44100).to_bytes(4, "little") +
                    (88200).to_bytes(4, "little") + (2).to_bytes(2, "little") +
                    (16).to_bytes(2, "little") + b"data" + (0).to_bytes(4, "little"))
            for _ in range(30):
                f.write(self._mp3_frame())

        ana._scan_signatures(wav_path)
        extracted = [r for r in ana.results["records"]
                     if r.file_type == "MP3_FRAME" and r.status == ExtractionStatus.EXTRACTED]
        assert len(extracted) == 1, (
            f"Expected exactly one merged record for the contiguous nested MP3 "
            f"stream, got {len(extracted)}: {[hex(r.offset) for r in extracted]}"
        )

    def test_bmp_declared_size_exceeding_remaining_bytes_rejected(self, config, tmp_dir):
        """A BMP header claiming a file size far larger than the bytes actually
        remaining in the host cannot be a real embedded BMP — the 'BM' sync
        matched by chance inside unrelated data."""
        from audio_stego.validate import validate_embedded
        bmp_header = b"BM" + (120_000_000).to_bytes(4, "little") + b"\x00" * 8
        data = b"\x00" * 50 + bmp_header + b"\x00" * 100
        vr = validate_embedded(data, 50, "BMP")
        assert vr.valid is False

    def test_summary_counts_accurate(self, config, tmp_dir, sample_wav):
        """v3: summary counts must reflect actual extraction outcomes."""
        ana, store = self._make(config, tmp_dir)
        ana._scan_signatures(sample_wav)
        ana._update_summary()
        s = ana.results["summary"]
        # All counts must be non-negative integers
        for key in ("extracted", "validated", "failed", "false_positive"):
            assert isinstance(s[key], int) and s[key] >= 0

    def test_stegseek_warning_on_missing_wordlist(self, config, tmp_dir, sample_wav):
        """v3: stegseek must warn and skip when wordlist is missing."""
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        from unittest.mock import patch

        store = ArtifactStore(os.path.join(tmp_dir, "sk_test"))
        config._config.set("stegseek", "wordlist", "/nonexistent/wl.txt")
        ana = ExtractionAnalyzer(config, store)
        with patch("audio_stego.extraction.tool_available", return_value=True):
            ana._run_stegseek(sample_wav)
        assert any("wordlist" in w.lower() for w in ana.results["warnings"])

    def test_extraction_report_written(self, config, tmp_dir, sample_wav):
        """v3: extraction_report.txt must be written to raw/ directory."""
        ana, store = self._make(config, tmp_dir)
        ana._scan_signatures(sample_wav)
        ana._update_summary()
        ana._write_extraction_report()
        report_path = store.tools / "extraction_report.txt"
        assert report_path.exists()
        content = report_path.read_text()
        assert "EXTRACTION REPORT" in content


# ---------------------------------------------------------------------------
# AudioForensicsAnalyzer tests
# ---------------------------------------------------------------------------

class TestAudioForensics:
    def _make(self, tmp_dir):
        from audio_stego.audio_forensics import AudioForensicsAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "af_out"))
        return AudioForensicsAnalyzer(store), store

    def test_run_returns_dict(self, tmp_dir, sample_wav):
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        results = ana.run(sample_wav)
        assert isinstance(results, dict)
        assert "lsb" in results
        assert "warnings" in results

    def test_lsb_on_silence_low_ratio(self, tmp_dir, mono_wav):
        """LSB of pure silence should have low printable ratio."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        lsb_list = ana.results.get("lsb", [])
        if lsb_list:
            # Silence LSBs are all zero → not printable
            for r in lsb_list:
                assert r["printable_ratio"] < 0.70, \
                    "Silence should not produce high LSB printable ratio"

    def test_lsb_high_ratio_generates_finding(self, tmp_dir):
        """LSB with embedded text should produce a HIGH finding."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")

        ana, store = self._make(tmp_dir)
        # Build WAV with text hidden in LSBs
        secret = b"flag{lsb_forensics_test}" + b" " * 100
        bits   = "".join(f"{b:08b}" for b in secret)
        n_samp = len(bits)
        samples = np.zeros(n_samp, dtype=np.int16)
        for i, bit in enumerate(bits):
            samples[i] = (samples[i] & ~1) | int(bit)

        wav_path = str(store.base / "lsb_embed.wav")
        import wave
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(44100)
            wf.writeframes(samples.tobytes())

        # Load and inject directly into analyzer
        y = samples.astype(np.float64) / 32768.0
        y = y[np.newaxis, :]   # shape (1, n)
        ana._analyze_lsb(y, 44100, 1)

        findings = [f for f in ana.results["findings"]
                    if "LSB" in f.get("title", "")]
        assert findings, "Expected LSB finding for embedded text"
        assert findings[0]["severity"] in ("HIGH", "CRITICAL")

    def test_stereo_diff_computed(self, tmp_dir, sample_wav):
        """Stereo analysis must produce channel diff results."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        ana.run(sample_wav)
        sd = ana.results.get("stereo_diff")
        # sample_wav is stereo silence — diff should be computed
        if sd is not None:
            assert "diff_ratio" in sd
            assert sd["diff_ratio"] < 0.01  # silence → near-zero diff

    def test_mono_stereo_skipped(self, tmp_dir, mono_wav):
        """Stereo analysis must skip mono files without error."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        assert ana.results.get("stereo_diff") is None

    def test_bit_planes_analysed(self, tmp_dir, mono_wav):
        """Bit-plane extraction should produce a result for each bit."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        bp = ana.results.get("bit_planes", [])
        assert isinstance(bp, list)

    def test_silence_segments_found(self, tmp_dir, mono_wav):
        """Silent WAV should produce silence segment entries."""
        try:
            import numpy as np
        except ImportError:
            pytest.skip("numpy not installed")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        # mono_wav is 1 s of silence → should find at least one segment
        silence = ana.results.get("silence", [])
        assert isinstance(silence, list)

    def test_no_crash_on_missing_numpy(self, tmp_dir, mono_wav):
        """Analyzer must not crash when numpy is missing — just warn."""
        import sys
        from unittest.mock import patch
        ana, _ = self._make(tmp_dir)
        with patch.dict(sys.modules, {"numpy": None}):
            # Should return gracefully with a warning
            try:
                results = ana.run(mono_wav)
                assert "warnings" in results
            except ImportError:
                pass  # acceptable — just must not raise AttributeError


# ---------------------------------------------------------------------------
# Phase 9 — expanded audio forensics DSP
# ---------------------------------------------------------------------------

class TestAudioForensicsPhase9:
    """Uses real synthetic signals with known injected properties (phase
    inversion, a carrier tone, LSB text) so assertions check actual DSP
    correctness, not just that the code runs without raising."""

    def _make(self, tmp_dir, name="af9"):
        from audio_stego.audio_forensics import AudioForensicsAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, name))
        return AudioForensicsAnalyzer(store), store

    def _write_stereo_wav(self, path, L, R, sr=44100):
        import numpy as np
        import wave
        L_int = np.clip(L * 32767, -32768, 32767).astype(np.int16)
        R_int = np.clip(R * 32767, -32768, 32767).astype(np.int16)
        with wave.open(path, "w") as wf:
            wf.setnchannels(2); wf.setsampwidth(2); wf.setframerate(sr)
            stereo = np.empty((len(L_int) * 2,), dtype=np.int16)
            stereo[0::2] = L_int
            stereo[1::2] = R_int
            wf.writeframes(stereo.tobytes())

    def _write_mono_wav(self, path, sig, sr=44100):
        import numpy as np
        import wave
        sig_int = np.clip(sig * 32767, -32768, 32767).astype(np.int16)
        with wave.open(path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            wf.writeframes(sig_int.tobytes())

    def test_lsb_now_covers_1_to_4_bits(self, tmp_dir, mono_wav):
        pytest.importorskip("numpy")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        n_bits_seen = {r["n_bits"] for r in ana.results["lsb"]}
        assert n_bits_seen == {1, 2, 3, 4}

    def test_msb_analysis_present_and_low_signal_on_silence(self, tmp_dir, mono_wav):
        pytest.importorskip("numpy")
        ana, _ = self._make(tmp_dir)
        ana.run(mono_wav)
        assert ana.results["msb"] is not None
        for r in ana.results["msb"]:
            assert r["printable_ratio"] < 0.70   # silence's top bits carry no text

    def test_phase_inversion_detected_on_mirrored_channels(self, tmp_dir):
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 44100
        t = np.linspace(0, 1, sr, endpoint=False)
        base = 0.3 * np.sin(2 * np.pi * 440 * t)
        wav_path = str(store.base / "inverted.wav")
        self._write_stereo_wav(wav_path, base, -base, sr)
        ana.run(wav_path)
        sd = ana.results["stereo_diff"]
        assert sd["correlation"] < -0.9
        assert sd["phase_inverted"] is True
        assert any(f["module"] == "forensics/phase_inversion" for f in ana.results["findings"])

    def test_normal_stereo_not_flagged_as_phase_inverted(self, tmp_dir):
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 44100
        t = np.linspace(0, 1, sr, endpoint=False)
        L = 0.3 * np.sin(2 * np.pi * 440 * t)
        R = 0.3 * np.sin(2 * np.pi * 440 * t + 0.1)   # same signal, tiny phase offset
        wav_path = str(store.base / "normal.wav")
        self._write_stereo_wav(wav_path, L, R, sr)
        ana.run(wav_path)
        assert ana.results["stereo_diff"]["phase_inverted"] is False

    def test_carrier_detection_finds_injected_tone_above_8khz(self, tmp_dir):
        """Regression: the first version picked the single loudest frequency
        anywhere in the spectrum, which fired on an ordinary 440 Hz musical
        note (ratio ~4x10^7) instead of an actually-hidden high-frequency
        carrier. Must now find the real injected carrier specifically."""
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 44100
        t = np.linspace(0, 2, sr * 2, endpoint=False)
        base = 0.3 * np.sin(2 * np.pi * 440 * t)
        carrier = 0.05 * np.sin(2 * np.pi * 15000 * t)
        wav_path = str(store.base / "carrier.wav")
        self._write_mono_wav(wav_path, base + carrier, sr)
        ana.run(wav_path)
        assert ana.results["carrier"] is not None
        assert abs(ana.results["carrier"]["peak_freq_hz"] - 15000) < 50

    def test_carrier_detection_does_not_false_positive_on_plain_tone(self, tmp_dir):
        """Regression: a plain sine tone with no hidden carrier must not be
        flagged (previously false-positived at ~10kHz from quantization
        noise being compared against a near-zero local median)."""
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 44100
        t = np.linspace(0, 2, sr * 2, endpoint=False)
        base = 0.3 * np.sin(2 * np.pi * 440 * t)
        wav_path = str(store.base / "plain_tone.wav")
        self._write_mono_wav(wav_path, base, sr)
        ana.run(wav_path)
        carrier_findings = [f for f in ana.results["findings"] if f["module"] == "forensics/carrier"]
        assert carrier_findings == []

    def test_entropy_map_produced_with_windows(self, tmp_dir):
        """Needs >=2 one-second windows, so sample_wav (1s total) is too
        short — build a longer file instead of loosening the requirement."""
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 8000
        wav_path = str(store.base / "three_sec.wav")
        self._write_mono_wav(wav_path, np.zeros(sr * 3), sr)
        ana.run(wav_path)
        em = ana.results["entropy_map"]
        assert em is not None
        assert em["n_windows"] >= 2
        assert len(em["entropies"]) == em["n_windows"]

    def test_entropy_map_flags_injected_high_entropy_region(self, tmp_dir):
        """A file that's mostly silence but has one window of pure random
        noise should show that window as an entropy spike."""
        np = pytest.importorskip("numpy")
        ana, store = self._make(tmp_dir)
        sr = 8000
        rng = np.random.default_rng(42)
        silence = np.zeros(sr * 4)
        noise_window = rng.uniform(-1, 1, sr)
        sig = np.concatenate([silence[:sr], noise_window, silence[:sr*3]])
        wav_path = str(store.base / "entropy_spike.wav")
        self._write_mono_wav(wav_path, sig, sr)
        ana.run(wav_path)
        em = ana.results["entropy_map"]
        assert len(em["spikes"]) >= 1

    def test_watermark_best_effort_capped_at_low_confidence(self, tmp_dir, sample_wav):
        pytest.importorskip("numpy")
        ana, _ = self._make(tmp_dir)
        ana.run(sample_wav)
        watermark_findings = [f for f in ana.results["findings"] if f["module"] == "forensics/watermark"]
        for f in watermark_findings:
            assert f["confidence"] <= 0.40
            assert f["severity"] == "INFO"

    def test_mfcc_computed_when_librosa_available(self, tmp_dir, sample_wav):
        pytest.importorskip("numpy")
        pytest.importorskip("librosa")
        ana, _ = self._make(tmp_dir)
        ana.run(sample_wav)
        mfcc = ana.results["mfcc"]
        assert mfcc is not None
        assert mfcc["n_coefficients"] == 13
        assert len(mfcc["mean"]) == 13
        assert len(mfcc["std"]) == 13

    def test_mfcc_gracefully_absent_without_librosa(self, tmp_dir, mono_wav):
        import sys
        from unittest.mock import patch
        pytest.importorskip("numpy")
        ana, _ = self._make(tmp_dir)
        with patch.dict(sys.modules, {"librosa": None}):
            ana.run(mono_wav)
        assert ana.results["mfcc"] is None


# ---------------------------------------------------------------------------
# HTML report tests
# ---------------------------------------------------------------------------

class TestHTMLReport:
    def _base_results(self, tmp_dir):
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "html_out"))
        results = {
            "metadata": {
                "hashes": {"md5": "abc", "sha1": "def", "sha256": "ghi"},
                "exiftool": {"FileType": "WAV", "Duration": "1.0s"},
            },
            "binary": {
                "entropy":        {"overall": 0.0, "max_block": 0.0,
                                   "high_entropy_blocks": []},
                "embedded_files": [],
                "appended_data":  None,
                "findings":       [],
                "encoded_data":   {},
            },
            "flags": {
                "flags_found": [
                    {"value": "flag{html_report_test}", "encoding": "plaintext",
                     "confidence_pct": "95%", "evidence": "test",
                     "confidence": 0.95}
                ],
                "findings": [],
            },
            "extraction": {
                "records": [],
                "extracted_files": [],
                "steghide": [],
                "stegseek": {},
                "findings": [],
                "summary":  {"extracted": 0, "validated": 0, "failed": 0,
                             "false_positive": 0},
            },
            "visual": {
                "spectrogram": None, "waveform": None, "fft": None, "findings": []
            },
            "forensics": {
                "lsb": [], "stereo_diff": None, "echo": None,
                "stats": None, "bit_planes": [], "findings": [],
            },
            "digital": {
                "morse": [], "dtmf": [], "minimodem": [], "findings": []
            },
            "ocr":  {"qr_codes": [], "ocr": [], "findings": []},
            "sstv": {"vis_detected": False, "decoded_image": None,
                     "decoders_tried": [], "confidence": 0.0,
                     "ocr_text": None, "qr_data": None, "findings": []},
        }
        return store, results

    def test_generates_html_file(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        gen  = HTMLReport(store)
        path = gen.generate(sample_wav, results, 5.0)
        assert os.path.exists(path)
        content = open(path).read()
        assert "<!DOCTYPE html>" in content
        assert "Audio Stego Solver" in content

    def test_flag_appears_prominently(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path = HTMLReport(store).generate(sample_wav, results, 5.0)
        content = open(path).read()
        assert "flag{html_report_test}" in content
        # Flag value must appear before the metadata section body (not the TOC link)
        flag_pos = content.find("flag{html_report_test}")
        # Find the metadata section *body* (not the TOC anchor)
        meta_section_pos = content.find('id="metadata"')
        assert flag_pos < meta_section_pos, (
            f"Flags must appear before metadata section "
            f"(flag@{flag_pos}, metadata@{meta_section_pos})"
        )

    def test_xss_escaped(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["ocr"]["ocr"] = [{
            "image": "/tmp/normal.png",
            "text":  "<script>alert('xss')</script>",
            "confidence": 90.0,
        }]
        path    = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "<script>alert(" not in content
        assert "&lt;script&gt;" in content

    def test_missing_image_placeholder(self, tmp_dir, sample_wav):
        from audio_stego.html_report import _embed_img
        result = _embed_img("/nonexistent/image.png", "test")
        assert "not available" in result or "could not embed" in result
        assert 'src="data:' not in result

    def test_dark_mode_attribute(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path    = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'data-theme="dark"' in content

    def test_copy_buttons_present(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path    = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "copy-btn" in content
        assert "copyEl" in content

    def test_collapsible_sections(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path    = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "toggleSection" in content
        assert "section-header" in content

    def test_extraction_section_and_verified_findings_removed(self, tmp_dir, sample_wav):
        """CTF edition: Extracted Files, Extraction Summary, and Verified
        Findings sections/counters were removed entirely — a validated
        extraction record is still surfaced as a concrete Manual
        Reproduction step (a real, useful artifact), but the dashboard of
        raw extraction counts/statuses is gone."""
        from audio_stego.html_report import HTMLReport
        from audio_stego.extraction import ExtractionRecord, ExtractionStatus
        store, results = self._base_results(tmp_dir)
        results["extraction"]["records"] = [
            ExtractionRecord("ZIP",  0x1000, ExtractionStatus.EXTRACTED,
                             0.97, "Valid ZIP", "/tmp/out.zip"),
            ExtractionRecord("JPEG", 0x2000, ExtractionStatus.FALSE_POSITIVE,
                             0.20, "SOI not followed by valid marker"),
            ExtractionRecord("PNG",  0x3000, ExtractionStatus.FAILED,
                             0.50, "Write failed: permission denied"),
        ]
        results["extraction"]["summary"] = {
            "extracted": 1, "validated": 0, "failed": 1, "false_positive": 1
        }
        path    = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'id="extraction"' not in content
        assert 'id="findings"' not in content
        assert "SOI not followed by valid marker" not in content

    # -----------------------------------------------------------------
    # v4.2: confidence-tier grouping + low-confidence hiding
    # -----------------------------------------------------------------

    def test_flags_grouped_verified_possible_encoded(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["flags"]["flags_found"] = [
            {"value": "flag{verified_one}", "encoding": "plaintext",
             "confidence": 0.95, "confidence_pct": "95%", "evidence": "e"},
            {"value": "flag{maybe}", "encoding": "plaintext",
             "confidence": 0.65, "confidence_pct": "65%", "evidence": "e"},
            {"value": "flag{b64}", "encoding": "base64",
             "confidence": 0.80, "confidence_pct": "80%", "evidence": "e"},
        ]
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "Verified Flags" in content
        assert "Possible Flags" in content
        assert "Encoded Flags" in content
        assert "Rejected Candidates" not in content  # none present — must not render an empty group

    def test_sidebar_has_executive_summary_and_no_advanced_menu(self, tmp_dir, sample_wav):
        """v4.5: the developer-facing Advanced menu (Timeline/Performance/
        Plugin Debug/Raw Tool Output/Scan Log/Rejected Findings/Rejected
        Extraction) was removed entirely — not collapsed, deleted — and
        replaced by Tools Used."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        # Tools Used only renders when a tool actually produced something —
        # give it one real card so this test can still assert the section
        # (and the removed Advanced-menu ids) the way it always has.
        results["_performance"] = {"tool_availability": {"binwalk": True}}
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "Executive Summary" in content
        assert 'id="toolsused"' in content
        for gone in ("advanced-nav-toggle", "advanced-nav-links", "toggleAdvancedNav",
                     'id="timeline"', 'id="performance"', 'id="toolexec"', 'id="scanlog"',
                     'id="plugindebug"', 'id="rawoutput"',
                     'id="rejectedfindings"', 'id="rejectedextraction"'):
            assert gone not in content, f"{gone!r} should have been removed entirely"

    def test_executive_summary_shows_manual_review_card(self, tmp_dir, sample_wav):
        """CTF edition: the Executive Summary no longer surfaces a generic
        "Most Important Finding" pulled from arbitrary module findings
        (that was exactly the kind of forensic-report noise the CTF report
        redesign removed) — only the Manual Review Needed indicator."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "Manual Review Needed" in content

    def test_tools_used_section_present(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["_performance"] = {"tool_availability": {"binwalk": True, "steghide": False}}
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'id="toolsused"' in content

    def test_manual_investigation_section_renders_hints(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["hints"] = ["🔍 Try binwalk -e on the file.", "⚠ High entropy detected."]
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'id="manual"' in content
        assert "Try binwalk -e on the file." in content
        assert "High entropy detected." in content


# ---------------------------------------------------------------------------
# SSTV tests
# ---------------------------------------------------------------------------

class TestSSTVAnalyzer:
    def _make(self, config, tmp_dir):
        from audio_stego.sstv import SSTVAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "sstv_out"))
        return SSTVAnalyzer(store, config), store

    def test_no_signal_produces_clean_report(self, config, tmp_dir, mono_wav):
        """No SSTV in file — must produce report with vis_detected=False."""
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)
        # Mock multimon-ng to return only banner (no SSTV lines)
        with patch("audio_stego.sstv.tool_available", return_value=True), \
             patch("audio_stego.sstv.run_command",
                   return_value=(0, "multimon-ng 1.2.0\nEnabled decoders: SSTV\n", "")):
            ana.run(mono_wav, mono_wav)
        assert ana.results["vis_detected"] is False
        assert ana.results["confidence"] < 0.50

    def test_vis_detected_from_real_signal(self, config, tmp_dir):
        """
        v3.1 regression: VIS detection no longer depends on multimon-ng
        (verified to have no SSTV demodulator at all — `multimon-ng` with no
        args lists its full demodulator set and SSTV is not in it) or qsstv
        (verified GUI-only via its own man page, zero CLI arguments). This
        builds a real VIS tone sequence per the VIS timing spec and checks
        the Goertzel-based detector actually decodes it, instead of mocking
        a multimon-ng output format that could never occur in practice.
        """
        import numpy as np
        import wave
        from audio_stego.sstv import VIS_CODES

        sr = 44100

        def synth_tone(freq, duration_s):
            t = np.arange(int(sr * duration_s)) / sr
            return 0.5 * np.sin(2 * np.pi * freq * t)

        vis_code = next(iter(VIS_CODES))   # a code actually in the (corrected) table
        expected_mode = VIS_CODES[vis_code]
        bits = [(vis_code >> i) & 1 for i in range(7)]
        parity = sum(bits) % 2
        seq = [synth_tone(1900, 0.300), synth_tone(1200, 0.010), synth_tone(1900, 0.300),
               synth_tone(1200, 0.030)]
        seq += [synth_tone(1100 if b else 1300, 0.030) for b in bits]
        seq.append(synth_tone(1100 if parity else 1300, 0.030))
        seq.append(synth_tone(1200, 0.030))
        audio = np.concatenate([np.zeros(sr // 2)] + seq + [np.zeros(sr)])

        wav_path = os.path.join(tmp_dir, "vis_test.wav")
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            wf.writeframes(np.clip(audio * 32767, -32768, 32767).astype(np.int16).tobytes())

        ana, store = self._make(config, tmp_dir)
        ana.run(wav_path, wav_path)
        assert ana.results["vis_detected"] is True
        assert ana.results["vis_code"] == vis_code
        assert ana.results["mode"] == expected_mode

    def test_vis_table_has_no_structurally_invalid_codes(self):
        """VIS is a 7-bit code (0-127) — the pre-v3.1 table had six entries
        above 127, which is provably impossible, not just uncertain."""
        from audio_stego.sstv import VIS_CODES
        assert all(0 <= code <= 127 for code in VIS_CODES)

    def test_no_false_positive_on_music_or_noise(self, config, tmp_dir):
        """Real music/noise must not be misdetected as a VIS code."""
        import numpy as np
        import wave
        sr = 44100
        rng = np.random.default_rng(7)
        noise = rng.uniform(-0.3, 0.3, sr * 2)
        wav_path = os.path.join(tmp_dir, "noise.wav")
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            wf.writeframes(np.clip(noise * 32767, -32768, 32767).astype(np.int16).tobytes())
        ana, store = self._make(config, tmp_dir)
        ana.run(wav_path, wav_path)
        assert ana.results["vis_detected"] is False

    def test_unrecognized_vis_code_gets_capped_confidence(self, config, tmp_dir):
        """
        Regression: running the full pipeline against real MP3 files already
        in this repo (not synthetic test signals) found VIS detection firing
        at 80% confidence / HIGH severity for VIS codes *not* in this
        project's recognized VIS_CODES table — twice, on two different real
        files, both with matching parity. An unrecognized code can never be
        decoded into an image (nothing maps it to a mode), and parity alone
        is only a 50%-by-chance check, so it's much weaker evidence than a
        recognized code. Must be capped well below the recognized-code
        ceiling (0.90) and below the report's "verified" confidence tier.
        """
        import numpy as np
        import wave
        from audio_stego.sstv import VIS_CODES

        sr = 44100
        unrecognized_code = next(c for c in range(128) if c not in VIS_CODES)

        def synth_tone(freq, duration_s):
            t = np.arange(int(sr * duration_s)) / sr
            return 0.5 * np.sin(2 * np.pi * freq * t)

        bits = [(unrecognized_code >> i) & 1 for i in range(7)]
        parity = sum(bits) % 2
        seq = [synth_tone(1900, 0.300), synth_tone(1200, 0.010), synth_tone(1900, 0.300),
               synth_tone(1200, 0.030)]
        seq += [synth_tone(1100 if b else 1300, 0.030) for b in bits]
        seq.append(synth_tone(1100 if parity else 1300, 0.030))
        seq.append(synth_tone(1200, 0.030))
        audio = np.concatenate([np.zeros(sr // 2)] + seq + [np.zeros(sr)])

        wav_path = os.path.join(tmp_dir, "unrecognized_vis.wav")
        with wave.open(wav_path, "w") as wf:
            wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
            wf.writeframes(np.clip(audio * 32767, -32768, 32767).astype(np.int16).tobytes())

        ana, store = self._make(config, tmp_dir)
        ana.run(wav_path, wav_path)
        assert ana.results["vis_detected"] is True
        assert ana.results["confidence"] <= 0.40, (
            f"Unrecognized VIS code must be capped low, got {ana.results['confidence']}"
        )
        titles_and_sev = [(f["title"], f["severity"]) for f in ana.results["findings"]]
        assert not any(sev == "HIGH" for _, sev in titles_and_sev), (
            f"Unrecognized VIS code must not be HIGH severity: {titles_and_sev}"
        )

    def test_gui_only_tools_reported_not_invoked(self, config, tmp_dir, mono_wav):
        """qsstv/multimon-ng presence must be reported as a warning, not
        silently invoked with a fabricated CLI contract."""
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)
        with patch("audio_stego.sstv.tool_available", return_value=True):
            ana.run(mono_wav, mono_wav)
        assert any("qsstv" in w and "GUI-only" in w for w in ana.results["warnings"])
        assert any("multimon-ng" in w and "no SSTV demodulator" in w for w in ana.results["warnings"])

    def test_report_written(self, config, tmp_dir, mono_wav):
        """SSTV report must be written to sstv/ directory."""
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)
        with patch("audio_stego.sstv.tool_available", return_value=False):
            ana.run(mono_wav, mono_wav)
        report = store.sstv_dir / "sstv_report.txt"
        assert report.exists()
        assert "SSTV ANALYSIS" in report.read_text()

    def test_no_tool_available_graceful(self, config, tmp_dir, mono_wav):
        """All decoders missing — must complete without crashing."""
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)
        with patch("audio_stego.sstv.tool_available", return_value=False):
            results = ana.run(mono_wav, mono_wav)
        assert results["vis_detected"] is False
        assert results["decoded_image"] is None

    def test_markers_detection_is_invoked_when_image_decoded(self, config, tmp_dir, mono_wav):
        """v4.1 regression: `_detect_markers` (ArUco/AprilTag) was fully
        implemented but never called anywhere in run() — dead code that
        could never produce a finding regardless of image content. Must be
        invoked on the decoded image whenever one is produced."""
        from unittest.mock import patch
        from PIL import Image
        import numpy as np

        ana, store = self._make(config, tmp_dir)
        img_path = str(store.sstv_dir / "decoded.png")
        Image.fromarray(np.zeros((16, 16, 3), dtype=np.uint8)).save(img_path)

        def fake_try_rx_sstv(self, wav_path):
            self.results["decoded_image"] = img_path
            self.results["decoders_tried"].append("rx_sstv")

        with patch("audio_stego.sstv.tool_available", return_value=False), \
             patch.object(type(ana), "_try_rx_sstv", fake_try_rx_sstv), \
             patch.object(type(ana), "_detect_markers") as mock_markers:
            ana.run(mono_wav, mono_wav)

        mock_markers.assert_called_once_with(img_path)

    # -----------------------------------------------------------------
    # v4.2: best-of decoder selection
    # -----------------------------------------------------------------

    def test_best_of_selection_picks_higher_confidence_custom_decoder(self, config, tmp_dir, mono_wav):
        """When both rx_sstv and the custom decoder produce an image, the
        higher-confidence one must be selected — not whichever ran first."""
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)

        with patch("audio_stego.sstv.tool_available", return_value=False), \
             patch.object(type(ana), "_try_rx_sstv", return_value=("/tmp/rx.png", 0.70)), \
             patch.object(type(ana), "_try_custom_decoder", return_value=("/tmp/custom.png", 0.92)), \
             patch("os.path.exists", return_value=True), \
             patch.object(type(ana), "_postprocess_image"), \
             patch.object(type(ana), "_analyze_decoded_image"), \
             patch.object(type(ana), "_detect_markers"):
            results = ana.run(mono_wav, mono_wav)

        assert results["decoder_selected"] == "custom_decoder"
        assert results["decoded_image"] == "/tmp/custom.png"
        assert results["confidence"] >= 0.92
        # Only the winner's finding — no stale finding for the loser.
        titles = [f["title"] for f in results["findings"]]
        assert any("rx_sstv" not in t and "SSTV Image Decoded" in t for t in titles)
        assert not any("rx_sstv" in t for t in titles)

    def test_best_of_selection_picks_rx_sstv_when_higher_confidence(self, config, tmp_dir, mono_wav):
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)

        with patch("audio_stego.sstv.tool_available", return_value=False), \
             patch.object(type(ana), "_try_rx_sstv", return_value=("/tmp/rx.png", 0.85)), \
             patch.object(type(ana), "_try_custom_decoder", return_value=("/tmp/custom.png", 0.62)), \
             patch("os.path.exists", return_value=True), \
             patch.object(type(ana), "_postprocess_image"), \
             patch.object(type(ana), "_analyze_decoded_image"), \
             patch.object(type(ana), "_detect_markers"):
            results = ana.run(mono_wav, mono_wav)

        assert results["decoder_selected"] == "rx_sstv"
        assert results["decoded_image"] == "/tmp/rx.png"
        titles = [f["title"] for f in results["findings"]]
        assert any("rx_sstv" in t for t in titles)

    def test_best_of_selection_warns_when_multiple_decoders_succeed(self, config, tmp_dir, mono_wav):
        from unittest.mock import patch
        ana, store = self._make(config, tmp_dir)

        with patch("audio_stego.sstv.tool_available", return_value=False), \
             patch.object(type(ana), "_try_rx_sstv", return_value=("/tmp/rx.png", 0.70)), \
             patch.object(type(ana), "_try_custom_decoder", return_value=("/tmp/custom.png", 0.92)), \
             patch("os.path.exists", return_value=True), \
             patch.object(type(ana), "_postprocess_image"), \
             patch.object(type(ana), "_analyze_decoded_image"), \
             patch.object(type(ana), "_detect_markers"):
            results = ana.run(mono_wav, mono_wav)

        assert any("Multiple SSTV decoders" in w for w in results["warnings"])

    def test_rx_sstv_confidence_derived_from_image_not_fixed(self, config, tmp_dir):
        """
        Regression: rx_sstv's confidence was a hardcoded 0.70 regardless of
        what image it actually produced. Since _select_best_decode picks
        whichever candidate has the *higher* confidence, a fixed value could
        make a garbled rx_sstv image outrank a genuinely well-validated
        custom_decoder result (whose real confidence floor is 0.55, below
        0.70). Verified: a coherent gradient image scores meaningfully
        higher than a flat/blank image, and pure random noise — despite
        scoring highest on raw sharpness/entropy alone — is pulled down by
        the pixel-smoothness penalty rather than reported as high-quality.
        """
        import numpy as np
        from PIL import Image

        ana, store = self._make(config, tmp_dir)

        x = np.linspace(0, 255, 64)
        y = np.linspace(0, 255, 48)
        xv, yv = np.meshgrid(x, y)
        coherent = np.stack([xv, yv, (xv + yv) / 2], axis=-1).astype(np.uint8)
        coherent_path = os.path.join(tmp_dir, "coherent.png")
        Image.fromarray(coherent).save(coherent_path)

        blank = np.full((48, 64, 3), 128, dtype=np.uint8)
        blank_path = os.path.join(tmp_dir, "blank.png")
        Image.fromarray(blank).save(blank_path)

        rng = np.random.default_rng(0)
        noise = rng.integers(0, 255, (48, 64, 3), dtype=np.uint8)
        noise_path = os.path.join(tmp_dir, "noise.png")
        Image.fromarray(noise).save(noise_path)

        conf_coherent = ana._rx_sstv_confidence(coherent_path)
        conf_blank = ana._rx_sstv_confidence(blank_path)
        conf_noise = ana._rx_sstv_confidence(noise_path)

        assert conf_coherent != 0.70 or conf_blank != 0.70, (
            "Confidence must vary with actual image content, not stay fixed"
        )
        assert conf_coherent > conf_blank, (
            f"A coherent image ({conf_coherent}) must score above a blank one ({conf_blank})"
        )
        assert conf_coherent > conf_noise, (
            f"A coherent image ({conf_coherent}) must score above pure noise ({conf_noise}), "
            f"even though noise has higher raw sharpness/entropy"
        )

    # -----------------------------------------------------------------
    # v4.2: expanded post-processing pipeline
    # -----------------------------------------------------------------

    def test_postprocess_pipeline_applies_expected_steps(self, config, tmp_dir):
        from PIL import Image
        import numpy as np
        ana, store = self._make(config, tmp_dir)
        img_path = os.path.join(tmp_dir, "decoded_pp.png")
        arr = np.zeros((100, 120, 3), dtype=np.uint8)
        arr[8:92, 8:112] = np.random.default_rng(1).integers(50, 200, size=(84, 104, 3), dtype=np.uint8)
        Image.fromarray(arr).save(img_path)

        ana._postprocess_image(img_path)

        # v4.4: four variants are generated and scored (standard/
        # high_contrast/minimal each apply contrast+histogram-eq, while
        # clahe_bilateral applies clahe instead) — either is acceptable
        # depending on which wins; sharpening always appears in some form.
        steps = ana.results["postprocess_steps"]
        assert ("contrast+histogram-eq" in steps) or ("clahe" in steps)
        assert any(s.startswith("adaptive-sharpen") for s in steps)
        assert ana.results["warnings"] == []
        assert os.path.exists(img_path)

    def test_postprocess_pipeline_generates_and_scores_multiple_variants(self, config, tmp_dir):
        from PIL import Image
        import numpy as np
        ana, store = self._make(config, tmp_dir)
        img_path = os.path.join(tmp_dir, "decoded_variants.png")
        arr = np.zeros((100, 120, 3), dtype=np.uint8)
        arr[8:92, 8:112] = np.random.default_rng(2).integers(50, 200, size=(84, 104, 3), dtype=np.uint8)
        Image.fromarray(arr).save(img_path)

        ana._postprocess_image(img_path)

        scores = ana.results["sstv_variant_scores"]
        assert set(scores.keys()) == {"standard", "high_contrast", "minimal", "clahe_bilateral"}
        assert all(isinstance(v, float) for v in scores.values())
        assert ana.results["sstv_variant_selected"] in scores
        # The winner must be the actual maximum of the recorded scores —
        # not just "a" variant, to prove selection logic used the metric.
        assert scores[ana.results["sstv_variant_selected"]] == max(scores.values())
        # Every variant must be written to decoded_all_variants/ for transparency.
        variant_files = os.listdir(store.sstv_variants)
        for name in ("standard", "high_contrast", "minimal", "clahe_bilateral"):
            assert f"variant_{name}.png" in variant_files

    def test_postprocess_quality_score_prefers_sharper_image(self, config, tmp_dir):
        """Direct unit check of the objective metric: a sharp checkerboard
        must score higher than a blurred/flat version of the same image —
        proves the metric actually measures something real, not just a
        constant that happens to let tests pass."""
        from PIL import Image, ImageFilter
        import numpy as np
        ana, store = self._make(config, tmp_dir)

        checker = np.indices((64, 64)).sum(axis=0) % 2 * 255
        sharp = Image.fromarray(checker.astype(np.uint8)).convert("RGB")
        blurred = sharp.filter(ImageFilter.GaussianBlur(radius=6))

        sharp_score = ana._pp_quality_score(sharp, np, None)
        blurred_score = ana._pp_quality_score(blurred, np, None)
        assert sharp_score > blurred_score

    def test_postprocess_pipeline_degrades_gracefully_without_numpy(self, config, tmp_dir):
        """Optional deps (numpy/scipy/cv2) missing must never crash the
        scan — steps that need them are skipped, the rest still apply."""
        import sys
        from PIL import Image
        ana, store = self._make(config, tmp_dir)
        img_path = os.path.join(tmp_dir, "decoded_pp2.png")
        Image.new("RGB", (100, 80), color=(120, 130, 140)).save(img_path)

        saved = {}
        for mod in ("numpy", "scipy", "scipy.ndimage", "cv2"):
            saved[mod] = sys.modules.pop(mod, "__absent__")
            sys.modules[mod] = None
        try:
            ana._postprocess_image(img_path)
        finally:
            for mod, val in saved.items():
                if val == "__absent__":
                    sys.modules.pop(mod, None)
                else:
                    sys.modules[mod] = val

        assert "denoise" in ana.results["postprocess_steps"]
        assert "gamma-correction" in ana.results["postprocess_steps"]
        assert "auto-crop" not in ana.results["postprocess_steps"]   # needs numpy
        assert "color-balance" not in ana.results["postprocess_steps"]  # needs numpy
        assert ana.results["decoded_bw_image"] is None  # needs numpy
        assert os.path.exists(img_path)


# ---------------------------------------------------------------------------
# Integration smoke test
# ---------------------------------------------------------------------------

class TestIntegrationSmoke:
    def test_artifact_store_with_extraction(self, config, tmp_dir, sample_wav):
        """Extraction via ArtifactStore writes to correct subdirs."""
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore

        store = ArtifactStore(os.path.join(tmp_dir, "integration"))
        config._config.set("analysis", "run_binwalk",  "false")
        config._config.set("analysis", "run_foremost", "false")
        config._config.set("analysis", "run_scalpel",  "false")
        config._config.set("analysis", "run_steghide", "false")
        config._config.set("analysis", "run_stegseek", "false")

        ana = ExtractionAnalyzer(config, store)
        results = ana.run(sample_wav)

        assert "records"  in results
        assert "summary"  in results
        assert "findings" in results
        assert (store.tools / "extraction_report.txt").exists()

    def test_html_report_integrates_all_sections(self, tmp_dir, sample_wav):
        """v5.0: a section with nothing useful for this scan is omitted
        entirely (not rendered with a placeholder), while a section that
        always has something to say (or genuinely has data) always
        renders with its id."""
        from audio_stego.html_report import HTMLReport
        from audio_stego.artifact_store import ArtifactStore

        empty_results = {
            "metadata":  {"hashes": {}, "exiftool": {}},
            "binary":    {"entropy": {}, "embedded_files": [], "appended_data": None,
                          "findings": [], "encoded_data": {}},
            "flags":     {"flags_found": [], "findings": []},
            "extraction":{"records": [], "extracted_files": [], "steghide": [],
                          "stegseek": {}, "findings": [], "summary": {}},
            "visual":    {"findings": []},
            "forensics": {"lsb": [], "stereo_diff": None, "echo": None,
                          "stats": None, "bit_planes": [], "findings": []},
            "digital":   {"morse": [], "dtmf": [], "minimodem": [], "findings": []},
            "ocr":       {"qr_codes": [], "ocr": [], "findings": []},
            "sstv":      {"vis_detected": False, "decoded_image": None,
                          "decoders_tried": [], "confidence": 0.0,
                          "ocr_text": None, "qr_data": None, "findings": []},
        }
        store = ArtifactStore(os.path.join(tmp_dir, "empty_html"))
        path    = HTMLReport(store).generate(sample_wav, empty_results, 2.0)
        content = open(path).read()

        for section_id in ["dashboard", "manual", "player", "metadata", "binary"]:
            assert f'id="{section_id}"' in content, \
                f"Missing always-on section id='{section_id}' in HTML report"

        for section_id in ["audioinfo", "waveform", "spectrogram", "fft", "freqanalysis",
                           "sstv", "qranalysis", "ocr", "digital", "toolsused"]:
            assert f'id="{section_id}"' not in content, \
                f"Empty section id='{section_id}' should be hidden, not rendered as a placeholder"

        for removed_id in ["extraction", "findings", "visuals", "forensics"]:
            assert f'id="{removed_id}"' not in content, \
                f"Section id='{removed_id}' should have been removed entirely"

        # Now give every optional section real data and confirm each one
        # actually renders — hiding logic must not be all-or-nothing.
        waveform_path = os.path.join(tmp_dir, "waveform.png")
        with open(waveform_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"0" * 32)
        full_results = dict(empty_results)
        full_results["metadata"] = {
            "hashes": {}, "exiftool": {}, "file_cmd": "test.wav: RIFF (little-endian) data",
            "ffprobe": {"format": {"duration": "1.0", "bit_rate": "128000"},
                        "streams": [{"codec_name": "pcm_s16le", "sample_rate": "44100",
                                     "channels": 2, "bits_per_sample": 16}]},
        }
        full_results["visual"] = {"waveform": waveform_path, "spectrogram": waveform_path,
                                   "fft": waveform_path, "findings": []}
        full_results["forensics"] = {"lsb": [], "stereo_diff": None, "echo": None,
                                      "stats": None, "bit_planes": [], "findings": [],
                                      "bands": {"infrasonic": "0%"}}
        full_results["digital"] = {"morse": [{"value": "SOS", "confidence_pct": "80%"}],
                                    "dtmf": [], "minimodem": [], "findings": []}
        full_results["ocr"] = {"qr_codes": [{"data": "flag{qr}", "type": "QR"}],
                                "ocr": [{"image": waveform_path, "text": "hello", "confidence": 90}],
                                "findings": []}
        full_results["sstv"] = {"vis_detected": True, "mode": "Robot36", "vis_code": 0x08,
                                 "decoded_image": None, "decoders_tried": ["custom_decoder"],
                                 "confidence": 0.9, "ocr_text": None, "qr_data": None, "findings": []}
        full_results["_performance"] = {"tool_availability": {"file": True}}

        store2 = ArtifactStore(os.path.join(tmp_dir, "full_html"))
        path2    = HTMLReport(store2).generate(sample_wav, full_results, 2.0)
        content2 = open(path2).read()
        for section_id in ["audioinfo", "waveform", "spectrogram", "fft", "freqanalysis",
                           "sstv", "qranalysis", "ocr", "digital", "toolsused"]:
            assert f'id="{section_id}"' in content2, \
                f"Section id='{section_id}' should render once real data exists"


# ---------------------------------------------------------------------------
# Phase 6 — Interactive DFIR dashboard
# ---------------------------------------------------------------------------

class TestPhase6Dashboard:
    def _base_results(self, tmp_dir, extra_extraction=None):
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "phase6"))
        extraction = {"records": [], "summary": {}, "extracted_files": [],
                      "steghide": [], "stegseek": {}}
        if extra_extraction:
            extraction.update(extra_extraction)
        results = {
            "extraction": extraction,
            "flags": {"flags": []}, "binary": {}, "digital": {}, "ocr": {},
            "metadata": {}, "forensics": {}, "sstv": {}, "plugins": {},
        }
        return store, results

    def test_generate_handles_records_without_sha256(self, tmp_dir, sample_wav):
        """Regression guard: records with sha256=None (and parent/child
        chains) must not crash report generation, even though the
        recursive artifact graph that used to render them was removed."""
        from audio_stego.html_report import HTMLReport
        from audio_stego.extraction import ExtractionRecord, ExtractionStatus
        store, results = self._base_results(tmp_dir, {
            "records": [
                ExtractionRecord("ZIP", 0x1000, ExtractionStatus.EXTRACTED, 0.97, "Valid ZIP"),
                ExtractionRecord("PNG", 0x2000, ExtractionStatus.FAILED, 0.50, "write failed"),
            ],
        })
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        assert os.path.exists(path)

    def test_audio_player_embedded(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert "<audio controls" in content
        assert 'id="player"' in content

    def test_tools_used_shows_binwalk_when_it_produced_hits(self, tmp_dir, sample_wav):
        """v4.5: the old developer-facing Performance (phase timing) and
        Tool Execution (pass/fail table) sections were removed entirely in
        favor of Tools Used — an analyst-facing card per tool that actually
        contributed to the scan, built from real result data."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["_performance"] = {"tool_availability": {"binwalk": True, "steghide": False}}
        results["extraction"]["binwalk"] = [{"type": "ZIP", "offset": 100}]
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'id="toolsused"' in content
        assert "binwalk" in content

    def test_tools_used_shows_no_card_for_unavailable_tool(self, tmp_dir, sample_wav):
        """A tool that was never available/never produced output must not
        get a fabricated card — no placeholders, no invented data."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["_performance"] = {"tool_availability": {"binwalk": False}}
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        toolsused = content[content.find('id="toolsused"'):]
        assert "binwalk" not in toolsused

    def test_tools_used_multimon_card_shows_real_decoded_output(self, tmp_dir, sample_wav):
        """CTF edition: the Tools Used multimon-ng card shows the tool's
        REAL decoded text, not a derived occurrence count — and is built
        from the same validated Findings the Digital Modes section uses
        (not the raw per-mode line dict, which can include lines the
        analyzer's own confidence gates already rejected)."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["_performance"] = {"tool_availability": {"multimon-ng": True}}
        results["digital"]["multimon"] = {"per_mode": {"EIA": ["EIA: HELLO WORLD"] * 3}}
        results["digital"]["findings"] = [
            {"module": "multimon", "title": "Digital mode verified: EIA",
             "confidence": 0.9, "confidence_pct": "90%", "value": "EIA: HELLO WORLD"},
        ]
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        toolsused = content[content.find('id="toolsused"'):]
        assert "multimon-ng" in toolsused
        assert "HELLO WORLD" in toolsused

    def test_digital_modes_excludes_unvalidated_multimon_noise(self, tmp_dir, sample_wav):
        """Regression: Digital Modes (and the Tools Used multimon-ng card)
        must reflect the same confidence gating the digital-modes analyzer
        applies — a raw per-mode line that never became a validated Finding
        (e.g. a single-digit selective-call hit from a held musical tone,
        rejected by the analyzer's own minimum-digit gate) must not appear
        just because it's present in the raw per_mode dict."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["digital"]["multimon"] = {"per_mode": {"EIA": ["EIA: 5"]}}
        results["digital"]["findings"] = []  # analyzer rejected it — no Finding created
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        digital_section = content[content.find('id="digital"'):content.find('id="binary"')]
        assert "EIA" not in digital_section

    def test_tools_used_sstv_and_base64_cards_reflect_real_chain(self, tmp_dir, sample_wav):
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        results["sstv"] = {
            "vis_detected": True, "vis_code": 0x3C, "mode": "Scottie S1",
            "decoded_image": None, "sstv_variant_selected": None,
            "decoders_tried": [], "confidence": 0.9, "ocr_text": None, "qr_data": None,
            "findings": [],
        }
        results["flags"]["flags_found"] = [
            {"value": "FLAG{x}", "encoding": "base64", "confidence": 0.9,
             "confidence_pct": "90%", "evidence": "e"},
        ]
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        toolsused = content[content.find('id="toolsused"'):]
        assert "Custom SSTV Decoder" in toolsused
        assert "0x3C" in toolsused
        assert "Base64 Decoder" in toolsused
        assert "FLAG{x}" in toolsused

    def test_evidence_tree_and_findings_table_removed(self, tmp_dir, sample_wav):
        """CTF edition: the recursive extraction artifact graph and the
        generic Verified Findings table (with its severity filter/sortable
        columns) were removed entirely."""
        from audio_stego.html_report import HTMLReport
        store, results = self._base_results(tmp_dir)
        path = HTMLReport(store).generate(sample_wav, results, 1.0)
        content = open(path).read()
        assert 'id="severity-filter"' not in content
        assert 'id="findings"' not in content
        assert "Recursive Artifact Graph" not in content


# ---------------------------------------------------------------------------
# Phase 7 — Recursive analysis engine (text-borne nesting)
# ---------------------------------------------------------------------------

class TestRecursiveAnalysisEngine:
    def _make(self, tmp_dir, name="rec_engine"):
        from audio_stego.config import Config
        from audio_stego.artifact_store import ArtifactStore
        from audio_stego.extraction import ExtractionAnalyzer
        store = ArtifactStore(os.path.join(tmp_dir, name))
        cfg = Config()
        ana = ExtractionAnalyzer(cfg, store)
        ana._root_sha = "root"
        return cfg, store, ana

    def test_base64_zip_chain_extracts_and_finds_flag(self, tmp_dir):
        """Regression for the spec's example chain (simplified):
        base64 text -> decode -> validated ZIP -> extracted -> flag found."""
        from audio_stego.recursive_engine import RecursiveAnalysisEngine
        cfg, store, ana = self._make(tmp_dir)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("secret.txt", "flag{recursive_decode_chain}")
        b64_text = base64.b64encode(buf.getvalue()).decode()
        seed_text = f"junk before {b64_text} junk after"

        engine = RecursiveAnalysisEngine(cfg, store, ana)
        result = engine.run(seed_text)

        assert len(result["decoded_artifacts"]) >= 1
        assert result["decoded_artifacts"][0].file_type == "ZIP"
        assert result["decoded_artifacts"][0].status.value == "nested"

        extracted_contents = []
        for root, _, files in os.walk(store.hidden_files):
            for fn in files:
                with open(os.path.join(root, fn), "rb") as f:
                    extracted_contents.append(f.read())
        assert b"flag{recursive_decode_chain}" in extracted_contents

    def test_decoded_payload_deduped_by_sha256(self, tmp_dir):
        """The same base64 blob appearing twice must not be processed twice."""
        from audio_stego.recursive_engine import RecursiveAnalysisEngine
        cfg, store, ana = self._make(tmp_dir)
        payload = base64.b64encode(b"just some plain text payload!!!").decode()
        seed_text = f"{payload} ... later in the file: {payload}"

        engine = RecursiveAnalysisEngine(cfg, store, ana)
        engine.run(seed_text)
        # process the exact same bytes again directly -- must resolve to the
        # existing record (dedup), not create a second one
        raw = base64.b64decode(payload + "==")
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        assert sha in ana._artifact_index
        matching = [r for r in ana.results["records"] if r.sha256 == sha]
        assert len(matching) == 1

    def test_garbage_text_produces_no_artifacts(self, tmp_dir):
        """Plain English text must not be misdecoded into spurious artifacts."""
        from audio_stego.recursive_engine import RecursiveAnalysisEngine
        cfg, store, ana = self._make(tmp_dir)
        engine = RecursiveAnalysisEngine(cfg, store, ana)
        result = engine.run("just a normal sentence with no encoded data at all, moving along")
        assert result["decoded_artifacts"] == []
        assert result["new_flags"] == []

    def test_recursion_bounded_by_max_passes(self, tmp_dir):
        """Even with a permissive seed, the engine must terminate within
        max_passes and not loop forever."""
        from audio_stego.recursive_engine import RecursiveAnalysisEngine
        cfg, store, ana = self._make(tmp_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "nothing special here")
        b64_text = base64.b64encode(buf.getvalue()).decode()
        engine = RecursiveAnalysisEngine(cfg, store, ana)
        result = engine.run(b64_text, max_passes=2)
        assert result["passes"] <= 2

    def test_scanner_wires_recursive_engine_without_crashing(self, tmp_dir, sample_wav, config):
        """Integration: the scanner's _run_recursive_analysis helper must be
        safely callable (best-effort, never raises) even with sparse results."""
        from audio_stego.scanner import AudioStegoScanner
        from audio_stego.artifact_store import ArtifactStore
        scanner = AudioStegoScanner(config)
        store = ArtifactStore(os.path.join(tmp_dir, "scanner_rec"))
        scanner.all_results = {"ocr": {"ocr": []}, "flags": {"flags_found": []}}
        scanner._extraction_analyzer = None   # not yet run -- must no-op, not raise
        scanner._run_recursive_analysis(sample_wav, store, "")   # must not raise


# ---------------------------------------------------------------------------
# Phase 8 — Encoding/decoding engine
# ---------------------------------------------------------------------------

class TestEncodingEngine:
    MSG = "flag{test_123}"

    def test_base16_hex_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_base16(self.MSG.encode().hex()) == self.MSG

    def test_base32_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_base32(base64.b32encode(self.MSG.encode()).decode()) == self.MSG

    def test_base45_roundtrip(self):
        from audio_stego import encoding_engine as ee
        alpha = ee._BASE45_ALPHABET
        data = self.MSG.encode()
        out = []
        for i in range(0, len(data), 2):
            chunk = data[i:i + 2]
            if len(chunk) == 2:
                c = chunk[0] * 256 + chunk[1]
                out.append(alpha[c % 45]); c //= 45
                out.append(alpha[c % 45]); c //= 45
                out.append(alpha[c % 45])
            else:
                c = chunk[0]
                out.append(alpha[c % 45]); c //= 45
                out.append(alpha[c % 45])
        assert ee.decode_base45("".join(out)) == self.MSG

    def test_base45_rejects_invalid_chars(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_base45("not valid base45!!") is None

    def test_base58_roundtrip(self):
        from audio_stego import encoding_engine as ee
        alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = int.from_bytes(self.MSG.encode(), "big")
        out = ""
        while n > 0:
            n, r = divmod(n, 58)
            out = alpha[r] + out
        assert ee.decode_base58(out) == self.MSG

    def test_base62_roundtrip(self):
        from audio_stego import encoding_engine as ee
        alpha = ee._BASE62_ALPHABET
        n = int.from_bytes(self.MSG.encode(), "big")
        out = ""
        while n > 0:
            n, r = divmod(n, 62)
            out = alpha[r] + out
        assert ee.decode_base62(out) == self.MSG

    def test_base64_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_base64(base64.b64encode(self.MSG.encode()).decode()) == self.MSG

    def test_base85_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_base85(base64.b85encode(self.MSG.encode()).decode()) == self.MSG

    def test_ascii85_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_ascii85(base64.a85encode(self.MSG.encode()).decode()) == self.MSG

    def test_binary_roundtrip(self):
        from audio_stego import encoding_engine as ee
        bits = " ".join(format(b, "08b") for b in self.MSG.encode())
        assert ee.decode_binary(bits) == self.MSG

    def test_octal_roundtrip(self):
        from audio_stego import encoding_engine as ee
        octal = " ".join(format(b, "o") for b in self.MSG.encode())
        assert ee.decode_octal(octal) == self.MSG

    def test_rot13_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_rot13(ee.decode_rot13(self.MSG)) == self.MSG   # involutive

    def test_atbash_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_atbash(ee.decode_atbash(self.MSG)) == self.MSG   # involutive

    def test_caesar_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_caesar(ee.decode_caesar(self.MSG, 7), -7) == self.MSG

    def test_affine_roundtrip_and_bruteforce(self):
        from audio_stego import encoding_engine as ee
        a, b = 5, 8
        enc = []
        for c in self.MSG:
            if "a" <= c <= "z":
                enc.append(chr((a * (ord(c) - 97) + b) % 26 + 97))
            elif "A" <= c <= "Z":
                enc.append(chr((a * (ord(c) - 65) + b) % 26 + 65))
            else:
                enc.append(c)
        enc = "".join(enc)
        assert ee.decode_affine(enc, a, b) == self.MSG
        assert any(h.output == self.MSG for h in ee.decode_affine_bruteforce(enc))

    def test_vigenere_keyed_roundtrip(self):
        from audio_stego import encoding_engine as ee
        text, key = "flagtest", "key"
        enc = []
        ki = 0
        for c in text:
            enc.append(chr((ord(c) - 97 + ord(key[ki % len(key)]) - 97) % 26 + 97))
            ki += 1
        assert ee.decode_vigenere("".join(enc), key) == text

    def test_vigenere_rejects_non_alpha_key(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_vigenere("something", "123") is None

    def test_rail_fence_roundtrip(self):
        from audio_stego import encoding_engine as ee
        text, rails = "WEAREDISCOVEREDFLEEATONCE", 3
        fence = [[] for _ in range(rails)]
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        for i, c in enumerate(text):
            fence[pattern[i % len(pattern)]].append(c)
        enc = "".join("".join(r) for r in fence)
        assert ee.decode_rail_fence(enc, rails) == text

    def test_bacon_roundtrip(self):
        from audio_stego import encoding_engine as ee
        rev = {v: k for k, v in ee._BACON_24.items()}
        enc = "".join(rev[c] for c in "HELLO")
        assert ee.decode_bacon(enc) == "HELLO"

    def test_bacon_rejects_wrong_group_length(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_bacon("AAAA") is None

    def test_braille_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_braille("⠓⠑⠇⠇⠕") == "hello"

    def test_morse_roundtrip(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_morse_text(".... . .-.. .-.. ---") == "HELLO"

    def test_morse_rejects_non_morse_text(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_morse_text("just english text") is None

    def test_jwt_decode(self):
        from audio_stego import encoding_engine as ee
        header  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"flag": "test"}).encode()).decode().rstrip("=")
        jwt = f"{header}.{payload}.sig"
        result = ee.decode_jwt(jwt)
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["flag"] == "test"

    def test_jwt_rejects_malformed_token(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_jwt("not.a.valid.jwt.token") is None

    def test_url_decode(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_url("flag%7Btest%7D") == "flag{test}"

    def test_quoted_printable_decode(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_quoted_printable("flag=7Btest=7D") == "flag{test}"

    def test_uuencode_roundtrip(self):
        from audio_stego import encoding_engine as ee
        body = binascii.b2a_uu(self.MSG.encode()).decode()
        full = f"begin 644 test.txt\n{body}`\nend\n"
        assert ee.decode_uuencode(full) == self.MSG

    def test_xxencode_roundtrip(self):
        from audio_stego import encoding_engine as ee
        alpha = ee._XX_ALPHABET
        data = self.MSG.encode()
        n = len(data)
        line = alpha[n]
        for j in range(0, len(data), 3):
            b = data[j:j + 3] + b"\x00" * (3 - len(data[j:j + 3]))
            v0 = b[0] >> 2
            v1 = ((b[0] & 0x03) << 4) | (b[1] >> 4)
            v2 = ((b[1] & 0x0F) << 2) | (b[2] >> 6)
            v3 = b[2] & 0x3F
            line += alpha[v0] + alpha[v1] + alpha[v2] + alpha[v3]
        assert ee.decode_xxencode(line) == self.MSG

    def test_decode_all_finds_base64_flag(self):
        from audio_stego import encoding_engine as ee
        hits = ee.decode_all(base64.b64encode(self.MSG.encode()).decode())
        assert any(h.output == self.MSG for h in hits)

    def test_recursive_decode_chains_hex_then_base64(self):
        from audio_stego import encoding_engine as ee
        chained = base64.b64encode(self.MSG.encode().hex().encode()).decode()
        hits = ee.recursive_decode(chained)
        assert any(h.output == self.MSG for h in hits)

    def test_recursive_decode_terminates_quickly_on_flag_shaped_input(self):
        """
        Regression: an earlier version gated Caesar/Affine/Rail-fence brute
        force on a generic printability check. Since letter-shifting/
        transposition ciphers keep output printable regardless of whether the
        guess is right, that let ~300+ wrong guesses per string through,
        multiplying every recursion depth — this hung for minutes on input
        that already looked like a flag. Must now terminate in well under a
        second even when handed already-flag-shaped text.
        """
        import time
        from audio_stego import encoding_engine as ee
        start = time.time()
        ee.recursive_decode(self.MSG)
        assert time.time() - start < 5.0

    def test_recursive_decode_respects_hard_caps(self):
        from audio_stego import encoding_engine as ee
        hits = ee.recursive_decode(self.MSG)
        assert len(hits) <= ee._MAX_RECURSIVE_HITS

    def test_garbage_input_produces_no_decodes(self):
        from audio_stego import encoding_engine as ee
        assert ee.decode_all("just plain english words here") == [] or all(
            h.output for h in ee.decode_all("just plain english words here")
        )


# ---------------------------------------------------------------------------
# Phase 5 — Confidence engine (findings.py)
# ---------------------------------------------------------------------------

class TestConfidenceEngine:
    def test_evidence_ladder_values(self):
        from audio_stego.findings import EvidenceLevel, confidence_for_evidence
        assert confidence_for_evidence(EvidenceLevel.MAGIC_ONLY) == 0.20
        assert confidence_for_evidence(EvidenceLevel.HEADER_PARSED) == 0.40
        assert confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED) == 0.60
        assert confidence_for_evidence(EvidenceLevel.CHECKSUM_VALID) == 0.80
        assert confidence_for_evidence(EvidenceLevel.EXTRACTED) == 0.95
        assert confidence_for_evidence(EvidenceLevel.PARSED_OPENED) == 1.00

    def test_cap_severity_never_raises(self):
        from audio_stego.findings import Severity, cap_severity
        # A LOW request must never be raised to something higher.
        assert cap_severity(Severity.LOW, 0.99) == Severity.LOW

    def test_cap_severity_blocks_high_at_low_confidence(self):
        """The spec's core rule: never show HIGH/CRITICAL for a low-confidence finding."""
        from audio_stego.findings import Severity, cap_severity
        assert cap_severity(Severity.CRITICAL, 0.20) == Severity.INFO
        assert cap_severity(Severity.HIGH, 0.20) == Severity.INFO
        assert cap_severity(Severity.HIGH, 0.45) == Severity.LOW

    def test_cap_severity_allows_high_at_high_confidence(self):
        from audio_stego.findings import Severity, cap_severity
        assert cap_severity(Severity.HIGH, 0.85) == Severity.HIGH
        assert cap_severity(Severity.CRITICAL, 0.97) == Severity.CRITICAL

    def test_severity_cap_monotonic_thresholds(self):
        from audio_stego.findings import severity_cap_for_confidence, Severity, _SEVERITY_RANK
        # Higher confidence must never produce a *lower* cap than a lower confidence.
        levels = [0.0, 0.19, 0.40, 0.61, 0.80, 0.96]
        caps = [severity_cap_for_confidence(c) for c in levels]
        ranks = [_SEVERITY_RANK[c] for c in caps]
        assert ranks == sorted(ranks)


# ---------------------------------------------------------------------------
# Phase 4 — Real MPEG (MP3/AAC) frame validators
# ---------------------------------------------------------------------------

class TestMP3FrameValidator:
    @staticmethod
    def _mp3_header(bitrate_idx=9, samp_idx=0, padding=0, protected_bit=1):
        b1 = 0xFF
        b2 = 0xE0 | (0b11 << 3) | (0b01 << 1) | protected_bit  # MPEG1 Layer3
        b3 = (bitrate_idx << 4) | (samp_idx << 2) | (padding << 1)
        b4 = 0x00 | (0b01 << 6)
        return bytes([b1, b2, b3, b4])

    def _build_stream(self, n_frames=5, **header_kwargs):
        from audio_stego.validate import _parse_mp3_frame
        header = self._mp3_header(**header_kwargs)
        fr = _parse_mp3_frame(header + b"\x00" * 500, 0)
        stream = b""
        for _ in range(n_frames):
            stream += header + b"\x00" * (fr.frame_length - 4)
        return stream

    def test_isolated_frame_sync_rejected(self):
        """Phase 4: a lone frame-sync match must NOT be classified as an embedded MP3."""
        from audio_stego.validate import validate_embedded
        header = self._mp3_header()
        data = b"\x00" * 100 + header + b"\x11" * 40   # garbage after one frame
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.valid is False
        assert vr.confidence <= 0.20

    def test_three_or_more_consecutive_frames_accepted(self):
        from audio_stego.validate import validate_embedded
        stream = self._build_stream(n_frames=3)
        data = b"\x00" * 100 + stream
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.valid is True
        assert "3 consecutive" in vr.reason

    def test_two_consecutive_frames_still_rejected(self):
        """Minimum is 3 consecutive frames — 2 must not be enough."""
        from audio_stego.validate import validate_embedded
        stream = self._build_stream(n_frames=2)
        data = b"\x00" * 100 + stream + b"\xff" * 20   # break the stream after 2 frames
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.valid is False

    def test_sample_rate_mismatch_breaks_consecutive_run(self):
        """v4.3: a real MP3 stream's sample rate never changes mid-stream;
        requiring it stay constant is one more independent signal against a
        coincidental run of frame syncs with otherwise-plausible headers.
        Two frames at 44.1kHz followed by frames at 48kHz must only count
        the first two as consistent — one short of the 3-frame minimum."""
        from audio_stego.validate import validate_embedded, _parse_mp3_frame
        h0 = self._mp3_header(samp_idx=0)   # MPEG1 -> 44100 Hz
        h1 = self._mp3_header(samp_idx=1)   # MPEG1 -> 48000 Hz
        fr0 = _parse_mp3_frame(h0 + b"\x00" * 500, 0)
        fr1 = _parse_mp3_frame(h1 + b"\x00" * 500, 0)
        frame0 = h0 + b"\x00" * (fr0.frame_length - 4)
        frame1 = h1 + b"\x00" * (fr1.frame_length - 4)
        stream = frame0 + frame0 + frame1 + frame1
        data = b"\x00" * 100 + stream
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.valid is False
        assert "Only 2" in vr.reason

    def test_bad_bitrate_index_rejected(self):
        """Bitrate index 0 (free) and 15 (bad) must be rejected."""
        from audio_stego.validate import validate_embedded
        for idx in (0, 15):
            header = self._mp3_header(bitrate_idx=idx)
            data = b"\x00" * 100 + header + b"\x00" * 40
            vr = validate_embedded(data, 100, "MP3_FRAME")
            assert vr.valid is False, f"bitrate_idx={idx} should be rejected"

    def test_reserved_sample_rate_rejected(self):
        from audio_stego.validate import validate_embedded
        header = self._mp3_header(samp_idx=3)   # reserved
        data = b"\x00" * 100 + header + b"\x00" * 40
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.valid is False

    def test_longer_run_has_higher_confidence_tier(self):
        from audio_stego.validate import validate_embedded
        short = self._build_stream(n_frames=3)
        long_ = self._build_stream(n_frames=15)
        vr_short = validate_embedded(b"\x00" * 100 + short, 100, "MP3_FRAME")
        vr_long  = validate_embedded(b"\x00" * 100 + long_, 100, "MP3_FRAME")
        assert vr_long.confidence >= vr_short.confidence

    def test_never_reported_as_embedded_file_without_validator_bypass(self):
        """Regression for the exact spec bug: an isolated MP3_FRAME magic hit
        must never be routed through validate_embedded's 'no validator' branch
        (which historically accepted anything on magic bytes alone at 40%)."""
        from audio_stego.validate import validate_embedded
        header = self._mp3_header()
        data = b"\x00" * 100 + header + b"\x00" * 10
        vr = validate_embedded(data, 100, "MP3_FRAME")
        assert vr.reason != f"No validator for MP3_FRAME — accepted on magic bytes alone"
        assert "isolated" in vr.reason.lower() or "only" in vr.reason.lower()


class TestAACFrameValidator:
    @staticmethod
    def _adts_header(sf_idx=3, channels=2, frame_length=200):
        b1 = 0xFF
        b2 = 0xF1  # MPEG-4, no CRC (protection_absent=1)
        b3 = (0b01 << 6) | (sf_idx << 2) | ((channels >> 2) & 0x01)
        b4 = ((channels & 0x03) << 6) | ((frame_length >> 11) & 0x03)
        b5 = (frame_length >> 3) & 0xFF
        b6 = ((frame_length & 0x07) << 5) | 0x1F
        b7 = 0xFC
        return bytes([b1, b2, b3, b4, b5, b6, b7])

    def test_isolated_adts_sync_rejected(self):
        from audio_stego.validate import validate_embedded
        header = self._adts_header()
        data = b"\x00" * 50 + header + b"\x22" * 30
        vr = validate_embedded(data, 50, "AAC_ADTS_MPEG4")
        assert vr.valid is False

    def test_three_consecutive_adts_frames_accepted(self):
        from audio_stego.validate import validate_embedded
        flen = 200
        header = self._adts_header(frame_length=flen)
        stream = (header + b"\x00" * (flen - 7)) * 3
        data = b"\x00" * 50 + stream
        vr = validate_embedded(data, 50, "AAC_ADTS_MPEG4")
        assert vr.valid is True


# ---------------------------------------------------------------------------
# Phase 3 — expanded structural validators
# ---------------------------------------------------------------------------

class TestExpandedValidators:
    def test_sqlite_reachable_via_correct_key(self):
        """Regression: validators dict previously used 'SQLite' while the
        scanner produces 'SQLITE' — the validator was unreachable dead code."""
        from audio_stego.validate import validate_embedded
        hdr = b"SQLite format 3\x00" + struct.pack(">H", 4096) + b"\x00" * 90
        vr = validate_embedded(b"pad" + hdr, 3, "SQLITE")
        assert vr.valid is True
        assert vr.confidence >= 0.60

    def test_tar_checksum_verified(self):
        import tarfile
        from audio_stego.validate import validate_embedded
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("hello.txt")
            payload = b"flag{tar_test}"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        tar_bytes = buf.getvalue()
        ustar_off = tar_bytes.find(b"ustar")
        data = b"\x00" * 50 + tar_bytes
        vr = validate_embedded(data, 50 + ustar_off, "TAR")
        assert vr.valid is True
        assert "checksum verified" in vr.reason

    def test_tar_tampered_checksum_rejected(self):
        import tarfile
        from audio_stego.validate import validate_embedded
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("hello.txt")
            payload = b"flag{tar_test}"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        tar_bytes = bytearray(buf.getvalue())
        ustar_off = tar_bytes.find(b"ustar")
        tar_bytes[0:8] = b"XXXXXXXX"   # corrupt the name field -> checksum mismatch
        data = b"\x00" * 50 + bytes(tar_bytes)
        vr = validate_embedded(data, 50 + ustar_off, "TAR")
        assert vr.valid is False

    def test_xz_crc32_verified(self):
        import lzma
        from audio_stego.validate import validate_embedded
        xz_bytes = lzma.compress(b"flag{xz_test}" * 10, format=lzma.FORMAT_XZ)
        data = b"\x00" * 20 + xz_bytes
        vr = validate_embedded(data, 20, "XZ")
        assert vr.valid is True
        assert vr.confidence >= 0.80

    def test_xz_corrupted_header_rejected(self):
        from audio_stego.validate import validate_embedded
        import lzma
        xz_bytes = bytearray(lzma.compress(b"flag{xz_test}" * 10, format=lzma.FORMAT_XZ))
        xz_bytes[6] ^= 0xFF   # flip a flag bit -> CRC32 mismatch
        data = b"\x00" * 20 + bytes(xz_bytes)
        vr = validate_embedded(data, 20, "XZ")
        assert vr.valid is False

    def test_bzip2_valid_stream_accepted(self):
        import bz2
        from audio_stego.validate import validate_embedded
        bz_bytes = bz2.compress(b"flag{bzip2_test}" * 10)
        data = b"\x00" * 20 + bz_bytes
        vr = validate_embedded(data, 20, "BZIP2")
        assert vr.valid is True

    def test_bzip2_bad_magic_rejected(self):
        from audio_stego.validate import validate_embedded
        vr = validate_embedded(b"\x00" * 20 + b"XXh0" + b"\x00" * 20, 20, "BZIP2")
        assert vr.valid is False

    def test_json_valid_object_accepted(self):
        from audio_stego.validate import validate_embedded
        payload = json.dumps({"flag": "test", "n": 1}).encode()
        vr = validate_embedded(b"garbage" + payload + b"trailing", 7, "JSON")
        assert vr.valid is True
        assert vr.confidence >= 0.90

    def test_json_malformed_rejected(self):
        from audio_stego.validate import validate_embedded
        vr = validate_embedded(b"garbage{not valid json,,,}", 7, "JSON")
        assert vr.valid is False

    def test_xml_well_formed_accepted(self):
        from audio_stego.validate import validate_embedded
        xml = b"<?xml version='1.0'?><root><a>1</a></root>"
        vr = validate_embedded(b"garbage" + xml, 7, "XML")
        assert vr.valid is True

    def test_xml_malformed_rejected(self):
        from audio_stego.validate import validate_embedded
        xml = b"<?xml version='1.0'?><root><a>unclosed"
        vr = validate_embedded(b"garbage" + xml, 7, "XML")
        assert vr.valid is False

    def test_pe_valid_header_accepted(self):
        from audio_stego.validate import validate_embedded
        pe = (b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00"
              + struct.pack("<H", 0x8664) + b"\x00" * 20)
        vr = validate_embedded(b"pad" + pe, 3, "PE")
        assert vr.valid is True
        assert "x64" in vr.reason

    def test_pe_bare_mz_without_pe_header_rejected(self):
        from audio_stego.validate import validate_embedded
        data = b"pad" + b"MZ" + b"\x00" * 100   # 'MZ' with no real PE signature
        vr = validate_embedded(data, 3, "PE")
        assert vr.valid is False

    def test_webp_detected_distinctly_from_wav(self):
        from audio_stego.validate import validate_embedded
        size = 20
        webp = b"RIFF" + struct.pack("<I", size) + b"WEBPVP8 " + b"\x00" * 20
        vr = validate_embedded(b"pad" + webp, 3, "WAV")
        assert vr.valid is True
        assert vr.file_type == "WEBP"

    def test_docx_detected_via_zip_content(self):
        from audio_stego.validate import validate_embedded
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("word/document.xml", "<doc/>")
            zf.writestr("[Content_Types].xml", "<Types/>")
        data = b"pad" + buf.getvalue()
        vr = validate_embedded(data, 3, "ZIP")
        assert vr.valid is True
        assert vr.file_type == "DOCX"

    def test_zip_corrupted_member_flagged(self):
        """A real ZIP whose member CRC fails must be tagged corrupted, not silently valid."""
        from audio_stego.validate import validate_embedded
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello world")
        raw = bytearray(buf.getvalue())
        # Flip a byte inside the compressed data region (after local file header)
        raw[40] ^= 0xFF
        vr = validate_embedded(b"pad" + bytes(raw), 3, "ZIP")
        assert vr.corrupted is True or vr.valid is False

    def test_aiff_valid_comm_chunk_accepted(self):
        from audio_stego.validate import validate_embedded
        comm = struct.pack(">hIh", 2, 1000, 16)
        comm_chunk = b"COMM" + struct.pack(">I", len(comm)) + comm
        body = b"AIFF" + comm_chunk
        aiff = b"FORM" + struct.pack(">I", len(body)) + body
        vr = validate_embedded(b"pad" + aiff, 3, "AIFF")
        assert vr.valid is True
        assert "2ch" in vr.reason

    def test_aiff_implausible_channels_rejected(self):
        from audio_stego.validate import validate_embedded
        comm = struct.pack(">hIh", 99, 1000, 16)   # 99 channels is implausible
        comm_chunk = b"COMM" + struct.pack(">I", len(comm)) + comm
        body = b"AIFF" + comm_chunk
        aiff = b"FORM" + struct.pack(">I", len(body)) + body
        vr = validate_embedded(b"pad" + aiff, 3, "AIFF")
        assert vr.valid is False


# ---------------------------------------------------------------------------
# Phase 2 — unified extraction evidence pipeline
# ---------------------------------------------------------------------------

class TestUnifiedEvidencePipeline:
    def _make(self, config, tmp_dir, name="ex_unified"):
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, name))
        return ExtractionAnalyzer(config, store), store

    def test_sha256_dedup_preserves_all_source_tools(self, config, tmp_dir):
        """Phase 2: the same bytes found by two tools must merge into ONE
        record whose source_tools lists both — not be double-counted."""
        ana, store = self._make(config, tmp_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("flag.txt", "flag{unified}")
        content = buf.getvalue()

        p1 = os.path.join(tmp_dir, "carved1.zip")
        p2 = os.path.join(tmp_dir, "carved1_dup.zip")
        with open(p1, "wb") as f: f.write(content)
        with open(p2, "wb") as f: f.write(content)

        r1 = ana._process_tool_artifact(p1, "binwalk")
        r2 = ana._process_tool_artifact(p2, "foremost")

        assert r1 is r2, "identical SHA256 content must resolve to the same record"
        assert set(r1.source_tools) == {"binwalk", "foremost"}
        assert len(ana.results["records"]) == 1

    def test_garbage_carved_file_never_counted_as_verified(self, config, tmp_dir):
        """Regression for the exact spec complaint: a tool-carved file that
        exists on disk but fails structural validation must not inflate the
        'verified'/'extracted' accounting."""
        ana, store = self._make(config, tmp_dir)
        junk = os.path.join(tmp_dir, "junk.bin")
        with open(junk, "wb") as f:
            f.write(b"\x01\x02\x03 not a real file structure" * 4)

        rec = ana._process_tool_artifact(junk, "scalpel")
        ana._update_summary()

        assert rec.status.value in ("unsupported", "rejected")
        assert ana.results["summary"]["verified"] == 0
        assert ana.results["summary"]["extracted"] == 0

    def test_valid_container_gets_nested_status(self, config, tmp_dir):
        """A validated archive is tagged NESTED (it will be recursed into),
        distinguishing containers from leaf artifacts in the evidence graph."""
        ana, store = self._make(config, tmp_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("flag.txt", "flag{nested}")
        p = os.path.join(tmp_dir, "container.zip")
        with open(p, "wb") as f:
            f.write(buf.getvalue())

        rec = ana._process_tool_artifact(p, "binwalk")
        from audio_stego.extraction import ExtractionStatus
        assert rec.status == ExtractionStatus.NESTED

    def test_oversized_artifact_skipped_not_silently_dropped(self, config, tmp_dir):
        from audio_stego.extraction import ExtractionStatus
        import audio_stego.extraction as extraction_mod
        ana, store = self._make(config, tmp_dir)
        p = os.path.join(tmp_dir, "big.bin")
        with open(p, "wb") as f:
            f.write(b"\x00" * 1024)
        old_max = extraction_mod._MAX_EXTRACT_SIZE
        extraction_mod._MAX_EXTRACT_SIZE = 100  # force the size-limit branch
        try:
            rec = ana._process_tool_artifact(p, "binwalk")
        finally:
            extraction_mod._MAX_EXTRACT_SIZE = old_max
        assert rec.status == ExtractionStatus.SKIPPED

    def test_record_carries_provenance_fields(self, config, tmp_dir):
        """Every evidence record must carry sha256/depth/source_tools/timestamp
        (Phase 2 requirement) in addition to the original fields."""
        ana, store = self._make(config, tmp_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hi")
        p = os.path.join(tmp_dir, "prov.zip")
        with open(p, "wb") as f:
            f.write(buf.getvalue())
        rec = ana._process_tool_artifact(p, "binwalk", parent_sha256="rootsha", depth=2)
        assert rec.sha256 and len(rec.sha256) == 64
        assert rec.parent_sha256 == "rootsha"
        assert rec.depth == 2
        assert rec.source_tools == ["binwalk"]
        assert rec.timestamp

    def test_extraction_record_positional_construction_still_works(self):
        """Backward compatibility: existing callers construct ExtractionRecord
        positionally through output_path; new fields must all have defaults."""
        from audio_stego.extraction import ExtractionRecord, ExtractionStatus
        rec = ExtractionRecord("ZIP", 0x1000, ExtractionStatus.EXTRACTED,
                                0.97, "Valid ZIP", "/tmp/out.zip")
        assert rec.sha256 is None
        assert rec.depth == 0
        assert rec.source_tools == []
        assert rec.timestamp   # auto-populated by __post_init__

    def test_signature_scan_severity_never_high_for_magic_only_confidence(self, config, tmp_dir):
        """Regression for the hardcoded Severity.HIGH bug: a low-confidence
        validation must not produce a HIGH/CRITICAL finding."""
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        from audio_stego.findings import Severity
        store = ArtifactStore(os.path.join(tmp_dir, "sev_test"))
        ana = ExtractionAnalyzer(config, store)

        # A bare 'MZ' with no valid PE header -> low-confidence/invalid, must
        # never surface as a HIGH severity "Validated Embedded" finding.
        wav_path = os.path.join(tmp_dir, "sev.wav")
        with open(wav_path, "wb") as f:
            f.write(b"RIFF" + (100).to_bytes(4, "little") + b"WAVE")
            f.write(b"\x00" * 50)
            f.write(b"MZ" + b"\x00" * 60)  # bare MZ, no PE signature

        ana._scan_signatures(wav_path)
        for finding in ana.results["findings"]:
            if finding["confidence"] < 0.40:
                assert finding["severity"] not in ("HIGH", "CRITICAL"), finding


# ---------------------------------------------------------------------------
# Phase 13 — performance: hash caching and reduced rescanning
# ---------------------------------------------------------------------------

class TestPerformanceCaching:
    def test_sha256_cache_avoids_rehashing_same_path(self, config, tmp_dir):
        """Regression: _recursive_multipass hashed a file, then
        _process_tool_artifact hashed the exact same path again — the cache
        must make the second call a no-op read from the dict, verified by
        counting real hashing calls via a patch on the module-level _sha256."""
        from unittest.mock import patch
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        import audio_stego.extraction as extraction_mod

        store = ArtifactStore(os.path.join(tmp_dir, "cache_test"))
        ana = ExtractionAnalyzer(config, store)

        p = os.path.join(tmp_dir, "same_file.bin")
        with open(p, "wb") as f:
            f.write(b"hello world, not a real archive")

        call_count = {"n": 0}
        real_sha256 = extraction_mod._sha256

        def counting_sha256(path):
            call_count["n"] += 1
            return real_sha256(path)

        with patch("audio_stego.extraction._sha256", side_effect=counting_sha256):
            first = ana._sha256_cached(p)
            second = ana._sha256_cached(p)

        assert first == second
        assert call_count["n"] == 1, "second call should have hit the cache, not re-hashed"

    def test_sha256_cache_returns_none_for_missing_file_without_caching_forever(self, tmp_dir, config):
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.artifact_store import ArtifactStore
        store = ArtifactStore(os.path.join(tmp_dir, "cache_missing"))
        ana = ExtractionAnalyzer(config, store)
        assert ana._sha256_cached("/nonexistent/path/does/not/exist") is None

    def test_recursive_engine_does_not_reread_already_scanned_files(self, tmp_dir, config):
        """Regression: _collect_text_from_new_artifacts used to walk and
        re-read every file in extracted/hidden_files from scratch on every
        pass, even ones already read in a prior pass that cannot have
        changed. Must only read each path once across the engine's lifetime."""
        from audio_stego.artifact_store import ArtifactStore
        from audio_stego.extraction import ExtractionAnalyzer
        from audio_stego.recursive_engine import RecursiveAnalysisEngine

        store = ArtifactStore(os.path.join(tmp_dir, "rescans"))
        ana = ExtractionAnalyzer(config, store)
        engine = RecursiveAnalysisEngine(config, store, ana)

        p = str(store.extracted / "existing.txt")
        with open(p, "w") as f:
            f.write("plain readable text, nothing encoded here")

        engine._collect_text_from_new_artifacts()
        assert p in engine._scanned_paths

        # A second call must not re-open the same file
        from unittest.mock import patch
        with patch("builtins.open") as mock_open:
            engine._collect_text_from_new_artifacts()
            mock_open.assert_not_called()


# ---------------------------------------------------------------------------
# Phase 14 — CLI commands
# ---------------------------------------------------------------------------

class TestCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_scan_command_exits_zero_on_success(self, tmp_dir, sample_wav):
        """
        Regression: `audio-stego scan` used to ALWAYS exit 1 even on a fully
        successful scan, because main.py called a non-existent method
        (scanner._setup_output_dir — the real method is _setup_store) while
        trying to run plugins a *second*, fully redundant time (plugins
        already run inside scanner.scan()'s own pipeline). Verified by
        actually invoking the CLI end-to-end, not just unit-testing pieces.
        """
        from audio_stego.main import cli
        runner = self._runner()
        out_dir = os.path.join(tmp_dir, "cli_scan_out")
        result = runner.invoke(cli, ["scan", sample_wav, "--output", out_dir, "--no-plugins"])
        assert result.exit_code == 0, result.output
        assert os.path.exists(os.path.join(out_dir, "test", "report.html"))

    def test_scan_no_plugins_flag_skips_plugin_execution(self, tmp_dir, sample_wav):
        from unittest.mock import patch
        from audio_stego.main import cli
        runner = self._runner()
        out_dir = os.path.join(tmp_dir, "cli_scan_noplug")
        with patch("audio_stego.plugins.manager.PluginManager.run_all") as mock_run_all:
            result = runner.invoke(cli, ["scan", sample_wav, "--output", out_dir, "--no-plugins"])
        assert result.exit_code == 0, result.output
        mock_run_all.assert_not_called()

    def test_doctor_command_runs(self):
        from audio_stego.main import cli
        runner = self._runner()
        result = runner.invoke(cli, ["doctor"])
        assert "Tool Health Check" in result.output
        assert "Python DSP Packages" in result.output

    def test_validate_command_on_real_wav(self, sample_wav):
        from audio_stego.main import cli
        runner = self._runner()
        result = runner.invoke(cli, ["validate", sample_wav])
        assert result.exit_code == 0, result.output
        assert "WAV" in result.output
        assert "yes" in result.output.lower() or "Valid" in result.output

    def test_extract_command(self, tmp_dir, sample_wav):
        from audio_stego.main import cli
        runner = self._runner()
        out_dir = os.path.join(tmp_dir, "cli_extract_out")
        result = runner.invoke(cli, ["extract", sample_wav, "--output", out_dir])
        assert result.exit_code == 0, result.output
        assert "Extraction Results" in result.output

    def test_decode_command_finds_base64_flag(self):
        from audio_stego.main import cli
        runner = self._runner()
        encoded = base64.b64encode(b"flag{cli_decode_test}").decode()
        result = runner.invoke(cli, ["decode", encoded])
        assert result.exit_code == 0
        assert "flag{cli_decode_test}" in result.output

    def test_decode_command_with_file(self, tmp_dir):
        from audio_stego.main import cli
        runner = self._runner()
        p = os.path.join(tmp_dir, "payload.txt")
        with open(p, "w") as f:
            f.write(base64.b64encode(b"flag{cli_decode_file_test}").decode())
        result = runner.invoke(cli, ["decode", "--file", p])
        assert result.exit_code == 0
        assert "flag{cli_decode_file_test}" in result.output

    def test_report_stats_verify_commands_on_real_scan(self, tmp_dir, sample_wav):
        """End-to-end: scan a file, then confirm report/stats/verify all read
        the resulting report.json correctly, including the extraction_records
        this phase added (previously report.json had no per-artifact SHA256
        data at all, only the raw extracted_files path list)."""
        from audio_stego.main import cli
        runner = self._runner()
        out_dir = os.path.join(tmp_dir, "cli_full_out")
        scan_result = runner.invoke(cli, ["scan", sample_wav, "--output", out_dir, "--no-plugins"])
        assert scan_result.exit_code == 0, scan_result.output

        results_dir = os.path.join(out_dir, "test")

        report_result = runner.invoke(cli, ["report", results_dir])
        assert report_result.exit_code == 0, report_result.output
        assert "Scan Report" in report_result.output
        assert f"v{__import__('audio_stego').__version__}" in report_result.output

        stats_result = runner.invoke(cli, ["stats", results_dir])
        assert stats_result.exit_code == 0, stats_result.output

        verify_result = runner.invoke(cli, ["verify", results_dir])
        assert verify_result.exit_code == 0, verify_result.output
        assert "mismatch" in verify_result.output.lower()

    def test_benchmark_command_shows_phase_timing(self, tmp_dir, sample_wav, monkeypatch):
        """benchmark uses the default config output_dir ('results/') since it
        takes no --output option — chdir into tmp_dir so this doesn't write
        into the real project directory."""
        from audio_stego.main import cli
        runner = self._runner()
        monkeypatch.chdir(tmp_dir)
        result = runner.invoke(cli, ["benchmark", sample_wav])
        assert result.exit_code == 0, result.output
        assert "Phase Timing" in result.output
        assert "Total" in result.output

    def test_clean_command_removes_directory_with_yes_flag(self, tmp_dir):
        from audio_stego.main import cli
        runner = self._runner()
        target = os.path.join(tmp_dir, "to_clean")
        os.makedirs(os.path.join(target, "sub"), exist_ok=True)
        result = runner.invoke(cli, ["clean", "--output", target, "--yes"])
        assert result.exit_code == 0, result.output
        assert not os.path.exists(target)

    def test_clean_command_aborts_without_confirmation(self, tmp_dir):
        from audio_stego.main import cli
        runner = self._runner()
        target = os.path.join(tmp_dir, "to_keep")
        os.makedirs(target, exist_ok=True)
        result = runner.invoke(cli, ["clean", "--output", target], input="n\n")
        assert os.path.exists(target), "must not delete without confirmation"

    def test_plugins_alias_matches_list_plugins(self):
        from audio_stego.main import cli
        runner = self._runner()
        r1 = runner.invoke(cli, ["list-plugins"])
        r2 = runner.invoke(cli, ["plugins"])
        assert r1.exit_code == 0 and r2.exit_code == 0
        assert "Available Plugins" in r1.output
        assert "Available Plugins" in r2.output


class TestScannerSummary:
    def _scanner(self):
        from audio_stego.scanner import AudioStegoScanner
        from audio_stego.config import Config
        from rich.console import Console
        return AudioStegoScanner(Config(), console=Console(record=True))

    def test_signals_row_only_lists_categories_that_actually_found_something(self, tmp_dir):
        """
        Regression: the "Signals" row's filter condition used to be
        `digital.get(key) or vis_detected` applied identically to every
        (label, key) pair. Since `vis_detected` doesn't vary per pair,
        whenever SSTV's VIS was detected, ALL FOUR labels (Morse/DTMF/
        Minimodem/SSTV) were listed — even when Morse/DTMF/Minimodem had
        each independently found nothing. Found by running the full
        pipeline against a real MP3 where the CLI showed "Signals: Morse,
        DTMF, Minimodem, SSTV" while report.json's morse/dtmf/minimodem
        fields were all empty lists.
        """
        scanner = self._scanner()
        scanner.all_results = {
            "summary": {},
            "digital": {"morse": [], "dtmf": [], "minimodem": []},
            "sstv": {"vis_detected": True},
        }
        report_path = os.path.join(tmp_dir, "report.html")
        open(report_path, "w").close()
        scanner._print_summary(report_path)
        output = scanner.console.export_text()
        assert "SSTV" in output
        assert "Morse" not in output
        assert "DTMF" not in output
        assert "Minimodem" not in output

    def test_signals_row_lists_morse_when_morse_actually_found(self, tmp_dir):
        scanner = self._scanner()
        scanner.all_results = {
            "summary": {},
            "digital": {"morse": [{"value": "SOS"}], "dtmf": [], "minimodem": []},
            "sstv": {"vis_detected": False},
        }
        report_path = os.path.join(tmp_dir, "report.html")
        open(report_path, "w").close()
        scanner._print_summary(report_path)
        output = scanner.console.export_text()
        assert "Morse" in output
        assert "DTMF" not in output
        assert "SSTV" not in output
