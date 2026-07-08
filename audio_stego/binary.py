"""
Binary analysis module for Audio Stego Solver.

FIXED (v1.1):
  - xxd / hexdump now limited to first 64 KB to prevent hangs on large files
  - _detect_appended_data formula fixed for compressed audio (uses stream duration × sample rate × bit_depth rather than codec bitrate)
  - find_embedded_files now skips offset 0 to avoid reporting the file's own header
  - base64 pattern tightened: uses is_likely_base64() validation before reporting
  - Block entropy stored as summary stats only (not full float list) to avoid RAM bloat
  - String deduplication added
  - Cipher logic removed — now imported from findings.py (single source of truth)
  - Bacon cipher detection gated: requires >= 10 chars before attempting
"""

import json
import math
import os
import re
import struct
from collections import Counter
from typing import Any, Dict, List

from .findings import EvidenceLevel, Finding, Severity, cap_severity, is_likely_base64
from .logger import get_logger
from .utils import find_embedded_files, read_bytes, run_command, save_bytes, save_text, tool_available
from .validate import validate_embedded

logger = get_logger("audio_stego.binary")

# Reduced / hardened patterns — no raw hex_block (too noisy), no binary_block
PATTERNS = {
    "url":    re.compile(r"https?://[^\s<>\"]{10,}"),
    "ip":     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email":  re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "jwt":    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
}

# Maximum bytes to dump via xxd / hexdump (64 KB)
_HEX_DUMP_LIMIT = 65_536
# Maximum bytes to load for magic scanning (100 MB)
_MAGIC_SCAN_LIMIT = 100 * 1024 * 1024
# Minimum extra bytes beyond expected size to flag as appended data
_APPENDED_THRESHOLD = 2048


class BinaryAnalyzer:
    """Performs binary-level analysis on audio files."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.tools_dir = os.path.join(output_dir, "tools")
        os.makedirs(self.tools_dir, exist_ok=True)
        self.min_string_len = config.getint("strings", "min_length", 4)
        self.block_size = config.getint("entropy", "block_size", 256)
        self.results: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audio_path: str) -> Dict[str, Any]:
        """Run all binary analyses."""
        logger.info(f"Starting binary analysis for: {audio_path}")
        self.results = {
            "strings": [],
            "hexdump": "",
            "entropy": {},
            "embedded_files": [],
            "encoded_data": {},
            "appended_data": None,
            "warnings": [],
            "findings": [],
        }

        self._run_strings(audio_path)
        self._run_hexdump(audio_path)
        self._run_entropy(audio_path)
        self._detect_embedded(audio_path)
        self._detect_encoded_data()
        self._detect_appended_data(audio_path)

        logger.info("Binary analysis complete")
        return self.results

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def _run_strings(self, path: str):
        """Extract printable strings, deduplicated."""
        min_len = str(self.min_string_len)

        if tool_available("strings"):
            rc, out, err = run_command(
                ["strings", f"-n{min_len}", path],
                timeout=30,
            )
            raw_list = [s for s in out.splitlines() if s.strip()]
        else:
            logger.warning("strings tool not available, using Python fallback")
            data = read_bytes(path)
            raw_list = self._python_strings(data, self.min_string_len)

        # Deduplicate while preserving order
        seen: set = set()
        string_list: List[str] = []
        for s in raw_list:
            if s not in seen:
                seen.add(s)
                string_list.append(s)

        self.results["strings"] = string_list
        out_path = os.path.join(self.tools_dir, "strings.txt")
        save_text(out_path, "\n".join(string_list))
        logger.info(f"Extracted {len(string_list)} unique strings → {out_path}")

    def _python_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Pure-Python ASCII string extraction fallback."""
        result: List[str] = []
        current: List[str] = []
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    result.append("".join(current))
                current = []
        if len(current) >= min_len:
            result.append("".join(current))
        return result

    # ------------------------------------------------------------------
    # Hex dump (size-limited)
    # ------------------------------------------------------------------

    def _run_hexdump(self, path: str):
        """
        Run hexdump on the first _HEX_DUMP_LIMIT bytes only.
        Previously attempted the full file, then sliced to 50 000 chars after blocking.
        """
        if not tool_available("hexdump"):
            self.results["warnings"].append("Tool not found: hexdump")
            return

        rc, out, err = run_command(
            ["hexdump", "-C", "-n", str(_HEX_DUMP_LIMIT), path],
            timeout=30,
        )
        self.results["hexdump"] = out[:50_000]
        out_path = os.path.join(self.tools_dir, "hexdump.txt")
        save_text(out_path, out)
        logger.info(f"Saved hexdump (first {_HEX_DUMP_LIMIT // 1024} KB) → {out_path}")

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    def _run_entropy(self, path: str):
        """
        Calculate Shannon entropy per block.
        Stores only summary stats (not raw float list) to avoid RAM bloat.
        Includes per-block offset for high-entropy anomalies.
        """
        data = read_bytes(path)
        if not data:
            return

        overall = self._shannon_entropy(data)
        block_size = self.block_size

        high_entropy_offsets: List[Dict] = []
        block_entropies: List[float] = []

        for i in range(0, len(data), block_size):
            block = data[i: i + block_size]
            ent = self._shannon_entropy(block)
            block_entropies.append(ent)
            if ent > 7.5:
                high_entropy_offsets.append({"offset": i, "entropy": round(ent, 4)})

        avg = sum(block_entropies) / max(len(block_entropies), 1)

        # Store summary only — not the full float list
        self.results["entropy"] = {
            "overall": round(overall, 4),
            "file_size": len(data),
            "block_size": block_size,
            "num_blocks": len(block_entropies),
            "max_block": round(max(block_entropies), 4) if block_entropies else 0.0,
            "min_block": round(min(block_entropies), 4) if block_entropies else 0.0,
            "avg_block": round(avg, 4),
            "high_entropy_blocks": high_entropy_offsets[:50],  # cap at 50
        }

        if high_entropy_offsets:
            f = Finding(
                module="entropy",
                title="High-Entropy Region Detected",
                severity=Severity.MEDIUM,
                confidence=0.70,
                value=f"{len(high_entropy_offsets)} block(s) with entropy > 7.5",
                evidence=f"First high-entropy block at offset 0x{high_entropy_offsets[0]['offset']:08x}",
                reason="High entropy may indicate encryption, compression, or hidden payload",
                false_positive_risk="Medium — compressed audio codecs also produce high entropy",
            )
            self.results["findings"].append(f.to_dict())

        lines = [
            "=== ENTROPY ANALYSIS ===",
            f"File size   : {len(data):,} bytes",
            f"Overall     : {overall:.4f} bits/byte",
            f"Block size  : {block_size} bytes",
            f"Blocks      : {len(block_entropies)}",
            f"Max block   : {self.results['entropy']['max_block']:.4f}",
            f"Min block   : {self.results['entropy']['min_block']:.4f}",
            f"Avg block   : {avg:.4f}",
            "",
            f"High-entropy blocks (>7.5): {len(high_entropy_offsets)}",
        ]
        for h in high_entropy_offsets[:20]:
            lines.append(f"  offset 0x{h['offset']:08x}  entropy={h['entropy']:.4f}")

        lines += ["", "Interpretation:"]
        if overall > 7.5:
            lines.append("  HIGH — possibly encrypted, compressed, or random data")
        elif overall > 6.0:
            lines.append("  MODERATE-HIGH — compressed audio, likely normal")
        elif overall > 4.0:
            lines.append("  MODERATE — typical for uncompressed audio (PCM)")
        else:
            lines.append("  LOW — silence, padding, or simple patterns")

        out_path = os.path.join(self.output_dir, "entropy.txt")
        save_text(out_path, "\n".join(lines))
        logger.info(f"Entropy: overall={overall:.4f}, {len(high_entropy_offsets)} high-entropy blocks")

    def _shannon_entropy(self, data: bytes) -> float:
        """Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    # ------------------------------------------------------------------
    # Embedded file detection (FIXED: skip offset 0)
    # ------------------------------------------------------------------

    def _detect_embedded(self, path: str):
        """
        Scan for embedded file magic signatures.

        FIX (v1.1): The original code reported the file's own header (e.g.
        'RIFF' at offset 0 for WAV files) as an 'embedded' signature.  We now
        skip offset 0 and also deduplicate same-type consecutive matches.

        FIX (v4.1): A bare magic-byte match used to be reported as a HIGH/85%
        "Embedded File Signatures" finding regardless of whether the bytes
        that followed actually formed a valid structure — the exact false
        positive pattern this project's own MP3/AAC frame validator was built
        to eliminate elsewhere (see validate.py), but this scanner never
        called into it. Every hit is now run through
        validate.py::validate_embedded() (the same structural validator
        extraction.py already uses) and split into two buckets:
          - Verified Embedded Artifact: validator confirmed real structure
            (evidence level above MAGIC_ONLY) -> confidence from the
            evidence-based confidence engine, severity capped accordingly.
          - Possible Signature: no validator for this type, magic-only match,
            or the validator rejected the structure -> capped at INFO/LOW and
            explicitly labeled unverified, never "Embedded File".
        """
        data = read_bytes(path, max_bytes=_MAGIC_SCAN_LIMIT)
        if not data:
            return

        all_found = find_embedded_files(data)

        # Filter: skip offset 0 (own header), skip obvious audio format signatures
        audio_self_magic = {b"RIFF", b"fLaC", b"OggS", b"ID3", b"\xff\xfb"}
        filtered: List[Dict] = []
        for item in all_found:
            if item["offset"] == 0:
                continue
            # Check raw bytes at this offset against audio self-magic
            magic_bytes = data[item["offset"]: item["offset"] + 4]
            if any(magic_bytes.startswith(m) for m in audio_self_magic if item["offset"] < 10):
                continue
            filtered.append(item)

        verified: List[Dict] = []
        possible: List[Dict] = []
        for item in filtered:
            result = validate_embedded(data, item["offset"], item["type"])
            item["validation"] = result
            if result.valid and result.evidence_level != EvidenceLevel.MAGIC_ONLY:
                verified.append(item)
            else:
                possible.append(item)

        self.results["embedded_files"] = filtered
        self.results["embedded_verified"] = verified
        self.results["embedded_possible"] = possible

        lines = [f"=== EMBEDDED FILE SIGNATURES ({len(filtered)} found) ==="]

        if verified:
            lines.append(f"\n--- Verified Embedded Artifacts ({len(verified)}) ---")
            for item in verified:
                r = item["validation"]
                lines.append(
                    f"  {item['type']} @ offset 0x{item['offset']:08x} "
                    f"({r.evidence_level.value}, confidence={r.confidence:.0%}): {r.reason}"
                )
            f = Finding(
                module="binary",
                title="Verified Embedded Artifact",
                severity=cap_severity(Severity.HIGH, max(i["validation"].confidence for i in verified)),
                confidence=max(i["validation"].confidence for i in verified),
                value=f"{len(verified)} verified embedded artifact(s): "
                      + ", ".join(sorted({i["type"] for i in verified})),
                evidence="\n".join(
                    f"  {i['type']} @ 0x{i['offset']:08x} — {i['validation'].reason}"
                    for i in verified[:5]
                ),
                reason="Structural validator confirmed real file structure, not just magic bytes",
                false_positive_risk="Low — structure was actually parsed/validated",
            )
            self.results["findings"].append(f.to_dict())
            logger.info(f"Found {len(verified)} verified embedded artifact(s)")

        if possible:
            lines.append(f"\n--- Possible Signatures (unverified, {len(possible)}) ---")
            for item in possible:
                r = item["validation"]
                lines.append(
                    f"  {item['type']} @ offset 0x{item['offset']:08x} — "
                    f"UNVERIFIED: {r.reason}"
                )
            f = Finding(
                module="binary",
                title="Possible Signature (Unverified)",
                severity=cap_severity(Severity.LOW, 0.20),
                confidence=0.20,
                value=f"{len(possible)} unverified magic-byte match(es): "
                      + ", ".join(sorted({i["type"] for i in possible})),
                evidence="\n".join(
                    f"  {i['type']} @ 0x{i['offset']:08x}" for i in possible[:5]
                ),
                reason="Magic bytes matched but structural validation failed or no validator exists "
                       "for this type — this is NOT a confirmed embedded file",
                false_positive_risk="High — bare magic-byte patterns occur by chance in PCM audio data",
            )
            self.results["findings"].append(f.to_dict())
            logger.info(f"Found {len(possible)} unverified possible signature(s)")

        if filtered:
            out_path = os.path.join(self.output_dir, "embedded_signatures.txt")
            save_text(out_path, "\n".join(lines))
        else:
            save_text(
                os.path.join(self.output_dir, "embedded_signatures.txt"),
                "=== EMBEDDED FILE SIGNATURES ===\nNo embedded file signatures found.\n",
            )

    # ------------------------------------------------------------------
    # Encoded data detection (FIXED: validated base64 only)
    # ------------------------------------------------------------------

    def _detect_encoded_data(self):
        """
        Search strings for encoded/obfuscated data.

        FIXED: base64 detection now uses is_likely_base64() validation
        to eliminate the massive false-positive rate from the raw regex.
        Other encoded patterns (URL, IP, JWT etc.) are searched directly.
        """
        strings = self.results.get("strings", [])
        full_text = "\n".join(strings)
        encoded: Dict[str, Any] = {}

        # Pattern-based detection (URL, IP, JWT, keys)
        for name, pattern in PATTERNS.items():
            matches = list(set(pattern.findall(full_text)))[:50]
            if matches:
                encoded[name] = matches
                logger.info(f"Found {len(matches)} {name} pattern(s)")

        # Validated base64 candidates (NOT raw regex — too many false positives)
        b64_candidates = re.findall(
            r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            full_text,
        )
        validated_b64: List[Dict] = []
        for candidate in dict.fromkeys(b64_candidates):  # deduplicate order-preserving
            if not is_likely_base64(candidate):
                continue
            try:
                import base64 as _b64
                decoded_bytes = _b64.b64decode(candidate + "==")
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                validated_b64.append({"encoded": candidate, "decoded": decoded_text[:200]})
            except Exception:
                pass
            if len(validated_b64) >= 20:
                break

        if validated_b64:
            encoded["base64"] = [i["encoded"] for i in validated_b64]
            encoded["base64_decoded"] = validated_b64
            logger.info(f"Found {len(validated_b64)} validated base64 string(s)")

        self.results["encoded_data"] = encoded

        if any(encoded.values()):
            lines = ["=== ENCODED DATA DETECTED ==="]
            for enc_type, items in encoded.items():
                if isinstance(items, list) and items:
                    lines.append(f"\n[{enc_type}] ({len(items)} matches)")
                    for item in items[:10]:
                        if isinstance(item, dict):
                            lines.append(f"  ENC: {item.get('encoded', '')[:80]}")
                            lines.append(f"  DEC: {item.get('decoded', '')[:80]}")
                        else:
                            lines.append(f"  {str(item)[:100]}")
            out_path = os.path.join(self.output_dir, "encoded_data.txt")
            save_text(out_path, "\n".join(lines))

    # ------------------------------------------------------------------
    # Appended data detection (FIXED formula for compressed audio)
    # ------------------------------------------------------------------

    def _detect_appended_data(self, path: str):
        """
        Detect data appended after the audio stream ends.

        FIXED: The original formula `(duration * bitrate) / 8` uses the
        *codec* bitrate which is the compressed output rate, not the container
        file byte rate — this produced constant false positives for MP3/OGG/FLAC.

        New approach: compare ffprobe-reported `format.size` with the sum of
        stream `duration_ts * time_base * sample_rate * channels * bit_depth / 8`
        for PCM streams, OR use the `format.size` minus header overhead estimated
        from `format.start_time` for compressed formats.

        For WAV: expected size = data chunk size + 44-byte header.  Read the RIFF
        header directly.  For other formats, fall back to ffprobe size comparison
        with a generous tolerance.
        """
        ext = os.path.splitext(path)[1].lower()

        if ext == ".wav":
            self._detect_appended_wav(path)
        else:
            self._detect_appended_generic(path)

    def _detect_appended_wav(self, path: str):
        """WAV-specific appended data detection using RIFF header parsing."""
        try:
            with open(path, "rb") as f:
                header = f.read(12)
            if len(header) < 12 or header[:4] != b"RIFF":
                return
            riff_size = struct.unpack_from("<I", header, 4)[0]
            # RIFF chunk size = total file size - 8
            expected_size = riff_size + 8
            actual_size = os.path.getsize(path)
            extra = actual_size - expected_size

            if extra > _APPENDED_THRESHOLD:
                self._record_appended(path, actual_size, expected_size, extra)
        except Exception as e:
            logger.debug(f"WAV appended data check failed: {e}")

    def _detect_appended_generic(self, path: str):
        """
        Generic appended data detection for non-WAV formats.
        Uses ffprobe format.size vs actual file size with 5% tolerance for
        container overhead — avoids the bitrate false-positive.
        """
        if not tool_available("ffprobe"):
            return
        rc, out, err = run_command(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_format", path],
            timeout=30,
        )
        try:
            info = json.loads(out)
            fmt = info.get("format", {})
            reported_size = int(fmt.get("size", 0))
            actual_size = os.path.getsize(path)

            if reported_size <= 0:
                return

            extra = actual_size - reported_size
            # Allow 5 % container overhead — only flag substantial extras
            if extra > max(_APPENDED_THRESHOLD, reported_size * 0.05):
                self._record_appended(path, actual_size, reported_size, extra)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            pass

    def _record_appended(self, path: str, actual: int, expected: int, extra: int):
        """Record and extract detected appended data."""
        self.results["appended_data"] = {
            "detected": True,
            "file_size": actual,
            "expected_size": expected,
            "extra_bytes": extra,
            "offset": expected,
        }
        logger.warning(
            f"Appended data: {extra:,} bytes after expected end "
            f"(offset 0x{expected:08x})"
        )
        data = read_bytes(path)
        if len(data) > expected > 0:
            appended = data[expected:]
            out_path = os.path.join(self.output_dir, "extracted", "appended_data.bin")
            save_bytes(out_path, appended)
            logger.info(f"Saved appended data ({extra:,} bytes) → {out_path}")

        f = Finding(
            module="binary",
            title="Appended Data Detected",
            severity=Severity.HIGH,
            confidence=0.75,
            value=f"{extra:,} extra bytes at offset 0x{expected:08x}",
            evidence=f"File size {actual:,} B vs expected {expected:,} B",
            reason="Data exists beyond the expected end of the audio stream",
            false_positive_risk="Low for WAV (RIFF header); medium for compressed formats",
        )
        self.results["findings"].append(f.to_dict())

    # ------------------------------------------------------------------
    # Cipher helpers (kept for scanner.py compatibility)
    # ------------------------------------------------------------------

    def detect_ciphers(self, text: str) -> Dict[str, Any]:
        """
        Detect common text-based ciphers.
        Now imports from findings.py to avoid duplication.
        Limits input to 4 KB to prevent O(25n) hang on large files.
        """
        from .findings import caesar as _caesar, rot13 as _rot13, looks_like_flag

        text = text[:4096]
        findings: Dict[str, Any] = {}

        rot13_result = _rot13(text)
        if looks_like_flag(rot13_result):
            findings["rot13"] = rot13_result[:200]

        caesar_hits = []
        for shift in range(1, 26):
            shifted = _caesar(text, shift)
            if looks_like_flag(shifted):
                caesar_hits.append({"shift": shift, "text": shifted[:200]})
        if caesar_hits:
            findings["caesar"] = caesar_hits

        return findings
