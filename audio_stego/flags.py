"""
Flag detection module for Audio Stego Solver.

FIXED (v1.1):
  - _gather_all_text: now skips report.html / report.json (circular false positives)
  - _search_encoded_flags: base64 validated with is_likely_base64() before decoding
  - _analyze_ciphers: input capped at 4 KB to prevent O(25n) hang on large files
  - Duplicate cipher code removed — now uses findings.py (single source of truth)
  - Catch-all generic flag pattern removed (too broad — matched CSS/JSON/format strings)
  - find_flags_in_text from findings.py used for consistent scoring
"""

import base64
import os
import re
from typing import Any, Dict, List, Set

from .findings import (
    Finding,
    SECRET_PATTERNS,
    caesar as _caesar, rot13 as _rot13,
    find_flags_in_text, is_likely_base64, looks_like_flag,
)
from .logger import get_logger
from .utils import recursive_file_search, save_text

logger = get_logger("audio_stego.flags")

# Files that must NOT be read during flag scanning (they are outputs that
# already contain the findings text — reading them creates circular FPs)
_SKIP_OUTPUT_FILES = {
    "report.html", "report.json", "report.txt",
    "flags.txt", "cipher_analysis.txt",
}


class FlagDetector:
    """Searches for CTF flags and interesting patterns across all outputs."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.results: Dict[str, Any] = {
            "flags_found": [],
            "suspicious_strings": [],
            "cipher_results": {},
            "warnings": [],
            "findings": [],
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, additional_text: str = "") -> Dict[str, Any]:
        """Search all output files and additional text for flags."""
        logger.info("Starting flag detection sweep")

        all_text = self._gather_all_text() + "\n" + additional_text

        # Plain-text flag search (using validated patterns from findings.py)
        plain_findings = find_flags_in_text(all_text, source="output_files")

        # Encoded flag search
        encoded_findings = self._search_encoded_flags(all_text)

        # Merge and deduplicate
        seen: Set[str] = set()
        all_flag_findings: List[Finding] = []
        for f in plain_findings + encoded_findings:
            key = f.value if isinstance(f, Finding) else f.get("value", "")
            if key and key not in seen:
                seen.add(key)
                all_flag_findings.append(f if isinstance(f, Finding) else f)

        self.results["flags_found"] = [
            (f.to_dict() if isinstance(f, Finding) else f)
            for f in all_flag_findings
        ]
        self.results["findings"] = self.results["flags_found"]

        # Suspicious strings
        self.results["suspicious_strings"] = self._find_suspicious(all_text)

        # Cipher analysis
        self._analyze_ciphers(all_text)

        # Save report
        self._save_flag_report()

        if self.results["flags_found"]:
            logger.info(f"FOUND {len(self.results['flags_found'])} POTENTIAL FLAG(S)!")
        else:
            logger.info("No flags matched known patterns")

        return self.results

    # ------------------------------------------------------------------
    # Text gathering (FIXED: skip output files to avoid circular FPs)
    # ------------------------------------------------------------------

    def _gather_all_text(self) -> str:
        """Read text output files, skipping reports that contain flag summaries."""
        texts: List[str] = []
        for fpath in recursive_file_search(self.output_dir):
            basename = os.path.basename(fpath)
            # Skip known circular-false-positive sources
            if basename in _SKIP_OUTPUT_FILES:
                continue
            ext = os.path.splitext(fpath)[1].lower()
            if ext not in (".txt", ".log", ".csv", ".xml", ".md", ""):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    texts.append(fh.read(500_000))
            except (IOError, OSError):
                pass
        return "\n".join(texts)

    # ------------------------------------------------------------------
    # Encoded flag search (FIXED: validated base64 only)
    # ------------------------------------------------------------------

    def _search_encoded_flags(self, text: str) -> List[Finding]:
        """Search for flags hidden in encoded forms."""
        found: List[Finding] = []

        # --- Base64 (validated) ---
        b64_re = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        )
        seen_b64: Set[str] = set()
        for candidate in b64_re.findall(text):
            if candidate in seen_b64:
                continue
            seen_b64.add(candidate)
            if not is_likely_base64(candidate):
                continue
            for decode_fn, label in [
                (base64.b64decode, "base64"),
                (base64.urlsafe_b64decode, "base64url"),
            ]:
                try:
                    decoded = decode_fn(candidate + "==").decode("utf-8", errors="replace")
                    for flag_finding in find_flags_in_text(decoded, source=f"{label} decode"):
                        flag_finding.encoding = label
                        flag_finding.evidence = (
                            f"Decoded from {label}: '{candidate[:40]}…'"
                        )
                        found.append(flag_finding)
                except Exception:
                    pass

        # --- Hex ---
        hex_re = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
        seen_hex: Set[str] = set()
        for candidate in hex_re.findall(text):
            if candidate in seen_hex:
                continue
            seen_hex.add(candidate)
            try:
                decoded = bytes.fromhex(candidate).decode("utf-8", errors="replace")
                printable = sum(1 for c in decoded if 0x20 <= ord(c) < 0x7F)
                if printable / max(len(decoded), 1) < 0.70:
                    continue
                for flag_finding in find_flags_in_text(decoded, source="hex decode"):
                    flag_finding.encoding = "hex"
                    flag_finding.evidence = f"Decoded from hex: '{candidate[:40]}'"
                    found.append(flag_finding)
            except Exception:
                pass

        # --- Binary (8-bit groups) ---
        bin_re = re.compile(r"(?:[01]{8}[\s]?){8,}")
        seen_bin: Set[str] = set()
        for candidate in bin_re.findall(text):
            if candidate in seen_bin:
                continue
            seen_bin.add(candidate)
            try:
                bits = re.sub(r"\s", "", candidate)
                decoded = "".join(
                    chr(int(bits[i: i + 8], 2))
                    for i in range(0, len(bits) - 7, 8)
                )
                for flag_finding in find_flags_in_text(decoded, source="binary decode"):
                    flag_finding.encoding = "binary"
                    flag_finding.evidence = f"Decoded from binary: '{candidate[:40]}'"
                    found.append(flag_finding)
            except Exception:
                pass

        return found

    # ------------------------------------------------------------------
    # Suspicious string detection
    # ------------------------------------------------------------------

    def _find_suspicious(self, text: str) -> List[str]:
        """Find credential / secret patterns beyond confirmed flags."""
        suspicious: List[str] = []
        seen: Set[str] = set()
        for pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                val = m.group(0)[:200]
                if val not in seen:
                    seen.add(val)
                    suspicious.append(val)
        return suspicious[:50]

    # ------------------------------------------------------------------
    # Cipher analysis (FIXED: input capped at 4 KB)
    # ------------------------------------------------------------------

    def _analyze_ciphers(self, text: str):
        """
        Try common cipher decodings on extracted text.

        FIXED: input is now capped at 4 KB to prevent O(25 × n) hang.
        """
        # Work only on the first 4 KB — enough to find a flag, avoids hanging
        sample = text[:4096]
        results: Dict[str, List[str]] = {}

        # ROT13
        rotted = _rot13(sample)
        if looks_like_flag(rotted):
            results.setdefault("rot13", []).append(rotted[:200])

        # All Caesar shifts
        for shift in range(1, 26):
            shifted = _caesar(sample, shift)
            if looks_like_flag(shifted):
                results.setdefault("caesar", []).append(f"shift={shift}: {shifted[:200]}")

        # XOR single-byte brute-force
        raw = sample.encode("utf-8", errors="replace")
        for key in range(1, 256):
            xored = bytes(b ^ key for b in raw)
            try:
                decoded = xored.decode("utf-8", errors="replace")
                if looks_like_flag(decoded):
                    results.setdefault("xor", []).append(f"key=0x{key:02x}: {decoded[:200]}")
            except Exception:
                pass

        self.results["cipher_results"] = results

        if results:
            lines = ["=== CIPHER ANALYSIS RESULTS ==="]
            for cipher, hits in results.items():
                lines.append(f"\n[{cipher}]")
                for hit in hits[:5]:
                    lines.append(f"  {hit}")
            out_path = os.path.join(self.output_dir, "cipher_analysis.txt")
            save_text(out_path, "\n".join(lines))

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _save_flag_report(self):
        lines = ["=" * 60, "FLAG DETECTION REPORT", "=" * 60]

        flags = self.results.get("flags_found", [])
        if flags:
            lines.append(f"\n[!!!] FOUND {len(flags)} POTENTIAL FLAG(S):\n")
            for i, flag in enumerate(flags, 1):
                v = flag.get("value", flag) if isinstance(flag, dict) else str(flag)
                enc = flag.get("encoding", "plaintext") if isinstance(flag, dict) else "?"
                conf = flag.get("confidence_pct", "?") if isinstance(flag, dict) else "?"
                lines.append(f"  {i}. {v}")
                lines.append(f"     Encoding   : {enc}")
                lines.append(f"     Confidence : {conf}")
                lines.append("")
        else:
            lines.append("\n  No flags found matching known patterns.")

        suspicious = self.results.get("suspicious_strings", [])
        if suspicious:
            lines.append("\n[~] SUSPICIOUS STRINGS:")
            for s in suspicious[:20]:
                lines.append(f"  - {s[:120]}")

        cipher = self.results.get("cipher_results", {})
        if cipher:
            lines.append("\n[~] CIPHER ANALYSIS HITS:")
            for ctype, hits in cipher.items():
                lines.append(f"\n  [{ctype}]")
                for hit in hits[:3]:
                    lines.append(f"    {hit[:150]}")

        out_path = os.path.join(self.output_dir, "flags.txt")
        save_text(out_path, "\n".join(lines))
        logger.info(f"Flag report → {out_path}")
