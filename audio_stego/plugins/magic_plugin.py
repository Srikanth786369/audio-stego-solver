"""File magic bytes detection plugin for Audio Stego Solver."""

from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import Severity

MAGIC_SIGS = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff":       "JPEG image",
    b"GIF8":               "GIF image",
    b"BM":                 "BMP image",
    b"PK\x03\x04":        "ZIP archive",
    b"Rar!\x1a\x07":      "RAR archive",
    b"7z\xbc\xaf'\x1c":   "7-Zip archive",
    b"\x1f\x8b":          "GZIP compressed",
    b"BZh":               "BZIP2 compressed",
    b"\xfd7zXZ\x00":      "XZ compressed",
    b"%PDF":              "PDF document",
    b"\x7fELF":           "ELF executable",
    b"MZ":                "Windows PE/EXE",
    b"SQLite format 3":   "SQLite database",
    b"-----BEGIN":        "PEM encoded data",
}

# Audio file self-magic — skip these at offset 0
_AUDIO_SELF_MAGIC = {b"RIFF", b"fLaC", b"OggS", b"ID3", b"\xff\xfb"}


class MagicPlugin(BasePlugin):
    name        = "magic"
    version     = "1.1.0"
    description = "Deep scan for embedded file magic signatures at all offsets"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        from ..utils import read_bytes
        raw = read_bytes(audio_path, max_bytes=100 * 1024 * 1024)

        lines: List[str] = [f"=== MAGIC BYTES SCAN ({len(raw):,} bytes) ===\n"]
        findings_list: List[Dict] = []

        for magic, label in MAGIC_SIGS.items():
            offset = 0
            while True:
                idx = raw.find(magic, offset)
                if idx == -1:
                    break
                offset = idx + 1
                if idx == 0:          # skip own audio header
                    continue
                lines.append(f"  {label} @ offset 0x{idx:08x} ({idx:,} bytes)")
                findings_list.append(
                    self.finding(
                        title=f"Embedded {label}",
                        value=f"{label} @ offset 0x{idx:08x}",
                        evidence=f"Magic bytes {magic.hex()} found at offset {idx:,}",
                        confidence=0.88,
                        severity=Severity.HIGH,
                        false_positive_risk="Low for specific magic bytes",
                    )
                )

        if not findings_list:
            lines.append("No unexpected embedded file signatures found.")
        else:
            lines.append(f"\nTotal: {len(findings_list)} embedded signature(s).")

        self.save_output(output_dir, "magic_results.txt", "\n".join(lines))
        return {"flags_found": [], "findings": findings_list}
