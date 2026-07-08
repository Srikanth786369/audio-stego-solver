"""GZIP decompression plugin for Audio Stego Solver."""

import gzip
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity


class GZIPPlugin(BasePlugin):
    name        = "gzip"
    version     = "1.1.0"
    description = "Decompress gzip blobs embedded in audio files"

    _MAGIC = b"\x1f\x8b"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        from ..utils import read_bytes
        raw   = read_bytes(audio_path, max_bytes=50 * 1024 * 1024)
        lines: List[str] = ["=== GZIP DECOMPRESSION ===\n"]
        flag_findings: List[Dict] = []
        found = 0
        idx   = 0

        while True:
            pos = raw.find(self._MAGIC, idx)
            if pos == -1:
                break
            idx = pos + 1
            try:
                data = gzip.decompress(raw[pos:pos + 10 * 1024 * 1024])
                text = data.decode("utf-8", errors="replace")
                out  = self.save_output(output_dir, f"gzip_{found}.bin", text)
                lines.append(f"Offset 0x{pos:08x}: {len(data):,} bytes → {out}")
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(text):
                        flag_findings.append(self.finding(
                            title="Flag in gzip-decompressed data",
                            value=m.group(0),
                            evidence=f"gzip stream at offset 0x{pos:08x}",
                            confidence=0.88,
                            severity=Severity.HIGH,
                            encoding="gzip",
                        ))
                found += 1
            except Exception:
                pass

        if found == 0:
            lines.append("No valid gzip streams found.")

        self.save_output(output_dir, "gzip_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
