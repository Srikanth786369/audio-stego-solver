"""ZIP extraction plugin for Audio Stego Solver."""

import io
import os
import zipfile
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity

_ZIP_MAGIC = b"PK\x03\x04"


class ZIPPlugin(BasePlugin):
    name        = "zip"
    version     = "1.1.0"
    description = "Extract and inspect ZIP archives embedded in audio files"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        from ..utils import read_bytes
        raw   = read_bytes(audio_path, max_bytes=100 * 1024 * 1024)
        lines: List[str] = ["=== ZIP EXTRACTION ===\n"]
        flag_findings: List[Dict] = []
        found = 0
        idx   = 0

        while True:
            pos = raw.find(_ZIP_MAGIC, idx)
            if pos == -1:
                break
            idx = pos + 1
            try:
                zf    = zipfile.ZipFile(io.BytesIO(raw[pos:]))
                names = zf.namelist()
                lines.append(f"Offset 0x{pos:08x}: ZIP with {len(names)} file(s): {names[:10]}")
                ex_dir = os.path.join(output_dir, f"zip_{found}")
                os.makedirs(ex_dir, exist_ok=True)
                for name in names:
                    try:
                        data = zf.read(name)
                        dest = os.path.join(ex_dir, os.path.basename(name))
                        with open(dest, "wb") as f:
                            f.write(data)
                        text = data.decode("utf-8", errors="replace")
                        for pat in FLAG_PATTERNS:
                            for m in pat.finditer(text):
                                flag_findings.append(self.finding(
                                    title=f"Flag in ZIP entry '{name}'",
                                    value=m.group(0),
                                    evidence=f"ZIP at 0x{pos:08x}, entry: {name}",
                                    confidence=0.92,
                                    severity=Severity.CRITICAL,
                                    encoding="zip_content",
                                ))
                    except Exception:
                        pass
                found += 1
            except Exception:
                pass

        if found == 0:
            lines.append("No valid ZIP archives found embedded in audio.")

        self.save_output(output_dir, "zip_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
