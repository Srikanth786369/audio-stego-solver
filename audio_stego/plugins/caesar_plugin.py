"""Atbash and other classical ciphers plugin for Audio Stego Solver."""

from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity, atbash


class CaesarPlugin(BasePlugin):
    name        = "caesar"
    version     = "1.1.0"
    description = "Apply Atbash and other classical ciphers to extracted strings"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        combined = self.get_all_text(results)[:8192]

        lines: List[str] = ["=== CLASSICAL CIPHER ANALYSIS ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        ab = atbash(combined)
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(ab):
                val = m.group(0)
                if val in seen:
                    continue
                seen.add(val)
                lines.append(f"[ATBASH] → {val}")
                flag_findings.append(
                    self.finding(
                        title="Flag via Atbash",
                        value=val,
                        evidence="Atbash applied to text corpus",
                        confidence=0.85,
                        severity=Severity.HIGH,
                        encoding="atbash",
                    )
                )

        if not flag_findings:
            lines.append("No flag patterns found via classical ciphers.")

        self.save_output(output_dir, "caesar_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
