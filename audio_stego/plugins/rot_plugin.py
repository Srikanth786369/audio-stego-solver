"""ROT13 / Caesar cipher plugin for Audio Stego Solver."""

from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity, caesar, rot13


class ROTPlugin(BasePlugin):
    name        = "rot"
    version     = "1.1.0"
    description = "Try ROT13 and all Caesar shifts on extracted strings"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        combined = self.get_all_text(results)[:8192]

        lines: List[str] = ["=== ROT / CAESAR ANALYSIS ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        for shift in range(1, 26):
            label   = "ROT13" if shift == 13 else f"ROT{shift}"
            shifted = (rot13 if shift == 13 else lambda t: caesar(t, shift))(combined)
            for pat in FLAG_PATTERNS:
                for m in pat.finditer(shifted):
                    val = m.group(0)
                    if val in seen:
                        continue
                    seen.add(val)
                    lines.append(f"[{label}] → {val}")
                    flag_findings.append(
                        self.finding(
                            title=f"Flag via {label}",
                            value=val,
                            evidence=f"Caesar shift={shift} applied to text corpus",
                            confidence=0.88,
                            severity=Severity.HIGH,
                            encoding=f"caesar:{shift}",
                        )
                    )

        if not flag_findings:
            lines.append("No flag patterns found via ROT/Caesar shifts.")

        self.save_output(output_dir, "rot_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
