"""Base85 / Ascii85 decode plugin for Audio Stego Solver."""

import base64
import re
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity


class Base85Plugin(BasePlugin):
    name        = "base85"
    version     = "1.1.0"
    description = "Decode Base85 (Ascii85) encoded strings from extracted text"

    _B85_RE = re.compile(r"[!-u]{16,}")

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        corpus     = self.get_all_text(results)
        candidates = list(dict.fromkeys(self._B85_RE.findall(corpus)))

        lines: List[str] = [f"=== BASE85 DECODE ({len(candidates)} candidates) ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        for candidate in candidates[:200]:
            for fn, label in [(base64.b85decode, "b85"), (base64.a85decode, "a85")]:
                try:
                    decoded = fn(candidate.encode()).decode("utf-8", errors="replace")
                    lines.append(f"[{label}] {candidate[:40]} → {decoded[:120]}")
                    for pat in FLAG_PATTERNS:
                        for m in pat.finditer(decoded):
                            val = m.group(0)
                            if val in seen:
                                continue
                            seen.add(val)
                            flag_findings.append(self.finding(
                                title=f"Flag in {label}-decoded string",
                                value=val,
                                evidence=f"Decoded from {label}: '{candidate[:40]}'",
                                confidence=0.85,
                                severity=Severity.HIGH,
                                encoding=label,
                            ))
                except Exception:
                    pass

        if not flag_findings:
            lines.append("No flags found in Base85-decoded strings.")

        self.save_output(output_dir, "base85_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
