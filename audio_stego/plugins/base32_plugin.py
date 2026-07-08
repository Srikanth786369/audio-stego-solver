"""Base32 decode plugin for Audio Stego Solver."""

import base64
import re
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity


class Base32Plugin(BasePlugin):
    name        = "base32"
    version     = "1.1.0"
    description = "Decode Base32-encoded strings from extracted text"

    _B32_RE = re.compile(r"(?:[A-Z2-7]{8})+(?:[A-Z2-7]{2,8}={0,6})?")

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        corpus = self.get_all_text(results)
        candidates = list(dict.fromkeys(self._B32_RE.findall(corpus)))

        lines: List[str] = [f"=== BASE32 DECODE ({len(candidates)} candidates) ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        for candidate in candidates[:200]:
            if len(candidate) < 8:
                continue
            try:
                padded  = candidate + "=" * ((8 - len(candidate) % 8) % 8)
                decoded = base64.b32decode(padded, casefold=True).decode("utf-8", errors="replace")
                lines.append(f"{candidate[:40]} → {decoded[:120]}")
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(decoded):
                        val = m.group(0)
                        if val in seen:
                            continue
                        seen.add(val)
                        flag_findings.append(self.finding(
                            title="Flag in Base32-decoded string",
                            value=val,
                            evidence=f"Decoded from base32: '{candidate[:40]}'",
                            confidence=0.88,
                            severity=Severity.HIGH,
                            encoding="base32",
                        ))
            except Exception:
                pass

        if not flag_findings:
            lines.append("No flags found in Base32-decoded strings.")

        self.save_output(output_dir, "base32_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
