"""Base64 decode plugin for Audio Stego Solver."""

import base64
import re
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity, is_likely_base64


class Base64Plugin(BasePlugin):
    name        = "base64"
    version     = "1.1.0"
    description = "Decode validated Base64-encoded strings and search for flags"

    _B64_RE = re.compile(
        r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    )

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        corpus = self.get_all_text(results)
        candidates = list(dict.fromkeys(self._B64_RE.findall(corpus)))

        lines: List[str] = [f"=== BASE64 DECODE ({len(candidates)} candidates) ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        for candidate in candidates[:500]:
            if not is_likely_base64(candidate):
                continue
            for fn, label in [(base64.b64decode, "b64"), (base64.urlsafe_b64decode, "b64url")]:
                try:
                    decoded = fn(candidate + "==").decode("utf-8", errors="replace")
                    lines.append(f"[{label}] {candidate[:40]}… → {decoded[:120]}")
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
                                confidence=0.90,
                                severity=Severity.HIGH,
                                encoding=label,
                            ))
                except Exception:
                    pass

        if not flag_findings:
            lines.append("No flags found in validated Base64 strings.")

        self.save_output(output_dir, "base64_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
