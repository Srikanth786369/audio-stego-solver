"""Base58 decode plugin for Audio Stego Solver."""

import re
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        if ch not in _ALPHABET:
            raise ValueError(f"Invalid base58 char: {ch!r}")
        num = num * 58 + _ALPHABET.index(ch)
    result = []
    while num > 0:
        result.append(num % 256)
        num //= 256
    for ch in s:
        if ch == _ALPHABET[0]:
            result.append(0)
        else:
            break
    return bytes(reversed(result))


class Base58Plugin(BasePlugin):
    name        = "base58"
    version     = "1.1.0"
    description = "Decode Base58-encoded strings from extracted text"

    _B58_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{20,}")

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        corpus     = self.get_all_text(results)
        candidates = list(dict.fromkeys(self._B58_RE.findall(corpus)))

        lines: List[str] = [f"=== BASE58 DECODE ({len(candidates)} candidates) ===\n"]
        flag_findings: List[Dict] = []
        seen: set = set()

        for candidate in candidates[:200]:
            try:
                decoded = _b58decode(candidate).decode("utf-8", errors="replace")
                printable = sum(1 for c in decoded if 0x20 <= ord(c) < 0x7F)
                if printable / max(len(decoded), 1) < 0.70:
                    continue
                lines.append(f"{candidate[:40]} → {decoded[:120]}")
                for pat in FLAG_PATTERNS:
                    for m in pat.finditer(decoded):
                        val = m.group(0)
                        if val in seen:
                            continue
                        seen.add(val)
                        flag_findings.append(self.finding(
                            title="Flag in Base58-decoded string",
                            value=val,
                            evidence=f"Decoded from base58: '{candidate[:40]}'",
                            confidence=0.85,
                            severity=Severity.HIGH,
                            encoding="base58",
                        ))
            except Exception:
                pass

        if not flag_findings:
            lines.append("No flags found in Base58-decoded strings.")

        self.save_output(output_dir, "base58_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
