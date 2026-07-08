"""
XOR single-byte brute-force plugin for Audio Stego Solver.

v4.1: single-byte XOR against 255 keys is guaranteed to produce garbage that
occasionally matches the generic flag regex (`[a-zA-Z]{2,12}\\{...\\}`) by pure
chance — the old version accepted any regex hit at a flat 85% confidence,
which is exactly the "XOR generates fake flags" false-positive pattern this
version is required to eliminate. A candidate is now only kept if it clears
ALL of:
  - printable ratio > 90% over the *entire* decoded buffer (not just the
    matched substring) — real plaintext decodes cleanly; noise doesn't.
  - entropy reasonable (<= 6.5 bits/byte) — random/still-encrypted data
    stays close to 8 bits/byte even after a single-byte XOR.
  - flag regex match (existing behavior, kept).
  - for the generic (non-platform-specific) flag pattern specifically: a
    language/dictionary score on the surrounding context, since "word{...}"
    can appear by chance far more easily than "flag{...}"/"HTB{...}" etc.
Anything failing a gate is discarded silently (debug-logged), never reported.
"""

from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import FLAG_PATTERNS, Severity, english_word_score, printable_ratio, shannon_entropy
from ..logger import get_logger

logger = get_logger("audio_stego.plugins.xor")

_MIN_PRINTABLE_RATIO = 0.90
_MAX_ENTROPY = 6.5
_MIN_CONTEXT_LANGUAGE_SCORE = 0.15   # required only for the generic flag pattern


class XORPlugin(BasePlugin):
    name        = "xor"
    version     = "1.2.0"
    description = "Brute-force XOR single-byte keys on extracted strings"

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        raw_text  = self.get_all_text(results)
        raw_bytes = raw_text.encode("utf-8", errors="replace")[:65_536]

        flag_findings: List[Dict] = []
        lines = ["=== XOR ANALYSIS (keys 0x01–0xFF) ===\n"]
        seen: set = set()
        discarded = 0

        for key in range(1, 256):
            xored = bytes(b ^ key for b in raw_bytes)

            p_ratio = printable_ratio(xored)
            if p_ratio <= _MIN_PRINTABLE_RATIO:
                continue  # too noisy to even be worth a regex scan
            entropy = shannon_entropy(xored)
            if entropy > _MAX_ENTROPY:
                continue  # still looks encrypted/random, not decoded plaintext

            decoded = xored.decode("utf-8", errors="replace")
            for pat in FLAG_PATTERNS:
                is_specific = not pat.pattern.startswith(r"[a-zA-Z]")
                for m in pat.finditer(decoded):
                    val = m.group(0)
                    if val in seen:
                        continue

                    start = max(0, m.start() - 80)
                    end = min(len(decoded), m.end() + 80)
                    context = decoded[start:end]
                    lang_score = english_word_score(context)

                    if not is_specific and lang_score < _MIN_CONTEXT_LANGUAGE_SCORE:
                        # Generic "word{...}" pattern with no surrounding
                        # English text — almost certainly decode noise.
                        discarded += 1
                        logger.debug(
                            f"XOR key=0x{key:02x}: discarded generic-pattern candidate "
                            f"'{val[:40]}' — language score {lang_score:.2f} < {_MIN_CONTEXT_LANGUAGE_SCORE}"
                        )
                        continue

                    seen.add(val)
                    confidence = min(0.97, 0.55 + p_ratio * 0.20 + lang_score * 0.15 + (0.10 if is_specific else 0))
                    lines.append(
                        f"key=0x{key:02x}: {val}  "
                        f"(printable={p_ratio:.0%}, entropy={entropy:.2f}, lang_score={lang_score:.2f})"
                    )
                    flag_findings.append(
                        self.finding(
                            title="Flag via XOR Decode",
                            value=val,
                            evidence=(
                                f"XOR key=0x{key:02x} applied to {len(raw_bytes):,} bytes — "
                                f"printable ratio {p_ratio:.0%}, entropy {entropy:.2f} bits/byte, "
                                f"context language score {lang_score:.2f}"
                            ),
                            confidence=confidence,
                            severity=Severity.HIGH,
                            encoding=f"xor:0x{key:02x}",
                            false_positive_risk=(
                                "Low — passed printable-ratio, entropy, and pattern-specificity gates"
                                if is_specific else
                                "Medium — generic flag pattern, gated on surrounding-context language score"
                            ),
                        )
                    )

        if not flag_findings:
            lines.append(
                f"No flag patterns found via XOR brute-force "
                f"(discarded {discarded} low-confidence candidate(s))."
            )
        elif discarded:
            lines.append(f"\n({discarded} additional candidate(s) discarded — failed language-score gate)")

        self.save_output(output_dir, "xor_results.txt", "\n".join(lines))
        return {"flags_found": flag_findings, "findings": flag_findings}
