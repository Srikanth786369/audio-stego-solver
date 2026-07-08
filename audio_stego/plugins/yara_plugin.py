"""YARA scanning plugin for Audio Stego Solver."""

import os
from typing import Any, Dict, List, Optional

from .base_plugin import BasePlugin
from ..findings import Severity

_BUILTIN_RULES = r"""
rule CTF_Flag_Generic {
    strings:
        $flag = /[a-zA-Z]{2,12}\{[A-Za-z0-9_\-]{6,80}\}/
    condition:
        $flag
}
rule Embedded_ELF {
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf and @elf > 512
}
rule Embedded_ZIP {
    strings:
        $pk = { 50 4B 03 04 }
    condition:
        $pk and @pk > 512
}
rule PEM_Key_Material {
    strings:
        $pem = "-----BEGIN"
    condition:
        $pem
}
"""


class YARAPlugin(BasePlugin):
    name        = "yara"
    version     = "1.1.0"
    description = "Run YARA rules against audio file for known signatures"
    dependencies = ["yara-python"]
    input_types  = ["audio_path"]
    output_types = ["findings"]

    def run(self, audio_path: str, output_dir: str, results: Dict[str, Any]) -> Optional[Dict]:
        lines: List[str] = ["=== YARA SCAN ===\n"]
        findings_list: List[Dict] = []

        try:
            import yara  # type: ignore

            rules_path = os.path.join(output_dir, "ctf_rules.yar")
            with open(rules_path, "w") as f:
                f.write(_BUILTIN_RULES)

            rule_files = [rules_path]
            user_dir   = os.path.expanduser("~/.config/audio-stego/yara")
            if os.path.isdir(user_dir):
                for fn in os.listdir(user_dir):
                    if fn.endswith((".yar", ".yara")):
                        rule_files.append(os.path.join(user_dir, fn))

            for rf in rule_files:
                try:
                    compiled = yara.compile(filepath=rf)
                    matches  = compiled.match(audio_path)
                    for m in matches:
                        lines.append(f"MATCH: {m.rule} [{rf}]")
                        sev = Severity.HIGH if "Flag" in m.rule else Severity.MEDIUM
                        findings_list.append(self.finding(
                            title=f"YARA rule match: {m.rule}",
                            value=m.rule,
                            evidence=f"Rule file: {rf}",
                            confidence=0.80,
                            severity=sev,
                        ))
                except Exception as e:
                    lines.append(f"Rule error in {rf}: {e}")

        except ImportError:
            lines.append("yara-python not installed: pip install yara-python")

        except Exception as e:
            lines.append(f"YARA error: {e}")

        self.save_output(output_dir, "yara_results.txt", "\n".join(lines))
        return {"flags_found": [], "findings": findings_list}
