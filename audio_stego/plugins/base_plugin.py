"""
Base plugin class for Audio Stego Solver.

FIXED (v1.1):
  - Plugin API now returns Finding dicts via self.finding() helper
  - All plugin results include confidence, severity, evidence
"""

import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..findings import Finding, Severity


class BasePlugin(ABC):
    """Abstract base class for all Audio Stego Solver plugins."""

    name: str        = "base"
    version: str     = "1.0.0"
    author: str      = "Audio Stego Solver"
    description: str = "Base plugin (override this)"

    # Phase 12 metadata — declared by each plugin so a scan/report can show
    # what a plugin operates on and needs without having to read its source.
    supported_file_types: List[str] = ["*"]   # e.g. ["wav", "mp3"] or ["*"] for any
    dependencies: List[str]         = []       # external tools/libraries required
    input_types: List[str]          = ["audio_path", "results"]
    output_types: List[str]         = ["findings"]

    def __init__(self, config):
        self.config = config

    @classmethod
    def metadata(cls) -> Dict[str, Any]:
        """Structured plugin metadata for introspection (CLI, reports)."""
        return {
            "name": cls.name,
            "version": cls.version,
            "author": cls.author,
            "description": cls.description,
            "supported_file_types": cls.supported_file_types,
            "dependencies": cls.dependencies,
            "input_types": cls.input_types,
            "output_types": cls.output_types,
        }

    @abstractmethod
    def run(
        self,
        audio_path: str,
        output_dir: str,
        results: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Execute plugin analysis.

        Args:
            audio_path: Path to the audio file being analysed
            output_dir: Directory where output files should be saved
            results:    Dict of results from all core analysers

        Returns:
            Dict with keys:
              - flags_found: list of Finding.to_dict()
              - findings:    list of Finding.to_dict() (non-flag)
              - (optional) any other data
        """
        ...

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def save_output(self, output_dir: str, filename: str, content: str) -> str:
        """Save plugin output to a file; create parent dirs as needed."""
        path = os.path.join(output_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        return path

    def finding(
        self,
        title: str,
        value: str,
        evidence: str = "",
        confidence: float = 0.70,
        severity: Severity = Severity.MEDIUM,
        encoding: str = "plaintext",
        false_positive_risk: str = "",
    ) -> Dict[str, Any]:
        """Create a structured Finding dict for this plugin."""
        f = Finding(
            module=f"plugin:{self.name}",
            title=title,
            severity=severity,
            confidence=confidence,
            value=value,
            evidence=evidence,
            encoding=encoding,
            false_positive_risk=false_positive_risk,
        )
        return f.to_dict()

    def get_strings(self, results: Dict[str, Any]) -> List[str]:
        """Extract strings from prior binary analysis results."""
        return results.get("binary", {}).get("strings", [])

    def get_ocr_text(self, results: Dict[str, Any]) -> str:
        """Get all OCR text from prior analysis."""
        return "\n".join(
            r.get("text", "") for r in results.get("ocr", {}).get("ocr", [])
        )

    def get_all_text(self, results: Dict[str, Any]) -> str:
        """Combine strings + OCR text into one corpus for analysis."""
        return "\n".join(self.get_strings(results)) + "\n" + self.get_ocr_text(results)
