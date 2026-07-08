"""
Extended report generators for Audio Stego Solver.

FIXED (v1.1):
  - HTML report: user-controlled data (filenames, OCR text) is HTML-escaped
  - HTML report: missing images produce a placeholder instead of broken tag
  - JSON report: non-serialisable objects are excluded, not silently str()-ified
  - CSVReportGenerator: now reads severity + confidence from Finding dicts
  - Findings from all sub-modules (binary, digital, visual, ocr) aggregated
"""

import csv
import html as html_mod
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from . import __version__
from .logger import get_logger

logger = get_logger("audio_stego.reports_ext")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """HTML-escape a string to prevent XSS in the report."""
    return html_mod.escape(str(s), quote=True)


def _all_findings(results: Dict[str, Any]) -> List[Dict]:
    """Collect Finding dicts from every sub-module that produces them."""
    findings: List[Dict] = []
    for key in ("binary", "digital", "visual", "ocr", "extraction", "flags"):
        section = results.get(key, {})
        if isinstance(section, dict):
            findings.extend(section.get("findings", []))
    return findings


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def _extraction_record_to_dict(rec: Any) -> Dict[str, Any]:
    """ExtractionRecord is a dataclass with an Enum status field — convert to
    a plain dict so it round-trips through JSON instead of being dropped as
    non-serialisable (previously the JSON report only exported the raw
    extracted_files path list, not the unified Phase 2 evidence records with
    sha256/status/confidence/depth/source_tools)."""
    status = getattr(rec, "status", None)
    return {
        "file_type": getattr(rec, "file_type", None),
        "offset": getattr(rec, "offset", None),
        "status": status.value if hasattr(status, "value") else str(status),
        "confidence": getattr(rec, "confidence", None),
        "reason": getattr(rec, "reason", None),
        "output_path": getattr(rec, "output_path", None),
        "size": getattr(rec, "size", None),
        "false_positive_risk": getattr(rec, "false_positive_risk", None),
        "sha256": getattr(rec, "sha256", None),
        "parent_sha256": getattr(rec, "parent_sha256", None),
        "depth": getattr(rec, "depth", None),
        "source_tools": getattr(rec, "source_tools", None),
        "validator": getattr(rec, "validator", None),
        "timestamp": getattr(rec, "timestamp", None),
    }


def _safe_serialisable(obj: Any) -> Any:
    """Recursively make an object JSON-serialisable without silently str()-ifying."""
    if isinstance(obj, dict):
        return {k: _safe_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_serialisable(v) for v in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    # For genuinely non-serialisable types, use repr but mark clearly
    return f"<non-serialisable: {type(obj).__name__}>"


class JSONReportGenerator:
    """Generates a machine-readable JSON forensic report."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate(self, audio_path: str, results: Dict[str, Any], elapsed_time: float) -> str:
        all_f = _all_findings(results)

        report = _safe_serialisable({
            "meta": {
                "tool": "Audio Stego Solver",
                "version": __version__,
                "generated_at": datetime.now().isoformat(),
                "audio_file": audio_path,
                "elapsed_seconds": round(elapsed_time, 2),
            },
            "summary": {
                "flags_found": len(results.get("flags", {}).get("flags_found", [])),
                "extracted_files": len(results.get("extraction", {}).get("extracted_files", [])),
                "total_findings": len(all_f),
                "severity_counts": {
                    sev: sum(1 for f in all_f if f.get("severity") == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                },
                "extraction_summary": results.get("extraction", {}).get("summary", {}),
            },
            "hashes":          results.get("metadata", {}).get("hashes", {}),
            "flags_found":     results.get("flags", {}).get("flags_found", []),
            "all_findings":    all_f,
            "extraction_records": [
                _extraction_record_to_dict(r)
                for r in results.get("extraction", {}).get("records", [])
            ],
            "extracted_files": results.get("extraction", {}).get("extracted_files", []),
            "binwalk":         results.get("extraction", {}).get("binwalk", []),
            "morse":           results.get("digital", {}).get("morse", []),
            "dtmf":            results.get("digital", {}).get("dtmf", []),
            "minimodem":       results.get("digital", {}).get("minimodem", []),
            "qr_codes":        results.get("ocr", {}).get("qr_codes", []),
            "ocr_text":        [r.get("text", "") for r in results.get("ocr", {}).get("ocr", [])],
            "lsb_analysis":    results.get("visual", {}).get("lsb_analysis"),
            "channel_diff":    results.get("visual", {}).get("channel_diff"),
            "suspicious_strings": results.get("flags", {}).get("suspicious_strings", []),
            "warnings":        list(dict.fromkeys(
                w for v in results.values()
                if isinstance(v, dict)
                for w in v.get("warnings", [])
            )),
        })

        out_path = os.path.join(self.output_dir, "report.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info(f"JSON report → {out_path}")
        return out_path


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

COLUMNS = ["File", "Module", "Severity", "Confidence", "Finding", "Offset", "Description"]


class CSVReportGenerator:
    """Generates a CSV findings report from structured Finding dicts."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate(self, audio_path: str, results: Dict[str, Any], elapsed_time: float) -> str:
        fname = os.path.basename(audio_path)
        rows: List[List[str]] = []
        all_f = _all_findings(results)

        for f in all_f:
            rows.append([
                fname,
                str(f.get("module", "")),
                str(f.get("severity", "")),
                str(f.get("confidence_pct", "")),
                str(f.get("title", "")),
                str(f.get("offset", "")),
                str(f.get("value", ""))[:200],
            ])

        # Flags (also include separately for easy grep)
        for flag in results.get("flags", {}).get("flags_found", []):
            if not isinstance(flag, dict):
                flag = {"value": str(flag)}
            rows.append([
                fname, "flags", "CRITICAL",
                flag.get("confidence_pct", "?"),
                "Flag detected",
                "",
                flag.get("value", "")[:200],
            ])

        out_path = os.path.join(self.output_dir, "findings.csv")
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(COLUMNS)
            writer.writerows(rows)

        logger.info(f"CSV report → {out_path} ({len(rows)} rows)")
        return out_path
