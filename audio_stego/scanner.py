"""
Main scanner orchestrator for Audio Stego Solver v3.

Changes from v1.1:
  - Uses ArtifactStore for organised output directory
  - Integrates AudioForensicsAnalyzer and SSTVAnalyzer
  - Integrates updated ExtractionAnalyzer (structured ExtractionRecord)
  - Single continuous Rich progress bar
  - Plugin results merged into all_results cleanly
  - self._binary_analyzer stored on self (NameError fix retained)
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from .artifact_store import ArtifactStore
from .audio_forensics import AudioForensicsAnalyzer
from .binary import BinaryAnalyzer
from .config import Config
from .digital import DigitalModesAnalyzer
from .extraction import ExtractionAnalyzer
from .flags import FlagDetector
from .logger import get_logger, setup_logger
from .metadata import MetadataAnalyzer
from .ocr import OCRAnalyzer
from .report import ReportGenerator
from .sstv import SSTVAnalyzer
from .utils import elapsed, human_size, tool_available
from .visual import VisualAnalyzer

logger = get_logger("audio_stego.scanner")

SUPPORTED_FORMATS = {
    ".wav", ".mp3", ".flac", ".ogg", ".aac",
    ".m4a", ".au", ".aiff", ".wma",
}

STEPS = [
    "Metadata", "Binary analysis", "Visual + forensics",
    "Extraction", "SSTV", "Digital modes", "OCR",
    "Flag sweep", "Reports",
]


class AudioStegoScanner:
    """Orchestrates all analysis modules against a single audio file."""

    def __init__(self, config: Config, console: Optional[Console] = None):
        self.config  = config
        self.console = console or Console()
        self.start_time = time.time()
        self.all_results: Dict[str, Any] = {}
        self._binary_analyzer: Optional[BinaryAnalyzer] = None
        self._extraction_analyzer: Optional[ExtractionAnalyzer] = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self, audio_path: str) -> Dict[str, Any]:
        audio_path = os.path.abspath(audio_path)
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"File not found: {audio_path}")

        ext = Path(audio_path).suffix.lower()
        if ext not in SUPPORTED_FORMATS:
            self.console.print(
                f"[yellow]Warning: '{ext}' not in supported list "
                f"({', '.join(sorted(SUPPORTED_FORMATS))})[/yellow]"
            )

        store = self._setup_store(audio_path)
        setup_logger(
            log_dir=str(store.logs),
            log_file=self.config.log_file,
            verbose=self.config.verbose,
        )
        logger.info(f"Scan start: {audio_path}")
        logger.info(f"Output: {store.base}")

        self._print_banner(audio_path, store)
        self._run_pipeline(audio_path, store)
        self._check_tools()

        elapsed_time = time.time() - self.start_time

        # Text report
        try:
            rg = ReportGenerator(self.config, str(store))
            rg.generate(audio_path, self.all_results, elapsed_time)
        except Exception as e:
            logger.error(f"Text report error: {e}")

        # Hint engine — runs before HTML report generation (v4.3) so its
        # "what to investigate manually" output can be surfaced in the
        # report's own Manual Investigation section instead of only living
        # in a separate hints.txt file the analyst has to know to open.
        try:
            from .hint_engine import HintEngine
            self.all_results["hints"] = HintEngine(str(store)).analyze(audio_path, self.all_results)
        except Exception as e:
            logger.error(f"Hint engine error: {e}")

        # HTML + JSON + CSV reports
        try:
            from .html_report import HTMLReport
            HTMLReport(store).generate(audio_path, self.all_results, elapsed_time)
        except Exception as e:
            logger.error(f"HTML report error: {e}")
            self.console.print(f"[yellow]HTML report warning: {e}[/yellow]")

        try:
            from .reports_ext import JSONReportGenerator, CSVReportGenerator
            JSONReportGenerator(str(store)).generate(audio_path, self.all_results, elapsed_time)
            CSVReportGenerator(str(store)).generate(audio_path, self.all_results, elapsed_time)
        except Exception as e:
            logger.error(f"JSON/CSV report error: {e}")

        self._print_summary(str(store.report_html))
        return self.all_results

    # ------------------------------------------------------------------
    # Store setup
    # ------------------------------------------------------------------

    def _setup_store(self, audio_path: str) -> ArtifactStore:
        stem = Path(audio_path).stem
        base = Path(self.config.output_dir) / stem
        return ArtifactStore(str(base))

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def _run_pipeline(self, audio_path: str, store: ArtifactStore):
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(), TaskProgressColumn(),
            MofNCompleteColumn(), TimeElapsedColumn(),
            console=self.console, expand=True,
        )

        phase_timings: List[Dict[str, Any]] = []
        checkpoint = time.time()

        with progress:
            task = progress.add_task("Scanning…", total=len(STEPS))

            def advance(label: str):
                nonlocal checkpoint
                now = time.time()
                phase_timings.append({"phase": label, "seconds": round(now - checkpoint, 3)})
                checkpoint = now
                progress.update(task, description=f"[cyan]{label}…")
                progress.advance(task)

            # 1 — Metadata
            meta = MetadataAnalyzer(self.config, str(store))
            mr   = meta.run(audio_path)
            mr["interesting_tags"] = meta.get_interesting_tags()
            self.all_results["metadata"] = mr
            advance("Metadata")

            # 2 — Binary
            self._binary_analyzer = BinaryAnalyzer(self.config, str(store))
            self.all_results["binary"] = self._binary_analyzer.run(audio_path)
            advance("Binary analysis")

            # 3 — Visual + audio forensics (parallel)
            with ThreadPoolExecutor(max_workers=2) as ex:
                fv = ex.submit(VisualAnalyzer(self.config, str(store)).run, audio_path)
                ff = ex.submit(AudioForensicsAnalyzer(store).run, audio_path)
                self.all_results["visual"]    = fv.result()
                self.all_results["forensics"] = ff.result()
            advance("Visual + forensics")

            # 4 — Extraction
            self._extraction_analyzer = ExtractionAnalyzer(self.config, store)
            self.all_results["extraction"] = self._extraction_analyzer.run(audio_path)
            advance("Extraction")

            # 5 — Digital modes + OCR (parallel). Runs before SSTV specifically
            # so SSTV can reuse the WAV conversion DigitalModesAnalyzer already
            # does (_wav_path) instead of loading the raw file a second time —
            # previously SSTV ran *before* this step, so all_results["digital"]
            # was always still empty and wav_path was always None.
            with ThreadPoolExecutor(max_workers=2) as ex:
                fd = ex.submit(DigitalModesAnalyzer(self.config, str(store)).run, audio_path)
                fo = ex.submit(OCRAnalyzer(self.config, str(store)).run, audio_path)
                self.all_results["digital"] = fd.result()
                self.all_results["ocr"]     = fo.result()
            advance("Digital modes + OCR")
            advance("OCR")  # counted separately in STEPS

            # 6 — SSTV
            if self.config.getbool("analysis", "run_sstv", True):
                wav_path = self.all_results.get("digital", {}).get("_wav_path")
                self.all_results["sstv"] = SSTVAnalyzer(store, self.config).run(
                    audio_path, wav_path
                )
            advance("SSTV")

            # 7 — Flag sweep
            extra = self._collect_extra_text()
            fd_det = FlagDetector(self.config, str(store))
            self.all_results["flags"] = fd_det.run(extra)
            # Cipher analysis on binary strings
            if self._binary_analyzer:
                strings = self.all_results.get("binary", {}).get("strings", [])
                if strings:
                    cipher_extra = self._binary_analyzer.detect_ciphers(
                        "\n".join(strings[:200])
                    )
                    if cipher_extra:
                        self.all_results["flags"].setdefault(
                            "cipher_results", {}
                        ).update(cipher_extra)
            advance("Flag sweep")

            # 7b — Recursive analysis engine (Phase 7): decode base64/hex found
            # in OCR text / digital-mode output / gathered flag-scan text,
            # validate through the same unified extraction pipeline, extract
            # anything that turns out to be a container, and re-check for flags.
            self._run_recursive_analysis(audio_path, store, extra)

            # 8 — Plugins
            if self.config.getbool("analysis", "run_plugins", True):
                try:
                    from .plugins.manager import PluginManager
                    pm = PluginManager(self.config)
                    # PluginManager.run_all() appends its own "plugins"
                    # subdir onto whatever directory it's given — pass the
                    # scan's base dir, not store.plugins itself, or plugin
                    # output ends up double-nested at plugins/plugins/.
                    plugin_results = pm.run_all(
                        audio_path, str(store.base), self.all_results
                    )
                    self.all_results["plugins"] = plugin_results
                except Exception as e:
                    logger.error(f"Plugin error: {e}")
            advance("Reports")

        self.all_results.setdefault("_performance", {})["phases"] = phase_timings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_recursive_analysis(self, audio_path: str, store: ArtifactStore, extra_text: str):
        """Phase 7 — see RecursiveAnalysisEngine docstring. Failures here must
        never abort the scan; this is best-effort enrichment of results
        already produced by the required pipeline phases."""
        if self._extraction_analyzer is None:
            return
        try:
            from .recursive_engine import RecursiveAnalysisEngine
            ocr_text = "\n".join(
                r.get("text", "") for r in self.all_results.get("ocr", {}).get("ocr", [])
            )
            seed_text = "\n".join(filter(None, [extra_text, ocr_text]))
            if not seed_text.strip():
                return

            engine = RecursiveAnalysisEngine(self.config, store, self._extraction_analyzer)
            rec_results = engine.run(seed_text)
            self.all_results["recursive"] = {
                "passes": rec_results["passes"],
                "decoded_artifact_count": len(rec_results["decoded_artifacts"]),
            }

            if rec_results["new_flags"]:
                existing = {f.get("value") for f in self.all_results["flags"].get("flags_found", [])}
                for f in rec_results["new_flags"]:
                    if f.get("value") not in existing:
                        self.all_results["flags"].setdefault("flags_found", []).append(f)
                        existing.add(f.get("value"))
                logger.info(f"Recursive analysis found {len(rec_results['new_flags'])} additional flag candidate(s)")

            # Refresh extraction summary counts — the recursive engine appended
            # new records directly onto the same ExtractionAnalyzer instance.
            self._extraction_analyzer._collect_all()
            self._extraction_analyzer._update_summary()

            # Anything newly extracted may include images the first OCR pass
            # never saw; a second OCR pass is cheap when there's nothing new.
            if rec_results["decoded_artifacts"]:
                try:
                    ocr_rerun = OCRAnalyzer(self.config, str(store)).run(audio_path)
                    if ocr_rerun.get("ocr") or ocr_rerun.get("qr_codes"):
                        self.all_results["ocr"] = ocr_rerun
                except Exception as e:
                    logger.error(f"Recursive analysis OCR re-run error: {e}")
        except Exception as e:
            logger.error(f"Recursive analysis engine error: {e}")

    def _collect_extra_text(self) -> str:
        parts: List[str] = []
        for r in self.all_results.get("ocr", {}).get("ocr", []):
            parts.append(r.get("text", ""))
        for r in self.all_results.get("ocr", {}).get("qr_codes", []):
            parts.append(r.get("data", ""))
        for m in self.all_results.get("digital", {}).get("morse", []):
            parts.append(m.get("value", ""))
        for d in self.all_results.get("digital", {}).get("dtmf", []):
            parts.append(d.get("value", ""))
        for item in self.all_results.get("binary", {}).get(
            "encoded_data", {}
        ).get("base64_decoded", []):
            parts.append(item.get("decoded", ""))
        sstv = self.all_results.get("sstv", {})
        if sstv.get("ocr_text"):
            parts.append(sstv["ocr_text"])
        if sstv.get("qr_data"):
            parts.append(sstv["qr_data"])
        return "\n".join(parts)

    # Tools unconditionally used by the core pipeline regardless of config
    # (metadata/binary/strings analysis always runs).
    _CORE_TOOLS = ["file", "exiftool", "mediainfo", "ffprobe", "ffmpeg",
                   "strings", "hexdump"]

    # Optional tools, each gated on the [analysis] config flag that actually
    # controls whether the pipeline step that could invoke it runs. A tool
    # not gated behind any config flag it's genuinely tied to (e.g. `sox`,
    # never invoked anywhere in this codebase, or the old blanket `rx_sstv`
    # check that ran regardless of whether SSTV analysis was even enabled)
    # is not shown at all — "optional tools should not appear as missing
    # unless they are enabled in the configuration."
    _OPTIONAL_TOOLS = [
        ("binwalk",      "run_binwalk"),
        ("foremost",     "run_foremost"),
        ("scalpel",      "run_scalpel"),
        ("steghide",     "run_steghide"),
        ("stegseek",     "run_stegseek"),
        ("tesseract",    "run_ocr"),
        ("zbarimg",      "run_qr"),
        ("multimon-ng",  "run_multimon"),
        ("minimodem",    "run_minimodem"),
        ("rx_sstv",      "run_sstv"),
    ]

    def _check_tools(self):
        """Runs after the pipeline, not before — 'executed' should mean
        what actually happened this scan, not a pre-flight PATH check.
        Only tools that are present (and therefore could run) are listed;
        a missing tool is simply omitted, never shown as "not found" here
        (that noise is exactly what the CTF report redesign removed from
        the HTML report too — see _is_tool_availability_noise)."""
        tools = list(self._CORE_TOOLS)
        for tool_name, flag in self._OPTIONAL_TOOLS:
            if self.config.getbool("analysis", flag, True):
                tools.append(tool_name)

        availability = {t: tool_available(t) for t in tools}
        self.all_results.setdefault("_performance", {})["tool_availability"] = availability

        executed = [t for t, ok in availability.items() if ok]
        if not executed:
            return
        table = Table(title="Tools Executed", header_style="bold cyan")
        table.add_column("Tool", style="cyan")
        table.add_column("Status")
        for t in executed:
            table.add_row(t, "[green]✓[/green]")
        self.console.print(table)

    def _print_banner(self, audio_path: str, store: ArtifactStore):
        t = Text()
        t.append("Audio Stego Solver v3\n", style="bold cyan")
        t.append(f"File   : {audio_path}\n",    style="white")
        t.append(f"Size   : {human_size(os.path.getsize(audio_path))}\n", style="white")
        t.append(f"Output : {store.base}\n",     style="white")
        self.console.print(Panel(
            t, title="[bold green]Starting Analysis[/bold green]",
            border_style="green",
        ))

    def _overall_confidence(self) -> float:
        """Same 'strongest real signal' definition html_report.py uses for
        its Executive Summary — kept independent (not imported) since this
        is a small, self-contained computation and html_report's helpers
        are private to that module."""
        all_f: List[Dict] = []
        for key in ("binary", "digital", "visual", "forensics", "ocr",
                    "extraction", "flags", "sstv"):
            sec = self.all_results.get(key, {})
            if isinstance(sec, dict):
                all_f.extend(sec.get("findings", []))
        conf = max((f.get("confidence", 0) for f in all_f if isinstance(f, dict)), default=0.0)
        flags = self.all_results.get("flags", {}).get("flags_found", [])
        if flags:
            conf = max(conf, max((f.get("confidence", 0) for f in flags if isinstance(f, dict)), default=0.0))
        return conf

    def _print_summary(self, report_path: str):
        flags = self.all_results.get("flags", {}).get("flags_found", [])

        # CTF-facing summary (v5.0): no extraction/rejection/false-positive
        # counters here either — a clean scan reads "Analysis Completed
        # Successfully", not a table of internal accounting a player can't
        # act on. Mirrors the same statistics removed from the HTML report.
        summary = Table(title="Analysis Complete", show_header=False, box=None)
        summary.add_column("Key",   style="cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Status",   "[bold green]Analysis Completed Successfully[/bold green]")
        summary.add_row("Duration", elapsed(self.start_time))
        summary.add_row("Report",   report_path)
        summary.add_row("Overall Confidence", f"{self._overall_confidence()*100:.0f}%")

        if flags:
            ft = Text()
            ft.append(f"[!!!] {len(flags)} FLAG(S) FOUND!", style="bold red on white")
            for f in flags[:3]:
                val = f.get("value", str(f)) if isinstance(f, dict) else str(f)
                ft.append(f"\n  {val}", style="bold green")
            summary.add_row("Flags Found", ft)
        else:
            summary.add_row("Flags Found", "[yellow]0[/yellow]")

        # Regression: the filter condition below used to be
        # `digital.get(key) or vis_detected` applied identically to every
        # (label, key) pair — since `vis_detected` doesn't depend on which
        # pair is being checked, whenever SSTV's VIS was detected, ALL FOUR
        # labels (Morse/DTMF/Minimodem/SSTV) were listed as "Signals" even
        # when Morse/DTMF/Minimodem had each independently found nothing
        # (`digital["morse"] == []` etc.) — found by running the full
        # pipeline against a real MP3 file where this showed "Signals:
        # Morse, DTMF, Minimodem, SSTV" while report.json's morse/dtmf/
        # minimodem fields were all empty lists. Each label must be gated
        # only by its own actual result.
        digital  = self.all_results.get("digital", {})
        vis_detected = self.all_results.get("sstv", {}).get("vis_detected")
        signals  = [lbl for lbl, found in [
            ("Morse", bool(digital.get("morse"))),
            ("DTMF", bool(digital.get("dtmf"))),
            ("Minimodem", bool(digital.get("minimodem"))),
            ("SSTV", bool(vis_detected)),
        ] if found]
        summary.add_row("Signals Found", ", ".join(signals) if signals else "None")

        qr = len(self.all_results.get("ocr", {}).get("qr_codes", []))
        if qr:
            summary.add_row("QR codes", f"[bold green]{qr} found![/bold green]")

        self.console.print("\n")
        self.console.print(Panel(
            summary,
            title="[bold green]Results Summary[/bold green]",
            border_style="green" if flags else "yellow",
        ))
        self.console.print(f"\n[bold]Report:[/bold] {report_path}")
