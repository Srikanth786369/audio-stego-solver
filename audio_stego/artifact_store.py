"""
Artifact directory manager for Audio Stego Solver.

Structured output layout (v5.0):

results/<stem>/
├── report.html          ← Primary interface
├── report.json          ← Machine-readable
├── report.txt            ← Quick text summary
├── metadata.txt
├── flags.txt
├── logs/
│   └── run.log
├── images/                waveform.png, spectrogram.png, fft.png
├── sstv/                  decoded_best.png, decoded_variants/, debug/
├── text/                  ocr.txt, qr.txt
├── tools/                  raw tool output (ffprobe, exiftool, binwalk, ...)
├── evidence/               audio-forensics text dumps (internal — not
│                            surfaced in the report, kept for analysts who
│                            want the raw numbers)
├── extracted/              carved files (binwalk/foremost/scalpel/...)
├── hidden_files/           contents of extracted archives
└── plugins/                per-plugin output
"""

from __future__ import annotations

from pathlib import Path


class ArtifactStore:
    """
    Centralised path resolver for the organised output directory.
    All modules should use this instead of building paths manually.
    """

    def __init__(self, base: str):
        self.base = Path(base)
        self._create_tree()

    # ------------------------------------------------------------------
    # Top-level paths
    # ------------------------------------------------------------------

    @property
    def report_html(self) -> Path:
        return self.base / "report.html"

    # ------------------------------------------------------------------
    # Images (waveform / spectrogram / FFT plots)
    # ------------------------------------------------------------------

    @property
    def images(self) -> Path:
        return self.base / "images"

    # ------------------------------------------------------------------
    # SSTV
    # ------------------------------------------------------------------

    @property
    def sstv_dir(self) -> Path:
        return self.base / "sstv"

    @property
    def sstv_debug(self) -> Path:
        """Sync-timing overlays and pre-validation raw decodes — kept
        separate from sstv_dir so only accepted images clutter the main
        sstv/ dir; debug/ always gets the attempt regardless of outcome."""
        return self.sstv_dir / "debug"

    @property
    def sstv_variants(self) -> Path:
        """Every post-processing candidate image generated for a single
        SSTV decode."""
        return self.sstv_dir / "decoded_variants"

    # ------------------------------------------------------------------
    # Text (general-purpose OCR/QR output, not tied to a specific tool)
    # ------------------------------------------------------------------

    @property
    def text_dir(self) -> Path:
        return self.base / "text"

    # ------------------------------------------------------------------
    # Tools (raw captured tool output — read back verbatim by the HTML
    # report's Tools Used section)
    # ------------------------------------------------------------------

    @property
    def tools(self) -> Path:
        return self.base / "tools"

    # ------------------------------------------------------------------
    # Evidence (audio-forensics raw text dumps — internal, not part of
    # the curated top-level layout, but real writers exist for these)
    # ------------------------------------------------------------------

    @property
    def evidence(self) -> Path:
        return self.base / "evidence"

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    @property
    def logs(self) -> Path:
        return self.base / "logs"

    # ------------------------------------------------------------------
    # Plugins
    # ------------------------------------------------------------------

    @property
    def plugins(self) -> Path:
        return self.base / "plugins"

    # ------------------------------------------------------------------
    # Extraction (binwalk/foremost carved files)
    # ------------------------------------------------------------------

    @property
    def extracted(self) -> Path:
        return self.base / "extracted"

    @property
    def hidden_files(self) -> Path:
        return self.base / "hidden_files"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def mkdir(self, path: Path) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ------------------------------------------------------------------
    # Compatibility shim for legacy code that uses output_dir directly
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return str(self.base)

    def __fspath__(self) -> str:
        return str(self.base)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _create_tree(self):
        """Create all directories upfront."""
        dirs = [
            self.base,
            self.images,
            self.sstv_dir,
            self.sstv_debug,
            self.sstv_variants,
            self.text_dir,
            self.tools,
            self.evidence,
            self.logs,
            self.plugins,
            self.extracted,
            self.hidden_files,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    def summary(self) -> dict:
        """Return a dict of path → exists for debugging."""
        return {str(d): d.exists() for d in [
            self.base, self.tools, self.evidence, self.logs
        ]}
