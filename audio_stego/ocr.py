"""
OCR and QR code detection module for Audio Stego Solver.

FIXED (v1.1):
  - tesseract now called ONCE per image (with --psm 6 + tsv) instead of 3 times
  - Minimum confidence threshold filters garbage OCR on noise
  - Minimum character count threshold filters near-empty results
  - _find_images: deduplication prevents same image appearing twice
  - Blank / whitespace-only text is filtered before reporting

TIGHTENED (v4.3): the confidence floor was 40% despite this docstring long
claiming a 60% default — actually measured against noise/spectrogram OCR
output, 40% let through enough garbage words to be a real false-positive
source. Raised to 55%, a middle ground that still accepts genuinely noisy
but real text (low-res or JPEG-artifacted screenshots) while rejecting the
near-random low-30s/40s-percent word confidence common on pure noise.
"""

import os
from typing import Any, Dict, List, Optional, Set

from .findings import Finding, Severity
from .logger import get_logger
from .utils import recursive_file_search, run_command, save_text, tool_available

logger = get_logger("audio_stego.ocr")

# Minimum average Tesseract word confidence to accept OCR output
_MIN_OCR_CONFIDENCE = 55.0   # percent (0–100) — see module docstring, v4.3
# Minimum printable characters in OCR output to be reportable
_MIN_OCR_CHARS = 5


class OCRAnalyzer:
    """Performs OCR and QR code detection on images in the output directory."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.images_dir = os.path.join(output_dir, "images")
        self.text_dir = os.path.join(output_dir, "text")
        os.makedirs(self.text_dir, exist_ok=True)
        self.results: Dict[str, Any] = {
            "ocr": [],
            "qr_codes": [],
            "warnings": [],
            "findings": [],
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audio_path: str) -> Dict[str, Any]:
        """Run OCR and QR detection on all images in the output directory."""
        logger.info("Starting OCR and QR analysis")
        image_paths = self._find_images()
        if not image_paths:
            logger.info("No images found for OCR/QR analysis")
            return self.results
        logger.info(f"Found {len(image_paths)} image(s) to analyse")

        if self.config.getbool("analysis", "run_ocr", True):
            self._run_ocr_on_images(image_paths)
        if self.config.getbool("analysis", "run_qr", True):
            self._run_qr_on_images(image_paths)

        logger.info("OCR and QR analysis complete")
        return self.results

    # ------------------------------------------------------------------
    # Image discovery (FIXED: proper deduplication)
    # ------------------------------------------------------------------

    # v4.1: filenames visual.py itself generates as diagnostic plots
    # (spectrogram/waveform/FFT, incl. the ffmpeg-fallback variants). These
    # are internally generated visualizations of the raw signal, not images
    # that could plausibly contain hidden text/QR/barcodes — OCR-ing them
    # only produces noise from axis labels/titles ("Spectrogram (Left)",
    # frequency axis numbers, etc.), never a real finding. Extracted or
    # SSTV-decoded images are never named these exact filenames, so an
    # exact-match denylist cannot accidentally skip real evidence.
    _GENERATED_PLOT_NAMES = {
        "spectrogram.png", "spectrogram_ffmpeg.png",
        "waveform.png", "waveform_ffmpeg.png",
        "fft.png",
    }

    def _find_images(self) -> List[str]:
        """Find all image files — deduplicated by resolved path, excluding
        this project's own internally-generated waveform/spectrogram/FFT
        plots (see _GENERATED_PLOT_NAMES)."""
        extensions = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".tif", ".webp"}
        seen_paths: Set[str] = set()
        images: List[str] = []

        search_dirs = [
            self.images_dir,
            self.output_dir,
            os.path.join(self.output_dir, "extracted"),
            os.path.join(self.output_dir, "hidden_files"),
        ]

        for directory in search_dirs:
            if not os.path.exists(directory):
                continue
            # Top-level files in output_dir only (not recursive for root)
            if directory == self.output_dir:
                candidates = [
                    os.path.join(directory, f)
                    for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f))
                ]
            else:
                candidates = recursive_file_search(directory)

            for fpath in candidates:
                if os.path.splitext(fpath)[1].lower() not in extensions:
                    continue
                if os.path.basename(fpath) in self._GENERATED_PLOT_NAMES:
                    continue
                resolved = os.path.realpath(fpath)
                if resolved not in seen_paths:
                    seen_paths.add(resolved)
                    images.append(fpath)

        return images

    # ------------------------------------------------------------------
    # OCR (FIXED: single tesseract call + confidence threshold)
    # ------------------------------------------------------------------

    def _run_ocr_on_images(self, image_paths: List[str]):
        """Run Tesseract OCR on each image with confidence filtering."""
        if not tool_available("tesseract"):
            self.results["warnings"].append("Tool not found: tesseract")
            return

        all_results: List[Dict] = []
        for img_path in image_paths:
            result = self._ocr_image(img_path)
            if result:
                all_results.append(result)

        self.results["ocr"] = all_results

        if all_results:
            lines = ["=== OCR RESULTS ==="]
            for r in all_results:
                lines.append(f"\nImage: {r['image']}")
                lines.append(f"Confidence: {r.get('confidence', 0):.1f}%  |  Chars: {len(r['text'])}")
                lines.append(r["text"][:2000])

            out_path = os.path.join(self.text_dir, "ocr.txt")
            save_text(out_path, "\n".join(lines))
            logger.info(f"OCR: {len(all_results)} image(s) with usable text → {out_path}")
        else:
            save_text(
                os.path.join(self.text_dir, "ocr.txt"),
                "=== OCR RESULTS ===\n"
                f"Status: No usable text found "
                f"(threshold: confidence>{_MIN_OCR_CONFIDENCE}%, chars>{_MIN_OCR_CHARS})\n",
            )

    def _ocr_image(self, img_path: str) -> Optional[Dict]:
        """
        Run OCR on a single image.

        FIXED: Single tesseract call with TSV output for text + confidence.
        Previous code ran 3 separate tesseract calls per image.
        Returns None if confidence < threshold or too little text.
        """
        # One call: psm 6 (uniform block) + tsv for word-level confidence
        rc, tsv_out, err = run_command(
            ["tesseract", img_path, "stdout", "--psm", "6", "tsv"],
            timeout=30,
        )
        if rc != 0 or not tsv_out.strip():
            return None

        # Parse TSV: columns are level, page, block, par, line, word, left, top, width, height, conf, text
        text_parts: List[str] = []
        confidences: List[float] = []

        for line in tsv_out.splitlines()[1:]:   # skip header
            cols = line.split("\t")
            if len(cols) < 12:
                continue
            try:
                conf = float(cols[10])
                word = cols[11].strip()
            except (ValueError, IndexError):
                continue
            if conf < 0:   # -1 means invalid
                continue
            confidences.append(conf)
            if word:
                text_parts.append(word)

        if not text_parts:
            return None

        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        text = " ".join(text_parts)

        # Filter: too low confidence
        if avg_conf < _MIN_OCR_CONFIDENCE:
            logger.debug(
                f"OCR {os.path.basename(img_path)}: "
                f"confidence {avg_conf:.1f}% < {_MIN_OCR_CONFIDENCE}% threshold — skip"
            )
            return None

        # Filter: too little text
        printable = sum(1 for c in text if 0x20 <= ord(c) < 0x7F)
        if printable < _MIN_OCR_CHARS:
            logger.debug(
                f"OCR {os.path.basename(img_path)}: "
                f"only {printable} printable chars — skip"
            )
            return None

        logger.info(
            f"OCR {os.path.basename(img_path)}: "
            f"{len(text)} chars, confidence={avg_conf:.1f}%"
        )

        result = {
            "image": img_path,
            "text": text,
            "confidence": avg_conf,
        }

        # Record as Finding if confidence is high
        if avg_conf >= 70.0 and printable >= 10:
            f = Finding(
                module="ocr",
                title="Text Found via OCR",
                severity=Severity.MEDIUM,
                confidence=avg_conf / 100.0,
                value=text[:300],
                evidence=f"Image: {os.path.basename(img_path)}, {len(text)} chars",
                reason=f"Tesseract avg confidence {avg_conf:.1f}%",
                false_positive_risk="Low for high-confidence results; spectrogram text may be label artifacts",
            )
            self.results["findings"].append(f.to_dict())

        return result

    # ------------------------------------------------------------------
    # QR detection
    # ------------------------------------------------------------------

    def _run_qr_on_images(self, image_paths: List[str]):
        """Run zbarimg to detect QR codes and barcodes."""
        if not tool_available("zbarimg"):
            self.results["warnings"].append("Tool not found: zbarimg")
            return

        all_qr: List[Dict] = []
        for img_path in image_paths:
            all_qr.extend(self._detect_qr(img_path))

        self.results["qr_codes"] = all_qr

        if all_qr:
            lines = ["=== QR / BARCODE RESULTS ==="]
            for r in all_qr:
                lines.append(f"\nImage: {r['image']}")
                lines.append(f"Type : {r.get('type', 'unknown')}")
                lines.append(f"Data : {r.get('data', '')}")

            out_path = os.path.join(self.text_dir, "qr.txt")
            save_text(out_path, "\n".join(lines))
            logger.info(f"QR/barcode: {len(all_qr)} result(s) → {out_path}")

            f = Finding(
                module="ocr",
                title="QR / Barcode Data Found",
                severity=Severity.HIGH,
                confidence=0.99,
                value="\n".join(r.get("data", "")[:100] for r in all_qr[:3]),
                evidence=f"{len(all_qr)} QR/barcode(s) decoded by zbarimg",
                reason="zbarimg reliably decodes standard QR and barcodes",
                false_positive_risk="Very low",
            )
            self.results["findings"].append(f.to_dict())
        else:
            save_text(
                os.path.join(self.text_dir, "qr.txt"),
                "=== QR / BARCODE RESULTS ===\nStatus: No QR codes or barcodes detected.\n",
            )

    def _detect_qr(self, img_path: str) -> List[Dict]:
        """Detect QR/barcodes in a single image using zbarimg."""
        results: List[Dict] = []

        rc, out, err = run_command(
            ["zbarimg", img_path],   # TYPE:DATA format
            timeout=20,
        )
        if rc != 0 or not out.strip():
            return results

        seen_data: Set[str] = set()
        for line in out.strip().splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2:
                qr_type, data = parts[0].strip(), parts[1].strip()
                if data and data not in seen_data:
                    seen_data.add(data)
                    results.append({"image": img_path, "type": qr_type, "data": data})
                    logger.info(f"QR [{qr_type}] in {os.path.basename(img_path)}: {data[:80]}")

        return results

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def get_all_text(self) -> str:
        """Get all OCR text and QR data concatenated for flag searching."""
        parts: List[str] = []
        for r in self.results.get("ocr", []):
            parts.append(r.get("text", ""))
        for r in self.results.get("qr_codes", []):
            parts.append(r.get("data", ""))
        return "\n".join(parts)
