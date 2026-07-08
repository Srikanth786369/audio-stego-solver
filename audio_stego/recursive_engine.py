"""
Recursive analysis engine for Audio Stego Solver (Phase 7).

The extraction pipeline (extraction.py) already recurses through nested
*binary* containers (archive inside archive, etc.). The gap this module
closes is text-borne nesting: a chain like

    audio.wav -> ZIP -> PNG -> OCR text -> Base64 -> ZIP -> PDF -> Flag

requires decoding text discovered by OCR/digital-mode/flag analysis, feeding
the decoded bytes back through the *same* unified evidence pipeline
(SHA256 dedup -> detect type -> validate -> confidence -> status), extracting
anything that turns out to be a container, and re-scanning the result for
more encoded data or flags — repeating until nothing new turns up.

Stop conditions (matching extraction.py's recursion):
  - maximum recursion depth (_MAX_RECURSION_DEPTH, shared with extraction.py)
  - duplicate SHA256 (shared _artifact_index on the ExtractionAnalyzer — a
    payload already seen, by decode or by tool, is never processed twice)
  - size limit (payloads are bounded before being written to disk)
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict, List, Set

from .encoding_engine import decode_all as decode_all_schemes
from .extraction import ExtractionAnalyzer, ExtractionStatus, _MAX_RECURSION_DEPTH
from .findings import find_flags_in_text, is_likely_base64
from .logger import get_logger
from .utils import FILE_MAGIC, recursive_file_search, save_bytes
from .validate import MAGIC_BACK_OFFSET

logger = get_logger("audio_stego.recursive_engine")

_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")

_MAX_TEXT_SCAN = 500_000       # bytes of text considered per pass
_MAX_CANDIDATE_BYTES = 20_000_000

# extraction._extract_archive() dispatches purely on file extension; decoded
# payloads are written out as "<sha>.bin" with no extension of their own, so
# a validated container must be renamed before _extract_archive can see it.
_ARCHIVE_EXT = {
    "ZIP": ".zip", "DOCX": ".zip", "XLSX": ".zip", "PPTX": ".zip",
    "RAR": ".rar", "RAR4": ".rar", "RAR5": ".rar", "7Z": ".7z",
    "TAR": ".tar", "GZIP": ".gz", "TAR_GZ": ".gz",
    "BZIP2": ".bz2", "TAR_BZ2": ".bz2", "XZ": ".xz",
}


def _looks_like_known_magic(raw: bytes) -> bool:
    for name, magic in FILE_MAGIC.items():
        off = MAGIC_BACK_OFFSET.get(name, 0)
        if raw[off:off + len(magic)] == magic:
            return True
    return False


class RecursiveAnalysisEngine:
    """
    Decodes base64/hex candidates out of already-gathered text, validates the
    decoded bytes through the extraction analyzer's unified pipeline,
    extracts anything that validates as a container, and re-scans anything
    newly produced for further encoded data or flags.
    """

    def __init__(self, config, store, extraction_analyzer: ExtractionAnalyzer):
        self.config = config
        self.store = store
        self.extraction = extraction_analyzer
        self._scanned_paths: Set[str] = set()   # Phase 13: avoid re-reading files across passes
        self.results: Dict[str, Any] = {
            "decoded_artifacts": [],   # List[ExtractionRecord] surfaced by decoding
            "new_flags": [],           # List[dict] — Finding.to_dict()
            "passes": 0,
        }

    def run(self, seed_text: str, max_passes: int = _MAX_RECURSION_DEPTH) -> Dict[str, Any]:
        text = (seed_text or "")[:_MAX_TEXT_SCAN]
        depth = 0
        while text and depth < max_passes:
            produced_new = self._one_pass(text, depth)
            self.results["passes"] = depth + 1
            if not produced_new:
                break
            text = self._collect_text_from_new_artifacts()[:_MAX_TEXT_SCAN]
            depth += 1
        return self.results

    # ------------------------------------------------------------------
    # One decode pass
    # ------------------------------------------------------------------

    def _one_pass(self, text: str, depth: int) -> bool:
        new_any = False
        seen_candidates: Set[str] = set()

        for candidate in _B64_RE.findall(text) + _HEX_RE.findall(text):
            if candidate in seen_candidates:
                continue
            seen_candidates.add(candidate)

            # Direct binary decode first — needed for non-text payloads
            # (archives, images) that Phase 8's text-only scheme sweep below
            # would garble by round-tripping through str decode/encode.
            raw = None
            if is_likely_base64(candidate):
                raw = self._decode_b64(candidate)
            raw = raw or self._decode_hex(candidate)
            if raw and self._process_decoded_bytes(raw, candidate, depth):
                new_any = True

            # Broader scheme sweep (Phase 8 encoding_engine): the same
            # candidate substring might also be Base32/45/58/62/85/rot13/
            # atbash/caesar/affine/rail-fence rather than base64/hex —
            # reuses encoding_engine as the single source of truth instead
            # of duplicating per-scheme decode logic here.
            for hit in decode_all_schemes(candidate):
                hit_bytes = hit.output.encode("utf-8", errors="ignore")
                if hit_bytes and self._process_decoded_bytes(hit_bytes, candidate, depth):
                    new_any = True

        return new_any

    @staticmethod
    def _decode_b64(candidate: str):
        try:
            raw = base64.b64decode(candidate + "==")
            return raw if 8 <= len(raw) <= _MAX_CANDIDATE_BYTES else None
        except Exception:
            return None

    @staticmethod
    def _decode_hex(candidate: str):
        try:
            raw = bytes.fromhex(candidate)
        except Exception:
            return None
        if not (8 <= len(raw) <= _MAX_CANDIDATE_BYTES):
            return None
        printable = sum(1 for b in raw if 0x20 <= b < 0x7F or b in (9, 10, 13))
        if printable / len(raw) < 0.5 and not _looks_like_known_magic(raw):
            return None
        return raw

    def _process_decoded_bytes(self, raw: bytes, candidate: str, depth: int) -> bool:
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        if sha in self.extraction._artifact_index:
            return False   # already seen this exact payload — no new ground covered

        out_dir = self.store.extracted / "decoded"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = str(out_dir / f"decoded_{sha[:16]}.bin")
        save_bytes(out_path, raw)

        rec = self.extraction._process_tool_artifact(
            out_path, "recursive_decode", parent_sha256=None, depth=depth + 1,
        )
        if rec is None:
            return False
        self.results["decoded_artifacts"].append(rec)

        try:
            decoded_text = raw.decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""
        if decoded_text:
            for f in find_flags_in_text(decoded_text, source=f"recursive decode ('{candidate[:24]}...')"):
                self.results["new_flags"].append(f.to_dict())

        if rec.status == ExtractionStatus.NESTED:
            extract_path = self._ensure_archive_extension(out_path, rec)
            self.extraction._extract_archive(extract_path)
            return True
        return rec.status in (
            ExtractionStatus.VERIFIED, ExtractionStatus.RECOVERED, ExtractionStatus.PARTIAL,
        )

    @staticmethod
    def _ensure_archive_extension(path: str, rec) -> str:
        """Rename a decoded '<sha>.bin' to carry the extension its validated
        type implies, so extraction.py's suffix-based archive dispatch fires."""
        ext = _ARCHIVE_EXT.get(rec.file_type)
        if not ext or path.endswith(ext):
            return path
        new_path = path + ext
        try:
            os.replace(path, new_path)
            rec.output_path = new_path
            return new_path
        except OSError:
            return path

    # ------------------------------------------------------------------
    # Gather text from anything the last pass extracted
    # ------------------------------------------------------------------

    def _collect_text_from_new_artifacts(self) -> str:
        """
        Phase 13: only reads files not already read by a previous pass —
        the original version walked and re-read the entire extracted/
        hidden_files tree from scratch on every pass, redoing disk I/O on
        files that could not possibly have changed (this engine only ever
        adds new files, never modifies existing ones).
        """
        texts: List[str] = []
        for directory in (str(self.store.extracted), str(self.store.hidden_files)):
            for fp in recursive_file_search(directory):
                if fp in self._scanned_paths:
                    continue
                self._scanned_paths.add(fp)
                try:
                    if os.path.getsize(fp) > 2_000_000:
                        continue
                    with open(fp, "rb") as f:
                        chunk = f.read(200_000)
                except OSError:
                    continue
                if not chunk:
                    continue
                printable = sum(1 for b in chunk if 0x20 <= b < 0x7F or b in (9, 10, 13))
                if printable / len(chunk) > 0.85:
                    texts.append(chunk.decode("utf-8", errors="ignore"))
        return "\n".join(texts)
