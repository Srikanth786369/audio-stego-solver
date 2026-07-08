"""
File extraction module for Audio Stego Solver v3.

KEY IMPROVEMENT: Differentiates between
  - Detected signatures (magic bytes found, not yet validated)
  - Validated (structural check passed)
  - Successfully extracted (file on disk, non-zero, readable)
  - Failed extraction (tool ran but produced no usable output)
  - False positives (signature but validation failed)

The report now says:
  "Detected embedded ZIP — Extraction failed — Reason: Corrupted archive"
instead of counting everything as "extracted".
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .artifact_store import ArtifactStore
from .findings import EvidenceLevel, Finding, Severity, cap_severity
from .logger import get_logger
from .utils import FILE_MAGIC, find_embedded_files, read_bytes, recursive_file_search, run_command, save_text, tool_available
from .validate import MAGIC_BACK_OFFSET, validate_embedded

logger = get_logger("audio_stego.extraction")

_MAX_RECURSION_DEPTH = 10
_MAX_EXTRACT_SIZE    = 500 * 1024 * 1024   # 500 MB
_MIN_EXTRACT_SIZE    = 1

# Container types that get recursed into — a successfully validated instance
# of one of these is tagged NESTED rather than VERIFIED, since it is not
# itself a leaf artifact.
_CONTAINER_TYPES = {
    "ZIP", "RAR", "RAR4", "RAR5", "7Z", "TAR", "GZIP", "TAR_GZ",
    "BZIP2", "TAR_BZ2", "XZ", "DOCX", "XLSX", "PPTX",
}

# Tool-metadata filenames that a carving tool writes into its own output
# directory alongside real carved artifacts — never a hidden payload itself,
# so it must never be counted as an "extracted file" anywhere in the report.
# foremost's audit.txt was already excluded from the foremost-specific
# carved-file count (see _run_foremost), but that exclusion did not apply to
# _collect_all()'s directory scan, so it still leaked into
# results["extracted_files"] (consumed unfiltered by html_report.py and
# reports_ext.py) as a spurious "extracted file" row.
_TOOL_METADATA_FILENAMES = {"audit.txt"}


def _is_tool_metadata_file(path: str) -> bool:
    return os.path.basename(path) in _TOOL_METADATA_FILENAMES


# Frame-sync magic types that belong to the same underlying bitstream family.
# When the host file's own leading bytes identify it as one of these families,
# scanning for that family's magic elsewhere in the file only ever finds the
# host's own continuing audio — never a distinct nested file — so those types
# are excluded from the signature scan entirely for that host.
_SELF_FRAME_TYPES: Dict[str, Set[str]] = {
    "mp3":  {"MP3_ID3", "MP3_FRAME"},
    "aac":  {"AAC_ADTS_MPEG4", "AAC_ADTS_MPEG2", "AAC_ADTS"},
}


def _host_audio_frame_family(data: bytes) -> Optional[str]:
    """Identify the host file's own frame-based audio family from its header,
    so that family's magic can be excluded from embedded-signature scanning."""
    head = data[:4]
    if data[:3] == b"ID3" or head[:2] == b"\xff\xfb":
        return "mp3"
    if head[:2] in (b"\xff\xf1", b"\xff\xf9"):
        return "aac"
    return None


class ExtractionStatus(str, Enum):
    DETECTED       = "detected"        # magic bytes seen
    VALIDATED      = "validated"       # structure confirmed
    EXTRACTED      = "extracted"       # file on disk
    FAILED         = "failed"          # tool ran, nothing produced
    FALSE_POSITIVE = "false_positive"  # validation rejected it
    UNSUPPORTED    = "unsupported"     # no validator / no tool available

    # Phase 2 (v3.1) unified evidence pipeline statuses
    VERIFIED            = "verified"             # checksum/parse-level evidence, fully confirmed
    RECOVERED           = "recovered"             # carved + structurally plausible, not checksum-verified
    PARTIAL             = "partial"               # recovered but smaller than the structure implies (truncated)
    REJECTED             = "rejected"             # carved file failed structural validation
    CORRUPTED            = "corrupted"            # real container, but internal checksum/CRC failed
    ENCRYPTED             = "encrypted"           # structure confirmed encrypted (generic)
    PASSWORD_PROTECTED    = "password_protected"  # structure confirmed password-protected (e.g. ZIP w/ flag bit)
    NESTED                = "nested"              # validated container that was recursed into
    SKIPPED               = "skipped"             # deliberately not processed (size limit, depth limit, etc.)


@dataclass
class ExtractionRecord:
    """Structured record for one embedded-file detection attempt."""
    file_type:   str
    offset:      int
    status:      ExtractionStatus
    confidence:  float             = 0.0
    reason:      str               = ""
    output_path: Optional[str]     = None
    size:        int               = 0
    false_positive_risk: str       = ""

    # Phase 2 (v3.1) unified evidence fields
    sha256:         Optional[str]  = None
    parent_sha256:  Optional[str]  = None
    depth:          int            = 0
    source_tools:   List[str]      = field(default_factory=list)
    validator:      str            = ""
    timestamp:      str            = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _safe_name(s: str) -> str:
    import re
    return re.sub(r"[^\w\-_.]", "_", s)[:40]


def _sniff_artifact_type(data: bytes) -> Optional[Tuple[str, int]]:
    """
    Identify a standalone carved artifact's file type from its own bytes.

    Honors the same fixed offsets used when a magic is found embedded in a
    larger blob (e.g. the 'ustar' tar magic sits 257 bytes into the header) —
    for a standalone file those offsets are simply relative to byte 0.
    Returns (type_name, magic_offset) or None if nothing matched.
    """
    for name, magic in FILE_MAGIC.items():
        off = MAGIC_BACK_OFFSET.get(name, 0)
        if data[off:off + len(magic)] == magic:
            return name, off
    return None


class ExtractionAnalyzer:
    """Extracts hidden files with structured per-item status reporting."""

    def __init__(self, config, store: ArtifactStore):
        self.config      = config
        self.store       = store
        self.output_dir  = str(store)               # legacy compat
        self._seen: Set[str] = set()
        self._root_sha: Optional[str] = None
        self._artifact_index: Dict[str, ExtractionRecord] = {}   # sha256 -> record (cross-tool dedup)
        self._archive_dir_to_sha: Dict[str, str] = {}            # extracted-to dir -> parent archive sha256
        self._sha256_cache: Dict[str, Optional[str]] = {}        # path -> sha256 (Phase 13: avoid re-hashing)
        self.results: Dict[str, Any] = {
            "records":         [],   # List[ExtractionRecord]
            "extracted_files": [],
            "binwalk":         [],
            "foremost":        [],
            "scalpel":         [],
            "steghide":        [],
            "stegseek":        {},
            "warnings":        [],
            "findings":        [],
            "summary": {
                "detected":       0,
                "validated":      0,
                "extracted":      0,
                "failed":         0,
                "false_positive": 0,
                # Phase 2 (v3.1) unified evidence pipeline — every tool-carved
                # artifact (binwalk/foremost/scalpel/steghide/stegseek/recursive)
                # is tallied here ONLY after passing through validate_embedded.
                # This is what "extracted_files" used to be conflated with.
                "verified":            0,
                "recovered":           0,
                "partial":             0,
                "rejected":            0,
                "corrupted":           0,
                "unsupported":         0,
                "encrypted":           0,
                "password_protected":  0,
                "nested":              0,
                "skipped":             0,
            },
        }

    def _sha256_cached(self, path: str) -> Optional[str]:
        """
        Per-scan SHA256 cache. Files this analyzer hashes are freshly carved
        or already-scanned outputs that don't change again within a single
        run, so caching purely by path (no mtime check needed) is safe here.
        Phase 13: found the same file was being hashed twice per pass —
        once in _recursive_multipass to check the dedup set, again inside
        _process_tool_artifact for the same path.
        """
        if path not in self._sha256_cache:
            self._sha256_cache[path] = _sha256(path)
        return self._sha256_cache[path]

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audio_path: str) -> Dict[str, Any]:
        logger.info(f"Extraction analysis: {audio_path}")
        self._root_sha = _sha256(audio_path)

        # Validated signature scan (replaces raw magic-byte detection)
        self._scan_signatures(audio_path)

        if self.config.getbool("analysis", "run_binwalk",   True): self._run_binwalk(audio_path)
        if self.config.getbool("analysis", "run_foremost",  True): self._run_foremost(audio_path)
        if self.config.getbool("analysis", "run_scalpel",   True): self._run_scalpel(audio_path)
        if self.config.getbool("analysis", "run_steghide",  True): self._run_steghide(audio_path)
        if self.config.getbool("analysis", "run_stegseek",  True): self._run_stegseek(audio_path)

        # Multi-pass recursive extraction with SHA256 dedup
        self._recursive_multipass(depth=0)
        self._collect_all()
        self._update_summary()
        self._write_extraction_report()

        logger.info(
            f"Extraction done — "
            f"{self.results['summary']['extracted']} extracted (signature scan), "
            f"{self.results['summary']['verified']} verified + "
            f"{self.results['summary']['recovered']} recovered (tool pipeline), "
            f"{self.results['summary']['failed']} failed, "
            f"{self.results['summary']['false_positive'] + self.results['summary']['rejected']} rejected/false positives"
        )
        return self.results

    # ------------------------------------------------------------------
    # Validated signature scan
    # ------------------------------------------------------------------

    def _scan_signatures(self, path: str):
        """
        Scan for embedded file signatures and validate each one structurally.
        Only reports signatures that pass structural validation.
        """
        data = read_bytes(path, max_bytes=100 * 1024 * 1024)
        if not data:
            return

        raw_sigs = find_embedded_files(data)
        audio_magic = {b"RIFF", b"fLaC", b"OggS", b"ID3", b"\xff\xfb"}

        # A frame-based audio host (MP3/AAC) is a continuous run of thousands
        # of self-consistent frame headers by construction — every single
        # frame boundary re-triggers _validate_mp3_frames/_validate_aac_adts,
        # which correctly reports "yes, a valid MPEG stream continues from
        # here" at every one of them, since it does. That is NOT evidence of
        # a hidden nested file, just the host's own native bitstream
        # continuing. Previously this produced one "extracted" record per
        # frame boundary (~2800+ on an 800KB MP3 — the exact "Extracted:
        # 2857 files" bug reported against this tool). Skip scanning for the
        # host's own frame family entirely; a real steganographic payload
        # inside an MP3/AAC file is still caught by every other registered
        # magic type (ZIP/PNG/etc.) below.
        host_family = _host_audio_frame_family(data)
        suppress_types = _SELF_FRAME_TYPES.get(host_family, set())

        # Belt-and-suspenders for the cross-container case (e.g. a WAV host
        # with a genuinely embedded MP3/AAC stream): once one offset within
        # a frame family validates as a real run of N consecutive frames
        # spanning [carve_off, carve_off+estimated_size), every other frame
        # sync inside that same span is the *same* stream, not a second
        # embedded file — skip it instead of emitting a duplicate record.
        covered: Dict[str, List[Tuple[int, int]]] = {}

        for sig in raw_sigs:
            offset = sig["offset"]
            mtype  = sig["type"]

            # Skip offset 0 (own header)
            if offset == 0:
                continue
            # Skip audio self-magic near the start
            chunk4 = data[offset:offset+4]
            if offset < 10 and any(chunk4.startswith(m) for m in audio_magic):
                continue
            if mtype in suppress_types:
                continue
            if any(start <= offset < end for start, end in covered.get(mtype, ())):
                continue

            vr = validate_embedded(data, offset, mtype)
            carve_off = vr.carve_offset if vr.carve_offset is not None else offset

            if vr.valid:
                span_end = carve_off + (vr.estimated_size or 1)
                covered.setdefault(vr.file_type, []).append((carve_off, span_end))

            rec = ExtractionRecord(
                file_type   = vr.file_type,
                offset      = carve_off,
                confidence  = vr.confidence,
                reason      = vr.reason,
                false_positive_risk = vr.false_positive_risk,
                status      = ExtractionStatus.VALIDATED if vr.valid
                              else ExtractionStatus.FALSE_POSITIVE,
                sha256      = None,
                source_tools = ["signature_scan"],
                validator   = vr.file_type,
            )

            if vr.valid:
                # Extract the validated slice
                chunk = data[carve_off: carve_off + (vr.estimated_size or 10_000_000)]
                out_path = str(self.store.extracted /
                               f"sig_{vr.file_type.lower()}_{carve_off:08x}.bin")
                try:
                    with open(out_path, "wb") as f:
                        f.write(chunk)
                    # Magic-only evidence (no dedicated validator) is recovered,
                    # not verified — every currently-registered type has a real
                    # validator, so this only fires for future unregistered types.
                    rec.status      = (ExtractionStatus.EXTRACTED
                                       if vr.evidence_level != EvidenceLevel.MAGIC_ONLY
                                       else ExtractionStatus.RECOVERED)
                    rec.output_path = out_path
                    rec.size        = len(chunk)
                    rec.sha256      = self._sha256_cached(out_path)
                    logger.info(f"Validated + extracted: {vr.file_type} @ 0x{carve_off:08x} → {out_path}")

                    severity = cap_severity(Severity.HIGH, vr.confidence)
                    self.results["findings"].append(Finding(
                        module   = "extraction",
                        title    = f"Validated Embedded {vr.file_type}",
                        severity = severity,
                        confidence = vr.confidence,
                        value    = f"{vr.file_type} @ offset 0x{carve_off:08x}",
                        evidence = vr.reason,
                        reason   = "Structural validation passed — not just magic bytes",
                        offset   = carve_off,
                        false_positive_risk = vr.false_positive_risk,
                    ).to_dict())
                except OSError as e:
                    rec.status = ExtractionStatus.FAILED
                    rec.reason = f"Write failed: {e}"
            else:
                logger.debug(f"Signature rejected (FP): {mtype} @ 0x{offset:08x}: {vr.reason}")

            self.results["records"].append(rec)

    # ------------------------------------------------------------------
    # binwalk
    # ------------------------------------------------------------------

    def _run_binwalk(self, path: str):
        if not tool_available("binwalk"):
            self.results["warnings"].append("Tool not found: binwalk")
            return

        bw_dir = str(self.store.extracted / "binwalk")
        os.makedirs(bw_dir, exist_ok=True)

        rc, out, err = run_command(["binwalk", path], timeout=self.config.timeout)
        save_text(str(self.store.tools / "binwalk_scan.txt"),
                  f"binwalk {path}\n{'='*60}\n{out}\nSTDERR:\n{err}")

        rc2, out2, err2 = run_command(
            ["binwalk", "-e", "--directory", bw_dir, path],
            timeout=self.config.timeout * 2,
        )
        save_text(str(self.store.tools / "binwalk_extract.txt"),
                  f"binwalk -e\n{'='*60}\n{out2}\nSTDERR:\n{err2}")

        findings: List[Dict] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("DECIMAL") or line.startswith("-"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit():
                findings.append({
                    "offset": parts[0], "hex": parts[1],
                    "description": parts[2],
                })

        self.results["binwalk"] = findings
        if findings:
            logger.info(f"binwalk: {len(findings)} signature(s)")

        for fp in recursive_file_search(bw_dir):
            self._process_tool_artifact(fp, "binwalk", parent_sha256=self._root_sha, depth=0)

    # ------------------------------------------------------------------
    # foremost
    # ------------------------------------------------------------------

    def _run_foremost(self, path: str):
        if not tool_available("foremost"):
            self.results["warnings"].append("Tool not found: foremost")
            return
        fm_dir = str(self.store.extracted / "foremost")
        os.makedirs(fm_dir, exist_ok=True)
        rc, out, err = run_command(
            ["foremost", "-o", fm_dir, "-i", path],
            timeout=self.config.timeout * 2,
        )
        save_text(str(self.store.tools / "foremost.txt"),
                  f"foremost\n{'='*60}\n{out}\nSTDERR:\n{err}")
        carved = [f for f in recursive_file_search(fm_dir)
                  if not _is_tool_metadata_file(f)]
        self.results["foremost"] = carved
        if carved:
            logger.info(f"foremost: {len(carved)} file(s) carved")

        for fp in carved:
            self._process_tool_artifact(fp, "foremost", parent_sha256=self._root_sha, depth=0)

    # ------------------------------------------------------------------
    # scalpel
    # ------------------------------------------------------------------

    def _run_scalpel(self, path: str):
        if not tool_available("scalpel"):
            self.results["warnings"].append("Tool not found: scalpel")
            return
        sc_dir = str(self.store.extracted / "scalpel")
        os.makedirs(sc_dir, exist_ok=True)
        rc, out, err = run_command(
            ["scalpel", "-o", sc_dir, path],
            timeout=self.config.timeout * 2,
        )
        save_text(str(self.store.tools / "scalpel.txt"),
                  f"scalpel\n{'='*60}\n{out}\nSTDERR:\n{err}")
        carved = recursive_file_search(sc_dir)
        self.results["scalpel"] = carved

        for fp in carved:
            self._process_tool_artifact(fp, "scalpel", parent_sha256=self._root_sha, depth=0)

    # ------------------------------------------------------------------
    # steghide
    # ------------------------------------------------------------------

    def _run_steghide(self, path: str):
        if not tool_available("steghide"):
            self.results["warnings"].append("Tool not found: steghide")
            return
        ext = Path(path).suffix.lower()
        if ext not in (".wav", ".jpg", ".jpeg", ".bmp", ".au"):
            return

        sh_dir = str(self.store.extracted / "steghide")
        os.makedirs(sh_dir, exist_ok=True)

        passphrases = [""]
        custom = self.config.get("steghide", "passphrase", "")
        if custom:
            passphrases.append(custom)
        passphrases.extend([
            "password", "secret", "hidden", "steg", "steghide",
            "flag", "ctf", "audio", "challenge",
        ])

        for pp in passphrases:
            safe   = _safe_name(pp) if pp else "empty"
            outf   = os.path.join(sh_dir, f"steghide_{safe}.bin")
            rc, out, err = run_command(
                ["steghide", "extract", "-sf", path, "-p", pp, "-f", "-xf", outf],
                timeout=30,
            )
            if rc == 0 and os.path.exists(outf) and os.path.getsize(outf) > 0:
                self.results["steghide"].append({
                    "passphrase": pp or "(empty)", "file": outf,
                })
                self.results["findings"].append(Finding(
                    module="extraction", title="steghide Extraction Succeeded",
                    severity=Severity.CRITICAL, confidence=0.99,
                    value=f"Extracted: {outf}",
                    evidence=f"Passphrase: '{pp or '(empty)'}' → {os.path.getsize(outf):,} bytes",
                    reason="steghide decrypted hidden payload",
                ).to_dict())
                logger.info(f"steghide: extracted with '{pp}'")
                self._process_tool_artifact(outf, "steghide", parent_sha256=self._root_sha,
                                             depth=0, create_finding=False)
                break

        save_text(str(self.store.tools / "steghide.txt"),
            ("steghide SUCCEEDED:\n" + "\n".join(
                f"  {x['passphrase']} → {x['file']}"
                for x in self.results["steghide"]
            )) if self.results["steghide"]
            else "steghide: no data extracted with tried passphrases."
        )

    # ------------------------------------------------------------------
    # stegseek
    # ------------------------------------------------------------------

    def _run_stegseek(self, path: str):
        if not tool_available("stegseek"):
            self.results["warnings"].append("Tool not found: stegseek")
            return
        ext = Path(path).suffix.lower()
        if ext not in (".wav", ".jpg", ".jpeg", ".bmp", ".au"):
            return

        wordlist = self.config.get("stegseek", "wordlist", "/usr/share/wordlists/rockyou.txt")
        if not os.path.exists(wordlist):
            self.results["warnings"].append(
                f"stegseek: wordlist not found ({wordlist}) — skipping"
            )
            return

        sk_dir = str(self.store.extracted / "stegseek")
        os.makedirs(sk_dir, exist_ok=True)
        outf = os.path.join(sk_dir, "stegseek_output.bin")

        rc, out, err = run_command(
            ["stegseek", path, wordlist, outf],
            timeout=self.config.timeout * 3,
        )
        save_text(str(self.store.tools / "stegseek.txt"),
                  f"stegseek\n{'='*60}\n{out}\nSTDERR:\n{err}")

        res: Dict[str, Any] = {"output": out, "file": None}
        if rc == 0 and os.path.exists(outf) and os.path.getsize(outf) > 0:
            res["file"] = outf
            self.results["findings"].append(Finding(
                module="extraction", title="stegseek Passphrase Cracked",
                severity=Severity.CRITICAL, confidence=0.99,
                value=f"Extracted: {outf}",
                evidence="stegseek cracked steghide passphrase from wordlist",
                reason=out[:200],
            ).to_dict())
            logger.info(f"stegseek: extracted → {outf}")
            self._process_tool_artifact(outf, "stegseek", parent_sha256=self._root_sha,
                                         depth=0, create_finding=False)
        self.results["stegseek"] = res

    # ------------------------------------------------------------------
    # Multi-pass recursive extraction with SHA256 dedup
    # ------------------------------------------------------------------

    def _parent_sha_for(self, fp: str) -> Optional[str]:
        """Walk up from fp to find the archive it was extracted from, if any."""
        p = Path(fp).parent
        while True:
            hit = self._archive_dir_to_sha.get(str(p))
            if hit is not None:
                return hit
            if p == p.parent:
                break
            p = p.parent
        return self._root_sha

    def _recursive_multipass(self, depth: int = 0):
        if depth >= _MAX_RECURSION_DEPTH:
            return
        prev = len(self._seen)
        for directory in [str(self.store.extracted), str(self.store.hidden_files)]:
            for fp in recursive_file_search(directory):
                sha = self._sha256_cached(fp)
                if sha is None or sha in self._seen:
                    continue
                self._seen.add(sha)
                self._process_tool_artifact(fp, "recursive_extract",
                                             parent_sha256=self._parent_sha_for(fp), depth=depth)

                sz = os.path.getsize(fp)
                if not (_MIN_EXTRACT_SIZE <= sz <= _MAX_EXTRACT_SIZE):
                    continue
                ext = Path(fp).suffix.lower()
                if ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"):
                    self._extract_archive(fp)
                # Carved images are already found directly by OCR's own
                # recursive search of extracted/hidden_files — copying them
                # into images/ too would just make OCR process the same
                # image twice (dedup is by resolved path, and a copy is a
                # different path).

        if len(self._seen) > prev:
            self._recursive_multipass(depth + 1)

    def _extract_archive(self, path: str):
        ext    = Path(path).suffix.lower()
        name   = _safe_name(Path(path).name)
        out_dir = str(self.store.hidden_files / (name + "_ex"))
        os.makedirs(out_dir, exist_ok=True)
        archive_sha = self._sha256_cached(path)
        if archive_sha:
            self._archive_dir_to_sha[out_dir] = archive_sha

        if   ext == ".zip"  and tool_available("unzip"):
            run_command(["unzip", "-o", path, "-d", out_dir], timeout=60)
        elif ext == ".rar"  and tool_available("unrar"):
            run_command(["unrar", "x", "-y", path, out_dir], timeout=60)
        elif ext == ".7z"   and tool_available("7z"):
            run_command(["7z", "x", path, f"-o{out_dir}", "-y"], timeout=60)
        elif ext in (".bz2", ".xz", ".tar") and tool_available("tar"):
            run_command(["tar", "-xf", path, "-C", out_dir], timeout=60)
        elif ext == ".gz":
            if Path(path).stem.endswith(".tar") and tool_available("tar"):
                run_command(["tar", "-xzf", path, "-C", out_dir], timeout=60)
            elif tool_available("gzip"):
                copy_path = str(Path(out_dir) / Path(path).name)
                try:
                    shutil.copy2(path, copy_path)
                    run_command(["gzip", "-d", "-f", copy_path], timeout=60)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Unified evidence pipeline (Phase 2, v3.1)
    #
    #   Tool -> Artifact -> SHA256 -> Dedup -> Detect Type -> Validator ->
    #   Confidence -> Evidence Record
    #
    # Every carved file from binwalk/foremost/scalpel/steghide/stegseek/
    # recursive-extraction passes through this single function. Nothing is
    # ever counted toward extraction statistics just because it exists on
    # disk — only artifacts that reach here with a classified status
    # contribute to results["summary"].
    # ------------------------------------------------------------------

    def _process_tool_artifact(
        self,
        path: str,
        tool: str,
        parent_sha256: Optional[str] = None,
        depth: int = 0,
        create_finding: bool = True,
    ) -> Optional[ExtractionRecord]:
        if not os.path.isfile(path):
            return None
        sha = self._sha256_cached(path)
        if sha is None:
            return None

        existing = self._artifact_index.get(sha)
        if existing is not None:
            # SHA256 dedup: same bytes found by a second tool — merge provenance,
            # do not create a second record or count it twice.
            if tool not in existing.source_tools:
                existing.source_tools.append(tool)
            return existing

        size = os.path.getsize(path)
        if size < _MIN_EXTRACT_SIZE:
            return None
        if size > _MAX_EXTRACT_SIZE:
            rec = ExtractionRecord(
                file_type="UNKNOWN", offset=0, status=ExtractionStatus.SKIPPED,
                confidence=0.0, reason=f"Exceeds max extract size ({_MAX_EXTRACT_SIZE:,} bytes)",
                output_path=path, size=size, sha256=sha, parent_sha256=parent_sha256,
                depth=depth, source_tools=[tool], validator="none",
            )
            self.results["records"].append(rec)
            self._artifact_index[sha] = rec
            return rec

        data = read_bytes(path, max_bytes=50 * 1024 * 1024)
        sniffed = _sniff_artifact_type(data)

        if sniffed is None:
            rec = ExtractionRecord(
                file_type="UNKNOWN", offset=0, status=ExtractionStatus.UNSUPPORTED,
                confidence=0.0, reason="No recognised structural signature",
                output_path=path, size=size, sha256=sha, parent_sha256=parent_sha256,
                depth=depth, source_tools=[tool], validator="none",
            )
            self.results["records"].append(rec)
            self._artifact_index[sha] = rec
            return rec

        type_name, magic_off = sniffed
        vr = validate_embedded(data, magic_off, type_name)
        status = self._classify_validation(vr, size)

        rec = ExtractionRecord(
            file_type=vr.file_type, offset=magic_off, status=status,
            confidence=vr.confidence, reason=vr.reason,
            output_path=path, size=size, false_positive_risk=vr.false_positive_risk,
            sha256=sha, parent_sha256=parent_sha256, depth=depth,
            source_tools=[tool], validator=vr.file_type,
        )
        self.results["records"].append(rec)
        self._artifact_index[sha] = rec

        if create_finding and status in (
            ExtractionStatus.VERIFIED, ExtractionStatus.RECOVERED,
            ExtractionStatus.PARTIAL, ExtractionStatus.NESTED,
        ):
            severity = cap_severity(Severity.HIGH, vr.confidence)
            self.results["findings"].append(Finding(
                module="extraction",
                title=f"{status.value.replace('_', ' ').title()} Artifact: {vr.file_type}",
                severity=severity, confidence=vr.confidence,
                value=f"{vr.file_type} recovered via {tool}",
                evidence=vr.reason,
                reason=f"sha256={sha[:16]}… depth={depth} tool={tool}",
                false_positive_risk=vr.false_positive_risk,
            ).to_dict())

        return rec

    def _classify_validation(self, vr, disk_size: int) -> ExtractionStatus:
        """Map a ValidationResult onto the Phase-2 status vocabulary."""
        if getattr(vr, "password_protected", False):
            return ExtractionStatus.PASSWORD_PROTECTED
        if getattr(vr, "corrupted", False):
            return ExtractionStatus.CORRUPTED
        if not vr.valid:
            return ExtractionStatus.REJECTED
        if vr.file_type in _CONTAINER_TYPES:
            return ExtractionStatus.NESTED
        if vr.evidence_level in (EvidenceLevel.CHECKSUM_VALID, EvidenceLevel.EXTRACTED,
                                  EvidenceLevel.PARSED_OPENED):
            if vr.estimated_size and disk_size < vr.estimated_size * 0.9:
                return ExtractionStatus.PARTIAL
            return ExtractionStatus.VERIFIED
        # HEADER_PARSED, STRUCTURE_VALIDATED, or (rarely) MAGIC_ONLY-but-valid
        # (only reachable for a magic type with no registered validator)
        return ExtractionStatus.RECOVERED

    # ------------------------------------------------------------------
    # Collect + summary
    # ------------------------------------------------------------------

    def _collect_all(self):
        all_files = (
            recursive_file_search(str(self.store.extracted))
            + recursive_file_search(str(self.store.hidden_files))
        )
        all_files = [f for f in all_files if not _is_tool_metadata_file(f)]
        self.results["extracted_files"] = list(dict.fromkeys(all_files))

    def _update_summary(self):
        """Recompute summary counts from self.results['records'] from scratch.
        Idempotent — safe to call again after more records are appended (e.g.
        by the recursive analysis engine), unlike a pure increment would be."""
        s = self.results["summary"]
        for key in s:
            s[key] = 0
        counters = {
            ExtractionStatus.EXTRACTED:          "extracted",
            ExtractionStatus.VALIDATED:          "validated",
            ExtractionStatus.DETECTED:           "detected",
            ExtractionStatus.FAILED:             "failed",
            ExtractionStatus.FALSE_POSITIVE:     "false_positive",
            ExtractionStatus.VERIFIED:           "verified",
            ExtractionStatus.RECOVERED:          "recovered",
            ExtractionStatus.PARTIAL:            "partial",
            ExtractionStatus.REJECTED:           "rejected",
            ExtractionStatus.CORRUPTED:          "corrupted",
            ExtractionStatus.UNSUPPORTED:        "unsupported",
            ExtractionStatus.ENCRYPTED:          "encrypted",
            ExtractionStatus.PASSWORD_PROTECTED: "password_protected",
            ExtractionStatus.NESTED:             "nested",
            ExtractionStatus.SKIPPED:            "skipped",
        }
        for rec in self.results["records"]:
            key = counters.get(rec.status)
            if key:
                s[key] += 1

    def _write_extraction_report(self):
        s = self.results["summary"]
        confirmed = s["extracted"] + s["verified"] + s["nested"]
        unvalidated_on_disk = len(self.results.get("extracted_files", []))
        lines = [
            "=== EXTRACTION REPORT ===",
            "",
            "--- Signature scan (embedded-in-audio detection) ---",
            f"Detected signatures   : {s['detected'] + s['validated'] + s['extracted'] + s['failed'] + s['false_positive']}",
            f"Validated             : {s['validated'] + s['extracted']}",
            f"Successfully extracted: {s['extracted']}",
            f"Extraction failed     : {s['failed']}",
            f"False positives       : {s['false_positive']}",
            "",
            "--- Unified tool pipeline (binwalk/foremost/scalpel/steghide/stegseek/recursive) ---",
            f"Verified (checksum/parse-confirmed) : {s['verified']}",
            f"Nested (validated container)        : {s['nested']}",
            f"Recovered (structurally plausible)  : {s['recovered']}",
            f"Partial (truncated)                 : {s['partial']}",
            f"Corrupted (real container, bad CRC) : {s['corrupted']}",
            f"Password-protected                  : {s['password_protected']}",
            f"Rejected (failed validation)        : {s['rejected']}",
            f"Unsupported (no known structure)    : {s['unsupported']}",
            f"Skipped (size/policy limit)         : {s['skipped']}",
            "",
            f"Confirmed artifacts (extracted+verified+nested): {confirmed}",
            f"Files written to disk by any tool (unvalidated): {unvalidated_on_disk} "
            "— NOT the same as 'confirmed'; see per-record detail below",
            "",
            "--- Per-artifact detail ---",
        ]
        for rec in self.results["records"]:
            prov = ",".join(rec.source_tools) or "signature_scan"
            lines.append(
                f"  [{rec.status.value:20s}] {rec.file_type:14s} @ 0x{rec.offset:08x} "
                f"conf={rec.confidence:.0%} depth={rec.depth} tools=[{prov}]  {rec.reason[:80]}"
            )
            if rec.status == ExtractionStatus.FAILED:
                lines.append(f"    → FAILED: {rec.reason}")
            if rec.status in (ExtractionStatus.FALSE_POSITIVE, ExtractionStatus.REJECTED):
                lines.append(f"    → REJECTED: {rec.reason}")
                lines.append(f"    → FP risk: {rec.false_positive_risk}")
            if rec.status == ExtractionStatus.CORRUPTED:
                lines.append(f"    → CORRUPTED: {rec.reason}")

        if self.results["steghide"]:
            lines += ["", "--- steghide ---"]
            for x in self.results["steghide"]:
                lines.append(f"  Extracted with passphrase '{x['passphrase']}' → {x['file']}")
        ssk = self.results.get("stegseek", {})
        if isinstance(ssk, dict) and ssk.get("file"):
            lines += ["", f"--- stegseek ---", f"  Cracked → {ssk['file']}"]

        save_text(str(self.store.tools / "extraction_report.txt"), "\n".join(lines))
