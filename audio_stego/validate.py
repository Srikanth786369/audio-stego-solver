"""
Embedded file validation module for Audio Stego Solver v3.

Replaces naive magic-byte detection with structural validation.
A signature is only reported if the file structure is internally consistent.

Fixes the false-positive problem where JPEG/MP3 byte patterns inside
PCM audio data were reported as embedded files.

Phase 3/4/5 (v3.1): every validator now tags an EvidenceLevel so confidence
is derived from the confidence engine (findings.py) instead of hand-picked
per validator, and the MP3/AAC validators do real consecutive-frame parsing
instead of accepting an isolated frame-sync byte pair.
"""

from __future__ import annotations

import gzip as _gzip_mod
import json
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import Dict, Optional

from .findings import EvidenceLevel, confidence_for_evidence
from .logger import get_logger

logger = get_logger("audio_stego.validate")


# Some magic bytes do not sit at the start of the structure they belong to
# (e.g. the 'ustar' tar magic is 257 bytes into the 512-byte header, and the
# 'ftyp' MP4/M4A box type follows a 4-byte box-size field). This table records
# how far to step *back* from a found magic offset to reach the true start of
# the structure. It is also used by extraction.py to sniff standalone carved
# files, where the same fixed offsets apply relative to the file's own start.
MAGIC_BACK_OFFSET: Dict[str, int] = {
    "TAR":     257,
    "M4A_MP4": 4,
}


@dataclass
class ValidationResult:
    valid: bool
    file_type: str
    confidence: float          # 0.0–1.0
    reason: str
    estimated_size: int = 0    # bytes of the embedded file
    false_positive_risk: str = ""
    evidence_level: EvidenceLevel = EvidenceLevel.MAGIC_ONLY
    corrupted: bool = False            # structure recognised but internally inconsistent
    password_protected: bool = False   # structure recognised but encrypted/locked
    carve_offset: Optional[int] = None  # true start offset once back-offset corrected


def validate_embedded(data: bytes, offset: int, magic_type: str) -> ValidationResult:
    """
    Validate that what looks like an embedded file actually is one.

    Args:
        data:       Full file bytes
        offset:     Byte offset where magic was found
        magic_type: Type name from FILE_MAGIC dict

    Returns:
        ValidationResult with valid=True only if structure checks pass
    """
    back = MAGIC_BACK_OFFSET.get(magic_type, 0)
    real_offset = max(0, offset - back)
    chunk = data[real_offset:]

    validators = {
        "ZIP":    _validate_zip,
        "PNG":    _validate_png,
        "JPEG":   _validate_jpeg,
        "PDF":    _validate_pdf,
        "GIF":    _validate_gif,
        "ELF":    _validate_elf,
        "TAR_GZ": _validate_gzip,
        "GZIP":   _validate_gzip,
        "RAR":    _validate_rar,
        "7Z":     _validate_7z,
        "BMP":    _validate_bmp,
        "WAV":    _validate_riff,
        "FLAC":   _validate_flac,
        "OGG":    _validate_ogg,
        "MP3_ID3":   _validate_id3,
        "MP3_FRAME": _validate_mp3_frames,
        "SQLite": _validate_sqlite,
        "SQLITE": _validate_sqlite,   # matches utils.FILE_MAGIC's actual key spelling
        "AIFF":   _validate_aiff,
        "TAR":    _validate_tar,
        "TAR_BZ2": _validate_bzip2,
        "BZIP2":  _validate_bzip2,
        "XZ":     _validate_xz,
        "TIFF":   _validate_tiff,
        "PE":     _validate_pe,
        "JSON":   _validate_json,
        "XML":    _validate_xml,
        "M4A_MP4": _validate_m4a,
        "AAC_ADTS": _validate_aac_adts,
        "AAC_ADTS_MPEG4": _validate_aac_adts,
        "AAC_ADTS_MPEG2": _validate_aac_adts,
        "DOCX":   lambda c, t: _validate_zip(c, t, office_hint="DOCX"),
        "XLSX":   lambda c, t: _validate_zip(c, t, office_hint="XLSX"),
        "PPTX":   lambda c, t: _validate_zip(c, t, office_hint="PPTX"),
    }
    fn = validators.get(magic_type)
    if fn is None:
        return ValidationResult(
            valid=True,
            file_type=magic_type,
            confidence=confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            reason=f"No validator for {magic_type} — accepted on magic bytes alone",
            false_positive_risk="Medium — only magic bytes checked",
            evidence_level=EvidenceLevel.MAGIC_ONLY,
        )
    result = fn(chunk, magic_type)
    if back:
        result.carve_offset = real_offset
    return result


# ---------------------------------------------------------------------------
# Individual validators
# ---------------------------------------------------------------------------

def _validate_zip(chunk: bytes, _type: str, office_hint: Optional[str] = None) -> ValidationResult:
    """ZIP: open as zipfile, verify member CRCs, detect OOXML/password cases."""
    if len(chunk) < 22:
        return ValidationResult(False, "ZIP", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short for valid ZIP", evidence_level=EvidenceLevel.MAGIC_ONLY)
    try:
        zf = zipfile.ZipFile(__import__("io").BytesIO(chunk))
        names = zf.namelist()
    except Exception as e:
        return ValidationResult(
            False, "ZIP", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            f"ZIP parse failed: {e}",
            false_positive_risk="High — PK magic appears in many binary formats",
            evidence_level=EvidenceLevel.MAGIC_ONLY,
        )

    file_type = "ZIP"
    if office_hint == "DOCX" or "word/document.xml" in names:
        file_type = "DOCX"
    elif office_hint == "XLSX" or "xl/workbook.xml" in names:
        file_type = "XLSX"
    elif office_hint == "PPTX" or "ppt/presentation.xml" in names:
        file_type = "PPTX"

    encrypted = any((zi.flag_bits & 0x1) for zi in zf.infolist())
    if encrypted:
        return ValidationResult(
            True, file_type, confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
            f"Valid {file_type} with {len(names)} member(s), password-protected (encryption flag set)",
            estimated_size=sum(i.compress_size for i in zf.infolist()),
            false_positive_risk="Very low — zipfile parser succeeded",
            evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
            password_protected=True,
        )

    bad_member = zf.testzip()
    size = sum(i.compress_size for i in zf.infolist())
    if bad_member is not None:
        return ValidationResult(
            True, file_type, confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
            f"Valid {file_type} container with {len(names)} member(s), "
            f"but CRC check failed on '{bad_member}' — corrupted",
            estimated_size=size,
            false_positive_risk="Very low — zipfile parser succeeded",
            evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
            corrupted=True,
        )

    return ValidationResult(
        valid=True, file_type=file_type,
        confidence=confidence_for_evidence(EvidenceLevel.PARSED_OPENED),
        reason=f"Valid {file_type} with {len(names)} member(s), all CRCs verified: {names[:3]}",
        estimated_size=size,
        false_positive_risk="Very low — zipfile parser succeeded, checksums verified",
        evidence_level=EvidenceLevel.PARSED_OPENED,
    )


def _validate_png(chunk: bytes, _type: str) -> ValidationResult:
    """PNG: check 8-byte signature + IHDR chunk."""
    PNG_SIG = b"\x89PNG\r\n\x1a\n"
    if not chunk.startswith(PNG_SIG) or len(chunk) < 24:
        return ValidationResult(False, "PNG", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing PNG signature or too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    # IHDR must follow immediately
    ihdr_len = struct.unpack_from(">I", chunk, 8)[0]
    ihdr_type = chunk[12:16]
    if ihdr_type != b"IHDR" or ihdr_len != 13:
        return ValidationResult(False, "PNG", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                 f"Expected IHDR, got {ihdr_type!r}", evidence_level=EvidenceLevel.HEADER_PARSED)
    width  = struct.unpack_from(">I", chunk, 16)[0]
    height = struct.unpack_from(">I", chunk, 20)[0]
    if width == 0 or height == 0 or width > 65536 or height > 65536:
        return ValidationResult(False, "PNG", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                 f"Implausible dimensions {width}×{height}", evidence_level=EvidenceLevel.HEADER_PARSED)
    # Find IEND
    iend_pos = chunk.find(b"IEND")
    size = iend_pos + 8 if iend_pos != -1 else 0
    level = EvidenceLevel.PARSED_OPENED if iend_pos != -1 else EvidenceLevel.EXTRACTED
    return ValidationResult(
        valid=True, file_type="PNG",
        confidence=confidence_for_evidence(level),
        reason=f"Valid PNG IHDR: {width}×{height}px" + (" (IEND found)" if iend_pos != -1 else " (no IEND — truncated)"),
        estimated_size=size,
        false_positive_risk="Very low",
        evidence_level=level,
    )


def _validate_jpeg(chunk: bytes, _type: str) -> ValidationResult:
    """
    JPEG: SOI marker + a real, consistent chain of marker segments.

    Previously this accepted SOI + one plausible-looking next marker byte,
    then did a blind chunk.find(b"\\xff\\xd9") for EOI across the *entire*
    remainder of the host file (chunk is data[offset:], unbounded) — in a
    multi-hundred-KB host, an incidental 0xFFD9 byte pair occurs by chance
    often enough that this produced false "extracted" JPEGs out of ordinary
    compressed audio. Now the marker chain is walked segment-by-segment
    (each marker's own 2-byte length field says exactly where the next
    marker is), which is real structural evidence, not a coincidental
    distant byte match.
    """
    if len(chunk) < 10:
        return ValidationResult(False, "JPEG", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    if chunk[:2] != b"\xff\xd8":
        return ValidationResult(False, "JPEG", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing SOI", evidence_level=EvidenceLevel.MAGIC_ONLY)
    marker = chunk[2:4]
    if not (marker[0] == 0xFF and marker[1] in range(0xC0, 0xFF)):
        return ValidationResult(
            False, "JPEG", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
            f"SOI not followed by valid marker (got {marker.hex()})",
            false_positive_risk="High — \\xff\\xd8 common in PCM audio",
            evidence_level=EvidenceLevel.HEADER_PARSED,
        )

    pos = 2
    segments = 0
    n = len(chunk)
    while pos + 2 <= n and segments < 500:
        if chunk[pos] != 0xFF:
            break
        m = chunk[pos + 1]
        if m == 0xD9:  # EOI
            size = pos + 2
            level = (EvidenceLevel.STRUCTURE_VALIDATED if segments >= 1
                     else EvidenceLevel.HEADER_PARSED)
            return ValidationResult(
                valid=segments >= 1, file_type="JPEG",
                confidence=confidence_for_evidence(level),
                reason=f"{segments} valid marker segment(s) parsed, EOI found",
                estimated_size=size,
                false_positive_risk="Low" if segments >= 1 else "High — EOI with no real segment chain",
                evidence_level=level,
            )
        if m in (0x01,) or 0xD0 <= m <= 0xD7:  # TEM / RSTn — no length field
            pos += 2
            continue
        if not (0xC0 <= m <= 0xFE):
            break
        if pos + 4 > n:
            break
        seg_len = struct.unpack_from(">H", chunk, pos + 2)[0]
        if seg_len < 2:
            break
        segments += 1
        if m == 0xDA:  # SOS — entropy-coded data follows; scan forward
            # (skipping byte-stuffed 0xFF00 and restart markers) for the
            # next real marker rather than trusting a length field, since
            # SOS's own length only covers the scan header, not the data.
            i = pos + 2 + seg_len
            while i + 1 < n:
                if chunk[i] == 0xFF and chunk[i + 1] != 0x00 and not (0xD0 <= chunk[i + 1] <= 0xD7):
                    break
                i += 1
            pos = i
        else:
            pos += 2 + seg_len

    # Ran off the end of the available data without a proper EOI — either
    # truncated (real signal is still ambiguous) or not a real JPEG at all.
    # A higher segment-count bar than the EOI-terminated case above (mirrors
    # this project's MP3/AAC frame validators requiring several consecutive
    # consistent units rather than one lucky match) since there is no EOI to
    # anchor the chain's end.
    if segments >= 4:
        return ValidationResult(
            True, "JPEG", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
            f"{segments} valid marker segment(s) parsed, no EOI — may be truncated",
            estimated_size=pos,
            false_positive_risk="Medium — no EOI to confirm end of stream",
            evidence_level=EvidenceLevel.HEADER_PARSED,
        )
    return ValidationResult(
        False, "JPEG", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
        f"Only {segments} valid marker segment(s) before the chain broke — "
        "isolated SOI rejected, not classified as an embedded file",
        false_positive_risk="High — marker chain did not sustain",
        evidence_level=EvidenceLevel.MAGIC_ONLY,
    )


def _validate_pdf(chunk: bytes, _type: str) -> ValidationResult:
    """PDF: %PDF header + %%EOF trailer."""
    if not chunk.startswith(b"%PDF-"):
        return ValidationResult(False, "PDF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing %PDF- header", evidence_level=EvidenceLevel.MAGIC_ONLY)
    version_end = chunk.find(b"\n", 0, 20)
    version = chunk[5:version_end].decode("ascii", errors="replace").strip()
    eof = chunk.rfind(b"%%EOF")
    level = EvidenceLevel.STRUCTURE_VALIDATED if eof != -1 else EvidenceLevel.HEADER_PARSED
    size = eof + 5 if eof != -1 else 0
    return ValidationResult(
        valid=True, file_type="PDF",
        confidence=confidence_for_evidence(level),
        reason=f"PDF version {version}; {'%%EOF found' if eof != -1 else 'no %%EOF'}",
        estimated_size=size,
        false_positive_risk="Low",
        evidence_level=level,
    )


def _validate_gif(chunk: bytes, _type: str) -> ValidationResult:
    """GIF: GIF87a or GIF89a header."""
    if len(chunk) < 13:
        return ValidationResult(False, "GIF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    sig = chunk[:6]
    if sig not in (b"GIF87a", b"GIF89a"):
        return ValidationResult(False, "GIF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 f"Bad GIF signature: {sig!r}", evidence_level=EvidenceLevel.MAGIC_ONLY)
    width  = struct.unpack_from("<H", chunk, 6)[0]
    height = struct.unpack_from("<H", chunk, 8)[0]
    trailer = chunk.rfind(b"\x3b")
    size = trailer + 1 if trailer != -1 else 0
    level = EvidenceLevel.STRUCTURE_VALIDATED if trailer != -1 else EvidenceLevel.HEADER_PARSED
    return ValidationResult(
        valid=True, file_type="GIF",
        confidence=confidence_for_evidence(level),
        reason=f"Valid GIF {'89a' if sig==b'GIF89a' else '87a'}: {width}×{height}px",
        estimated_size=size,
        false_positive_risk="Low",
        evidence_level=level,
    )


def _validate_elf(chunk: bytes, _type: str) -> ValidationResult:
    """ELF: magic + valid class/endian/type."""
    if len(chunk) < 16:
        return ValidationResult(False, "ELF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    if chunk[:4] != b"\x7fELF":
        return ValidationResult(False, "ELF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing ELF magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    ei_class = chunk[4]   # 1=32-bit, 2=64-bit
    ei_data  = chunk[5]   # 1=LE, 2=BE
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return ValidationResult(False, "ELF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Invalid class={ei_class} data={ei_data}", evidence_level=EvidenceLevel.HEADER_PARSED)
    e_type = struct.unpack_from("<H" if ei_data == 1 else ">H", chunk, 16)[0]
    type_names = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
    type_name = type_names.get(e_type, f"type={e_type}")
    return ValidationResult(
        valid=True, file_type="ELF",
        confidence=confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
        reason=f"Valid ELF {'64-bit' if ei_class==2 else '32-bit'} {type_name}",
        false_positive_risk="Low",
        evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
    )


def _validate_gzip(chunk: bytes, _type: str) -> ValidationResult:
    """GZIP: magic + CM=8 + valid flags byte + real decompression."""
    if len(chunk) < 10:
        return ValidationResult(False, "GZIP", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    if chunk[:2] != b"\x1f\x8b":
        return ValidationResult(False, "GZIP", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing gzip magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    cm = chunk[2]
    if cm != 8:
        return ValidationResult(False, "GZIP", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                 f"Unknown compression method CM={cm}", evidence_level=EvidenceLevel.HEADER_PARSED)
    try:
        _gzip_mod.decompress(chunk[:min(len(chunk), 1_000_000)])
        level = EvidenceLevel.PARSED_OPENED
        reason = "Decompression succeeded"
    except Exception as e:
        level = EvidenceLevel.HEADER_PARSED
        reason = f"Magic valid but decompression failed: {e}"
    return ValidationResult(
        valid=True, file_type="GZIP",
        confidence=confidence_for_evidence(level),
        reason=reason,
        false_positive_risk="Low if decompression succeeds",
        evidence_level=level,
    )


def _validate_rar(chunk: bytes, _type: str) -> ValidationResult:
    """RAR: signature bytes."""
    RAR5 = b"Rar!\x1a\x07\x01\x00"
    RAR4 = b"Rar!\x1a\x07\x00"
    if chunk[:8] == RAR5:
        return ValidationResult(True, "RAR5", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                                "Valid RAR5 signature", false_positive_risk="Low",
                                evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)
    if chunk[:7] == RAR4:
        return ValidationResult(True, "RAR4", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                                "Valid RAR4 signature", false_positive_risk="Low",
                                evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)
    return ValidationResult(False, "RAR", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                            "RAR signature mismatch", evidence_level=EvidenceLevel.HEADER_PARSED)


def _validate_7z(chunk: bytes, _type: str) -> ValidationResult:
    """7-Zip: signature + version."""
    if len(chunk) < 8:
        return ValidationResult(False, "7Z", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short", evidence_level=EvidenceLevel.MAGIC_ONLY)
    if chunk[:6] != b"7z\xbc\xaf'\x1c":
        return ValidationResult(False, "7Z", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Wrong 7z magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    major = chunk[6]
    minor = chunk[7]
    return ValidationResult(
        valid=True, file_type="7Z",
        confidence=confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
        reason=f"Valid 7z v{major}.{minor}",
        false_positive_risk="Low",
        evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
    )


def _validate_bmp(chunk: bytes, _type: str) -> ValidationResult:
    """BMP: 'BM' + plausible file size."""
    if len(chunk) < 14 or chunk[:2] != b"BM":
        return ValidationResult(False, "BMP", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing BM signature", evidence_level=EvidenceLevel.MAGIC_ONLY)
    file_size = struct.unpack_from("<I", chunk, 2)[0]
    if file_size < 54 or file_size > 200_000_000:
        return ValidationResult(False, "BMP", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Implausible file_size={file_size}", evidence_level=EvidenceLevel.HEADER_PARSED)
    if file_size > len(chunk):
        return ValidationResult(
            False, "BMP", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
            f"Declared file_size={file_size:,} exceeds {len(chunk):,} bytes actually "
            "remaining in the host file — cannot be a real embedded BMP",
            false_positive_risk="High — 'BM' sync matched by chance, header fields not backed by real data",
            evidence_level=EvidenceLevel.HEADER_PARSED,
        )
    return ValidationResult(
        valid=True, file_type="BMP",
        confidence=confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
        reason=f"Valid BMP header, size={file_size:,} bytes",
        false_positive_risk="Medium — BM is a common 2-byte pattern",
        evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
    )


def _validate_riff(chunk: bytes, _type: str) -> ValidationResult:
    """RIFF container: WAV, WEBP, or generic AVI/RIFF."""
    if len(chunk) < 12 or chunk[:4] != b"RIFF":
        return ValidationResult(False, "WAV", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing RIFF", evidence_level=EvidenceLevel.MAGIC_ONLY)
    riff_type = chunk[8:12]
    size = struct.unpack_from("<I", chunk, 4)[0]
    if riff_type == b"WAVE":
        return ValidationResult(True, "WAV", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                                f"Valid RIFF/WAVE, size={size:,} bytes",
                                estimated_size=size + 8,
                                false_positive_risk="Low", evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)
    if riff_type == b"WEBP":
        codec = chunk[12:16]
        if codec not in (b"VP8 ", b"VP8L", b"VP8X"):
            return ValidationResult(False, "WEBP", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                    f"RIFF/WEBP present but unknown codec chunk {codec!r}",
                                    evidence_level=EvidenceLevel.HEADER_PARSED)
        return ValidationResult(True, "WEBP", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                                f"Valid RIFF/WEBP, codec={codec.decode(errors='replace').strip()}, size={size:,} bytes",
                                estimated_size=size + 8,
                                false_positive_risk="Medium — RIFF also used by WAV/AVI",
                                evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)
    return ValidationResult(True, "RIFF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                            f"RIFF/{riff_type.decode('ascii','replace')}",
                            estimated_size=size + 8,
                            false_positive_risk="Medium", evidence_level=EvidenceLevel.HEADER_PARSED)


def _validate_flac(chunk: bytes, _type: str) -> ValidationResult:
    """FLAC: fLaC marker."""
    if chunk[:4] != b"fLaC":
        return ValidationResult(False, "FLAC", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing fLaC", evidence_level=EvidenceLevel.MAGIC_ONLY)
    return ValidationResult(True, "FLAC", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                            "Valid FLAC signature", false_positive_risk="Low",
                            evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)


def _validate_ogg(chunk: bytes, _type: str) -> ValidationResult:
    """OGG: OggS capture pattern."""
    if chunk[:4] != b"OggS":
        return ValidationResult(False, "OGG", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing OggS", evidence_level=EvidenceLevel.MAGIC_ONLY)
    version = chunk[4]
    if version != 0:
        return ValidationResult(False, "OGG", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Unknown OGG version {version}", evidence_level=EvidenceLevel.HEADER_PARSED)
    return ValidationResult(True, "OGG", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
                            "Valid OGG page header", false_positive_risk="Low",
                            evidence_level=EvidenceLevel.STRUCTURE_VALIDATED)


def _validate_id3(chunk: bytes, _type: str) -> ValidationResult:
    """MP3 ID3 tag: 'ID3' + version byte in valid range; upgrade confidence
    if valid MPEG audio frames are found immediately after the tag."""
    if len(chunk) < 10 or chunk[:3] != b"ID3":
        return ValidationResult(False, "MP3_ID3", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing ID3", evidence_level=EvidenceLevel.MAGIC_ONLY)
    major = chunk[3]
    if major not in range(1, 5):
        return ValidationResult(False, "MP3_ID3", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Unknown ID3 version 2.{major}", evidence_level=EvidenceLevel.HEADER_PARSED)
    size_bytes = chunk[6:10]
    # Syncsafe integer
    tag_size = ((size_bytes[0] & 0x7F) << 21 | (size_bytes[1] & 0x7F) << 14 |
                (size_bytes[2] & 0x7F) << 7  |  (size_bytes[3] & 0x7F))

    audio_start = 10 + tag_size
    frames_note = ""
    level = EvidenceLevel.STRUCTURE_VALIDATED
    if 0 <= audio_start < len(chunk):
        frame_result = _validate_mp3_frames(chunk[audio_start:], "MP3_FRAME")
        if frame_result.valid:
            level = EvidenceLevel.CHECKSUM_VALID
            frames_note = f"; {frame_result.reason}"

    return ValidationResult(
        True, "MP3_ID3", confidence_for_evidence(level),
        f"Valid ID3v2.{major} tag, {tag_size:,} bytes{frames_note}",
        estimated_size=tag_size + 10,
        false_positive_risk="Low",
        evidence_level=level,
    )


def _validate_sqlite(chunk: bytes, _type: str) -> ValidationResult:
    """SQLite: 16-byte magic string."""
    MAGIC = b"SQLite format 3\x00"
    if not chunk.startswith(MAGIC):
        return ValidationResult(False, "SQLite", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing SQLite magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    if len(chunk) < 100:
        return ValidationResult(False, "SQLite", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                "Too short for SQLite header", evidence_level=EvidenceLevel.HEADER_PARSED)
    page_size = struct.unpack_from(">H", chunk, 16)[0]
    if page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
        return ValidationResult(False, "SQLite", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Unusual page size {page_size}", evidence_level=EvidenceLevel.HEADER_PARSED)
    return ValidationResult(
        True, "SQLite", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
        f"Valid SQLite3, page_size={page_size}",
        false_positive_risk="Very low",
        evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
    )


# ---------------------------------------------------------------------------
# MPEG audio frame validator (Phase 4) — real frame parsing, not magic bytes
# ---------------------------------------------------------------------------

_MPEG_VERSIONS = {0b00: "MPEG2.5", 0b10: "MPEG2", 0b11: "MPEG1"}   # 0b01 reserved
_MPEG_LAYERS   = {0b01: "Layer3", 0b10: "Layer2", 0b11: "Layer1"}  # 0b00 reserved

_SAMPLE_RATES = {
    "MPEG1":   {0b00: 44100, 0b01: 48000, 0b10: 32000},
    "MPEG2":   {0b00: 22050, 0b01: 24000, 0b10: 16000},
    "MPEG2.5": {0b00: 11025, 0b01: 12000, 0b10: 8000},
}

_BITRATES = {
    ("MPEG1", "Layer1"): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    ("MPEG1", "Layer2"): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    ("MPEG1", "Layer3"): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    ("MPEG2", "Layer1"): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    ("MPEG2", "Layer2"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ("MPEG2", "Layer3"): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
_BITRATES[("MPEG2.5", "Layer1")] = _BITRATES[("MPEG2", "Layer1")]
_BITRATES[("MPEG2.5", "Layer2")] = _BITRATES[("MPEG2", "Layer2")]
_BITRATES[("MPEG2.5", "Layer3")] = _BITRATES[("MPEG2", "Layer3")]


@dataclass
class _MP3Frame:
    version: str
    layer: str
    bitrate: int
    sample_rate: int
    padding: int
    protected: bool
    frame_length: int
    channel_mode: int


def _parse_mp3_frame(data: bytes, offset: int) -> Optional[_MP3Frame]:
    """Parse one MPEG audio frame header. Returns None if not a plausible frame."""
    if offset < 0 or offset + 4 > len(data):
        return None
    b0, b1, b2, b3 = data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return None  # no frame sync (11 bits: 1111 1111 111)

    version_bits = (b1 >> 3) & 0x03
    layer_bits   = (b1 >> 1) & 0x03
    protected    = (b1 & 0x01) == 0   # bit=1 means NOT protected; 0 means CRC follows
    version = _MPEG_VERSIONS.get(version_bits)
    layer   = _MPEG_LAYERS.get(layer_bits)
    if version is None or layer is None:
        return None

    bitrate_idx = (b2 >> 4) & 0x0F
    samp_idx    = (b2 >> 2) & 0x03
    padding     = (b2 >> 1) & 0x01
    if bitrate_idx in (0, 15):
        return None   # 'free' or 'bad' bitrate index — reject
    if samp_idx == 3:
        return None   # reserved sample-rate index

    bitrate = _BITRATES[(version, layer)][bitrate_idx] * 1000
    sample_rate = _SAMPLE_RATES[version][samp_idx]
    channel_mode = (b3 >> 6) & 0x03

    if layer == "Layer1":
        frame_length = (12 * bitrate // sample_rate + padding) * 4
    else:
        samples_per_frame = 144 if version == "MPEG1" else 72
        frame_length = samples_per_frame * bitrate // sample_rate + padding

    if frame_length < 21:   # smaller than the header itself is never valid
        return None

    return _MP3Frame(version, layer, bitrate, sample_rate, padding, protected, frame_length, channel_mode)


def _validate_mp3_frames(chunk: bytes, _type: str) -> ValidationResult:
    """
    Real MPEG audio frame validator (Phase 4).

    Checks frame sync, MPEG version, layer, bitrate, sample rate, computed
    frame size, and CRC-presence, then requires a minimum of 3 consecutive,
    mutually-consistent frames before treating the region as an actual
    embedded MP3 stream. An isolated frame-sync match (the 0xFFEx bit
    pattern occurs by chance fairly often in PCM/compressed audio) is
    rejected rather than reported as an embedded file.
    """
    first = _parse_mp3_frame(chunk, 0)
    if first is None:
        return ValidationResult(
            False, "MP3_FRAME", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            "Frame sync bits present but header fields invalid (bad bitrate/sample-rate/layer index)",
            false_positive_risk="High — 0xFFEx bit pattern occurs by chance in PCM/compressed audio",
            evidence_level=EvidenceLevel.MAGIC_ONLY,
        )

    frames = [first]
    pos = first.frame_length
    while len(frames) < 64 and pos + 4 <= len(chunk):
        nxt = _parse_mp3_frame(chunk, pos)
        # v4.3: also require constant sample rate across the run — bitrate
        # legitimately varies frame-to-frame in a real VBR stream, so it's
        # deliberately not checked here, but sample rate never changes
        # mid-stream in practice; requiring it agree too is one more
        # independent signal against a coincidental run of frame syncs
        # with plausible-but-unrelated headers.
        if (nxt is None or nxt.version != first.version or nxt.layer != first.layer
                or nxt.sample_rate != first.sample_rate):
            break
        frames.append(nxt)
        pos += nxt.frame_length

    n = len(frames)
    if n < 3:
        return ValidationResult(
            False, "MP3_FRAME", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            f"Only {n} consecutive valid frame(s) found (minimum 3 required) — "
            "isolated frame sync rejected, not classified as an embedded file",
            false_positive_risk="High — isolated sync pattern with no sustained stream",
            evidence_level=EvidenceLevel.MAGIC_ONLY,
        )

    crc_note = "CRC present (protected)" if first.protected else "no CRC (unprotected)"
    level = EvidenceLevel.CHECKSUM_VALID if n >= 10 else EvidenceLevel.STRUCTURE_VALIDATED
    return ValidationResult(
        True, "MP3_FRAME", confidence_for_evidence(level),
        f"{n} consecutive consistent {first.version} {first.layer} frames "
        f"@ {first.sample_rate}Hz {first.bitrate // 1000}kbps ({crc_note})",
        estimated_size=pos,
        false_positive_risk="Low" if n >= 10 else "Medium — short valid run",
        evidence_level=level,
    )


# ---------------------------------------------------------------------------
# AAC ADTS frame validator — same false-positive risk profile as MP3 frames
# ---------------------------------------------------------------------------

_ADTS_SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000,
                       22050, 16000, 12000, 11025, 8000, 7350]


def _parse_adts_frame(data: bytes, offset: int) -> Optional[dict]:
    if offset < 0 or offset + 7 > len(data):
        return None
    b0, b1, b2, b3, b4, b5 = data[offset:offset + 6]
    if b0 != 0xFF or (b1 & 0xF0) != 0xF0:
        return None
    protection_absent = b1 & 0x01
    profile = (b2 >> 6) & 0x03
    sf_idx  = (b2 >> 2) & 0x0F
    if sf_idx >= 13:
        return None
    channel_cfg = ((b2 & 0x01) << 2) | ((b3 >> 6) & 0x03)
    frame_length = ((b3 & 0x03) << 11) | (b4 << 3) | ((b5 >> 5) & 0x07)
    header_len = 7 if protection_absent else 9
    if frame_length < header_len or frame_length > 8191:
        return None
    return {
        "profile": profile,
        "sample_rate": _ADTS_SAMPLE_RATES[sf_idx],
        "channels": channel_cfg,
        "frame_length": frame_length,
        "protection_absent": bool(protection_absent),
    }


def _validate_aac_adts(chunk: bytes, _type: str) -> ValidationResult:
    """Real ADTS/AAC frame validator; rejects isolated sync bytes like MP3."""
    first = _parse_adts_frame(chunk, 0)
    if first is None:
        return ValidationResult(
            False, "AAC_ADTS", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            "ADTS sync present but header fields invalid",
            false_positive_risk="High — 0xFFFx bit pattern occurs by chance",
            evidence_level=EvidenceLevel.MAGIC_ONLY,
        )
    frames = [first]
    pos = first["frame_length"]
    while len(frames) < 64 and pos + 7 <= len(chunk):
        nxt = _parse_adts_frame(chunk, pos)
        if nxt is None or nxt["sample_rate"] != first["sample_rate"] or nxt["channels"] != first["channels"]:
            break
        frames.append(nxt)
        pos += nxt["frame_length"]

    n = len(frames)
    if n < 3:
        return ValidationResult(
            False, "AAC_ADTS", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
            f"Only {n} consecutive valid ADTS frame(s) — isolated sync rejected",
            false_positive_risk="High", evidence_level=EvidenceLevel.MAGIC_ONLY,
        )
    level = EvidenceLevel.CHECKSUM_VALID if n >= 10 else EvidenceLevel.STRUCTURE_VALIDATED
    return ValidationResult(
        True, "AAC_ADTS", confidence_for_evidence(level),
        f"{n} consecutive consistent ADTS frames @ {first['sample_rate']}Hz {first['channels']}ch",
        estimated_size=pos,
        false_positive_risk="Low" if n >= 10 else "Medium",
        evidence_level=level,
    )


# ---------------------------------------------------------------------------
# AIFF (hand-parsed — the stdlib aifc module is deprecated/removed upstream)
# ---------------------------------------------------------------------------

def _validate_aiff(chunk: bytes, _type: str) -> ValidationResult:
    if len(chunk) < 12 or chunk[:4] != b"FORM":
        return ValidationResult(False, "AIFF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing FORM header", evidence_level=EvidenceLevel.MAGIC_ONLY)
    form_size = struct.unpack_from(">I", chunk, 4)[0]
    form_type = chunk[8:12]
    if form_type not in (b"AIFF", b"AIFC"):
        return ValidationResult(False, "AIFF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"FORM present but type={form_type!r} is not AIFF/AIFC",
                                evidence_level=EvidenceLevel.HEADER_PARSED)

    pos = 12
    found_comm = False
    channels = frames = bits = 0
    while pos + 8 <= len(chunk) and pos < form_size + 8:
        cid = chunk[pos:pos + 4]
        try:
            csize = struct.unpack_from(">I", chunk, pos + 4)[0]
        except struct.error:
            break
        if cid == b"COMM" and pos + 16 <= len(chunk):
            channels = struct.unpack_from(">h", chunk, pos + 8)[0]
            frames = struct.unpack_from(">I", chunk, pos + 10)[0]
            bits = struct.unpack_from(">h", chunk, pos + 14)[0]
            found_comm = True
            break
        pos += 8 + csize + (csize % 2)

    if not found_comm:
        return ValidationResult(True, "AIFF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Valid FORM/{form_type.decode()} header, size={form_size:,}; COMM chunk not located",
                                estimated_size=form_size + 8,
                                false_positive_risk="Medium", evidence_level=EvidenceLevel.HEADER_PARSED)

    plausible = 1 <= channels <= 8 and 0 < bits <= 32
    level = EvidenceLevel.STRUCTURE_VALIDATED if plausible else EvidenceLevel.HEADER_PARSED
    return ValidationResult(
        plausible, "AIFF", confidence_for_evidence(level),
        (f"FORM/{form_type.decode()} COMM: {channels}ch {bits}-bit, {frames} frames" if plausible
         else f"COMM chunk has implausible values: channels={channels} bits={bits}"),
        estimated_size=form_size + 8,
        false_positive_risk="Low" if plausible else "High",
        evidence_level=level,
    )


# ---------------------------------------------------------------------------
# TAR (ustar) — checksum-verified
# ---------------------------------------------------------------------------

def _validate_tar(chunk: bytes, _type: str) -> ValidationResult:
    """`chunk` is already back-offset corrected to the 512-byte header start."""
    if len(chunk) < 512:
        return ValidationResult(False, "TAR", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short for a full tar header block", evidence_level=EvidenceLevel.MAGIC_ONLY)
    magic = chunk[257:263]
    if magic not in (b"ustar\x00", b"ustar "):
        return ValidationResult(False, "TAR", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                f"ustar magic not found at expected offset (got {magic!r})",
                                evidence_level=EvidenceLevel.MAGIC_ONLY)
    try:
        raw = chunk[148:156].split(b"\x00")[0].strip().rstrip(b" ")
        stored = int(raw or b"0", 8)
    except ValueError:
        return ValidationResult(False, "TAR", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                "Checksum field is not valid octal", evidence_level=EvidenceLevel.HEADER_PARSED)

    header = bytearray(chunk[:512])
    header[148:156] = b" " * 8
    computed = sum(header)
    if computed != stored:
        return ValidationResult(False, "TAR", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Header checksum mismatch (stored={stored}, computed={computed})",
                                false_positive_risk="High", evidence_level=EvidenceLevel.HEADER_PARSED)

    name = chunk[:100].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return ValidationResult(
        True, "TAR", confidence_for_evidence(EvidenceLevel.CHECKSUM_VALID),
        f"Valid ustar header, checksum verified, first member '{name}'",
        estimated_size=512, false_positive_risk="Low — header checksum matched",
        evidence_level=EvidenceLevel.CHECKSUM_VALID,
    )


# ---------------------------------------------------------------------------
# BZIP2
# ---------------------------------------------------------------------------

def _validate_bzip2(chunk: bytes, _type: str) -> ValidationResult:
    if len(chunk) < 4 or chunk[:3] != b"BZh":
        return ValidationResult(False, "BZIP2", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing BZh magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    level_digit = chunk[3:4]
    if not level_digit.isdigit() or level_digit == b"0":
        return ValidationResult(False, "BZIP2", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Invalid block-size digit {level_digit!r}", evidence_level=EvidenceLevel.HEADER_PARSED)
    import bz2
    try:
        bz2.BZ2Decompressor().decompress(chunk[:min(len(chunk), 2_000_000)])
        return ValidationResult(True, "BZIP2", confidence_for_evidence(EvidenceLevel.PARSED_OPENED),
                                f"Valid bzip2 stream, block size {level_digit.decode()}00k, decompression succeeded",
                                false_positive_risk="Low", evidence_level=EvidenceLevel.PARSED_OPENED)
    except Exception as e:
        return ValidationResult(True, "BZIP2", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Valid bzip2 header but decompression check inconclusive: {e}",
                                false_positive_risk="Medium", evidence_level=EvidenceLevel.HEADER_PARSED)


# ---------------------------------------------------------------------------
# XZ — stream-header CRC32 verified
# ---------------------------------------------------------------------------

def _validate_xz(chunk: bytes, _type: str) -> ValidationResult:
    MAGIC = b"\xfd7zXZ\x00"
    if len(chunk) < 12 or chunk[:6] != MAGIC:
        return ValidationResult(False, "XZ", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing XZ magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    flags = chunk[6:8]
    stored_crc = struct.unpack_from("<I", chunk, 8)[0]
    actual_crc = zlib.crc32(flags) & 0xFFFFFFFF
    if actual_crc != stored_crc:
        return ValidationResult(False, "XZ", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Stream header CRC32 mismatch (got {actual_crc:08x}, expected {stored_crc:08x})",
                                false_positive_risk="High", evidence_level=EvidenceLevel.HEADER_PARSED)
    import lzma
    try:
        lzma.LZMADecompressor().decompress(chunk[:min(len(chunk), 2_000_000)])
        level = EvidenceLevel.PARSED_OPENED
        reason = "Stream header CRC32 valid; decompression succeeded"
    except Exception as e:
        level = EvidenceLevel.CHECKSUM_VALID
        reason = f"Stream header CRC32 valid; decompression inconclusive: {e}"
    return ValidationResult(True, "XZ", confidence_for_evidence(level), reason,
                            false_positive_risk="Low", evidence_level=level)


# ---------------------------------------------------------------------------
# TIFF
# ---------------------------------------------------------------------------

def _validate_tiff(chunk: bytes, _type: str) -> ValidationResult:
    if len(chunk) < 8:
        return ValidationResult(False, "TIFF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Too short for TIFF header", evidence_level=EvidenceLevel.MAGIC_ONLY)
    order = chunk[:2]
    if order not in (b"II", b"MM"):
        return ValidationResult(False, "TIFF", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "Bad byte-order marker", evidence_level=EvidenceLevel.MAGIC_ONLY)
    fmt = "<" if order == b"II" else ">"
    magic_num = struct.unpack_from(fmt + "H", chunk, 2)[0]
    if magic_num != 42:
        return ValidationResult(False, "TIFF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Byte order ok but magic number={magic_num} != 42", evidence_level=EvidenceLevel.HEADER_PARSED)
    ifd_offset = struct.unpack_from(fmt + "I", chunk, 4)[0]
    if ifd_offset < 8 or ifd_offset + 2 > len(chunk):
        return ValidationResult(True, "TIFF", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Valid TIFF header ({'little' if order==b'II' else 'big'}-endian); "
                                f"IFD offset {ifd_offset} out of captured range",
                                evidence_level=EvidenceLevel.HEADER_PARSED)
    num_entries = struct.unpack_from(fmt + "H", chunk, ifd_offset)[0]
    plausible = 1 <= num_entries <= 200
    level = EvidenceLevel.STRUCTURE_VALIDATED if plausible else EvidenceLevel.HEADER_PARSED
    return ValidationResult(
        plausible, "TIFF", confidence_for_evidence(level),
        (f"Valid TIFF, IFD at 0x{ifd_offset:x} with {num_entries} entries" if plausible
         else f"IFD entry count implausible: {num_entries}"),
        false_positive_risk="Low" if plausible else "High", evidence_level=level,
    )


# ---------------------------------------------------------------------------
# PE (Windows executable)
# ---------------------------------------------------------------------------

def _validate_pe(chunk: bytes, _type: str) -> ValidationResult:
    if len(chunk) < 64 or chunk[:2] != b"MZ":
        return ValidationResult(False, "PE", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                 "Missing MZ magic", evidence_level=EvidenceLevel.MAGIC_ONLY)
    e_lfanew = struct.unpack_from("<I", chunk, 60)[0]
    if e_lfanew < 64 or e_lfanew + 24 > len(chunk):
        return ValidationResult(False, "PE", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"MZ header present but e_lfanew={e_lfanew} is implausible/out of range",
                                false_positive_risk="High — 'MZ' is a common 2-byte pattern",
                                evidence_level=EvidenceLevel.HEADER_PARSED)
    if chunk[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return ValidationResult(False, "PE", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"MZ header present but no PE signature at e_lfanew=0x{e_lfanew:x}",
                                false_positive_risk="High", evidence_level=EvidenceLevel.HEADER_PARSED)
    machine = struct.unpack_from("<H", chunk, e_lfanew + 4)[0]
    machines = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    return ValidationResult(
        True, "PE", confidence_for_evidence(EvidenceLevel.STRUCTURE_VALIDATED),
        f"Valid MZ+PE header, machine={machines.get(machine, hex(machine))}",
        false_positive_risk="Low", evidence_level=EvidenceLevel.STRUCTURE_VALIDATED,
    )


# ---------------------------------------------------------------------------
# M4A / MP4 (ISOBMFF) — offset is back-corrected to the ftyp box-size field
# ---------------------------------------------------------------------------

_MP4_BRANDS = {b"M4A ", b"M4B ", b"mp42", b"mp41", b"isom", b"iso2", b"iso4",
               b"iso5", b"iso6", b"qt  ", b"3gp4", b"3gp5", b"dash", b"avc1"}


def _validate_m4a(chunk: bytes, _type: str) -> ValidationResult:
    if len(chunk) < 16 or chunk[4:8] != b"ftyp":
        return ValidationResult(False, "M4A_MP4", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "ftyp atom marker not at expected position", evidence_level=EvidenceLevel.MAGIC_ONLY)
    box_size = struct.unpack_from(">I", chunk, 0)[0]
    major_brand = chunk[8:12]
    if box_size < 16 or box_size > len(chunk) + 1_000_000:
        return ValidationResult(False, "M4A_MP4", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"ftyp box size implausible: {box_size}", evidence_level=EvidenceLevel.HEADER_PARSED)

    plausible_brand = major_brand in _MP4_BRANDS or major_brand.strip(b"\x00 ").isalnum()
    if not plausible_brand:
        return ValidationResult(False, "M4A_MP4", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                f"ftyp brand={major_brand!r} is not plausible", evidence_level=EvidenceLevel.MAGIC_ONLY)

    found_next = False
    next_type = b""
    pos = box_size
    if pos + 8 <= len(chunk):
        next_type = chunk[pos + 4:pos + 8]
        if next_type in (b"moov", b"mdat", b"free", b"skip", b"wide", b"udta"):
            found_next = True

    level = EvidenceLevel.STRUCTURE_VALIDATED if found_next else EvidenceLevel.HEADER_PARSED
    return ValidationResult(
        True, "M4A_MP4", confidence_for_evidence(level),
        f"ftyp brand={major_brand!r}, box_size={box_size}"
        + (f", followed by '{next_type.decode(errors='replace')}' box" if found_next
           else ", no recognised follow-on box found"),
        false_positive_risk="Low" if found_next else "Medium",
        evidence_level=level,
    )


# ---------------------------------------------------------------------------
# JSON — not wired into the raw magic-byte scanner (no safe anchor sequence;
# a bare '{' is far too common in binary data to scan for). Callable directly
# for explicitly-typed inputs, e.g. base64-decoded payloads in the encoding
# engine.
# ---------------------------------------------------------------------------

def _validate_json(chunk: bytes, _type: str) -> ValidationResult:
    window = chunk[:200_000]
    try:
        text = window.decode("utf-8")
    except UnicodeDecodeError:
        return ValidationResult(False, "JSON", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "Not valid UTF-8", evidence_level=EvidenceLevel.MAGIC_ONLY)
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        return ValidationResult(False, "JSON", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "Does not start with { or [", evidence_level=EvidenceLevel.MAGIC_ONLY)
    try:
        obj, end = json.JSONDecoder().raw_decode(stripped)
    except json.JSONDecodeError as e:
        return ValidationResult(False, "JSON", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Starts like JSON but failed to parse: {e}", evidence_level=EvidenceLevel.HEADER_PARSED)
    if not isinstance(obj, (dict, list)) or len(obj) == 0:
        return ValidationResult(False, "JSON", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                "Parsed but produced an empty/non-container JSON value",
                                evidence_level=EvidenceLevel.HEADER_PARSED)
    kind = "object" if isinstance(obj, dict) else "array"
    return ValidationResult(True, "JSON", confidence_for_evidence(EvidenceLevel.PARSED_OPENED),
                            f"Valid JSON {kind} with {len(obj)} top-level element(s)",
                            estimated_size=end, false_positive_risk="Low — full JSON parse succeeded",
                            evidence_level=EvidenceLevel.PARSED_OPENED)


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------

def _validate_xml(chunk: bytes, _type: str) -> ValidationResult:
    window = chunk[:200_000]   # bounds worst-case entity-expansion cost
    try:
        text = window.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ValidationResult(False, "XML", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "Not valid UTF-8", evidence_level=EvidenceLevel.MAGIC_ONLY)
    stripped = text.lstrip()
    if not stripped.startswith("<?xml") and not stripped.startswith("<"):
        return ValidationResult(False, "XML", confidence_for_evidence(EvidenceLevel.MAGIC_ONLY),
                                "Does not start with an XML declaration or tag", evidence_level=EvidenceLevel.MAGIC_ONLY)
    import xml.etree.ElementTree as ET
    last_close = text.rfind(">")
    candidate = text[:last_close + 1] if last_close != -1 else text
    try:
        ET.fromstring(candidate)
    except ET.ParseError as e:
        return ValidationResult(False, "XML", confidence_for_evidence(EvidenceLevel.HEADER_PARSED),
                                f"Starts like XML but failed to parse: {e}", evidence_level=EvidenceLevel.HEADER_PARSED)
    return ValidationResult(True, "XML", confidence_for_evidence(EvidenceLevel.PARSED_OPENED),
                            "Well-formed XML document parsed successfully",
                            estimated_size=len(candidate), false_positive_risk="Low — full XML parse succeeded",
                            evidence_level=EvidenceLevel.PARSED_OPENED)
