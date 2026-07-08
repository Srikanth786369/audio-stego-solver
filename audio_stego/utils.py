"""
Utility functions for Audio Stego Solver.
Shared helpers used across all modules.
"""

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .logger import get_logger

logger = get_logger("audio_stego.utils")

# Magic bytes for file type detection
FILE_MAGIC: Dict[str, bytes] = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "PDF": b"%PDF",
    "ZIP": b"PK\x03\x04",
    "RAR": b"Rar!\x1a\x07",
    "7Z": b"7z\xbc\xaf'\x1c",
    "WAV": b"RIFF",
    "MP3_ID3": b"ID3",
    "MP3_FRAME": b"\xff\xfb",
    "OGG": b"OggS",
    "FLAC": b"fLaC",
    "GIF": b"GIF8",
    "BMP": b"BM",
    "TIFF": b"II*\x00",
    "ELF": b"\x7fELF",
    "TAR_GZ": b"\x1f\x8b",
    "TAR_BZ2": b"BZh",
    "SQLITE": b"SQLite format 3",
    "PE": b"MZ",
    "XZ": b"\xfd7zXZ\x00",
    "TAR": b"ustar",
    "M4A_MP4": b"ftyp",
    "AIFF": b"FORM",
    "AAC_ADTS_MPEG4": b"\xff\xf1",
    "AAC_ADTS_MPEG2": b"\xff\xf9",
    "XML": b"<?xml",
    # JSON is intentionally not registered here: it has no reliable magic-byte
    # anchor (a bare '{' occurs constantly in binary/audio data), so scanning
    # for it would flood results with false positives. The JSON validator in
    # validate.py is still available for explicitly-typed inputs (e.g. the
    # encoding engine handing it a base64-decoded payload).
}


def run_command(
    cmd: List[str],
    timeout: int = 60,
    capture_output: bool = True,
    input_data: Optional[bytes] = None,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run a shell command and return (returncode, stdout, stderr).

    Args:
        cmd: Command and arguments as list
        timeout: Timeout in seconds
        capture_output: Capture stdout/stderr
        input_data: Optional stdin data
        cwd: Working directory

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            timeout=timeout,
            input=input_data,
            cwd=cwd,
            text=True,
            errors="replace",
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        logger.warning(f"Command not found: {cmd[0]}")
        return -127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        logger.error(f"Command failed {' '.join(cmd)}: {e}")
        return -1, "", str(e)


def tool_available(name: str) -> bool:
    """Check if a command-line tool is available in PATH."""
    return shutil.which(name) is not None


def check_tools(tools: List[str]) -> Dict[str, bool]:
    """Check availability of multiple tools."""
    return {tool: tool_available(tool) for tool in tools}


def file_hash(path: str) -> Dict[str, str]:
    """Compute MD5, SHA1, SHA256 hashes of a file."""
    hashes: Dict[str, str] = {}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha1"] = sha1.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        logger.error(f"Hashing failed for {path}: {e}")
    return hashes


def detect_file_type_by_magic(path: str) -> Optional[str]:
    """Detect file type using magic bytes."""
    try:
        with open(path, "rb") as f:
            header = f.read(32)
        for name, magic in FILE_MAGIC.items():
            if header.startswith(magic):
                return name
    except Exception as e:
        logger.error(f"Magic detection failed for {path}: {e}")
    return None


def find_embedded_files(data: bytes) -> List[Dict]:
    """
    Scan binary data for embedded file signatures.

    Returns list of dicts with 'type', 'offset', 'magic'.
    """
    found = []
    for name, magic in FILE_MAGIC.items():
        offset = 0
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            found.append({"type": name, "offset": idx, "magic": magic.hex()})
            offset = idx + 1
    found.sort(key=lambda x: x["offset"])
    return found


def save_text(path: str, content: str):
    """Save text content to file, creating parent dirs as needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)


def save_bytes(path: str, content: bytes):
    """Save binary content to file, creating parent dirs as needed."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def read_bytes(path: str, max_bytes: int = 0) -> bytes:
    """Read bytes from file, optionally limited to max_bytes."""
    try:
        with open(path, "rb") as f:
            if max_bytes:
                return f.read(max_bytes)
            return f.read()
    except Exception as e:
        logger.error(f"Failed to read {path}: {e}")
        return b""


def human_size(n: int) -> str:
    """Convert byte count to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def safe_filename(name: str) -> str:
    """Sanitize a string to be safe as a filename."""
    import re
    return re.sub(r"[^\w\-_\.]", "_", name)


def elapsed(start: float) -> str:
    """Return elapsed time as human-readable string."""
    secs = time.time() - start
    if secs < 60:
        return f"{secs:.1f}s"
    mins = int(secs // 60)
    secs = secs % 60
    return f"{mins}m {secs:.0f}s"


def recursive_file_search(directory: str) -> List[str]:
    """Recursively find all files under a directory."""
    files = []
    for root, _, filenames in os.walk(directory):
        for fn in filenames:
            files.append(os.path.join(root, fn))
    return files
