"""
Metadata extraction module for Audio Stego Solver.
Runs file, exiftool, mediainfo, ffprobe and collects file info.
"""

import json
import os
from typing import Any, Dict

from .logger import get_logger
from .utils import file_hash, run_command, save_text, tool_available

logger = get_logger("audio_stego.metadata")


class MetadataAnalyzer:
    """Extracts metadata from audio files using multiple tools."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.tools_dir = os.path.join(output_dir, "tools")
        os.makedirs(self.tools_dir, exist_ok=True)
        self.results: Dict[str, Any] = {}

    def run(self, audio_path: str) -> Dict[str, Any]:
        """Run all metadata extraction on the given audio file."""
        logger.info(f"Starting metadata analysis for: {audio_path}")
        self.results = {
            "file_path": audio_path,
            "file_size": os.path.getsize(audio_path),
            "hashes": {},
            "file_cmd": "",
            "exiftool": {},
            "mediainfo": "",
            "ffprobe": {},
            "warnings": [],
        }

        logger.debug("Computing file hashes")
        self.results["hashes"] = file_hash(audio_path)

        self._run_file_cmd(audio_path)
        self._run_exiftool(audio_path)
        self._run_mediainfo(audio_path)
        self._run_ffprobe(audio_path)
        self._save_metadata_report(audio_path)

        logger.info("Metadata analysis complete")
        return self.results

    def _run_file_cmd(self, path: str):
        """Run the `file` command."""
        if not tool_available("file"):
            self.results["warnings"].append("Tool not found: file")
            return

        rc, out, err = run_command(["file", path], timeout=10)
        self.results["file_cmd"] = out.strip()

        out_path = os.path.join(self.tools_dir, "fileinfo.txt")
        save_text(out_path, f"file {path}\n{'='*60}\n{out}\n\nSTDERR:\n{err}")
        logger.info(f"Saved fileinfo to {out_path}")

    def _run_exiftool(self, path: str):
        """Run exiftool for detailed metadata."""
        if not tool_available("exiftool"):
            self.results["warnings"].append("Tool not found: exiftool")
            return

        rc, out, err = run_command(["exiftool", "-j", path], timeout=30)

        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
                if isinstance(data, list) and data:
                    self.results["exiftool"] = data[0]
            except json.JSONDecodeError:
                self.results["exiftool"] = {"raw": out}

        rc2, out2, _ = run_command(["exiftool", path], timeout=30)
        combined = f"=== exiftool JSON ===\n{out}\n\n=== exiftool Text ===\n{out2}\n\nSTDERR:\n{err}"
        out_path = os.path.join(self.tools_dir, "exiftool.txt")
        save_text(out_path, combined)
        logger.info(f"Saved exiftool metadata to {out_path}")

    def _run_mediainfo(self, path: str):
        """Run mediainfo."""
        if not tool_available("mediainfo"):
            self.results["warnings"].append("Tool not found: mediainfo")
            return

        rc, out, err = run_command(["mediainfo", path], timeout=30)
        self.results["mediainfo"] = out

        rc2, out2, _ = run_command(["mediainfo", "--Output=JSON", path], timeout=30)
        combined = f"=== mediainfo Text ===\n{out}\n\n=== mediainfo JSON ===\n{out2}\n\nSTDERR:\n{err}"

        out_path = os.path.join(self.tools_dir, "mediainfo.txt")
        save_text(out_path, combined)
        logger.info(f"Saved mediainfo output to {out_path}")

    def _run_ffprobe(self, path: str):
        """Run ffprobe for stream information."""
        if not tool_available("ffprobe"):
            self.results["warnings"].append("Tool not found: ffprobe")
            return

        cmd = [
            "ffprobe", "-v", "quiet",
            "-print_format", "json",
            "-show_format", "-show_streams", "-show_chapters",
            path,
        ]
        rc, out, err = run_command(cmd, timeout=30)

        if rc == 0 and out.strip():
            try:
                self.results["ffprobe"] = json.loads(out)
            except json.JSONDecodeError:
                self.results["ffprobe"] = {"raw": out}

        rc2, out2, err2 = run_command(["ffprobe", "-v", "verbose", path], timeout=30)
        combined = f"=== ffprobe JSON ===\n{out}\n\n=== ffprobe Verbose ===\n{err2}\n\nSTDERR:\n{err}"
        out_path = os.path.join(self.tools_dir, "ffprobe.txt")
        save_text(out_path, combined)
        logger.info(f"Saved ffprobe output to {out_path}")

    def _save_metadata_report(self, path: str):
        """Write a consolidated metadata report."""
        lines = []
        lines.append("=" * 70)
        lines.append("AUDIO STEGO SOLVER - METADATA REPORT")
        lines.append("=" * 70)
        lines.append(f"File: {path}")
        lines.append(f"Size: {self.results['file_size']} bytes")

        hashes = self.results.get("hashes", {})
        lines.append(f"MD5:    {hashes.get('md5', 'N/A')}")
        lines.append(f"SHA1:   {hashes.get('sha1', 'N/A')}")
        lines.append(f"SHA256: {hashes.get('sha256', 'N/A')}")

        lines.append("\n--- file ---")
        lines.append(self.results.get("file_cmd", "N/A"))

        lines.append("\n--- exiftool (key fields) ---")
        exif = self.results.get("exiftool", {})
        interesting_fields = [
            "FileType", "MIMEType", "AudioFormat", "AudioBitrate",
            "SampleRate", "Channels", "Duration", "BitDepth",
            "EncoderSettings", "Comment", "Description", "Title",
            "Artist", "Album", "Date", "Software", "Warning",
        ]
        for field in interesting_fields:
            if field in exif:
                lines.append(f"  {field}: {exif[field]}")

        lines.append("\n--- ffprobe streams ---")
        ffp = self.results.get("ffprobe", {})
        for stream in ffp.get("streams", []):
            lines.append(
                f"  Stream #{stream.get('index', '?')}: "
                f"{stream.get('codec_type', '?')} / "
                f"{stream.get('codec_name', '?')} "
                f"@ {stream.get('sample_rate', '?')} Hz"
            )

        fmt = ffp.get("format", {})
        if fmt:
            lines.append(f"\n--- ffprobe format ---")
            lines.append(f"  Format: {fmt.get('format_name', 'N/A')}")
            lines.append(f"  Duration: {fmt.get('duration', 'N/A')}s")
            lines.append(f"  Bit rate: {fmt.get('bit_rate', 'N/A')}")
            tags = fmt.get("tags", {})
            if tags:
                lines.append("  Tags:")
                for k, v in tags.items():
                    lines.append(f"    {k}: {v}")

        if self.results.get("warnings"):
            lines.append("\n--- Warnings ---")
            for w in self.results["warnings"]:
                lines.append(f"  ! {w}")

        out_path = os.path.join(self.output_dir, "metadata.txt")
        save_text(out_path, "\n".join(lines))
        logger.info(f"Saved consolidated metadata to {out_path}")

    def get_interesting_tags(self) -> Dict[str, str]:
        """Extract potentially interesting metadata tags for reporting."""
        interesting = {}
        exif = self.results.get("exiftool", {})
        suspect_keys = [
            "Comment", "Description", "Title", "Artist", "Album",
            "EncoderSettings", "Software", "Warning", "Error",
        ]
        for key in suspect_keys:
            if key in exif:
                interesting[key] = str(exif[key])

        ffp = self.results.get("ffprobe", {})
        for tag, val in ffp.get("format", {}).get("tags", {}).items():
            interesting[f"ffprobe:{tag}"] = str(val)

        return interesting
