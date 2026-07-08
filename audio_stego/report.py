"""
Report generation module for Audio Stego Solver.
Generates the final comprehensive report.txt from all analysis results.
"""

import os
import time
from datetime import datetime
from typing import Any, Dict, List

from .logger import get_logger
from .utils import human_size, recursive_file_search, save_text

logger = get_logger("audio_stego.report")

REPORT_SEPARATOR = "=" * 72
SECTION_SEPARATOR = "-" * 72

MANUAL_STEPS = """
SUGGESTED MANUAL NEXT STEPS
════════════════════════════

1. SPECTROGRAM REVIEW
   - Open spectrogram.png and look for hidden text/images at unusual frequencies
   - Pay attention to frequencies above 18kHz (beyond normal hearing)
   - Look for patterns in the lower frequency range too (SubRosa)
   - Tool: Sonic Visualiser (open source) for interactive inspection

2. CHANNEL DIFFERENCES
   - Subtract left from right channel to reveal steganographic LSB differences
     sox challenge.wav -c1 left.wav remix 1
     sox challenge.wav -c1 right.wav remix 2
     sox -m left.wav right.wav diff.wav

3. LSB ANALYSIS
   - Try StegSolve equivalent for audio: analyze least significant bits
   - Tools: audacity (view individual samples), python scipy/numpy manual analysis

4. PHASE ENCODING
   - Phase coding hides data in phase shifts between audio segments
     Python: librosa phase analysis

5. ECHO HIDING
   - Echo steganography adds imperceptible echoes
   - Cepstrum analysis can reveal echo patterns
     sox challenge.wav -n stat

6. DEEP STEGHIDE / OUTGUESS
   - outguess -r challenge.mp3 output.txt
   - Try additional passphrases from context (artist name, title, comment field)

7. AUDIO METADATA DEEP DIVE
   - Check ID3v2 frames for custom/private tags:
     id3v2 -l challenge.mp3
   - Look for APIC (album art), PRIV (private), TXXX (custom) frames

8. REVERSE AUDIO
   - Sometimes messages are played backwards
     sox challenge.wav reversed.wav reverse

9. SPEED CHANGES
   - Try 2x or 0.5x speed playback for hidden Morse/voice messages
     sox challenge.wav fast.wav speed 2.0

10. FREQUENCY SHIFT
    - Try demodulating AM/FM encoding
      GNU Radio or inspectrum

11. BIT PLANE ANALYSIS
    - Manually extract LSBs from all audio samples:
      python3 -c "
      import librosa, numpy as np
      y, sr = librosa.load('challenge.wav', sr=None)
      samples = (y * 32768).astype(np.int16)
      bits = ''.join(bin(s & 1)[2:] for s in samples)
      chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8)]
      print(''.join(c for c in chars if 32 <= ord(c) < 127))
      "

12. STATISTICAL ANALYSIS
    - Compare audio statistics to typical distributions
    - High regularity in samples can indicate steganography
      python3 -c "
      import librosa, numpy as np
      y, sr = librosa.load('challenge.wav', sr=None)
      print('Mean:', np.mean(y), 'Std:', np.std(y))
      print('LSB zeros:', sum(1 for s in y if s == 0))
      "

13. DUAL CHANNEL STEGANOGRAPHY
    - Some tools hide in stereo channel differences
      ffmpeg -i challenge.wav -filter_complex '[0:a]channelsplit=channel_layout=stereo[L][R]' \\
        -map '[L]' left.wav -map '[R]' right.wav

14. MIDI/NOTE ENCODING
    - Convert audio to MIDI and look for unusual note patterns
      audio-to-midi tools or manual note reading from spectrogram

15. BRUTE FORCE WITH CUSTOM WORDLISTS
    - Create domain-specific wordlist from found metadata:
      echo "$(artist) $(title) $(year)" > custom.txt
      stegseek challenge.wav custom.txt
"""


class ReportGenerator:
    """Generates comprehensive analysis reports."""

    def __init__(self, config, output_dir: str):
        self.config = config
        self.output_dir = output_dir
        self.start_time = time.time()

    def generate(
        self,
        audio_path: str,
        all_results: Dict[str, Any],
        elapsed_time: float,
    ) -> str:
        """
        Generate the final report.txt.

        Args:
            audio_path: Path to analyzed audio file
            all_results: Combined results from all analyzers
            elapsed_time: Total analysis time in seconds

        Returns:
            Path to the generated report file
        """
        logger.info("Generating final report")
        lines = []

        lines += self._header(audio_path, elapsed_time)
        lines += self._section_summary(all_results)
        lines += self._section_metadata(all_results.get("metadata", {}))
        lines += self._section_binary(all_results.get("binary", {}))
        lines += self._section_extraction(all_results.get("extraction", {}))
        lines += self._section_digital(all_results.get("digital", {}))
        lines += self._section_ocr(all_results.get("ocr", {}))
        lines += self._section_flags(all_results.get("flags", {}))
        lines += self._section_files(all_results)
        lines += self._section_warnings(all_results)
        lines += self._section_manual_steps()

        report_text = "\n".join(lines)
        out_path = os.path.join(self.output_dir, "report.txt")
        save_text(out_path, report_text)
        logger.info(f"Final report saved to {out_path}")
        return out_path

    def _header(self, audio_path: str, elapsed: float) -> List[str]:
        """Generate report header."""
        lines = [
            REPORT_SEPARATOR,
            " AUDIO STEGO SOLVER - ANALYSIS REPORT",
            REPORT_SEPARATOR,
            f" Date/Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f" File      : {audio_path}",
            f" Duration  : {elapsed:.1f} seconds",
            f" Output Dir: {self.output_dir}",
            REPORT_SEPARATOR,
            "",
        ]
        return lines

    def _section_summary(self, results: Dict) -> List[str]:
        """Generate executive summary."""
        flags = results.get("flags", {}).get("flags_found", [])
        extraction = results.get("extraction", {})
        digital = results.get("digital", {})
        binary = results.get("binary", {})

        lines = [
            "EXECUTIVE SUMMARY",
            SECTION_SEPARATOR,
        ]

        # Flag status
        if flags:
            lines.append(f"  [!!!] POTENTIAL FLAGS FOUND: {len(flags)}")
            for f in flags[:5]:
                lines.append(f"        >> {f.get('value', 'N/A')} ({f.get('encoding', 'plaintext')})")
        else:
            lines.append("  [ ] No flag patterns detected automatically")

        # Key findings
        findings = []

        binwalk = extraction.get("binwalk", [])
        if binwalk:
            findings.append(f"binwalk found {len(binwalk)} embedded signatures")

        extracted = extraction.get("extracted_files", [])
        if extracted:
            findings.append(f"{len(extracted)} files extracted from audio")

        steghide = extraction.get("steghide", [])
        if steghide:
            findings.append(f"steghide extracted hidden data!")

        stegseek = extraction.get("stegseek", {})
        if isinstance(stegseek, dict) and stegseek.get("file"):
            findings.append(f"stegseek cracked steghide passphrase!")

        embedded = binary.get("embedded_files", [])
        if embedded:
            findings.append(f"{len(embedded)} embedded file magic signatures found")

        appended = binary.get("appended_data", {})
        if appended and appended.get("detected"):
            findings.append(
                f"Possible appended data: {appended.get('extra_bytes', 0)} extra bytes"
            )

        morse = digital.get("morse", [])
        if morse:
            findings.append(f"Morse code detected!")

        dtmf = digital.get("dtmf", [])
        if dtmf:
            findings.append(f"DTMF tones detected: {dtmf[0].get('digits', '')}")

        multimon = digital.get("multimon", {})
        if isinstance(multimon, dict) and multimon.get("output", "").strip():
            findings.append(f"multimon-ng decoded digital signals")

        minimodem = digital.get("minimodem", [])
        if minimodem:
            findings.append(f"minimodem decoded modem data at {minimodem[0].get('baud')} baud")

        ocr = results.get("ocr", {}).get("ocr", [])
        if ocr:
            findings.append(f"OCR extracted text from {len(ocr)} images")

        qr = results.get("ocr", {}).get("qr_codes", [])
        if qr:
            findings.append(f"QR/barcode data found in {len(qr)} images!")

        encoded = binary.get("encoded_data", {})
        if encoded.get("base64_decoded"):
            findings.append(f"Base64 encoded data decoded successfully")

        if findings:
            lines.append("\n  Key Findings:")
            for f in findings:
                lines.append(f"    [+] {f}")
        else:
            lines.append("\n  No significant findings detected automatically.")
            lines.append("  Review manual steps section for next actions.")

        lines.append("")
        return lines

    def _section_metadata(self, metadata: Dict) -> List[str]:
        """Metadata section."""
        if not metadata:
            return []

        lines = ["", "METADATA", SECTION_SEPARATOR]

        hashes = metadata.get("hashes", {})
        if hashes:
            lines.append(f"  MD5:    {hashes.get('md5', 'N/A')}")
            lines.append(f"  SHA256: {hashes.get('sha256', 'N/A')}")

        file_cmd = metadata.get("file_cmd", "")
        if file_cmd:
            lines.append(f"  Type:   {file_cmd}")

        exif = metadata.get("exiftool", {})
        interesting = {
            "Duration": exif.get("Duration"),
            "SampleRate": exif.get("SampleRate"),
            "Channels": exif.get("Channels"),
            "BitDepth": exif.get("BitDepth"),
            "Comment": exif.get("Comment"),
            "Artist": exif.get("Artist"),
            "Title": exif.get("Title"),
            "Software": exif.get("Software"),
        }
        for key, val in interesting.items():
            if val:
                lines.append(f"  {key}: {val}")

        # Interesting tags
        tags = metadata.get("interesting_tags", {})
        if tags:
            lines.append("\n  [!] Potentially interesting metadata:")
            for k, v in tags.items():
                lines.append(f"      {k}: {v[:100]}")

        lines.append("")
        return lines

    def _section_binary(self, binary: Dict) -> List[str]:
        """Binary analysis section."""
        if not binary:
            return []

        lines = ["", "BINARY ANALYSIS", SECTION_SEPARATOR]

        entropy = binary.get("entropy", {})
        if entropy:
            overall = entropy.get("overall", 0)
            lines.append(f"  Overall entropy: {overall:.4f} bits/byte")
            if overall > 7.5:
                lines.append("  [!] HIGH entropy - may indicate encryption or compression")
            anomalies = entropy.get("anomalous_blocks", [])
            if anomalies:
                lines.append(f"  [!] {len(anomalies)} blocks with anomalous entropy")

        embedded = binary.get("embedded_files", [])
        if embedded:
            lines.append(f"\n  Embedded file signatures ({len(embedded)} found):")
            for e in embedded[:10]:
                lines.append(f"    {e['type']} @ offset 0x{int(e['offset']):08x}")

        appended = binary.get("appended_data", {})
        if appended and appended.get("detected"):
            lines.append(
                f"\n  [!] Possible appended data: "
                f"{appended.get('extra_bytes', 0)} bytes "
                f"after expected audio end @ offset {appended.get('offset', 0)}"
            )

        encoded = binary.get("encoded_data", {})
        for enc_type, items in encoded.items():
            if items and enc_type != "base64_decoded":
                lines.append(f"\n  {enc_type} patterns: {len(items)} found")
        if encoded.get("base64_decoded"):
            lines.append(f"  [!] Base64 decoded content available")

        strings = binary.get("strings", [])
        lines.append(f"\n  Strings extracted: {len(strings)}")

        lines.append("")
        return lines

    def _section_extraction(self, extraction: Dict) -> List[str]:
        """Extraction results section."""
        if not extraction:
            return []

        lines = ["", "EXTRACTION RESULTS", SECTION_SEPARATOR]

        tools = [
            ("binwalk", "Binwalk signatures"),
            ("foremost", "Foremost carved files"),
            ("scalpel", "Scalpel carved files"),
            ("steghide", "Steghide hidden data"),
            ("stegseek", "Stegseek crack result"),
        ]

        for key, label in tools:
            val = extraction.get(key)
            if isinstance(val, list) and val:
                lines.append(f"  [+] {label}: {len(val)} item(s)")
                if key == "steghide":
                    for item in val:
                        lines.append(f"      Passphrase: {item.get('passphrase', 'N/A')}")
                        lines.append(f"      File: {item.get('file', 'N/A')}")
                elif key == "binwalk":
                    for item in val[:5]:
                        lines.append(f"      @ {item.get('offset', '?')}: {item.get('description', '')[:60]}")
            elif isinstance(val, dict):
                if val.get("file"):
                    lines.append(f"  [+] {label}: SUCCESS - {val['file']}")

        extracted_files = extraction.get("extracted_files", [])
        if extracted_files:
            lines.append(f"\n  Total extracted files: {len(extracted_files)}")
            for f in extracted_files[:15]:
                size = os.path.getsize(f) if os.path.exists(f) else 0
                lines.append(f"    {f} ({human_size(size)})")
            if len(extracted_files) > 15:
                lines.append(f"    ... and {len(extracted_files) - 15} more")

        lines.append("")
        return lines

    def _section_digital(self, digital: Dict) -> List[str]:
        """Digital modes section."""
        if not digital:
            return []

        lines = ["", "DIGITAL MODES ANALYSIS", SECTION_SEPARATOR]

        morse = digital.get("morse", [])
        if morse:
            lines.append("  [+] MORSE CODE DETECTED:")
            for m in morse:
                decoded = m.get("decoded", m.get("output", ""))
                lines.append(f"      {decoded[:200]}")

        dtmf = digital.get("dtmf", [])
        if dtmf:
            lines.append("  [+] DTMF TONES:")
            for d in dtmf:
                lines.append(f"      Digits: {d.get('digits', 'N/A')}")

        sstv = digital.get("sstv", [])
        if sstv:
            lines.append(f"  [+] SSTV signals detected: {len(sstv)}")

        multimon = digital.get("multimon", {})
        if isinstance(multimon, dict):
            output = multimon.get("output", "")
            meaningful = [l for l in output.splitlines() if ":" in l]
            if meaningful:
                lines.append(f"  [+] multimon-ng decoded {len(meaningful)} signals")
                for l in meaningful[:5]:
                    lines.append(f"      {l[:100]}")

        minimodem = digital.get("minimodem", [])
        if minimodem:
            lines.append(f"  [+] minimodem decoded data:")
            for m in minimodem:
                lines.append(f"      @ {m.get('baud')} baud: {m.get('decoded', '')[:100]}")

        if not any([morse, dtmf, sstv, minimodem,
                    (isinstance(multimon, dict) and multimon.get("output", "").strip())]):
            lines.append("  No digital mode signals detected")

        lines.append("")
        return lines

    def _section_ocr(self, ocr: Dict) -> List[str]:
        """OCR and QR results section."""
        if not ocr:
            return []

        lines = ["", "OCR & QR CODE RESULTS", SECTION_SEPARATOR]

        ocr_results = ocr.get("ocr", [])
        if ocr_results:
            lines.append(f"  [+] OCR text extracted from {len(ocr_results)} images")
            for r in ocr_results[:3]:
                text_preview = r.get("text", "")[:150].replace("\n", " ")
                lines.append(f"      {r.get('image', '')}: {text_preview}")

        qr_codes = ocr.get("qr_codes", [])
        if qr_codes:
            lines.append(f"  [!!!] QR/BARCODE DATA FOUND:")
            for q in qr_codes:
                lines.append(f"      Type: {q.get('type', 'N/A')}")
                lines.append(f"      Data: {q.get('data', 'N/A')[:200]}")

        if not ocr_results and not qr_codes:
            lines.append("  No OCR text or QR codes detected")

        lines.append("")
        return lines

    def _section_flags(self, flags: Dict) -> List[str]:
        """Flags section."""
        if not flags:
            return []

        lines = ["", "FLAG DETECTION", SECTION_SEPARATOR]

        found = flags.get("flags_found", [])
        if found:
            lines.append(f"  [!!!] {len(found)} POTENTIAL FLAG(S) FOUND:")
            for i, f in enumerate(found, 1):
                lines.append(f"\n  {i}. VALUE   : {f.get('value', 'N/A')}")
                lines.append(f"     ENCODING: {f.get('encoding', 'plaintext')}")
                if f.get("encoded_value"):
                    lines.append(f"     ENCODED : {f['encoded_value'][:80]}")
                ctx = f.get("context", "")
                if ctx:
                    lines.append(f"     CONTEXT : {ctx[:100]}")
        else:
            lines.append("  No flags matching known patterns were found.")

        cipher = flags.get("cipher_results", {})
        if cipher:
            lines.append("\n  Cipher analysis hits:")
            for ctype, hits in cipher.items():
                lines.append(f"    [{ctype}] {len(hits)} hit(s)")

        suspicious = flags.get("suspicious_strings", [])
        if suspicious:
            lines.append(f"\n  Suspicious strings ({len(suspicious)}):")
            for s in suspicious[:10]:
                lines.append(f"    - {s[:100]}")

        lines.append("")
        return lines

    def _section_files(self, results: Dict) -> List[str]:
        """Output files section."""
        lines = ["", "OUTPUT FILES", SECTION_SEPARATOR]

        output_files = recursive_file_search(self.output_dir)
        output_files.sort()

        for fpath in output_files:
            try:
                size = os.path.getsize(fpath)
                rel = os.path.relpath(fpath, self.output_dir)
                lines.append(f"  {rel:<60} {human_size(size):>10}")
            except OSError:
                pass

        lines.append("")
        return lines

    def _section_warnings(self, results: Dict) -> List[str]:
        """Warnings section."""
        all_warnings = []

        for key, val in results.items():
            if isinstance(val, dict):
                all_warnings.extend(val.get("warnings", []))

        if not all_warnings:
            return []

        lines = ["", "WARNINGS / MISSING TOOLS", SECTION_SEPARATOR]
        seen = set()
        for w in all_warnings:
            if w not in seen:
                lines.append(f"  ! {w}")
                seen.add(w)

        lines.append("")
        return lines

    def _section_manual_steps(self) -> List[str]:
        """Manual steps section."""
        return ["", MANUAL_STEPS, ""]
