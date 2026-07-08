"""
Hint Engine for Audio Stego Solver.

FIXED (v1.1):
  - _analyze_binary: entropy blocks stored as summary dict (not list of floats);
    AttributeError on .get("entropy", 0) from float elements is now eliminated
  - Deduplication uses a set instead of O(n²) list scan
  - Generic hints are gated behind a "nothing found" condition to reduce noise
  - Hints reference the actual audio filename, not hardcoded 'challenge.wav'
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Set

from .logger import get_logger

logger = get_logger("audio_stego.hints")


class HintEngine:
    """Analyses scan results and produces actionable investigation recommendations."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self._hints: List[str] = []
        self._seen: Set[str] = set()   # O(1) dedup instead of O(n²)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, audio_path: str, results: Dict[str, Any]) -> List[str]:
        """Generate hints based on all analysis results."""
        self._hints = []
        self._seen = set()
        fname = Path(audio_path).name

        any_finding = False

        any_finding |= self._analyze_binary(results.get("binary", {}))
        any_finding |= self._analyze_extraction(results.get("extraction", {}))
        any_finding |= self._analyze_digital(results.get("digital", {}))
        any_finding |= self._analyze_ocr(results.get("ocr", {}))
        any_finding |= self._analyze_flags(results.get("flags", {}))
        self._analyze_visual(results.get("visual", {}))
        self._analyze_metadata(results.get("metadata", {}))

        # Only add generic manual-investigation hints if nothing specific was found
        if not any_finding:
            self._add_generic_hints(fname)

        return self._hints

    # ------------------------------------------------------------------
    # Per-module analysis
    # ------------------------------------------------------------------

    def _add(self, hint: str) -> bool:
        """Add a hint if not already present. Returns True (for any_finding tracking)."""
        if hint not in self._seen:
            self._seen.add(hint)
            self._hints.append(hint)
        return True

    def _analyze_binary(self, binary: Dict) -> bool:
        found = False

        # FIXED: entropy summary is a dict with keys, not a list of floats
        entropy = binary.get("entropy", {})
        high_blocks = entropy.get("high_entropy_blocks", [])
        if high_blocks:
            offsets = [f"0x{b['offset']:08x}" for b in high_blocks[:3]]
            self._add(
                f"⚠ High entropy (>7.5 bits) at offsets: {', '.join(offsets)}.\n"
                "  → May indicate encryption, compression, or hidden payload.\n"
                "  → Cross-reference with binwalk output."
            )
            found = True

        embedded = binary.get("embedded_files", [])
        if embedded:
            types = list({e["type"] for e in embedded})
            self._add(
                f"🔍 Embedded file signatures: {', '.join(types)}.\n"
                "  → Run: binwalk -e <file>  to extract."
            )
            found = True

        appended = binary.get("appended_data") or {}
        if appended and appended.get("detected"):
            extra = appended.get("extra_bytes", 0)
            offset = appended.get("offset", 0)
            self._add(
                f"🔍 Appended data: {extra:,} extra bytes after expected audio end "
                f"(offset 0x{offset:08x}).\n"
                "  → Check extracted/appended_data.bin"
            )
            found = True

        encoded = binary.get("encoded_data", {})
        if encoded.get("base64_decoded"):
            self._add(
                "📦 Validated Base64 strings decoded — review encoded_data.txt.\n"
                "  → Check decoded values for flags or further encoding."
            )
            found = True

        if encoded.get("jwt"):
            self._add(
                "🔑 JWT token found in strings.\n"
                "  → Decode at jwt.io and check payload claims."
            )
            found = True

        if encoded.get("aws_key") or encoded.get("github_token"):
            self._add(
                "🔑 Credential pattern found (AWS key / GitHub token).\n"
                "  → This may be a red herring or the actual secret."
            )
            found = True

        strings = binary.get("strings", [])
        sus = [
            s for s in strings
            if any(kw in s.lower() for kw in ["password", "secret", "key", "passphrase"])
        ]
        if sus:
            self._add(
                f"🔑 Suspicious strings: {sus[:3]}\n"
                "  → These may be steghide / stegseek passphrases."
            )
            found = True

        return found

    def _analyze_extraction(self, extraction: Dict) -> bool:
        found = False

        if extraction.get("steghide"):
            for item in extraction["steghide"]:
                self._add(
                    f"✅ steghide extracted with passphrase '{item.get('passphrase', '')}'\n"
                    f"  → Extracted file: {item.get('file', 'N/A')}"
                )
            found = True

        elif not extraction.get("steghide"):
            self._add(
                "🔑 steghide found nothing with common passphrases.\n"
                "  → Try: stegseek <file> /usr/share/wordlists/rockyou.txt\n"
                "  → Or build a custom wordlist from metadata (artist/title/year)."
            )

        ssk = extraction.get("stegseek") or {}
        if ssk.get("file"):
            self._add(
                f"✅ stegseek cracked passphrase!\n"
                f"  → Extracted: {ssk['file']}"
            )
            found = True

        extracted = extraction.get("extracted_files", [])
        if extracted:
            self._add(
                f"📂 {len(extracted)} file(s) extracted — analyse each:\n"
                "  → file <extracted_file>\n"
                "  → Check for nested steganography in extracted images."
            )
            found = True

        return found

    def _analyze_digital(self, digital: Dict) -> bool:
        found = False

        for m in digital.get("morse", []):
            val = m.get("value", m.get("decoded", m.get("output", "")))
            conf = m.get("confidence_pct", "?")
            self._add(
                f"📡 Morse code detected (confidence {conf}): '{val[:100]}'\n"
                "  → If it resembles a flag prefix, complete manually.\n"
                "  → Try Sonic Visualiser CW plugin for manual verification."
            )
            found = True

        for d in digital.get("dtmf", []):
            digits = d.get("value", d.get("digits", ""))
            conf = d.get("confidence_pct", "?")
            self._add(
                f"📞 DTMF tones (confidence {conf}): '{digits}'\n"
                "  → May encode a phone number, PIN, or ASCII (pairs of digits)."
            )
            # Attempt ASCII interpretation
            if digits and all(c.isdigit() for c in digits) and len(digits) >= 4:
                try:
                    pairs = [int(digits[i:i+2]) for i in range(0, len(digits)-1, 2)]
                    ascii_chars = "".join(chr(v) for v in pairs if 32 <= v < 127)
                    if ascii_chars:
                        self._add(f"  💡 DTMF as ASCII pairs: '{ascii_chars}'")
                except Exception:
                    pass
            found = True

        if digital.get("minimodem"):
            for m in digital["minimodem"]:
                self._add(
                    f"📶 Modem signal decoded ({m.get('title','?')}): '{m.get('value','')[:80]}'"
                )
            found = True

        if digital.get("sstv"):
            self._add(
                "📺 SSTV signal detected!\n"
                "  → Use QSSTV or rx_sstv to decode the image.\n"
                "  → The image may contain the flag directly."
            )
            found = True

        multimon = digital.get("multimon") or {}
        meaningful = multimon.get("meaningful_lines", [])
        if meaningful:
            self._add(
                f"📻 multimon-ng decoded {len(meaningful)} signal line(s).\n"
                "  → Review multimon.txt for POCSAG/FLEX/AFSK content."
            )
            found = True

        return found

    def _analyze_ocr(self, ocr: Dict) -> bool:
        found = False

        for q in ocr.get("qr_codes", []):
            self._add(
                f"✅ QR code decoded: '{q.get('data', '')[:100]}'\n"
                "  → This may be the flag or a URL pointing to the next step."
            )
            found = True

        for r in ocr.get("ocr", []):
            if len(r.get("text", "")) >= 10:
                self._add(
                    f"📝 OCR text found in {os.path.basename(r.get('image',''))} "
                    f"(confidence {r.get('confidence', 0):.0f}%)\n"
                    "  → Review text/ocr.txt — hidden text may appear in spectrogram image."
                )
                found = True
                break   # one hint is enough for OCR

        return found

    def _analyze_flags(self, flags: Dict) -> bool:
        found = False

        for f in flags.get("flags_found", []):
            val = f.get("value", str(f)) if isinstance(f, dict) else str(f)
            enc = f.get("encoding", "plaintext") if isinstance(f, dict) else "?"
            conf = f.get("confidence_pct", "?") if isinstance(f, dict) else "?"
            self._add(f"🏁 POTENTIAL FLAG ({enc}, confidence {conf}): {val}")
            found = True

        cipher = flags.get("cipher_results", {})
        if cipher.get("rot13"):
            self._add("🔤 ROT13 produced flag-like output — review cipher_analysis.txt.")
            found = True
        if cipher.get("caesar"):
            self._add(
                f"🔤 Caesar cipher hit(s) — review cipher_analysis.txt for shift values."
            )
            found = True
        if cipher.get("xor"):
            self._add("🔤 XOR single-byte brute-force hit — review cipher_analysis.txt.")
            found = True

        if not found:
            self._add(
                "❓ No flags found automatically.\n"
                "  → Inspect spectrogram.png at 15–22 kHz (above audible range).\n"
                "  → Check waveform.png for unusual amplitude patterns.\n"
                "  → Review strings.txt for suspicious text."
            )

        return found

    def _analyze_visual(self, visual: Dict):
        if visual.get("spectrogram") or visual.get("spectrogram_ffmpeg"):
            self._add(
                "🖼 Review spectrogram.png:\n"
                "  → Look for hidden text/images at 15–22 kHz\n"
                "  → Use Sonic Visualiser for interactive zoomed inspection\n"
                "  → Compare left vs right channel for differences"
            )
        if visual.get("fft"):
            self._add(
                "📊 Review fft.png:\n"
                "  → Unusual spikes at specific frequencies may encode data\n"
                "  → Dead-silent frequency bands may be used for covert channels"
            )

    def _analyze_metadata(self, metadata: Dict):
        tags = metadata.get("interesting_tags", {})
        for key, val in list(tags.items())[:5]:
            if val and len(val.strip()) > 2:
                self._add(
                    f"🏷 Metadata field '{key}': '{val[:120]}'\n"
                    "  → May be a passphrase hint or encoded flag."
                )

    def _add_generic_hints(self, fname: str):
        """Generic hints — only shown when no specific findings exist."""
        self._add(
            f"🔄 Try reversing the audio:\n"
            f"  sox {fname} reversed.wav reverse\n"
            "  → Then re-run audio-stego scan reversed.wav"
        )
        self._add(
            "🔢 Try LSB extraction manually:\n"
            "  python3 -c \"\n"
            "  import librosa, numpy as np\n"
            f"  y, sr = librosa.load('{fname}', sr=None)\n"
            "  s = (y * 32768).astype(np.int16)\n"
            "  bits = ''.join(str(v & 1) for v in s)\n"
            "  print(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits)-7,8)"
            "  if 32<=int(bits[i:i+8],2)<127))\n"
            "  \""
        )
        self._add(
            "🎚 Check stereo channel differences:\n"
            f"  ffmpeg -i {fname} -filter_complex 'channelsplit=channel_layout=stereo[L][R]'"
            " -map '[L]' left.wav -map '[R]' right.wav\n"
            "  → Then diff left.wav and right.wav"
        )
        self._add(
            "🔑 Try outguess if steghide found nothing:\n"
            f"  outguess -r {fname} output.txt"
        )

