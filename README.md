# 🎵 Audio Stego Solver

> The best open-source terminal-based audio steganography analysis framework for CTF challenges and digital forensics.

```
audio-stego scan challenge.wav
```

---

## What It Does

Automated analysis of audio files for hidden data using every available technique:

| Category | Techniques |
|----------|-----------|
| **Metadata** | file, exiftool, mediainfo, ffprobe — all tags, hashes, format info |
| **Binary** | Strings (deduplicated), entropy per block, hexdump (64 KB), embedded magic detection, appended data (RIFF-accurate for WAV) |
| **Visual** | Spectrogram (librosa + ffmpeg), waveform, FFT |
| **Audio Forensics** | LSB extraction + printable ratio analysis, stereo channel difference |
| **Extraction** | binwalk, foremost, scalpel, steghide, stegseek — every carved artifact from every tool passes through one unified evidence pipeline (SHA256 dedup across tools → structural validator → evidence-based confidence → status), multi-pass recursive |
| **Digital Modes** | DTMF (validated ≥3 digits), Morse CW (validated decode), SSTV, multimon-ng, minimodem (validated printable ratio) |
| **OCR / QR** | Tesseract (confidence-filtered ≥40%), zbarimg — on spectrograms and extracted images |
| **Flag Detection** | 14 platform patterns, Base64/hex/binary encoded flags, cipher analysis (ROT/Caesar/XOR) — all validated |
| **Plugins** | XOR brute-force, Base64/32/58/85, ROT/Caesar/Atbash, GZIP, ZIP, YARA, magic bytes |
| **Reports** | `report.txt`, `report.html` (dark mode, collapsible, XSS-safe, grouped sidebar), `report.json`, `findings.csv` |

### Detection Philosophy

Every finding includes:
- **Confidence score** (0–100%)
- **Evidence** — what was observed
- **Reason** — why we believe it
- **False positive risk** — known sources of noise

The tool never reports a finding without a confidence score. A clean scan looks like:

```
Morse     Status: No valid Morse detected   Confidence: 0%   Reason: Only banner lines returned
DTMF      Status: No valid DTMF digits      Confidence: 2%   Reason: Only 1 digit found (min 3)
minimodem Status: No modem protocol         Confidence: 5%   Reason: Output below printable threshold
```

### Confidence Engine (v3.1)

Confidence is derived from *what kind of evidence backs the finding*, not hand-picked per call site:

| Evidence level | Confidence | What it means |
|----------------|-----------|----------------|
| Magic bytes only | 20% | A signature matched; nothing else was checked |
| Header parsed | 40% | Header fields decoded without error |
| Structure validated | 60% | Internal structure walked/confirmed consistent |
| Checksum/consistency | 80% | A CRC/checksum/hash inside the artifact was actually verified |
| Successfully extracted | 95% | Bytes written to disk and non-empty |
| Successfully parsed/opened | 100% | A real parser/decoder fully processed the content |

Severity is capped by confidence — a finding can never show **HIGH** or **CRITICAL** unless the evidence backing it is strong enough (≥80%/≥95% respectively). A 20%-confidence "no validator for this type" hit will only ever render as INFO.

### Confidence Tiers & CTF-First Report (v4.7 / v5.0)

The numeric confidence engine above feeds a human-facing tier: **Verified** (≥80%), **Possible** (≥20%, <80%), **Encoded** (recovered through a decode step), **Rejected** (below the magic-only floor, or explicitly rejected by validation). Rejected-tier findings never render in the HTML report at all — they're not hidden behind a toggle, they're simply not in scope for a report meant to answer "can I solve this challenge from this page alone?" (they're still fully visible in `report.json` for anyone who wants the raw data). There is no dashboard of extraction/rejection/false-positive counts anywhere in the report; the Executive Summary shows only what's actionable: flags found, overall confidence, and whether manual review is needed.

The sidebar is grouped into **Overview** (Executive Summary, Flags, Manual Reproduction), **Analysis** (Audio Preview, Metadata, Audio Information, Waveform, Spectrogram, FFT, Frequency Analysis), **Signals** (SSTV, QR, OCR, Digital Modes, Binary Analysis), and **Evidence** (Tools Used, Warnings) — and a section with nothing useful for a given scan (e.g. no SSTV signal detected) is omitted entirely rather than rendered as an empty placeholder.

### Extraction Pipeline (v3.1)

Every artifact carved by binwalk, foremost, scalpel, steghide, stegseek, or recursive extraction passes through one pipeline before it's trusted:

```
Tool → Artifact → SHA256 → Dedup (merge source tools) → Detect Type →
Structural Validator → Confidence → Evidence Record (status + reason)
```

A file existing on disk is never, by itself, treated as a real finding — it has to pass structural validation first. A genuinely useful extracted artifact is surfaced as a concrete, downloadable step inside **Manual Reproduction**, not a statistics table.

Per-artifact statuses: `VERIFIED`, `RECOVERED`, `PARTIAL`, `REJECTED`, `CORRUPTED`, `UNSUPPORTED`, `ENCRYPTED`, `PASSWORD_PROTECTED`, `NESTED`, `SKIPPED` (plus the original signature-scan statuses `DETECTED`/`VALIDATED`/`EXTRACTED`/`FAILED`/`FALSE_POSITIVE`) — all still recorded in `report.json` for anyone who wants the full accounting.

### MP3/AAC Frame Validation (v3.1)

Embedded MP3/AAC detection no longer accepts an isolated frame-sync byte pair as an "embedded file." The validator parses MPEG version, layer, bitrate, sample rate, computed frame size, and CRC-presence, then requires **≥3 consecutive, mutually-consistent frames** before treating a region as a real audio stream — eliminating the false-positive pattern where the 0xFFEx/0xFFFx bit pattern occurs by chance inside PCM data.

### SSTV Support (v4.6)

Real Goertzel-based VIS detection + a dependency-free FM-scanline image decoder (no external `rx_sstv`/`qsstv` required, though `rx_sstv` is used opportunistically if installed). Every VIS code below was cross-verified against two independent open-source SSTV codec references before being wired to auto-decode:

| Family | Modes |
|--------|-------|
| Martin | M1, M2 |
| Scottie | S1, S2, DX |
| Robot | 36, 72, 8 B/W |
| PD | 50, 90, 120, 160, 180, 240, 290 |
| Wraase | SC-2 120, SC-2 180 |
| Pasokon | P3, P5, P7 |

Includes real per-line sync-drift tracking, slant/clock-drift correction (measures the actual playback rate from observed sync timing and corrects per-line segment durations by it), multi-recipe post-processing (denoise, gamma, color balance, adaptive sharpening, CLAHE) with objective-quality-metric variant selection, and a confidence score that reflects actual measured image quality (sync regularity, entropy, row/pixel smoothness, saturation) rather than "the decoder didn't crash." AVT-90/AVT-94 are not implemented — they use a digital-header synchronization scheme with no per-line sync pulse at all, incompatible with this engine's decode model; reported honestly as unsupported rather than guessed at. PSK31/Olivia/Hellschreiber (need fldigi), FT8/JT65 (need wsjt-x/jt9), and NOAA APT similarly have no batch-decode CLI contract this project can verify — tool presence/absence is reported honestly instead of a fabricated integration.

---

## Installation

### Requirements

- Python 3.9+
- Optional system tools (install what you have):

```bash
# Debian/Ubuntu
sudo apt install exiftool mediainfo ffmpeg binwalk foremost scalpel \
  steghide tesseract-ocr zbar-tools multimon-ng minimodem

# stegseek (from GitHub releases)
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
sudo dpkg -i stegseek_0.6-1.deb
```


### Install the tool

```bash
git clone https://github.com/Srikanth786369/audio-stego-solver.git
cd audio-stego-solver

python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install .

# With YARA support
pip install ".[yara]"

# Verify
audio-stego --version
```

---

## Usage

### Scan a single file

```bash
audio-stego scan challenge.wav
```

### Scan a directory (all supported audio files)

```bash
audio-stego scan challenges/
# Creates: results/challenge1/, results/challenge2/, ...
```

### With options

```bash
audio-stego scan challenge.wav \
  --output /tmp/results \
  --config custom.ini \
  --workers 4 \
  --verbose \
  --timeout 120
```

### Generate default config

```bash
audio-stego gen-config --output my.ini
# Edit my.ini, then:
audio-stego scan challenge.wav --config my.ini
```

### List all plugins

```bash
audio-stego list-plugins    # or: audio-stego plugins
```

### Other commands (v3.1)

```bash
audio-stego doctor                       # environment health check (tools + Python packages)
audio-stego validate FILE                # check FILE's own structure (magic + real validators)
audio-stego extract FILE [-o DIR]        # run only the extraction pipeline, standalone
audio-stego decode "<text>" [--file F]   # try every encoding scheme against text/a file
audio-stego report RESULTS_DIR           # summarize an existing scan's report.json
audio-stego stats RESULTS_DIR            # extraction status counts + avg confidence
audio-stego verify RESULTS_DIR           # re-hash extracted artifacts vs. recorded SHA256
audio-stego benchmark FILE               # full scan + per-phase timing breakdown
audio-stego clean [-o DIR] [--yes]       # remove a results directory (asks to confirm)
```

---

## Supported Formats

`.wav` `.mp3` `.flac` `.ogg` `.aac` `.m4a` `.au` `.aiff` `.wma`

---

## Supported Signals

| Signal | How it's detected |
|--------|-------------------|
| SSTV | Real Goertzel-based VIS detection + dependency-free FM-scanline image decoder — see [SSTV Support](#sstv-support-v46) for the full mode table |
| Morse (CW) | multimon-ng decode (validated) + text-pattern search in extracted strings |
| DTMF | multimon-ng decode, requires ≥3 valid digits to report |
| RTTY / other modem tones | minimodem, validated by printable-ratio threshold |
| POCSAG / FLEX / ZVEI / EIA / CCIR / other pager & selective-call protocols | multimon-ng "all mode" scan, gated by the same confidence engine as everything else |
| QR codes / barcodes | zbarimg, on spectrograms, extracted images, and SSTV-decoded images |
| Text in images | Tesseract OCR, confidence-filtered (≥40%) |
| LSB steganography | Per-channel, 1–4 bit LSB extraction + printable-ratio/entropy analysis |
| Embedded files | binwalk signature scan + foremost/scalpel carving, each carved artifact structurally validated before being trusted |
| Passphrase-protected steganography | steghide (known passphrase) + stegseek (wordlist attack) |
| Encoded/ciphered flags | Base64/32/45/58/62/64/85, hex, binary, ROT/Caesar/Atbash, Rail Fence, Bacon, Braille, Morse — blind-tried and recursively chained |

---

## Example Report

Every scan produces a single self-contained `report.html` — open it directly
in a browser, no server needed. It leads with an Executive Summary and any
Flags found, followed by a numbered Manual Reproduction walkthrough built
from this scan's own real evidence, then the full analysis (metadata,
waveform/spectrogram/FFT, SSTV, QR, OCR, digital modes, binary analysis),
and a Tools Used section showing each tool's actual captured output. Sections
with nothing to show for a given file (e.g. no SSTV signal) are omitted
automatically rather than padded out with empty placeholders.

```bash
audio-stego scan challenge.wav
xdg-open results/challenge/report.html   # or just double-click it
```

---

## Output Structure

A flat, curated layout — every file here is either a primary report or something
a real tool actually produced this scan:

```
results/
└── challenge/
    ├── report.html              ← Primary interface (dark mode, collapsible, XSS-safe)
    ├── report.json              ← Machine-readable (clean serialisation)
    ├── report.txt               ← Quick text summary
    ├── metadata.txt             ← Consolidated metadata report
    ├── flags.txt                ← Flag detection results + confidence
    │
    ├── images/                  ← waveform.png, spectrogram.png, fft.png
    ├── sstv/                    ← decoded_best.png, decoded_variants/, debug/
    ├── text/                    ← ocr.txt, qr.txt (general-purpose OCR/QR module)
    ├── tools/                   ← Raw output from every tool that ran: ffprobe.txt,
    │                              exiftool.txt, mediainfo.txt, fileinfo.txt,
    │                              binwalk_scan.txt, binwalk_extract.txt, foremost.txt,
    │                              scalpel.txt, steghide.txt, stegseek.txt, strings.txt,
    │                              hexdump.txt, multimon.txt, minimodem.txt
    │
    ├── logs/run.log             ← This scan's log
    ├── evidence/                ← Audio-forensics raw text dumps (internal — not
    │                              surfaced in the report, kept for analysts who
    │                              want the raw numbers: LSB/MSB, phase, echo,
    │                              carrier, watermark, MFCC, entropy map, ...)
    ├── extracted/                ← Files carved by binwalk/foremost/scalpel/steghide/stegseek
    ├── hidden_files/              ← Recursively extracted archive contents
    └── plugins/                   ← Plugin output directories
```

Digital-mode summary files (`morse.txt`, `dtmf.txt`) and a few other derived
reports still live at the top level alongside `metadata.txt`/`flags.txt` —
`tools/` specifically holds *raw* tool stdout, not this project's own
synthesized reports.

---

## Architecture

```
audio_stego/
├── findings.py         ← Finding dataclass, confidence engine (EvidenceLevel/cap_severity),
│                          FLAG_PATTERNS, cipher utils — single source of truth
├── config.py           ← Config loading + defaults
├── logger.py           ← Logging setup
├── utils.py            ← Shared helpers (run_command, file_hash, FILE_MAGIC, magic detection)
├── main.py             ← Rich CLI (Click) — scan/doctor/validate/extract/decode/report/
│                          stats/verify/benchmark/clean/list-plugins/gen-config
├── scanner.py           ← Orchestrator: metadata → binary → visual+forensics → extraction →
│                          digital+OCR → SSTV → flags → recursive analysis → plugins → reports
├── artifact_store.py    ← Structured output directory (results/<stem>/tools, images, sstv, text, evidence, ...)
├── metadata.py          ← file/exiftool/mediainfo/ffprobe
├── binary.py            ← strings/entropy/hexdump/embedded/appended detection
├── visual.py            ← spectrogram/waveform/FFT
├── audio_forensics.py   ← LSB(1-4bit)/MSB, phase-inversion, entropy map, carrier detection,
│                           echo/cepstrum, MFCC, bit-planes — real DSP, numpy/scipy/librosa
├── extraction.py        ← Unified evidence pipeline: SHA256 dedup → detect type → validate →
│                          confidence → status (binwalk/foremost/scalpel/steghide/stegseek)
├── validate.py           ← Structural validators (20+ formats incl. real MPEG frame parsing)
├── recursive_engine.py   ← Decodes text-borne nesting back through the extraction pipeline
├── encoding_engine.py    ← Base16/32/45/58/62/64/85, Rail Fence, Bacon, Braille, Morse, ...
├── digital.py            ← DTMF/Morse/multimon-ng/minimodem (all confidence-scored)
├── sstv.py               ← Goertzel-based VIS detection; runs rx_sstv and the custom
│                          FM-scanline decoder (sstv_decode.py) and keeps whichever
│                          produces the higher validated confidence; expanded image
│                          post-processing (denoise/gamma/color-balance/sharpen/auto-crop)
├── ocr.py                ← Tesseract OCR (confidence-filtered) + zbarimg QR/barcode
├── flags.py              ← Flag pattern search + encoded flag decode + cipher analysis
├── hint_engine.py        ← Generates investigation hints, surfaced inside the HTML
│                            report's Manual Reproduction section
├── report.py             ← Text report
├── reports_ext.py        ← JSON/CSV reports (JSON includes full extraction_records)
├── html_report.py        ← Primary interface: grouped sidebar (Overview/Analysis/
│                            Signals/Evidence), real per-tool output in Tools Used,
│                            About modal, dark/light mode
└── plugins/
    ├── base_plugin.py ← BasePlugin ABC — name/version/author/description/supported_file_types/
    │                     dependencies/input_types/output_types + finding() helper
    ├── manager.py     ← Auto-discovery + execution (per-plugin execution_time, fault isolation)
    ├── xor_plugin.py, base64_plugin.py, base32_plugin.py, base58_plugin.py, base85_plugin.py,
    ├── rot_plugin.py, caesar_plugin.py, gzip_plugin.py, zip_plugin.py, yara_plugin.py,
    └── magic_plugin.py
```

---

## Plugin Development

Plugins are auto-discovered — no changes to `scanner.py` needed.

**Discovery paths:**
- `audio_stego/plugins/` — built-in
- `~/.config/audio-stego/plugins/` — user plugins
- `/etc/audio-stego/plugins/` — system plugins

Any file named `*_plugin.py` containing a `BasePlugin` subclass is loaded automatically.

### Minimal plugin example

```python
# ~/.config/audio-stego/plugins/my_plugin.py

from audio_stego.plugins.base_plugin import BasePlugin
from audio_stego.findings import Severity

class MyPlugin(BasePlugin):
    name        = "my_plugin"
    version     = "1.0.0"
    author      = "Your Name"                 # defaults to "Audio Stego Solver" if omitted
    description = "My custom analysis plugin"
    supported_file_types = ["*"]              # or e.g. ["wav", "flac"]
    dependencies = []                         # external tools/libraries this plugin needs
    input_types  = ["audio_path", "results"]
    output_types = ["findings"]
    # execution_time is recorded automatically by PluginManager — no need to set it.
    # A plugin that raises is caught per-plugin and never stops the rest of the scan.

    def run(self, audio_path, output_dir, results):
        strings = self.get_strings(results)    # from binary analysis
        ocr     = self.get_ocr_text(results)   # from OCR analysis
        corpus  = self.get_all_text(results)   # strings + OCR combined

        findings = []
        for s in strings:
            if "magic_pattern" in s:
                findings.append(self.finding(
                    title="Magic Pattern Found",
                    value=s,
                    evidence=f"Found in strings: '{s[:60]}'",
                    confidence=0.85,
                    severity=Severity.HIGH,
                    encoding="plaintext",
                ))

        self.save_output(output_dir, "my_results.txt",
                         f"Found {len(findings)} pattern(s)")

        return {
            "flags_found": findings,   # shown in flag report
            "findings":    findings,   # shown in all-findings section
        }
```

### Plugin API reference

| Method | Description |
|--------|-------------|
| `self.get_strings(results)` | Deduplicated strings from binary analysis |
| `self.get_ocr_text(results)` | All OCR text concatenated |
| `self.get_all_text(results)` | `get_strings` + `get_ocr_text` combined |
| `self.save_output(out_dir, filename, content)` | Save text file (creates dirs) |
| `self.finding(title, value, ...)` | Create a structured Finding dict |

---

## Manual Investigation

The HTML report's **Manual Reproduction** section walks through this scan's
own real evidence step by step (what happened, why, and the result) — for
techniques it doesn't automate end-to-end, here's how to run them by hand:

```bash
# Extract LSBs
python3 -c "
import librosa, numpy as np
y, sr = librosa.load('challenge.wav', sr=None)
s = (y * 32768).astype(np.int16)
bits = ''.join(str(v & 1) for v in s)
print(''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits)-7,8)
      if 32<=int(bits[i:i+8],2)<127))
"

# Reverse audio
sox challenge.wav reversed.wav reverse

# Split stereo channels
ffmpeg -i challenge.wav \
  -filter_complex 'channelsplit=channel_layout=stereo[L][R]' \
  -map '[L]' left.wav -map '[R]' right.wav

# Brute-force steghide
stegseek challenge.wav /usr/share/wordlists/rockyou.txt

# SSTV decode
rx_sstv challenge.wav sstv_output/

# Try outguess
outguess -r challenge.mp3 output.txt
```

---

## Running Tests

```bash
pytest tests/ -v
# 314 passed (a handful more skip only if librosa/scipy/soundfile/multimon-ng
# aren't installed — run `audio-stego doctor` to check what's missing)
```

---

## Troubleshooting

- **`audio-stego scan` used to always exit with an error even on success.**
  Fixed in v3.1 — a leftover call to a renamed internal method made every
  scan report failure at the very end regardless of outcome. If you're on an
  older version, upgrade; there's no workaround short of patching the code.
- **SSTV / mode name shows "Unknown (VIS 0xXX)".** The signal was decoded
  correctly (the VIS byte itself, including its parity bit, is verified) but
  that particular code isn't in this project's mode-name table yet — several
  entries were found to be structurally invalid in earlier versions and were
  removed rather than replaced with unverified guesses. The code number is
  still reliable; only the mode *name* is best-effort.
- **A digital-mode tool (fldigi/wsjt-x/jt9) shows up in warnings but nothing
  gets decoded.** PSK31/Olivia/Hellschreiber/FT8/JT65 have no simple
  one-shot CLI decode contract this project integrates with — see the
  Digital Modes section of CHANGELOG.md. Presence is reported so you know
  what to run manually; it isn't run automatically.
- **`audio-stego doctor` reports a required tool missing.** Install it via
  your package manager (see Requirements above) — `file`, `exiftool`,
  `mediainfo`, `ffprobe`, `ffmpeg`, and `strings` are required for baseline
  functionality; everything else degrades gracefully when absent.
- **HTML report is large / slow to open.** The audio player and any embedded
  images are base64-inlined, and each image is embedded exactly once (shared
  between the inline preview and its download button). The audio player caps
  at 25MB and shows a message instead of embedding beyond that; there's no
  cap on spectrogram/waveform image size yet.
- **Something looks wrong and you're not sure why.** Check `logs/run.log` in
  the scan's output directory first, then `tools/` for the raw, unfiltered
  output of every tool that ran.

---

## Known Limitations

- **opencv (cv2) is optional, not required.** SSTV post-processing (quality
  scoring, CLAHE/bilateral variants) falls back to numpy-only implementations
  when cv2 isn't installed — image reconstruction still works, just without
  a couple of opencv-specific enhancement steps.
- **JWT and Vigenère decoders exist but aren't auto-tried.** Both are real,
  tested functions in `encoding_engine.py`, but JWT isn't part of the blind-
  decode sweep (`audio-stego decode`) and Vigenère needs a key you don't
  have until you already suspect it — use them directly from Python if you
  need them (`from audio_stego.encoding_engine import decode_jwt`).
- **AVT-90/AVT-94 SSTV modes are not implemented.** They use a digital-header
  synchronization scheme with no per-line sync pulse, incompatible with this
  project's decode model — reported honestly as unsupported rather than
  guessed at.
- **PSK31/Olivia/Hellschreiber/FT8/JT65/NOAA APT have no batch-decode CLI
  contract** this project can verify (they need fldigi/wsjt-x/jt9, all
  interactive/GUI-oriented tools) — tool presence is reported, but they
  aren't invoked automatically.
- **rx_sstv is optional.** The custom FM-scanline decoder (`sstv_decode.py`)
  works standalone; `rx_sstv` is only used opportunistically as a second
  candidate decoder when installed.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code style, and how to add
a plugin.

---

## License

MIT — see [LICENSE](LICENSE)
