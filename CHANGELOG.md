# Changelog

## [5.0.0] - 2026-07-07 — GitHub Release: Report Gaps Closed, Dead Code Removed, results/ Restructured

v4.7.0 did the first pass of the CTF report redesign (real per-tool output,
correct section order, removed statistics tables). This release finishes the
job — closing the remaining gaps against the original report spec, cutting
confirmed-dead code, giving `results/<name>/` a flat and predictable layout,
and refreshing the docs — as a clean, stable v5.0 ready for a public repo. No
new decoders, analyzers, or plugins; no architecture redesign.

### HTML report
- **Empty sections are hidden, not padded.** Waveform/Spectrogram/FFT/
  Frequency Analysis/Audio Information/SSTV/QR/OCR/Digital Modes/Tools Used
  previously always rendered, falling back to a "No X available" placeholder
  when there was nothing to show. Now a section with nothing useful for a
  given scan is omitted entirely, from both the body and the sidebar TOC.
- **SSTV section reordered and completed.** The hero image now renders above
  the data table (was reversed). Added Quality and Decode Time fields (the
  decode loop is now timed; quality reuses the existing post-processing
  quality score). The four post-processing variants (Standard/Contrast/
  Minimal/CLAHE) were being computed and saved to disk every scan but never
  linked from the report — their paths are now wired through and rendered as
  a clickable "Other Variants" gallery.
- **Sidebar grouped into Overview / Analysis / Signals / Evidence**, using
  CSS classes that existed since the last redesign but were never wired to
  actual grouping logic.
- **About modal** (header button) with version, author, LinkedIn, and the
  GitHub remote URL auto-detected from `git config` when available.
- **Footer** now credits the author with a LinkedIn link, not just the tool
  name/version.
- **Evidence chain** (Audio → SSTV → Image → QR/OCR → Encoding → Flag) is now
  rendered as connected boxes instead of plain arrow-separated text.
- Deleted an unreachable "Rejected Candidates" flag-grouping branch (flags
  are always tagged `["flag"]`, so it could never fire) — a landmine left
  over from the v4.7.0 pass.
- **Every embedded image is base64-encoded exactly once.** Previously the
  same image was encoded twice — once for the inline `<img>`, again for its
  download link — roughly doubling that image's contribution to file size.
  The download button now reads the already-rendered `<img>`'s own `src` via
  a small JS helper. Real-world effect on a representative scan:
  `report.html` dropped from 7.4MB to 5.6MB even after the SSTV variant
  gallery started embedding 4 additional images it hadn't before.
- The CLI's terminal summary panel got the same treatment as the HTML report
  in v4.7.0: dropped the Extracted/Failed-extract/Rejected-findings rows,
  added Status ("Analysis Completed Successfully") and Overall Confidence to
  match the report's Executive Summary.
- The pre-scan **"Tool Availability"** panel — which printed a ✗ row for
  every missing/inapplicable tool (e.g. `rx_sstv ✗ not found`) before the
  scan even started — is gone. Tool-presence checking now runs *after* the
  pipeline and prints a **"Tools Executed"** table listing only the tools
  that were actually present; a missing tool is simply omitted, matching the
  policy already applied to Tools Used and Warnings.

### results/ output restructure
`ArtifactStore` was designed as the single owner of output paths but only
3 of 9 writer modules actually used it — everything else hand-built paths
with `os.path.join`. Finished the adoption and moved to a flat, curated
layout:

```
results/<name>/
  report.html  report.json  report.txt  metadata.txt  flags.txt
  logs/run.log
  images/    waveform.png, spectrogram.png, fft.png
  sstv/      decoded_best.png, decoded_variants/, debug/
  text/      ocr.txt, qr.txt
  tools/     ffprobe/exiftool/mediainfo/fileinfo/binwalk/foremost/scalpel/
             steghide/stegseek/strings/hexdump/multimon/minimodem — every
             tool's raw output, one place
  evidence/, extracted/, hidden_files/, plugins/  — real writers, kept as
             internal subfolders (not part of the curated top-level list)
```

Removed `ArtifactStore` properties/directories with zero writers anywhere in
the codebase (`report_json`, `summary_txt`, `artifacts/`,
`decoded/{morse,dtmf,minimodem,cipher,multimon}`, `audio/`, `archives/`,
`flags_dir`, `raw_file()`/`evidence_file()`/`artifact()`/`plugin_dir()`).
Stopped writing `xxd.txt` (redundant with `hexdump.txt`, never read by
anything — `xxd` itself is no longer invoked), `fft_frequencies.txt`, and
`hints.txt` (all three: written, never read, not even in memory).

Two real bugs fixed as part of the restructure:
- **`plugins/plugins` double-nesting** — `scanner.py` was passing
  `store.plugins` (already ending in `/plugins`) into
  `PluginManager.run_all()`, which appends its own `"plugins"` subdir. Fixed
  by passing `store.base` instead.
- **The `images/` dual-directory bug** — `extraction.py` copied carved
  images into `artifacts/images/`, a path OCR never scanned (it already
  recursively scans `extracted/`/`hidden_files/` directly, which contains
  the same file). Removed the copy rather than redirecting it, since keeping
  it would have made OCR process the same image twice under two different
  paths.

### Dead code removed
- `reports_ext.py`'s `HTMLReportGenerator` (~300 lines) — a superseded HTML
  report generator never wired into the live pipeline (`scanner.py` uses
  `html_report.HTMLReport`), only ever exercised by its own tests.
- `encoding_engine.py`'s unused `decode_hex` alias;
  `sstv_decode.py`'s unused `VIS_TO_DECODABLE_MODE` dict (`sstv.py` already
  does the equivalent lookup itself).
- ~25 confirmed-unused imports and a handful of write-only local variables
  across `binary`/`report`/`extraction`/`logger`/`visual`/`encoding_engine`/
  `audio_forensics`/`artifact_store`/`metadata`/`html_report`/`sstv`/
  `validate`/`ocr`/`flags`/`digital`/`config`/`plugins`.
- Fixed the `decode` CLI's docstring, which overclaimed JWT support — the
  JWT/Vigenère decoders are real, tested library functions but were never
  wired into the blind-decode dispatch table, so they were never actually
  reachable from the CLI.
- Removed `PROJECT_AUDIT.md` — its content is fully superseded by this
  CHANGELOG and isn't the kind of file a public OSS repo ships.

*Correction made during this pass:* `sstv_decode.py`'s `SYNC_HZ` constant was
initially deleted as unused based on a static-analysis pass that only
grepped production code. It's actually imported by
`tests/sstv_test_vectors.py` to synthesize SSTV sync tones — caught
immediately by the test suite (`ImportError`) and restored with a comment
explaining the cross-module dependency. A reminder that "no production
callers" isn't the same as "no callers."

### Docs
README's Output Structure/Architecture sections updated to match the new
layout; added Supported Signals, Example Report, and Known Limitations
sections. SECURITY.md now points to GitHub's private vulnerability
reporting instead of a placeholder email, and lists 5.x as supported.

### Tests
314 passing (320 at the end of v4.7.0 → 317 after removing 3 tests for the
deleted `HTMLReportGenerator` → 314 after removing 3 more for the deleted
`ArtifactStore.raw_file()`/`evidence_file()`/`plugin_dir()` helpers). Two
tests updated to assert the new hide-when-empty/show-when-present section
behavior instead of every section id being present unconditionally.
Verified end-to-end against `p.mp3`/`s.mp3`/`signal.wav`/the Cicada 3301
sample: correct folder layout, no broken image placeholders, `plugins/` no
longer double-nested.

## [4.7.0] - 2026-07-07 — HTML Report Redesign: CTF Edition

The HTML report was rebuilt around one question — "can a CTF player solve
the challenge from this page alone?" — rather than around forensic
completeness. Extraction/validator accounting that never helped solve a
challenge is gone; every tool that ran now shows its real output instead of
a bare "Success"; and section order follows an actual investigation
workflow.

### Removed entirely (not hidden)
Verified Findings, Extracted Files, Extraction Summary, Rejected Findings,
Best Extracted Artifact, and the "Most Important Finding" card — along
with the raw-count dashboard stats that used to read things like
"Extracted: 2848" / "Rejected: 842" / "Total findings: 2870". These numbers
never told a CTF player what to do next; a genuinely useful extracted
artifact is still surfaced, but as a concrete, downloadable step inside
Manual Reproduction, not a statistics table. The recursive extraction
artifact graph and its supporting code (`_evidence_tree`) are gone with it.
Audio Forensics (stereo diff, cepstrum echo, entropy-map spike table,
carrier/watermark/MFCC) is removed as a standalone section — LSB
extraction, the one technique common enough in real audio CTF challenges to
matter, is folded into Binary Analysis instead of discarded.

### Tools Used: real output, not a status badge
Every tool card previously showed a derived count ("3 candidate
signature(s) found") and a hardcoded "✓ Success" badge. Now shows the
tool's actual captured output: exiftool's real parsed fields, ffprobe's
real codec/duration/sample-rate/channels, mediainfo's real stdout,
binwalk's real DECIMAL/HEXADECIMAL/DESCRIPTION rows, foremost/scalpel/
steghide's real result text (read from the `.txt` files already written
during scanning — never re-invoked), strings' real extracted lines,
hexdump's real captured bytes, multimon-ng's real per-mode decoded text,
minimodem's real decoded text per baud rate, the SSTV decoder's real mode/
VIS/confidence, zbarimg's real decoded data, and Tesseract's real OCR text.
No shell commands are ever displayed. A tool that ran but found nothing
still gets a card, honestly saying "No useful output produced." — never
invented. A tool that is missing, disabled, or was never invoked (e.g.
`rx_sstv` when not installed) gets no card at all, and no longer generates
a "rx_sstv not found"-style line in Warnings either (filtered by a new
`_is_tool_availability_noise` check) — a missing tool is simply omitted
once, not mentioned twice.

### Regression caught and fixed during this pass: Digital Modes bypassed its own confidence gate
The new Digital Modes section initially rendered straight from
`digital["multimon"]["per_mode"]` — the raw per-line dict multimon-ng
produces before the digital-modes analyzer's own confidence gates run.
That reintroduced exactly the noise the `[4.6.0]` selective-call
minimum-digit fix was built to suppress (a single-digit ZVEI/EIA/CCIR hit
from an ordinary musical tone). Fixed by rendering from `digital["findings"]`
(module="multimon") instead — the same validated Finding objects the
analyzer already produced — so Digital Modes and the Tools Used
multimon-ng card can never show something the analyzer itself rejected.
Caught by re-running the real pipeline against `p.mp3`/`s.mp3` (not just
unit tests) as part of verifying this pass, not assumed correct.

### Section order (fixed, matches an investigation workflow)
Executive Summary → Flags → Manual Reproduction → Audio Preview → Metadata
→ Audio Information → Waveform → Spectrogram → FFT → Frequency Analysis →
SSTV Analysis → QR Analysis → OCR → Digital Modes → Binary Analysis →
Tools Used → Warnings. The sidebar TOC mirrors this exactly; no other
top-level sections exist.

- **Audio Preview**: player + real duration/channels/sample-rate/bitrate
  (from ffprobe).
- **Metadata**: filename/hashes/codec/container/artist/album/title/comment/
  creation time explicitly surfaced (not just a raw exiftool key dump);
  anything else exiftool reported still shown under "Other Tags".
- **Waveform / Spectrogram / FFT**: split into three sections (previously
  one combined "Visual Analysis" block) — each still a click-to-zoom image.
- **Frequency Analysis**: real per-band energy ratios (infrasonic through
  ultrasonic), not a placeholder.
- **Digital Modes**: only protocols that actually decoded something render
  at all — a clean scan shows one honest "No useful output produced." line,
  never a checklist of "Morse: not detected" / "DTMF: not detected" rows.

### Manual Reproduction (renamed from "Manual Reproduction Guide")
Rewritten to read like a real investigator's notes: numbered steps quoting
this scan's own actual evidence, a genuinely extracted artifact now
embedded/linked directly in its step (image preview or download button)
instead of pointing at the deleted Extracted Files section, a "Run
Strings" step showing the real string count with an honest "Nothing
useful." when nothing was, and — when real steps ran but no flag was
recovered — an explicit "Final Conclusion: No hidden flag found from the
steps above." rather than silence. The Executive Summary status line no
longer implies a flag was found just because some other high-confidence
finding (e.g. a validated SSTV decode) exists.

### Cleanup
Removed the header search bar and severity-filter dropdown (they only ever
filtered the now-deleted findings table) and their supporting JS
(`doSearch`, `sortTable`), and all now-dead CSS (`.findings-table`,
`.search-bar`, `.filter-select`, `.conf-bar`/`.conf-fill`, `.status-*`
extraction-status colors, `.tree`) and the now-unused `_TIER_BADGE_CLASS`/
`_TIER_RANK`/`Finding`/`LOW_CONFIDENCE_DISPLAY_THRESHOLD` imports.

### Tests
320 passing (was 326 at the end of `[4.6.0]`; 7 tests covering deleted UI
—search input, low-confidence toggle, findings tier badges, rejected-finding
table exclusion, rejected-extraction-record exclusion, the recursive
evidence tree, and findings-by-category cards — were removed since the
features themselves are gone, not hidden; replaced/added tests cover the
new section set, the Tools Used real-output cards, and the Digital
Modes/multimon-ng confidence-gate regression found and fixed during this
pass). Verified end-to-end against real scans of `p.mp3` and `s.mp3` (not
just unit tests with synthetic `results` dicts) — no exceptions, no
`None`/`Traceback`/`KeyError` leaking into the rendered HTML, every section
renders real data.

## [4.6.0] - 2026-07-07 — Full Decoder Audit: Two Critical "Never Fired" Bugs, a Wrong VIS Code That Recovered a Real Missed Image, SSTV Slant Correction, 6 New SSTV Modes

A full, systematic audit of every signal decoder (SSTV, Morse, DTMF,
minimodem/Bell103/Bell202/RTTY, multimon-ng POCSAG/FLEX/AFSK1200/selective-call,
PSK31/Hellschreiber/JT65/FT8/Olivia/NOAA-APT), driven by actually generating
real or synthetic ground-truth signals for each protocol and running them
through the real pipeline end to end — not just reading the code. This found
two decoders that could **never produce a result regardless of input** (not
merely false-positive-prone), a wrong VIS code that had been silently
discarding a real image every scan, and several genuine false positives that
only appeared against real-world audio (a real MP3 in this repo), not the
synthetic signals prior test suites used exclusively.

### CRITICAL: Morse and DTMF detection were completely non-functional
`_MULTIMON_BANNER_PREFIXES` (the list of multimon-ng startup-banner lines to
strip before looking for real decoder output) included the literal strings
`"DTMF:"` and `"MORSE_CW:"` — but those are not banner text, they are the
exact prefix multimon-ng puts on every real DTMF decode line (`"DTMF: 7"`).
Since the banner filter runs *before* the marker check, every genuine DTMF
decode was discarded as if it were startup noise, on every scan, regardless
of input. Verified directly: generated a real dual-tone DTMF sequence
(1-3-3-7) and a real Morse CW sequence (SOS/HELLO/WORLD), confirmed
multimon-ng itself decodes both correctly, then confirmed the *pipeline*
reported zero digits/zero characters for either — a complete decoder outage,
not a false-positive issue. Separately, Morse had a second, independent bug:
multimon-ng's CW demodulator emits bare decoded text with **no per-line
marker at all** (unlike DTMF), so the code's `"MORSE_CW:" in line` check
could never be true either way. Both fixed; both now verified against real
generated audio through the real multimon-ng binary (not mocked), with new
regression tests that exercise the actual tool so this class of bug can't
regress silently behind a mock again.

### CRITICAL: Robot 72's SSTV VIS code was wrong — a real image was being missed on every scan
Wired to VIS 0x44, which is not a real, assigned SSTV VIS code at all.
Cross-checked against two independent, mutually-agreeing open-source SSTV
codec implementations (windytan/slowrx's `modespec.c` mode table and
rimio/libsstv's mode enum) that both give Robot 72's real code as **0x0C**.
Investigating this surfaced the same transposition in PD240/PD290 (were
wired to PD160/PD180's actual codes) — all corrected together, and PD50/
PD160/PD180 (previously left completely unwired for lack of a verified
code) are now wired using the same doubly-verified source.

This was **not a theoretical fix**: `p.mp3` and `s.mp3`, real audio files
already in this repo, each contain a genuine SSTV transmission of the
classic BBC Test Card F (the well-known "girl with a clown doll" test
image) — one in Robot 72 (color), one in Robot 8 B/W (new mode, see below).
Before this fix, both were reported as an unactionable "Unknown VIS code",
capped at low confidence, with no image ever produced. After the fix, both
decode to a clearly recognizable image with legible "BBC" text, confirmed
by eye (screenshots reviewed directly) — the tool had been silently missing
a real embedded image in its own test files every single scan. See
`results/*/artifacts/decoded/sstv/decoded_best_upscaled.png` for either file.

### SSTV: real slant/clock-drift correction
The per-line sync locator already re-anchored at the start of every line
(correcting *where* each line begins even under clock drift), but every
per-family decoder still sampled *within* each line using the mode's fixed
nominal millisecond durations — a constant playback-rate mismatch (e.g. a
recording's sample clock running a few percent off nominal) accumulates
across a line exactly like classic SSTV "slant", uncorrected. Verified: at
5% clock drift, Martin M2's mean abs error against the source image was
48.1/255 before the fix; `_measure_rate_scale` (comparing the empirically
observed sync-to-sync period against the mode's nominal line time) now
corrects it to <27/255 — roughly half the error, confirmed across Martin/
Scottie/Robot/PD family representatives.

### SSTV: confidence now actually reflects image quality
`validate_decoded_image`'s confidence formula (sync regularity + row
continuity + saturation) left confidence pinned at a constant 0.95 all the
way from a clean decode down to 10dB SNR, where mean abs error against the
source image had actually risen from 3.8 to 45.6/255 — none of the existing
metrics are sensitive to additive per-pixel noise, since they're aggregate
row/sync-level signals. Added `pixel_smoothness` (within-row adjacent-pixel
smoothness, the horizontal counterpart of the existing vertical
`line_continuity` check) — verified to track the same noise sweep cleanly
(0.99 clean → 0.68 at 10dB SNR) — and reweighted the confidence formula to
include it. A genuinely degraded decode now scores meaningfully lower
(0.90 vs 0.95), not identical to a clean one.

### SSTV: rx_sstv confidence derived from the image, not a fixed guess
`_try_rx_sstv`'s confidence was a hardcoded 0.70 regardless of what the
external tool actually produced. Since the decoder-selection step picks
whichever candidate has the *higher* confidence, a fixed placeholder meant
a garbled rx_sstv image could outrank a genuinely well-validated
custom-decoder result (whose real floor is 0.55). Now derived from the same
objective quality metric used to pick post-processing variants
(`_pp_quality_score`: Laplacian sharpness + contrast + entropy), with a
pixel-smoothness⁴ penalty added after a first attempt was found — via
direct testing against a synthetic pure-noise image — to score noise
*higher* than a real photo, since random noise is inherently high-frequency
and high-entropy, exactly what the raw metric rewards.

### SSTV: VIS detector false-positive hardening
Investigating the Robot 72 case above also required tightening the VIS
detector itself, since it was independently found to trigger on real MP3
music: (1) the per-window tone-dominance threshold (is a 10ms window's
energy actually concentrated in one of the 4 VIS frequencies, vs. generic
broadband audio) was raised from 0.15 to 0.30 — the real-signal floor is
~0.365 even at a severe 6dB SNR, so this keeps a wide margin; (2) a single
classified window could decide an entire 3-window bit period even when the
other windows were unclassified — now requires an actual majority, the same
standard already applied to leader/break/start-bit runs; (3) an
*unrecognized* VIS code (parity matching, but not one of this project's
verified real codes) is capped well below the "verified" confidence tier —
parity alone is only a 50%-by-chance check, and an unrecognized code can
never be decoded into an image anyway.

### 6 new SSTV modes: Wraase SC-2 120/180, Pasokon P3/P5/P7, Robot 8 B/W
Implemented following the audit's "verify before implement" mandate — every
timing constant is cross-checked against the same two independent
open-source references used for the Robot 72/PD fix above (cross-validated
against this project's own pre-existing Martin/Scottie/PD constants, which
match exactly). AVT-90/AVT-94 were investigated and **not** implemented:
they use a fundamentally different synchronization scheme (a digital
header repeated 32 times, no per-line horizontal sync pulse at all) that
doesn't fit this engine's per-line-sync decode model — implementing it
would need substantially new architecture unverifiable without a reference
recording, the same reasoning already applied to fldigi/wsjt-x. Reported
honestly as unimplemented rather than guessed at.
All 6 new modes round-trip tested (encode a known image → decode → compare)
with the same methodology as every pre-existing mode.

### Digital modes: minimodem — 3 new false-positive classes fixed
- minimodem's own stderr confidence value (`confidence=X` in its NOCARRIER
  trailer) was parsed but never used. Now gates acceptance: verified a
  plain 440Hz tone decoding as `"FJFJJJFJFFJ"` (confidence=1.61) and a
  frequency chirp decoding as `"LIIIWWWWWW"` (confidence=1.83) — both 100%
  printable, both previously accepted — while every genuine signal tested
  (Bell103/202, RTTY, TDD, SAME, full volume down to 1%) scored ≥2.28.
- RTTY and TDD are the same nominal 45.45-baud signal under two different
  stop-bit framings — feeding a real RTTY signal through the full baud
  sweep previously reported it *twice*, once correctly and once as
  `"_BVUGKMKWPQ"` garbage from the wrong framing. Now resolved by keeping
  only the higher-confidence framing.
- Found by running the full pipeline against a real MP3 already in this
  repo (not a synthetic signal): minimodem locked onto a carrier-like
  segment of ordinary music and decoded `"T _____________________T"` — 100%
  printable, confidence=3.16 (above the new noise-floor gate), but 88% one
  repeated character. Added a dominant-character-ratio check; every
  genuine decode verified in this pipeline has a ratio ≤26%.

### Digital modes: selective-call protocols (ZVEI/DZVEI/PZVEI/EEA/EIA/CCIR)
These decode one digit per sustained tone frequency with no frame/CRC
structure at all. Sweeping 8 plain sine tones (220Hz-2200Hz — ordinary
musical frequencies) through multimon-ng found 6 of them each triggered a
one-digit "decode" at confidence up to 0.59. A real selective-call address
is always several digits; now requires ≥4 before reporting, the same
principle as the pre-existing DTMF minimum-digit gate.

### NOAA APT: honestly reported as unsupported
No code anywhere in this project attempted NOAA weather-satellite APT
decoding, and it was simply absent from every report — no indication
whether that was deliberate or an oversight. Now reported the same honest
way as PSK31/FT8/JT65 (tool-presence check, no fabricated decode path).

### scanner.py: "Signals" summary row fixed
The CLI summary's filter condition was `digital.get(key) or vis_detected`
applied identically to all four labels (Morse/DTMF/Minimodem/SSTV) — since
`vis_detected` doesn't vary per label, whenever SSTV's VIS fired, ALL FOUR
were listed as detected even when Morse/DTMF/Minimodem had each
independently found nothing. Found via the same real-MP3 full-pipeline run
that surfaced the Robot 72 VIS bug.

### Tests
326 passing, up from 298 at the start of this pass. New: real (non-mocked)
end-to-end Morse/DTMF tests driving the actual multimon-ng binary; a
6-mode-family SSTV round-trip suite (was 5); slant-correction and
confidence-quality regression tests; VIS-code cross-reference test locking
in the corrected table; minimodem confidence-gate, rtty/tdd-conflict, and
repeated-character tests; selective-call digit-count tests; scanner-summary
tests.

### Known limitation (not fixed this pass, documented honestly)
`validate_decoded_image`'s structural checks (sync regularity, entropy,
continuity, saturation, pixel smoothness) were found — via a synthetic
Martin M2 signal decoded with all 14 other modes' geometries — to accept
*every* wrong-mode reconstruction at a similar confidence to the correct
one, because a smoothly frequency-modulated signal reshaped into almost any
reasonable raster retains some row/pixel continuity regardless of whether
the segmentation boundaries are actually correct. This does not cause
wrong images to be reported in the normal pipeline flow (VIS code
deterministically selects the one mode that gets decoded), but it means the
validator cannot, on its own, catch a wrong decode if an incorrect-but-
recognized VIS code were ever detected. A proper fix (e.g. a reference-free
metric that specifically discriminates correct from incorrect scanline
segmentation) would need real research effort beyond this pass's scope.

## [4.5.1] - 2026-07-07 — Fix: MP3/AAC Host's Own Frames Reported as Thousands of Fake "Extracted Files"

Bug report: scanning an ordinary MP3 file reported "Extracted: 2857 files" —
reproduced exactly against `p.mp3` (811KB) in this repo, which independently
confirmed the report to the byte (2855 records, off only by the two files
this pass also fixed — see below).

### Root cause
`find_embedded_files()` scans for the `MP3_FRAME` sync (`\xff\xfb`) at every
byte offset in the file. In a real MP3, that sync recurs at every single
frame boundary throughout the entire audio stream. `_validate_mp3_frames`
correctly reports "yes, a valid, self-consistent run of MPEG frames
continues from here" at *every one* of those offsets, because it's true —
it's the same continuous audio. `extraction.py::_scan_signatures` then
treated every one of those validated runs as a *separate* "embedded file"
and wrote each one to disk, with no awareness that (a) the host file being
scanned is itself that same MP3/AAC format, so this is its own native
bitstream, not a nested file, and (b) even setting that aside, each
validated run heavily overlaps the previous one, so the same bytes were
being carved out dozens of times over.

### Fix (`extraction.py`)
- `_host_audio_frame_family()` sniffs the scanned file's own leading bytes
  (`ID3`/`\xff\xfb` → mp3, `\xff\xf1`/`\xff\xf9` → aac). `_scan_signatures`
  now skips that family's magic types entirely when the host is already
  that format — a real embedded MP3/AAC inside a *different* container
  (WAV, PNG, etc.) is still fully detected by every other registered magic
  type.
- Added containment-range dedup as defense in depth: once a signature of a
  given type validates as a real run spanning `[offset, offset+size)`, any
  other candidate offset of the same type inside that span is skipped
  rather than re-validated and re-carved as a second "file" — covers the
  cross-container case (e.g. a real MP3 stream nested inside a WAV host)
  where dozens of internal frame boundaries would otherwise still each
  produce a duplicate record.
- Verified: `p.mp3` (811KB) went from 2855 spurious "extracted" MP3_FRAME
  records to 0; `s.mp3` (115KB) went from 404 to 0. A synthetic WAV with a
  genuinely embedded ZIP still extracts correctly (confidence 1.0, CRC
  verified) — the suppression only applies to the host's own native audio
  frame family, not to real embedded-file detection generally. A synthetic
  WAV with a genuinely nested, contiguous MP3 stream appended is still
  reported — exactly once, not once per internal frame boundary.

### Also fixed while investigating (same test file, same root cause class —
weak structural validators accepting coincidental byte matches over huge
haystacks)
- **BMP** (`validate.py::_validate_bmp`): a declared file size was only
  checked against a fixed 200MB absolute ceiling, not against how many
  bytes actually remain in the host file. `p.mp3` had a `'BM'` byte pair
  followed by a header claiming a 120MB file size — comfortably under the
  200MB ceiling, but impossible in an 811KB file. Now also rejected if the
  declared size exceeds the bytes actually remaining.
- **JPEG** (`validate.py::_validate_jpeg`): previously accepted SOI + one
  plausible next-marker byte, then did an *unbounded* `chunk.find(b"\xff\xd9")`
  for EOI across the entire remainder of the host file — in an 811KB MP3
  this coincidentally matched a random byte pair far from the SOI and was
  reported as an "extracted" JPEG. Replaced with a real marker-chain walk
  (each segment's own 2-byte length field says exactly where the next
  marker is; SOS's entropy-coded scan data is skipped correctly rather than
  searched blindly), requiring either an EOI reached via a consistent chain
  or 4+ consecutive valid segments before accepting a truncated stream —
  mirrors this project's existing MP3/AAC frame validators requiring
  several consecutive consistent units rather than one lucky match.

### Tests
301 passing, up from 298. New: `test_mp3_host_native_frames_not_reported_as_extracted`,
`test_embedded_mp3_stream_in_wav_reported_once_not_per_frame`,
`test_bmp_declared_size_exceeding_remaining_bytes_rejected` (all in
`TestExtractionAnalyzerV3`/`TestValidate`). The pre-existing
`test_jpeg_with_valid_marker` fixture was itself not a byte-accurate JPEG
marker chain (raw filler bytes between the APP0 segment and EOI, which no
real JPEG encoder produces) — rewritten to a real, correctly-length-prefixed
APP0/JFIF segment followed directly by EOI.

## [4.5.0] - 2026-07-06 — Professional Forensic Report: No Developer Debug Surface

Follow-up to 4.4.0's usability pass, driven by explicit feedback that the
report still looked like a developer debug dump rather than a professional
CTF/DFIR forensic report. This removes the debug-facing "Advanced" menu
entirely (not just collapsed) and replaces it with an analyst-facing
"Tools Used" section, and rewords the one remaining raw internal counter
that leaked into the scan summary.

### Advanced section deleted entirely
Timeline, Performance (phase timing), Plugin Debug Output, Raw Tool Output,
Scan Log, Rejected Findings, and Rejected Extraction sections — along with
their sidebar nav entries, the collapsible "Advanced ▶" toggle (JS + CSS),
and the now-dead `.timeline`/`.tl-item` CSS rules — are gone from
`html_report.py`, not hidden. Rejected/unsupported findings and extraction
records are still fully present in `report.json`; they are simply never
rendered in the analyst-facing HTML at all now (previously they were
itemized under Advanced). `_needs_manual_review()`/`_group_duplicate_digital_findings()`
and the rest of the confidence-tier machinery are unaffected — only the
now-unused rendering methods for these seven sections were removed.

### New: Tools Used section
Replaces Tool Execution/Performance/Plugin Debug/Raw Tool Output with one
expandable card per tool that actually contributed to this scan — Tool
Name, Purpose, Status, (execution time where genuinely tracked — plugins
only; other tools honestly omit it rather than inventing a number),
Output, and Conclusion, built from each tool's own real result data:
exiftool/ffprobe metadata, binwalk/foremost/scalpel carve counts, strings
count, multimon-ng's real per-mode decode counts (e.g. "EIA (41)"),
minimodem, the custom SSTV decoder's mode/VIS-code/image, zbarimg's QR
hit, the flag's own encoding-decoder chain (e.g. "Base64 Decoder"), OCR,
and any plugin that produced findings. A tool that was unavailable or
produced nothing gets no card at all — verified with a regression test
that a disabled/absent tool never appears.

### Rewording: "False positives: N" → "Rejected findings: N filtered automatically"
The only remaining raw internal counter (`scanner.py`'s CLI summary table)
is renamed and only appears there — the HTML Executive Summary never
displayed a raw false-positive count in the first place (confirmed by
inspection, not changed) and the Extracted Files section already used
"rejected" phrasing from Phase 2's original accounting work.

### Report order (fixed)
Executive Summary → Flags → Manual Reproduction Guide → SSTV Analysis →
QR Analysis → OCR → Extracted Files → Audio Analysis (Preview/Visuals/
Forensics) → Digital Modes → Metadata → Binary → Verified Findings →
Tools Used. Binary Analysis (entropy/appended-data/embedded-signature
summary) was kept — it wasn't named in the removal list and its content is
real forensic signal (appended-data-after-EOF is a standard CTF technique),
not developer debug output — but repositioned to just before Verified
Findings rather than living under the deleted Advanced menu.

### Tests
- 298 passing, up from 282 at the start of this pass (296 after 4.4.0, +2
  net after removing/replacing 6 tests that covered now-deleted sections
  and adding tests for Tools Used content, the false-positive rewording,
  and full section-order verification against a real rendered report).

## [4.4.0] - 2026-07-06 — SSTV Multi-Variant Selection, Reproduction Guide, QR Analysis

Continuation of the confidence-tiered reporting work in 4.3.0, focused on
SSTV image quality and turning the report into something a CTF player can
follow to reproduce a flag by hand, without reading source code.

### SSTV: multi-recipe post-processing + composite quality/OCR/QR scoring
Extended the existing 3-recipe post-processing pipeline with a 4th
(`clahe_bilateral`: CLAHE tiled adaptive histogram equalization + an
edge-preserving bilateral filter, real cv2 implementations with genuine
numpy-only fallbacks — not placeholders) and changed variant selection from
pure image-quality score to a composite score that also weights real OCR
confidence and QR-decode success, since a "sharp-looking" variant that
neither tesseract nor zbarimg can actually read is less useful than a
slightly softer one that decodes cleanly. Added:
- **Horizontal line alignment** (cross-correlation-based per-row jitter
  correction — a real, well-documented SSTV artifact from audio timing
  drift, distinct from whole-image deskew/perspective, which remain
  deliberately unimplemented since there is no camera geometry in a
  directly-reconstructed scanline raster for either to correct).
- **Adaptive sharpening** (unsharp-mask strength now scales with a measured
  blur metric instead of one fixed amount for every image).
- **Automatic rotation**, gated on a real signal — tesseract's own OSD
  (orientation-and-script-detection) pass, applied only when it reports a
  rotation with reasonable confidence; never a blind geometric guess.
- New exports: `decoded_best.png`, `decoded_best_upscaled.png` (2x Lanczos),
  and every variant saved to `decoded_all_variants/` for transparency.
- Note: "sync refinement" and "VIS-based timing correction" were already
  real, implemented, tested decode-time features in `sstv_decode.py`
  (`_find_sync`'s windowed-argmin drift tracking, anchored to the VIS
  preamble's end sample) predating this pass — not re-implemented, just
  confirmed present rather than assumed missing.

### Manual Reproduction Guide (replaces the old raw Hint Engine text dump)
New numbered, beginner-friendly step-by-step guide (`_build_reproduction_guide`)
built entirely from a scan's own real results — every Evidence/Why/Result
line quotes an actual Finding's evidence/reason/value or a real results
field, nothing invented. Covers SSTV detection → image reconstruction → OCR
→ QR → encoded-flag recognition/decode → Final Flag + confidence, or an
extraction-based chain when there's no SSTV. Hint Engine text is preserved
as supplementary "Additional Investigation Tips" rather than discarded.
Reordered `scanner.py` so the Hint Engine runs *before* HTML generation
(previously after, so its output could never reach the report at all).

### Dedicated QR Analysis section
Split QR out of the old combined "OCR & QR" into its own section: decoded
QR image, decoded text, encoding detected (real `is_likely_base64`/hex
pattern check, reusing the same tightened detector from 4.3.0), decoded
value, confidence, raw bytes (hex), copy button — pulling from both the
general OCR module's zbarimg pass and the SSTV pipeline's own.

### Flag evidence chain
Each flag now shows a real "Audio → SSTV → Image → QR → [Encoding] → Flag"
breadcrumb with clickable anchors, built by checking which stages actually
ran/contributed for this scan (`_flag_evidence_chain`) — not a fixed
template applied regardless of what happened.

### Verified Findings: duplicate digital-decoder grouping
Findings from `digital`/`multimon`/`minimodem` that repeat 3+ times (a real
pattern — e.g. many recursively-extracted files each independently
triggering the same multimon-ng mode) are grouped into one "Digital
Decoder — EIA (×41)" card with occurrence count and best confidence/output,
instead of dozens of visually-identical rows. Aggregate statistics are
unaffected — only the rendered table groups them.

### Report reorder
Executive Summary, Flags, Manual Reproduction Guide, SSTV Analysis, QR
Analysis, OCR, Extracted Files, Audio Analysis, Digital Modes, Metadata,
Verified Findings, then Advanced (unchanged content, moved to match the new
primary-section order).

### Tests
- 296 passing, up from 282. New tests cover SSTV variant scoring/selection
  (composite metric verified to score a sharp image higher than a blurred
  one), export paths, the reproduction guide's step generation, QR section
  rendering, flag evidence chains, and duplicate-decoder grouping.

## [4.3.0] - 2026-07-06 — Analyst-First Report, Multi-Variant SSTV Selection, Tighter Thresholds

Continuation of the v4.2 usability/accuracy work, focused specifically on
making `report.html` answer three questions immediately (was a flag found?
what's the highest-confidence evidence? what should I investigate next?),
on real SSTV image-quality improvements, and on measurably tightening five
detectors' false-positive thresholds.

### 1. HTML report: primary sections restricted to the analyst workflow
The sidebar now contains exactly: Executive Summary, Flags, SSTV, Extracted
Files, OCR & QR, Audio Analysis (Preview/Visuals/Forensics), Digital Modes,
Metadata, Verified Findings, and the new Manual Investigation. Everything
else (Timeline, Binary Analysis, Performance, Plugin Debug Output, Raw Tool
Output, Tool Execution, Scan Log, and the two new Rejected-data sections
below) lives behind the existing collapsible Advanced group — nothing is
deleted, all raw data is still written under `results/<stem>/raw/`, it's
just no longer competing for attention with the primary triage path.

### 2. Rejected findings/extraction excluded from the primary report AND its statistics
Previously "Rejected"-tier findings were merely hidden by the <50%-confidence
toggle (still counted in "Total findings", still in the main table's DOM).
Now `generate()` splits `all_f` into non-rejected vs. rejected before any
other computation, so Executive Summary counts, the Verified Findings table,
and the tier-summary cards never include a Rejected-tier item — full detail
moves to two new Advanced sections, **Rejected Findings** and **Rejected /
Unsupported Extraction Records**, so nothing is silently discarded, only
excluded from the primary triage view and its aggregate numbers.

### 3. New Manual Investigation section
The Hint Engine (`hint_engine.py`) already generated real, results-derived
"what to try next" text into `hints.txt`, but `scanner.py` ran it *after*
`HTMLReport.generate()`, so none of that content ever reached the primary
report. Reordered — Hint Engine now runs first, and its output is stored in
`all_results["hints"]` and rendered directly in the new Manual Investigation
section, next to a clear "flag confirmed" vs. "manual review recommended"
status line (backed by the same `_needs_manual_review()` check used by the
Executive Summary card, extracted as a shared helper so both can never
disagree).

### 4. Executive Summary: Best Extracted Artifact + Manual Review Recommended
Added a "Best Extracted Artifact" card (highest-confidence record among the
same "confirmed" extraction statuses the Extracted Files dashboard counts)
and an explicit "Manual Review Recommended" card with a pointer to the new
Manual Investigation section, alongside the existing Overall Confidence /
Most Important Finding / SSTV-decoded / OCR / QR cards from v4.2.

### 5. Tool Availability: only tools tied to the current scan's configuration
`scanner._check_tools()` previously ran a hardcoded 19-tool preflight check
regardless of what the scan would actually do, including `sox` (never
invoked anywhere in this codebase — confirmed by repo-wide grep) and an
unconditional `rx_sstv` check. Now: core tools that always run
(file/exiftool/mediainfo/ffprobe/ffmpeg/strings/xxd/hexdump) are always
checked; every optional tool is only checked if the `[analysis]` config flag
that actually gates its pipeline step is enabled (e.g. `rx_sstv` only
appears if `run_sstv = true`, `steghide` only if `run_steghide = true`).
`sox` is removed entirely — it was never wired to any flag because nothing
in the codebase calls it.

### 6. SSTV: multi-variant post-processing + objective quality selection
`_postprocess_image` now generates three processing recipes (`standard`,
`high_contrast`, `minimal`) from the same auto-cropped base image instead of
one fixed sequential pipeline, scores each with a reference-free objective
quality metric (Laplacian-variance sharpness + pixel-stddev contrast +
histogram entropy — verified in a new test to actually score a sharp image
higher than a Gaussian-blurred copy of itself), and embeds only the
highest-scoring variant in the report. OCR and QR/barcode detection run
against **every** variant (not just the winner) and the strongest result
across all of them is kept — a variant can look objectively better and
still not be the one tesseract/zbarimg happen to read best. Added:
- **Horizontal line alignment**: corrects the real, well-documented SSTV
  artifact of per-scanline horizontal jitter from audio timing drift (cross-
  correlates each row against the previous one and rolls it into alignment)
  — distinct from whole-image deskew/perspective correction, which remain
  deliberately unimplemented (documented in `sstv.py`) because there is no
  camera geometry in a directly-reconstructed scanline raster for either to
  correct.
- **Adaptive sharpening**: unsharp-mask strength now scales with a measured
  blur metric (stronger on blurrier input, lighter on already-sharp input)
  instead of one fixed percentage for every image.
- `results["sstv_variant_selected"]` and `results["sstv_variant_scores"]`
  exposed for transparency in `report.json`; every variant is also saved to
  `decoded_sstv/debug/variant_<name>.png`.

### 7. False-positive threshold tightening (with regression tests pinning each change)
- **Base64** (`is_likely_base64`): printable-ratio floor raised from 60% to
  75% (the magic-byte-match branch is unaffected — that's already
  independent strong evidence). Also fixed a stale docstring that claimed
  40%/60% inconsistently with the actual code at different points in its
  history.
- **OCR**: confidence floor raised from 40% to 55% — the module's own
  docstring had claimed a 60% default for multiple versions while the real
  constant was 40%; measured against known noise/spectrogram OCR garbage,
  40% let too much through.
- **Morse**: minimum decoded alphanumeric characters raised from 2 to 3 —
  still accepts the canonical "SOS" (3 chars) test signal, but no longer
  reports on a 2-character decode that's too easily produced by chance.
- **MP3 frame validation**: the consecutive-frame run now also requires
  constant *sample rate* across every frame (bitrate is deliberately still
  allowed to vary — real VBR streams do this legitimately). This brings MP3
  validation up to the same rigor the AAC/ADTS validator already had
  (sample rate + channel config consistency), closing a gap where a
  coincidental run of frame-syncs with plausible-but-differing sample rates
  could previously still count toward the 3-consecutive-frame minimum.
- **XOR/Caesar/ROT/DTMF/QR**: audited — already gated on strong independent
  evidence (XOR: printable ratio ≥90% + language score for generic
  patterns; Caesar/ROT/Atbash: only reported when decoded text matches an
  actual `flag{...}`-style structural pattern, not a fuzzy "looks like
  English" heuristic; DTMF: ≥3 validated digits; QR/barcode: a hard
  decode-or-not with no fuzzy threshold to tighten). No changes made where
  the existing bar was already appropriately strict — see CHANGELOG history
  for the phases that established each of these.

### Tests
- 296 passing, up from 282. 14 new tests: rejected-findings/extraction
  exclusion from the primary report and its stats, Manual Investigation
  rendering, Tool Availability config-gating (sox absent, rx_sstv tied to
  `run_sstv`, steghide tied to `run_steghide`), SSTV multi-variant scoring
  and selection (including a direct sharp-vs-blurred metric check), and one
  pinned regression test per tightened threshold (base64 ratio, OCR
  confidence, Morse min-chars, MP3 sample-rate consistency).

## [4.2.0] - 2026-07-06 — Confidence-Tiered Reporting, Report Redesign, SSTV Best-of Decoding

A focused pass on the two things most likely to make or break real-world
use of this tool: whether a reported finding can actually be trusted, and
whether the report surfaces that trust level instead of a flat list of
percentages. Also extends the SSTV pipeline to choose the best of multiple
decode attempts and to apply a materially deeper (but still honest,
non-fabricated) image-enhancement pipeline before OCR/QR/marker analysis.

### 1. Confidence-tier classification (`findings.py`)
Added `ConfidenceTier` (`VERIFIED`/`PROBABLE`/`POSSIBLE`/`REJECTED`) and
`confidence_tier()`, layered on top of the existing Phase 5 numeric
confidence engine (`EvidenceLevel`/`confidence_for_evidence`) rather than
replacing it — every analyzer already produces a 0.0-1.0 confidence; this
adds the human-facing classification that reporting groups/hides by.
`LOW_CONFIDENCE_DISPLAY_THRESHOLD = 0.50` is the single source of truth for
what counts as "low confidence" everywhere in the report.

### 2. HTML report: findings grouped by tier, sorted by confidence, low-confidence hidden by default
- The findings table now shows a Tier badge per row (Verified/Probable/
  Possible/Rejected) in addition to severity, sorted by (tier, confidence)
  descending instead of severity alone.
- A tier-count summary (e.g. "12 Verified, 4 Probable, 30 Possible") renders
  above the per-module breakdown that already existed.
- Findings below 50% confidence are hidden by default (`display:none` via a
  `low-conf-row` CSS class) with a "Show Low Confidence Findings (&lt;50% —
  N hidden)" checkbox that reveals them — they are never removed from
  `report.json`, only de-emphasized in the human-facing HTML view.

### 3. HTML report: flags grouped into Verified / Possible / Encoded / Rejected
Previously every flag match rendered in one flat "Possible Flags" list
regardless of how it was found. Now split by encoding/confidence into
Verified Flags (plaintext, ≥80% confidence), Possible Flags (plaintext,
lower confidence), Encoded Flags (base64/etc.), and Rejected Candidates
(explicitly tagged `rejected`, if any) — empty groups don't render. Cipher
brute-force sweep output was already never merged into `flags_found`
(confirmed by reading `flags.py`: `cipher_results` is a separate dict), so
there was nothing to filter out for "never show random XOR/Caesar output" —
this only had to sort what was already a real pattern match.

### 4. HTML report: sidebar redesign, Executive Summary, Tool Execution split
- Sidebar reorganized into the primary "is this challenge solved?" workflow
  (Executive Summary, Flags, SSTV, Extracted Files, Findings, Digital Modes,
  OCR & QR, Metadata, Audio Analysis, Tool Execution, Scan Log) with a
  collapsible **Advanced** nav group (closed by default, toggled via JS) for
  Timeline, Binary Analysis, Performance, Plugin Debug Output, and Raw Tool
  Output — deep-dive/debug sections no longer compete for attention with the
  primary triage sections.
- The dashboard is now an explicit **Executive Summary**: adds Overall
  Confidence, SSTV Decoded (yes/no), OCR results count, a "Most Important
  Finding" card (highest-confidence finding or first flag), and a "Manual
  Review Needed" indicator (true when no flag was found and nothing reached
  the PROBABLE tier).
- **Tool Execution** is now its own top-level section (pass/fail per tool,
  no raw output) — previously combined with Performance's phase-timing
  table under one "Performance & Tool Execution" heading.
- New **Scan Log** section (tail of the run's log file) and **Raw Tool
  Output** / **Plugin Debug Output** sections under Advanced — raw stdout
  is now listed per-tool in collapsible `<details>` blocks instead of never
  being surfaced in the primary report at all.
- "Deskew" and "Perspective Correction" were requested but are not applied
  anywhere (SSTV or otherwise) without a genuine source of skew/perspective
  distortion to correct — applying either to data that was never
  photographed/scanned would be exactly the "confidently wrong" fabricated
  processing this project's own engineering practice avoids. Documented in
  `sstv.py` rather than silently omitted.

### 5. SSTV: best-of decoder selection
`sstv.py`'s decode step previously used rx_sstv's output unconditionally if
it produced *any* image, only falling back to the custom FM-scanline decoder
if rx_sstv didn't run or produced nothing. Now both are tried whenever
applicable and `_select_best_decode()` keeps whichever has the higher
*validated* confidence — rx_sstv's output was never independently
structure-validated the way the custom decoder's is, so a rx_sstv success
is no longer assumed to beat a custom-decoder success. Only the winning
decoder's "SSTV Image Decoded" finding is added (previously the custom
decoder appended its finding unconditionally on success, which — before this
change — could have left a stale finding referencing an image that wasn't
actually the one in the report, had a "try both" policy existed without
this fix). Also fixed: a successful rx_sstv decode previously produced no
`Finding` at all even though its image was used in the report — it's now
reported like any other decode, with an honest "not independently
structure-validated" false-positive-risk note.

### 6. SSTV: expanded post-processing pipeline
`_postprocess_image` grew from 2 steps (contrast/histogram + adaptive
threshold) to a real pipeline: auto-crop (trims genuinely blank border rows/
columns left by sync-pulse regions, with a guard against over-cropping a
low-contrast-but-valid image), denoise, gamma correction, color balance
(gray-world white balance), contrast/histogram equalization (existing),
sharpening (unsharp mask), then adaptive threshold + morphological
open/close cleanup for the black/white variant. OpenCV is used for
denoising and morphology when installed (`cv2.fastNlMeansDenoisingColored`,
`cv2.morphologyEx`); every step has a pure PIL/numpy/scipy fallback and is
individually try/excepted, so a missing optional dependency degrades only
that one step — confirmed by actually running the pipeline with
numpy/scipy/cv2 all removed from `sys.modules` (see tests): the four
PIL-only steps still applied and nothing crashed. `results["postprocess_steps"]`
records which steps actually ran, for transparency in `report.json`.

### Tests
- 282 passing, up from 268. 14 new tests: confidence-tier classification
  (thresholds + rejected-tag override), low-confidence hiding, tier badges/
  summary cards, flags grouping, sidebar/Advanced-group/Executive-Summary
  presence, Tool Execution + Scan Log sections, best-of decoder selection
  (both directions, plus the multi-decoder warning), and the post-processing
  pipeline (both the happy path and the numpy/scipy/cv2-absent fallback path).

## [4.1.0] - 2026-07-06 — Custom SSTV Image Decoder + Marker-Detection Wiring Fix

### Custom FM-scanline SSTV decoder (`sstv_decode.py`)
Added a real, dependency-free SSTV image decoder used as the primary decode
path in `sstv.py` (`_try_custom_decoder`), replacing reliance on the
best-effort `rx_sstv` external binary alone. Given a VIS-detected mode and
the sample position where the VIS preamble ends, it demodulates the FM
scanline signal directly into pixel data and independently validates the
result (sync-pulse regularity, pixel entropy, line-to-line continuity,
saturation, and VIS parity) before ever writing a "decoded" image — a
decode that fails validation is recorded as `rejected` with reasons, never
silently presented as a finding. See `sstv_decode.py`'s module docstring for
the exact mode dispatch table and which modes are implemented vs. pending.

### Bug found and fixed: fiducial marker detection was fully implemented but never invoked
`sstv.py::_detect_markers` (ArUco/AprilTag detection via `cv2.aruco` /
`pupil_apriltags` on a decoded SSTV image, with a real `Finding` emitted on a
hit) was completely implemented but not called from anywhere — `run()`
decoded and post-processed the image, ran OCR/QR/EXIF via
`_analyze_decoded_image`, and returned, without ever reaching the marker
detector. No test exercised it either, so the gap was invisible from the
test suite alone. This is the same class of bug as the Phase 7 "decoded
payloads never actually extracted" issue: a fully-written code path that the
pipeline simply never reaches. Fixed by calling `_detect_markers` after
`_analyze_decoded_image` in `run()`, and by adding the decoded markers list
to the `sstv_report.txt` summary (previously omitted even though the field
existed in `results["markers"]`). A regression test now asserts
`_detect_markers` is actually called with the decoded image path whenever
one is produced, using a mock rather than `assert valid == True` on the
overall result — the exact testing gap that let this ship unnoticed.

### Dead code removed
`binary.py::BinaryAnalyzer._is_printable` was a fully-written, unreachable
duplicate of `findings.printable_ratio` (the version actually used
elsewhere in the codebase) — not a "pending" method, just an orphaned
earlier draft that never got deleted when it was superseded. Removed.

### Tests
- 268 passing, up from 267. New test:
  `TestSSTVAnalyzer::test_markers_detection_is_invoked_when_image_decoded`.

## [4.0.0] - 2026-07-05 — v4 Specification Complete (Phases 1-16)

Full engineering pass against the "Audio Stego Solver v4" specification:
audit, extraction pipeline redesign, structural validators, real MP3/AAC
frame validation, evidence-based confidence engine, interactive DFIR
dashboard, recursive analysis engine, encoding engine, expanded DSP forensics,
SSTV VIS detection, digital-mode audit, plugin metadata, performance work,
CLI commands, 243 tests, and documentation. See PROJECT_AUDIT.md for the
full audit trail and the phase-by-phase sections below for detail on each.

**Headline results:**
- Test suite: 118 → 243 passing (0 skipped with full DSP deps installed)
- Found and fixed 6 fabricated/non-functional integrations that predated
  this pass (multimon-ng "SSTV" demodulator that doesn't exist, qsstv's
  nonexistent CLI flags, minimodem's invalid BELL103/BELL202 arguments, a
  numerically-impossible VIS code table, a CLI command that crashed on every
  successful scan, a combinatorial-explosion bug in the decode engine) — all
  caught by actually executing the code against real inputs, not by review.
- Extraction accounting no longer conflates "exists on disk" with "verified"
  (the spec's original complaint) — every artifact from every tool now flows
  through one evidence pipeline with SHA256/status/confidence/depth/provenance.

See the phase sections below (still present for detailed history) and
CONTRIBUTING.md / README.md for what changed in each area.

---

## Phase 14: CLI Commands — Plus a Live Production Bug Found

### Critical bug found and fixed: `audio-stego scan` always exited with failure
While building the new commands, actually running `audio-stego scan` end-to-end
(not just its unit-tested pieces) showed it printing a complete, correct
"Analysis Complete" summary and a valid `report.html` — and then crashing:

```
Unexpected error: 'AudioStegoScanner' object has no attribute '_setup_output_dir'
```

`main.py`'s `_scan_file`/`_scan_directory` were calling `scanner._setup_output_dir(path)`
to get a directory for a *second*, separate plugin run — but that method
doesn't exist (the real method is `_setup_store`, added when `ArtifactStore`
was introduced) and hadn't been updated. Plugins already run once, correctly,
inside `scanner.scan()`'s own pipeline (step 8) — this was fully redundant
duplicate logic on top of being broken. Every single `audio-stego scan`
invocation exited with code 1 even on complete success, which would break any
CI/automation checking the exit status. Fixed by removing the redundant call
entirely and wiring `--no-plugins` to a proper `run_plugins` config flag that
gates the *real* plugin execution inside the scanner.

### New commands
- `doctor` — environment health check (required/optional external tools +
  optional Python DSP packages), non-zero exit if a required tool is missing.
- `validate FILE` — run the Phase 3 structural validators against a file's
  own header (not embedded-signature scanning — "is this file what it claims
  to be").
- `extract FILE` — run only the unified extraction pipeline, standalone.
- `decode TEXT` (or `--file`) — run the Phase 8 encoding engine
  (`decode_all`/`recursive_decode`) against arbitrary text from the CLI.
- `report DIR` — print a summary of an existing scan's `report.json`.
- `benchmark FILE` — full scan with a per-phase timing table (reuses the
  Phase 6/9 `_performance` data).
- `clean [--output DIR]` — remove a results directory (confirmation prompt
  unless `--yes`).
- `verify DIR` — re-hash every extracted artifact recorded in `report.json`
  and confirm it still matches its recorded SHA256 — a real chain-of-custody
  check, made possible by exporting the Phase 2 evidence records (see below).
- `stats DIR` — extraction status counts + average confidence from an
  existing scan.
- `plugins` — alias for the existing `list-plugins` (also now shows author,
  dependencies, and supported file types, from the Phase 12 metadata work).

### Also fixed while wiring `verify`/`stats`
`report.json` never exported the Phase 2 unified evidence records
(`extraction.records` — the ones with sha256/status/confidence/depth/
source_tools) at all; only the raw `extracted_files` path list and legacy
`binwalk` output were included, so nothing in the JSON report reflected any
of this project's Phase 2-5 work. Added `extraction_records` and
`extraction_summary` to the JSON report. Also fixed the report's `meta.version`
being hardcoded to `"1.1.0"` regardless of the actual installed version.

### Tests
- 243 passing (245 total, 2 skipped), up from 231. New tests invoke every
  command end-to-end via Click's `CliRunner` (not just unit-test internals),
  including a direct regression test for the exit-code-1-on-success bug and
  confirmation that `--no-plugins` actually prevents `PluginManager.run_all`
  from being called.

## Phase 13: Performance — Hash Caching, Reduced Rescanning

Most of this phase's ground (artifact caching, deduplication, thread-safe
parallel execution) was already covered by the Phase 2 unified evidence
pipeline and the existing `ThreadPoolExecutor` usage in `scanner.py` (worker
threads each own an independent analyzer and only the main thread writes to
`self.all_results`, after both futures resolve — no concurrent shared-state
mutation to fix). Two concrete, measurable gaps remained:

- **Duplicate SHA256 hashing of the same file.** `extraction.py`'s
  `_recursive_multipass` hashes a file to check its dedup set, then calls
  `_process_tool_artifact()`, which hashes the *same file* again — every
  carved artifact was being read and hashed twice per pass. Added
  `ExtractionAnalyzer._sha256_cached()`, a simple per-scan path→hash cache
  (safe without mtime checks, since every path here is a freshly-carved
  output that never changes again within a run), and routed all five
  internal hashing call sites through it.
- **Full-tree rescan on every recursive-decode pass.** `recursive_engine.py`'s
  `_collect_text_from_new_artifacts()` walked and re-read *every* file under
  `extracted/`/`hidden_files/` from scratch on each pass, including files a
  previous pass had already read — this engine only ever adds files, never
  modifies existing ones, so re-reading them was pure waste. Now tracks
  `_scanned_paths` and only reads genuinely new files each pass.

### Tests
- 231 passing (233 total, 2 skipped), up from 228. New tests verify the
  SHA256 cache actually avoids a second real hash computation (by counting
  calls to the underlying hash function, not just checking the result), and
  that a second recursive-engine pass does not reopen an already-read file.

## Phase 12: Plugin Framework Metadata

- `BasePlugin` now declares `author`, `supported_file_types`, `dependencies`,
  `input_types`, `output_types` (in addition to the existing `name`/`version`/
  `description`), plus a `metadata()` classmethod for introspection.
- `PluginManager.run_all()` now times every plugin's execution
  (`execution_time`, recorded even on failure) and attaches each plugin's
  full `metadata()` to its result — surfaced in the plugin summary text file
  and the `audio-stego list-plugins` CLI command (now also shows author,
  dependencies, and supported file types, not just name/version/description).
- `yara_plugin.py` declares its real dependency (`yara-python`) — the only
  built-in plugin with an actual external library requirement; the others
  are pure-stdlib and correctly declare none.
- Plugin failure isolation was already correct (confirmed by tests, not
  changed): a plugin raising an exception is caught per-plugin in
  `run_all()`, logged, and recorded as `{"error": ...}` without stopping the
  scan or preventing other plugins from running.

### Tests
- 228 passing (230 total, 2 skipped), up from 223. New tests cover required
  metadata fields, the yara dependency declaration, execution-time recording
  across all discovered plugins, and fault isolation (a deliberately broken
  plugin injected into a real `PluginManager` must not stop the others).

## Phase 11: Digital Modes — Audit and Fixes

Applied the same "verify the tool's real CLI contract before trusting the
code" methodology from Phase 10 to `digital.py`. The good news first: the
existing `multimon-ng` all-mode sweep is genuinely correct — its demodulator
list matches multimon-ng's real, verified set exactly, so POCSAG and FLEX
pager decoding already worked for real. Two real bugs were still found:

### Bugs found and fixed
1. **`"BELL103"`/`"BELL202"` are not valid minimodem arguments.** Verified
   against minimodem's own usage text and by actually running it: passing
   `--rx BELL103` exits 1 with a usage dump every time. Bell103/Bell202 are
   just the descriptive names minimodem's help text uses for baud rates
   300/1200 — which were already in the sweep numerically. Every scan was
   wasting two guaranteed-to-fail decode attempts (each with its own
   timeout) for zero benefit. Removed; `rtty`/`tdd`/`same` (confirmed to
   work, case-insensitively in practice) were kept.
2. **`digital.py::_detect_sstv`** was a second, independent instance of the
   exact fake `multimon-ng -a SSTV` call removed in Phase 10 — dead code
   that could never produce a result. Removed (SSTV detection now lives
   solely in `sstv.py`).

Also fixed the `scanner.py` pipeline-ordering bug uncovered while tracing
through this (SSTV ran before Digital modes but depended on Digital modes'
WAV-conversion output) — see Phase 10 entry.

### AX.25/APRS
No new integration needed — `AFSK1200` (Bell 202, 1200 baud) *is* the AX.25
packet-radio physical layer that APRS runs on, and it was already correctly
included in the multimon-ng sweep. It's now labeled explicitly ("AFSK1200
(AX.25/APRS packet layer)") so a hit reads as what it actually is instead of
an opaque demodulator name.

### PSK31 / Olivia / Hellschreiber / FT8 / JT65
Not implemented as automatic decoders. All five normally require fldigi
(PSK31/Olivia/Hellschreiber) or wsjt-x/jt9 (FT8/JT65, explicitly "best
effort" per the spec), and none of the three expose a simple one-shot batch
CLI contract the way multimon-ng/minimodem do:
- fldigi's only scriptable interface is XML-RPC — stateful and session-based,
  not "run once on a file."
- wsjt-x/jt9 expect specific 15-second-aligned framing that would need
  reference recordings to validate against.

Building an integration for either without being able to verify it works
would repeat exactly the mistake Phase 10 found and removed. Instead,
`_check_advanced_mode_tools()` reports each tool's presence/absence
honestly — "gracefully skip unavailable tools," applied to something this
project genuinely can't verify rather than something it merely didn't get
to.

### Verified end-to-end with real audio
Beyond unit tests, generated actual modem-encoded audio with
`minimodem --tx` (Bell202 1200-baud and RTTY) and confirmed the analyzer
decodes real signals correctly end-to-end, not just that arguments look right.

### Tests
- 223 passing (225 total, 2 skipped), up from 221. New tests cover the
  BELL103/BELL202 removal (and confirm rtty/tdd/same/300/1200 remain), the
  AFSK1200→AX.25/APRS labeling, and honest advanced-tool reporting.

## Phase 10: SSTV Pipeline — Replaced Fabricated Decoders

This phase started by checking the CLI contracts of the tools `sstv.py`
actually invokes, since qsstv/multimon-ng/rx_sstv/tesseract/zbarimg all
happen to be installed in this dev environment — and found the existing
implementation had never been able to work.

### Two fabricated integrations found and removed
1. **`multimon-ng -a SSTV`** — verified by running `multimon-ng` with no
   arguments, which prints its own demodulator list:
   `POCSAG512 POCSAG1200 POCSAG2400 FLEX FLEX_NEXT EAS UFSK1200 CLIPFSK
   FMSFSK AFSK1200 AFSK2400 AFSK2400_2 AFSK2400_3 HAPN4800 FSK9600 DTMF
   ZVEI1 ZVEI2 ZVEI3 DZVEI PZVEI EEA EIA CCIR MORSE_CW DUMPCSV X10 SCOPE`.
   There is no SSTV demodulator in multimon-ng and there never has been.
   This call existed in **two places** — `sstv.py::_detect_vis`/`_try_multimon`
   and, via duplicated logic, `digital.py::_detect_sstv` — both entirely
   dead code that could never produce a result.
2. **`qsstv -r <wav> -o <dir>`** — verified via `qsstv`'s own man page,
   whose SYNOPSIS is just `qsstv`: zero command-line arguments. It's a
   Qt GUI application that captures live audio from a soundcard; running
   the old invocation in this environment actually launched (and hung) the
   GUI rather than erroring cleanly, since Qt fell back to a headless
   platform plugin instead of failing outright.

Both were replaced rather than patched, since there was nothing real to fix.

### New: real, tested VIS code detection
`detect_vis_code()` — a from-scratch Goertzel-based tone classifier that
implements the actual VIS timing spec (300ms leader / 10ms break / 300ms
leader / 30ms start bit / 7 data bits + 1 parity bit at 30ms each / 30ms
stop bit, tones 1900/1200/1300/1100 Hz), vectorized with numpy so it runs in
one pass over the file instead of a per-sample loop. Verified by
synthesizing real VIS tone sequences in the test suite and confirming exact
byte-for-byte round-trip decode, including parity checking and correct
rejection of plain music/noise (no false positives).

### Also found and fixed: corrupted VIS code table
Six of the fourteen entries in `VIS_CODES` were greater than 127 — a VIS
code is a 7-bit value (0-127), so those were structurally impossible, not
just questionable. Removed rather than replaced with unverified guesses
(no authoritative reference was available in this environment to confirm
correct replacement values); the remaining eight entries are commonly-cited
but not independently cross-checked in this pass, so mode *names* remain
best-effort while the *VIS code byte itself* (which comes directly from
real decoded signal bits, not a lookup) is the verified, reliable part of
this analyzer's output — an unknown code is now reported honestly as
`"Unknown (VIS 0xXX)"` instead of silently mapping to nothing or a
wrong name.

### Other fixes in this pass
- `digital.py`'s duplicate (and equally dead) `_detect_sstv` method removed.
- Fixed a real pipeline-ordering bug in `scanner.py`: SSTV ran *before*
  Digital modes, but tried to read `all_results["digital"]["_wav_path"]` —
  which Digital modes hadn't set yet, so it was always `None` and SSTV
  always analyzed the raw input file directly instead of a properly
  ffmpeg-converted WAV for non-WAV inputs. SSTV now runs after the
  Digital+OCR step and receives the real converted path.
- `run_sstv` config flag now actually gates the SSTV step (previously it
  only gated the dead code in `digital.py`; the real `SSTVAnalyzer` call in
  `scanner.py` ran unconditionally).
- zbarimg output parsing now reports the actual detected symbology (QR,
  EAN13, Code128, etc.) instead of hardcoding every hit as "QR Code" — real
  barcode detection, not just QR, satisfying that spec bullet honestly.
- Decoded-image metadata extraction added via exiftool when available.

### Known limitation (unchanged scope, stated plainly)
Actual pixel-level image reconstruction from SSTV audio (rendering the
picture) is still not implemented. Every SSTV mode has its own
scanline/color-encoding scheme (Robot 36 is YUV, Martin/Scottie are RGB
with different scan orders, PD-series pairs lines differently), and without
reference test vectors to verify a decoder's output against, shipping one
now would risk exactly the "confidently wrong" result this project explicitly
tries to avoid. VIS/mode identification is real; `rx_sstv` remains wired as
a best-effort external decoder (gated on tool availability, not installed in
this dev environment so its exact CLI contract could not be verified either
— failures are logged rather than assumed away).

### Tests
- 221 passing (223 total, 2 skipped), up from 216. New tests build real VIS
  tone sequences and verify exact decode (including a code deliberately not
  in the mode-name table, to confirm the byte-level decode doesn't depend on
  the table being complete), confirm no false positives on music/noise,
  confirm the corrected table has no structurally invalid entries, confirm
  qsstv/multimon-ng presence is reported rather than invoked, and confirm
  the scanner ordering/`run_sstv` gating fixes.

## Phase 9: Expanded Audio Forensics DSP

Installed the previously-missing scipy/librosa/soundfile/matplotlib in the
dev environment specifically so this phase's DSP code could be verified by
execution against real synthetic signals with known properties, not just
read. That testing caught two real, meaningful bugs before they shipped —
see below.

### New in `audio_forensics.py`
- LSB extraction extended from 1-2 bit to the spec's full **1-4 bit** range.
- **MSB analysis** — mirrors LSB extraction on the high-order bits (mainly
  useful as a negative control; MSB manipulation is audible and rare).
- **Channel correlation + phase-inversion detection** — Pearson correlation
  between L/R; a strongly negative coefficient (mirror-image channels that
  cancel to silence when summed to mono) is flagged as a known technique for
  hiding a payload that only exists in one channel or the difference signal.
- **Entropy mapping over time** — windowed Shannon entropy across the file's
  duration (not just one whole-file number), with outlier windows (>6 MAD
  from the median via a robust modified z-score) flagged as possible
  injected/appended-data boundaries.
- **Hidden carrier / tone detection** — flags an unusually strong, narrow
  spectral peak above 8 kHz (see bug #1 below for why it's restricted to
  that band) as a possible digital-mode subcarrier.
- **Watermark detection (best effort)** — FFT-based autocorrelation
  periodicity check, deliberately capped at INFO severity / ≤40% confidence
  per the spec's own "best effort" framing; this is not a watermark decoder.
- **MFCC summary** — real 13-coefficient MFCCs via librosa when available,
  reported as informational mean/std per coefficient. No automatic "anomaly"
  Finding is generated from this — there's no labeled baseline to compare
  against, and fabricating a confidence score here would be exactly the kind
  of "confidently wrong" output this project is trying to eliminate.
- All of the above surfaced in the HTML report's Audio Forensics section
  (previously several Phase 9 fields would have been computed but invisible).

### Bugs caught and fixed during this pass (both found by testing against
### real synthetic audio with known injected properties, not by review)

1. **Carrier detector fired on ordinary music.** The first version picked
   whichever frequency bin had the single highest magnitude anywhere in the
   spectrum and compared it to its local neighborhood. A pure sustained
   440 Hz test tone — completely ordinary, nothing hidden — produced a
   ~4×10⁷x peak/neighborhood ratio, because a pure tone concentrates nearly
   all its energy into 1-2 FFT bins *by definition*, regardless of whether
   anything is actually hidden there. This would have made the detector fire
   on almost any music with a sustained note, directly against the project's
   "accuracy and low false-positive rate" principle. Fixed by restricting
   the search to frequencies above 8 kHz, where music's dominant fundamental
   energy rarely lives — a genuinely rarer, more specific signal that
   matches how carriers are actually placed in practice.
2. **Same detector still false-positived after fix #1**, this time on a
   *plain* 440 Hz tone with nothing injected above 8 kHz at all: a tiny
   quantization-noise artifact around 10 kHz was compared against an
   almost-exactly-zero local median (since a synthetic pure tone has
   essentially no real energy up there), producing a ~10⁹x ratio from pure
   numerical noise. Fixed by adding an absolute energy floor — the peak must
   also be a non-negligible fraction of the file's overall loudest bin, not
   just large relative to a near-zero neighborhood.

### Tests
- 216 passing (218 total, 2 skipped only when librosa/numpy are genuinely
  absent), up from 205. 11 new tests build real synthetic audio with known
  injected properties — a phase-inverted stereo pair, an actual 15 kHz
  carrier tone, an injected noise window — and assert the DSP correctly
  detects them (and, for the carrier detector, correctly does *not* fire on
  plain music), rather than only checking that the code runs.

## Phase 8: Encoding/Decoding Engine

New `audio_stego/encoding_engine.py` — single source of truth for every
encoding scheme the spec calls for: Base16/32/45/58/62/64/85, Ascii85, Hex,
Binary, Octal, ROT13, Caesar (+ brute force), Atbash, Affine (+ brute force),
keyed Vigenère, Rail Fence (+ brute force), Bacon, Braille, Morse (text-form),
JWT, URL encoding, Quoted-Printable, UUEncode, XXEncode — plus `decode_all()`
(try every parameterless scheme against one string) and `recursive_decode()`
(chain decodes, e.g. base64-of-hex-of-ROT13, bounded by depth).

Reuses existing code rather than duplicating it: `rot13`/`caesar`/`atbash`
from `findings.py`, and `_b58decode` from `plugins/base58_plugin.py`.
Base16/32/64/85/Ascii85 use Python's stdlib `base64` module. Where no stdlib
or existing implementation existed (Base45, Base62, Rail Fence, Bacon,
Braille, Morse, JWT, UUEncode, XXEncode), each was hand-rolled against its
real specification and round-trip tested. UUEncode intentionally uses
`binascii.a2b_uu` rather than the `uu` module — `uu` is a PEP 594
deprecated-for-removal stdlib module (removed in Python 3.13); `binascii`'s
lower-level codec is not deprecated.

Wired into Phase 7's `RecursiveAnalysisEngine`: candidate substrings found in
gathered text are now run through `encoding_engine.decode_all()` in addition
to the direct base64/hex decode, so e.g. a Base58-encoded flag embedded in
OCR output is now caught — previously only base64/hex were attempted there.

### Bug caught and fixed during this pass (real — found by testing, not review)
The first version of `decode_all()`/`recursive_decode()` gated Caesar/Affine/
Rail-fence brute force on a generic "is the output printable" check. Letter
substitution and transposition ciphers **always** keep output printable
regardless of whether the guess is correct — shifting or permuting letters
never produces control characters. That meant essentially every one of the
25 Caesar shifts, 312 Affine (a,b) pairs, and ~8 Rail-fence rail-counts
"passed" the filter for any alphabetic input, and each became a new
candidate for the next recursion depth in `recursive_decode()` — a
combinatorial explosion that hung for minutes (caught by a smoke test, not
by review; a size-mismatch in the original test data made it look benign at
first glance). Fixed two ways:
1. Correctness fix: Caesar/Affine/Rail-fence/ROT13/Atbash are now gated on
   `looks_like_flag()` (same convention `flags.py`'s cipher analysis already
   uses) instead of a printability check, since only the presence of an
   actual flag-shaped pattern is meaningful evidence for these ciphers.
2. Defense in depth: `recursive_decode()` now also hard-caps total hits
   (200) and per-depth frontier width (25) regardless of any individual
   scheme's gating, so a similarly-shaped bug in a future scheme addition
   fails safely instead of hanging.

### Known limitations (documented, not silently skipped)
- Vigenère key recovery (frequency analysis to guess an unknown key) is not
  implemented — only keyed decoding, when a candidate key is already known
  from elsewhere (metadata, another decoded artifact). Automatic key
  recovery is a substantially larger, uncertain problem; faking it would
  produce confidently-wrong output.
- Even with the fix above, brute-force substitution-cipher search against
  already flag-shaped plaintext (not actually encoded) can still surface
  many "hits" from the generic flag pattern's structural tolerance (braces +
  alnum survive any letter shift). This is bounded (no hang) but is a
  precision characteristic of blind classical-cipher search in general
  (the same behavior CyberChef's "Magic" feature exhibits), not unique to
  this implementation.

### Tests
- 203 passing (205 total, 2 skipped), up from 169. 34 new tests cover every
  scheme's round-trip (encode independently, decode via this module),
  rejection of malformed input per scheme, the `decode_all`/`recursive_decode`
  orchestration finding real chained payloads, and — critically — a
  regression test asserting `recursive_decode` terminates in under 5 seconds
  on the exact input shape that hung before the fix.

## Phase 7: Recursive Analysis Engine

Closed the specific gap identified while reviewing Phase 7 against the actual
pipeline: `extraction.py` already recursed through nested *binary* containers
(archive-in-archive), but nothing decoded text-borne nesting — a chain like
`audio.wav → ZIP → PNG → OCR text → Base64 → ZIP → PDF → Flag` stopped dead
at the OCR step because `flags.py::_search_encoded_flags` only ever searched
*decoded text* for flag patterns; it never checked whether the decoded bytes
were themselves a file that needed extracting.

- New `audio_stego/recursive_engine.py::RecursiveAnalysisEngine` — decodes
  base64/hex candidates out of already-gathered text (OCR output,
  digital-mode decodes, the flag sweep's gathered text), writes each decode
  through the **same unified evidence pipeline** from Phase 2
  (`ExtractionAnalyzer._process_tool_artifact`), extracts anything that
  validates as a container, and re-scans newly extracted content for further
  encoded data or flags. Stops on: max recursion depth (shared constant with
  `extraction.py`), duplicate SHA256 (shared `_artifact_index`, so a payload
  already seen is never processed twice), or a size limit.
- Wired into `scanner.py` as a best-effort pass after the flag sweep — the
  extraction analyzer instance is now kept on `self._extraction_analyzer`
  (previously discarded after `.run()`) so the engine can append to the same
  record set, and OCR is re-run once if the pass produced new files.
- Fixed a bug caught while smoke-testing this feature end-to-end: decoded
  payloads were written as `decoded_<sha>.bin`, but
  `extraction.py::_extract_archive` dispatches purely on file extension —
  a validated ZIP payload never actually got extracted because `.bin` matched
  no branch. Fixed by renaming to the correct extension once the type is known.
- Fixed a related idempotency bug in `extraction.py::_update_summary()`: it
  incremented counters without resetting them, so calling it a second time
  (needed after the recursive engine appends more records) would have
  silently double-counted every existing record. Now recomputes from scratch.

### Tests
- 169 passing (171 total, 2 skipped), up from 164. 5 new tests cover the
  full base64→ZIP→flag chain end-to-end (including confirming the archive
  really lands on disk with correct content), SHA256 dedup of repeated
  payloads, garbage text producing no spurious artifacts, bounded
  termination, and the scanner integration point.

### Known limitation
- This is a bounded, single-track recursive pass (decode → validate →
  extract → re-scan, repeated up to the depth limit) rather than a fully
  interleaved fixpoint loop across every analyzer (OCR/digital/flags) at
  every depth. A true fixpoint loop was considered and rejected for this
  pass: re-invoking every analyzer at every recursion depth multiplies
  runtime cost and risk (e.g. tesseract/binwalk being re-run many times over)
  for a marginal gain over the bounded version, given CTF payloads are
  rarely nested more than 2-3 levels deep. The OCR re-run after new content
  appears covers the common case from the spec's own example chain.

## Phase 6: Interactive DFIR Dashboard

Builds on the 3.1.0 evidence pipeline to make the HTML report show what that
pipeline now knows, instead of leaving `sha256`/`parent_sha256`/`depth` and
per-phase timing sitting unused in `results`.

- **Recursive artifact graph** (`html_report.py::_evidence_tree`) — nests each
  `ExtractionRecord` under the parent it was carved from via
  `sha256`/`parent_sha256`, so a chain like `audio.wav → ZIP → PNG` renders as
  an actual tree instead of a flat table. Reuses the `.tree` CSS class that
  was defined but never used by any code path before this change.
- **Findings grouped by category** — the "All Findings" section now leads
  with per-module summary cards (counts by severity) before the flat
  sortable/searchable table, instead of dropping hundreds of ungrouped rows
  on the reader.
- **Sortable tables** — clicking any `<th class="sortable">` sorts that
  column (numeric-aware, toggles ascending/descending); applied to the
  findings and extraction tables.
- **Severity filter** — a dropdown next to search that combines with the
  existing text search (`doSearch()` now checks both).
- **Audio player** — the actual scanned file is embedded as a playable
  `<audio>` element (size-capped at 25MB with a clear fallback message above
  that, so a large file doesn't produce a multi-hundred-MB HTML report).
- **Timeline** — chronological view built from `ExtractionRecord.timestamp`
  (added in the 3.1.0 evidence pipeline, previously unused by any report).
- **Tool Execution Summary + Performance Metrics** — `scanner.py` now records
  real per-phase wall-clock timing (`_performance.phases`) and tool
  availability (`_performance.tool_availability`) instead of only a single
  total `elapsed_time`; both are rendered as a new "Performance & Tool
  Execution" section.

### Bug fixed during this pass
- The evidence-tree renderer initially recursed infinitely on any
  `ExtractionRecord` with `sha256=None` (the common case for the original
  signature-scan path, which doesn't always set a hash) — `None` was both the
  top-level sentinel key and the record's own lookup key, so a record with no
  hash looked up its own top-level sibling list as its "children" and
  re-rendered it forever. Fixed by only doing the children lookup when
  `sha256` is truthy. Caught immediately by the existing HTML report test
  suite before this reached anyone.

### Tests
- 164 passing (166 total, 2 skipped), up from 157. 7 new tests cover the
  recursion-safety fix, parent/child nesting, category grouping, the audio
  player, the performance section, and timeline ordering.

### Not yet done (Phase 6 items still open)
- Bit-plane/LSB *visualization* (image, not just the existing text table) —
  `audio_forensics.py` already computes bit planes; rendering them as images
  in the report is unstarted.
- Digital-mode and validator-catalog dedicated sections beyond what already
  exists are unstarted (current Digital/Extraction sections cover the data
  but not in the exact grouped form the spec describes).
- A dedicated in-report log viewer (spec's "Logs" bullet) is unstarted —
  `store.logs` exists on disk but isn't surfaced in the HTML report yet.

## [3.1.0] - 2026 — Extraction Accounting & Confidence Engine Redesign (v4 Phases 2-5)

Audited the v3.0.0 pipeline against its own claims and found the "extraction
accounting is misleading" complaint (e.g. "Extracted: 165, False positives: 17"
with no explanation of the rest) was real: binwalk/foremost/scalpel/steghide/
stegseek carved files were written to `extracted/`/`hidden_files/` and counted
in the "Total Files" stat purely because they existed on disk — they never
passed through `validate.py` at all. Only the raw magic-byte signature scan
produced `ExtractionRecord`s. Root cause and fix below.

### Phase 2 — Unified extraction evidence pipeline
- Every tool-carved artifact now flows through one pipeline: **Tool → Artifact
  → SHA256 → Dedup (merge source tools) → Detect Type → Structural Validator →
  Confidence → Evidence Record**. Nothing is counted toward extraction
  statistics just because it exists on disk (`extraction.py::_process_tool_artifact`).
- `ExtractionRecord` gained `sha256`, `parent_sha256`, `depth`, `source_tools`,
  `validator`, `timestamp` fields (appended after existing fields — positional
  construction in existing callers/tests is unaffected).
- SHA256 dedup now spans tools: the same bytes carved by both binwalk and
  foremost merge into a single record whose `source_tools` lists both, instead
  of being processed and reported twice.
- New `ExtractionStatus` values: `VERIFIED`, `RECOVERED`, `PARTIAL`,
  `REJECTED`, `CORRUPTED`, `ENCRYPTED`, `PASSWORD_PROTECTED`, `NESTED`,
  `SKIPPED` — in addition to the original `DETECTED`/`VALIDATED`/`EXTRACTED`/
  `FAILED`/`FALSE_POSITIVE`/`UNSUPPORTED` used by the signature-scan path.
- Fixed: oversized carved files were silently discarded during recursion with
  no record; they are now recorded as `SKIPPED` with a reason.

### Phase 3 — Expanded structural validators
- Added real validators for **AIFF** (hand-parsed COMM chunk — the stdlib
  `aifc` module is deprecated/removed upstream, so this is intentionally
  dependency-free), **TAR** (ustar header checksum verified byte-for-byte),
  **BZIP2** and **XZ** (XZ's stream-header CRC32 is cryptographically
  verified against the spec), **TIFF**, **PE** (MZ+PE, machine type),
  **AAC/ADTS** (see Phase 4), **M4A/MP4** (ftyp brand + follow-on box),
  **JSON** and **XML** (full parse, not just anchor bytes).
- **ZIP** validator now calls `testzip()` to verify every member's CRC (tags
  `CORRUPTED` if a real ZIP has a bad member), detects password-protection via
  the local-header encryption flag bit, and recognizes **DOCX/XLSX/PPTX** by
  inspecting `namelist()` for their signature parts (`word/document.xml` etc.)
  since Office Open XML files are ZIPs and can only be told apart by content.
- **RIFF** validator now distinguishes **WEBP** from WAV by the `WEBP`/codec
  chunk instead of only ever labeling every `RIFF` hit "WAV".
- Fixed a real dead-code bug: the validators dict used the key `"SQLite"`
  while `utils.FILE_MAGIC` (the scanner) produces `"SQLITE"` — Python dict
  lookups are case-sensitive, so the SQLite validator was unreachable via the
  normal scan path since it was introduced. Both spellings are now registered.
- JSON is deliberately **not** wired into the raw magic-byte scanner — there is
  no anchor byte sequence for JSON that isn't extremely common in ordinary
  binary/audio data, so scanning for it would flood results with false
  positives. The validator remains directly callable for explicitly-typed
  inputs (e.g. a base64-decoded payload).

### Phase 4 — Real MP3/AAC frame validation
- Replaced the "MP3_FRAME has no validator, accepted at 40% on magic bytes
  alone" bug (the exact example in the v4 spec) with a real MPEG audio frame
  parser: frame sync, MPEG version, layer, bitrate index, sample-rate index,
  computed frame length, and CRC-presence are all checked, and a **minimum of
  3 consecutive, mutually-consistent frames** is required before a region is
  treated as an embedded MP3 stream. An isolated frame-sync match (the 0xFFEx
  bit pattern occurs by chance fairly often in PCM/compressed audio) is now
  rejected instead of written to disk as a "validated" file.
- The same frame-run validation is applied to raw AAC/ADTS streams, which
  have the same false-positive risk profile as MP3 frame sync.
- ID3v2 tag validation now looks for valid MPEG frames immediately following
  the tag and upgrades confidence when they're found, instead of trusting the
  tag alone.

### Phase 5 — Evidence-based confidence engine
- New `findings.EvidenceLevel` enum + `confidence_for_evidence()`: magic bytes
  only → 20%, header parsed → 40%, structure validated → 60%,
  checksums/consistency verified → 80%, successfully extracted → 95%,
  successfully parsed/opened → 100%. All new validators derive their
  confidence from this ladder instead of a hand-picked float per call site.
- New `findings.cap_severity()` / `severity_cap_for_confidence()`: severity
  can now only be *lowered*, never raised, to what the confidence justifies.
  Fixed a real bug in `extraction.py::_scan_signatures` where every validated
  signature hit — even a hypothetical 20%-confidence "no validator" fallback —
  was unconditionally given `Severity.HIGH`. It is now `cap_severity(HIGH, confidence)`.

### Tests
- 157 passing (159 total, 2 skipped — librosa/scipy/soundfile not installed
  in this environment), up from 118. 39 new regression tests cover the
  confidence engine, every new/changed validator (accept + reject cases), the
  SQLite dead-code fix, cross-tool SHA256 dedup with provenance merging,
  NESTED/SKIPPED/UNSUPPORTED classification, and the severity-cap fix.

### Known limitations carried forward
- RAR/7Z password/encryption detection is not implemented (would require
  parsing more of each proprietary format than is justified right now); only
  ZIP's password-protection flag is checked. Documented rather than faked.
- MP3 CRC-16 (when the protection bit is set) is detected as *present*, not
  cryptographically verified — computing it correctly requires decoding
  per-layer/per-channel-mode side info, which was judged not worth the
  complexity/risk of a subtly wrong "verified" claim. The frame-run
  consistency check is the primary anti-false-positive signal instead.

## [3.0.0] - 2024 — Major Architecture Release

### New Modules
- `artifact_store.py` — Organised output directory (results/<stem>/artifacts/, evidence/, raw/, logs/)
- `audio_forensics.py` — Pure DSP forensics: LSB extraction, stereo diff, Mid/Side, phase analysis, echo hiding (cepstrum), frequency bands, silence detection, amplitude stats, bit-plane extraction
- `sstv.py` — Multi-decoder SSTV pipeline: VIS code detection, multimon-ng/rx_sstv/qsstv, post-decode OCR+QR, confidence scoring
- `validate.py` — Structural file validation (ZIP/PNG/JPEG/PDF/GIF/ELF/GZIP/RAR/7Z/BMP/WAV/FLAC/OGG/MP3/SQLite) eliminates magic-byte false positives
- `html_report.py` — Professional interactive HTML report: dark/light mode, search, copy buttons, image zoom, download buttons, collapsible sections, flag-first layout

### Critical Bug Fixes (retained from v1.1)
- Morse/DTMF/minimodem/SSTV false positives eliminated (confidence + validation)
- `binary_analyzer` NameError in scanner fixed
- Appended data detection formula fixed (RIFF header for WAV, ffprobe size for compressed)
- Embedded file detection skips offset 0
- OCR single-call with confidence threshold
- Cipher analysis capped at 4KB input
- Recursive extraction with SHA256 dedup + depth limit

### Extraction Reporting (v3 major improvement)
- `ExtractionRecord` dataclass with `ExtractionStatus` enum
- Every detected signature now has one of: `detected / validated / extracted / failed / false_positive / unsupported`
- Report clearly states: "Detected embedded ZIP — Extraction failed — Corrupted archive"
- No more counting unvalidated magic bytes as "extracted files"

### Output Directory Structure (v3)
```
results/<stem>/
├── report.html          ← Primary interface
├── report.json
├── summary.txt
├── artifacts/
│   ├── decoded/{morse,dtmf,sstv,minimodem,cipher}/
│   ├── images/
│   ├── audio/
│   ├── archives/
│   ├── text/
│   └── flags/
├── evidence/            ← Analysis outputs (strings, entropy, LSB, etc.)
├── logs/
├── raw/                 ← Raw tool output only
├── plugins/
├── extracted/           ← Carved files
└── hidden_files/        ← Recursively extracted content
```

### HTML Report Features
- Flag banner at top — immediate visibility
- Dashboard: flags, critical/high counts, extracted files, QR codes, duration
- All findings table with severity badges, confidence bars, sortable
- Search across all findings
- Dark/light mode toggle (persisted in localStorage)
- Copy-to-clipboard buttons on all values
- Image zoom overlay (click to enlarge)
- Download buttons on embedded images
- Collapsible sections (auto-open for flags + findings)
- Extraction table shows extracted/failed/false_positive per signature
- Audio forensics section: LSB table, stereo diff, echo analysis, amplitude stats
- SSTV section: decoded image embedded, OCR text, QR data
- Fully XSS-safe (all user data HTML-escaped)

### Tests
- 115 passing (117 total, 2 skipped — librosa not in bare environment)
- Added: ArtifactStore, Validate, ExtractionAnalyzerV3, AudioForensics, HTMLReport, SSTV, Integration

## [1.1.0] - 2024 — Bug Fix Release
(See previous CHANGELOG entries)

## [1.0.0] - 2024 — Initial Release
