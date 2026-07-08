"""
Professional HTML report for Audio Stego Solver v3.

Design goals:
  - Primary interface — user rarely needs to open individual text files
  - Dashboard with executive summary at the top
  - "Possible Flags" section immediately visible
  - Collapsible sections, dark/light mode toggle
  - Copy buttons, image zoom, download buttons
  - Search across all findings
  - Responsive layout
  - All data HTML-escaped (XSS-safe)
"""

from __future__ import annotations

import base64
import html as html_mod
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .artifact_store import ArtifactStore
from .findings import ConfidenceTier, confidence_tier, is_likely_base64
from .logger import get_logger
from .utils import human_size

logger = get_logger("audio_stego.html_report")

_AUTHOR_NAME = "Srikanth T"
_AUTHOR_LINKEDIN = "https://www.linkedin.com/in/srikanth786369/"


def _detect_github_url() -> Optional[str]:
    """Best-effort: read the git remote URL if this is a git checkout —
    a local-only git-config read, never a network call."""
    try:
        import subprocess
        out = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=2,
        )
        url = out.stdout.strip()
        if not url:
            return None
        if url.startswith("git@"):
            url = url.replace(":", "/", 1).replace("git@", "https://")
        return url[:-4] if url.endswith(".git") else url
    except Exception:
        return None


def _esc(s: Any) -> str:
    return html_mod.escape(str(s), quote=True)


_img_uid_counter = 0


def _embed_img(path: Optional[str], alt: str = "image") -> str:
    if not path or not os.path.exists(path):
        return f'<div class="img-placeholder">[ {_esc(alt)} not available ]</div>'
    try:
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        ext  = Path(path).suffix.lower().lstrip(".")
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "gif": "image/gif", "bmp": "image/bmp"}.get(ext, "image/png")
        global _img_uid_counter
        _img_uid_counter += 1
        uid = f"img-{_img_uid_counter}"
        # The image data is embedded exactly once. The download button reads
        # the already-rendered <img>'s own src via JS instead of re-emitting
        # a second copy of the same base64 blob — halves the report's size
        # for every embedded image.
        return (
            f'<div class="img-wrap" onclick="zoomImg(this)">'
            f'<img id="{uid}" src="data:{mime};base64,{data}" alt="{_esc(alt)}" '
            f'title="Click to zoom" loading="lazy">'
            f'<a class="dl-btn" href="#" onclick="downloadImg(event,\'{uid}\',\'{_esc(Path(path).name)}\')">'
            f'⬇ Download</a>'
            f'</div>'
        )
    except Exception:
        return f'<div class="img-placeholder">[ {_esc(alt)} — could not embed ]</div>'


def _badge(text: str, cls: str = "info") -> str:
    return f'<span class="badge badge-{_esc(cls)}">{_esc(text)}</span>'


def _copy_btn(target_id: str) -> str:
    return (f'<button class="copy-btn" onclick="copyEl(\'{_esc(target_id)}\')"'
            f' title="Copy to clipboard">⎘ Copy</button>')


_AUDIO_MIME = {
    ".wav": "audio/wav", ".mp3": "audio/mpeg", ".flac": "audio/flac",
    ".ogg": "audio/ogg", ".aac": "audio/aac", ".m4a": "audio/mp4",
    ".au": "audio/basic", ".aiff": "audio/aiff", ".wma": "audio/x-ms-wma",
}


def _embed_audio_player(path: str, max_bytes: int = 25 * 1024 * 1024) -> str:
    """Embed the scanned audio file as a playable <audio> element."""
    if not path or not os.path.exists(path):
        return '<p style="color:var(--text3)">Audio file not available for playback.</p>'
    size = os.path.getsize(path)
    if size > max_bytes:
        return (f'<p style="color:var(--text3)">Audio file too large to embed for playback '
                f'({human_size(size)} &gt; {human_size(max_bytes)}). Open it directly instead.</p>')
    ext  = Path(path).suffix.lower()
    mime = _AUDIO_MIME.get(ext, "audio/wav")
    try:
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
    except OSError:
        return '<p style="color:var(--text3)">Could not read audio file for playback.</p>'
    return (
        f'<audio controls preload="none" style="width:100%;max-width:600px" '
        f'src="data:{mime};base64,{data}">Your browser cannot play this audio format.</audio>'
    )


def _all_module_findings(results: Dict[str, Any]) -> List[Dict]:
    out: List[Dict] = []
    for key in ("binary", "digital", "visual", "forensics", "ocr",
                "extraction", "flags", "sstv"):
        sec = results.get(key, {})
        if isinstance(sec, dict):
            out.extend(sec.get("findings", []))
    return out


def _needs_manual_review(flags: List, all_f: List[Dict]) -> bool:
    """No flag and nothing above the PROBABLE tier: the scan found some
    evidence but nothing conclusive enough that a human shouldn't still
    look at it themselves. Single source of truth shared by the Executive
    Summary card and the Manual Investigation section."""
    overall_confidence = max((f.get("confidence", 0) for f in all_f), default=0.0)
    if flags:
        overall_confidence = max(overall_confidence,
                                  max((f.get("confidence", 0) for f in flags if isinstance(f, dict)), default=0.0))
    return not flags and overall_confidence < 0.60


_TOOL_NOISE_MARKERS = ("not found", "not installed", "not available", "disabled",
                       "no batch-decode", "wordlist not found", "no CLI contract")


def _is_tool_availability_noise(warning: str) -> bool:
    """True for warnings that just say a tool is missing/disabled/not
    configured — a missing tool is simply omitted from Tools Used, so
    re-stating its absence in Warnings would be the same noise twice."""
    low = warning.lower()
    return any(marker in low for marker in _TOOL_NOISE_MARKERS)


# ---------------------------------------------------------------------------
# CSS + JS (inlined)
# ---------------------------------------------------------------------------

_STYLE = """
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --border:#30363d;--text:#c9d1d9;--text2:#8b949e;--text3:#6e7681;
  --blue:#58a6ff;--green:#3fb950;--yellow:#e3b341;
  --red:#f85149;--purple:#d2a8ff;--orange:#ffa657;
}
[data-theme=light]{
  --bg:#ffffff;--bg2:#f6f8fa;--bg3:#eaeef2;
  --border:#d0d7de;--text:#24292f;--text2:#57606a;--text3:#8c959f;
  --blue:#0969da;--green:#1a7f37;--yellow:#9a6700;
  --red:#cf222e;--purple:#8250df;--orange:#bc4c00;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
  color:var(--text);line-height:1.6;font-size:14px}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1400px;margin:0 auto;padding:16px}
/* Header */
.header{background:var(--bg2);border-bottom:1px solid var(--border);
  padding:12px 20px;display:flex;align-items:center;gap:12px;
  position:sticky;top:0;z-index:100}
.header h1{font-size:1.2em;color:var(--blue);flex:1}
.header-meta{color:var(--text2);font-size:.85em}
/* Theme toggle */
.theme-btn{background:var(--bg3);border:1px solid var(--border);
  color:var(--text);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:.85em}
/* Dashboard grid */
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:12px;margin:16px 0}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:16px;text-align:center}
.stat-card .num{font-size:2em;font-weight:700;line-height:1}
.stat-card .lbl{color:var(--text2);font-size:.8em;margin-top:4px}
.num-red{color:var(--red)} .num-green{color:var(--green)}
.num-blue{color:var(--blue)} .num-yellow{color:var(--yellow)}
/* Flag banner */
.flag-banner{background:#1a0a0a;border:2px solid var(--red);border-radius:8px;
  padding:16px;margin:16px 0}
.flag-banner h2{color:var(--red);margin-bottom:8px}
.flag-item{background:var(--bg2);border-left:4px solid var(--red);
  padding:10px 14px;margin:6px 0;border-radius:0 6px 6px 0;font-family:monospace}
.flag-value{font-size:1.1em;font-weight:700;color:var(--red)}
.flag-meta{font-size:.8em;color:var(--text2);margin-top:4px}
/* Manual Reproduction Guide */
.repro-step{border:1px solid var(--border);border-left:4px solid var(--blue);
  border-radius:0 6px 6px 0;padding:10px 14px;margin:10px 0;background:var(--bg2)}
.repro-step-title{font-weight:700;color:var(--blue);margin-bottom:6px}
.repro-field{margin:3px 0;font-size:.92em}
.repro-final{border:2px solid var(--green);border-radius:8px;padding:14px;
  margin-top:14px;background:#0a1a0a}
[data-theme=light] .repro-final{background:#eafaf0}
/* Tools Used */
.tool-card{border:1px solid var(--border);border-radius:6px;padding:8px 12px;
  margin:6px 0;background:var(--bg2)}
.tool-card summary{cursor:pointer;list-style:none}
.tool-card summary::-webkit-details-marker{display:none}
.tool-card[open]{background:var(--bg3)}
/* Sections */
.section{background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;margin:12px 0;overflow:hidden}
.section-header{padding:10px 16px;cursor:pointer;display:flex;
  align-items:center;gap:8px;user-select:none;
  border-bottom:1px solid var(--border)}
.section-header:hover{background:var(--bg3)}
.section-header h2{font-size:1em;font-weight:600;flex:1;color:var(--text)}
.section-body{padding:16px;display:none}
.section-body.open{display:block}
.chevron{transition:transform .2s;color:var(--text2)}
.open-chevron .chevron{transform:rotate(90deg)}
/* Badges */
.badge{display:inline-block;padding:2px 7px;border-radius:10px;
  font-size:.75em;font-weight:600;margin:1px}
.badge-CRITICAL,.badge-critical{background:#490202;color:var(--red)}
.badge-HIGH,.badge-high{background:#272115;color:var(--yellow)}
.badge-MEDIUM,.badge-medium{background:#122138;color:var(--blue)}
.badge-LOW,.badge-low{background:#12261e;color:var(--green)}
.badge-INFO,.badge-info{background:var(--bg3);color:var(--text2)}
/* Code blocks */
pre,code{font-family:'Consolas','Courier New',monospace;
  font-size:.85em;background:var(--bg);color:#a5d6ff}
pre{padding:12px;border-radius:6px;border:1px solid var(--border);
  overflow-x:auto;white-space:pre-wrap;max-height:400px;overflow-y:auto}
/* Images */
.img-wrap{display:inline-block;position:relative;cursor:zoom-in;
  max-width:100%;margin:6px 0}
.img-wrap img{max-width:100%;border-radius:6px;border:1px solid var(--border);
  display:block}
.img-placeholder{color:var(--text3);font-style:italic;padding:8px;
  background:var(--bg3);border-radius:6px;margin:6px 0}
.dl-btn{display:inline-block;margin-top:4px;font-size:.75em;
  color:var(--blue);background:var(--bg3);padding:2px 8px;
  border-radius:4px;border:1px solid var(--border)}
/* SSTV hero image — larger display than the default inline embed */
.sstv-hero-image .img-wrap{max-width:640px}
.sstv-hero-image .img-wrap img{width:100%}
/* Image zoom overlay */
.zoom-overlay{position:fixed;inset:0;background:rgba(0,0,0,.85);
  z-index:999;display:none;align-items:center;justify-content:center;cursor:zoom-out}
.zoom-overlay img{max-width:95vw;max-height:95vh;border-radius:6px}
/* Copy button */
.copy-btn{background:var(--bg3);border:1px solid var(--border);
  color:var(--text2);padding:3px 8px;border-radius:4px;cursor:pointer;
  font-size:.75em;margin-left:6px}
.copy-btn:hover{background:var(--blue);color:#fff;border-color:var(--blue)}
/* Key-value table */
.kv-table{width:100%;border-collapse:collapse;font-size:.88em}
.kv-table td{padding:5px 10px;border-bottom:1px solid var(--border)}
.kv-table td:first-child{color:var(--text2);width:200px;font-weight:500}
.kv-table td:last-child{font-family:monospace;word-break:break-all}
/* Grid layouts */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:800px){.grid2,.grid3{grid-template-columns:1fr}}
/* Sidebar TOC */
.layout{display:flex;gap:16px}
.toc{width:200px;flex-shrink:0;position:sticky;top:60px;height:fit-content}
.toc a{display:block;padding:4px 8px;border-radius:4px;color:var(--text2);font-size:.85em}
.toc a:hover{background:var(--bg3);color:var(--blue)}
.toc a.nav-sub{padding-left:20px;font-size:.8em;color:var(--text3)}
.toc .nav-group-label{padding:8px 8px 2px;font-size:.75em;font-weight:600;
  text-transform:uppercase;letter-spacing:.04em;color:var(--text3)}
.main-content{flex:1;min-width:0}
@media(max-width:900px){.layout{flex-direction:column}.toc{position:static;width:auto}}
/* Evidence chain */
.evidence-chain{display:flex;flex-wrap:wrap;align-items:center;gap:4px;margin-top:8px}
.evidence-chain .chain-node{background:var(--bg3);border:1px solid var(--border);
  border-radius:6px;padding:3px 10px;font-size:.8em;color:var(--text2)}
.evidence-chain .chain-node a{color:var(--blue)}
.evidence-chain .chain-arrow{color:var(--text3);font-size:.85em}
/* About modal */
.about-btn{background:var(--bg3);border:1px solid var(--border);
  color:var(--text);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:.85em}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);
  z-index:998;display:none;align-items:center;justify-content:center}
.modal-box{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  padding:24px;max-width:420px;width:90%;position:relative}
.modal-box h2{color:var(--blue);margin-bottom:12px}
.modal-close{position:absolute;top:10px;right:14px;cursor:pointer;
  color:var(--text2);font-size:1.2em;background:none;border:none}
/* Footer */
.footer{color:var(--text3);text-align:center;margin-top:32px;
  padding-top:16px;border-top:1px solid var(--border);font-size:.8em}
.footer a{color:var(--text2)}
/* Warning box */
.warning-box{background:#272115;border:1px solid var(--yellow);
  border-radius:6px;padding:8px 12px;margin:4px 0;font-size:.88em;
  color:var(--yellow)}
</style>
"""

_SCRIPT = """
<script>
// Theme toggle
function toggleTheme(){
  const t = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', t==='light'?'dark':'light');
  localStorage.setItem('theme', t==='light'?'dark':'light');
}
(function(){
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();

// About modal
function toggleAbout(){
  const el = document.getElementById('about-overlay');
  if(!el) return;
  el.style.display = el.style.display === 'flex' ? 'none' : 'flex';
}
(function(){
  const overlay = document.getElementById('about-overlay');
  if(overlay){
    overlay.addEventListener('click', function(e){
      if(e.target === overlay) overlay.style.display = 'none';
    });
  }
})();

// Section toggle
function toggleSection(id){
  const body = document.getElementById('sb-'+id);
  const hdr  = document.getElementById('sh-'+id);
  if(!body) return;
  body.classList.toggle('open');
  hdr.classList.toggle('open-chevron');
}
function openSection(id){
  const body = document.getElementById('sb-'+id);
  const hdr  = document.getElementById('sh-'+id);
  if(body){ body.classList.add('open'); hdr.classList.add('open-chevron'); }
}
// Auto-open sections with flags, or SSTV/QR if something was found
document.addEventListener('DOMContentLoaded', function(){
  ['flags','manual','sstv'].forEach(openSection);
});

// Copy
function copyEl(id){
  const el = document.getElementById(id);
  if(!el) return;
  navigator.clipboard.writeText(el.innerText || el.textContent).then(function(){
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

// Image download (reads the already-embedded <img> src — no duplicate data)
function downloadImg(evt, imgId, filename){
  evt.preventDefault();
  evt.stopPropagation();
  const img = document.getElementById(imgId);
  if(!img) return;
  const a = document.createElement('a');
  a.href = img.src;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

// Image zoom
const overlay = document.getElementById('zoom-overlay');
function zoomImg(wrap){
  const img = wrap.querySelector('img');
  if(!img) return;
  const big = document.getElementById('zoom-img');
  big.src = img.src;
  overlay.style.display = 'flex';
}
if(overlay){ overlay.addEventListener('click', function(){ overlay.style.display='none'; }); }
</script>
"""


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class HTMLReport:
    """Builds the primary interactive HTML report."""

    def __init__(self, store: ArtifactStore):
        self.store = store

    def generate(
        self,
        audio_path: str,
        results: Dict[str, Any],
        elapsed_time: float,
    ) -> str:
        flags    = results.get("flags", {}).get("flags_found", [])
        all_f_raw = _all_module_findings(results)
        # Rejected-tier findings are excluded from the primary report and
        # its summary statistics entirely — they still exist, fully
        # visible, in report.json, so nothing is silently discarded; they
        # are simply never rendered in the analyst-facing HTML.
        all_f    = [f for f in all_f_raw
                    if confidence_tier(f.get("confidence", 0), f.get("tags")) != ConfidenceTier.REJECTED]
        metadata = results.get("metadata", {})
        binary   = results.get("binary", {})
        visual   = results.get("visual", {})
        forensics= results.get("forensics", {})
        digital  = results.get("digital", {})
        ocr      = results.get("ocr", {})
        sstv     = results.get("sstv", {})

        fname    = os.path.basename(audio_path)
        now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ---- Build page sections ------------------------------------------
        # CTF-edition order (v4.7): Executive Summary, Flags, Manual
        # Reproduction, Audio Preview, Metadata, Audio Information, Waveform,
        # Spectrogram, FFT, Frequency Analysis, SSTV Analysis, QR Analysis,
        # OCR, Digital Modes, Binary Analysis, Tools Used, Warnings. Every
        # section that only ever showed extraction/validator counters
        # (Verified Findings, Extracted Files, Extraction Summary, Rejected
        # Findings, Best Extracted Artifact) is gone — those numbers never
        # helped solve a challenge. A genuinely useful extracted artifact is
        # still surfaced, but as a concrete step in Manual Reproduction, not
        # a dashboard of counts.
        manual_review_needed = _needs_manual_review(flags, all_f)

        # Warnings — tool-availability noise ("X not found", "Y disabled")
        # is filtered out; a missing/disabled tool is simply omitted from
        # Tools Used, not called out again here. Only real analysis
        # warnings (parse failures, truncation, etc.) are shown.
        all_warnings = list(dict.fromkeys(
            w for v in results.values()
            if isinstance(v, dict)
            for w in v.get("warnings", [])
        ))
        all_warnings = [w for w in all_warnings if not _is_tool_availability_noise(w)]

        # Section list — each entry's `html` may be None, meaning that
        # section had nothing useful to show for this scan and is omitted
        # entirely (both from the body and the sidebar), rather than
        # rendering an empty "No X available" placeholder. Order here is
        # both the body order and (grouped) the sidebar order.
        sections: List[Dict[str, Any]] = [
            {"id": "dashboard", "label": "🏁 Executive Summary", "group": "Overview",
             "html": self._dashboard(flags, all_f, elapsed_time, results)},
            {"id": "flags", "label": "🚨 Flags", "group": "Overview",
             "html": self._flags_section(flags, results) if flags else None},
            {"id": "manual", "label": "🕵 Manual Reproduction", "group": "Overview",
             "html": self._manual_investigation_section(results, manual_review_needed)},
            {"id": "player", "label": "🎧 Audio Preview", "group": "Analysis",
             "html": self._audio_preview_section(audio_path, metadata)},
            {"id": "metadata", "label": "📋 Metadata", "group": "Analysis",
             "html": self._metadata_section(metadata)},
            {"id": "audioinfo", "label": "🎚 Audio Information", "group": "Analysis",
             "html": self._audio_information_section(metadata)},
            {"id": "waveform", "label": "〰️ Waveform", "group": "Analysis",
             "html": self._waveform_section(visual)},
            {"id": "spectrogram", "label": "📊 Spectrogram", "group": "Analysis",
             "html": self._spectrogram_section(visual)},
            {"id": "fft", "label": "📈 FFT", "group": "Analysis",
             "html": self._fft_section(visual)},
            {"id": "freqanalysis", "label": "🔊 Frequency Analysis", "group": "Analysis",
             "html": self._frequency_analysis_section(forensics)},
            {"id": "sstv", "label": "📺 SSTV Analysis", "group": "Signals",
             "html": self._sstv_section(sstv)},
            {"id": "qranalysis", "label": "📱 QR Analysis", "group": "Signals",
             "html": self._qr_analysis_section(results)},
            {"id": "ocr", "label": "🔍 OCR", "group": "Signals",
             "html": self._ocr_section(ocr)},
            {"id": "digital", "label": "📡 Digital Modes", "group": "Signals",
             "html": self._digital_section(digital)},
            {"id": "binary", "label": "🔢 Binary Analysis", "group": "Signals",
             "html": self._binary_section(binary, forensics)},
            {"id": "toolsused", "label": "🛠 Tools Used", "group": "Evidence",
             "html": self._tools_used_section(results)},
            {"id": "warnings", "label": f"⚠ Warnings ({len(all_warnings)})", "group": "Evidence",
             "html": self._warnings_section(all_warnings) if all_warnings else None},
        ]

        visible = [s for s in sections if s["html"]]
        body_parts = [s["html"] for s in visible]

        nav_parts: List[str] = []
        last_group = None
        for s in visible:
            if s["group"] != last_group:
                nav_parts.append(f'<div class="nav-group-label">{_esc(s["group"])}</div>')
                last_group = s["group"]
            nav_parts.append(f'<a href="#{s["id"]}">{s["label"]}</a>')
        toc_html = "\n".join(nav_parts)

        github_url = _detect_github_url()
        about_rows = (
            f'<tr><td>Version</td><td>{_esc(__version__)}</td></tr>'
            f'<tr><td>Author</td><td>{_esc(_AUTHOR_NAME)}</td></tr>'
            f'<tr><td>LinkedIn</td><td><a href="{_esc(_AUTHOR_LINKEDIN)}" target="_blank" '
            f'rel="noopener">{_esc(_AUTHOR_LINKEDIN)}</a></td></tr>'
        )
        if github_url:
            about_rows += (
                f'<tr><td>GitHub</td><td><a href="{_esc(github_url)}" target="_blank" '
                f'rel="noopener">{_esc(github_url)}</a></td></tr>'
            )
        about_modal = (
            '<div class="modal-overlay" id="about-overlay">'
            '<div class="modal-box">'
            '<button class="modal-close" onclick="toggleAbout()">✕</button>'
            '<h2>Audio Stego Solver</h2>'
            f'<table class="kv-table">{about_rows}</table>'
            '<p style="margin-top:10px;color:var(--text2)">Automated Audio Steganography '
            'Analysis Framework</p>'
            '<p style="margin-top:8px;color:var(--text2);font-size:.85em">Built for: '
            'CTF &middot; Digital Forensics &middot; Steganography Research &middot; Bug Bounty</p>'
            '</div></div>'
        )

        html = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Audio Stego Solver — {_esc(fname)}</title>
{_STYLE}
</head>
<body>
<div class="header">
  <h1>🎵 Audio Stego Solver</h1>
  <span class="header-meta">{_esc(fname)} &nbsp;|&nbsp; {_esc(now)} &nbsp;|&nbsp; {elapsed_time:.1f}s</span>
  <button class="about-btn" onclick="toggleAbout()">ℹ About</button>
  <button class="theme-btn" onclick="toggleTheme()">☀/🌙</button>
</div>
<div class="zoom-overlay" id="zoom-overlay"><img id="zoom-img" src="" alt="zoom"></div>
{about_modal}
<div class="container">
  <div class="layout">
    <nav class="toc">{toc_html}</nav>
    <main class="main-content">
      {''.join(body_parts)}
    </main>
  </div>
  <div class="footer">
    Audio Stego Solver v{_esc(__version__)} &mdash;
    Created by {_esc(_AUTHOR_NAME)} &mdash;
    <a href="{_esc(_AUTHOR_LINKEDIN)}" target="_blank" rel="noopener">LinkedIn</a>
  </div>
</div>
{_SCRIPT}
</body>
</html>"""

        out = str(self.store.report_html)
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"HTML report → {out}")
        return out

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def _dashboard(self, flags, all_f, elapsed, results):
        qr    = len(results.get("ocr", {}).get("qr_codes", []))
        ocr_hits = len(results.get("ocr", {}).get("ocr", []))
        sstv  = results.get("sstv", {})
        sstv_decoded = bool(sstv.get("decoded_image"))

        overall_confidence = max((f.get("confidence", 0) for f in all_f), default=0.0)
        if flags:
            overall_confidence = max(overall_confidence,
                                      max((f.get("confidence", 0) for f in flags if isinstance(f, dict)), default=0.0))

        manual_investigation = _needs_manual_review(flags, all_f)

        # No extraction counters, no raw finding tallies (all_f is only used
        # above as an input to the confidence/manual-review heuristics) —
        # every card here is something a CTF player can act on directly.
        stats = [
            (str(len(flags)),         "Flags",           "red"    if flags else "blue"),
            (f"{overall_confidence*100:.0f}%", "Overall Confidence", "green" if overall_confidence >= 0.60 else "blue"),
            ("Yes" if sstv_decoded else "No", "SSTV Decoded", "green" if sstv_decoded else "blue"),
            (str(qr),                 "QR codes",         "green" if qr else "blue"),
            (str(ocr_hits),           "OCR results",      "green" if ocr_hits else "blue"),
            (f"{elapsed:.0f}s",       "Duration",         "blue"),
            ("Yes" if manual_investigation else "No", "Manual Review Needed",
             "yellow" if manual_investigation else "green"),
        ]
        cards = "".join(
            f'<div class="stat-card">'
            f'<div class="num num-{cls}">{_esc(n)}</div>'
            f'<div class="lbl">{_esc(lbl)}</div></div>'
            for n, lbl, cls in stats
        )

        if manual_investigation:
            cards += (
                '<div class="stat-card" style="grid-column:1/-1;text-align:left">'
                '<div style="font-weight:600">🕵 Manual Review Recommended</div>'
                '<div style="margin-top:4px;color:var(--text2)">No flag was confirmed and no finding '
                'reached the Probable confidence tier — see the Manual Investigation section below '
                'for specific next steps generated from this scan\'s actual findings.</div></div>'
            )

        return (
            f'<div id="dashboard">'
            f'<h2 style="margin:4px 0 10px">🏁 Executive Summary</h2>'
            f'<div class="dashboard">{cards}</div></div>\n'
        )

    # ------------------------------------------------------------------
    # Flags
    # ------------------------------------------------------------------

    def _flag_evidence_chain(self, f: Dict, results: Dict[str, Any]) -> List[Any]:
        """Builds the real evidence chain for a flag — which pipeline
        stages actually ran and contributed, from this scan's own results,
        not a fixed/fabricated template. Returns a list of (label, anchor)
        pairs; anchor is None for the non-clickable endpoints."""
        sstv = results.get("sstv", {})
        ocr = results.get("ocr", {})
        chain: List[Any] = [("Audio", "#player")]

        if sstv.get("vis_detected"):
            chain.append(("SSTV", "#sstv"))
        if sstv.get("decoded_image"):
            chain.append(("Image", "#sstv"))
        if sstv.get("qr_data") or ocr.get("qr_codes"):
            chain.append(("QR", "#qranalysis"))
        elif sstv.get("ocr_text") or ocr.get("ocr"):
            chain.append(("OCR", "#ocr"))

        enc = f.get("encoding", "plaintext") if isinstance(f, dict) else "plaintext"
        if enc and enc != "plaintext":
            chain.append((enc.replace("_", " ").title(), "#toolsused"))

        chain.append(("Flag", "#flags"))
        return chain

    def _flag_item_html(self, i: int, f: Dict, results: Optional[Dict[str, Any]] = None) -> str:
        val  = f.get("value", str(f)) if isinstance(f, dict) else str(f)
        enc  = f.get("encoding", "plaintext") if isinstance(f, dict) else "?"
        conf = f.get("confidence_pct", "?") if isinstance(f, dict) else "?"
        ev   = f.get("evidence", "") if isinstance(f, dict) else ""
        uid  = f"flag-{i}"

        chain_html = ""
        if results is not None:
            chain = self._flag_evidence_chain(f, results)
            nodes = []
            for i, (label, anchor) in enumerate(chain):
                if i:
                    nodes.append('<span class="chain-arrow">→</span>')
                inner = f'<a href="{anchor}">{_esc(label)}</a>' if anchor else _esc(label)
                nodes.append(f'<span class="chain-node">{inner}</span>')
            chain_html = '<div class="evidence-chain">' + "".join(nodes) + '</div>'

        return (
            f'<div class="flag-item">'
            f'<div class="flag-value" id="{uid}">{_esc(val)}</div>'
            f'<div class="flag-meta">'
            f'Encoding: {_esc(enc)} &nbsp;|&nbsp; Confidence: {_esc(conf)}'
            f'{_copy_btn(uid)}</div>'
            f'<div class="flag-meta" style="margin-top:2px">{_esc(ev[:120])}</div>'
            f'{chain_html}'
            f'</div>\n'
        )

    def _flags_section(self, flags: List, results: Optional[Dict[str, Any]] = None) -> str:
        """
        Groups flag candidates into Verified / Possible / Encoded / Rejected
        instead of one flat "Possible Flags" bucket — a plaintext hit on a
        project-specific pattern (flag{...}, HTB{...}, ...) is materially
        more trustworthy than a base64-decoded candidate, and neither should
        be presented with the same visual weight. Cipher brute-force noise
        (raw XOR/Caesar sweep output) is never in `flags` at all — flags.py
        only merges pattern-matched Finding objects here, never the sweep
        results in `cipher_results` — so there is nothing to filter out for
        that case; this only has to sort what's already a real match.
        """
        if not flags:
            return ""

        verified: List[Dict] = []
        possible: List[Dict] = []
        encoded: List[Dict] = []
        for f in flags:
            if not isinstance(f, dict):
                verified.append({"value": str(f)})
                continue
            if f.get("encoding", "plaintext") != "plaintext":
                encoded.append(f)
            elif f.get("confidence", 0) >= 0.80:
                verified.append(f)
            else:
                possible.append(f)

        def render_group(label: str, icon: str, items: List[Dict], start: int) -> str:
            if not items:
                return ""
            body = "".join(self._flag_item_html(start + i, f, results) for i, f in enumerate(items))
            return f'<h3 style="margin:10px 0 4px">{icon} {label} ({len(items)})</h3>{body}'

        idx = 0
        groups = ""
        for label, icon, items in [
            ("Verified Flags",  "✅", verified),
            ("Possible Flags",  "🟡", possible),
            ("Encoded Flags",   "🔐", encoded),
        ]:
            groups += render_group(label, icon, items, idx)
            idx += len(items)

        return (
            f'<div id="flags" class="flag-banner">'
            f'<h2>🏁 Flags ({len(flags)})</h2>'
            f'{groups}</div>\n'
        )

    # ------------------------------------------------------------------
    # All findings table
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Tools Used (v4.7 — CTF edition) — one card per tool that actually
    # executed, showing that tool's REAL captured output (stdout, parsed
    # structured data, or decoded text) instead of a bare "Success". A tool
    # only gets a card if it actually ran (available + enabled in config);
    # missing/disabled tools are simply omitted, never called out as
    # "not found". A tool that ran but produced nothing still gets a card,
    # honestly saying so — never fabricated.
    # ------------------------------------------------------------------

    def _tool_card(self, name: str, purpose: str, output: str, warning: Optional[str] = None) -> str:
        """One card: tool name, purpose, and its REAL captured output —
        never a command line, never a bare "Success"."""
        uid = f"tool-{abs(hash(name + purpose + output[:40])) % 1000000}"
        warn_html = (f'<div class="warning-box" style="margin-top:6px">⚠ {_esc(warning)}</div>'
                     if warning else "")
        return (
            '<details class="tool-card">'
            f'<summary><b>{_esc(name)}</b> '
            f'<span style="color:var(--text2);font-weight:400">— {_esc(purpose)}</span></summary>'
            f'<div style="padding:10px 4px 4px">'
            f'<pre id="{uid}">{_esc(output)}</pre>{_copy_btn(uid)}'
            f'{warn_html}'
            f'</div></details>'
        )

    def _read_cached(self, *candidates: Path) -> Optional[str]:
        """Read a tool's output text file already written during scanning —
        never re-invokes the tool. Returns the first candidate path that
        exists, or None if none do."""
        for path in candidates:
            try:
                if path.exists():
                    return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return None

    def _tools_used_section(self, results: Dict[str, Any]) -> Optional[str]:
        tools_avail = results.get("_performance", {}).get("tool_availability", {})
        metadata = results.get("metadata", {})
        binary = results.get("binary", {})
        extract = results.get("extraction", {})
        digital = results.get("digital", {})
        ocr = results.get("ocr", {})
        sstv = results.get("sstv", {})
        flags = results.get("flags", {}).get("flags_found", [])
        plugins = results.get("plugins", {})
        tools_dir = self.store.tools

        cards: List[str] = []

        # --- file ---
        if tools_avail.get("file") and metadata.get("file_cmd"):
            cards.append(self._tool_card("file", "Identify file type", metadata["file_cmd"]))

        # --- exiftool: real parsed fields, not a count ---
        exif = metadata.get("exiftool")
        if tools_avail.get("exiftool") and isinstance(exif, dict) and exif:
            lines = "\n".join(f"{k:20s}: {v}" for k, v in exif.items() if v not in (None, ""))
            cards.append(self._tool_card("exiftool", "Metadata extraction",
                                          lines or "No metadata fields found."))

        # --- ffprobe: real parsed codec/duration/sample rate/channels ---
        ffprobe = metadata.get("ffprobe")
        if tools_avail.get("ffprobe") and isinstance(ffprobe, dict) and ffprobe.get("format"):
            fmt = ffprobe["format"]
            streams = ffprobe.get("streams", [])
            s0 = streams[0] if streams else {}
            lines = "\n".join([
                f"codec       : {s0.get('codec_name', '?')}",
                f"duration    : {fmt.get('duration', '?')}s",
                f"sample_rate : {s0.get('sample_rate', '?')} Hz",
                f"channels    : {s0.get('channels', '?')}",
                f"bit_rate    : {fmt.get('bit_rate', '?')}",
                f"format_name : {fmt.get('format_name', '?')}",
            ])
            cards.append(self._tool_card("ffprobe", "Read audio stream metadata", lines))

        # --- mediainfo: real raw stdout ---
        mediainfo = metadata.get("mediainfo")
        if tools_avail.get("mediainfo") and mediainfo:
            cards.append(self._tool_card("mediainfo", "Container/stream metadata", mediainfo[:3000]))

        # --- binwalk: real DECIMAL/HEXADECIMAL/DESCRIPTION rows ---
        if tools_avail.get("binwalk"):
            hits = extract.get("binwalk", [])
            if hits:
                header = f"{'DECIMAL':<12}{'HEXADECIMAL':<14}DESCRIPTION"
                rows = "\n".join(f"{h.get('offset',''):<12}{h.get('hex',''):<14}{h.get('description','')}"
                                 for h in hits[:100])
                cards.append(self._tool_card("binwalk", "Embedded file/signature scan",
                                              f"{header}\n{rows}"))
            else:
                cached = self._read_cached(tools_dir / "binwalk_scan.txt")
                cards.append(self._tool_card("binwalk", "Embedded file/signature scan",
                                              cached or "No embedded signatures found."))

        # --- foremost / scalpel: no in-memory stdout, read the cached file ---
        for tool, filename, purpose in (
            ("foremost", "foremost.txt", "File carving"),
            ("scalpel", "scalpel.txt", "Signature carving"),
        ):
            if not tools_avail.get(tool):
                continue
            cached = self._read_cached(tools_dir / filename)
            cards.append(self._tool_card(tool, purpose, cached or "No useful output produced."))

        # --- steghide: real cached result message ---
        if tools_avail.get("steghide"):
            cached = self._read_cached(tools_dir / "steghide.txt")
            cards.append(self._tool_card("steghide", "Passphrase-based extraction attempt",
                                          cached or "No embedded data found."))

        # --- stegseek: real in-memory stdout ---
        stegseek = extract.get("stegseek", {})
        if tools_avail.get("stegseek") and isinstance(stegseek, dict) and stegseek.get("output"):
            cards.append(self._tool_card("stegseek", "Wordlist-based steghide passphrase cracking",
                                          stegseek["output"][:3000]))

        # --- strings: real extracted strings, not just a count ---
        strings_list = binary.get("strings")
        if tools_avail.get("strings") and strings_list:
            preview = "\n".join(strings_list[:60])
            cards.append(self._tool_card("strings", "Printable strings extraction", preview))

        # --- hexdump: real captured bytes ---
        if tools_avail.get("hexdump") and binary.get("hexdump"):
            cards.append(self._tool_card("hexdump", "Binary header inspection",
                                          binary["hexdump"][:2000]))

        # --- multimon-ng: real decoded output across all 3 invocations
        # (DTMF/Morse have dedicated methods; everything else runs together) ---
        if tools_avail.get("multimon-ng"):
            blocks = []
            dtmf_hits = digital.get("dtmf", [])
            if dtmf_hits:
                blocks.append("DTMF:\n" + "\n".join(str(d.get("value", "")) for d in dtmf_hits))
            morse_hits = digital.get("morse", [])
            if morse_hits:
                blocks.append("MORSE:\n" + "\n".join(str(m.get("value", "")) for m in morse_hits))
            # Validated Findings only — the raw per-mode line dict includes
            # everything multimon-ng printed even when the analyzer's own
            # confidence gates rejected it (e.g. a single-digit selective-call
            # hit from a held musical tone); using the same Finding objects
            # the Digital Modes section renders keeps the two in agreement.
            for f in digital.get("findings", []):
                if f.get("module") == "multimon":
                    blocks.append(f"{f.get('title', 'Digital Mode')}:\n{f.get('value', '')}")
            cards.append(self._tool_card("multimon-ng", "Digital mode decoding",
                                          "\n\n".join(blocks) if blocks else "No useful output produced."))

        # --- minimodem: real decoded text per baud rate ---
        if tools_avail.get("minimodem"):
            minimodem_hits = digital.get("minimodem", [])
            if minimodem_hits:
                blocks = [f"{h.get('title','')}:\n{h.get('value','')}" for h in minimodem_hits]
                cards.append(self._tool_card("minimodem", "Baudot/modem tone decoding",
                                              "\n\n".join(blocks)))
            else:
                cards.append(self._tool_card("minimodem", "Baudot/modem tone decoding",
                                              "No useful output produced."))

        # --- Custom SSTV Decoder ---
        if sstv.get("vis_detected") or sstv.get("decoded_image"):
            mode = sstv.get("mode", "Unknown")
            lines = [f"Mode         : {mode}"]
            if sstv.get("vis_code"):
                lines.append(f"VIS Code     : 0x{sstv['vis_code']:02X}")
            lines.append(f"Confidence   : {sstv.get('confidence', 0):.0%}")
            if sstv.get("decoded_image"):
                lines.append(f"Image        : {os.path.basename(sstv['decoded_image'])}")
                lines.append(f"Variant      : {sstv.get('sstv_variant_selected', 'N/A')}")
            else:
                lines.append("No image could be validated for this signal.")
            cards.append(self._tool_card("Custom SSTV Decoder", "SSTV image reconstruction",
                                          "\n".join(lines)))

        # --- rx_sstv: only if it was actually invoked this scan ---
        if "rx_sstv" in sstv.get("decoders_tried", []):
            cached = self._read_cached(tools_dir / "sstv_rx_sstv.txt")
            cards.append(self._tool_card("rx_sstv", "External SSTV decoder",
                                          cached or "No useful output produced."))

        # --- zbarimg: real decoded QR/barcode data ---
        qr_hits = list(ocr.get("qr_codes", []))
        if sstv.get("qr_data"):
            qr_hits.append({"data": sstv["qr_data"]})
        if tools_avail.get("zbarimg"):
            if qr_hits:
                text = "\n\n".join(f"QR Detected\n\n{q.get('data','')}" for q in qr_hits)
                cards.append(self._tool_card("zbarimg", "QR/barcode scanning", text))
            else:
                cards.append(self._tool_card("zbarimg", "QR/barcode scanning",
                                              "No useful output produced."))

        # --- encoded-flag decoder chain ---
        encoded_flag = next((f for f in flags if isinstance(f, dict)
                              and f.get("encoding", "plaintext") != "plaintext"), None)
        if encoded_flag:
            enc_name = encoded_flag.get("encoding", "encoded").replace("_", " ").title()
            cards.append(self._tool_card(f"{enc_name} Decoder", f"{enc_name} decoding",
                                          str(encoded_flag.get("value", ""))))

        # --- Tesseract OCR: real decoded text ---
        ocr_hits = ocr.get("ocr", [])
        if tools_avail.get("tesseract"):
            text = sstv.get("ocr_text") or (ocr_hits[0].get("text", "") if ocr_hits else "")
            cards.append(self._tool_card("Tesseract OCR", "Text recognition in images",
                                          text[:1000] if text else "No useful output produced."))

        # --- Plugins ---
        for name, result in sorted(plugins.items()):
            if not isinstance(result, dict) or result.get("error"):
                continue
            findings = result.get("findings", [])
            text = "\n".join(str(f.get("value", f.get("title", ""))) for f in findings)
            cards.append(self._tool_card(
                f"Plugin: {name}", result.get("metadata", {}).get("description", "Plugin analysis"),
                text if findings else "No useful output produced.",
            ))

        if not cards:
            return None
        return self._section("toolsused", f"🛠 Tools Used ({len(cards)})", "".join(cards))

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    # Standard fields surfaced explicitly (in this order); anything else
    # exiftool reported is still shown, grouped under "Other Tags" below.
    _METADATA_FIELD_LABELS = [
        ("Artist", "Artist"), ("Album", "Album"),
        ("Title", "Title"), ("Comment", "Comment"), ("Description", "Comment"),
        ("CreateDate", "Creation Time"), ("DateTimeOriginal", "Creation Time"),
        ("ModifyDate", "Modified Time"),
    ]

    def _metadata_section(self, metadata: Dict) -> str:
        hashes = metadata.get("hashes", {})
        exif = metadata.get("exiftool") if isinstance(metadata.get("exiftool"), dict) else {}
        ffprobe = metadata.get("ffprobe") if isinstance(metadata.get("ffprobe"), dict) else {}
        fmt = ffprobe.get("format", {}) if isinstance(ffprobe, dict) else {}
        streams = ffprobe.get("streams", []) if isinstance(ffprobe, dict) else []
        s0 = streams[0] if streams else {}

        rows = [
            ("Filename", exif.get("FileName") or os.path.basename(fmt.get("filename", "")) or "N/A"),
            ("SHA256", hashes.get("sha256", "N/A")),
            ("MD5", hashes.get("md5", "N/A")),
            ("SHA1", hashes.get("sha1", "N/A")),
            ("Codec", s0.get("codec_name") or exif.get("AudioFormat") or "N/A"),
            ("Container", fmt.get("format_long_name") or exif.get("FileType") or "N/A"),
        ]
        shown_exif_keys = {"FileName"}
        for key, label in self._METADATA_FIELD_LABELS:
            val = exif.get(key)
            if val:
                rows.append((label, val))
                shown_exif_keys.add(key)

        html = '<table class="kv-table">' + "".join(
            f'<tr><td>{_esc(k)}</td><td><code>{_esc(str(v))}</code></td></tr>' for k, v in rows
        ) + '</table>'

        other_tags = {k: v for k, v in exif.items()
                      if k not in shown_exif_keys and v not in (None, "")}
        if other_tags:
            html += '<h3 style="margin:10px 0 4px">Other Tags</h3><table class="kv-table">' + "".join(
                f'<tr><td>{_esc(k)}</td><td><code>{_esc(str(v))}</code></td></tr>'
                for k, v in list(other_tags.items())[:30]
            ) + '</table>'

        return self._section("metadata", "📋 Metadata", html)

    # ------------------------------------------------------------------
    # Audio Preview / Audio Information
    # ------------------------------------------------------------------

    def _audio_preview_section(self, audio_path: str, metadata: Dict) -> str:
        ffprobe = metadata.get("ffprobe") if isinstance(metadata.get("ffprobe"), dict) else {}
        fmt = ffprobe.get("format", {}) if isinstance(ffprobe, dict) else {}
        streams = ffprobe.get("streams", []) if isinstance(ffprobe, dict) else []
        s0 = streams[0] if streams else {}

        dur = fmt.get("duration")
        dur_str = f"{float(dur):.1f}s" if dur else "N/A"
        rows = (
            f'<tr><td>Duration</td><td>{_esc(dur_str)}</td></tr>'
            f'<tr><td>Channels</td><td>{_esc(s0.get("channels", "N/A"))}</td></tr>'
            f'<tr><td>Sample Rate</td><td>{_esc(s0.get("sample_rate", "N/A"))} Hz</td></tr>'
            f'<tr><td>Bitrate</td><td>{_esc(fmt.get("bit_rate", "N/A"))}</td></tr>'
        )
        html = _embed_audio_player(audio_path) + f'<table class="kv-table" style="margin-top:10px">{rows}</table>'
        return self._section("player", "🎧 Audio Preview", html)

    def _audio_information_section(self, metadata: Dict) -> Optional[str]:
        ffprobe = metadata.get("ffprobe") if isinstance(metadata.get("ffprobe"), dict) else {}
        fmt = ffprobe.get("format", {}) if isinstance(ffprobe, dict) else {}
        streams = ffprobe.get("streams", []) if isinstance(ffprobe, dict) else []
        s0 = streams[0] if streams else {}
        if not fmt and not s0:
            return None
        rows = "".join(
            f'<tr><td>{_esc(k)}</td><td><code>{_esc(str(v))}</code></td></tr>'
            for k, v in [
                ("Format", fmt.get("format_name")), ("Codec (long)", s0.get("codec_long_name")),
                ("Sample Format", s0.get("sample_fmt")), ("Bits per Sample", s0.get("bits_per_sample")),
                ("Channel Layout", s0.get("channel_layout")), ("Bit Rate", fmt.get("bit_rate")),
                ("Size (bytes)", fmt.get("size")), ("Number of Streams", fmt.get("nb_streams")),
            ] if v not in (None, "", 0)
        )
        return self._section("audioinfo", "🎚 Audio Information", f'<table class="kv-table">{rows}</table>')

    # ------------------------------------------------------------------
    # Visuals — Waveform / Spectrogram / FFT / Frequency Analysis, each its
    # own section (per the CTF report order) instead of one combined block.
    # ------------------------------------------------------------------

    def _waveform_section(self, visual: Dict) -> Optional[str]:
        p = visual.get("waveform") or visual.get("waveform_ffmpeg")
        if not p:
            return None
        return self._section("waveform", "〰️ Waveform", _embed_img(p, "Waveform"))

    def _spectrogram_section(self, visual: Dict) -> Optional[str]:
        p = visual.get("spectrogram") or visual.get("spectrogram_ffmpeg")
        if not p:
            return None
        return self._section("spectrogram", "📊 Spectrogram", _embed_img(p, "Spectrogram"))

    def _fft_section(self, visual: Dict) -> Optional[str]:
        p = visual.get("fft")
        if not p:
            return None
        return self._section("fft", "📈 FFT", _embed_img(p, "FFT Spectrum"))

    def _frequency_analysis_section(self, forensics: Dict) -> Optional[str]:
        bands = forensics.get("bands")
        if not bands:
            return None
        rows = "".join(f'<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>' for k, v in bands.items())
        return self._section("freqanalysis", "🔊 Frequency Analysis", f'<table class="kv-table">{rows}</table>')

    # ------------------------------------------------------------------
    # SSTV
    # ------------------------------------------------------------------

    # Display names for each post-processing variant, matching the order
    # the user wants them presented in ("Other Variants").
    _SSTV_VARIANT_LABELS = {
        "standard": "Standard", "high_contrast": "Contrast",
        "minimal": "Minimal", "clahe_bilateral": "CLAHE",
    }

    def _sstv_section(self, sstv: Dict) -> Optional[str]:
        if not sstv.get("vis_detected") and not sstv.get("decoded_image"):
            return None

        content = ""
        if sstv.get("decoded_image"):
            dims = sstv.get("decoded_image_dimensions")
            dims_str = f"{dims[0]}×{dims[1]} px" if dims else "unknown"
            variant = sstv.get("sstv_variant_selected")
            variant_scores = sstv.get("sstv_variant_scores", {})
            quality_scores = sstv.get("sstv_image_quality_scores", {})
            variant_paths = sstv.get("sstv_variant_paths", {})
            decode_time = sstv.get("decode_time_s")

            content += f'<div class="sstv-hero-image">{_embed_img(sstv["decoded_image"], "SSTV decoded image (best)")}</div>'
            if sstv.get("decoded_image_upscaled") and os.path.exists(sstv["decoded_image_upscaled"]):
                content += (
                    f'<p style="margin-top:6px"><a class="dl-btn" '
                    f'href="data:image/png;base64,{base64.b64encode(open(sstv["decoded_image_upscaled"],"rb").read()).decode()}" '
                    f'download="decoded_best_upscaled.png">⬇ Download Full-Resolution Upscaled (2x)</a></p>'
                )

            rows = [
                ("Mode", sstv.get("mode", "Unknown")),
                ("VIS", f'0x{sstv.get("vis_code", 0):02X}'),
                ("Quality", f'{quality_scores.get(variant, 0):.2f}' if variant in quality_scores else "N/A"),
                ("Confidence", f'{sstv.get("confidence", 0):.0%}'),
                ("Image Resolution", dims_str),
                ("Decode Time", f'{decode_time:.2f}s' if decode_time is not None else "N/A"),
            ]
            content += '<table class="kv-table" style="margin:10px 0">' + "".join(
                f'<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>' for k, v in rows
            ) + '</table>'

            if variant_scores:
                content += "<h3 style='margin:10px 0 4px'>Other Variants</h3>"
                content += '<div class="grid3">'
                for n, s in sorted(variant_scores.items(), key=lambda kv: -kv[1]):
                    label = self._SSTV_VARIANT_LABELS.get(n, n)
                    selected = n == variant
                    vpath = variant_paths.get(n)
                    img_html = _embed_img(vpath, f"SSTV variant: {label}") if vpath else ""
                    content += (
                        f'<div class="tool-card" style="{"border-color:var(--green)" if selected else ""}">'
                        f'<b>{_esc(label)}</b>{" ✓ selected" if selected else ""}'
                        f'<div style="color:var(--text2);font-size:.85em">score {s:.2f}</div>'
                        f'{img_html}</div>'
                    )
                content += '</div>'
        else:
            content += (
                '<p style="color:var(--text3)">SSTV signal detected but no image could be '
                f'reconstructed. Decoders tried: {_esc(", ".join(sstv.get("decoders_tried", [])) or "none")}.</p>'
            )

        if sstv.get("ocr_text"):
            uid = "sstv-ocr"
            content += (
                f'<h3 style="margin:10px 0 4px">OCR Text {_copy_btn(uid)}</h3>'
                f'<pre id="{uid}">{_esc(sstv["ocr_text"][:1000])}</pre>'
            )
        if sstv.get("qr_data"):
            content += f'<h3 style="margin:10px 0 4px">QR Data</h3>'
            content += f'<div class="flag-item"><code>{_esc(sstv["qr_data"])}</code></div>'
        return self._section("sstv", "📺 SSTV Analysis", content)

    # ------------------------------------------------------------------
    # Digital modes
    # ------------------------------------------------------------------

    def _digital_section(self, digital: Dict) -> Optional[str]:
        """Only protocols that actually decoded something get shown — a
        clean scan renders nothing here except the one honest fallback
        line, never a checklist of "not detected" placeholders."""
        parts = []
        for key, label, icon in [
            ("morse",     "Morse CW",    "📡"),
            ("dtmf",      "DTMF",        "📞"),
            ("minimodem", "Minimodem",   "📶"),
        ]:
            items = digital.get(key, [])
            if not items:
                continue
            parts.append(f'<h3 style="margin:8px 0 4px">{icon} {_esc(label)}</h3>')
            for item in items:
                val  = item.get("value", item.get("decoded", item.get("digits", "")))
                conf = item.get("confidence_pct", "?")
                parts.append(
                    f'<div class="flag-item" style="border-color:var(--blue)">'
                    f'{_badge(conf, "medium")} <code>{_esc(str(val)[:300])}</code>'
                    f'</div>'
                )
        # multimon-ng "all mode" protocols (POCSAG/FLEX/AFSK1200/selective-call/
        # etc.) — rendered from validated Findings, not the raw per-mode line
        # dict. The raw dict includes every line multimon-ng printed, even
        # ones the digital-modes analyzer's own confidence gates reject (e.g.
        # a single-digit selective-call hit from a held musical tone); using
        # the same Finding objects the analyzer already validated keeps this
        # section and Tools Used from disagreeing with each other.
        multimon_findings = [f for f in digital.get("findings", []) if f.get("module") == "multimon"]
        for f in multimon_findings:
            parts.append(f'<h3 style="margin:8px 0 4px">📻 {_esc(f.get("title", "Digital Mode"))}</h3>')
            parts.append(f'<div class="flag-item" style="border-color:var(--blue)">'
                         f'{_badge(f.get("confidence_pct", "?"), "medium")} '
                         f'<code>{_esc(str(f.get("value", ""))[:300])}</code></div>')

        if not parts:
            return None
        return self._section("digital", "📡 Digital Modes", "".join(parts))

    # ------------------------------------------------------------------
    # OCR / QR
    # ------------------------------------------------------------------

    def _ocr_section(self, ocr: Dict) -> Optional[str]:
        parts = []
        for r in ocr.get("ocr", []):
            uid = f"ocr-{id(r)}"
            parts.append(
                f'<div style="margin-bottom:12px">'
                f'<strong>{_esc(os.path.basename(r.get("image","?")))}</strong>'
                f' — confidence {r.get("confidence",0):.0f}%'
                f'{_copy_btn(uid)}'
                f'<pre id="{uid}">{_esc(r.get("text","")[:1000])}</pre></div>'
            )
        if not parts:
            return None
        return self._section("ocr", "🔍 OCR", "".join(parts))

    # ------------------------------------------------------------------
    # QR Analysis (v4.4) — dedicated section, split out of the old
    # combined "OCR & QR"; pulls from every source that can produce a QR
    # hit (the general-purpose OCR module's zbarimg pass over extracted/
    # decoded images, and the SSTV pipeline's own zbarimg pass on the
    # reconstructed image).
    # ------------------------------------------------------------------

    def _qr_hit_card(self, image: Optional[str], data: str, qr_type: str, confidence: float) -> str:
        uid = f"qr-{abs(hash(data)) % 100000}"
        detected_encoding = "Plaintext"
        decoded_value = data
        if is_likely_base64(data):
            detected_encoding = "Base64"
            try:
                import base64 as _b64
                decoded_value = _b64.b64decode(data + "==").decode("utf-8", errors="replace")
            except Exception:
                decoded_value = "(could not decode)"
        elif re.fullmatch(r"[0-9A-Fa-f]{8,}", data) and len(data) % 2 == 0:
            detected_encoding = "Hex"
            try:
                decoded_value = bytes.fromhex(data).decode("utf-8", errors="replace")
            except Exception:
                decoded_value = "(could not decode)"

        raw_bytes_hex = data.encode("utf-8", errors="replace").hex()
        img_html = _embed_img(image, "Decoded QR image") if image else ""

        return (
            f'<div class="flag-item" style="border-color:var(--green)">'
            f'{img_html}'
            f'<table class="kv-table" style="margin-top:8px">'
            f'<tr><td>Symbology</td><td>{_badge(qr_type or "QR", "high")}</td></tr>'
            f'<tr><td>Decoded Text</td><td><code id="{uid}">{_esc(data)}</code>{_copy_btn(uid)}</td></tr>'
            f'<tr><td>Encoding Detected</td><td>{_esc(detected_encoding)}</td></tr>'
            f'<tr><td>Decoded Value</td><td><code>{_esc(decoded_value)}</code></td></tr>'
            f'<tr><td>Confidence</td><td>{confidence*100:.0f}%</td></tr>'
            f'<tr><td>Raw Bytes (hex)</td><td><code style="word-break:break-all">{_esc(raw_bytes_hex)}</code></td></tr>'
            f'</table></div>'
        )

    def _qr_analysis_section(self, results: Dict[str, Any]) -> Optional[str]:
        cards = []
        ocr = results.get("ocr", {})
        sstv = results.get("sstv", {})

        for q in ocr.get("qr_codes", []):
            cards.append(self._qr_hit_card(q.get("image"), q.get("data", ""), q.get("type", "QR"), 0.99))

        if sstv.get("qr_data"):
            raw = sstv["qr_data"]
            symbology, sep, value = raw.partition(":")
            data = value if sep else raw
            cards.append(self._qr_hit_card(
                sstv.get("decoded_image"), data, sstv.get("barcode_type") or symbology, 0.99))

        if not cards:
            return None
        return self._section("qranalysis", f"📱 QR Analysis ({len(cards)})", "".join(cards))

    # ------------------------------------------------------------------
    # Binary
    # ------------------------------------------------------------------

    def _binary_section(self, binary: Dict, forensics: Optional[Dict] = None) -> str:
        entropy = binary.get("entropy", {})
        parts   = [
            '<table class="kv-table">',
            f'<tr><td>Overall entropy</td><td>{_esc(str(entropy.get("overall","?")))}</td></tr>',
            f'<tr><td>Max block entropy</td><td>{_esc(str(entropy.get("max_block","?")))}</td></tr>',
            f'<tr><td>High-entropy blocks</td><td>{_esc(str(len(entropy.get("high_entropy_blocks",[]))))}</td></tr>',
            '</table>',
        ]
        appended = binary.get("appended_data")
        if appended and appended.get("detected"):
            parts.append(
                f'<div class="warning-box" style="margin-top:8px">'
                f'⚠ Appended data: {_esc(str(appended.get("extra_bytes",0)))} bytes '
                f'at offset 0x{appended.get("offset",0):08x}</div>'
            )

        # LSB extraction — the one audio-forensics signal common enough in
        # real CTF challenges to keep front and center; folded in here
        # rather than a separate "Audio Forensics" page of numeric noise.
        lsb_list = (forensics or {}).get("lsb", [])
        if lsb_list:
            parts.append("<h3 style='margin:10px 0 4px'>LSB Extraction</h3>")
            parts.append('<table class="kv-table">'
                         '<tr><td>Channel/Bits</td><td>Printable Ratio</td><td>Preview</td></tr>')
            for r in lsb_list:
                prev = _esc(r.get("text_preview", "")[:120])
                parts.append(
                    f'<tr><td>ch{r["channel"]}, {r["n_bits"]}-bit</td>'
                    f'<td>{r["printable_ratio"]:.0%}</td>'
                    f'<td><code>{prev}</code></td></tr>'
                )
            parts.append('</table>')

        return self._section("binary", "🔢 Binary Analysis", "".join(parts))

    # ------------------------------------------------------------------
    # Manual Investigation (v4.3) — surfaces the Hint Engine's actionable,
    # results-derived recommendations directly in the primary report instead
    # of only in a separate hints.txt an analyst has to know to open.
    # ------------------------------------------------------------------

    def _build_reproduction_guide(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Builds a numbered, beginner-friendly reproduction guide entirely
        from this scan's own real results (v4.4, replacing the old raw
        Hint Engine text dump). Every Evidence/Why/Result line quotes an
        actual Finding's own evidence/reason/value or a real results field —
        nothing invented. A stage that genuinely ran but found nothing
        (e.g. OCR attempted, no text) is still shown, since "no text
        found" is real information; a stage that never ran at all (e.g.
        SSTV disabled in config) is simply absent from the list rather
        than faked.
        """
        steps: List[Dict[str, Any]] = []
        sstv = results.get("sstv", {})
        flags = results.get("flags", {}).get("flags_found", [])
        extract = results.get("extraction", {})

        if sstv.get("vis_detected"):
            vis_finding = next((f for f in sstv.get("findings", [])
                                 if "VIS Code Detected" in f.get("title", "")), None)
            steps.append({
                "title": "SSTV Signal Detected",
                "evidence": f"{sstv.get('mode', 'Unknown')} detected "
                            f"(VIS 0x{sstv.get('vis_code', 0):02X})",
                "why": vis_finding["reason"] if vis_finding else
                       "VIS preamble matched the timing spec for this mode.",
                "result": "Continue with SSTV image reconstruction.",
            })

        if sstv.get("decoded_image"):
            variant = sstv.get("sstv_variant_selected")
            scores = sstv.get("sstv_variant_scores", {})
            why = (f"Variant '{variant}' scored highest ({scores.get(variant, 0):.2f}) among "
                   f"{len(scores)} reconstruction candidates." if variant else
                   "Reconstruction completed and passed independent validation.")
            steps.append({
                "title": "Image Reconstructed",
                "evidence": "Decoded image generated: decoded_best.png",
                "why": why,
                "result": "See the SSTV Analysis section for the image.",
                "file": "decoded_best.png",
            })

            steps.append({
                "title": "Run OCR",
                "evidence": "Tesseract OCR executed on the reconstructed image.",
                "why": "Text may be embedded directly in the picture.",
                "result": (f'Text found: "{sstv["ocr_text"][:200]}"' if sstv.get("ocr_text")
                           else "No text found."),
            })

            steps.append({
                "title": "Run QR/Barcode Detector",
                "evidence": "zbarimg executed on the reconstructed image.",
                "why": "A QR code or barcode may encode the flag directly.",
                # zbarimg's own output already includes its "QR-Code:"/
                # "EAN13:"/etc. symbology prefix — not re-added here.
                "result": (sstv["qr_data"] if sstv.get("qr_data") else "No QR code found."),
            })
        elif extract.get("records"):
            _confirmed = {"verified", "extracted", "nested", "recovered", "partial"}
            confirmed_recs = [r for r in extract["records"]
                               if (r.status.value if hasattr(r.status, "value") else str(r.status)) in _confirmed]
            if confirmed_recs:
                best_rec = max(confirmed_recs, key=lambda r: r.confidence)
                steps.append({
                    "title": f"{best_rec.file_type} Extracted",
                    "evidence": f"Carved at offset 0x{best_rec.offset:08x}, "
                                f"{best_rec.confidence*100:.0f}% confidence",
                    "why": best_rec.reason,
                    "result": f"See {os.path.basename(best_rec.output_path or '')} below.",
                    "artifact_path": best_rec.output_path,
                })

        # Encoded-flag decode step — reuses flags.py's own already-computed
        # evidence/reason text, not new narrative.
        encoded_flag = next((f for f in flags if isinstance(f, dict)
                              and f.get("encoding", "plaintext") != "plaintext"), None)
        if encoded_flag:
            enc_name = encoded_flag.get("encoding", "encoded").replace("_", " ").title()
            steps.append({
                "title": f"Recognize {enc_name}",
                "evidence": encoded_flag.get("evidence", ""),
                "why": encoded_flag.get("reason", "Encoded data pattern matched."),
                "result": f"Decode {enc_name}.",
            })
            steps.append({
                "title": f"Decode {enc_name}",
                "evidence": encoded_flag.get("value", ""),
                "why": "Applying the standard decoding for this encoding recovers the flag text.",
                "result": f"Decoded: {encoded_flag.get('value', '')}",
            })

        top_flag = None
        if flags:
            dict_flags = [f for f in flags if isinstance(f, dict)]
            if dict_flags:
                top_flag = max(dict_flags, key=lambda f: f.get("confidence", 0))

        # Strings is checked on essentially every real investigation — show
        # what it actually found, honestly, even when the answer is
        # "nothing" (that's still real information, not a blank).
        strings_list = results.get("binary", {}).get("strings") or []
        if strings_list and not top_flag:
            steps.append({
                "title": "Run Strings",
                "evidence": f"{len(strings_list)} printable string(s) extracted",
                "why": "A flag or hint may appear directly as printable text.",
                "result": "Nothing useful.",
            })

        if top_flag:
            steps.append({
                "final": True,
                "value": top_flag.get("value", ""),
                "confidence": top_flag.get("confidence", 0),
            })
        elif steps:
            # Real steps ran and produced no flag — say so plainly, the
            # same honest "no hidden flag" conclusion a human investigator
            # would write, not silence.
            steps.append({"final": True, "no_flag": True})

        return steps

    def _manual_investigation_section(self, results: Dict[str, Any], manual_review_needed: bool) -> str:
        guide = self._build_reproduction_guide(results)
        hints = results.get("hints", [])

        status = (
            '<p style="color:var(--yellow);margin-bottom:12px">⚠ No flag confirmed — '
            'manual review recommended.</p>' if manual_review_needed else
            '<p style="color:var(--green);margin-bottom:12px">✓ Real evidence was recovered — '
            'follow the steps below.</p>'
        )

        body_parts: List[str] = []
        step_no = 0
        for step in guide:
            if step.get("final"):
                if step.get("no_flag"):
                    body_parts.append(
                        '<div class="repro-final" style="border-color:var(--text3);background:none">'
                        '<h3 style="margin:0 0 8px">Final Conclusion</h3>'
                        '<div style="color:var(--text2)">No hidden flag found from the steps above.</div>'
                        '</div>'
                    )
                    continue
                uid = "final-flag-value"
                body_parts.append(
                    '<div class="repro-final">'
                    '<h3 style="margin:0 0 8px">🏁 Final Flag</h3>'
                    f'<div class="flag-value" id="{uid}" style="font-size:1.2em">{_esc(step["value"])}</div>'
                    f'{_copy_btn(uid)}'
                    f'<div style="margin-top:8px;color:var(--text2)">Confidence: '
                    f'<b>{step["confidence"]*100:.0f}%</b></div>'
                    '</div>'
                )
                continue
            step_no += 1
            file_html = (
                f'<div class="repro-field"><b>File:</b> <code>{_esc(step["file"])}</code></div>'
                if step.get("file") else ""
            )
            artifact_path = step.get("artifact_path")
            if artifact_path and os.path.exists(artifact_path):
                ext = Path(artifact_path).suffix.lower()
                if ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif"):
                    file_html += _embed_img(artifact_path, os.path.basename(artifact_path))
                else:
                    try:
                        with open(artifact_path, "rb") as fh:
                            data = base64.b64encode(fh.read()).decode()
                        file_html += (
                            f'<a class="dl-btn" href="data:application/octet-stream;base64,{data}" '
                            f'download="{_esc(os.path.basename(artifact_path))}">'
                            f'⬇ Download {_esc(os.path.basename(artifact_path))}</a>'
                        )
                    except OSError:
                        pass
            body_parts.append(
                f'<div class="repro-step">'
                f'<div class="repro-step-title">Step {step_no} — {_esc(step["title"])}</div>'
                f'<div class="repro-field"><b>Evidence:</b> {_esc(step["evidence"])}</div>'
                f'<div class="repro-field"><b>Why:</b> {_esc(step["why"])}</div>'
                f'{file_html}'
                f'<div class="repro-field"><b>Result:</b> {_esc(step["result"])}</div>'
                f'</div>'
            )

        if not guide and not hints:
            body_parts.append(
                "<p style='color:var(--text3)'>No automatic evidence chain could be reconstructed "
                "for this scan, and no specific hints were generated either — review the Tools Used "
                "section directly.</p>"
            )
        elif not guide:
            body_parts.append(
                "<p style='color:var(--text3)'>No automatic evidence chain could be reconstructed "
                "for this scan. General investigation tips based on this scan's findings:</p>"
            )

        # Hints are always shown when present — either as the only content
        # (no automatic chain could be built) or as supplementary tips
        # alongside a chain/flag that was found through a different path
        # than the hints describe.
        if hints:
            label = "Additional Investigation Tips" if guide else None
            if label:
                body_parts.append(f'<h3 style="margin:14px 0 6px">{_esc(label)}</h3>')
            body_parts.append("".join(
                f'<div class="flag-item" style="border-color:var(--blue)">'
                f'<pre style="white-space:pre-wrap;background:none;border:none;padding:0">'
                f'{_esc(h)}</pre></div>'
                for h in hints
            ))

        return self._section("manual", "🕵 Manual Reproduction", status + "".join(body_parts))

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------

    def _warnings_section(self, warnings: List[str]) -> str:
        html = "".join(f'<div class="warning-box">⚠ {_esc(w)}</div>' for w in warnings)
        return self._section("warnings", f"⚠ Warnings ({len(warnings)})", html)

    # ------------------------------------------------------------------
    # Section template
    # ------------------------------------------------------------------

    def _section(self, sid: str, title: str, body: str, open_by_default: bool = False) -> str:
        open_cls = " open" if open_by_default else ""
        chev_cls = " open-chevron" if open_by_default else ""
        return (
            f'<div id="{_esc(sid)}" class="section">'
            f'<div class="section-header{chev_cls}" id="sh-{_esc(sid)}" '
            f'onclick="toggleSection(\'{_esc(sid)}\')">'
            f'<span class="chevron">▶</span>'
            f'<h2>{_esc(title)}</h2></div>'
            f'<div class="section-body{open_cls}" id="sb-{_esc(sid)}">'
            f'{body}'
            f'</div></div>\n'
        )
