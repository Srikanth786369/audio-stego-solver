"""
Shared data structures and cipher utilities for Audio Stego Solver.
Eliminates code duplication across binary.py, flags.py, and plugins.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity / Confidence
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    """
    Structured finding produced by any analyzer.
    Every detection MUST go through this structure so reports are uniform.
    """
    module: str                        # e.g. "morse", "dtmf", "flags"
    title: str                         # Short human title
    severity: Severity = Severity.INFO
    confidence: float = 0.0            # 0.0 – 1.0
    value: str = ""                    # The actual found value (flag, digits, text…)
    evidence: str = ""                 # What was observed
    reason: str = ""                   # Why we believe this
    raw_output: str = ""               # Raw tool output (truncated)
    encoding: str = "plaintext"
    offset: Optional[int] = None
    false_positive_risk: str = ""      # Known FP risk for this detection
    tags: List[str] = field(default_factory=list)

    @property
    def confidence_pct(self) -> str:
        return f"{self.confidence * 100:.0f}%"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "confidence_pct": self.confidence_pct,
            "value": self.value,
            "evidence": self.evidence,
            "reason": self.reason,
            "raw_output": self.raw_output[:500],
            "encoding": self.encoding,
            "offset": self.offset,
            "false_positive_risk": self.false_positive_risk,
            "tags": self.tags,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.module}/{self.title} "
            f"(confidence={self.confidence_pct}) → {self.value[:80]}"
        )


# ---------------------------------------------------------------------------
# Confidence engine (Phase 5) — evidence-based scoring, single source of truth
# ---------------------------------------------------------------------------

class EvidenceLevel(str, Enum):
    """
    What kind of proof backs a detection. Confidence is derived from this,
    not hand-picked per call site, so the same kind of evidence always
    produces the same score across every analyzer.
    """
    MAGIC_ONLY           = "magic_only"            # bytes matched a signature, nothing else checked
    HEADER_PARSED        = "header_parsed"         # header fields decoded and read without error
    STRUCTURE_VALIDATED  = "structure_validated"   # internal structure walked/confirmed consistent
    CHECKSUM_VALID       = "checksum_valid"        # a checksum/CRC/hash inside the artifact was verified
    EXTRACTED            = "extracted"             # bytes successfully written to disk and are non-empty
    PARSED_OPENED        = "parsed_opened"         # a real parser/decoder fully processed the content


EVIDENCE_CONFIDENCE: Dict[EvidenceLevel, float] = {
    EvidenceLevel.MAGIC_ONLY:          0.20,
    EvidenceLevel.HEADER_PARSED:       0.40,
    EvidenceLevel.STRUCTURE_VALIDATED: 0.60,
    EvidenceLevel.CHECKSUM_VALID:      0.80,
    EvidenceLevel.EXTRACTED:           0.95,
    EvidenceLevel.PARSED_OPENED:       1.00,
}


def confidence_for_evidence(level: EvidenceLevel) -> float:
    """Return the standard confidence score for a given evidence level."""
    return EVIDENCE_CONFIDENCE[level]


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}

# Highest severity permissible at a given confidence floor (checked high to low).
_CONFIDENCE_SEVERITY_CAP = [
    (0.95, Severity.CRITICAL),
    (0.80, Severity.HIGH),
    (0.60, Severity.MEDIUM),
    (0.40, Severity.LOW),
    (0.00, Severity.INFO),
]


def severity_cap_for_confidence(confidence: float) -> Severity:
    """The highest severity a finding at this confidence is allowed to carry."""
    for threshold, sev in _CONFIDENCE_SEVERITY_CAP:
        if confidence >= threshold:
            return sev
    return Severity.INFO


def cap_severity(severity: Severity, confidence: float) -> Severity:
    """
    Clamp a requested severity down to what its confidence score justifies.
    Never raises severity — only lowers it. This is what prevents a 20%
    confidence "no validator for this type" hit from being displayed as HIGH.
    """
    cap = severity_cap_for_confidence(confidence)
    if _SEVERITY_RANK[severity] > _SEVERITY_RANK[cap]:
        return cap
    return severity


# ---------------------------------------------------------------------------
# Confidence tiers (v4.2) — human-facing classification layered on top of the
# numeric confidence engine above, used by report rendering to group/hide
# findings instead of presenting a flat list of raw percentages.
# ---------------------------------------------------------------------------

class ConfidenceTier(str, Enum):
    VERIFIED = "VERIFIED"   # checksum/structure verified or better (>= 0.80)
    PROBABLE = "PROBABLE"   # structure validated (>= 0.60)
    POSSIBLE = "POSSIBLE"   # header parsed or magic-only (>= 0.20)
    REJECTED = "REJECTED"   # explicitly rejected, or below the magic-only floor


# Findings/flags below this confidence are hidden from the report by default
# (a "Show Low Confidence Findings" toggle reveals them) — never deleted or
# omitted from report.json, only de-emphasized in the human-facing HTML view.
LOW_CONFIDENCE_DISPLAY_THRESHOLD = 0.50

_TIER_THRESHOLDS = [
    (0.80, ConfidenceTier.VERIFIED),
    (0.60, ConfidenceTier.PROBABLE),
    (0.20, ConfidenceTier.POSSIBLE),
]


def confidence_tier(confidence: float, tags: Optional[List[str]] = None) -> ConfidenceTier:
    """
    Classify a numeric confidence (plus optional tags) into the human-facing
    tier used for grouping/hiding in reports. A "rejected" tag always wins
    regardless of the numeric score, since a rejected decode/validation may
    still carry a nonzero confidence value for diagnostic purposes.
    """
    if tags and "rejected" in tags:
        return ConfidenceTier.REJECTED
    for threshold, tier in _TIER_THRESHOLDS:
        if confidence >= threshold:
            return tier
    return ConfidenceTier.REJECTED


# ---------------------------------------------------------------------------
# Cipher utilities (single source of truth — import from here everywhere)
# ---------------------------------------------------------------------------

def rot13(text: str) -> str:
    """Apply ROT13 to alphabetic characters."""
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


def caesar(text: str, shift: int) -> str:
    """Apply a Caesar shift to alphabetic characters."""
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


def atbash(text: str) -> str:
    """Apply Atbash cipher."""
    result = []
    for c in text:
        if "a" <= c <= "z":
            result.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            result.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# Characters valid in any CTF flag value (conservative)
_FLAG_VALUE_CHARS = re.compile(r"^[A-Za-z0-9_\-!@#$%^&*()+= ,.<>?;:'\"\\|/\[\]{}~`]+$")

# Known false-positive sources in flag detection
_FP_SOURCES = {"format", "css", "json", "xml", "html", "javascript"}

FLAG_PATTERNS: List[re.Pattern] = [
    re.compile(r"flag\{[^}]{3,80}\}",      re.IGNORECASE),
    re.compile(r"HTB\{[^}]{3,80}\}"),
    re.compile(r"THM\{[^}]{3,80}\}"),
    re.compile(r"picoCTF\{[^}]{3,80}\}"),
    re.compile(r"CTF\{[^}]{3,80}\}"),
    re.compile(r"Hero\{[^}]{3,80}\}"),
    re.compile(r"Hack\{[^}]{3,80}\}"),
    re.compile(r"iris\{[^}]{3,80}\}"),
    re.compile(r"uiuctf\{[^}]{3,80}\}"),
    re.compile(r"corCTF\{[^}]{3,80}\}"),
    re.compile(r"NACTF\{[^}]{3,80}\}"),
    re.compile(r"LACTF\{[^}]{3,80}\}"),
    re.compile(r"Buckeye\{[^}]{3,80}\}",   re.IGNORECASE),
    re.compile(r"GreyCat\{[^}]{3,80}\}",   re.IGNORECASE),
    re.compile(r"[a-zA-Z]{2,12}\{[A-Za-z0-9_\-]{6,80}\}"),  # Generic CTF flag
]

# Suspicious credential / secret patterns
SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"password[:\s=]+\S{4,}", re.IGNORECASE),
    re.compile(r"\bsecret[:\s=]+\S{4,}", re.IGNORECASE),
    re.compile(r"\btoken[:\s=]+[A-Za-z0-9\-_]{10,}", re.IGNORECASE),
    re.compile(r"(?:BEGIN|END)\s+(?:PGP|RSA|DSA|EC)\s+(?:PRIVATE\s+)?KEY"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
    re.compile(r"ghp_[A-Za-z0-9]{36}"),   # GitHub token
    re.compile(r"AKIA[0-9A-Z]{16}"),       # AWS access key
]


def looks_like_flag(text: str) -> bool:
    """Return True if text contains a recognisable CTF flag."""
    return any(p.search(text) for p in FLAG_PATTERNS)


def find_flags_in_text(text: str, source: str = "unknown") -> List[Finding]:
    """
    Search text for CTF flag patterns.
    Returns only high-confidence results (no catch-all generic matches
    that overlap with CSS/JSON).
    """
    findings: List[Finding] = []
    seen: set = set()

    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0)
            if val in seen:
                continue
            seen.add(val)

            # Confidence heuristic: specific patterns → higher confidence
            is_specific = not pat.pattern.startswith(r"[a-zA-Z]")
            conf = 0.95 if is_specific else 0.70

            start = max(0, m.start() - 60)
            end   = min(len(text), m.end() + 60)
            context = text[start:end].replace("\n", " ")

            findings.append(Finding(
                module="flags",
                title="CTF Flag Detected",
                severity=Severity.CRITICAL,
                confidence=conf,
                value=val,
                evidence=f"Pattern match in {source}: context='{context}'",
                reason=f"Matched pattern: {pat.pattern[:60]}",
                encoding="plaintext",
                false_positive_risk="Low for specific patterns; medium for generic pattern",
                tags=["flag"],
            ))

    return findings


# ---------------------------------------------------------------------------
# Generic decode-quality scoring (v4.1) — shared by any plugin/engine that
# brute-forces a decode (XOR, cipher, base-N) and needs to tell a real
# plaintext hit apart from decode noise. Single source of truth so every
# call site uses the same thresholds.
# ---------------------------------------------------------------------------

def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII or common whitespace."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return printable / len(data)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. ~8.0 = random/encrypted, ~4.0-5.0 = English text."""
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# Small, deliberately conservative common-word list for a cheap "does this
# look like real language, not decode noise" signal. Not a full dictionary —
# just enough high-frequency English words that random/garbage decode output
# essentially never matches more than a couple by chance.
_COMMON_WORDS = frozenset({
    "the", "and", "for", "are", "you", "that", "this", "with", "from", "have",
    "flag", "key", "password", "secret", "admin", "user", "file", "data",
    "http", "https", "www", "com", "net", "org", "was", "not", "but", "all",
    "can", "her", "his", "one", "our", "out", "day", "get", "has", "him",
    "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy",
    "did", "its", "let", "put", "say", "she", "too", "use", "here", "there",
    "your", "will", "what", "when", "them", "then", "than", "into", "over",
    "some", "more", "would", "could", "should", "hidden", "found", "welcome",
})


def english_word_score(text: str) -> float:
    """
    Fraction of alphabetic 'words' in text that are common English words.
    0.0 for empty/no-word input. Used as a cheap dictionary/language-score
    signal to reject decode candidates that only coincidentally match a
    regex but aren't real language (e.g. XOR noise that happens to contain
    a flag-shaped pattern).
    """
    words = re.findall(r"[A-Za-z]{2,}", text)
    if not words:
        return 0.0
    hits = sum(1 for w in words if w.lower() in _COMMON_WORDS)
    return hits / len(words)


def is_likely_base64(s: str) -> bool:
    """
    Return True only if s looks like intentional Base64, not accidental matches.
    Requires:
      - Length >= 16 (which always decodes to >= 10 bytes, so no separate
        decoded-length check is needed on top of this)
      - Only valid base64 chars
      - Correct padding (or no padding with length % 4 in {0, 2, 3})
      - Decoded bytes are >= 75% printable OR start with a known file magic
        (v4.3: raised from 60% — two independent signals, charset structure
        plus either strong printable ratio or a real magic-byte match, are
        required before this is treated as intentional Base64)
    """
    if len(s) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+=*", s):
        return False
    # Reject all-lowercase or all-uppercase — likely a word, not base64
    if s.lower() == s or s.upper() == s:
        return False
    try:
        import base64
        decoded = base64.b64decode(s + "==")
        printable = sum(1 for b in decoded if 0x20 <= b < 0x7F or b in (9, 10, 13))
        ratio = printable / len(decoded) if decoded else 0
        # Accept if strongly printable OR has known file magic
        MAGIC = [b"\x89PNG", b"\xff\xd8\xff", b"PK\x03", b"BM", b"GIF8", b"fLaC", b"ID3"]
        has_magic = any(decoded.startswith(m) for m in MAGIC)
        return ratio >= 0.75 or has_magic
    except Exception:
        return False
