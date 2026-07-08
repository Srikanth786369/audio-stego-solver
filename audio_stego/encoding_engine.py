"""
Encoding/decoding engine for Audio Stego Solver (Phase 8).

Single source of truth for every supported text/byte encoding scheme used
across the project. Reuses existing cipher primitives from findings.py and
the base58 plugin rather than re-implementing them — this module fills in
the schemes nothing else in the codebase already provides.

Provides:
  - One `decode_<scheme>()` function per scheme, each returning the decoded
    text/bytes on success or None on failure (never raises).
  - `decode_all(text)` — try every scheme against one string, keeping only
    plausible results (a `Finding`-free heuristic; callers decide what to do
    with a hit).
  - `recursive_decode(text, max_depth)` — chain decodes (e.g. a base64 blob
    that decodes to hex that decodes to a ROT13'd flag), bounded by depth
    and by not re-processing a value already seen.

Deliberately NOT implemented: automatic Vigenère key recovery (frequency
analysis to guess the key) and blind XOR-with-arbitrary-length-key. Both are
open research problems with a real risk of confidently-wrong output; keyed
Vigenère decoding is provided instead. This is a documented scope choice, not
an oversight.
"""

from __future__ import annotations

import base64
import binascii
import json
import quopri
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import unquote as _url_unquote

from .findings import atbash, caesar, looks_like_flag, rot13

# ---------------------------------------------------------------------------
# Plausibility heuristics
# ---------------------------------------------------------------------------

def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return ok / len(s)


def plausible(s: Optional[str], min_ratio: float = 0.85, min_len: int = 2) -> bool:
    return bool(s) and len(s) >= min_len and _printable_ratio(s) >= min_ratio


@dataclass
class DecodeResult:
    scheme: str
    output: str
    reason: str = ""


# ---------------------------------------------------------------------------
# Base-N family
# ---------------------------------------------------------------------------

def decode_base16(text: str) -> Optional[str]:
    try:
        cleaned = text.strip()
        if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned) or len(cleaned) % 2:
            return None
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base32(text: str) -> Optional[str]:
    try:
        s = text.strip().upper()
        pad = (-len(s)) % 8
        return base64.b32decode(s + "=" * pad, casefold=True).decode("utf-8", errors="replace")
    except Exception:
        return None


_BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_BASE45_INDEX = {c: i for i, c in enumerate(_BASE45_ALPHABET)}


def decode_base45(text: str) -> Optional[str]:
    """RFC 9285 Base45 decoding."""
    s = text.strip()
    if not s or any(c not in _BASE45_INDEX for c in s):
        return None
    try:
        out = bytearray()
        i = 0
        n = len(s)
        while i < n:
            remaining = n - i
            if remaining >= 3:
                c = (_BASE45_INDEX[s[i]] + _BASE45_INDEX[s[i + 1]] * 45
                     + _BASE45_INDEX[s[i + 2]] * 45 * 45)
                if c > 0xFFFF:
                    return None
                out.append(c // 256)
                out.append(c % 256)
                i += 3
            elif remaining == 2:
                c = _BASE45_INDEX[s[i]] + _BASE45_INDEX[s[i + 1]] * 45
                if c > 0xFF:
                    return None
                out.append(c)
                i += 2
            else:
                return None   # a single leftover char is invalid Base45
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base58(text: str) -> Optional[str]:
    try:
        from .plugins.base58_plugin import _b58decode   # single source of truth
        return _b58decode(text.strip()).decode("utf-8", errors="replace")
    except Exception:
        return None


_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_INDEX = {c: i for i, c in enumerate(_BASE62_ALPHABET)}


def decode_base62(text: str) -> Optional[str]:
    s = text.strip()
    if not s or any(c not in _BASE62_INDEX for c in s):
        return None
    try:
        num = 0
        for ch in s:
            num = num * 62 + _BASE62_INDEX[ch]
        out = bytearray()
        while num > 0:
            out.append(num % 256)
            num //= 256
        return bytes(reversed(out)).decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base64(text: str) -> Optional[str]:
    try:
        s = text.strip()
        pad = (-len(s)) % 4
        return base64.b64decode(s + "=" * pad).decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_base85(text: str) -> Optional[str]:
    """Python's base64.b85decode — the git/Mercurial/RFC-1924-derived variant."""
    try:
        return base64.b85decode(text.strip()).decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_ascii85(text: str) -> Optional[str]:
    try:
        return base64.a85decode(text.strip()).decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_binary(text: str) -> Optional[str]:
    try:
        bits = re.sub(r"\s", "", text)
        if not bits or len(bits) % 8 or any(c not in "01" for c in bits):
            return None
        return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    except Exception:
        return None


def decode_octal(text: str) -> Optional[str]:
    try:
        groups = text.split()
        if not groups or not all(re.fullmatch(r"[0-7]{1,3}", g) for g in groups):
            return None
        return "".join(chr(int(g, 8)) for g in groups)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Classical ciphers
# ---------------------------------------------------------------------------

def decode_rot13(text: str) -> Optional[str]:
    return rot13(text)


def decode_caesar(text: str, shift: int) -> Optional[str]:
    return caesar(text, shift)


def decode_atbash(text: str) -> Optional[str]:
    return atbash(text)


_AFFINE_VALID_A = [a for a in range(1, 26) if __import__("math").gcd(a, 26) == 1]


def _mod_inverse(a: int, m: int) -> Optional[int]:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def decode_affine(text: str, a: int, b: int) -> Optional[str]:
    """Affine cipher decode: D(y) = a_inv * (y - b) mod 26."""
    a_inv = _mod_inverse(a, 26)
    if a_inv is None:
        return None
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((a_inv * (ord(c) - ord("a") - b)) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((a_inv * (ord(c) - ord("A") - b)) % 26 + ord("A")))
        else:
            out.append(c)
    return "".join(out)


def decode_affine_bruteforce(text: str) -> List[DecodeResult]:
    """
    Try every valid (a, b) pair. Gated on looks_like_flag(), NOT plausible():
    shifting/permuting letters keeps the output printable no matter which of
    the 312 (a, b) combinations is tried, so a printability check alone lets
    almost every combination through — this was found to cause a
    combinatorial explosion in recursive_decode() (25-letter-shift-style
    ciphers all "pass", multiplying the search frontier every depth).
    Matches the existing project convention in flags.py's cipher analysis.
    """
    hits = []
    for a in _AFFINE_VALID_A:
        for b in range(26):
            out = decode_affine(text, a, b)
            if out and out != text and looks_like_flag(out):
                hits.append(DecodeResult("affine", out, f"a={a}, b={b}"))
    return hits


def decode_vigenere(text: str, key: str) -> Optional[str]:
    """
    Keyed Vigenère decode. Automatic key recovery (frequency analysis) is
    intentionally not implemented — it is a much larger, uncertain problem;
    this is only useful when a candidate key is already known (e.g. found in
    metadata or another decoded artifact).
    """
    if not key or not key.isalpha():
        return None
    key = key.lower()
    out = []
    ki = 0
    for c in text:
        if "a" <= c <= "z":
            shift = ord(key[ki % len(key)]) - ord("a")
            out.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
            ki += 1
        elif "A" <= c <= "Z":
            shift = ord(key[ki % len(key)]) - ord("a")
            out.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def decode_rail_fence(text: str, rails: int) -> Optional[str]:
    """Standard zig-zag rail fence decode for a given rail count."""
    if rails < 2 or rails >= max(len(text), 2):
        return None
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    if not pattern:
        return None
    row_of_index = [pattern[i % len(pattern)] for i in range(len(text))]
    order = sorted(range(len(text)), key=lambda i: (row_of_index[i], i))
    result = [""] * len(text)
    for slot, orig_i in enumerate(order):
        result[orig_i] = text[slot]
    return "".join(result)


def decode_rail_fence_bruteforce(text: str, max_rails: int = 10) -> List[DecodeResult]:
    """Gated on looks_like_flag() for the same reason as decode_affine_bruteforce:
    a transposition cipher never changes which characters appear, only their
    order, so a printability check can never reject a wrong rail count."""
    hits = []
    for rails in range(2, min(max_rails, len(text)) + 1):
        out = decode_rail_fence(text, rails)
        if out and looks_like_flag(out):
            hits.append(DecodeResult("rail_fence", out, f"rails={rails}"))
    return hits


_BACON_24 = {  # classic 24-letter table (I/J and U/V share a code)
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z",
}


def decode_bacon(text: str) -> Optional[str]:
    """
    Baconian cipher decode. Accepts A/B groups of 5 directly, or the common
    stego-friendly variants using two distinguishable characters (0/1,
    upper/lower) — caller is expected to normalize those to A/B first.
    """
    cleaned = re.sub(r"[^AB]", "", text.upper())
    if len(cleaned) < 5 or len(cleaned) % 5:
        return None
    out = []
    for i in range(0, len(cleaned), 5):
        group = cleaned[i:i + 5]
        letter = _BACON_24.get(group)
        if letter is None:
            return None
        out.append(letter)
    return "".join(out)


_BRAILLE_MAP = {
    "⠁": "a", "⠃": "b", "⠉": "c", "⠙": "d", "⠑": "e", "⠋": "f", "⠛": "g",
    "⠓": "h", "⠊": "i", "⠚": "j", "⠅": "k", "⠇": "l", "⠍": "m", "⠝": "n",
    "⠕": "o", "⠏": "p", "⠟": "q", "⠗": "r", "⠎": "s", "⠞": "t", "⠥": "u",
    "⠧": "v", "⠺": "w", "⠭": "x", "⠽": "y", "⠵": "z", "⠀": " ",
}


def decode_braille(text: str) -> Optional[str]:
    if not text or not any(ch in _BRAILLE_MAP for ch in text):
        return None
    out = []
    for ch in text:
        mapped = _BRAILLE_MAP.get(ch)
        if mapped is None:
            return None
        out.append(mapped)
    return "".join(out)


_MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def decode_morse_text(text: str) -> Optional[str]:
    """Decode textual Morse (dots/dashes separated by spaces, '/' between
    words) — independent of digital.py's audio-domain Morse detection."""
    s = text.strip()
    if not s or not re.fullmatch(r"[.\-/ ]+", s):
        return None
    words = s.split("/")
    out_words = []
    for word in words:
        letters = [_MORSE_MAP.get(tok) for tok in word.split()]
        if any(l is None for l in letters):
            return None
        out_words.append("".join(letters))
    result = " ".join(out_words)
    return result if result else None


def decode_jwt(token: str) -> Optional[dict]:
    """Decode (not verify — no signature key available) a JWT's header+payload."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        def _b64url(seg: str) -> dict:
            pad = (-len(seg)) % 4
            return json.loads(base64.urlsafe_b64decode(seg + "=" * pad))
        return {"header": _b64url(parts[0]), "payload": _b64url(parts[1])}
    except Exception:
        return None


def decode_url(text: str) -> Optional[str]:
    try:
        out = _url_unquote(text)
        return out if out != text else None
    except Exception:
        return None


def decode_quoted_printable(text: str) -> Optional[str]:
    try:
        return quopri.decodestring(text.encode("ascii", errors="ignore")).decode(
            "utf-8", errors="replace")
    except Exception:
        return None


def decode_uuencode(text: str) -> Optional[str]:
    """
    Standard uuencode: an optional 'begin MODE NAME' header, data lines each
    prefixed by a length character, terminated by a blank/'`' line and 'end'.
    Uses binascii.a2b_uu per line (not the deprecated/removed `uu` module).
    """
    lines = [l for l in text.splitlines() if l.strip()]
    lines = [l for l in lines if not l.startswith("begin ") and l.strip() != "end"]
    if not lines:
        return None
    out = bytearray()
    try:
        for line in lines:
            if line.strip() in ("`", "`\n"):
                continue
            out += binascii.a2b_uu(line)
        return out.decode("utf-8", errors="replace") if out else None
    except Exception:
        return None


_XX_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_XX_INDEX = {c: i for i, c in enumerate(_XX_ALPHABET)}


def decode_xxencode(text: str) -> Optional[str]:
    """
    XXencode: same structural scheme as uuencode (length char + 4-char groups
    encoding 3 bytes via 6-bit values) but with its own 64-character alphabet.
    No stdlib support exists for this format, so it's fully hand-rolled here.
    """
    lines = [l for l in text.splitlines() if l.strip()]
    lines = [l for l in lines if not l.startswith("begin ") and l.strip() != "end"]
    if not lines:
        return None
    out = bytearray()
    try:
        for line in lines:
            if not line or line[0] not in _XX_INDEX:
                continue
            n = _XX_INDEX[line[0]]
            if n == 0:
                continue
            body = line[1:]
            chunk_bytes = bytearray()
            for i in range(0, len(body) - (len(body) % 4 or 4) + 1, 4):
                group = body[i:i + 4]
                if len(group) < 4 or any(c not in _XX_INDEX for c in group):
                    break
                vals = [_XX_INDEX[c] for c in group]
                b0 = (vals[0] << 2) | (vals[1] >> 4)
                b1 = ((vals[1] & 0x0F) << 4) | (vals[2] >> 2)
                b2 = ((vals[2] & 0x03) << 6) | vals[3]
                chunk_bytes += bytes([b0, b1, b2])
            out += chunk_bytes[:n]
        return out.decode("utf-8", errors="replace") if out else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# Content-transforming schemes: decoding garbage through these usually
# produces non-printable noise, so a plausibility (printable-ratio) filter
# is a meaningful, self-limiting gate.
_BLIND_SCHEMES: List[tuple] = [
    ("base64", decode_base64),
    ("base32", decode_base32),
    ("base45", decode_base45),
    ("base58", decode_base58),
    ("base62", decode_base62),
    ("base85", decode_base85),
    ("ascii85", decode_ascii85),
    ("base16/hex", decode_base16),
    ("binary", decode_binary),
    ("octal", decode_octal),
    ("url", decode_url),
    ("quoted_printable", decode_quoted_printable),
    ("morse", decode_morse_text),
    ("braille", decode_braille),
    ("bacon", decode_bacon),
    ("uuencode", decode_uuencode),
    ("xxencode", decode_xxencode),
]

# Substitution/transposition schemes: these only rearrange or remap letters,
# so the output is *always* printable regardless of whether the guess was
# right — a plausibility filter can never reject a wrong guess here. Must be
# gated on looks_like_flag() instead, or every one of 1 (rot13/atbash) to 312
# (affine) candidates "passes," which caused a combinatorial explosion in
# recursive_decode() before this fix.
_SUBSTITUTION_SCHEMES: List[tuple] = [
    ("rot13", lambda t: decode_rot13(t)),
    ("atbash", lambda t: decode_atbash(t)),
]


def decode_all(text: str) -> List[DecodeResult]:
    """Try every scheme that doesn't need an extra parameter; keep plausible hits."""
    text = text.strip()
    if not text:
        return []
    hits: List[DecodeResult] = []
    for name, fn in _BLIND_SCHEMES:
        try:
            out = fn(text)
        except Exception:
            out = None
        if out and out != text and plausible(out):
            hits.append(DecodeResult(name, out))
    for name, fn in _SUBSTITUTION_SCHEMES:
        out = fn(text)
        if out and out != text and looks_like_flag(out):
            hits.append(DecodeResult(name, out))
    for shift in range(1, 26):
        out = decode_caesar(text, shift)
        if out and looks_like_flag(out):
            hits.append(DecodeResult("caesar", out, f"shift={shift}"))
    hits.extend(decode_affine_bruteforce(text))
    hits.extend(decode_rail_fence_bruteforce(text))
    return hits


_MAX_RECURSIVE_HITS = 200        # hard cap regardless of any single gate's behavior
_MAX_FRONTIER_WIDTH = 25         # cap candidates carried into the next depth


def recursive_decode(text: str, max_depth: int = 5) -> List[DecodeResult]:
    """
    Chain decodes: e.g. a base64 blob that decodes to hex that decodes to a
    ROT13'd flag. Bounded by max_depth, by never re-processing a value already
    produced (prevents cycles like rot13(rot13(x)) == x looping), and by two
    hard caps (_MAX_RECURSIVE_HITS, _MAX_FRONTIER_WIDTH) kept as defense in
    depth after a combinatorial explosion was found here in testing: a loose
    plausibility filter on substitution ciphers let ~300 wrong guesses per
    string through, multiplying every recursion level. Individual decoders
    are now gated correctly (see _SUBSTITUTION_SCHEMES), but these caps stay
    as a backstop against the next scheme added without the same care.
    """
    all_hits: List[DecodeResult] = []
    seen: set = {text.strip()}
    frontier = [text]
    depth = 0
    while frontier and depth < max_depth and len(all_hits) < _MAX_RECURSIVE_HITS:
        next_frontier: List[str] = []
        for candidate in frontier:
            for hit in decode_all(candidate):
                if hit.output in seen:
                    continue
                seen.add(hit.output)
                all_hits.append(hit)
                next_frontier.append(hit.output)
                if len(all_hits) >= _MAX_RECURSIVE_HITS:
                    break
            if len(all_hits) >= _MAX_RECURSIVE_HITS:
                break
        frontier = next_frontier[:_MAX_FRONTIER_WIDTH]
        depth += 1
    return all_hits
