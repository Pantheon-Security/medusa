"""Shared obfuscation-normalization for manifest/prose scanners.

Manifest vetters (SKILL.md, mcp.json) match natural-language directives that an
attacker will try to hide behind Unicode tricks: zero-width joiners, bidi
overrides, the invisible Tag block, NFKC-decomposable lookalikes, and
Cyrillic/Greek homoglyphs. This module centralizes that normalization so the
SKILL and MCP scanners share one definition instead of drifting apart.

Only genuinely invisible / control characters trigger `has_invisible` — accented
letters and emoji are ordinary text and must never be flagged.
"""

import re
import unicodedata

# Zero-width, bidi, word-joiner, invisible-operator, Tag block, soft-hyphen,
# Mongolian vowel separator, BOM. These carry no visible glyph and are used to
# smuggle or split hidden instructions.
_INVISIBLE_RE = re.compile(
    "["
    "­"              # soft hyphen
    "᠎"             # Mongolian vowel separator
    "​-‏"      # zero-width space/joiners + bidi marks
    "‪-‮"      # bidi embeddings / overrides
    "⁠-⁤"      # word joiner + invisible operators
    "⁦-⁩"      # bidi isolates
    "﻿"             # BOM / zero-width no-break space
    "]"
    "|[\U000e0000-\U000e007f]"   # Unicode Tag block
)

# Cyrillic / Greek lookalikes commonly used to disguise ASCII directive words.
_HOMOGLYPH = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ϲ": "c", "ο": "o", "ν": "v",
}


def has_invisible(text: str) -> bool:
    """True if the text contains any zero-width/bidi/invisible control char."""
    return bool(_INVISIBLE_RE.search(text or ""))


def normalize(text: str) -> str:
    """NFKC-fold, strip invisibles, map common Cyrillic/Greek homoglyphs to ASCII."""
    t = unicodedata.normalize("NFKC", text or "")
    t = _INVISIBLE_RE.sub("", t)
    return "".join(_HOMOGLYPH.get(c, c) for c in t)


def whitespace_flatten(text: str) -> str:
    """Collapse ALL runs of whitespace (incl. newlines) to single spaces."""
    return re.sub(r"\s+", " ", text or "")
