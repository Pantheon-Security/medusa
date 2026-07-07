"""Gate: MEDUSA CLI output source must be FULLY PLAIN TEXT (no emoji glyphs).

Ross's requirement: the CLI must never print decorative emoji — only Rich
colour markup and ordinary typographic punctuation. This gate scans the two
files that produce user-facing terminal output (`medusa/cli.py` and
`medusa/core/parallel.py`) and fails on ANY emoji, so a regression can't sneak
back in.

It checks two representations so it can't be fooled by escaping:
  1. Literal emoji CHARACTERS in the source text.
  2. Emoji written as ``\\uXXXX`` / ``\\U00XXXXXX`` escape sequences (which
     `parallel.py` historically used behind a `force_ascii` fallback).

Rich colour tags ([green], [bold red], …), arrows (-> ← →), em/en dashes,
middle dots, ellipses and box-drawing/block characters are NOT emoji and are
deliberately outside the ranges below, so they pass untouched.

Run standalone (project disables addopts in CI for this lane):

    python3 -m pytest tests/test_cli_no_emoji.py -q -o addopts=""
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "medusa" / "cli.py"
PARALLEL = REPO_ROOT / "medusa" / "core" / "parallel.py"


# Pictographic-emoji code-point ranges (mirrors tests/test_review2_docs.py).
# Deliberately EXCLUDES typographic punctuation that legitimately appears in
# CLI output: em/en dashes, arrows (U+2190-21FF), box-drawing (U+2500-257F),
# block elements (U+2580-259F), smart quotes, ellipsis, etc.
_EMOJI_RANGES = (
    (0x1F300, 0x1FAFF),  # Misc symbols & pictographs, emoji, supplemental
    (0x1F000, 0x1F0FF),  # Mahjong / dominoes / playing cards
    (0x2600, 0x26FF),    # Misc symbols (warning sign, gear, etc.)
    (0x2700, 0x27BF),    # Dingbats (check marks, crosses)
    (0x2B00, 0x2BFF),    # Misc symbols & arrows (stars, etc.)
    (0xFE00, 0xFE0F),    # Variation selectors (emoji presentation)
    (0x1F1E6, 0x1F1FF),  # Regional indicator (flags)
)

_ESCAPE_RE = re.compile(r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})")


def _in_emoji_range(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


def _find_literal_emoji(text: str):
    """Emoji present as actual characters in the source."""
    return [ch for ch in text if _in_emoji_range(ord(ch))]


def _find_escaped_emoji(text: str):
    """Emoji written as \\uXXXX / \\U00XXXXXX escapes in the source."""
    hits = []
    for m in _ESCAPE_RE.finditer(text):
        cp = int(m.group(1) or m.group(2), 16)
        if _in_emoji_range(cp):
            hits.append(chr(cp))
    return hits


def _read(path: Path) -> str:
    assert path.exists(), f"expected source file missing: {path}"
    return path.read_text(encoding="utf-8")


def test_cli_py_has_no_literal_emoji():
    hits = _find_literal_emoji(_read(CLI))
    assert not hits, (
        "medusa/cli.py contains literal emoji glyph(s): "
        + ", ".join(f"U+{ord(c):04X}" for c in hits)
    )


def test_cli_py_has_no_escaped_emoji():
    hits = _find_escaped_emoji(_read(CLI))
    assert not hits, (
        "medusa/cli.py contains \\u/\\U-escaped emoji: "
        + ", ".join(f"U+{ord(c):04X}" for c in hits)
    )


def test_parallel_py_has_no_literal_emoji():
    hits = _find_literal_emoji(_read(PARALLEL))
    assert not hits, (
        "medusa/core/parallel.py contains literal emoji glyph(s): "
        + ", ".join(f"U+{ord(c):04X}" for c in hits)
    )


def test_parallel_py_has_no_escaped_emoji():
    hits = _find_escaped_emoji(_read(PARALLEL))
    assert not hits, (
        "medusa/core/parallel.py contains \\u/\\U-escaped emoji: "
        + ", ".join(f"U+{ord(c):04X}" for c in hits)
    )


if __name__ == "__main__":  # pragma: no cover
    import pytest

    raise SystemExit(pytest.main([__file__, "-q", "-o", "addopts="]))
