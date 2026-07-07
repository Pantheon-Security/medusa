"""Documentation lint tests for the Review-2 fix pass.

These tests READ the project's Markdown docs (README.md, CLAUDE.md, and the
false-positive guide) and assert the doc-coherence invariants chosen during the
Review-2 reshape. They exercise no application code -- they are a guard against
the specific contradictions and stale snippets that Review-2 flagged.

Run standalone (project disables addopts in CI for this lane):

    python3 -m pytest tests/test_review2_docs.py -q -o addopts=""
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
FP_GUIDE = REPO_ROOT / "docs" / "guides" / "handling-false-positives.md"


def _read(path: Path) -> str:
    assert path.exists(), f"expected doc file missing: {path}"
    return path.read_text(encoding="utf-8")


def _strip_code_fences(text: str) -> str:
    """Return `text` with fenced code blocks removed.

    Fences are triple-backtick delimited (``` ... ```). Anything inside a fence
    is replaced with blank lines so line-based assertions outside fences are
    unaffected by fenced content (e.g. CLI sample output that may contain
    glyphs).
    """
    out = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else line)
    return "\n".join(out)


# Pictographic-emoji code-point ranges. Deliberately EXCLUDES typographic
# punctuation that legitimately appears in prose: em/en dashes, arrows (->),
# the multiplication sign, smart quotes, ellipsis, etc.
_EMOJI_RANGES = (
    (0x1F300, 0x1FAFF),  # Misc symbols & pictographs, emoji, supplemental
    (0x1F000, 0x1F0FF),  # Mahjong / dominoes / playing cards
    (0x2600, 0x26FF),    # Misc symbols (warning sign, etc.)
    (0x2700, 0x27BF),    # Dingbats (check marks, crosses)
    (0x2B00, 0x2BFF),    # Misc symbols & arrows (stars, etc.)
    (0xFE00, 0xFE0F),    # Variation selectors (emoji presentation)
    (0x1F1E6, 0x1F1FF),  # Regional indicator (flags)
)


def _find_emoji(text: str):
    hits = []
    for ch in text:
        cp = ord(ch)
        for lo, hi in _EMOJI_RANGES:
            if lo <= cp <= hi:
                hits.append(ch)
                break
    return hits


# --------------------------------------------------------------------------
# RH-3: init example must not advertise "Missing: NN tools".
# --------------------------------------------------------------------------
def test_readme_no_missing_tools_count():
    import re

    text = _read(README)
    matches = re.findall(r"Missing:\s*\d+\s*tools", text)
    assert not matches, f"README still shows stale 'Missing: NN tools': {matches}"


# --------------------------------------------------------------------------
# RH-5: CLAUDE.md GH Actions/GitLab examples must use real flags, not the
# nonexistent `output-format:` input or a fixed `results.sarif` filename.
# --------------------------------------------------------------------------
def test_claude_md_no_output_format_input():
    text = _read(CLAUDE_MD)
    assert "output-format: sarif" not in text, (
        "CLAUDE.md uses nonexistent 'output-format: sarif' action input"
    )


def test_claude_md_no_results_sarif():
    text = _read(CLAUDE_MD)
    assert "results.sarif" not in text, (
        "CLAUDE.md references fixed 'results.sarif'; real file is medusa-scan-<ts>.sarif"
    )


# --------------------------------------------------------------------------
# RH-7: the --quick option must not claim it "requires git" (it uses the cache).
# --------------------------------------------------------------------------
def test_readme_quick_does_not_require_git():
    text = _read(README)
    for line in text.splitlines():
        if "--quick" in line and "requires git" in line:
            pytest.fail(f"README --quick line wrongly claims 'requires git': {line!r}")


# --------------------------------------------------------------------------
# RH-8: inline suppression must be documented in the FP guide and README.
# --------------------------------------------------------------------------
def test_fp_guide_documents_inline_suppression():
    text = _read(FP_GUIDE)
    assert "medusa:ignore" in text, (
        "FP guide must document the inline 'medusa:ignore' suppression marker"
    )
    # Both comment styles should be shown.
    assert "# medusa:ignore" in text, "FP guide missing Python/shell '# medusa:ignore'"
    assert "// medusa:ignore" in text, "FP guide missing Rust/PHP/JS '// medusa:ignore'"


def test_readme_documents_inline_suppression():
    text = _read(README)
    assert "medusa:ignore" in text, (
        "README FP section must mention the 'medusa:ignore' inline suppression marker"
    )


# --------------------------------------------------------------------------
# RH-2: CVE count must be coherent -- only 265, never the stale 133.
# --------------------------------------------------------------------------
def test_readme_cve_count_is_only_310():
    import re

    text = _read(README)
    # No stale CVE counts anywhere (133 = old CVEMiner, 265 = pre-2026.8.0 count).
    stale = re.findall(r"\b(?:133|265)\s+[A-Za-z ]*CVE", text, flags=re.IGNORECASE)
    assert not stale, f"README still claims a stale CVE count: {stale}"
    # The canonical, measured number (PR-019: rules/cve/ = 310).
    assert "310" in text, "README must state the canonical CVE count (310)"


# --------------------------------------------------------------------------
# RH-2 (analyzers): analyzer count coherent on 79, no stale 78.
# --------------------------------------------------------------------------
def test_readme_analyzer_count_is_79_not_78():
    import re

    text = _read(README)
    stale = re.findall(r"\b78\s+(?:Specialized\s+)?[Aa]nalyzers\b", text)
    assert not stale, f"README still claims 78 analyzers: {stale}"


# --------------------------------------------------------------------------
# RM-4: scan-options table must document the newer flags.
# --------------------------------------------------------------------------
def test_readme_scan_options_documents_new_flags():
    text = _read(README)
    for flag in (
        "--yes",
        "--no-prompt",
        "--trace-rules",
        "--screening",
        "--no-ai-safe",
        "--allow-any-host",
    ):
        assert flag in text, f"README scan-options table missing {flag}"


# --------------------------------------------------------------------------
# RH-2 / Ross requirement: README must be emoji-free OUTSIDE code fences.
# --------------------------------------------------------------------------
def test_readme_has_no_emoji_outside_code_fences():
    text = _strip_code_fences(_read(README))
    hits = _find_emoji(text)
    assert not hits, (
        "README contains emoji outside code fences: "
        + ", ".join(f"U+{ord(c):04X}" for c in hits)
    )


# --------------------------------------------------------------------------
# RL-4: footer must not carry a trailing space.
# --------------------------------------------------------------------------
def test_readme_footer_has_no_trailing_space():
    text = _read(README)
    offenders = [
        ln for ln in text.splitlines()
        if "Multi-Language Security Scanner" in ln and ln != ln.rstrip()
    ]
    assert not offenders, f"README footer has a trailing space: {offenders!r}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q", "-o", "addopts="]))
