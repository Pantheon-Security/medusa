#!/usr/bin/env python3
"""
Shared documentation / quoted-signature context gate for MEDUSA's signature
scanners.

Security-content skills — detection playbooks, agent rosters, rule catalogues —
legitimately *quote* attack strings so a human or an agent can learn to detect
them: ``ignore previous instructions`` inside inline backticks, a markdown table
of example payloads, a fenced example block, or a "patterns to detect" bullet
list. Those are documentation, not live directives — yet a naive signature
scanner reads a quoted signature exactly like an operative instruction, so a
teaching repo (and MEDUSA's own ``medusa-vet`` skill) trips DO_NOT_INSTALL on
pure false positives.

This module answers one question: *does a matched attack string sit in a benign
documentation position, or in the skill's operative body?* Only clearly quoted /
tabled / fenced / catalogued positions are treated as documentation. A directive
in plain instruction prose — the real poisoning vector — is NOT documentation
and is always kept.

Mirrors :mod:`medusa.scanners._ml_context` / :mod:`medusa.scanners._web_context`
in spirit: a conservative gate that removes false positives without punching a
hole in coverage. The guard is deliberately *asymmetric* — when in doubt, treat
a line as operative (keep the finding), because a missed real directive costs
more than a surviving FP.

Security hardening (SigReview CRITICAL — do not relax):
  * A fenced code block is NOT documentation. A markdown fence is a human
    rendering hint, not an LLM trust boundary — models act on fenced directives —
    so suppressing there is a total bypass (wrap the payload in ``` and evade).
    The ``in_code_fence`` parameter is accepted for caller compatibility but is
    intentionally ignored.
  * A quoted/backticked signature only counts as documentation when the line is
    also a structural list item or table row (a detection catalogue) — never in
    plain operative prose that merely contains a backticked phrase.
  * A markdown table row only counts as documentation when it sits under a
    documentation heading — a lone fake table row cannot smuggle a directive.
"""

import re
from typing import Optional, Sequence

# A markdown list item: `-`, `*`, `+`, or `1.` / `1)` bullets.
_LIST_ITEM_RE = re.compile(r'^\s*(?:[-*+]|\d+[.)])\s+')

# Inline code spans (`...`) and single/double-quoted spans ("..." / '...').
_INLINE_CODE_RE = re.compile(r'`([^`]+)`')
_QUOTED_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'')

# Markdown ATX heading: `## Attack patterns`.
_HEADING_RE = re.compile(r'^\s{0,3}#{1,6}\s+(.*)$')
# Bold label used as a pseudo-heading: `**Patterns to detect:**`.
_BOLD_LABEL_RE = re.compile(r'^\s*\*\*(.+?)\*\*\s*:?\s*$')

# Vocabulary that marks a heading / intro line as introducing a catalogue of
# things-to-detect or illustrative examples (i.e. documentation, not orders).
_DOC_VOCAB_RE = re.compile(
    r'(?i)\b(?:'
    r'example|examples|for\s+example|e\.g\.|such\s+as|for\s+instance|'
    r'attack\s+pattern|attack\s+patterns|pattern|patterns|'
    r'signature|signatures|indicator|indicators|'
    r'pitfall|pitfalls|red\s+flag|red\s+flags|'
    r'payload|payloads|sample|samples|'
    r'detect|detection|detecting|screen|screening|'
    r'audit|auditing|look\s+for|looking\s+for|watch\s+for|check\s+for|'
    r'scan\s+for|search\s+for|what\s+to\s+(?:look|watch)\s+for'
    r')\b'
)

# How many preceding lines to scan when looking for an owning doc heading/intro.
_HEADING_WINDOW = 10


def _match_is_quoted(line: str, match_text: str) -> bool:
    """True when ``match_text`` is fully contained inside an inline-code span or a
    quoted span on ``line``. Partial straddling of a delimiter does not count —
    a signature that spills out of its backticks is treated as operative prose.
    """
    if not match_text:
        return False
    for m in _INLINE_CODE_RE.finditer(line):
        if match_text in m.group(1):
            return True
    for m in _QUOTED_RE.finditer(line):
        span = m.group(1) if m.group(1) is not None else m.group(2)
        if span is not None and match_text in span:
            return True
    return False


def _under_doc_heading(preceding_lines: Sequence[str]) -> bool:
    """True when the nearest preceding heading / bold-label / list-intro marks a
    documentation section (examples, patterns-to-detect, an "audit ... for:"
    intro). Scans backwards through ``preceding_lines`` (document order) within a
    bounded window and stops at the first structural marker it finds.
    """
    window = list(preceding_lines)[-_HEADING_WINDOW:]
    for line in reversed(window):
        stripped = line.strip()
        if not stripped:
            continue
        h = _HEADING_RE.match(line)
        if h:
            return bool(_DOC_VOCAB_RE.search(h.group(1)))
        b = _BOLD_LABEL_RE.match(line)
        if b:
            return bool(_DOC_VOCAB_RE.search(b.group(1)))
        # A prose intro line that ends in a colon and names a detect/example verb
        # ("... audit its contents for:", "patterns to detect:") introduces a
        # documentation list of the bullets that follow.
        if stripped.endswith(":") and _DOC_VOCAB_RE.search(stripped):
            return True
        # Table structure rows (header, |---| separator, other data rows) belong to
        # the same table — skip them so the heading ABOVE the table is still found.
        if stripped.startswith("|"):
            continue
        # A non-marker, non-intro line breaks the run — the list is not under a
        # documentation heading.
        return False
    return False


def is_documentation_context(
    line: str,
    preceding_lines: Optional[Sequence[str]] = None,
    *,
    match_text: Optional[str] = None,
    in_code_fence: bool = False,
) -> bool:
    """Classify whether a matched attack string sits in a benign documentation
    position rather than the skill's operative body.

    Returns True (documentation → suppress) when the line is:
      1. a markdown table row (``| ... |``) UNDER a documentation heading, or
      2. a line where ``match_text`` is wrapped in inline backticks/quotes AND the
         line is also a list item or a table row (a detection catalogue), or
      3. a bulleted/numbered list item under a documentation heading / intro
         ("Examples", "Patterns to detect", "... audit its contents for:").

    Returns False (operative → keep) for plain instruction prose — including a
    prose paragraph under a documentation heading, a bare quoted phrase in prose,
    a lone table row with no doc heading, and ANYTHING inside a fenced code block
    (``in_code_fence`` is ignored) — so a live poisoning directive is never
    suppressed just because it is fenced, quoted, or tabled.
    """
    # A fenced code block is NOT a trust boundary — intentionally not suppressed.
    _ = in_code_fence  # accepted for caller compatibility; deliberately ignored

    stripped = line.strip()
    is_table_row = stripped.startswith("|") and stripped.count("|") >= 2
    is_list_item = bool(_LIST_ITEM_RE.match(line))
    under_heading = bool(preceding_lines) and _under_doc_heading(preceding_lines)

    # 1. Markdown table row of examples — only under a documentation heading.
    if is_table_row and under_heading:
        return True

    # 2. Signature in inline backticks/quotes — only in a list item or table row.
    if (is_list_item or is_table_row) and _match_is_quoted(line, match_text or ""):
        return True

    # 3. List item under a documentation heading / intro.
    if is_list_item and under_heading:
        return True

    return False
