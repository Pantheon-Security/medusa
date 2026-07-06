"""
Rule lint — detect ReDoS-prone (catastrophic-backtracking) regex patterns.

Two layers:
  - STATIC: cheap structural heuristics (nested quantifiers `(x+)+`, nested
    character sets `[..[..]`) — flags suspects across all 40k rules instantly.
  - CANARY: run a flagged pattern against pathological inputs in a SUBPROCESS
    with a hard timeout + terminate(). This is the only way to time-bound a
    regex stuck in C-level backtracking (the `re` module can't be interrupted
    in-process, and the `regex` module with timeout= is not installed).

Used by `tests/test_rule_redos.py` (ship gate), the `rule-validator` skill, and
a compile-time DEBUG warning in Rule.__post_init__.
"""
import re
from multiprocessing import Process, Queue
from typing import List, Tuple

# A group that contains an inner quantifier AND is itself quantified — the classic
# exponential-backtracking shape. Inner/outer quantifier may be +, *, or a brace
# range {n,}: (a+)+, (.*)*, (\d+)*, and — the GPTs ReDoS — (?:[^\x00-\x7F]{5,}){3,}.
_QUANT = r'(?:[*+]|\{\d+,\d*\})'
_NESTED_QUANT = re.compile(
    r'\((?:\?[:=!>]|\?<[=!])?[^()]*' + _QUANT + r'[^()]*\)\s*' + _QUANT)
# Nested character set [ ... [ ... ] — Python's "Possible nested set" FutureWarning.
_NESTED_SET = re.compile(r'\[[^\]]*\[')


def static_findings(pattern: str) -> List[str]:
    """Cheap structural ReDoS/lint smells in a pattern string (no execution)."""
    out = []
    if _NESTED_QUANT.search(pattern):
        out.append("nested_quantifier")
    if _NESTED_SET.search(pattern):
        out.append("nested_set")
    return out


def _match_worker(pattern: str, text: str, q: Queue) -> None:
    try:
        re.compile(pattern, re.IGNORECASE).search(text)
        q.put("ok")
    except Exception:  # noqa: BLE001 - invalid patterns aren't ReDoS
        q.put("err")


# Pathological inputs: long repetitive runs (which inner quantifiers gobble) with
# a failing terminator (which forces the outer quantifier to backtrack). The
# non-ASCII run (★) is essential — the GPTs ReDoS was a [^\x00-\x7F] class that
# ASCII inputs never triggered.
def _canary_inputs(n: int = 40) -> List[str]:
    return [c * n + "!" for c in ("a", "0", " ", "★", "é")] + ["a1 " * n + "!"]


def is_redos(pattern: str, timeout_ms: int = 120) -> bool:
    """True if `pattern` exceeds the timeout on any pathological input (ReDoS)."""
    for text in _canary_inputs():
        q: Queue = Queue()
        p = Process(target=_match_worker, args=(pattern, text, q))
        p.start()
        p.join(timeout_ms / 1000.0)
        if p.is_alive():
            p.terminate()
            p.join()
            return True
    return False


def lint_pattern(pattern: str, run_canary: bool = True) -> List[str]:
    """Return reasons a single pattern is risky ([] = clean)."""
    reasons = static_findings(pattern)
    if run_canary and is_redos(pattern):
        reasons.append("redos_canary")
    return reasons


def lint_rules(rules, run_canary: bool = True) -> List[Tuple[str, str, List[str]]]:
    """Lint a list of loaded Rule objects.

    Returns (rule_id, pattern, reasons) for every risky pattern. To stay fast
    over 40k rules, the (slow) canary only runs on patterns the static pass
    already flagged.
    """
    findings = []
    for rule in rules:
        for pat in rule.patterns:
            static = static_findings(pat)
            reasons = list(static)
            if run_canary and static and is_redos(pat):
                reasons.append("redos_canary")
            if reasons:
                findings.append((rule.id, pat, reasons))
    return findings


# ---------------------------------------------------------------------------
# PR-015: corpus-quality lint (beyond ReDoS)
#
# Three structural checks that a bad rule can trip at authoring time. Run as a
# pytest gate (tests/test_rule_corpus_lint.py) against a committed baseline of
# grandfathered violations, so the gate blocks only NEW regressions rather than
# forcing a mass-edit of the existing 42k-rule corpus.
#
#   (a) short_literal_alternate — an unanchored alternation branch that is a bare
#       short literal (<MIN_LITERAL chars, no \b, no structure). This is what let
#       `PLA|...` match "temPLAte".
#   (b) harvested_missing_file_types — a harvested-provenance rule with no
#       file_types, so its pattern can fire on every file type.
#   (c) critical_requires_curated — CRITICAL severity self-assigned by a
#       non-curated (harvested/unknown) rule.
# ---------------------------------------------------------------------------

CHECK_SHORT_ALT = "short_literal_alternate"
CHECK_HARVEST_FT = "harvested_missing_file_types"
CHECK_CRIT_PROV = "critical_requires_curated"

# Minimum literal length for an unanchored alternation branch to be considered
# specific enough not to mention-match arbitrary substrings.
MIN_LITERAL = 5

# Anchors / assertions that give a short literal enough matching context.
_HAS_ANCHOR = re.compile(r'\\b|\\B|\\<|\\>|\^|\$|\(\?[=!]|\(\?<[=!]')
# Any regex structure metacharacter — if a branch has one, it is more than a
# bare literal token (char class, group, quantifier, escape, wildcard, …).
_HAS_STRUCTURE = re.compile(r'[\[\](){}\\.*+?]')


def _split_top_alternation(pattern: str) -> List[str]:
    """Split `pattern` on top-level `|` only (not inside (), [], or escaped)."""
    branches: List[str] = []
    cur: List[str] = []
    depth = 0
    in_class = False
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == '\\' and i + 1 < n:
            cur.append(c)
            cur.append(pattern[i + 1])
            i += 2
            continue
        if in_class:
            cur.append(c)
            if c == ']':
                in_class = False
            i += 1
            continue
        if c == '[':
            in_class = True
            cur.append(c)
        elif c == '(':
            depth += 1
            cur.append(c)
        elif c == ')':
            depth = max(0, depth - 1)
            cur.append(c)
        elif c == '|' and depth == 0:
            branches.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    branches.append(''.join(cur))
    return branches


def _iter_group_contents(pattern: str):
    """Yield the inner text of each parenthesized group (group prefix stripped)."""
    stack: List[int] = []
    in_class = False
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == '\\' and i + 1 < n:
            i += 2
            continue
        if in_class:
            if c == ']':
                in_class = False
            i += 1
            continue
        if c == '[':
            in_class = True
        elif c == '(':
            stack.append(i)
        elif c == ')':
            if stack:
                start = stack.pop()
                inner = pattern[start + 1:i]
                # Strip a leading group prefix: (?:  (?i)  (?=  (?<=  (?P<name>  …
                inner = re.sub(r'^\?(P<[^>]+>|<[=!]|[:=!aiLmsux-]+)', '', inner)
                yield inner
        i += 1


def _alternation_branches(pattern: str) -> List[str]:
    """Every alternation branch at the top level and inside every group.

    Only contents that actually contain a top-level `|` (i.e. a real
    alternation of >=2 branches) contribute branches.
    """
    out: List[str] = []
    for content in (pattern, *_iter_group_contents(pattern)):
        branches = _split_top_alternation(content)
        if len(branches) >= 2:
            out.extend(branches)
    return out


def is_short_bare_alternate(branch: str) -> bool:
    """True if `branch` is an unanchored, structure-free literal < MIN_LITERAL.

    Precise by design: a branch is only flagged when it is a plain literal token
    (no anchor/assertion, no char class/group/quantifier/escape/wildcard) whose
    trimmed length is below the minimum. `\\berror\\b`, `\\d{5}`, `foo(?:x|y)`
    and any branch >= MIN_LITERAL literal chars all pass.
    """
    if _HAS_ANCHOR.search(branch):
        return False
    if _HAS_STRUCTURE.search(branch):
        return False
    return len(branch.strip()) < MIN_LITERAL


def corpus_findings(rules) -> List[Tuple[str, str, str]]:
    """Corpus-quality violations across loaded Rule objects.

    Returns (rule_id, check, detail) tuples. `check` is one of the CHECK_*
    constants. At most one finding per (rule, check) is emitted (the first
    offending branch/pattern), so the baseline stays rule-scoped and stable.
    """
    findings: List[Tuple[str, str, str]] = []
    for rule in rules:
        # (a) short bare literal alternation branch
        flagged = None
        for pat in rule.patterns:
            for branch in _alternation_branches(pat):
                if is_short_bare_alternate(branch):
                    flagged = branch.strip()
                    break
            if flagged is not None:
                break
        if flagged is not None:
            findings.append((rule.id, CHECK_SHORT_ALT, flagged))

        provenance = getattr(rule, 'provenance', None)

        # (b) harvested rule must declare file_types
        if provenance == 'harvested' and not getattr(rule, 'file_types', None):
            findings.append((rule.id, CHECK_HARVEST_FT, ''))

        # (c) CRITICAL severity requires curated provenance
        sev = getattr(rule, 'severity', None)
        sev_name = getattr(sev, 'value', sev)
        if str(sev_name).upper() == 'CRITICAL' and provenance != 'curated':
            findings.append((rule.id, CHECK_CRIT_PROV, str(provenance)))

    return findings
