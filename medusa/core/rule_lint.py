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

# A group that contains an inner quantifier AND is itself quantified: (a+)+,
# (.*)*, (\d+)*, (?:x*)+ — the classic exponential-backtracking shape.
_NESTED_QUANT = re.compile(r'\((?:\?[:=!>]|\?<[=!])?[^()]*[*+][^()]*\)\s*[*+]')
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
# a failing terminator (which forces the outer quantifier to backtrack).
def _canary_inputs(n: int = 40) -> List[str]:
    return [c * n + "!" for c in ("a", "0", " ")] + ["a1 " * n + "!"]


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
