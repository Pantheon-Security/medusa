#!/usr/bin/env python3
"""
Tests for the rule ReDoS lint (medusa.core.rule_lint).

Proves the static detector catches catastrophic-backtracking shapes and stays
quiet on safe patterns, and that the subprocess canary time-bounds a genuinely
catastrophic regex (terminating it rather than hanging the test).
"""
import pytest

from medusa.core import rule_lint


# ── static detector ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(.*)*x", r"(?:\d+)+", r"(\w+)*!"])
def test_static_flags_nested_quantifier(pattern):
    assert "nested_quantifier" in rule_lint.static_findings(pattern)


@pytest.mark.parametrize("pattern", [
    r"(?:[^\x00-\x7F]{5,}){3,}",     # the real GPTs ReDoS shape (brace-nested)
    r"(?:\w{2,}){4,}",
    r"(a{1,3})+",
])
def test_static_flags_brace_nested_quantifier(pattern):
    # Brace-range quantifiers {n,} nest just as dangerously as +/* — the GPTs
    # hang was (?:[^\x00-\x7F]{5,}){3,} and the original detector missed it.
    assert "nested_quantifier" in rule_lint.static_findings(pattern)


def test_gpts_redos_rule_stays_fixed():
    # Regression: MEDUSA-PIA-SCAN-077 hung the scanner on GPTs/(A.I. Bestie).md.
    # Every shipped pattern of that rule must be free of nested quantifiers.
    from medusa.rules import get_loader
    rule = next(r for r in get_loader().load_all_rules() if r.id == "MEDUSA-PIA-SCAN-077")
    for pat in rule.patterns:
        assert "nested_quantifier" not in rule_lint.static_findings(pat), pat


def test_static_flags_nested_set():
    assert "nested_set" in rule_lint.static_findings(r"[a-z[0-9]]")


@pytest.mark.parametrize("pattern", [
    r"\bDAN\b",
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b",
    r"developer\s+mode\s+output",
])
def test_static_clean_on_safe_patterns(pattern):
    assert rule_lint.static_findings(pattern) == []


# ── subprocess canary ────────────────────────────────────────────────────────
def test_canary_terminates_catastrophic_pattern():
    # (a+)+$ on a long non-matching run is exponential; the canary must TIME IT
    # OUT (return True) by terminating the subprocess — not hang this test.
    assert rule_lint.is_redos(r"(a+)+$", timeout_ms=200) is True


def test_canary_clean_on_linear_pattern():
    assert rule_lint.is_redos(r"ignore\s+previous\s+instructions", timeout_ms=400) is False
