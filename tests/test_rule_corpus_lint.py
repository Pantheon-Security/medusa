"""PR-015: corpus-quality lint gate.

Two layers:
  - fast synthetic unit tests pin the three checks (short bare alternate,
    harvested-without-file_types, CRITICAL-without-curated) and the baseline
    grandfathering behavior;
  - a @pytest.mark.slow full-corpus regression loads all ~42k rules and asserts
    NO new violation appears outside the committed baseline
    (tests/rule_lint_baseline.json).

The slow test is what blocks a new bad rule from shipping; the baseline lets the
existing corpus through unchanged (mass-editing 42k rules is explicitly out of
scope for this gate).
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from medusa.core import rule_lint
from medusa.core.rule_lint import (
    CHECK_CRIT_PROV,
    CHECK_HARVEST_FT,
    CHECK_SHORT_ALT,
    corpus_findings,
    is_short_bare_alternate,
)

BASELINE_PATH = Path(__file__).parent / "rule_lint_baseline.json"


def _rule(rid, patterns, provenance='curated', file_types=None, severity='MEDIUM'):
    """Minimal Rule stand-in with just the attributes corpus_findings reads."""
    return SimpleNamespace(
        id=rid,
        patterns=patterns if isinstance(patterns, list) else [patterns],
        provenance=provenance,
        file_types=file_types or [],
        severity=SimpleNamespace(value=severity),
    )


def _checks_for(rule):
    return {check for _rid, check, _d in corpus_findings([rule])}


# ---- (a) short bare literal alternate ------------------------------------

def test_short_bare_alternate_is_flagged():
    # `PLA` matches "temPLAte" — the motivating FP.
    rule = _rule('A-1', [r'(?:PLA|jailbreak|exfiltrate)'])
    assert CHECK_SHORT_ALT in _checks_for(rule)


def test_top_level_short_alternate_is_flagged():
    assert is_short_bare_alternate('PLA') is True
    assert CHECK_SHORT_ALT in _checks_for(_rule('A-2', [r'PLA|template']))


def test_word_boundary_alternate_is_clean():
    # \b anchor gives the short token matching context.
    rule = _rule('A-3', [r'(?:\bPLA\b|\bDAN\b)'])
    assert CHECK_SHORT_ALT not in _checks_for(rule)


def test_long_literal_alternate_is_clean():
    rule = _rule('A-4', [r'(?:jailbreak|exfiltrate|poison)'])
    assert CHECK_SHORT_ALT not in _checks_for(rule)


def test_structured_short_branch_is_clean():
    # A branch with regex structure (char class / quantifier) is not a bare token.
    rule = _rule('A-5', [r'(?:\d{3}|API_KEY)'])
    assert CHECK_SHORT_ALT not in _checks_for(rule)


def test_single_non_alternation_pattern_not_flagged_as_short_alt():
    # No top-level `|` anywhere -> no alternation branches to check.
    rule = _rule('A-6', [r'os'])
    assert CHECK_SHORT_ALT not in _checks_for(rule)


def test_nested_group_alternation_is_reached():
    rule = _rule('A-7', [r'password\s*=\s*(?:foo|os|value)'])
    assert CHECK_SHORT_ALT in _checks_for(rule)   # `os` branch inside the group


# ---- (b) harvested rules must declare file_types -------------------------

def test_harvested_without_file_types_is_flagged():
    rule = _rule('B-1', [r'(?:jailbreak|exfiltrate)'], provenance='harvested',
                 file_types=[])
    assert CHECK_HARVEST_FT in _checks_for(rule)


def test_harvested_with_file_types_is_clean():
    rule = _rule('B-2', [r'(?:jailbreak|exfiltrate)'], provenance='harvested',
                 file_types=['*.py'])
    assert CHECK_HARVEST_FT not in _checks_for(rule)


def test_curated_without_file_types_is_clean():
    rule = _rule('B-3', [r'(?:jailbreak|exfiltrate)'], provenance='curated',
                 file_types=[])
    assert CHECK_HARVEST_FT not in _checks_for(rule)


# ---- (c) CRITICAL requires curated provenance ----------------------------

def test_harvested_critical_is_flagged():
    rule = _rule('C-1', [r'(?:jailbreak|exfiltrate)'], provenance='harvested',
                 file_types=['*.py'], severity='CRITICAL')
    assert CHECK_CRIT_PROV in _checks_for(rule)


def test_curated_critical_is_clean():
    rule = _rule('C-2', [r'(?:jailbreak|exfiltrate)'], provenance='curated',
                 severity='CRITICAL')
    assert CHECK_CRIT_PROV not in _checks_for(rule)


def test_unknown_provenance_critical_is_flagged():
    rule = _rule('C-3', [r'(?:jailbreak|exfiltrate)'], provenance=None,
                 severity='CRITICAL')
    assert CHECK_CRIT_PROV in _checks_for(rule)


# ---- clean rule + baseline grandfathering --------------------------------

def test_fully_clean_rule_has_no_findings():
    rule = _rule('CLEAN-1', [r'(?:jailbreak|exfiltrate)'], provenance='curated',
                 file_types=['*.py'], severity='HIGH')
    assert _checks_for(rule) == set()


def test_grandfathered_id_in_baseline_does_not_fail_gate():
    baseline = _load_baseline()
    # A rule grandfathered for the short-alt check must not count as a NEW
    # violation for that check (grandfathering is per (check, rule_id)).
    grandfathered_id = baseline[CHECK_SHORT_ALT][0]
    rule = _rule(grandfathered_id, [r'PLA|x'], provenance='curated',
                 file_types=['*.py'], severity='HIGH')
    findings = corpus_findings([rule])
    assert {c for _r, c, _d in findings} == {CHECK_SHORT_ALT}  # only the grandfathered check
    new = _new_violations(findings, baseline)
    assert new == [], f"grandfathered id should not fail: {new}"


def test_new_violation_not_in_baseline_fails_gate():
    baseline = _load_baseline()
    rule = _rule('DEFINITELY-NOT-IN-BASELINE-XYZ', [r'PLA|x'])
    findings = corpus_findings([rule])
    new = _new_violations(findings, baseline)
    assert ('DEFINITELY-NOT-IN-BASELINE-XYZ', CHECK_SHORT_ALT) in new


# ---- helpers -------------------------------------------------------------

def _load_baseline():
    with BASELINE_PATH.open() as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith('_')}


def _new_violations(findings, baseline):
    """(rule_id, check) pairs not grandfathered by the baseline."""
    grandfathered = {(check, rid) for check, ids in baseline.items() for rid in ids}
    new = []
    for rule_id, check, _detail in findings:
        if (check, rule_id) not in grandfathered:
            new.append((rule_id, check))
    return sorted(set(new))


# ---- full-corpus regression (the actual ship gate) -----------------------

@pytest.mark.slow
def test_full_corpus_has_no_new_violations():
    """Load all rules; assert every corpus-lint violation is grandfathered.

    Slow (loads ~42k rules). A NEW rule tripping any check fails here with the
    offending (rule_id, check) pairs — fix the rule or, for a deliberate corpus
    change, regenerate the baseline via tests/gen_rule_lint_baseline.py.
    """
    from medusa.rules import RuleLoader

    assert BASELINE_PATH.exists(), (
        "rule_lint_baseline.json missing — regenerate via "
        "tests/gen_rule_lint_baseline.py and commit it")
    baseline = _load_baseline()
    rules = RuleLoader().load_all_rules()
    findings = corpus_findings(rules)
    new = _new_violations(findings, baseline)
    assert new == [], (
        f"{len(new)} NEW corpus-lint violation(s) not in baseline (showing 20): "
        f"{new[:20]}\nFix the rule(s) or regenerate the baseline if intentional.")
