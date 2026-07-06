"""PR-014: pipeline_confidence / fp_guards are loaded and compose with the PR-013
provenance gate.

The harvest pipeline emits `pipeline_confidence` and `fp_guards` on each rule; the
loader used to discard both. These tests pin that:
  - both fields are parsed onto the Rule object,
  - a low-confidence rule is screening-only (gated in a default scan, active in
    screening) EVEN when its provenance is curated — confidence composes with,
    rather than depends on, provenance,
  - a high/missing-confidence curated rule always runs,
  - missing confidence is NEUTRAL (never invented).
"""
from types import SimpleNamespace

from medusa.rules import RuleLoader, RuleSeverity, is_screening_only
from medusa.scanners.base import RuleBasedScanner


def _parse(data, default_provenance='harvested'):
    return RuleLoader()._parse_rule(data, default_provenance=default_provenance)


def _gate(screening, all_rules, rules):
    fake = SimpleNamespace(_screening=screening, _all_rules_override=all_rules,
                           _provenance_cache=None)
    return RuleBasedScanner._gate_provenance(fake, rules)


# ---- parsing -------------------------------------------------------------

def test_pipeline_confidence_and_fp_guards_are_loaded():
    rule = _parse({
        'id': 'T-1', 'patterns': [r'\bfoobar\b'], 'severity': 'MEDIUM',
        'pipeline_confidence': 'low',
        'fp_guards': ['import foobar as fb', 'foobar = benign()'],
    })
    assert rule.pipeline_confidence == 'low'
    assert rule.fp_guards == ['import foobar as fb', 'foobar = benign()']


def test_missing_confidence_is_neutral_not_invented():
    rule = _parse({'id': 'T-2', 'patterns': [r'\bfoobar\b']})
    assert rule.pipeline_confidence is None       # never inferred
    assert rule.fp_guards == []
    # Isolate confidence from provenance: a curated file with no confidence field
    # must NOT be gated (missing = neutral).
    curated = _parse({'id': 'T-2c', 'patterns': [r'\bfoobar\b']},
                     default_provenance='curated')
    assert curated.pipeline_confidence is None
    assert is_screening_only(curated) is False


def test_fp_guards_scalar_is_coerced_to_list():
    rule = _parse({'id': 'T-3', 'patterns': [r'x'], 'fp_guards': 'single guard'})
    assert rule.fp_guards == ['single guard']


# ---- gate composition (PR-014 x PR-013) ----------------------------------

def test_low_confidence_curated_rule_is_screening_only():
    """Confidence composes with provenance: a CURATED but low-confidence rule is
    still gated out of a default scan (screening-only)."""
    rule = _parse({'id': 'T-4', 'patterns': [r'\bfoobar\b'],
                   'pipeline_confidence': 'low'}, default_provenance='curated')
    assert rule.provenance == 'curated'
    assert is_screening_only(rule) is True

    # gated in normal mode, active in screening
    assert _gate(False, False, [rule]) == []
    assert _gate(True, False, [rule]) == [rule]
    assert _gate(False, True, [rule]) == [rule]   # --all-rules escape hatch


def test_high_confidence_curated_rule_always_runs():
    rule = _parse({'id': 'T-5', 'patterns': [r'\bfoobar\b'],
                   'pipeline_confidence': 'high'}, default_provenance='curated')
    assert is_screening_only(rule) is False
    assert _gate(False, False, [rule]) == [rule]
    assert _gate(True, False, [rule]) == [rule]


def test_missing_confidence_curated_rule_always_runs():
    rule = _parse({'id': 'T-6', 'patterns': [r'\bfoobar\b']},
                  default_provenance='curated')
    assert is_screening_only(rule) is False
    assert _gate(False, False, [rule]) == [rule]


def test_harvested_provenance_still_gated_without_confidence():
    """PR-013 behavior preserved: harvested provenance alone is screening-only."""
    rule = _parse({'id': 'T-7', 'patterns': [r'\bfoobar\b']},
                  default_provenance='harvested')
    assert rule.provenance == 'harvested'
    assert is_screening_only(rule) is True
    assert _gate(False, False, [rule]) == []
    assert _gate(True, False, [rule]) == [rule]


def test_confidence_case_and_whitespace_insensitive():
    rule = _parse({'id': 'T-8', 'patterns': [r'\bfoobar\b'],
                   'pipeline_confidence': ' LOW '}, default_provenance='curated')
    assert is_screening_only(rule) is True


def test_typo_confidence_values_are_neutral():
    """Only exact 'low' gates; harvester typos ('midium', 'median') never gate a
    curated rule (they are not 'low')."""
    for typo in ('midium', 'median', 'middle', 'medium', 'high'):
        rule = _parse({'id': f'T-9-{typo}', 'patterns': [r'\bfoobar\b'],
                       'pipeline_confidence': typo}, default_provenance='curated')
        assert is_screening_only(rule) is False
