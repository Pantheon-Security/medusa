"""Gate for FX-H02 (#25a) — `medusa scan` must not let test-file findings drive the
numeric security SCORE (PC001 handover 2026-07-22-fp-realworld cross-cutting).

Security tests embed attack strings (169.254.169.254, reverse-shell fixtures) and always
trip signature scanners, so a hardened repo's score was dominated by its own test corpus
(FX-005 fixed this for VET verdicts only; the SCAN report score is a separate path).
Findings in non-executing test/fixture/example dirs are still reported + counted, but do
not drive `calculate_security_score` / the risk level.
"""
from medusa.core.reporter import MedusaReportGenerator


def _score(findings):
    return MedusaReportGenerator().calculate_security_score(findings)


def _f(sev, file):
    return {"severity": sev, "file": file, "line": 1, "rule_id": "X", "issue": ""}


def test_critical_only_in_tests_does_not_tank_score():
    # a CRITICAL that exists ONLY in a test dir must not force the repo to CRITICAL risk
    s = _score([_f("CRITICAL", "repo/tests/test_ssrf.py")])
    assert s > 40, f"test-only CRITICAL should not cap the score at 40, got {s}"


def test_critical_in_real_source_still_caps():
    s = _score([_f("CRITICAL", "repo/src/app.py")])
    assert s <= 40, f"a real-source CRITICAL must cap the score at 40, got {s}"


def test_test_findings_excluded_from_weight():
    # two identical findings; the one in tests/ contributes less/none to the penalty
    src = _score([_f("HIGH", "repo/src/a.py")])
    tst = _score([_f("HIGH", "repo/tests/a_test.py")])
    assert tst > src, f"test-dir finding should penalize less than a src finding ({tst} vs {src})"


def test_clean_repo_still_100():
    assert _score([]) == 100.0


def test_mixed_uses_worst_nontest_severity():
    # CRITICAL in tests/ + HIGH in src/ -> capped by the src HIGH (65), not the test CRITICAL (40)
    s = _score([_f("CRITICAL", "repo/tests/t.py"), _f("HIGH", "repo/src/a.py")])
    assert 40 < s <= 65, f"cap should follow the worst NON-test severity (HIGH=65), got {s}"
