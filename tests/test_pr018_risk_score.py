"""PR-018a: a CRITICAL/HIGH finding must never read as a 'GOOD' risk level.

Before the fix, calculate_security_score used only a weighted penalty
(CRITICAL=10, HIGH=5), so 1 CRITICAL + 1 HIGH scored 85 -> risk level "GOOD" —
a trust-killer for a security scanner. The score is now capped by the worst
severity present.
"""
import pytest

from medusa.core.reporter import MedusaReportGenerator


@pytest.fixture
def reporter():
    return MedusaReportGenerator()


def test_single_critical_is_not_good(reporter):
    findings = [
        {"severity": "CRITICAL", "rule_id": "X", "file": "a.py", "line": 1},
        {"severity": "HIGH", "rule_id": "Y", "file": "a.py", "line": 2},
    ]
    score = reporter.calculate_security_score(findings)
    level = reporter.calculate_risk_level(score)
    assert score <= 40, score
    assert level == "CRITICAL", (score, level)  # never GOOD/EXCELLENT


def test_lowercase_severity_still_capped(reporter):
    findings = [{"severity": "critical", "rule_id": "X", "file": "a.py", "line": 1}]
    assert reporter.calculate_risk_level(reporter.calculate_security_score(findings)) == "CRITICAL"


def test_high_only_is_concerning_not_good(reporter):
    findings = [{"severity": "HIGH", "rule_id": "Y", "file": "a.py", "line": 1}]
    score = reporter.calculate_security_score(findings)
    assert score <= 65, score
    assert reporter.calculate_risk_level(score) in {"CONCERNING", "MODERATE"}


def test_clean_scan_is_excellent(reporter):
    assert reporter.calculate_security_score([]) == 100.0
    assert reporter.calculate_risk_level(100.0) == "EXCELLENT"


def test_only_low_findings_not_over_penalized(reporter):
    # A couple of LOWs should not be force-capped to CRITICAL/CONCERNING.
    findings = [{"severity": "LOW", "rule_id": "L", "file": "a.py", "line": i} for i in range(3)]
    score = reporter.calculate_security_score(findings)
    assert score >= 90, score  # 100 - 3 = 97, uncapped


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
