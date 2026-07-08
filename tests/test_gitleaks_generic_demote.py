"""Gate: gitleaks' low-confidence generic-* rules must not drive a blocking vet.

Corpus gate found GL-generic-api-key false-blocking clean repos. generic-api-key
matches any high-entropy assignment — gitleaks' biggest FP source. Demoted to
MEDIUM (non-blocking) while specific-format rules still block. External scanner,
so the native benchmark (353) is unaffected.
"""
from medusa.scanners.gitleaks_scanner import GitLeaksScanner
from medusa.scanners.base import Severity


def _sev(rule_id):
    return GitLeaksScanner()._map_severity({"RuleID": rule_id})


def test_generic_rules_demoted_below_blocking():
    assert _sev("generic-api-key") == Severity.MEDIUM
    assert _sev("generic-token") == Severity.MEDIUM


def test_specific_rules_still_block():
    assert _sev("aws-access-token") == Severity.CRITICAL
    assert _sev("private-key") == Severity.CRITICAL
    assert _sev("github-pat") == Severity.HIGH
    assert _sev("stripe-access-token") == Severity.CRITICAL
