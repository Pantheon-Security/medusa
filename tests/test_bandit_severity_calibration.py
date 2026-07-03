"""Bandit severity is honored 1:1 (not inflated one level). [r2-fp P4b]"""
from medusa.scanners.python_scanner import PythonScanner
from medusa.scanners.base import Severity


def test_bandit_severity_1to1():
    s = PythonScanner()
    assert s._map_severity('LOW') == Severity.LOW      # was inflated to MEDIUM (B101 etc.)
    assert s._map_severity('MEDIUM') == Severity.MEDIUM  # was HIGH
    assert s._map_severity('HIGH') == Severity.HIGH      # was CRITICAL
    assert s._map_severity('nonsense') == Severity.LOW   # unknown -> LOW (unchanged)
