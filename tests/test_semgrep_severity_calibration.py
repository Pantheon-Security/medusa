"""Semgrep severity honored 1:1 (capped at HIGH), no arbitrary OWASP boost. [r3 B2]"""
from medusa.scanners.semgrep_scanner import SemgrepScanner
from medusa.scanners.base import Severity


def _sev(s, level, owasp=None):
    extra = {'severity': level}
    if owasp is not None:
        extra['metadata'] = {'owasp': owasp}
    return s._map_severity({'extra': extra})


def test_semgrep_severity_1to1_no_owasp_boost():
    s = SemgrepScanner()
    assert _sev(s, 'ERROR') == Severity.HIGH      # was inflated to CRITICAL
    assert _sev(s, 'WARNING') == Severity.MEDIUM   # was HIGH
    assert _sev(s, 'INFO') == Severity.LOW         # was MEDIUM
    assert _sev(s, 'nonsense') == Severity.LOW     # unknown -> LOW
    # OWASP A01/A02/A03 boost dropped: a sha1-class A02 finding is no longer force-CRITICAL
    assert _sev(s, 'WARNING', owasp=['A02:2021']) == Severity.MEDIUM
    assert _sev(s, 'ERROR', owasp=['A03:2021']) == Severity.HIGH
