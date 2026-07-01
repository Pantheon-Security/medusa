#!/usr/bin/env python3
"""Tests for vet-verdict scoping (P1-trust-safety).

The install verdict (SAFE / CAUTION / DO_NOT_INSTALL) must be driven ONLY by
malice / supply-chain SIGNAL findings, not by the full 40k-pattern generic SAST
sweep. Summing every generic finding into the verdict flagged 8 of 9
universally-trusted libraries (requests, flask, six, ...) as DO_NOT_INSTALL.

These tests exercise the REAL verdict path — ``scan_api._summarize`` (the same
function ``vet_path`` / ``vet_repo`` build their result from) — with synthesized
standardized-finding dicts, so they assert the actual behaviour a user sees, not
a reimplementation.
"""

from medusa.core import scan_api


def _finding(scanner, rule_id, severity, file="x.py", line=1):
    """Build a standardized finding dict shaped like _extract_findings output."""
    return {
        "scanner": scanner,
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "issue": f"{rule_id} on {file}",
    }


# --------------------------------------------------------------------------- #
# _is_vet_signal classification
# --------------------------------------------------------------------------- #

def test_generic_sast_is_not_a_signal():
    # WebSecurityScanner web-vuln + PythonScanner B1xx + dual-use AST behaviour
    # are informational for an install decision — never signals.
    assert not scan_api._is_vet_signal(_finding("WebSecurityScanner", "WEB-SSTI-001", "CRITICAL"))
    assert not scan_api._is_vet_signal(_finding("WebSecurityScanner", "WEB-EVAL-001", "CRITICAL"))
    assert not scan_api._is_vet_signal(_finding("PythonScanner", "B105", "MEDIUM"))
    assert not scan_api._is_vet_signal(_finding("AstBehaviorScanner", "MEDUSA-AST-SHELL", "HIGH"))
    assert not scan_api._is_vet_signal(_finding("OWASPLLMScanner", "LLM01", "HIGH"))


def test_malice_signals_are_signals_by_scanner():
    assert scan_api._is_vet_signal(_finding("ClaudeCodeScanner", "CC-HOOK-001", "CRITICAL"))
    assert scan_api._is_vet_signal(_finding("SkillManifestScanner", "MEDUSA-SKILL-001", "HIGH"))
    assert scan_api._is_vet_signal(_finding("MCPConfigScanner", "MEDUSA-MCP-POISON-002", "HIGH"))
    assert scan_api._is_vet_signal(_finding("TaintScanner", "MEDUSA-TAINT-EXFIL", "HIGH"))
    assert scan_api._is_vet_signal(_finding("AIAttackSignatureScanner", "MEDUSA-ATKSIG-9", "CRITICAL"))


def test_signal_by_rule_prefix_even_if_scanner_unknown():
    # Defence in depth: rule_id prefix alone marks a signal regardless of scanner.
    assert scan_api._is_vet_signal(_finding("unknown", "CC-CONFIG-003", "HIGH"))
    assert scan_api._is_vet_signal(_finding("unknown", "MEDUSA-TAINT-1", "HIGH"))
    assert scan_api._is_vet_signal(_finding("unknown", "CVE-2024-1234", "CRITICAL"))


def test_osv_incomplete_is_not_a_signal():
    # MEDUSA-OSV-INCOMPLETE is a "couldn't reach OSV" network notice from a
    # signal scanner — it must NOT drive the verdict, but a real OSV hit must.
    assert not scan_api._is_vet_signal(
        _finding("DependencyCVEScanner", "MEDUSA-OSV-INCOMPLETE", "INFO")
    )
    assert scan_api._is_vet_signal(
        _finding("DependencyCVEScanner", "MEDUSA-OSV-001", "HIGH")
    )


# --------------------------------------------------------------------------- #
# _summarize verdict scoping (the real result path)
# --------------------------------------------------------------------------- #

def test_only_generic_findings_verdict_is_safe():
    # A trusted lib producing lots of generic SAST noise must be SAFE, and the
    # noise must still be counted (total_findings) — just not blocking.
    findings = [
        _finding("WebSecurityScanner", "WEB-SSTI-001", "CRITICAL"),
        _finding("WebSecurityScanner", "WEB-EVAL-001", "CRITICAL"),
        _finding("WebSecurityScanner", "WEB-AUTH-002", "HIGH"),
        _finding("PythonScanner", "B105", "MEDIUM"),
        _finding("AstBehaviorScanner", "MEDUSA-AST-EXEC", "HIGH"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.SAFE
    assert s["blocking_findings"] == 0
    assert s["other_findings"] == 5
    assert s["total_findings"] == 5          # all findings counted
    assert s["top_findings"] == []           # top drawn from signal set only


def test_single_malice_signal_blocks_despite_generic_noise():
    findings = [
        _finding("SkillManifestScanner", "MEDUSA-SKILL-ANTIREFUSAL", "CRITICAL"),
        # ...buried in generic noise that on its own would be SAFE:
        _finding("WebSecurityScanner", "WEB-SSTI-001", "CRITICAL"),
        _finding("PythonScanner", "B105", "MEDIUM"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.DO_NOT_INSTALL
    assert s["blocking_findings"] == 1
    assert s["other_findings"] == 2
    assert s["total_findings"] == 3
    # The user sees WHY: the top finding is the malice signal, not the WEB noise.
    assert s["top_findings"][0]["rule_id"] == "MEDUSA-SKILL-ANTIREFUSAL"


def test_taint_mcp_poison_together_block():
    findings = [
        _finding("TaintScanner", "MEDUSA-TAINT-EXFIL", "HIGH"),
        _finding("MCPConfigScanner", "MEDUSA-MCP-POISON-001", "HIGH"),
        _finding("ClaudeCodeScanner", "CC-HOOK-POISON", "HIGH"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.DO_NOT_INSTALL     # 3 HIGH signals
    assert s["blocking_findings"] == 3


def test_osv_incomplete_alone_does_not_block():
    findings = [
        _finding("DependencyCVEScanner", "MEDUSA-OSV-INCOMPLETE", "INFO"),
        _finding("WebSecurityScanner", "WEB-SSRF-001", "HIGH"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.SAFE
    assert s["blocking_findings"] == 0


# --------------------------------------------------------------------------- #
# Dependency-vulnerability CAUTION tier (option B)
# --------------------------------------------------------------------------- #

def test_dependency_vuln_classifier():
    assert scan_api._is_dependency_vuln_signal(
        _finding("CriticalCVEScanner", "cve-cve-2023-37920", "CRITICAL")
    )
    assert scan_api._is_dependency_vuln_signal(
        _finding("DependencyCVEScanner", "MEDUSA-OSV-001", "HIGH")
    )
    assert scan_api._is_dependency_vuln_signal(
        _finding("unknown", "CVE-2024-1234", "CRITICAL")
    )
    # A malice signal is NOT a dependency-vuln.
    assert not scan_api._is_dependency_vuln_signal(
        _finding("TaintScanner", "MEDUSA-TAINT-EXFIL", "HIGH")
    )


def test_dependency_cve_alone_caps_at_caution():
    # A CRITICAL CVE on a dependency manifest, with NO malice, must be CAUTION,
    # never DO_NOT_INSTALL (this is the requests/flask case).
    findings = [
        _finding("CriticalCVEScanner", "cve-cve-2023-37920", "CRITICAL",
                 file="pyproject.toml"),
        _finding("DependencyCVEScanner", "MEDUSA-OSV-001", "HIGH",
                 file="requirements.txt"),
        _finding("DependencyCVEScanner", "MEDUSA-OSV-001", "HIGH",
                 file="requirements.txt"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.CAUTION
    assert s["blocking_findings"] == 3
    # It IS surfaced so the user knows to update the dep.
    assert s["top_findings"][0]["rule_id"] == "cve-cve-2023-37920"


def test_malice_plus_dependency_vuln_still_do_not_install():
    # The bad-fixture shape: malice signals + CVE/OSV -> DO_NOT_INSTALL, driven
    # by the malice tier (the CVE alone would only be CAUTION).
    findings = [
        _finding("TaintScanner", "MEDUSA-TAINT-EXFIL-001", "CRITICAL"),
        _finding("SkillManifestScanner", "MEDUSA-SKILL-ANTIREFUSAL-001", "CRITICAL"),
        _finding("CriticalCVEScanner", "cve-cve-2020-1747", "CRITICAL"),
        _finding("DependencyCVEScanner", "MEDUSA-OSV-001", "HIGH"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.DO_NOT_INSTALL


def test_dependency_vuln_does_not_escalate_an_existing_malice_caution():
    # A single HIGH malice signal is CAUTION on its own; adding a dep-vuln must
    # not push it to DO_NOT_INSTALL (dep-vuln can raise to CAUTION at most).
    findings = [
        _finding("GitLeaksScanner", "GITLEAKS-AWS", "HIGH"),
        _finding("CriticalCVEScanner", "cve-cve-2020-1747", "CRITICAL"),
    ]
    s = scan_api._summarize(findings)
    assert s["verdict"] == scan_api.CAUTION


def test_counts_by_severity_reflects_signal_subset_only():
    findings = [
        _finding("TaintScanner", "MEDUSA-TAINT-EXFIL", "HIGH"),
        _finding("WebSecurityScanner", "WEB-SSTI-001", "CRITICAL"),  # generic
    ]
    s = scan_api._summarize(findings)
    # The generic CRITICAL must NOT inflate the signal counts.
    assert s["counts_by_severity"]["CRITICAL"] == 0
    assert s["counts_by_severity"]["HIGH"] == 1
    assert s["total_findings"] == 2
