"""Vet verdict must not hard-block on findings buried in non-executing test-data
dirs (test vectors / fixtures / examples). Real-world driver: pyca/cryptography
ships 300+ high-entropy test vectors that trip the generic secret detector — a
committed test vector is not a reason to refuse installing the library. Malice in
the actual install path (root, package code, .claude/) must still block.
"""
from medusa.core.scan_api import (
    _is_test_data_path,
    _is_vet_signal,
    _summarize,
    SAFE,
    CAUTION,
    DO_NOT_INSTALL,
)


def _f(rule_id, severity, file, scanner="GitLeaksScanner"):
    return {"rule_id": rule_id, "severity": severity, "file": file, "scanner": scanner}


def test_test_data_path_detection():
    assert _is_test_data_path("cryptography/vectors/x/keys.txt")
    assert _is_test_data_path("pkg/tests/fixtures/data.py")
    assert _is_test_data_path("a/b/examples/demo.py")
    assert not _is_test_data_path("pkg/core/client.py")
    assert not _is_test_data_path(".claude/settings.json")


def test_secret_in_vectors_does_not_block():
    findings = [_f("GL-generic-api-key", "HIGH", "cryptography/vectors/rsa/k%d.txt" % i)
                for i in range(20)]
    out = _summarize(findings)
    assert out["verdict"] == SAFE, out  # test-data secrets don't gate install


def test_malice_at_root_still_blocks():
    findings = [
        _f("CC-HOOK-001", "CRITICAL", ".claude/settings.json", scanner="ClaudeCodeScanner"),
        _f("MEDUSA-TAINT-EXFIL-001", "CRITICAL", "exfil.py", scanner="TaintScanner"),
    ]
    assert _summarize(findings)["verdict"] == DO_NOT_INSTALL


def test_malice_inside_tests_is_not_a_signal():
    # A signal-scanner finding buried in a tests/ dir is not an install-risk gate.
    assert not _is_vet_signal(_f("MEDUSA-TAINT-EXFIL-001", "CRITICAL",
                                 "pkg/tests/test_exfil.py", scanner="TaintScanner"))
    # …but the same finding in the package path IS.
    assert _is_vet_signal(_f("MEDUSA-TAINT-EXFIL-001", "CRITICAL",
                             "pkg/client.py", scanner="TaintScanner"))
