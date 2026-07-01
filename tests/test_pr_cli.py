"""Product-review (RESHAPE) regression tests for the CLI lane.

Covers the code-side product/UX fixes from `.claude-review/REMEDIATION.md`:

* PR-001 -- the SCAN COMPLETE terminal box surfaces the severity breakdown,
            risk level, and the top CRITICAL/HIGH findings inline (a scan that
            finds CRITICALs no longer renders identically to a clean scan).
* PR-002 -- `medusa init` on a non-interactive stdin refuses cleanly BEFORE any
            disk write instead of writing config then aborting half-initialized.
* PR-006 -- `medusa vet` default output shows the top findings under the verdict.
* PR-011 -- a first-class `--offline` flag wires MEDUSA_OFFLINE so the OSV.dev
            dependency-CVE lookup short-circuits (no network egress).
* PR-015 -- `medusa scan --git URL --llm-triage` (and --baseline/--write-baseline)
            is rejected explicitly instead of being silently ignored.
* PR-016 -- `--llm-triage` announces itself up-front (not silent until the end).
* PR-017 -- one canonical scanner count: the clean-state line matches the box.

These exercise the REAL paths: the SCAN COMPLETE box is produced by the real
`MedusaParallelScanner.generate_report`; the CLI commands are invoked through
Click's CliRunner (the same entrypoint a user hits). No network or git clone is
performed (the --git rejection short-circuits before any clone).
"""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from medusa.cli import main
from medusa.core import scan_api
from medusa.core.parallel import MedusaParallelScanner, ScanResult
from medusa.scanners.dependency_cve_scanner import DependencyCVEScanner


# --------------------------------------------------------------------------- #
# PR-001 -- severity breakdown + risk level + top findings in the scan box
# --------------------------------------------------------------------------- #

def test_pr001_scan_box_shows_severity_risk_and_top_finding(tmp_path, capsys):
    """A scan result with a CRITICAL + HIGH finding must render the severity
    split, a risk level, and a top finding's file:line in the terminal box —
    not just the plain 'Issues found: N' a clean scan shows."""
    src = tmp_path / "app"
    src.mkdir()
    vuln_file = src / "payment.py"
    vuln_file.write_text("def charge():\n    eval(user_input)\n    os.system(cmd)\n")

    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    result = ScanResult(
        file=str(vuln_file),
        scanner="PythonASTScanner",
        issues=[
            {"severity": "CRITICAL", "rule_id": "PY-EVAL-001",
             "line": 2, "message": "eval() on untrusted input"},
            {"severity": "HIGH", "rule_id": "PY-SHELL-002",
             "line": 3, "message": "os.system with tainted command"},
        ],
        scan_time=0.01,
        scanner_stats={"PythonASTScanner": 2},
        line_count=3,
    )

    scanner.generate_report([result], tmp_path / "reports", formats=[], screening=True)
    out = capsys.readouterr().out

    assert "Risk level" in out, out
    assert "CRITICAL" in out, out
    # A top finding must name the offending file:line, not just a count.
    assert "payment.py:2" in out, out


# --------------------------------------------------------------------------- #
# PR-002 -- init refuses non-TTY before any write
# --------------------------------------------------------------------------- #

def test_pr002_init_non_tty_writes_nothing_and_exits_2():
    """CliRunner stdin is non-interactive; with no --ide, `init` must exit 2 and
    leave the project untouched (no .medusa.yml / .claude written)."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 2, result.output
        assert not Path(".medusa.yml").exists()
        assert not Path("medusa.yml").exists()
        assert not Path(".claude").exists()


def test_pr002_init_with_ide_none_is_allowed_non_tty():
    """An explicit --ide makes the run fully non-interactive: it must NOT hit the
    refusal guard (it may still do other work, just not exit 2 for the guard)."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--ide", "none"])
        # The guard is the only source of exit 2 in this path; passing --ide
        # must bypass it, so a write is expected to have happened.
        assert Path(".medusa.yml").exists() or result.exit_code != 2, result.output


# --------------------------------------------------------------------------- #
# PR-006 -- vet default output shows the top findings under the verdict
# --------------------------------------------------------------------------- #

def test_pr006_vet_prints_top_findings(monkeypatch):
    """The non-JSON vet output must render the top findings (rule + file:line)
    that drove the verdict, reusing the result's top_findings."""
    fake = {
        "verdict": scan_api.DO_NOT_INSTALL,
        "score": 250,
        "counts_by_severity": {"CRITICAL": 1},
        "total_findings": 3,
        "top_findings": [
            {"severity": "CRITICAL", "rule_id": "MCP-POISON-001",
             "file": "server.py", "line": 12},
        ],
        "target": "some/dir",
    }
    monkeypatch.setattr("medusa.core.scan_api.vet_repo", lambda *a, **k: fake)

    result = CliRunner().invoke(main, ["vet", "some/dir"])
    assert result.exit_code == 2, result.output  # DO_NOT_INSTALL
    assert "Top findings" in result.output, result.output
    assert "server.py:12" in result.output, result.output


def test_pr006_vet_json_unchanged(monkeypatch):
    """`vet --json` must still emit valid JSON (the top-findings rendering is
    non-JSON only)."""
    import json as _json
    fake = {
        "verdict": scan_api.SAFE, "score": 0, "counts_by_severity": {},
        "total_findings": 0, "top_findings": [], "target": "x",
    }
    monkeypatch.setattr("medusa.core.scan_api.vet_repo", lambda *a, **k: fake)
    result = CliRunner().invoke(main, ["vet", "x", "--json"])
    assert result.exit_code == 0, result.output
    parsed = _json.loads(result.output)
    assert parsed["verdict"] == scan_api.SAFE


# --------------------------------------------------------------------------- #
# PR-011 -- --offline flag disables OSV network egress
# --------------------------------------------------------------------------- #

def test_pr011_offline_flag_exists():
    """The scan command must expose a first-class --offline flag."""
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0, result.output
    assert "--offline" in result.output, result.output


def test_pr011_scanner_honors_offline_env(monkeypatch, tmp_path):
    """With MEDUSA_OFFLINE=1 the DependencyCVEScanner starts offline and NEVER
    touches the network when scanning a manifest."""
    monkeypatch.setenv("MEDUSA_OFFLINE", "1")
    scanner = DependencyCVEScanner()
    assert scanner._offline is True

    def _boom(*a, **k):
        raise AssertionError("network was contacted while --offline")

    monkeypatch.setattr(scanner, "_post_querybatch", _boom)

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.0\nflask==0.12.0\n")
    result = scanner.scan(req)  # must not raise
    # No OSV/CVE findings can exist without a network round-trip.
    assert all("OSV" not in (getattr(i, "rule_id", "") or "") for i in result.issues)


def test_pr011_scanner_online_by_default(monkeypatch):
    """Sanity: without the env var the scanner is NOT offline (proves the test
    above is exercising the flag, not a default)."""
    monkeypatch.delenv("MEDUSA_OFFLINE", raising=False)
    assert DependencyCVEScanner()._offline is False


# --------------------------------------------------------------------------- #
# PR-015 -- --git rejects baseline/llm-triage instead of silently ignoring
# --------------------------------------------------------------------------- #

def test_pr015_git_rejects_llm_triage():
    """`scan --git URL --llm-triage` must exit 2 with a message naming the flag,
    BEFORE any clone happens."""
    result = CliRunner().invoke(main, ["scan", "--git", "user/repo", "--llm-triage"])
    assert result.exit_code == 2, result.output
    assert "--llm-triage" in result.output, result.output


def test_pr015_git_rejects_baseline():
    result = CliRunner().invoke(
        main, ["scan", "--git", "user/repo", "--baseline", "b.json"]
    )
    assert result.exit_code == 2, result.output
    assert "--baseline" in result.output, result.output


# --------------------------------------------------------------------------- #
# PR-016 -- --llm-triage announces itself up-front
# --------------------------------------------------------------------------- #

def test_pr016_llm_triage_announced(tmp_path):
    """`scan <dir> --llm-triage` must print the up-front triage notice even when
    no backend is installed (console notice only, network-free)."""
    (tmp_path / "hello.py").write_text("x = 1\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--llm-triage"])
    assert "LLM triage enabled" in result.output, result.output


# --------------------------------------------------------------------------- #
# PR-017 -- one canonical scanner count + correct pluralization
# --------------------------------------------------------------------------- #

def test_pr017_clean_line_scanner_count_matches_box(tmp_path):
    """On a clean scan the affirmative clean-state line's scanner count must
    equal the SCAN COMPLETE box's 'Scanners used: N' count."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    out = result.output

    import re
    box = re.search(r"Scanners used:\s*(\d+)", out)
    clean = re.search(r"across\s+\d+\s+files?,\s+(\d+)\s+(scanner|scanners)\b", out)
    assert box, out
    assert clean, out
    box_n = int(box.group(1))
    clean_n = int(clean.group(1))
    assert clean_n == box_n, f"clean line {clean_n} != box {box_n}\n{out}"
    # Pluralization must agree with the count.
    expected_word = "scanner" if clean_n == 1 else "scanners"
    assert clean.group(2) == expected_word, out
