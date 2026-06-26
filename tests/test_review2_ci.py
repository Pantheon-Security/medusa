#!/usr/bin/env python3
"""
Review-2 RH-6: real-path lint of the GitHub Actions security workflow.

Reads .github/workflows/medusa-scan.yml and asserts the scan step is wired
correctly: no fictional `--no-install` flag, no `|| true` masking failures,
every `--flag` passed to `medusa scan` is a real Click option on the scan
command, and the SARIF upload references the real timestamped report glob.

Deliberately introspects the live CLI (medusa.cli.scan) rather than hardcoding
a flag list, so the test tracks the command as it evolves.
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "medusa-scan.yml"


def _workflow_text() -> str:
    assert WORKFLOW.exists(), f"missing workflow file: {WORKFLOW}"
    return WORKFLOW.read_text()


def _medusa_scan_command_lines(text: str) -> list[str]:
    """Return the `run:` command strings that invoke `medusa scan`."""
    cmds = []
    for line in text.splitlines():
        stripped = line.strip()
        # match either `run: medusa scan ...` or a bare `medusa scan ...` line
        m = re.search(r"(medusa\s+scan\b.*)$", stripped)
        if m:
            cmds.append(m.group(1))
    return cmds


def test_workflow_has_no_fake_no_install_flag():
    assert "--no-install" not in _workflow_text(), (
        "workflow uses fictional `--no-install` flag (not a real scan option)"
    )


def test_workflow_does_not_mask_failures_with_or_true():
    text = _workflow_text()
    assert "|| true" not in text, (
        "`|| true` masks scan failures — the security check must surface them"
    )


def test_workflow_invokes_medusa_scan():
    cmds = _medusa_scan_command_lines(_workflow_text())
    assert cmds, "workflow no longer runs `medusa scan` — RH-6 regression"


def test_workflow_scan_uses_sarif_format():
    cmds = _medusa_scan_command_lines(_workflow_text())
    assert any("--format sarif" in c for c in cmds), (
        f"scan step should emit SARIF for upload; got: {cmds}"
    )


def test_workflow_uploads_real_sarif_glob():
    """The SARIF upload must point at the real timestamped report filename
    (reporter writes medusa-scan-<ts>.sarif into .medusa/reports/)."""
    text = _workflow_text()
    assert "github/codeql-action/upload-sarif" in text, (
        "missing standard SARIF upload step"
    )
    assert ".medusa/reports/*.sarif" in text, (
        "SARIF upload must reference .medusa/reports/*.sarif (timestamped name)"
    )


def test_workflow_scan_flags_are_real_click_options():
    """Every --flag passed to `medusa scan` in the workflow must be a real
    Click option on the scan command (introspected live)."""
    from medusa.cli import scan

    valid_opts = {opt for p in scan.params for opt in getattr(p, "opts", [])}

    cmds = _medusa_scan_command_lines(_workflow_text())
    used_flags = set()
    for c in cmds:
        # tokens that look like long/short flags (strip any =value)
        for tok in c.split():
            if tok.startswith("-") and not tok.startswith("---"):
                used_flags.add(tok.split("=", 1)[0])

    assert used_flags, f"no flags parsed from scan commands: {cmds}"
    unknown = sorted(f for f in used_flags if f not in valid_opts)
    assert not unknown, (
        f"workflow passes flags not defined on `medusa scan`: {unknown} "
        f"(valid options: {sorted(valid_opts)})"
    )


def test_workflow_is_valid_yaml():
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(_workflow_text())
    assert isinstance(data, dict) and "jobs" in data, "workflow YAML malformed"
