#!/usr/bin/env python3
"""
Security hardening tests for scanner argv injection defenses.

Covers two tightly-coupled fixes:

C-1a: External-tool cmd lists must include a ``--`` separator before the
      trailing path positional, so that a maliciously named file like
      ``--config=https://evil.tld/rce.yaml`` cannot be re-parsed by the tool
      as a CLI option.

C-1b: As defense-in-depth, scanners must refuse (without spawning a
      subprocess) any file whose basename starts with ``-``.

These tests mock ``BaseScanner._run_command`` to capture argv without invoking
the real external tool. They exercise the per-file subprocess fallback path
(``_scan_file_subprocess``) directly, so neither a populated cache nor the
tool actually being installed matters.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import List
from unittest.mock import patch

import pytest

from medusa.scanners.semgrep_scanner import SemgrepScanner
from medusa.scanners.trivy_scanner import TrivyScanner
from medusa.scanners.gitleaks_scanner import GitLeaksScanner


def _fake_completed(stdout: str = "", returncode: int = 0):
    """Return a stand-in for subprocess.CompletedProcess used by _run_command."""
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


def _make_scanner(cls):
    """Instantiate a scanner with a deterministic tool_path (bypasses PATH lookup)."""
    with patch.object(cls, "_find_tool", return_value=Path(f"/fake/bin/{cls.__name__}")):
        scanner = cls()
    # _find_tool is called in __init__; ensure tool_path is set regardless.
    scanner.tool_path = Path(f"/fake/bin/{cls.__name__}")
    return scanner


# ---------------------------------------------------------------------------
# C-1a: '--' separator before trailing path positional
# ---------------------------------------------------------------------------


def test_semgrep_argv_has_dashdash_separator(tmp_path):
    """semgrep _scan_file_subprocess must insert '--' before the file path."""
    scanner = _make_scanner(SemgrepScanner)
    target = tmp_path / "safe.py"
    target.write_text("print('ok')\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called once"
    cmd = captured[0]
    assert cmd[-1] == str(target), f"last arg should be the target path, got {cmd[-1]!r}"
    assert cmd[-2] == "--", f"expected '--' immediately before path, got {cmd[-2]!r}"


def test_trivy_config_argv_has_dashdash_separator(tmp_path):
    """trivy config-scan cmd must insert '--' before the file path."""
    scanner = _make_scanner(TrivyScanner)
    # .tf extension routes to 'config' scan type
    target = tmp_path / "main.tf"
    target.write_text('resource "aws_s3_bucket" "b" {}\n')

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    assert "config" in cmd, f"expected trivy config path, got {cmd}"
    assert cmd[-1] == str(target)
    assert cmd[-2] == "--", f"expected '--' before path in config cmd, got {cmd[-2]!r}"


def test_trivy_fs_argv_has_dashdash_separator(tmp_path):
    """trivy fs-scan cmd must insert '--' before the parent-dir path."""
    scanner = _make_scanner(TrivyScanner)
    # requirements.txt routes to 'fs' scan type (scans parent directory)
    target = tmp_path / "requirements.txt"
    target.write_text("requests==2.0.0\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    assert "fs" in cmd, f"expected trivy fs path, got {cmd}"
    assert cmd[-1] == str(target.parent)
    assert cmd[-2] == "--", f"expected '--' before parent path in fs cmd, got {cmd[-2]!r}"


def test_gitleaks_argv_safe(tmp_path):
    """
    gitleaks uses '--source <value>' (value form), so the attack surface is
    different from semgrep/trivy: there is no trailing positional to inject
    into. This test pins that invariant so a future refactor that adds a
    trailing positional is forced to re-evaluate the defense.
    """
    scanner = _make_scanner(GitLeaksScanner)
    target = tmp_path / "config.env"
    target.write_text("FOO=bar\n")

    captured: List[List[str]] = []

    def fake_run(cmd, timeout=30):
        captured.append(list(cmd))
        return _fake_completed(stdout="")

    with patch.object(scanner, "_run_command", side_effect=fake_run):
        scanner._scan_file_subprocess(target, time.time())

    assert captured, "expected _run_command to be called"
    cmd = captured[0]
    # The path appears as the value after '--source', not as a trailing positional.
    assert "--source" in cmd
    src_idx = cmd.index("--source")
    assert cmd[src_idx + 1] == str(target)
    # Last arg should be a flag or its value, NOT the scanned path.
    assert cmd[-1] != str(target), (
        f"gitleaks should not end with the target path; got cmd={cmd}"
    )


# ---------------------------------------------------------------------------
# C-1b: reject dash-prefixed basenames without spawning a subprocess
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scanner_cls",
    [SemgrepScanner, TrivyScanner, GitLeaksScanner],
    ids=["semgrep", "trivy", "gitleaks"],
)
def test_scanner_rejects_dash_prefixed_basename(scanner_cls, tmp_path):
    """
    A file whose basename starts with '-' must be refused before any
    subprocess is invoked. The returned ScannerResult must be unsuccessful
    and its error message must mention the defense.
    """
    scanner = _make_scanner(scanner_cls)
    # Literal malicious filename from the advertised attack.
    malicious = tmp_path / "--config=evil.yaml"
    malicious.write_text("rules: []\n")
    assert malicious.name.startswith("-")

    with patch.object(scanner, "_run_command") as mock_run:
        result = scanner._scan_file_subprocess(malicious, time.time())

    assert mock_run.call_count == 0, (
        f"{scanner_cls.__name__} must NOT spawn a subprocess for a dash-prefixed "
        f"filename; got {mock_run.call_count} calls"
    )
    assert result.success is False
    assert result.issues == []
    assert result.error_message is not None
    assert "argv injection defense" in result.error_message.lower()
    assert result.scanner_name == scanner.name
    assert result.file_path == str(malicious)


def test_reject_helper_passes_safe_paths(tmp_path):
    """The helper must return None for safe (non-dash-prefixed) basenames."""
    scanner = _make_scanner(SemgrepScanner)
    safe = tmp_path / "app.py"
    safe.write_text("print('ok')\n")
    assert scanner._reject_if_dash_prefixed(safe, time.time()) is None


def test_reject_helper_rejects_dash_prefix(tmp_path):
    """The helper must return an error ScannerResult for dash-prefixed names."""
    scanner = _make_scanner(TrivyScanner)
    evil = tmp_path / "-rf"
    evil.write_text("")
    result = scanner._reject_if_dash_prefixed(evil, time.time())
    assert result is not None
    assert result.success is False
    assert "argv injection defense" in (result.error_message or "").lower()
