"""Tests for the optional LLM semantic triage pass (build item #7).

These run with NO real CLI and NO real network. The backend call is always
mocked or skipped:
  * backend detection is monkeypatched (``shutil.which`` for the CLIs, env vars
    for the API backends);
  * CLI backends are exercised by monkeypatching ``subprocess.run``;
  * the CLI default path is asserted to NEVER call triage (zero subprocess).

Fail-safe is the headline contract: a finding is never dropped on error, and
a CRITICAL is never dropped at all. Interactive users triage via their existing
``claude`` / ``codex`` subscription CLI — no API key required.
"""

import subprocess

import pytest

import medusa.core.llm_triage as llm_triage
from click.testing import CliRunner

from medusa.cli import main
from medusa.core.llm_triage import (
    BACKEND_CLAUDE_CLI,
    BACKEND_CODEX_CLI,
    VERDICT_FALSE,
    VERDICT_TRUE,
    VERDICT_UNCERTAIN,
    llm_available,
    triage_findings,
)


# --- Fake subprocess.CompletedProcess --------------------------------------

class _FakeProc:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_run(returncode=0, stdout="", stderr=""):
    """Build a monkeypatch target for subprocess.run returning a fixed result."""

    def _run(cmd, **kwargs):
        return _FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)

    return _run


def _claude_json(verdict_line):
    """Shape a claude -p --output-format json payload with `verdict_line` text."""
    import json

    return json.dumps({"result": verdict_line})


def _finding(severity="MEDIUM", rule_id="R1", msg="possible issue", code="x = 1"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "issue": msg,
        "file": "app.py",
        "line": 10,
        "code": code,
    }


def _clear_llm_env(monkeypatch):
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "MEDUSA_LLM_API_KEY",
        "MEDUSA_LLM_BACKEND",
        "MEDUSA_LLM_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


def _which_none(monkeypatch):
    """No CLI on PATH."""
    monkeypatch.setattr(llm_triage.shutil, "which", lambda name: None)


def _which_only(monkeypatch, present):
    """Only `present` (e.g. 'claude') resolves on PATH; everything else missing."""
    monkeypatch.setattr(
        llm_triage.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name == present else None,
    )


# --- llm_available: backend detection & priority ---------------------------

def test_llm_available_false_when_nothing(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)
    ok, reason = llm_available()
    assert ok is False
    assert "no LLM backend available" in reason


def test_llm_available_prefers_claude_cli(monkeypatch):
    _clear_llm_env(monkeypatch)
    # Both CLIs present + an API key: claude-cli must win by priority.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(
        llm_triage.shutil, "which", lambda name: f"/usr/bin/{name}"
    )
    ok, backend = llm_available()
    assert ok is True
    assert backend == BACKEND_CLAUDE_CLI


def test_llm_available_falls_back_to_codex_cli(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "codex")
    ok, backend = llm_available()
    assert ok is True
    assert backend == BACKEND_CODEX_CLI


def test_llm_available_falls_back_to_anthropic_api(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ok, backend = llm_available()
    assert ok is True
    assert backend == "anthropic-api"


def test_llm_available_falls_back_to_openai_api(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    ok, backend = llm_available()
    assert ok is True
    assert backend == "openai-api"


def test_llm_available_env_override(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "codex")
    # Force claude-cli via env, but claude is NOT on PATH -> unavailable.
    monkeypatch.setenv("MEDUSA_LLM_BACKEND", "claude-cli")
    ok, reason = llm_available()
    assert ok is False
    assert "claude-cli" in reason


def test_llm_available_arg_override_beats_env_and_autodetect(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "codex")
    ok, backend = llm_available("codex-cli")
    assert ok is True
    assert backend == BACKEND_CODEX_CLI


# --- claude-cli backend: happy path ----------------------------------------

def test_claude_cli_false_positive_parsed_and_suppressed(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(
            returncode=0,
            stdout=_claude_json(
                "VERDICT: false_positive | REASON: this is a test fixture"
            ),
        ),
    )
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings)

    assert out["backend"] == BACKEND_CLAUDE_CLI
    assert out["triaged"] == 1
    assert out["errors"] == 0
    # Sub-CRITICAL confident FP is suppressed (dropped from kept) but counted.
    assert out["suppressed_fp"] == 1
    assert out["kept"] == []
    assert findings[0]["llm_verdict"] == VERDICT_FALSE
    assert "fixture" in findings[0]["llm_reason"]


def test_claude_cli_true_positive_kept(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(
            returncode=0,
            stdout=_claude_json("VERDICT: true_positive | REASON: real sql injection"),
        ),
    )
    findings = [_finding(severity="HIGH")]
    out = triage_findings(findings)

    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_TRUE


# --- claude-cli fail-safe: nonzero / timeout / bad JSON --------------------

def test_claude_cli_nonzero_exit_keeps_uncertain(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")
    monkeypatch.setattr(
        subprocess, "run", _fake_run(returncode=1, stdout="", stderr="boom")
    )
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings)

    assert out["errors"] == 1
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_UNCERTAIN
    assert "triage error" in findings[0]["llm_reason"]


def test_claude_cli_timeout_keeps_uncertain(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")

    def _timeout_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 30))

    monkeypatch.setattr(subprocess, "run", _timeout_run)
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings)

    assert out["errors"] == 1
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_UNCERTAIN


def test_claude_cli_bad_json_keeps_uncertain(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")
    monkeypatch.setattr(
        subprocess, "run", _fake_run(returncode=0, stdout="not-json{")
    )
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings)

    assert out["errors"] == 1
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_UNCERTAIN


# --- codex-cli backend -----------------------------------------------------

def test_codex_cli_false_positive_parsed_and_suppressed(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "codex")
    # codex exec prints plain text to stdout (no JSON wrapper).
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(
            returncode=0,
            stdout="VERDICT: false_positive | REASON: example code in docs",
        ),
    )
    findings = [_finding(severity="LOW")]
    out = triage_findings(findings)

    assert out["backend"] == BACKEND_CODEX_CLI
    assert out["triaged"] == 1
    assert out["suppressed_fp"] == 1
    assert out["kept"] == []
    assert findings[0]["llm_verdict"] == VERDICT_FALSE


def test_codex_cli_nonzero_exit_keeps_uncertain(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "codex")
    monkeypatch.setattr(
        subprocess, "run", _fake_run(returncode=2, stdout="", stderr="err")
    )
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings)

    assert out["errors"] == 1
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_UNCERTAIN


# --- CRITICAL is never dropped ---------------------------------------------

def test_triage_never_drops_critical_even_if_fp(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_only(monkeypatch, "claude")
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_run(
            returncode=0,
            stdout=_claude_json("VERDICT: false_positive | REASON: looks safe to me"),
        ),
    )
    findings = [_finding(severity="CRITICAL")]
    out = triage_findings(findings)

    # Annotated as FP but KEPT — CRITICAL is sacrosanct.
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_FALSE


# --- no backend available -> no-op -----------------------------------------

def test_triage_no_backend_is_noop(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)
    findings = [_finding()]
    out = triage_findings(findings)  # nothing available -> no-op
    assert out["triaged"] == 0
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert "no LLM backend available" in out["note"]
    # No annotation when nothing ran.
    assert "llm_verdict" not in findings[0]


# --- injected runner (backend-agnostic test hook) --------------------------

def test_triage_injected_runner_bypasses_backend(monkeypatch):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)  # no real backend; runner injection wins

    def _runner(prompt, timeout):
        return "VERDICT: false_positive | REASON: injected"

    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings, runner=_runner)
    assert out["suppressed_fp"] == 1
    assert findings[0]["llm_verdict"] == VERDICT_FALSE


# --- CLI flag presence -----------------------------------------------------

def test_scan_has_llm_triage_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--llm-triage" in result.output
    assert "--llm-backend" in result.output


def test_scan_command_params_include_llm_options():
    scan_cmd = main.commands["scan"]
    param_names = {p.name for p in scan_cmd.params}
    assert "llm_triage" in param_names
    assert "llm_backend" in param_names


# --- CLI: default path never invokes triage (no subprocess) ----------------

@pytest.mark.slow  # real CLI scan call, full rule corpus reload (~11s)
def test_default_scan_does_not_invoke_triage(monkeypatch, tmp_path):
    """Without --llm-triage, triage_findings must never be called."""
    called = {"n": 0}

    def _boom(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("triage_findings called on default path")

    monkeypatch.setattr(llm_triage, "triage_findings", _boom)

    (tmp_path / "sample.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--no-report"])
    assert called["n"] == 0
    assert "🤖 LLM triage" not in result.output


# --- CLI: --llm-triage with no backend prints message, exits 0 -------------

@pytest.mark.slow  # real CLI scan call, full rule corpus reload (~12s)
def test_llm_triage_flag_no_backend_message_and_exit_zero(monkeypatch, tmp_path):
    _clear_llm_env(monkeypatch)
    _which_none(monkeypatch)

    # Guard: triage_findings must NOT be called when no backend is available.
    def _boom(*args, **kwargs):
        raise AssertionError("triage_findings called with no backend")

    monkeypatch.setattr(llm_triage, "triage_findings", _boom)

    (tmp_path / "sample.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--no-report", "--llm-triage"]
    )
    assert result.exit_code == 0
    assert "no LLM backend available" in result.output
