"""Tests for the optional LLM semantic triage pass (build item #7).

These run with NO real network. The LLM call is always mocked or skipped:
  * provider detection is env-var based (monkeypatched);
  * the LLM client is a fake injected via `client=`;
  * the CLI default path is asserted to NEVER call triage (zero network).

Fail-safe is the headline contract: a finding is never dropped on error, and
a CRITICAL is never dropped at all.
"""

import medusa.core.llm_triage as llm_triage
from click.testing import CliRunner

from medusa.cli import main
from medusa.core.llm_triage import (
    VERDICT_FALSE,
    VERDICT_TRUE,
    VERDICT_UNCERTAIN,
    llm_available,
    triage_findings,
)


# --- Fakes -----------------------------------------------------------------

class _FakeAnthropicResponse:
    def __init__(self, text):
        self.content = [type("Block", (), {"text": text})()]


class _FakeAnthropicMessages:
    def __init__(self, reply):
        self._reply = reply

    def create(self, **kwargs):
        return _FakeAnthropicResponse(self._reply)


class _FakeAnthropicClient:
    """Minimal stand-in matching the anthropic.Anthropic surface we use."""

    def __init__(self, reply):
        self.messages = _FakeAnthropicMessages(reply)


class _RaisingClient:
    """Client whose call always raises — exercises the fail-safe path."""

    class _Messages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    def __init__(self):
        self.messages = self._Messages()


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
        "MEDUSA_LLM_PROVIDER",
        "MEDUSA_LLM_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


# --- llm_available ---------------------------------------------------------

def test_llm_available_false_when_no_env(monkeypatch):
    _clear_llm_env(monkeypatch)
    ok, reason = llm_available()
    assert ok is False
    assert "no LLM provider configured" in reason


def test_llm_available_detects_anthropic(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ok, provider = llm_available()
    assert ok is True
    assert provider == "anthropic"


def test_llm_available_detects_openai(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    ok, provider = llm_available()
    assert ok is True
    assert provider == "openai"


def test_llm_available_explicit_provider_without_key(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("MEDUSA_LLM_PROVIDER", "anthropic")
    ok, reason = llm_available()
    assert ok is False
    assert "no matching API key" in reason


# --- triage_findings: happy path / annotation ------------------------------

def test_triage_marks_false_positive_and_annotates(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = _FakeAnthropicClient(
        "VERDICT: false_positive | REASON: this is a test fixture"
    )
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings, provider="anthropic", client=client)

    assert out["triaged"] == 1
    assert out["errors"] == 0
    # Sub-CRITICAL confident FP is suppressed (dropped from kept) but counted.
    assert out["suppressed_fp"] == 1
    assert out["kept"] == []
    # Annotation still landed on the finding object itself (mutated in place).
    assert findings[0]["llm_verdict"] == VERDICT_FALSE
    assert "fixture" in findings[0]["llm_reason"]


def test_triage_keeps_true_positive(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = _FakeAnthropicClient(
        "VERDICT: true_positive | REASON: real sql injection"
    )
    findings = [_finding(severity="HIGH")]
    out = triage_findings(findings, provider="anthropic", client=client)

    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_TRUE


# --- Fail-safe: error keeps finding as uncertain ---------------------------

def test_triage_error_keeps_finding_as_uncertain(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    findings = [_finding(severity="MEDIUM")]
    out = triage_findings(findings, provider="anthropic", client=_RaisingClient())

    # Never dropped on error.
    assert out["errors"] == 1
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_UNCERTAIN
    assert "triage error" in findings[0]["llm_reason"]


# --- CRITICAL is never dropped ---------------------------------------------

def test_triage_never_drops_critical_even_if_fp(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = _FakeAnthropicClient(
        "VERDICT: false_positive | REASON: looks safe to me"
    )
    findings = [_finding(severity="CRITICAL")]
    out = triage_findings(findings, provider="anthropic", client=client)

    # Annotated as FP but KEPT — CRITICAL is sacrosanct.
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert findings[0]["llm_verdict"] == VERDICT_FALSE


def test_triage_no_provider_is_noop(monkeypatch):
    _clear_llm_env(monkeypatch)
    findings = [_finding()]
    out = triage_findings(findings)  # no client, no env -> no-op
    assert out["triaged"] == 0
    assert out["suppressed_fp"] == 0
    assert out["kept"] == findings
    assert "no LLM provider configured" in out["note"]
    # No annotation when nothing ran.
    assert "llm_verdict" not in findings[0]


# --- CLI flag presence -----------------------------------------------------

def test_scan_has_llm_triage_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--llm-triage" in result.output


def test_scan_command_param_includes_llm_triage():
    # Introspect the Click command params, not just help text.
    scan_cmd = main.commands["scan"]
    param_names = {p.name for p in scan_cmd.params}
    assert "llm_triage" in param_names


# --- CLI: default path never invokes triage (no network) -------------------

def test_default_scan_does_not_invoke_triage(monkeypatch, tmp_path):
    """Without --llm-triage, triage_findings must never be called."""
    called = {"n": 0}

    def _boom(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("triage_findings called on default path")

    # Patch on the module so any import-site lookup sees the guard.
    monkeypatch.setattr(llm_triage, "triage_findings", _boom)

    (tmp_path / "sample.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--no-report"])
    # Scan may exit 0 or with findings; the point is triage was never called.
    assert called["n"] == 0
    assert "🤖 LLM triage" not in result.output


# --- CLI: --llm-triage with no provider prints message, exits 0 ------------

def test_llm_triage_flag_no_provider_message_and_exit_zero(monkeypatch, tmp_path):
    _clear_llm_env(monkeypatch)

    # Guard: triage_findings must NOT be called when no provider is configured.
    def _boom(*args, **kwargs):
        raise AssertionError("triage_findings called with no provider")

    monkeypatch.setattr(llm_triage, "triage_findings", _boom)

    (tmp_path / "sample.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--no-report", "--llm-triage"]
    )
    assert result.exit_code == 0
    assert "no LLM provider configured" in result.output
