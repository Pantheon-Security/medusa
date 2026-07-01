"""Phase 4 (LOW / readability) remediation tests: CR-028, CR-029, CR-030, CR-031.

Written GATE-FIRST (RED before the fixes, GREEN after). Each test exercises the
real code path (module import + public/behavioral surface), not a to_dict() or a
source grep, except where the ticket's contract is explicitly about source
ordering (CR-028 regex placement) — which is verified against the real module
source.
"""

import urllib.error

import pytest
from click.testing import CliRunner


# --------------------------------------------------------------------------- #
# CR-028: hoist _EXACT_NPM_VERSION_RE + OSV cross-file circuit breaker
# --------------------------------------------------------------------------- #
def test_cr028_npm_version_re_defined_before_first_use():
    """_EXACT_NPM_VERSION_RE must be a top-level constant defined before the
    lockfile parsers that use it (it was defined at the bottom of the module,
    used ~line 282)."""
    import inspect

    from medusa.scanners import dependency_cve_scanner as m

    # It imports and works as a real regex.
    assert m._EXACT_NPM_VERSION_RE.match("1.2")
    assert m._EXACT_NPM_VERSION_RE.match("1")
    assert not m._EXACT_NPM_VERSION_RE.match("^1.2.3")

    src = inspect.getsource(m)
    def_idx = src.index("_EXACT_NPM_VERSION_RE = re.compile")
    first_use_idx = src.index("_EXACT_NPM_VERSION_RE.match")
    assert def_idx < first_use_idx, "regex must be defined before its first use"


def test_cr028_circuit_breaker_short_circuits_after_k_failures(monkeypatch):
    """After K consecutive network failures in a run, the scanner opens its
    circuit breaker and short-circuits remaining lookups — no further HTTP
    calls are made."""
    from medusa.scanners.dependency_cve_scanner import (
        DependencyCVEScanner,
        _OSV_CIRCUIT_BREAKER_K,
    )

    scanner = DependencyCVEScanner()
    calls = {"n": 0}

    def _boom(payload):
        calls["n"] += 1
        # A non-transport HTTP error (not 429/503): returns no data but does not
        # itself flip the run offline — the circuit breaker must do that after K.
        raise urllib.error.HTTPError("u", 500, "err", {}, None)

    monkeypatch.setattr(scanner, "_http_post", _boom)

    k = _OSV_CIRCUIT_BREAKER_K
    # Resolve K+3 distinct pins, one at a time (distinct so the cache never
    # dedups them). The first K trigger real HTTP calls; once the breaker opens
    # the rest short-circuit with zero further calls.
    for i in range(k + 3):
        scanner._resolve([(f"pkg{i}", "1.0.0", "PyPI")])

    assert calls["n"] == k, f"expected exactly {k} HTTP calls, got {calls['n']}"
    assert scanner._offline is True


# --------------------------------------------------------------------------- #
# CR-029: scrub secret-pattern tokens from the triage prompt before egress
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "token",
    [
        "AKIAIOSFODNN7EXAMPLE",                       # AWS access key id
        "sk-abcdEFGH1234567890ijklMNOP",             # OpenAI-style key
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKL",  # JWT
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # long hex
    ],
)
def test_cr029_secret_tokens_scrubbed_from_prompt(token):
    from medusa.core.llm_triage import _build_prompt

    prompt = _build_prompt({"code": token, "severity": "LOW", "issue": "x"})
    assert token not in prompt


def test_cr029_secret_scrubbed_from_message_too():
    from medusa.core.llm_triage import _build_prompt

    prompt = _build_prompt(
        {"code": "y", "severity": "LOW", "issue": "leak: AKIAIOSFODNN7EXAMPLE"}
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in prompt


def test_cr029_docstring_notes_api_egress():
    from medusa.core import llm_triage

    assert "third part" in (llm_triage.__doc__ or "").lower()


# --------------------------------------------------------------------------- #
# CR-030: hooks group + mcp command moved to cli_hooks.py (pure move)
# --------------------------------------------------------------------------- #
def test_cr030_mcp_help_still_works():
    from medusa.cli import main

    result = CliRunner().invoke(main, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "gatekeeper" in result.output.lower()


def test_cr030_hooks_status_still_works():
    from medusa.cli import main

    with CliRunner().isolated_filesystem():
        result = CliRunner().invoke(main, ["hooks", "status"])
        assert result.exit_code == 0


def test_cr030_hooks_and_mcp_live_in_cli_hooks_module():
    """The commands must actually be defined in the new module (real move, not a
    re-export left in cli.py)."""
    from medusa import cli_hooks

    assert hasattr(cli_hooks, "hooks")
    assert hasattr(cli_hooks, "mcp")


def test_cr030_hooks_install_still_writes(tmp_path):
    from medusa.cli import main

    runner = CliRunner()
    with runner.isolated_filesystem():
        from pathlib import Path

        Path(".git").mkdir()
        result = runner.invoke(main, ["hooks", "install", "--all"])
        assert result.exit_code == 0, result.output
        assert Path(".claude/settings.json").exists()
        assert Path(".cursor/mcp.json").exists()


# --------------------------------------------------------------------------- #
# CR-031: readability — dropped unused params / module-level helper
# --------------------------------------------------------------------------- #
def test_cr031_is_network_sink_has_no_root_param():
    import inspect

    from medusa.scanners.taint_scanner import _TaintAnalyzer

    params = inspect.signature(_TaintAnalyzer._is_network_sink).parameters
    assert "root" not in params


def test_cr031_skill_checks_drop_lines_param():
    import inspect

    from medusa.scanners.skill_manifest_scanner import SkillManifestScanner

    for meth in ("_check_triggers", "_check_shadow_name", "_check_tools"):
        params = inspect.signature(getattr(SkillManifestScanner, meth)).parameters
        assert "lines" not in params, f"{meth} still takes a `lines` param"


def test_cr031_key_re_is_class_constant():
    from medusa.scanners.skill_manifest_scanner import SkillManifestScanner

    assert hasattr(SkillManifestScanner, "_FRONTMATTER_KEY_RE")


def test_cr031_is_medusa_entry_module_level_helper():
    from medusa.hooks import install

    assert hasattr(install, "_is_medusa_entry")
    assert callable(install._is_medusa_entry)
