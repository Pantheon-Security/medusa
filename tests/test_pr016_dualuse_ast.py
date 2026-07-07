#!/usr/bin/env python3
"""
PR-016 dual-use precision tests for the code-based (AST + regex) scanners.

These lock in the two-sided contract for AstBehaviorScanner and
WebSecurityScanner: benign dual-use forms measured as false positives on clean
third-party code (black / jinja / flask / typer / click / requests ...) must NOT
fire (or must be demoted below CRITICAL), while genuine attacker-controlled sinks
MUST still fire at HIGH/CRITICAL. Detection is never removed — only context-gated
or severity-tiered.

Each test drives the REAL scanner over a crafted source string.
"""

from pathlib import Path

import pytest

from medusa.scanners.ast_behavior_scanner import AstBehaviorScanner
from medusa.scanners.web_security_scanner import WebSecurityScanner
from medusa.scanners.base import Severity


CRITICAL = Severity.CRITICAL
HIGH = Severity.HIGH


@pytest.fixture
def ast_scanner() -> AstBehaviorScanner:
    return AstBehaviorScanner()


@pytest.fixture
def web_scanner() -> WebSecurityScanner:
    return WebSecurityScanner()


def _ast_findings(scanner: AstBehaviorScanner, tmp_path: Path, code: str) -> list:
    """Return the list of (rule_id, severity) emitted by the AST scanner."""
    f = tmp_path / "sample.py"
    f.write_text(code)
    result = scanner.scan_file(f)
    assert result.success
    return [(i.rule_id, i.severity) for i in result.issues]


def _ast_rules(scanner, tmp_path, code) -> set:
    return {rid for rid, _ in _ast_findings(scanner, tmp_path, code)}


def _sev_for(findings: list, rule_id: str):
    return [sev for rid, sev in findings if rid == rule_id]


def _web_ssrf(scanner: WebSecurityScanner, tmp_path: Path, code: str) -> list:
    """Return severities of WEB-SSRF findings from the real web scan path."""
    f = tmp_path / "app.py"
    f.write_text(code)
    result = scanner.scan_file(f)
    assert result.success
    return [i.severity for i in result.issues if i.rule_id == "WEB-SSRF"]


# A minimal Flask+requests preamble so has_web_context / framework gate is True.
_WEB_PREAMBLE = (
    "from flask import Flask, request\n"
    "import requests\n"
    "app = Flask(__name__)\n"
)


# --------------------------------------------------------------------------- #
# REFLECT-001 — getattr / setattr
# --------------------------------------------------------------------------- #
def test_reflect_benign_getattr_with_default_not_flagged(ast_scanner, tmp_path):
    # typer/click _compat idiom: literal attr name + default -> safe fallback.
    code = 'import os\nflags = 0\nflags |= getattr(os, "O_BINARY", 0)\n'
    assert "MEDUSA-AST-REFLECT-001" not in _ast_rules(ast_scanner, tmp_path, code)


def test_reflect_dangerous_module_literal_still_fires(ast_scanner, tmp_path):
    # 2-arg reflective dispatch on os (no default) is still evasive -> HIGH.
    code = 'import os\ndef run(cmd):\n    getattr(os, "system")(cmd)\n'
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert HIGH in _sev_for(findings, "MEDUSA-AST-REFLECT-001")


def test_reflect_tainted_attribute_name_fires_high(ast_scanner, tmp_path):
    # Attribute NAME is attacker-controlled (request.args) -> HIGH, any target.
    code = (
        "from flask import request\n"
        "def run(obj):\n"
        '    return getattr(obj, request.args["attr"])\n'
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert HIGH in _sev_for(findings, "MEDUSA-AST-REFLECT-001")


# --------------------------------------------------------------------------- #
# DYNIMPORT-001 — __import__ / import_module
# --------------------------------------------------------------------------- #
def test_dynimport_literal_not_flagged(ast_scanner, tmp_path):
    code = 'from importlib import import_module\nmod = import_module("json")\n'
    assert "MEDUSA-AST-DYNIMPORT-001" not in _ast_rules(ast_scanner, tmp_path, code)


def test_dynimport_local_name_demoted_to_medium(ast_scanner, tmp_path):
    # jinja/plugin-loader idiom: locally-derived module name -> fire, but MEDIUM.
    code = (
        "from importlib import import_module\n"
        "def load(package_name):\n"
        "    return import_module(package_name)\n"
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    sev = _sev_for(findings, "MEDUSA-AST-DYNIMPORT-001")
    assert sev == [Severity.MEDIUM]


def test_dynimport_tainted_name_fires_high(ast_scanner, tmp_path):
    code = (
        "from flask import request\n"
        "from importlib import import_module\n"
        "def load():\n"
        '    return import_module(request.form["mod"])\n'
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert HIGH in _sev_for(findings, "MEDUSA-AST-DYNIMPORT-001")


# --------------------------------------------------------------------------- #
# EXEC-001 — exec / eval / compile
# --------------------------------------------------------------------------- #
def test_compile_self_contained_demoted_below_critical(ast_scanner, tmp_path):
    # black's parser: compile of locally-built source -> fire, but not CRITICAL.
    code = (
        "def parse(src):\n"
        '    return compile(src, "<string>", "exec")\n'
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    sev = _sev_for(findings, "MEDUSA-AST-EXEC-001")
    assert sev, "compile(..., 'exec') on a non-literal must still fire"
    assert CRITICAL not in sev


def test_eval_local_var_demoted_below_critical(ast_scanner, tmp_path):
    # parser doing eval(mo.group(1)) on its own match -> fire, but not CRITICAL.
    code = (
        "import re\n"
        "def parse(text):\n"
        "    mo = re.match(r'(.*)', text)\n"
        "    return eval(mo.group(1))\n"
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    sev = _sev_for(findings, "MEDUSA-AST-EXEC-001")
    assert sev and CRITICAL not in sev


def test_exec_tainted_request_fires_critical(ast_scanner, tmp_path):
    code = (
        "from flask import request\n"
        "def run():\n"
        "    exec(request.data)\n"
    )
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert CRITICAL in _sev_for(findings, "MEDUSA-AST-EXEC-001")


def test_eval_tainted_user_input_fires_critical(ast_scanner, tmp_path):
    code = "def run(user_input):\n    return eval(user_input)\n"
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert CRITICAL in _sev_for(findings, "MEDUSA-AST-EXEC-001")


# --------------------------------------------------------------------------- #
# EXEC-001 — LLM/model output is untrusted (OWASP LLM02 insecure output handling)
# --------------------------------------------------------------------------- #
def test_exec_llm_output_attr_fires_critical(ast_scanner, tmp_path):
    # exec of a model-response attribute (result.text) -> CRITICAL, not HIGH.
    code = "def run(result):\n    exec(result.text)\n"
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert CRITICAL in _sev_for(findings, "MEDUSA-AST-EXEC-001")


def test_eval_response_content_fires_critical(ast_scanner, tmp_path):
    code = "def run(response):\n    return eval(response.content)\n"
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert CRITICAL in _sev_for(findings, "MEDUSA-AST-EXEC-001")


def test_exec_llm_response_var_fires_critical(ast_scanner, tmp_path):
    # variable name carrying model output (llm_response) -> CRITICAL.
    code = "def run(llm_response):\n    exec(llm_response)\n"
    findings = _ast_findings(ast_scanner, tmp_path, code)
    assert CRITICAL in _sev_for(findings, "MEDUSA-AST-EXEC-001")


def test_llm_taint_does_not_disturb_benign_getattr_or_import(ast_scanner, tmp_path):
    # The LLM-output taint additions must not make benign literal reflection /
    # imports fire: getattr-with-default stays silent, literal import stays silent.
    code = (
        "import os\n"
        "from importlib import import_module\n"
        'flags = getattr(os, "O_BINARY", 0)\n'
        'mod = import_module("json")\n'
    )
    rules = _ast_rules(ast_scanner, tmp_path, code)
    assert "MEDUSA-AST-REFLECT-001" not in rules
    assert "MEDUSA-AST-DYNIMPORT-001" not in rules


# --------------------------------------------------------------------------- #
# WEB-SSRF — regex, web_security_scanner
# --------------------------------------------------------------------------- #
def test_ssrf_localhost_literal_not_flagged(web_scanner, tmp_path):
    code = _WEB_PREAMBLE + 'host = "127.0.0.1"\ndefault = "localhost"\n'
    assert _web_ssrf(web_scanner, tmp_path, code) == []


def test_ssrf_db_url_localhost_literal_not_flagged(web_scanner, tmp_path):
    code = _WEB_PREAMBLE + 'DATABASE_URL = "postgresql://a:b@localhost:5432/db"\n'
    assert _web_ssrf(web_scanner, tmp_path, code) == []


def test_ssrf_user_input_to_requests_get_fires(web_scanner, tmp_path):
    code = (
        _WEB_PREAMBLE
        + "@app.route('/fetch')\n"
        + "def fetch():\n"
        + "    url = request.args.get('url')\n"
        + "    return requests.get(url).text\n"
    )
    assert HIGH in _web_ssrf(web_scanner, tmp_path, code)


def test_ssrf_fstring_internal_url_fires(web_scanner, tmp_path):
    code = (
        _WEB_PREAMBLE
        + "@app.route('/proxy')\n"
        + "def proxy():\n"
        + "    return requests.get(f\"http://internal/{request.args['path']}\").text\n"
    )
    assert HIGH in _web_ssrf(web_scanner, tmp_path, code)
