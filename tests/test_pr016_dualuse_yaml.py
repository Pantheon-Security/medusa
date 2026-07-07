#!/usr/bin/env python3
"""
Precision tests for PR-016 dual-use YAML rule tightening.

A batch of curated WEB-*/SAST-*/MEDUSA-OUTPUT-* rules fired as false positives
on clean third-party code (measured on black / jinja / flask / typer / starlette
/ requests / click in DEFAULT scan mode). This pins the asymmetric behaviour for
each: the benign construct no longer fires (or is demoted off CRITICAL for the
dual-use ones), while a crafted REAL positive still fires at a proportionate
severity.

All tests drive the REAL scan path — code written to a .py file and scanned by
WebSecurityScanner.scan (the scanner that owns the WEB-/SAST- prefixes and the
sql_injection / deserialization categories these rules live under). Gated rules
(WEB-SSRF/WEB-AUTH/WEB-REDIR) only fire in genuine web context, so the crafted
files carry a `flask` import — the same condition a real handler satisfies.

Rules covered:
  MEDUSA-OUTPUT-SQL-003, SAST-ENV-001, WEB-CRYPTO-001, SAST-CRYPTO-003,
  WEB-DESER-001, SAST-DESER-001 (+WEB-DESER-003/SAST-DESER-003), WEB-REDIR-002,
  WEB-SSRF-003, WEB-AUTH-002, WEB-LOG-001.
"""

from pathlib import Path

from medusa.scanners.web_security_scanner import WebSecurityScanner


# `flask` token → has_web_context() classifies the file as web code, so the
# context-gated WEB-SSRF / WEB-AUTH / WEB-REDIR rules are in play.
_HEADER = "from flask import Flask, request\nimport requests\napp = Flask(__name__)\n\n"


def _scan(tmp_path: Path, name: str, body: str):
    fp = tmp_path / name
    fp.write_text(_HEADER + body, encoding="utf-8")
    return WebSecurityScanner().scan(fp).issues


def _ids(issues):
    return {i.rule_id for i in issues}


def _sevs(issues, rule_id):
    return {i.severity.value for i in issues if i.rule_id == rule_id}


# ── MEDUSA-OUTPUT-SQL-003 — plain comparisons are not SQL ─────────────────────

def test_sql003_plain_comparison_does_not_fire(tmp_path):
    body = (
        "def wrap(word, total_length, max_length):\n"
        "    if total_length > max_length:\n"
        "        return word\n"
        '    if word[-1] == ".":\n'
        "        return word\n"
    )
    assert "MEDUSA-OUTPUT-SQL-003" not in _ids(_scan(tmp_path, "utils.py", body)), (
        "plain numeric/string comparisons must not trip SQL-003"
    )


def test_sql003_concat_injection_fires(tmp_path):
    body = 'def q(user_id):\n    query = "SELECT * FROM t WHERE id=" + user_id\n    return query\n'
    issues = _scan(tmp_path, "dao.py", body)
    assert "MEDUSA-OUTPUT-SQL-003" in _ids(issues), (
        "SQL string concatenated with a variable must still fire SQL-003"
    )
    assert "CRITICAL" in _sevs(issues, "MEDUSA-OUTPUT-SQL-003")


def test_sql003_union_select_still_fires(tmp_path):
    body = 'def q(user_input):\n    run(user_input + " UNION SELECT * FROM users")\n'
    assert "MEDUSA-OUTPUT-SQL-003" in _ids(_scan(tmp_path, "dao2.py", body)), (
        "classic UNION SELECT payload must still fire SQL-003"
    )


# ── SAST-ENV-001 — reading/writing env vars is normal ────────────────────────

def test_env001_plain_environ_access_does_not_fire(tmp_path):
    body = (
        "import os\n"
        "def cfg(key, value):\n"
        "    os.environ[key] = value\n"
        "    value = os.environ[key]\n"
        "    return value\n"
    )
    assert "SAST-ENV-001" not in _ids(_scan(tmp_path, "config.py", body)), (
        "plain os.environ read/write must not trip SAST-ENV-001"
    )


def test_env001_environ_to_shell_sink_fires(tmp_path):
    body = "import os\ndef run():\n    os.system(os.environ['CMD'])\n"
    issues = _scan(tmp_path, "runner.py", body)
    assert "SAST-ENV-001" in _ids(issues), (
        "env var flowing into os.system must still fire SAST-ENV-001"
    )
    assert "HIGH" in _sevs(issues, "SAST-ENV-001")


# ── WEB-CRYPTO-001 / SAST-CRYPTO-003 — usedforsecurity=False is explicit ──────

def test_crypto_usedforsecurity_false_does_not_fire(tmp_path):
    body = (
        "import hashlib\n"
        "def etag(x):\n"
        "    return hashlib.md5(x, usedforsecurity=False).hexdigest()\n"
        "def tag2(y):\n"
        "    return hashlib.sha1(y, usedforsecurity=False).hexdigest()\n"
    )
    ids = _ids(_scan(tmp_path, "cache.py", body))
    assert "WEB-CRYPTO-001" not in ids, "md5/sha1 with usedforsecurity=False must not fire WEB-CRYPTO-001"
    assert "SAST-CRYPTO-003" not in ids, "md5 with usedforsecurity=False must not fire SAST-CRYPTO-003"


def test_crypto_md5_password_still_fires(tmp_path):
    body = "import hashlib\ndef h(password):\n    return hashlib.md5(password).hexdigest()\n"
    issues = _scan(tmp_path, "auth.py", body)
    assert "WEB-CRYPTO-001" in _ids(issues), (
        "hashlib.md5 without usedforsecurity=False must still fire WEB-CRYPTO-001"
    )
    assert "HIGH" in _sevs(issues, "WEB-CRYPTO-001")


# ── WEB-DESER-001 / SAST-DESER-001 — bare pickle is dual-use (demote) ─────────

def test_deser_bare_pickle_demoted_to_medium(tmp_path):
    body = "import pickle\ndef load(f):\n    return pickle.load(f)\n"
    issues = _scan(tmp_path, "grammar_cache.py", body)
    # Still detected...
    assert "WEB-DESER-001" in _ids(issues) or "SAST-DESER-001" in _ids(issues), (
        "bare pickle.load must still be detected"
    )
    # ...but NOT at CRITICAL, and no untrusted-source escalation rule fires.
    assert "CRITICAL" not in _sevs(issues, "WEB-DESER-001")
    assert "CRITICAL" not in _sevs(issues, "SAST-DESER-001")
    assert "WEB-DESER-003" not in _ids(issues)
    assert "SAST-DESER-003" not in _ids(issues)


def test_deser_untrusted_source_stays_critical(tmp_path):
    body = "import pickle\ndef load():\n    return pickle.loads(request.data)\n"
    issues = _scan(tmp_path, "handler.py", body)
    escalated = _sevs(issues, "WEB-DESER-003") | _sevs(issues, "SAST-DESER-003")
    assert "CRITICAL" in escalated, (
        "pickle.loads(request.data) from an untrusted source must fire CRITICAL"
    )


# ── WEB-REDIR-002 — framework redirect helper is not a vuln ───────────────────

def test_redir002_framework_helper_does_not_fire(tmp_path):
    body = "def login(next_url):\n    return RedirectResponse(url=next_url)\n"
    assert "WEB-REDIR-002" not in _ids(_scan(tmp_path, "auth_views.py", body)), (
        "RedirectResponse(url=next_url) framework helper must not fire WEB-REDIR-002"
    )


def test_redir_user_controlled_still_fires(tmp_path):
    body = "def go():\n    return redirect(request.args['next'])\n"
    issues = _scan(tmp_path, "views.py", body)
    ids = _ids(issues)
    assert ("WEB-REDIR-001" in ids) or ("WEB-REDIR-002" in ids), (
        "redirect(request.args['next']) must still be detected as an open redirect"
    )


# ── WEB-SSRF-003 — a scheme check is the OPPOSITE of SSRF ──────────────────────

def test_ssrf003_scheme_check_does_not_fire(tmp_path):
    body = (
        "def fetch(url):\n"
        '    if url.lower().startswith("https"):\n'
        "        return requests.get(url).text\n"
    )
    assert "WEB-SSRF-003" not in _ids(_scan(tmp_path, "client.py", body)), (
        "url.startswith('https') scheme check must not fire WEB-SSRF-003"
    )


def test_ssrf003_host_prefix_allowlist_fires(tmp_path):
    body = (
        "def fetch(url):\n"
        '    if url.startswith("https://internal.corp"):\n'
        "        return requests.get(url).text\n"
    )
    assert "WEB-SSRF-003" in _ids(_scan(tmp_path, "client2.py", body)), (
        "bypassable host-prefix allowlist must still fire WEB-SSRF-003"
    )


# ── WEB-AUTH-002 — setting a proxy auth header is normal client behaviour ─────

def test_auth002_proxy_auth_header_does_not_fire(tmp_path):
    body = (
        "def prep(headers, username, password):\n"
        '    headers["Proxy-Authorization"] = _basic_auth_str(username, password)\n'
        "    return headers\n"
    )
    assert "WEB-AUTH-002" not in _ids(_scan(tmp_path, "adapters.py", body)), (
        "setting Proxy-Authorization via _basic_auth_str must not fire WEB-AUTH-002"
    )


def test_auth002_literal_basic_credentials_still_fire(tmp_path):
    body = 'HEADERS = {"Authorization": "Basic dXNlcjpzM2NyZXRwYXNzd29yZA=="}\n'
    assert "WEB-AUTH-002" in _ids(_scan(tmp_path, "leak.py", body)), (
        "a literal Basic <base64> credential header must still fire WEB-AUTH-002"
    )


# ── WEB-LOG-001 — print in a teaching example is not a logging call ───────────

def test_log001_print_password_does_not_fire(tmp_path):
    body = "def demo(password):\n    print(f'Your password: {password}')\n"
    assert "WEB-LOG-001" not in _ids(_scan(tmp_path, "tutorial.py", body)), (
        "print(...) in an example must not fire WEB-LOG-001"
    )


def test_log001_logging_password_still_fires(tmp_path):
    body = "import logging\ndef h(password):\n    logging.info('user password=%s', password)\n"
    assert "WEB-LOG-001" in _ids(_scan(tmp_path, "svc.py", body)), (
        "logging a password via logging.info must still fire WEB-LOG-001"
    )
