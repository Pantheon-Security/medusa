"""Gate for #24b/#6 — a cookie/token PARSER must not be flagged as hardcoded credentials
(PC001 handover 2026-07-22-fp-realworld #6).

Ground truth (agent-reach cli.py:1159):
    if "auth_token=" in value and "ct0=" in value:   # membership test — PARSING
MEDUSA-CGS-SCAN-039 pattern 1 matched `token=" ... "` spanning the line (the `.{3,100}`
between quotes swallowed the code ` in value and `), reading it as `token = "<secret>"`.
A real hardcoded secret VALUE is a contiguous token (`"sk-proj-abc"`), never code with
spaces. Fix: the captured value is `[^\s'"]{3,100}` (contiguous, no whitespace/quote), so
the parser membership-test stops matching while a real hardcoded secret still fires.
"""
import re

import yaml
from pathlib import Path

RULE_FILE = (Path(__file__).resolve().parent.parent / "medusa" / "rules" /
             "code_gen_security" / "code_gen_security_2025_scanner.yaml")


def _pattern0(rule_id):
    doc = yaml.safe_load(RULE_FILE.read_text())
    rules = doc["rules"] if isinstance(doc, dict) else doc
    for r in rules:
        if isinstance(r, dict) and r.get("id") == rule_id:
            return r["patterns"][0]
    raise AssertionError(f"{rule_id} not found")


def test_cookie_parser_not_flagged():
    pat = _pattern0("MEDUSA-CGS-SCAN-039")
    for benign in ('if "auth_token=" in value and "ct0=" in value:',
                   'if part.startswith("auth_token="):',
                   'value.replace("token=", "").split()'):
        assert not re.search(pat, benign), f"parser membership-test must NOT be flagged: {benign!r}"


def test_real_hardcoded_secret_still_flagged():
    pat = _pattern0("MEDUSA-CGS-SCAN-039")
    for real in ('api_key = "sk-proj-abc123def456ghi"',
                 "password = 'hunter2SecretPass'",
                 'token="ghp_ABCDEFGHIJKLMNOP0123456"'):
        assert re.search(pat, real), f"real hardcoded secret must still fire: {real!r}"


# --- WEB-AUTH-001 (same cookie-parser FP class, web_security rule file) -------- #
_WEB_RULE_FILE = (Path(__file__).resolve().parent.parent / "medusa" / "rules" /
                  "web_security" / "python_web_security.yaml")


def _web_auth_patterns():
    doc = yaml.safe_load(_WEB_RULE_FILE.read_text())
    rules = doc["rules"] if isinstance(doc, dict) else doc
    for r in rules:
        if isinstance(r, dict) and r.get("id") == "WEB-AUTH-001":
            return r["patterns"]
    raise AssertionError("WEB-AUTH-001 not found")


def test_web_auth_parser_not_flagged():
    pats = _web_auth_patterns()
    assert not any(re.search(p, 'if "auth_token=" in value and "ct0=" in value:') for p in pats), \
        "WEB-AUTH-001 must not flag the cookie parser membership-test"


def test_web_auth_real_secret_still_flagged():
    pats = _web_auth_patterns()
    for real in ('$api_key = "sk_live_realkey9876543210";',
                 'password = "hunter2SecretPass"',
                 'token = "ghp_ABCDEFGHIJKLMNOP0123456"'):
        assert any(re.search(p, real) for p in pats), f"real secret must still fire: {real!r}"
