"""Gate for FX-H03 (#25b) — the FP filter must recognize a sensitive host/IP inside a
DENYLIST literal as defensive-code DATA (PC001 handover 2026-07-22-fp-realworld #2 /
suggestion "context-gate matches whose token sits inside a blocklist/denylist literal").

The handover's exact case: agent-reach's `_BLOCKED_HOSTS = { "metadata.google.internal", ... }`
(an SSRF DEFENSE denylist) was flagged as an SSRF vuln, and the FP filter returned
is_likely_fp=false / confidence 0.0 — the _PATTERN_LITERAL check only recognized
`_PATTERNS`/`_SIGNATURES`-suffixed names and rejected any leading-underscore name. Now it
matches a collection whose name (optional leading `_`) carries a signature/denylist token
(BLOCK/DENY/ALLOW/HOST/DOMAIN/ORIGIN/PATTERN/…). FN-safety: the same host/IP in a real
fetch call (executable logic, not a bare list element) is NOT suppressed.
"""
from medusa.core.fp_filter import FalsePositiveFilter, FPReason


def _check(context_lines, finding_line):
    """Run the pattern-literal check with the given source context."""
    filt = FalsePositiveFilter()
    finding = {"file": "agent_reach/transcribe.py", "line": finding_line,
               "rule_id": "AGENT_SSRF_INTERNAL_METADATA_FETCH", "severity": "CRITICAL",
               "message": "SSRF internal metadata fetch"}
    return filt._check_pattern_literal(finding, context_lines)


DENYLIST_SRC = [
    "import socket",                                  # 1
    "",                                              # 2
    "_BLOCKED_HOSTS = {",                            # 3
    '    "169.254.169.254",',                        # 4
    '    "metadata.google.internal",',              # 5
    '    "metadata.azure.com",',                     # 6
    "}",                                             # 7
]


def test_denylist_member_is_suppressed():
    # the metadata host on line 5 is a denylist datum -> FP (PATTERN_LITERAL)
    r = _check(DENYLIST_SRC, 5)
    assert r.is_likely_fp, "a host inside _BLOCKED_HOSTS must be recognized as denylist data"
    assert r.reason == FPReason.PATTERN_LITERAL


def test_leading_underscore_blocklist_suppressed():
    src = ["_BLOCKLIST = [", '    "169.254.169.254",', "]"]
    assert _check(src, 2).is_likely_fp, "leading-underscore _BLOCKLIST must be recognized"


def test_denyside_domains_and_hosts_recognized():
    # DENY-side defense-data constants keep the recognition (their BLOCKED*/DENIED*
    # token remains in _PATTERN_LITERAL_NAME_TOKENS after CR-017).
    for name in ("BLOCKED_DOMAINS", "DENIED_HOSTS"):
        src = [f"{name} = {{", '    "metadata.google.internal",', "}"]
        assert _check(src, 2).is_likely_fp, f"{name} must be recognized as a denylist"


def test_cr017_allowside_constants_not_suppressed():
    # CR-017: the ALLOW-side network tokens (ALLOWED/ALLOWLIST/WHITELIST/HOST/
    # DOMAIN/ORIGIN) were REMOVED. A permissive allowlist member — e.g. the `'*'`
    # in `ALLOWED_ORIGINS = ['*']` / `CORS_ALLOWED_HOSTS = ['*']` — IS the
    # vulnerability, not denylist DATA, so it must NOT be suppressed.
    for name in ("ALLOWED_ORIGINS", "ALLOWED_HOSTS", "CORS_WHITELIST"):
        src = [f"{name} = {{", '    "*",', "}"]
        assert not _check(src, 2).is_likely_fp, f"{name} must NOT be suppressed (CR-017)"


# --- FN-safety: a real fetch of the metadata IP is NOT suppressed ------------- #
def test_real_metadata_fetch_not_suppressed():
    src = [
        "import requests",
        "def leak():",
        '    r = requests.get("http://169.254.169.254/latest/meta-data/")',  # line 3 - real SSRF
        "    return r.text",
    ]
    r = _check(src, 3)
    assert not r.is_likely_fp, "a real fetch of the metadata IP must NOT be suppressed"


def test_non_denylist_constant_not_suppressed():
    # a generic config constant is not a signature/denylist -> a real leak in it still counts
    src = ["ORIGINAL_CONFIG = {", '    "169.254.169.254",', "}"]
    assert not _check(src, 2).is_likely_fp, "a non-denylist-named constant must not be suppressed"
