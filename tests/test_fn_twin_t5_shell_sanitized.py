#!/usr/bin/env python3
"""T5 — FN twins for `FalsePositiveFilter._check_shell_sanitized`.

The shlex-sanitisation FP suppressor is a *silencer*: every bug in it is a
FALSE NEGATIVE, i.e. a genuine command-injection finding deleted before the
user ever sees it. Two root causes made it forgeable:

1. The rebind / `+=` guard never ran on the case it was written for — the loop
   did `if name in quoted: continue` BEFORE consulting the guard, so a value
   that was quoted once and then rebound to raw input read as sanitised.
2. The lookback was a regex over raw text, so `# url = shlex.quote(url)` in a
   COMMENT — or the same line inside a DOCSTRING — vouched for the sink. An
   attacker can write that comment.

Every FN twin below is a real injection that the filter deleted. The precision
twins are the FP-campaign behaviour that must survive the fix: genuinely
`shlex.quote()`-sanitised commands are the correct defence and must stay
suppressed, including the one-level f-string composition form.
"""

import pytest

from medusa.core.fp_filter import FalsePositiveFilter


def _shell_fp(source: str, needle: str = "os.system", file: str = "") -> bool:
    """True when the filter SUPPRESSES the command-injection finding on `needle`."""
    lines = source.split("\n")
    line_num = next(i for i, line in enumerate(lines, 1) if needle in line)
    finding = {"rule_id": "MCP102", "severity": "HIGH", "line": line_num,
               "issue": "os.system() call - potential command injection"}
    if file:
        finding["file"] = file
    return FalsePositiveFilter(".")._check_shell_sanitized(finding, lines).is_likely_fp


# --------------------------------------------------------------------------- #
# FN twins — a real injection that MUST NOT be suppressed
# --------------------------------------------------------------------------- #

_REBIND = '''\
import os, shlex


def ping(user):
    host = shlex.quote(user)
    host = user
    os.system(f"ping -c1 {host}")
'''

_COMMENT_ONLY = '''\
import os


def fetch(url):
    # url = shlex.quote(url)
    os.system(f"curl -sL {url}")
'''

_DOCSTRING_ONLY = '''\
import os


def fetch(url):
    """Fetch a URL.

    Callers must sanitise first:
        url = shlex.quote(url)
    """
    os.system(f"curl -sL {url}")
'''

_APPEND_RAW = '''\
import os, shlex


def scan(target, extra):
    target = shlex.quote(target)
    target += extra
    os.system(f"nmap {target}")
'''

_QUOTE_PLUS_RAW = '''\
import os, shlex


def scan(target, extra):
    target = shlex.quote(target) + extra
    os.system(f"nmap {target}")
'''

_OTHER_FUNCTION = '''\
import os, shlex


def safe(target):
    target = shlex.quote(target)
    return target


def unsafe(target):
    os.system(f"nmap {target}")
'''

_LOOP_REBIND = '''\
import os, shlex


def scan(targets):
    target = shlex.quote(targets[0])
    for nxt in targets:
        os.system(f"nmap {target}")
        target = nxt
'''

_COMPOSED_REBIND = '''\
import os, shlex


def scan(target, raw):
    target = shlex.quote(target)
    command = f"nmap {target}"
    command = f"nmap {raw}"
    os.system(command)
'''

# The sink line's own trailing comment is attacker-writable text: judging the
# call on `{safe}` from the comment instead of on `command` hides the injection.
_SINK_COMMENT_DECOY = '''\
import os, shlex


def scan(target):
    safe = shlex.quote(target)
    command = f"nmap {target}"
    os.system(command)  # e.g. nmap {safe}
'''


# …and the converse: a `#` INSIDE the command is data. Cutting the line there
# would drop `{frag}` and suppress a command that interpolates it unquoted.
_HASH_IN_COMMAND = '''\
import os, shlex


def fetch(url, frag):
    url = shlex.quote(url)
    os.system(f"curl -sL {url}#{frag}")
'''


@pytest.mark.parametrize("source,label", [
    (_REBIND, "quoted then rebound to the raw parameter"),
    (_HASH_IN_COMMAND, "unquoted value after a `#` inside the command string"),
    (_COMMENT_ONLY, "shlex.quote appears only in a `#` comment"),
    (_DOCSTRING_ONLY, "shlex.quote appears only inside a docstring"),
    (_APPEND_RAW, "quoted then `+=` raw input"),
    (_QUOTE_PLUS_RAW, "quote() concatenated with raw input"),
    (_OTHER_FUNCTION, "the quoting lives in a DIFFERENT function"),
    (_LOOP_REBIND, "rebound to raw input later in the same loop"),
    (_COMPOSED_REBIND, "composed command rebound to an unquoted f-string"),
    (_SINK_COMMENT_DECOY, "a decoy `{quoted}` in the sink line's own comment"),
])
def test_t5_fn_twin_injection_is_not_suppressed(source, label):
    assert not _shell_fp(source), (
        f"FALSE NEGATIVE — {label}: the shell command reaches os.system() with "
        "unsanitised input, so the finding must survive the FP filter")


# The same two forgeries in a source region that does NOT parse as a whole
# (truncated `try:` — exactly the shape the existing pentest-mcp fixtures have).
# The graceful fallback must not become the hole the AST path just closed.
_TRUNCATED_COMMENT = '''\
import os


async def fetch(url):
    try:
        # url = shlex.quote(url)
        os.system(f"curl -sL {url}")
'''

_TRUNCATED_REBIND = '''\
import os, shlex


async def ping(user):
    try:
        host = shlex.quote(user)
        host = user
        os.system(f"ping -c1 {host}")
'''


@pytest.mark.parametrize("source,label", [
    (_TRUNCATED_COMMENT, "commented-out quote in an unparseable region"),
    (_TRUNCATED_REBIND, "quote-then-rebind in an unparseable region"),
])
def test_t5_fn_twin_survives_in_unparseable_region(source, label):
    assert not _shell_fp(source), (
        f"FALSE NEGATIVE — {label}: a region that fails to parse must fail "
        "CLOSED (keep the finding), never suppress on unverified text")


# --------------------------------------------------------------------------- #
# Precision twins — the FP-campaign behaviour that must survive the fix
# --------------------------------------------------------------------------- #

_GENUINE = '''\
import os, shlex


def ping(user):
    host = shlex.quote(user)
    os.system(f"ping -c1 {host}")
'''

_COMPOSED = '''\
import os, shlex


def gobuster(url, wordlist):
    url = shlex.quote(url)
    wordlist = shlex.quote(wordlist)
    command = f"gobuster dir -u {url} -w {wordlist} -o /tmp/out.txt"
    os.system(command)
'''

_MULTI_INLINE = '''\
import os, shlex


def curl(url, headers, out):
    url = shlex.quote(url)
    headers = shlex.quote(headers)
    out = shlex.quote(out)
    os.system(f"curl -H {headers} -o {out} {url}")
'''

_REQUOTE = '''\
import os, shlex


def fetch(request):
    url = request.args.get("url")
    url = shlex.quote(url)
    os.system(f"curl -sL {url}")
'''

_ALIASED_IMPORT = '''\
import os
from shlex import quote


def ping(user):
    host = quote(user)
    os.system(f"ping -c1 {host}")
'''

_MODULE_ALIAS = '''\
import os
import shlex as sh


def ping(user):
    host = sh.quote(user)
    os.system(f"ping -c1 {host}")
'''


@pytest.mark.parametrize("source,label", [
    (_GENUINE, "single shlex.quote() binding interpolated inline"),
    (_COMPOSED, "one-level f-string composition, every value quoted"),
    (_MULTI_INLINE, "three interpolated names, all quoted"),
    (_REQUOTE, "raw read then re-bound through shlex.quote()"),
    (_ALIASED_IMPORT, "`from shlex import quote`"),
    (_MODULE_ALIAS, "`import shlex as sh`"),
])
def test_t5_precision_twin_stays_suppressed(source, label):
    assert _shell_fp(source), (
        f"FALSE BLOCK — {label}: shlex.quote() IS the documented shell-injection "
        "defence; flagging it punishes code for defending itself")


# --------------------------------------------------------------------------- #
# Graceful degradation — never crash, never suppress on what we cannot read
# --------------------------------------------------------------------------- #

_NOT_PYTHON = '''\
const shlex = require("shlex");

function run(target) {
  target = shlex.quote(target);
  const cmd = `nmap ${target}`;
  os.system(cmd);
}
'''

_UNTOKENIZABLE = '''\
import os, shlex


def run(target):
    target = shlex.quote(target)
    note = """unterminated
    os.system(f"nmap {target}")
'''


@pytest.mark.parametrize("source,label,file", [
    (_NOT_PYTHON, "JavaScript source", "run.js"),
    (_UNTOKENIZABLE, "source that cannot even be tokenised", "run.py"),
])
def test_t5_unparseable_context_is_safe_and_silent(source, label, file):
    # No exception, and no suppression: we could not prove sanitisation.
    assert not _shell_fp(source, file=file), (
        f"{label}: sanitisation that cannot be verified must not suppress")


def test_t5_empty_and_degenerate_contexts_do_not_crash():
    f = FalsePositiveFilter(".")
    finding = {"rule_id": "MCP102", "severity": "HIGH", "line": 3,
               "issue": "os.system() call - potential command injection"}
    assert f._check_shell_sanitized(finding, []).is_likely_fp is False
    assert f._check_shell_sanitized(finding, ["", "", ""]).is_likely_fp is False
    assert f._check_shell_sanitized({**finding, "line": 0}, ["x"]).is_likely_fp is False
    assert f._check_shell_sanitized({**finding, "line": 999}, ["x"]).is_likely_fp is False


# --- cache identity ---------------------------------------------------------
# The parsed-source cache added with this fix was keyed by file PATH alone, on
# the premise that one path means one content for the life of a filter instance.
# That premise fails wherever a single instance sees more than one tree — the MCP
# gatekeeper vets repo after repo in a long-lived process, and `scan --git`
# reuses temp clone dirs. The consequence is the exact FN class this whole file
# exists to prevent: repo B's `src/util.py` judged on repo A's parse, so a
# genuine injection in B is suppressed by A's `shlex.quote`.

_REBOUND = """def run(user):
    host = shlex.quote(user)
    host = user
    os.system(f"ping {host}")
"""
_GENUINE = """def run(user):
    host = shlex.quote(user)
    os.system(f"ping {host}")
"""


def test_t5_cache_does_not_leak_between_files_sharing_a_path():
    """Same path, different content, one instance — each judged on its OWN code."""
    f = FalsePositiveFilter(".")

    def verdict(source):
        lines = source.split("\n")
        line_num = next(i for i, ln in enumerate(lines, 1) if "os.system" in ln)
        return f.filter_finding(
            {"rule_id": "MCP102", "severity": "HIGH", "line": line_num,
             "file": "src/util.py",  # SAME path both times — the collision
             "issue": "os.system() call - potential command injection"},
            lines).is_likely_fp

    # Order matters: the rebound (unsuppressed) analysis is cached first, then a
    # genuinely sanitised file at the same path must NOT inherit it, and vice versa.
    assert verdict(_REBOUND) is False, "rebound-to-raw must not be suppressed"
    assert verdict(_GENUINE) is True, (
        "a genuinely quoted file was judged on a DIFFERENT file's parse "
        "(cache keyed by path, not content)")
    assert verdict(_REBOUND) is False, (
        "a real injection was suppressed by the previous file's parse "
        "(cache keyed by path, not content)")


def test_t5_cache_still_memoises_identical_content():
    """The cache must still do its job: same content analysed once, not per finding."""
    f = FalsePositiveFilter(".")
    lines = _GENUINE.split("\n")
    line_num = next(i for i, ln in enumerate(lines, 1) if "os.system" in ln)
    finding = {"rule_id": "MCP102", "severity": "HIGH", "line": line_num,
               "file": "src/util.py",
               "issue": "os.system() call - potential command injection"}
    assert f.filter_finding(finding, lines).is_likely_fp is True
    before = len(f._shell_scope_cache)
    for _ in range(25):
        assert f.filter_finding(finding, lines).is_likely_fp is True
    assert len(f._shell_scope_cache) == before, "identical content re-cached per finding"
