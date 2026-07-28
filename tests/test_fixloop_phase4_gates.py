"""Phase-4 LOW/NIT gates for the install-gate / vet trust-surface remediation.

Born-RED where a behaviour changed (CR-037 mktemp fail-closed, CR-038 clone `--` +
backup hardening + codex-TOML data-loss, CR-039 single score call, CR-040 SLEEP SQLi
widen). CR-041 is a pure refactor — asserted by the existing behaviour suites plus a
smoke check that the extracted helper exists and both installers agree.

Traceability: .claude-review/REMEDIATION.md Phase 4.
Scope note: CR-040 intentionally applies ONLY the SLEEP widen. The SSRF localhost,
`{message}` restore, and has_ml_context loosening were reassessed as FP regressions
on this anti-cry-wolf branch and deliberately NOT applied.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from medusa.hooks import install
from medusa.core import git_clone

REPO = Path(__file__).resolve().parents[1]
HOOK = Path(install.__file__).with_name("claude_pretooluse.sh")
_BASH = os.environ.get("BASH") or "/bin/bash"
_PY3_DIR = os.path.dirname(os.popen("command -v python3").read().strip() or "/usr/bin/python3")


def _need_git():
    import shutil
    if not shutil.which("git"):
        pytest.skip("git not on PATH")


# ---- CR-037 — mktemp failure fails CLOSED + a loud bypass audit line ----------
def test_cr037_mktemp_failure_blocks(tmp_path):
    stub_dir = tmp_path / "b"
    stub_dir.mkdir()
    med = stub_dir / "medusa"
    med.write_text("#!/usr/bin/env bash\nexit 0\n")
    med.chmod(med.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ,
               TMPDIR="/nonexistent/definitely-not-here",
               PATH=f"{stub_dir}{os.pathsep}{_PY3_DIR}:/usr/bin:/bin",
               MEDUSA_BIN=str(med))
    r = subprocess.run([_BASH, str(HOOK)],
                       input='{"tool_input":{"command":"git clone https://github.com/ok/repo"}}',
                       capture_output=True, text=True, env=env)
    assert r.returncode == 2
    assert "fail closed" in r.stderr.lower()


def test_cr037_bypass_audit_line_present():
    txt = HOOK.read_text()
    assert "MEDUSA VET BYPASSED" in txt   # loud, greppable audit banner


# ---- CR-038 — clone `--` guard, backup hardening, codex-TOML data-loss --------
def test_cr038_clone_uses_double_dash():
    src = Path(git_clone.__file__).read_text()
    assert '"--", url, tmp_dir' in src   # option-terminator before the URL


def test_cr038_backup_skips_symlink_and_is_0600(tmp_path):
    real = tmp_path / "real.json"
    real.write_text('{"k": 1}')
    # regular file -> backup created 0600
    install._backup(real)
    baks = list(tmp_path.glob("real.json.medusa.bak.*"))
    assert baks, "a regular file must be backed up"
    assert (baks[0].stat().st_mode & 0o777) == 0o600
    # symlink -> NOT followed/backed up
    target = tmp_path / "secret.txt"
    target.write_text("secret")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    install._backup(link)
    assert not list(tmp_path.glob("link.json.medusa.bak.*")), "a symlink must not be backed up"


def test_cr038_codex_corrupt_toml_refuses(tmp_path):
    if install.tomllib is None:
        pytest.skip("tomllib unavailable")
    cfg = tmp_path / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("this is = not valid = toml [[[\n")
    with pytest.raises(install.ConfigParseError):
        install.install_codex_mcp(tmp_path)
    # the user's (unparseable) file is preserved, not overwritten with just medusa
    assert "not valid" in cfg.read_text()


# ---- CR-039 — calculate_security_score computed ONCE per report ---------------
def test_cr039_score_computed_once(tmp_path):
    from medusa.core.reporter import MedusaReportGenerator
    gen = MedusaReportGenerator(output_dir=tmp_path)
    calls = {"n": 0}
    real = gen.calculate_security_score

    def _counting(findings):
        calls["n"] += 1
        return real(findings)

    gen.calculate_security_score = _counting
    gen.generate_json_report({"findings": [], "files_scanned": 1},
                             output_path=tmp_path / "r.json")
    assert calls["n"] == 1, f"score should be computed once, was {calls['n']}"


# ---- CR-040 — SLEEP SQLi widen recognises `)` and `||` injection prefixes ------
def _sleep_regex():
    rule = (REPO / "medusa" / "rules" / "inference_infrastructure"
            / "inference_infrastructure_scanner.yaml").read_text()
    for line in rule.splitlines():
        if "SLEEP" in line and line.strip().startswith("- "):
            return re.compile(line.strip()[2:])
    raise AssertionError("SLEEP SQLi pattern not found")


def test_cr040_sleep_sqli_paren_and_concat_prefixes():
    rx = _sleep_regex()
    assert rx.search("admin')SLEEP(5)--"), "`)SLEEP(` injection form must match"
    assert rx.search("x'||SLEEP(5)||'"), "`||SLEEP(` injection form must match"
    # unchanged forms still match
    assert rx.search("1 AND SLEEP(5)")
    assert rx.search("'; WAITFOR DELAY '0:0:5'")


# ---- CR-041 — MCP-installer dedup helper exists and both installers agree ------
def test_cr041_install_medusa_server_helper(tmp_path):
    _need_git()
    assert hasattr(install, "_install_medusa_server")
    install.install_claude_mcp(tmp_path)
    install.install_cursor_mcp(tmp_path)
    claude = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]["medusa"]
    cursor = json.loads((tmp_path / ".cursor" / "mcp.json").read_text())["mcpServers"]["medusa"]
    assert claude == cursor == {"command": "medusa", "args": ["mcp"]}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
