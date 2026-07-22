"""Gate for #23 — os-command-injection must not fire on a list-arg subprocess whose
variable is merely named `cmd`/`command` (PC001 handover 2026-07-22-fp-realworld #3/#4).

Ground truth (agent-reach cli.py:715):
    for tool, cmd in [("pipx", ["pipx","install","twitter-cli"]), ...]:
        subprocess.run(cmd, capture_output=True, ...)   # cmd is a LIST, no shell=True
MEDUSA-CODEGEN-SCAN-004 pattern 3 flagged it CRITICAL purely because the arg variable is
named `cmd`. Passing argv as a list is the CORRECT anti-injection pattern. Fix: drop the
generic list-variable names `cmd|command` from that bare-name pattern; keep the genuine
user-data indicators (user|input|request|param) and the shell=True / os.system patterns,
so real command injection still fires.
"""
import re

import yaml
from pathlib import Path

RULE_FILE = (Path(__file__).resolve().parent.parent / "medusa" / "rules" /
             "code_gen_security" / "code_gen_security_2025_scanner.yaml")


def _rule(rule_id):
    doc = yaml.safe_load(RULE_FILE.read_text())
    rules = doc["rules"] if isinstance(doc, dict) else doc
    for r in rules:
        if isinstance(r, dict) and r.get("id") == rule_id:
            return r
    raise AssertionError(f"{rule_id} not found")


def _fires(rule, text):
    return any(re.search(p, text) for p in rule["patterns"])


def test_listarg_subprocess_named_cmd_not_flagged():
    rule = _rule("MEDUSA-CODEGEN-SCAN-004")
    for benign in ("subprocess.run(cmd, capture_output=True, timeout=120)",
                   "subprocess.run(command, check=True)",
                   'subprocess.run(["pipx", "install", "twitter-cli"])'):
        assert not _fires(rule, benign), f"list-arg subprocess must NOT be flagged: {benign!r}"


def test_real_command_injection_still_flagged():
    rule = _rule("MEDUSA-CODEGEN-SCAN-004")
    for real in ("subprocess.run(user_input)",
                 "subprocess.run(request.args['x'])",
                 'os.system("ping " + user_input)',
                 'subprocess.run(f"ls {user}", shell=True)'):
        assert _fires(rule, real), f"real command injection must still fire: {real!r}"
