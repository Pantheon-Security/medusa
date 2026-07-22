"""Gate for #21 — the PreToolUse hook's secrets check (PC001 handover 2026-07-22-hook-fp Bonus).

The old line `medusa secrets scan || block` was DEAD: no --exit-code (so it returned 0
even on a detection -> never blocked) and it scanned $HOME chat/shell history, not the
install target. Re-scoped (Ross's call) to scan the install COMMAND STRING with
--exit-code: a credential embedded in the command (a token in a clone URL) now blocks;
a clean install command still passes.

Drives the real installed hook via its stdin JSON contract, so it exercises the exact
shell path Claude Code runs. Skips if `medusa` isn't on PATH.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "medusa" / "hooks" / "claude_pretooluse.sh"


def _run_hook(command: str):
    payload = json.dumps({"tool_input": {"command": command}})
    return subprocess.run(["bash", str(HOOK)], input=payload,
                          capture_output=True, text=True)


pytestmark = pytest.mark.skipif(shutil.which("medusa") is None,
                                reason="medusa CLI not on PATH")


def test_hook_blocks_token_embedded_in_clone_url():
    # a real-looking token in the clone URL -> secrets detection -> BLOCK (exit 2)
    cmd = ("git clone https://user:ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
           "@github.com/x/y.git")
    r = _run_hook(cmd)
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "credential" in r.stderr.lower() or "secret" in r.stderr.lower()


def test_hook_allows_clean_install_command():
    # no embedded secret + a benign (non-resolving) URL vet must not FP-block here;
    # use a bypass so the URL-vet network call can't flake the assertion — we are
    # asserting the SECRETS line specifically does not block a clean command.
    import os
    env = dict(os.environ, MEDUSA_HOOK_BYPASS="1")
    payload = json.dumps({"tool_input": {"command": "git clone https://github.com/acme/app.git"}})
    r = subprocess.run(["bash", str(HOOK)], input=payload, capture_output=True,
                       text=True, env=env)
    assert r.returncode == 0, (r.returncode, r.stderr)


def test_non_install_command_untouched():
    r = _run_hook("ls -la")
    assert r.returncode == 0, (r.returncode, r.stderr)
