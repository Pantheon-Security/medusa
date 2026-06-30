"""Real-path tests for the MEDUSA hooks + MCP installer (Lane B).

Each writer is exercised against a tmp base dir and checked for: valid output
format, idempotency (run twice -> one MEDUSA entry), merge that preserves a
pre-seeded unrelated key/server, and the documented contract (executable
pre-commit referencing `medusa secrets`, a Claude PreToolUse Bash hook calling
medusa). No scanning is performed, so these stay fast.
"""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

import pytest

from medusa.hooks import install


# --------------------------------------------------------------------------- #
# Claude PreToolUse hook
# --------------------------------------------------------------------------- #
def test_claude_hook_valid_and_contract(tmp_path: Path):
    path = install.install_claude_hook(tmp_path)
    assert path == tmp_path / ".claude" / "settings.json"

    data = json.loads(path.read_text())  # valid JSON
    pre = data["hooks"]["PreToolUse"]
    assert isinstance(pre, list)

    medusa_entries = [
        e
        for e in pre
        if e.get("matcher") == "Bash"
        and any("medusa" in h.get("command", "") for h in e.get("hooks", []))
    ]
    assert len(medusa_entries) == 1
    cmd = medusa_entries[0]["hooks"][0]
    assert cmd["type"] == "command"
    assert "medusa scan --git" in cmd["command"]


def test_claude_hook_idempotent(tmp_path: Path):
    install.install_claude_hook(tmp_path)
    install.install_claude_hook(tmp_path)
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    pre = data["hooks"]["PreToolUse"]
    medusa_entries = [
        e
        for e in pre
        if any("medusa" in h.get("command", "") for h in e.get("hooks", []))
    ]
    assert len(medusa_entries) == 1


def test_claude_hook_merge_preserves_existing(tmp_path: Path):
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "model": "claude-opus-4-8",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Write",
                            "hooks": [{"type": "command", "command": "echo other"}],
                        }
                    ]
                },
            }
        )
    )

    install.install_claude_hook(tmp_path)
    data = json.loads(settings_path.read_text())

    assert data["model"] == "claude-opus-4-8"  # unrelated top-level key kept
    pre = data["hooks"]["PreToolUse"]
    # original Write hook still present + our Bash hook added
    assert any(e.get("matcher") == "Write" for e in pre)
    assert any(e.get("matcher") == "Bash" for e in pre)


# --------------------------------------------------------------------------- #
# Git pre-commit
# --------------------------------------------------------------------------- #
def test_pre_commit_executable_and_references_secrets(tmp_path: Path):
    path = install.install_pre_commit(tmp_path)
    assert path == tmp_path / ".git" / "hooks" / "pre-commit"
    assert os.access(path, os.X_OK)  # executable
    content = path.read_text()
    assert "medusa secrets" in content
    assert "exit 1" in content  # blocks the commit


def test_pre_commit_idempotent(tmp_path: Path):
    install.install_pre_commit(tmp_path)
    install.install_pre_commit(tmp_path)
    content = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
    assert content.count(install._MARKER_BEGIN) == 1
    assert content.count("medusa secrets scan") == 1


def test_pre_commit_preserves_existing_hook(tmp_path: Path):
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True)
    hook_path.write_text("#!/bin/sh\necho 'existing project hook'\n")

    install.install_pre_commit(tmp_path)
    content = hook_path.read_text()
    assert "existing project hook" in content  # not clobbered
    assert "medusa secrets" in content
    assert os.access(hook_path, os.X_OK)


# --------------------------------------------------------------------------- #
# Cursor MCP
# --------------------------------------------------------------------------- #
def test_cursor_mcp_valid_and_idempotent(tmp_path: Path):
    path = install.install_cursor_mcp(tmp_path)
    install.install_cursor_mcp(tmp_path)
    assert path == tmp_path / ".cursor" / "mcp.json"

    data = json.loads(path.read_text())  # valid JSON
    medusa = data["mcpServers"]["medusa"]
    assert medusa["command"] == "medusa"
    assert medusa["args"] == ["mcp"]
    # idempotent: exactly one medusa server
    assert list(data["mcpServers"]).count("medusa") == 1


def test_cursor_mcp_merge_preserves_server(tmp_path: Path):
    cfg_path = tmp_path / ".cursor" / "mcp.json"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(json.dumps({"mcpServers": {"other": {"command": "foo"}}}))

    install.install_cursor_mcp(tmp_path)
    data = json.loads(cfg_path.read_text())
    assert data["mcpServers"]["other"] == {"command": "foo"}  # preserved
    assert "medusa" in data["mcpServers"]


# --------------------------------------------------------------------------- #
# Codex MCP
# --------------------------------------------------------------------------- #
def test_codex_mcp_valid_and_idempotent(tmp_path: Path):
    path = install.install_codex_mcp(tmp_path)
    install.install_codex_mcp(tmp_path)
    assert path == tmp_path / ".codex" / "config.toml"

    data = tomllib.loads(path.read_text())  # valid TOML
    medusa = data["mcp_servers"]["medusa"]
    assert medusa["command"] == "medusa"
    assert medusa["args"] == ["mcp"]


def test_codex_mcp_merge_preserves_server(tmp_path: Path):
    cfg_path = tmp_path / ".codex" / "config.toml"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text(
        'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "foo"\nargs = ["bar"]\n'
    )

    install.install_codex_mcp(tmp_path)
    data = tomllib.loads(cfg_path.read_text())
    assert data["model"] == "gpt-5"  # unrelated key preserved
    assert data["mcp_servers"]["other"]["command"] == "foo"  # other server preserved
    assert data["mcp_servers"]["medusa"]["command"] == "medusa"


# --------------------------------------------------------------------------- #
# install_all
# --------------------------------------------------------------------------- #
def test_install_all(tmp_path: Path):
    result = install.install_all(tmp_path)
    assert set(result) == {"claude", "pre_commit", "cursor", "codex"}
    for p in result.values():
        assert Path(p).exists()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
