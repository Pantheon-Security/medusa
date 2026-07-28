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
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from medusa.hooks import install


def _init_repo(path: Path) -> None:
    """CR-024: the pre-commit installer now requires a real git work tree
    (it resolves the hooks dir via git so core.hooksPath is honored and never
    fabricates a bogus .git/). Init one so these writer tests have somewhere to
    land; skip if git is unavailable."""
    if not shutil.which("git"):
        pytest.skip("git not on PATH")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


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
    # The hook now invokes the shipped, fail-closed script by absolute path
    # (CR-009) rather than an inline one-liner.
    assert "claude_pretooluse.sh" in cmd["command"]
    assert install._CLAUDE_HOOK_SCRIPT.exists()


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
    _init_repo(tmp_path)
    path = install.install_pre_commit(tmp_path)
    assert path == tmp_path / ".git" / "hooks" / "pre-commit"
    assert os.access(path, os.X_OK)  # executable
    content = path.read_text()
    assert "medusa secrets" in content
    assert "exit 1" in content  # blocks the commit


def test_pre_commit_idempotent(tmp_path: Path):
    _init_repo(tmp_path)
    install.install_pre_commit(tmp_path)
    install.install_pre_commit(tmp_path)
    content = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
    assert content.count(install._MARKER_BEGIN) == 1
    assert content.count("medusa secrets scan") == 1


def test_pre_commit_preserves_existing_hook(tmp_path: Path):
    _init_repo(tmp_path)
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text("#!/bin/sh\necho 'existing project hook'\n")

    install.install_pre_commit(tmp_path)
    content = hook_path.read_text()
    assert "existing project hook" in content  # not clobbered
    assert "medusa secrets" in content
    assert os.access(hook_path, os.X_OK)


def test_pre_commit_scans_staged_diff_not_host_history(tmp_path: Path):
    """The gate must inspect the STAGED changes, not host chat/shell history."""
    _init_repo(tmp_path)
    install.install_pre_commit(tmp_path)
    content = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
    assert "git diff --cached" in content          # scans the staged diff
    assert "--exit-code" in content                # so a finding actually fails


def test_pre_commit_blocks_a_staged_secret(tmp_path: Path):
    """Born-RED gate for B3: a staged detectable credential blocks the commit,
    a clean file commits fine. Exercises the real hook + real `medusa`."""
    import shutil
    import subprocess

    med = shutil.which("medusa")
    if not (med and shutil.which("git")):
        pytest.skip("git/medusa not on PATH")

    def git(*a, **kw):
        return subprocess.run(["git", *a], cwd=tmp_path, capture_output=True, text=True, **kw)

    git("init", "-q")
    git("config", "user.email", "a@b.c")
    git("config", "user.name", "t")
    install.install_pre_commit(tmp_path)

    (tmp_path / "clean.txt").write_text("nothing secret here\n")
    git("add", "clean.txt")
    assert git("commit", "-m", "clean").returncode == 0, "clean file must commit"

    ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # detectable GitHub PAT
    (tmp_path / "leak.env").write_text(f"GITHUB_TOKEN={ghp}\n")
    git("add", "leak.env")
    r = git("commit", "-m", "leak")
    assert r.returncode != 0, "pre-commit gate must block a staged secret"
    assert "blocked" in (r.stdout + r.stderr).lower()


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
# Claude SessionStart hook
# --------------------------------------------------------------------------- #
def test_claude_sessionstart_present_and_contract(tmp_path: Path):
    path = install.install_claude_sessionstart(tmp_path)
    assert path == tmp_path / ".claude" / "settings.json"

    data = json.loads(path.read_text())  # valid JSON
    start = data["hooks"]["SessionStart"]
    assert isinstance(start, list)

    medusa_entries = [
        e
        for e in start
        if any("medusa" in h.get("command", "") for h in e.get("hooks", []))
    ]
    assert len(medusa_entries) == 1
    hook = medusa_entries[0]["hooks"][0]
    assert hook["type"] == "command"
    assert "medusa" in hook["command"]


def test_claude_sessionstart_idempotent(tmp_path: Path):
    install.install_claude_sessionstart(tmp_path)
    install.install_claude_sessionstart(tmp_path)
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    start = data["hooks"]["SessionStart"]
    medusa_entries = [
        e
        for e in start
        if any("medusa" in h.get("command", "") for h in e.get("hooks", []))
    ]
    assert len(medusa_entries) == 1


def test_claude_sessionstart_merges_with_pretooluse(tmp_path: Path):
    # Installing both hooks must not clobber each other in the same settings.json.
    install.install_claude_hook(tmp_path)
    install.install_claude_sessionstart(tmp_path)
    data = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert any(
        e.get("matcher") == "Bash" for e in data["hooks"]["PreToolUse"]
    )
    assert len(data["hooks"]["SessionStart"]) == 1


# --------------------------------------------------------------------------- #
# Claude skill (SKILL.md)
# --------------------------------------------------------------------------- #
def test_claude_skill_frontmatter_and_tools(tmp_path: Path):
    path = install.install_claude_skill(tmp_path)
    assert path == tmp_path / ".claude" / "skills" / "medusa-vet" / "SKILL.md"

    content = path.read_text()
    # Valid YAML frontmatter delimited by --- ... ---
    assert content.startswith("---\n")
    _, fm, _body = content.split("---\n", 2)
    meta = __import__("yaml").safe_load(fm)
    assert meta["name"] == "medusa-vet"
    assert "description" in meta and meta["description"]
    assert "when-to-use" in meta

    # Body references the real MCP gatekeeper tools.
    assert "scan_repo" in content
    assert "scan_skill" in content
    assert "secrets_scan" in content
    assert "secrets" in content.lower()


def test_claude_skill_idempotent(tmp_path: Path):
    p1 = install.install_claude_skill(tmp_path)
    first = p1.read_text()
    p2 = install.install_claude_skill(tmp_path)
    assert p2 == p1
    assert p2.read_text() == first  # stable rewrite


# --------------------------------------------------------------------------- #
# Claude project MCP (.mcp.json)
# --------------------------------------------------------------------------- #
def test_claude_mcp_valid_and_idempotent(tmp_path: Path):
    path = install.install_claude_mcp(tmp_path)
    install.install_claude_mcp(tmp_path)
    assert path == tmp_path / ".mcp.json"

    data = json.loads(path.read_text())  # valid JSON
    medusa = data["mcpServers"]["medusa"]
    assert medusa["command"] == "medusa"
    assert medusa["args"] == ["mcp"]
    assert list(data["mcpServers"]).count("medusa") == 1


def test_claude_mcp_merge_preserves_server(tmp_path: Path):
    cfg_path = tmp_path / ".mcp.json"
    cfg_path.write_text(json.dumps({"mcpServers": {"other": {"command": "foo"}}}))

    install.install_claude_mcp(tmp_path)
    data = json.loads(cfg_path.read_text())
    assert data["mcpServers"]["other"] == {"command": "foo"}  # preserved
    assert "medusa" in data["mcpServers"]


# --------------------------------------------------------------------------- #
# install_all
# --------------------------------------------------------------------------- #
def test_install_all(tmp_path: Path):
    _init_repo(tmp_path)
    result = install.install_all(tmp_path)
    assert set(result) == {
        "claude",
        "claude_sessionstart",
        "claude_skill",
        "claude_mcp",
        "pre_commit",
        "cursor",
        "codex",
    }
    for p in result.values():
        assert Path(p).exists()
    # The skill and project MCP config are wired by --all.
    assert Path(result["claude_skill"]).name == "SKILL.md"
    assert Path(result["claude_mcp"]).name == ".mcp.json"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
