"""Gate for FX-H01 (#26) — uninstall removes a now-empty config file MEDUSA created,
instead of leaving `{}` / an empty TOML behind (PC001 handover 2026-07-22-hooks LOW).

A file MEDUSA created and now fully emptied (the medusa entry was its only content) is
litter; uninstall should unlink it. A file the user shares (other servers/keys present)
must survive uninstall with the user's content intact.
"""
import json

from medusa.hooks import install as I


# --- JSON (.mcp.json / .cursor/mcp.json) ------------------------------------- #
def test_claude_mcp_file_removed_when_medusa_only(tmp_path):
    I.install_claude_mcp(tmp_path)
    p = tmp_path / ".mcp.json"
    assert p.exists(), "install should create .mcp.json"
    I.uninstall_claude_mcp(tmp_path)
    assert not p.exists(), "uninstall must remove the now-empty .mcp.json MEDUSA created, not leave {}"


def test_cursor_mcp_file_removed_when_medusa_only(tmp_path):
    I.install_cursor_mcp(tmp_path)
    p = tmp_path / ".cursor" / "mcp.json"
    assert p.exists()
    I.uninstall_cursor_mcp(tmp_path)
    assert not p.exists(), "uninstall must remove the now-empty .cursor/mcp.json"


def test_user_server_preserved_on_uninstall(tmp_path):
    # user already had their own MCP server -> uninstall keeps the file + their server
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node", "args": ["x.js"]}}}))
    I.install_claude_mcp(tmp_path)
    I.uninstall_claude_mcp(tmp_path)
    assert p.exists(), "a file with the user's own server must NOT be deleted"
    data = json.loads(p.read_text())
    assert "myserver" in data.get("mcpServers", {}), "user's server must survive uninstall"
    assert "medusa" not in data.get("mcpServers", {}), "medusa entry must be gone"


# --- TOML (.codex/config.toml) ----------------------------------------------- #
def test_codex_toml_removed_when_medusa_only(tmp_path):
    I.install_codex_mcp(tmp_path)
    p = tmp_path / ".codex" / "config.toml"
    assert p.exists()
    I.uninstall_codex_mcp(tmp_path)
    assert not p.exists(), "uninstall must remove the now-empty .codex/config.toml"
