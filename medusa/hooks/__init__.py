"""MEDUSA native hooks + MCP installer.

Pure, testable writer functions that wire MEDUSA's `--git` repo scanner and
`secrets scan` into Claude Code (PreToolUse hook), git (pre-commit), Cursor
(MCP) and ChatGPT/Codex (MCP). Each writer takes a target base dir so the
behaviour can be exercised against a tmp dir in tests; all writers merge into
existing config without clobbering, are idempotent, and back up before edit.
"""

from medusa.hooks.install import (
    install_all,
    install_claude_hook,
    install_codex_mcp,
    install_cursor_mcp,
    install_pre_commit,
)

__all__ = [
    "install_all",
    "install_claude_hook",
    "install_codex_mcp",
    "install_cursor_mcp",
    "install_pre_commit",
]
