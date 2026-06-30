"""MEDUSA MCP gatekeeper server package.

Exposes MEDUSA's repo / skill vetting and secrets scanning to MCP clients
(Claude Code, Cursor, ChatGPT/Codex) so they can vet-before-install. The
stdio entry point is ``medusa.mcp.server:main`` — Phase 2 wires it into the
CLI as ``medusa mcp``.
"""

from medusa.mcp.server import main, mcp

__all__ = ["main", "mcp"]
