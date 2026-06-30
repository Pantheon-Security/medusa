"""Writer functions for MEDUSA's native hooks + MCP gatekeeper integration.

Each ``install_*`` function takes a ``base`` directory (the project or home
root the config lives under) and returns the absolute :class:`Path` it wrote.
Every writer is:

* **idempotent** — running twice yields exactly one MEDUSA entry;
* **merge-safe** — it preserves unrelated keys / servers / hook blocks;
* **backup-first** — an existing file is copied to ``<name>.medusa.bak``
  before it is modified.

The writers are deliberately free of any scanning logic so they stay fast and
trivially testable; they only emit config that invokes the ``medusa`` CLI at
runtime.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

try:  # Python 3.11+ stdlib reader
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - we target 3.11+
    tomllib = None  # type: ignore[assignment]

try:
    import tomli_w
except ModuleNotFoundError:  # pragma: no cover - optional, guarded-block fallback
    tomli_w = None  # type: ignore[assignment]

# Stable identifier used to recognise MEDUSA-owned config across runs so we can
# update in place instead of appending a duplicate.
MEDUSA_MARKER = "medusa"
_MARKER_BEGIN = "# >>> medusa >>>"
_MARKER_END = "# <<< medusa <<<"

# The Claude PreToolUse hook command. Single robust shell line: it reads the
# tool input on stdin, and when the Bash command looks like a risky fetch/install
# (git clone / pip|npm|uv install) it vets it with MEDUSA before the command runs.
# A git clone URL is routed through `medusa scan --git <url>`; everything else
# triggers a fast workspace `medusa secrets scan`. Exit 2 from a PreToolUse hook
# tells Claude Code to block the tool call.
_CLAUDE_HOOK_COMMAND = (
    "cmd=$(cat | python3 -c "
    "'import sys,json;print(json.load(sys.stdin).get(\"tool_input\",{}).get(\"command\",\"\"))' "
    "2>/dev/null); "
    'case "$cmd" in '
    "*'git clone'*) "
    'url=$(printf "%s" "$cmd" | grep -oE "(https?://|git@)[^ ]+" | head -n1); '
    '[ -n "$url" ] && medusa scan --git "$url" --fail-on high || exit 0 ;; '
    "*'pip install'*|*'npm install'*|*'uv pip install'*|*'pip3 install'*) "
    "medusa secrets scan || exit 0 ;; "
    "*) exit 0 ;; "
    "esac"
)


def _backup(path: Path) -> None:
    """Copy ``path`` to ``<path>.medusa.bak`` if it exists (best effort)."""
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".medusa.bak"))


def _load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from ``path``; return ``{}`` if missing/invalid."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Claude Code PreToolUse hook
# --------------------------------------------------------------------------- #
def install_claude_hook(base: str | os.PathLike[str]) -> Path:
    """Write/merge a MEDUSA ``PreToolUse`` hook into ``<base>/.claude/settings.json``.

    The hook matches the ``Bash`` tool and vets risky shell (git clone /
    pip|npm|uv install) by invoking MEDUSA before the command runs. Existing
    settings keys and unrelated hooks are preserved; calling twice does not
    duplicate the MEDUSA hook.
    """
    path = Path(base) / ".claude" / "settings.json"
    settings = _load_json(path)

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        pre = []
        hooks["PreToolUse"] = pre

    def _is_medusa_entry(entry: Any) -> bool:
        if not isinstance(entry, dict):
            return False
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and MEDUSA_MARKER in str(hook.get("command", "")):
                return True
        return False

    medusa_entry = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": _CLAUDE_HOOK_COMMAND}],
    }

    # Replace any prior MEDUSA entry (idempotent update), keep everything else.
    new_pre = [e for e in pre if not _is_medusa_entry(e)]
    new_pre.append(medusa_entry)
    hooks["PreToolUse"] = new_pre

    _backup(path)
    _write_json(path, settings)
    return path


# --------------------------------------------------------------------------- #
# 2. Git pre-commit secrets block
# --------------------------------------------------------------------------- #
_PRE_COMMIT_BLOCK = f"""{_MARKER_BEGIN}
# MEDUSA secrets gate: block the commit if secrets are detected.
if command -v medusa >/dev/null 2>&1; then
    if ! medusa secrets scan; then
        echo "MEDUSA: secrets detected in working tree - commit blocked." >&2
        echo "Resolve the findings or run 'git commit --no-verify' to override." >&2
        exit 1
    fi
fi
{_MARKER_END}
"""


def install_pre_commit(base: str | os.PathLike[str]) -> Path:
    """Write/merge ``<base>/.git/hooks/pre-commit`` running ``medusa secrets scan``.

    A fresh hook gets a shebang + the MEDUSA block. An existing non-MEDUSA hook
    is preserved and the MEDUSA block is appended (guarded by markers). The file
    is made executable. Idempotent via the marker block.
    """
    path = Path(base) / ".git" / "hooks" / "pre-commit"
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = path.read_text(encoding="utf-8") if path.exists() else ""

    if _MARKER_BEGIN in existing:
        # Replace the existing MEDUSA block in place (idempotent update).
        head, _, rest = existing.partition(_MARKER_BEGIN)
        _, _, tail = rest.partition(_MARKER_END)
        new_content = head + _PRE_COMMIT_BLOCK + tail.lstrip("\n")
    elif existing.strip():
        # Preserve the existing hook, append our guarded block.
        sep = "" if existing.endswith("\n") else "\n"
        new_content = existing + sep + "\n" + _PRE_COMMIT_BLOCK
    else:
        new_content = "#!/usr/bin/env bash\n" + _PRE_COMMIT_BLOCK

    _backup(path)
    path.write_text(new_content, encoding="utf-8")

    # chmod +x (preserve read perms, add execute for u/g/o).
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# --------------------------------------------------------------------------- #
# 3. Cursor MCP server entry
# --------------------------------------------------------------------------- #
def install_cursor_mcp(base: str | os.PathLike[str]) -> Path:
    """Write/merge ``<base>/.cursor/mcp.json`` with a ``medusa`` MCP server.

    Existing servers under ``mcpServers`` are preserved; the MEDUSA entry is set
    to launch ``medusa mcp``. Idempotent (re-running overwrites only the medusa
    key with the same value).
    """
    path = Path(base) / ".cursor" / "mcp.json"
    config = _load_json(path)

    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        config["mcpServers"] = servers

    servers[MEDUSA_MARKER] = {"command": "medusa", "args": ["mcp"]}

    _backup(path)
    _write_json(path, config)
    return path


# --------------------------------------------------------------------------- #
# 4. Codex / ChatGPT MCP server entry
# --------------------------------------------------------------------------- #
_CODEX_TOML_BLOCK = f"""{_MARKER_BEGIN}
[mcp_servers.medusa]
command = "medusa"
args = ["mcp"]
{_MARKER_END}
"""


def install_codex_mcp(base: str | os.PathLike[str]) -> Path:
    """Write/merge ``<base>/.codex/config.toml`` with an ``[mcp_servers.medusa]`` entry.

    Existing TOML is read with :mod:`tomllib` and rewritten with
    :mod:`tomli_w` so other servers/keys survive. If round-tripping is not
    available, a marker-guarded block is appended/replaced as text instead.
    Idempotent either way.
    """
    path = Path(base) / ".codex" / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)

    medusa_server = {"command": "medusa", "args": ["mcp"]}
    existing_text = path.read_text(encoding="utf-8") if path.exists() else ""

    if tomllib is not None and tomli_w is not None and _MARKER_BEGIN not in existing_text:
        # Preferred path: parse + structured merge + serialize.
        try:
            data: dict[str, Any] = tomllib.loads(existing_text) if existing_text else {}
        except tomllib.TOMLDecodeError:
            data = {}
        mcp_servers = data.get("mcp_servers")
        if not isinstance(mcp_servers, dict):
            mcp_servers = {}
            data["mcp_servers"] = mcp_servers
        mcp_servers[MEDUSA_MARKER] = medusa_server
        _backup(path)
        path.write_text(tomli_w.dumps(data), encoding="utf-8")
        return path

    # Fallback: guarded text block (also used to update an existing block).
    if _MARKER_BEGIN in existing_text:
        head, _, rest = existing_text.partition(_MARKER_BEGIN)
        _, _, tail = rest.partition(_MARKER_END)
        new_content = head + _CODEX_TOML_BLOCK + tail.lstrip("\n")
    elif existing_text.strip():
        sep = "" if existing_text.endswith("\n") else "\n"
        new_content = existing_text + sep + "\n" + _CODEX_TOML_BLOCK
    else:
        new_content = _CODEX_TOML_BLOCK

    _backup(path)
    path.write_text(new_content, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 5. Install everything
# --------------------------------------------------------------------------- #
def install_all(base: str | os.PathLike[str]) -> dict[str, str]:
    """Run every installer against ``base`` and return ``{name: path}``."""
    return {
        "claude": str(install_claude_hook(base)),
        "pre_commit": str(install_pre_commit(base)),
        "cursor": str(install_cursor_mcp(base)),
        "codex": str(install_codex_mcp(base)),
    }
