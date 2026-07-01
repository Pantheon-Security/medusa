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

# The Claude PreToolUse hook is a shipped, MEDUSA-authored shell script
# (``claude_pretooluse.sh``, packaged alongside this module). It reads the tool
# input on stdin and, when the Bash command looks like a risky fetch/install
# (git/gh clone, curl|sh, wget, pip/pipx/uv/npm/poetry/cargo/go install), vets
# every URL with MEDUSA before the command runs. Crucially it **fails closed**
# and **exits 2** on any finding or when medusa is unavailable — Claude Code only
# blocks a tool call on exit 2, so exit 1 would fail open. The settings hook just
# invokes the script by absolute path; the script itself is the fixed constant so
# no untrusted data is ever templated into a shell string.
_CLAUDE_HOOK_SCRIPT = Path(__file__).resolve().with_name("claude_pretooluse.sh")
_CLAUDE_HOOK_COMMAND = f'bash "{_CLAUDE_HOOK_SCRIPT}"'

# The Claude SessionStart hook command. Runs once when a session starts to
# announce that the MEDUSA MCP gatekeeper is available. It CHECKS — it never
# rewrites config (CR-024): a consent-less `.mcp.json` rewrite on every session
# was both surprising and a re-entrenchment vector if a PATH `medusa` were
# compromised. Wiring the project MCP server stays gated behind the explicit
# `medusa hooks install --claude`. The output is a fixed constant (no per-run
# diff) and the command performs no file writes.
_CLAUDE_SESSIONSTART_COMMAND = (
    'echo "MEDUSA gatekeeper available: vet repos/skills with scan_repo/scan_skill '
    'and check for leaked credentials with secrets_scan before risky actions. '
    'If the tools are not loaded, run: medusa hooks install --claude."'
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


def _is_medusa_entry(entry: Any) -> bool:
    """True if a Claude settings hook entry is a MEDUSA-owned one (its command
    carries the MEDUSA marker). Used by both the PreToolUse and SessionStart
    installers to replace any prior MEDUSA entry idempotently."""
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks", []):
        if isinstance(hook, dict) and MEDUSA_MARKER in str(hook.get("command", "")):
            return True
    return False


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

    # Ensure the shipped hook script is executable (0755). We invoke it via
    # `bash <path>` so the exec bit is not strictly required, but keep it set so
    # the script is runnable directly too. Best effort — a read-only install dir
    # must not break wiring the hook.
    try:
        mode = _CLAUDE_HOOK_SCRIPT.stat().st_mode
        _CLAUDE_HOOK_SCRIPT.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        pre = []
        hooks["PreToolUse"] = pre

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


def install_claude_sessionstart(base: str | os.PathLike[str]) -> Path:
    """Write/merge a MEDUSA ``SessionStart`` hook into ``<base>/.claude/settings.json``.

    On every new Claude Code session this ensures the project ``.mcp.json``
    carries the ``medusa`` gatekeeper server and announces that vetting is
    active. Existing settings keys and unrelated SessionStart hooks are
    preserved; calling twice does not duplicate the MEDUSA hook.
    """
    path = Path(base) / ".claude" / "settings.json"
    settings = _load_json(path)

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks
    start = hooks.setdefault("SessionStart", [])
    if not isinstance(start, list):
        start = []
        hooks["SessionStart"] = start

    medusa_entry = {
        "hooks": [{"type": "command", "command": _CLAUDE_SESSIONSTART_COMMAND}],
    }

    # Replace any prior MEDUSA entry (idempotent update), keep everything else.
    new_start = [e for e in start if not _is_medusa_entry(e)]
    new_start.append(medusa_entry)
    hooks["SessionStart"] = new_start

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
# 5. Claude Code skill: always-on vetting via the MEDUSA gatekeeper
# --------------------------------------------------------------------------- #
_CLAUDE_SKILL_MD = """\
---
name: medusa-vet
description: >-
  Always vet untrusted code and check for leaked credentials with the MEDUSA
  MCP gatekeeper before risky actions. Use BEFORE cloning, installing, or
  running a repo/skill, and BEFORE committing or pasting code that may contain
  secrets.
when-to-use: >-
  Trigger before any of: cloning a git repo, installing a package/skill/plugin,
  running fetched code, committing, or pasting content that could contain
  credentials. If the medusa MCP tools are unavailable, fall back to the
  `medusa scan` / `medusa secrets scan` CLI.
---

# MEDUSA vet (always-on gatekeeper)

The `medusa` MCP server exposes three READ-ONLY vetting tools. Use them
proactively — do not wait to be asked.

## Tools

- `scan_repo(url_or_path)` — vet a local repo path or a remote git URL before
  you clone, install, or run it. Returns a verdict label, a numeric score, and
  the top findings.
- `scan_skill(path)` — vet a skill directory or `SKILL.md` before installing or
  trusting it (catches prompt-injection / toxic-skill payloads).
- `secrets_scan(path?)` — scan for leaked credentials. Pass a path, or omit it
  to scan the working directory. Run this before committing or before pasting
  code/config into a message.

## When to vet

1. **Before cloning/installing a repo or skill** — call `scan_repo` on the URL
   or `scan_skill` on the skill path FIRST. If the verdict is high-risk, stop
   and report the findings instead of proceeding.
2. **Before running fetched/untrusted code** — `scan_repo` on the local path.
3. **Before committing or pasting code** — `secrets_scan` to catch credentials.

If a tool reports a blocking verdict, surface the findings and ask before
continuing. If the MCP tools are not available, use the CLI equivalents
(`medusa scan --git <url>`, `medusa scan <path>`, `medusa secrets scan`).
"""


def install_claude_skill(base: str | os.PathLike[str]) -> Path:
    """Write ``<base>/.claude/skills/medusa-vet/SKILL.md`` (always-on vetting skill).

    The skill instructs Claude Code to vet untrusted repos/skills and check for
    leaked credentials via the MEDUSA MCP gatekeeper tools before risky actions.
    Idempotent: re-running rewrites the same file. Backup-first.
    """
    path = Path(base) / ".claude" / "skills" / "medusa-vet" / "SKILL.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    _backup(path)
    path.write_text(_CLAUDE_SKILL_MD, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 6. Claude Code project MCP server entry (.mcp.json)
# --------------------------------------------------------------------------- #
def install_claude_mcp(base: str | os.PathLike[str]) -> Path:
    """Write/merge ``<base>/.mcp.json`` with the ``medusa`` MCP gatekeeper server.

    Claude Code auto-loads project-level ``.mcp.json`` servers, so this wires the
    gatekeeper for the project. Existing servers under ``mcpServers`` are
    preserved; the MEDUSA entry launches ``medusa mcp``. Idempotent and
    backup-first.
    """
    path = Path(base) / ".mcp.json"
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
# 7. Install everything
# --------------------------------------------------------------------------- #
def install_all(base: str | os.PathLike[str]) -> dict[str, str]:
    """Run every installer against ``base`` and return ``{name: path}``."""
    return {
        "claude": str(install_claude_hook(base)),
        "claude_sessionstart": str(install_claude_sessionstart(base)),
        "claude_skill": str(install_claude_skill(base)),
        "claude_mcp": str(install_claude_mcp(base)),
        "pre_commit": str(install_pre_commit(base)),
        "cursor": str(install_cursor_mcp(base)),
        "codex": str(install_codex_mcp(base)),
    }


# --------------------------------------------------------------------------- #
# 8. Installed-state detection (owned here so `medusa hooks status` can't drift)
# --------------------------------------------------------------------------- #
def _claude_hook_present(base: Path) -> bool:
    """True if a MEDUSA PreToolUse hook is wired in ``<base>/.claude/settings.json``."""
    data = _load_json(Path(base) / ".claude" / "settings.json")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    for entry in hooks.get("PreToolUse", []):
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and MEDUSA_MARKER in str(hook.get("command", "")):
                return True
    return False


def _pre_commit_present(base: Path) -> bool:
    """True if the MEDUSA marker block is present in ``<base>/.git/hooks/pre-commit``."""
    path = Path(base) / ".git" / "hooks" / "pre-commit"
    if not path.exists():
        return False
    try:
        return _MARKER_BEGIN in path.read_text(encoding="utf-8")
    except OSError:
        return False


def _cursor_present(base: Path) -> bool:
    """True if a ``medusa`` MCP server is registered in ``<base>/.cursor/mcp.json``."""
    data = _load_json(Path(base) / ".cursor" / "mcp.json")
    servers = data.get("mcpServers", {})
    return isinstance(servers, dict) and MEDUSA_MARKER in servers


def _codex_present(base: Path) -> bool:
    """True if a ``medusa`` MCP server is registered in ``<base>/.codex/config.toml``."""
    path = Path(base) / ".codex" / "config.toml"
    if not path.exists():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    # Match both the structured table and the marker-guarded text fallback.
    return f"mcp_servers.{MEDUSA_MARKER}" in text or _MARKER_BEGIN in text


def _claude_sessionstart_present(base: Path) -> bool:
    """True if a MEDUSA SessionStart hook is wired in ``<base>/.claude/settings.json``."""
    data = _load_json(Path(base) / ".claude" / "settings.json")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    for entry in hooks.get("SessionStart", []):
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and MEDUSA_MARKER in str(hook.get("command", "")):
                return True
    return False


def _claude_skill_present(base: Path) -> bool:
    """True if the always-on ``medusa-vet`` skill manifest exists under ``base``."""
    return (Path(base) / ".claude" / "skills" / "medusa-vet" / "SKILL.md").exists()


def _claude_mcp_present(base: Path) -> bool:
    """True if a ``medusa`` MCP server is registered in the project ``<base>/.mcp.json``."""
    data = _load_json(Path(base) / ".mcp.json")
    servers = data.get("mcpServers", {})
    return isinstance(servers, dict) and MEDUSA_MARKER in servers


def status(base: str | os.PathLike[str]) -> dict[str, bool]:
    """Report which MEDUSA hooks/configs are present under ``base``.

    Returns ``{config_id: present}`` for every config an ``install --all`` writes
    (all 7). Detection lives here (next to the writers) so ``medusa hooks
    status`` reads state through this function instead of re-implementing the
    config paths/structure and drifting out of sync.
    """
    base = Path(base)
    return {
        "claude_hook": _claude_hook_present(base),
        "claude_sessionstart": _claude_sessionstart_present(base),
        "claude_skill": _claude_skill_present(base),
        "claude_mcp": _claude_mcp_present(base),
        "pre_commit": _pre_commit_present(base),
        "cursor": _cursor_present(base),
        "codex": _codex_present(base),
    }


# --------------------------------------------------------------------------- #
# 9. Uninstallers — reverse exactly what the writers above emit
# --------------------------------------------------------------------------- #
# Every ``uninstall_*`` function is the surgical inverse of its ``install_*``
# counterpart. It removes ONLY the MEDUSA-owned entry/block/file, preserves any
# unrelated user content, and is idempotent — returning the :class:`Path` it
# touched, or ``None`` when there was nothing MEDUSA-owned to remove (safe to
# run when nothing is installed). Each backs up before it edits.


def _remove_medusa_from_settings(base: str | os.PathLike[str], hook_type: str) -> Path | None:
    """Drop MEDUSA entries from ``hooks.<hook_type>`` in ``.claude/settings.json``.

    Non-MEDUSA hooks (and every other settings key) are left untouched. Empty
    containers that would be left behind are pruned. Returns the path if an
    entry was removed, else ``None``.
    """
    path = Path(base) / ".claude" / "settings.json"
    if not path.exists():
        return None
    settings = _load_json(path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return None
    entries = hooks.get(hook_type)
    if not isinstance(entries, list):
        return None
    kept = [e for e in entries if not _is_medusa_entry(e)]
    if len(kept) == len(entries):
        return None  # nothing MEDUSA-owned here
    if kept:
        hooks[hook_type] = kept
    else:
        hooks.pop(hook_type, None)
    if not hooks:
        settings.pop("hooks", None)
    _backup(path)
    _write_json(path, settings)
    return path


def uninstall_claude_hook(base: str | os.PathLike[str]) -> Path | None:
    """Remove the MEDUSA ``PreToolUse`` hook from ``.claude/settings.json``."""
    return _remove_medusa_from_settings(base, "PreToolUse")


def uninstall_claude_sessionstart(base: str | os.PathLike[str]) -> Path | None:
    """Remove the MEDUSA ``SessionStart`` hook from ``.claude/settings.json``."""
    return _remove_medusa_from_settings(base, "SessionStart")


def uninstall_claude_skill(base: str | os.PathLike[str]) -> Path | None:
    """Delete the ``.claude/skills/medusa-vet/`` skill directory."""
    skill_dir = Path(base) / ".claude" / "skills" / "medusa-vet"
    if not skill_dir.exists():
        return None
    shutil.rmtree(skill_dir)
    # Tidy an empty skills/ parent we would have created (never touch it if a
    # user still keeps other skills there).
    parent = skill_dir.parent
    try:
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()
    except OSError:
        pass
    return skill_dir


def _remove_medusa_server(path: Path) -> Path | None:
    """Remove the ``medusa`` key from an ``mcpServers`` JSON config at ``path``."""
    if not path.exists():
        return None
    config = _load_json(path)
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or MEDUSA_MARKER not in servers:
        return None
    servers.pop(MEDUSA_MARKER, None)
    if not servers:
        config.pop("mcpServers", None)
    _backup(path)
    _write_json(path, config)
    return path


def uninstall_claude_mcp(base: str | os.PathLike[str]) -> Path | None:
    """Remove the ``medusa`` server from the project ``.mcp.json``."""
    return _remove_medusa_server(Path(base) / ".mcp.json")


def uninstall_cursor_mcp(base: str | os.PathLike[str]) -> Path | None:
    """Remove the ``medusa`` server from ``.cursor/mcp.json``."""
    return _remove_medusa_server(Path(base) / ".cursor" / "mcp.json")


def _strip_marker_block(text: str) -> str:
    """Remove the ``# >>> medusa >>> ... # <<< medusa <<<`` block from ``text``."""
    head, _, rest = text.partition(_MARKER_BEGIN)
    _, _, tail = rest.partition(_MARKER_END)
    head = head.rstrip("\n")
    tail = tail.lstrip("\n")
    if head and tail:
        joined = head + "\n" + tail
    else:
        joined = head + tail
    if joined and not joined.endswith("\n"):
        joined += "\n"
    return joined


def uninstall_codex_mcp(base: str | os.PathLike[str]) -> Path | None:
    """Remove the MEDUSA server from ``.codex/config.toml`` (structured or block)."""
    path = Path(base) / ".codex" / "config.toml"
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    # Text-fallback form: strip the marker-guarded block.
    if _MARKER_BEGIN in text:
        _backup(path)
        path.write_text(_strip_marker_block(text), encoding="utf-8")
        return path

    # Structured form: parse, drop [mcp_servers.medusa], re-serialize.
    if tomllib is not None and tomli_w is not None:
        try:
            data: dict[str, Any] = tomllib.loads(text) if text else {}
        except tomllib.TOMLDecodeError:
            return None
        servers = data.get("mcp_servers")
        if isinstance(servers, dict) and MEDUSA_MARKER in servers:
            servers.pop(MEDUSA_MARKER, None)
            if not servers:
                data.pop("mcp_servers", None)
            _backup(path)
            path.write_text(tomli_w.dumps(data), encoding="utf-8")
            return path
    return None


def uninstall_pre_commit(base: str | os.PathLike[str]) -> Path | None:
    """Strip the MEDUSA block from ``.git/hooks/pre-commit``.

    If the file is *only* the MEDUSA hook (bare shebang + our block), it is
    removed entirely; a hook that also holds user commands keeps them.
    """
    path = Path(base) / ".git" / "hooks" / "pre-commit"
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if _MARKER_BEGIN not in text:
        return None

    head, _, rest = text.partition(_MARKER_BEGIN)
    _, _, tail = rest.partition(_MARKER_END)
    remainder = head + tail
    # Is anything left besides a shebang / blank lines?
    meaningful = [
        ln for ln in remainder.splitlines()
        if ln.strip() and not ln.strip().startswith("#!")
    ]

    _backup(path)
    if not meaningful:
        path.unlink()
        return path
    path.write_text(_strip_marker_block(text), encoding="utf-8")
    return path


def uninstall_all(base: str | os.PathLike[str]) -> dict[str, str]:
    """Run every uninstaller against ``base``; return ``{name: path}`` for removed."""
    removed: dict[str, str] = {}
    for name, fn in (
        ("claude", uninstall_claude_hook),
        ("claude_sessionstart", uninstall_claude_sessionstart),
        ("claude_skill", uninstall_claude_skill),
        ("claude_mcp", uninstall_claude_mcp),
        ("pre_commit", uninstall_pre_commit),
        ("cursor", uninstall_cursor_mcp),
        ("codex", uninstall_codex_mcp),
    ):
        p = fn(base)
        if p is not None:
            removed[name] = str(p)
    return removed
