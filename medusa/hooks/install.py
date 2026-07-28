"""Writer functions for MEDUSA's native hooks + MCP gatekeeper integration.

Each ``install_*`` function takes a ``base`` directory (the project or home
root the config lives under) and returns the absolute :class:`Path` it wrote.
Every writer is:

* **idempotent** — running twice yields exactly one MEDUSA entry;
* **merge-safe** — it preserves unrelated keys / servers / hook blocks;
* **backup-first** — an existing file is copied to a timestamped
  ``<name>.medusa.bak.<epoch>`` before it is modified (never overwriting an
  earlier backup), and JSON writes are atomic (temp + ``os.replace``).

The writers are deliberately free of any scanning logic so they stay fast and
trivially testable; they only emit config that invokes the ``medusa`` CLI at
runtime.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import time
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
# CR-026: ownership is decided on these SPECIFIC shipped-command fingerprints, not
# a bare "medusa" substring — otherwise a user's own hook whose command merely
# mentions medusa (e.g. `python ~/my_medusa_notes.py`) was treated as MEDUSA-owned
# and silently replaced/removed. The pretooluse script basename and the
# SessionStart sentinel phrase are both unique to MEDUSA's emitted commands and
# survive a reinstall at a different absolute path.
_CLAUDE_HOOK_SCRIPT_NAME = _CLAUDE_HOOK_SCRIPT.name           # claude_pretooluse.sh
_SESSIONSTART_SENTINEL = "MEDUSA gatekeeper available"


def _pinned_hook_command() -> str:
    """The PreToolUse hook command with the resolved ``medusa`` binary PINNED into
    it (CR-030): a ``MEDUSA_BIN=<abs path>`` env prefix so the hook invokes that
    exact binary rather than a PATH-resolved ``medusa`` a compromise could shim.

    The path is resolved and shell-quoted at install time (MEDUSA-controlled, not
    attacker input). If ``medusa`` can't be resolved now, the bare command is
    emitted and the hook falls back to PATH resolution at runtime.
    """
    med = shutil.which("medusa")
    if med:
        return f"MEDUSA_BIN={shlex.quote(med)} {_CLAUDE_HOOK_COMMAND}"
    return _CLAUDE_HOOK_COMMAND

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
    'These tools are ADVISORY (the PreToolUse hook is the enforcing gate) - on any '
    'non-SAFE verdict, STOP and defer to a human. '
    'If the tools are not loaded, run: medusa hooks install --claude."'
)


class ConfigParseError(ValueError):
    """An existing config file could not be parsed.

    Raised by :func:`_load_json` when a file that EXISTS and has content will not
    parse as JSON. Callers on the WRITE path MUST abort rather than merge into an
    empty dict — merging would silently overwrite the user's real settings with
    ``{}`` (CR-012). Read-only callers use :func:`_load_json_safe` to treat this as
    "no MEDUSA config present" instead.
    """


def _backup(path: Path) -> None:
    """Copy ``path`` to a TIMESTAMPED ``<name>.medusa.bak.<epoch>`` if it exists.

    Timestamped and never-overwriting (CR-012): a single fixed ``.medusa.bak`` let
    a second run copy an already-corrupt file over the last recoverable backup.
    Best effort — a backup failure must not block the (atomic) write itself.
    """
    if not path.exists():
        return
    stamp = int(time.time())
    dest = path.with_name(f"{path.name}.medusa.bak.{stamp}")
    n = 0
    while dest.exists():                       # never clobber an existing backup
        n += 1
        dest = path.with_name(f"{path.name}.medusa.bak.{stamp}.{n}")
    shutil.copy2(path, dest)


def _load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from ``path``.

    Missing OR empty/whitespace-only file → ``{}`` (nothing to lose by merging).
    An existing file with content that will not parse raises
    :class:`ConfigParseError` so a caller never merges MEDUSA config into ``{}``
    and overwrites a settings file it simply couldn't read (e.g. one with a ``//``
    JSONC comment). Valid non-object JSON still yields ``{}`` (unchanged).
    """
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigParseError(f"cannot read {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigParseError(
            f"{path} is not valid JSON ({exc}); refusing to overwrite it — "
            f"fix or remove the file, then re-run."
        ) from exc
    return data if isinstance(data, dict) else {}


def _load_json_safe(path: Path) -> dict[str, Any]:
    """Best-effort read for READ-ONLY callers (status / uninstall detection).

    An unparseable existing file is treated as ``{}`` ("no MEDUSA config here")
    rather than aborting — a `hooks status` check must never crash, and an
    uninstall that can't parse the file leaves it untouched (no medusa key found).
    """
    try:
        return _load_json(path)
    except ConfigParseError:
        return {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write ``data`` as JSON to ``path`` (CR-012).

    Writes a sibling ``.medusa.tmp`` then ``os.replace`` (atomic on the same
    filesystem), so a crash mid-write can never truncate the real file — it either
    holds the old content or the new, never a partial.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".medusa.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Created-by-MEDUSA manifest (CR-025)
# --------------------------------------------------------------------------- #
# Uninstall unlinks a config file only when the file becomes empty AFTER removing
# the MEDUSA entry. Without a record of WHICH files MEDUSA created, that deleted a
# file the USER hand-authored with a lone `medusa` server. We record every file a
# MEDUSA installer CREATES (did not exist before) in a small per-base manifest and
# only unlink files present in it. A file absent from the manifest — user-authored,
# or a manifest we couldn't read — is KEPT (fail safe: never delete on doubt).
def _manifest_path(base: str | os.PathLike[str]) -> Path:
    return Path(base) / ".medusa" / "install-manifest.json"


def _manifest_load(base: str | os.PathLike[str]) -> set[str]:
    try:
        data = json.loads(_manifest_path(base).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    created = data.get("created") if isinstance(data, dict) else None
    return {str(p) for p in created} if isinstance(created, list) else set()


def _manifest_key(path: Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def _manifest_record_created(base: str | os.PathLike[str], path: Path,
                             existed_before: bool) -> None:
    """Record ``path`` as MEDUSA-created iff it did not exist before the write."""
    if existed_before:
        return
    created = _manifest_load(base)
    created.add(_manifest_key(path))
    mp = _manifest_path(base)
    try:
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(json.dumps({"created": sorted(created)}, indent=2) + "\n",
                      encoding="utf-8")
    except OSError:
        pass  # best effort — an unwritable manifest just means "don't auto-delete"


def _manifest_says_created(base: str | os.PathLike[str], path: Path) -> bool:
    return _manifest_key(path) in _manifest_load(base)


def _manifest_forget(base: str | os.PathLike[str], path: Path) -> None:
    created = _manifest_load(base)
    key = _manifest_key(path)
    if key not in created:
        return
    created.discard(key)
    mp = _manifest_path(base)
    try:
        if created:
            mp.write_text(json.dumps({"created": sorted(created)}, indent=2) + "\n",
                          encoding="utf-8")
        else:
            mp.unlink()
            try:                       # prune an empty .medusa/ we may have made
                mp.parent.rmdir()
            except OSError:
                pass
    except OSError:
        pass


def _is_medusa_command(command: Any) -> bool:
    """True if a settings hook COMMAND is one MEDUSA emits (CR-026).

    Matched on the shipped-command fingerprints (the pretooluse script basename or
    the SessionStart sentinel), NOT a bare ``medusa`` substring — so an unrelated
    user hook that merely mentions medusa in a path/word is never claimed as ours.
    """
    c = str(command or "")
    return _CLAUDE_HOOK_SCRIPT_NAME in c or _SESSIONSTART_SENTINEL in c


def _is_medusa_entry(entry: Any) -> bool:
    """True if a Claude settings hook entry is a MEDUSA-owned one. Used by both the
    PreToolUse and SessionStart installers to replace any prior MEDUSA entry
    idempotently."""
    if not isinstance(entry, dict):
        return False
    for hook in entry.get("hooks", []):
        if isinstance(hook, dict) and _is_medusa_command(hook.get("command", "")):
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
        "hooks": [{"type": "command", "command": _pinned_hook_command()}],  # CR-030
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
# POSIX-sh compatible (the block may be appended to a /bin/sh hook, not only the
# fresh bash one), so no arrays/process-substitution. Scans the STAGED changes
# (`git diff --cached` files) — NOT host chat/shell history — and relies on
# `secrets scan --exit-code` to fail the command when a credential is found.
_PRE_COMMIT_BLOCK = (
    _MARKER_BEGIN + "\n"
    + r"""# MEDUSA secrets gate: block the commit if a secret is in the STAGED changes.
if command -v medusa >/dev/null 2>&1; then
    set --
    _medusa_ifs=$IFS
    IFS='
'
    for _f in $(git diff --cached --name-only --diff-filter=ACM); do
        [ -f "$_f" ] && set -- "$@" --path "$_f"
    done
    IFS=$_medusa_ifs
    if [ "$#" -gt 0 ] && ! medusa secrets scan --exit-code "$@"; then
        echo "MEDUSA: secrets detected in staged changes - commit blocked." >&2
        echo "Resolve the findings or run 'git commit --no-verify' to override." >&2
        exit 1
    fi
fi
"""
    + _MARKER_END + "\n"
)


def _git_query(base_path: Path, args: list[str]) -> tuple[int, str]:
    """Run ``git -C <base_path> <args>``; return ``(returncode, stripped stdout)``.

    Isolated in its own helper so the ``subprocess.run`` call and its stdout stay
    local: the caller only ever receives a plain string, never a run() result that
    then flows onward into a filesystem path (which is a legitimate-but-noisy
    tainted-output shape). List-form (no shell); trusted git binary.
    """
    proc = subprocess.run(
        ["git", "-C", str(base_path), *args],
        capture_output=True, text=True, timeout=5, check=False,
    )
    return proc.returncode, (proc.stdout or "").strip()


def _git_hooks_dir(base: str | os.PathLike[str]) -> Path:
    """Resolve the git hooks directory for ``base`` (CR-024).

    Uses ``git -C <base> rev-parse --git-path hooks`` so ``core.hooksPath``
    (husky / the pre-commit framework) is honored — writing to ``.git/hooks``
    directly would silently never run under those setups. Refuses (RuntimeError)
    when ``base`` is not inside a git work tree, so we never fabricate a bogus
    ``.git/`` in a plain directory.
    """
    base_path = Path(base)
    try:
        rc, out = _git_query(base_path, ["rev-parse", "--is-inside-work-tree"])
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"cannot run git to locate the hooks dir: {exc}") from exc
    if rc != 0 or out != "true":
        raise RuntimeError(
            f"{base_path} is not a git work tree — refusing to create a .git/ "
            "hooks dir; run `medusa hooks install --pre-commit` inside a repo"
        )
    rc, out = _git_query(base_path, ["rev-parse", "--git-path", "hooks"])
    raw = out if (rc == 0 and out) else "hooks"
    hooks_dir = Path(raw)
    if not hooks_dir.is_absolute():
        # git returns a path relative to base (we passed -C base).
        hooks_dir = base_path / raw
    return hooks_dir


def install_pre_commit(base: str | os.PathLike[str]) -> Path:
    """Write/merge the git ``pre-commit`` hook running ``medusa secrets scan``.

    The hooks directory is resolved via git (honoring ``core.hooksPath``); a
    non-repo ``base`` is refused rather than fabricating ``.git/`` (CR-024). A
    fresh hook gets a shebang + the MEDUSA block. An existing non-MEDUSA hook is
    preserved and the MEDUSA block is appended (guarded by markers). The file is
    made executable. Idempotent via the marker block.
    """
    hooks_dir = _git_hooks_dir(base)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    path = hooks_dir / "pre-commit"
    existed = path.exists()

    existing = path.read_text(encoding="utf-8") if existed else ""

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
    _manifest_record_created(base, path, existed)   # CR-025

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
    existed = path.exists()
    config = _load_json(path)

    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        config["mcpServers"] = servers

    servers[MEDUSA_MARKER] = {"command": "medusa", "args": ["mcp"]}

    _backup(path)
    _write_json(path, config)
    _manifest_record_created(base, path, existed)   # CR-025
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
    existed = path.exists()
    existing_text = path.read_text(encoding="utf-8") if existed else ""

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
        _manifest_record_created(base, path, existed)   # CR-025
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
    _manifest_record_created(base, path, existed)   # CR-025
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

**These tools are ADVISORY, not enforcement.** They only return a verdict; the
deterministic control that actually blocks a risky command is the MEDUSA
PreToolUse hook (installed by `medusa hooks install --claude`), which fails
closed. On ANY non-SAFE verdict (CAUTION or DO_NOT_INSTALL), **STOP and defer to
a human — do not proceed.** Never treat a SAFE verdict from these advisory tools
as permission to skip the hook.

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

On ANY non-SAFE verdict, STOP and defer to a human — surface the findings and do
not proceed. Remember these MCP tools are advisory: the PreToolUse hook is the
real gate. If the MCP tools are not available, use the CLI equivalents
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
    existed = path.exists()
    config = _load_json(path)

    servers = config.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        servers = {}
        config["mcpServers"] = servers

    servers[MEDUSA_MARKER] = {"command": "medusa", "args": ["mcp"]}

    _backup(path)
    _write_json(path, config)
    _manifest_record_created(base, path, existed)   # CR-025
    return path


# --------------------------------------------------------------------------- #
# 7. Install everything
# --------------------------------------------------------------------------- #
def install_all(base: str | os.PathLike[str]) -> dict[str, str]:
    """Run every installer against ``base`` and return ``{name: path}``.

    The pre-commit gate needs a git work tree (CR-024); in a non-repo ``base`` it
    is skipped (omitted from the result) rather than aborting the whole install.
    """
    result = {
        "claude": str(install_claude_hook(base)),
        "claude_sessionstart": str(install_claude_sessionstart(base)),
        "claude_skill": str(install_claude_skill(base)),
        "claude_mcp": str(install_claude_mcp(base)),
        "cursor": str(install_cursor_mcp(base)),
        "codex": str(install_codex_mcp(base)),
    }
    try:
        result["pre_commit"] = str(install_pre_commit(base))
    except RuntimeError:
        pass  # not a git work tree — the other configs still install
    return result


# --------------------------------------------------------------------------- #
# 8. Installed-state detection (owned here so `medusa hooks status` can't drift)
# --------------------------------------------------------------------------- #
def _claude_hook_present(base: Path) -> bool:
    """True if a MEDUSA PreToolUse hook is wired in ``<base>/.claude/settings.json``."""
    data = _load_json_safe(Path(base) / ".claude" / "settings.json")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    for entry in hooks.get("PreToolUse", []):
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and _is_medusa_command(hook.get("command", "")):
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
    data = _load_json_safe(Path(base) / ".cursor" / "mcp.json")
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
    data = _load_json_safe(Path(base) / ".claude" / "settings.json")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    for entry in hooks.get("SessionStart", []):
        if not isinstance(entry, dict):
            continue
        for hook in entry.get("hooks", []):
            if isinstance(hook, dict) and _is_medusa_command(hook.get("command", "")):
                return True
    return False


def _claude_skill_present(base: Path) -> bool:
    """True if the always-on ``medusa-vet`` skill manifest exists under ``base``."""
    return (Path(base) / ".claude" / "skills" / "medusa-vet" / "SKILL.md").exists()


def _claude_mcp_present(base: Path) -> bool:
    """True if a ``medusa`` MCP server is registered in the project ``<base>/.mcp.json``."""
    data = _load_json_safe(Path(base) / ".mcp.json")
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
    settings = _load_json_safe(path)   # unparseable -> {} -> no medusa entry -> no-op
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


def _remove_medusa_server(base: str | os.PathLike[str], path: Path) -> Path | None:
    """Remove the ``medusa`` key from an ``mcpServers`` JSON config at ``path``."""
    if not path.exists():
        return None
    config = _load_json_safe(path)     # unparseable -> {} -> no medusa server -> no-op
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or MEDUSA_MARKER not in servers:
        return None
    servers.pop(MEDUSA_MARKER, None)
    if not servers:
        config.pop("mcpServers", None)
    _backup(path)
    # If MEDUSA was the only content the file is now empty ({}). Unlink it ONLY if
    # MEDUSA created it (manifest) — FX-H01 litter-cleanup. A file the USER
    # authored with a lone medusa server (or one we can't confirm we made) is KEPT
    # as `{}` rather than deleted (CR-025 — never delete a user's file on doubt).
    if not config:
        if _manifest_says_created(base, path):
            path.unlink()
            _manifest_forget(base, path)
        else:
            _write_json(path, config)
    else:
        _write_json(path, config)
    return path


def uninstall_claude_mcp(base: str | os.PathLike[str]) -> Path | None:
    """Remove the ``medusa`` server from the project ``.mcp.json``."""
    return _remove_medusa_server(base, Path(base) / ".mcp.json")


def uninstall_cursor_mcp(base: str | os.PathLike[str]) -> Path | None:
    """Remove the ``medusa`` server from ``.cursor/mcp.json``."""
    return _remove_medusa_server(base, Path(base) / ".cursor" / "mcp.json")


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
        stripped = _strip_marker_block(text)
        # Nothing left but whitespace -> the MEDUSA block was the only content.
        # Unlink only a file MEDUSA created (manifest); otherwise keep the user's
        # now-empty file rather than deleting it (CR-025 / FX-H01).
        if not stripped.strip():
            if _manifest_says_created(base, path):
                path.unlink()
                _manifest_forget(base, path)
            else:
                path.write_text(stripped, encoding="utf-8")
        else:
            path.write_text(stripped, encoding="utf-8")
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
            # MEDUSA was the only content. Remove only a file MEDUSA created
            # (manifest); keep a user-authored now-empty file (CR-025 / FX-H01).
            if not data:
                if _manifest_says_created(base, path):
                    path.unlink()
                    _manifest_forget(base, path)
                else:
                    path.write_text(tomli_w.dumps(data), encoding="utf-8")
            else:
                path.write_text(tomli_w.dumps(data), encoding="utf-8")
            return path
    return None


def uninstall_pre_commit(base: str | os.PathLike[str]) -> Path | None:
    """Strip the MEDUSA block from the git ``pre-commit`` hook.

    The hooks dir is resolved via git (honoring ``core.hooksPath``, CR-024); a
    non-repo base is a no-op. If the file is *only* the MEDUSA hook (bare shebang +
    our block) AND MEDUSA created it, it is removed; a hook that also holds user
    commands — or one MEDUSA did not create — keeps its content (CR-025).
    """
    try:
        hooks_dir = _git_hooks_dir(base)
    except RuntimeError:
        return None            # not a git work tree -> nothing MEDUSA wrote here
    path = hooks_dir / "pre-commit"
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
    if not meaningful and _manifest_says_created(base, path):
        path.unlink()
        _manifest_forget(base, path)
        return path
    # User-authored hook (or unknown provenance) — keep the file, strip our block.
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
