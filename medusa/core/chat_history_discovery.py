"""Locate AI chat and shell history artefacts on the host.

Each entry point in `SOURCE_PROVIDERS` returns a list of `Target`
records: the absolute file path, the source label (used for grouping
in reports), and the source kind (`ai-chats` or `shell`) used by the
`--source` CLI filter.

Adding a new source — a browser password DB, a `~/.aws/credentials`
cache, a Docker config file — is one entry in this module: write a
`_discover_*` function and append it to `SOURCE_PROVIDERS`.

Discovery is deliberately conservative: only files that *exist* and
are readable are returned. Symlinks are resolved. Directories listed
in `_GLOB_PATTERNS` are walked with `glob`, not `os.walk`, so we don't
descend into giant home subtrees by accident.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple


@dataclass(frozen=True)
class Target:
    path: Path
    source: str       # human label: "claude-code", "bash", "cursor", ...
    kind: str         # "ai-chats" | "shell"


def _home() -> Path:
    return Path.home()


def _exists_file(p: Path) -> Optional[Path]:
    """Return `p.resolve()` if it's a readable regular file, else None."""
    try:
        if p.is_file() and os.access(p, os.R_OK):
            return p.resolve()
    except OSError:
        pass
    return None


def _glob_files(base: Path, pattern: str, recursive: bool = False) -> List[Path]:
    """Glob under `base` for files matching `pattern`. Returns existing
    regular files only; the caller decides what source label to assign.
    """
    if not base.exists():
        return []
    matches: List[Path] = []
    iterator = base.rglob(pattern) if recursive else base.glob(pattern)
    for p in iterator:
        resolved = _exists_file(p)
        if resolved is not None:
            matches.append(resolved)
    return matches


# ---------------------------------------------------------------------------
# AI chat history providers
# ---------------------------------------------------------------------------

def _discover_claude_code() -> List[Target]:
    home = _home()
    targets: List[Target] = []

    direct = _exists_file(home / ".claude" / "history.jsonl")
    if direct is not None:
        targets.append(Target(direct, "claude-code", "ai-chats"))

    projects_dir = home / ".claude" / "projects"
    for path in _glob_files(projects_dir, "*/history.jsonl"):
        targets.append(Target(path, "claude-code", "ai-chats"))

    # The conversation transcript ledger is the most likely place for
    # pasted secrets — it captures every user/assistant turn verbatim.
    ledger = _exists_file(home / ".claude" / "history.jsonl")
    # Memory files often include API references but are usually safer; we
    # include them so the scanner can decide per pattern.
    for path in _glob_files(home / ".claude" / "projects", "*/memory/*.md"):
        targets.append(Target(path, "claude-code-memory", "ai-chats"))

    return targets


def _discover_claude_desktop() -> List[Target]:
    """Claude Desktop (Electron) keeps conversations in IndexedDB under
    `Local Storage` / `IndexedDB` subdirs. We pull the top-level JSON
    state + logs only — recursive walk hits Chromium-cache noise.
    """
    home = _home()
    targets: List[Target] = []
    candidates: List[Path] = []
    if sys.platform == "darwin":
        candidates.append(home / "Library" / "Application Support" / "Claude")
    else:
        candidates.append(home / ".config" / "Claude")
    for base in candidates:
        if not base.exists():
            continue
        for path in _glob_files(base, "*.json"):  # non-recursive
            targets.append(Target(path, "claude-desktop", "ai-chats"))
        for path in _glob_files(base, "*.log"):
            targets.append(Target(path, "claude-desktop", "ai-chats"))
        # Conversations may live under a dedicated subdir on some versions.
        for sub in ("Conversations", "conversations"):
            for path in _glob_files(base / sub, "**/*", recursive=True):
                if path.suffix in {".json", ".jsonl", ".txt", ".md"}:
                    targets.append(Target(path, "claude-desktop", "ai-chats"))
    return targets


def _discover_cursor() -> List[Target]:
    """Cursor stores chat sessions under workspaceStorage. Scoping to
    paths that include `chat` or `composer` in the filename avoids
    pulling every extension's cache file.
    """
    home = _home()
    targets: List[Target] = []
    bases: List[Path] = []
    if sys.platform == "darwin":
        bases.append(home / "Library" / "Application Support" / "Cursor" / "User")
    else:
        bases.append(home / ".config" / "Cursor" / "User")
    for base in bases:
        if not base.exists():
            continue
        ws = base / "workspaceStorage"
        for path in _glob_files(ws, "**/state.vscdb", recursive=True):
            targets.append(Target(path, "cursor", "ai-chats"))
        for pattern in ("**/*chat*.json", "**/*composer*.json", "**/*Chat*.json"):
            for path in _glob_files(ws, pattern, recursive=True):
                targets.append(Target(path, "cursor", "ai-chats"))
    return targets


def _discover_zed() -> List[Target]:
    home = _home()
    bases: List[Path] = []
    if sys.platform == "darwin":
        bases.append(home / "Library" / "Application Support" / "Zed" / "conversations")
    else:
        bases.append(home / ".local" / "share" / "zed" / "conversations")
    targets: List[Target] = []
    for base in bases:
        for path in _glob_files(base, "*"):
            targets.append(Target(path, "zed", "ai-chats"))
    return targets


def _discover_vscode_copilot() -> List[Target]:
    home = _home()
    bases: List[Path] = []
    if sys.platform == "darwin":
        bases.append(home / "Library" / "Application Support" / "Code" / "User")
    elif sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            bases.append(Path(appdata) / "Code" / "User")
    else:
        bases.append(home / ".config" / "Code" / "User")
    targets: List[Target] = []
    for base in bases:
        for path in _glob_files(base / "workspaceStorage", "**/chatSessions/*.json", recursive=True):
            targets.append(Target(path, "vscode-copilot", "ai-chats"))
        for path in _glob_files(base / "globalStorage", "**/chat*.json", recursive=True):
            targets.append(Target(path, "vscode-copilot", "ai-chats"))
    return targets


def _discover_gemini_cli() -> List[Target]:
    """Gemini CLI keeps chat sessions under `~/.gemini/history/`.

    The top-level `.gemini/` dir also contains oauth credentials, state
    files, and tmp scratch data — we deliberately don't walk those
    recursively because they include plugin caches with thousands of
    JSON files that aren't chat history.
    """
    home = _home()
    targets: List[Target] = []
    for base in [home / ".gemini" / "history", home / ".config" / "gemini-cli" / "history"]:
        for path in _glob_files(base, "**/*.json", recursive=True):
            targets.append(Target(path, "gemini-cli", "ai-chats"))
        for path in _glob_files(base, "**/*.jsonl", recursive=True):
            targets.append(Target(path, "gemini-cli", "ai-chats"))
    return targets


def _discover_aider() -> List[Target]:
    home = _home()
    targets: List[Target] = []
    for filename, label in [
        (".aider.chat.history.md", "aider-chat"),
        (".aider.input.history", "aider-input"),
        (".aider.llm.history", "aider-llm"),
    ]:
        path = _exists_file(home / filename)
        if path is not None:
            targets.append(Target(path, label, "ai-chats"))
    return targets


def _discover_codex_cli() -> List[Target]:
    """Codex CLI keeps history at the top of `~/.codex/`.

    We do NOT walk recursively: `.codex/.tmp/plugins/**` and
    `.codex/cache/**` contain thousands of unrelated JSON files
    (plugin manifests, app-tool caches) that pollute results.
    """
    home = _home()
    targets: List[Target] = []
    base = home / ".codex"
    # Explicit known artefacts at the top level.
    for filename in ("history.jsonl", "auth.json"):
        path = _exists_file(base / filename)
        if path is not None:
            targets.append(Target(path, "codex-cli", "ai-chats"))
    # If there's a dedicated history subdir, walk it.
    for path in _glob_files(base / "history", "**/*", recursive=True):
        targets.append(Target(path, "codex-cli", "ai-chats"))
    return targets


# ---------------------------------------------------------------------------
# Shell history providers
# ---------------------------------------------------------------------------

def _discover_shell_histories() -> List[Target]:
    """Plain-text REPL / shell histories. These leak secrets just as
    often as chat histories — users paste `export PYPI_TOKEN=...` and
    `curl -H "Authorization: Bearer ..."` constantly.
    """
    home = _home()
    candidates: List[Tuple[str, str]] = [
        (".bash_history", "bash"),
        (".zsh_history", "zsh"),
        (".python_history", "python-repl"),
        (".node_repl_history", "node-repl"),
        (".psql_history", "psql"),
        (".mysql_history", "mysql"),
        (".irb_history", "irb"),
        (".rediscli_history", "redis-cli"),
        (".sqlite_history", "sqlite"),
    ]
    targets: List[Target] = []
    for filename, label in candidates:
        path = _exists_file(home / filename)
        if path is not None:
            targets.append(Target(path, label, "shell"))

    # Fish keeps history in an XDG location.
    fish_path = _exists_file(home / ".local" / "share" / "fish" / "fish_history")
    if fish_path is not None:
        targets.append(Target(fish_path, "fish", "shell"))

    return targets


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ProviderFn = Callable[[], List[Target]]

SOURCE_PROVIDERS: List[ProviderFn] = [
    _discover_claude_code,
    _discover_claude_desktop,
    _discover_cursor,
    _discover_zed,
    _discover_vscode_copilot,
    _discover_gemini_cli,
    _discover_aider,
    _discover_codex_cli,
    _discover_shell_histories,
]


_VALID_KINDS = {"ai-chats", "shell", "all"}


def list_targets(source_filter: Optional[List[str]] = None) -> List[Target]:
    """Return every discoverable target, optionally filtered by kind.

    `source_filter` accepts any of "ai-chats", "shell", "all" — or None
    for default behaviour (everything). Unknown filter values raise
    `ValueError` so the CLI surface can report them.
    """
    if source_filter:
        invalid = [s for s in source_filter if s not in _VALID_KINDS]
        if invalid:
            raise ValueError(f"unknown source(s): {', '.join(invalid)}")
        if "all" in source_filter:
            source_filter = None

    # If a provider returns more than this many files it's almost
    # certainly matching a cache directory, not a real chat history.
    # We drop the provider's results entirely rather than scan thousands
    # of unrelated files.
    _PER_PROVIDER_CAP = 500

    seen: set[Path] = set()
    targets: List[Target] = []
    for provider in SOURCE_PROVIDERS:
        try:
            results = provider()
        except Exception:
            continue
        if len(results) > _PER_PROVIDER_CAP:
            # Skip this provider; report nothing rather than wrong things.
            continue
        for t in results:
            if t.path in seen:
                continue
            if source_filter and t.kind not in source_filter:
                continue
            seen.add(t.path)
            targets.append(t)
    return targets
