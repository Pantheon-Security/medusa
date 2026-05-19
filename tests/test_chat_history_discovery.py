"""Tests for discovery of AI chat / shell history artefacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from medusa.core import chat_history_discovery as disc


def _make(path: Path, content: str = "x"):
    """Create a regular file with parent dirs already in place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch) -> Path:
    """Point Path.home() at an empty tmp_path for the duration of the test."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def test_finds_claude_code_history(fake_home: Path):
    _make(fake_home / ".claude" / "history.jsonl", '{"x":1}\n')
    targets = disc.list_targets()
    sources = {t.source for t in targets}
    assert "claude-code" in sources


def test_finds_shell_histories(fake_home: Path):
    _make(fake_home / ".bash_history", "ls\n")
    _make(fake_home / ".zsh_history", ": 1:0;ls\n")
    _make(fake_home / ".python_history", "print(1)\n")

    targets = disc.list_targets()
    sources = {t.source for t in targets}
    assert {"bash", "zsh", "python-repl"}.issubset(sources)


def test_source_filter_ai_chats_excludes_shell(fake_home: Path):
    _make(fake_home / ".claude" / "history.jsonl", "{}\n")
    _make(fake_home / ".bash_history", "x\n")

    ai_only = disc.list_targets(["ai-chats"])
    assert {t.kind for t in ai_only} == {"ai-chats"}

    shell_only = disc.list_targets(["shell"])
    assert {t.kind for t in shell_only} == {"shell"}


def test_source_filter_all_is_synonym_for_default(fake_home: Path):
    _make(fake_home / ".claude" / "history.jsonl", "{}\n")
    _make(fake_home / ".bash_history", "x\n")

    default = {(t.path, t.kind) for t in disc.list_targets()}
    explicit_all = {(t.path, t.kind) for t in disc.list_targets(["all"])}
    assert default == explicit_all


def test_unknown_source_rejected(fake_home: Path):
    with pytest.raises(ValueError):
        disc.list_targets(["browser-passwords"])


def test_provider_returning_too_many_files_is_dropped(
    fake_home: Path, monkeypatch
):
    """If a provider matches more files than the safety cap, none of
    its results may surface — that's what protects against accidental
    globs of cache directories."""

    def runaway() -> list[disc.Target]:
        return [
            disc.Target(fake_home / f"x{i}", "runaway", "ai-chats")
            for i in range(600)
        ]

    monkeypatch.setattr(disc, "SOURCE_PROVIDERS", [runaway])
    targets = disc.list_targets()
    assert targets == []


def test_only_existing_files_returned(fake_home: Path):
    """Providers may name plausible paths that don't exist on this host;
    those must be filtered out."""
    # Don't create any files at all.
    targets = disc.list_targets()
    # The shell-history provider returns [], same for AI providers.
    assert targets == []


def test_deduplicates_across_providers(fake_home: Path, monkeypatch):
    """If two providers happen to surface the same file path, it must
    appear once in the output."""
    shared = fake_home / "shared.jsonl"
    _make(shared, "{}\n")

    def p1():
        return [disc.Target(shared, "p1", "ai-chats")]

    def p2():
        return [disc.Target(shared, "p2", "ai-chats")]

    monkeypatch.setattr(disc, "SOURCE_PROVIDERS", [p1, p2])
    targets = disc.list_targets()
    assert len(targets) == 1
    # First provider wins.
    assert targets[0].source == "p1"
