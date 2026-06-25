#!/usr/bin/env python3
"""
Gate P1-3 — docs honesty.

Asserts that README.md and CLAUDE.md contain NO occurrences of:
  - 'medusa license'      (command doesn't exist in the free package)
  - '--runtime-filters'   (flag doesn't exist in the free package)

These features live in the paid tier only and must not be documented in the
public repo as if they are available to all users.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


class TestDocsHonesty:
    """P1-3: README.md must not reference non-existent free-tier commands."""

    def test_readme_has_no_medusa_license_command(self):
        """README.md must not reference 'medusa license' (command does not exist in free tier)"""
        readme = REPO_ROOT / 'README.md'
        assert readme.exists(), f"README.md not found at {readme}"

        content = readme.read_text(encoding='utf-8')
        occurrences = [
            (i + 1, line.rstrip())
            for i, line in enumerate(content.splitlines())
            if 'medusa license' in line
        ]
        assert not occurrences, (
            "README.md references 'medusa license' which does not exist in the free package. "
            "Lines: " + "; ".join(f"{ln}: {txt!r}" for ln, txt in occurrences)
        )

    def test_readme_has_no_runtime_filters_flag(self):
        """README.md must not reference '--runtime-filters' (flag does not exist in free tier)"""
        readme = REPO_ROOT / 'README.md'
        assert readme.exists(), f"README.md not found at {readme}"

        content = readme.read_text(encoding='utf-8')
        occurrences = [
            (i + 1, line.rstrip())
            for i, line in enumerate(content.splitlines())
            if '--runtime-filters' in line
        ]
        assert not occurrences, (
            "README.md references '--runtime-filters' which does not exist in the free package. "
            "Lines: " + "; ".join(f"{ln}: {txt!r}" for ln, txt in occurrences)
        )

    def test_claude_md_has_no_medusa_license_command(self):
        """CLAUDE.md must not reference 'medusa license' (command does not exist in free tier)"""
        claude_md = REPO_ROOT / 'CLAUDE.md'
        assert claude_md.exists(), f"CLAUDE.md not found at {claude_md}"

        content = claude_md.read_text(encoding='utf-8')
        occurrences = [
            (i + 1, line.rstrip())
            for i, line in enumerate(content.splitlines())
            if 'medusa license' in line
        ]
        assert not occurrences, (
            "CLAUDE.md references 'medusa license' which does not exist in the free package. "
            "Lines: " + "; ".join(f"{ln}: {txt!r}" for ln, txt in occurrences)
        )

    def test_claude_md_has_no_runtime_filters_flag(self):
        """CLAUDE.md must not reference '--runtime-filters' (flag does not exist in free tier)"""
        claude_md = REPO_ROOT / 'CLAUDE.md'
        assert claude_md.exists(), f"CLAUDE.md not found at {claude_md}"

        content = claude_md.read_text(encoding='utf-8')
        occurrences = [
            (i + 1, line.rstrip())
            for i, line in enumerate(content.splitlines())
            if '--runtime-filters' in line
        ]
        assert not occurrences, (
            "CLAUDE.md references '--runtime-filters' which does not exist in the free package. "
            "Lines: " + "; ".join(f"{ln}: {txt!r}" for ln, txt in occurrences)
        )
