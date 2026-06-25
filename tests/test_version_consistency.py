#!/usr/bin/env python3
"""
Gate P1-4 — version consistency + get_stats.

Asserts:
- .medusa.yml version == medusa.__version__
- MedusaConfig() default version == medusa.__version__
- README.md **Version**: line matches medusa.__version__
- medusa/cli.py contains no hardcoded '2026.5.1' strings
- RuleLoader().load_all_rules() + .get_stats() runs without raising
- Total rule count reported by get_stats() is >= 40000
"""

import re
from pathlib import Path

import pytest

# Repo root is two levels up from tests/
REPO_ROOT = Path(__file__).parent.parent


class TestVersionConsistency:
    """P1-4a-c: version strings must match medusa.__version__ everywhere."""

    def test_medusa_yml_version_matches_package(self):
        """'.medusa.yml' version field must match medusa.__version__"""
        import medusa
        import yaml

        medusa_yml = REPO_ROOT / '.medusa.yml'
        assert medusa_yml.exists(), f".medusa.yml not found at {medusa_yml}"

        with open(medusa_yml) as f:
            config = yaml.safe_load(f)

        yml_version = str(config.get('version', ''))
        assert yml_version == medusa.__version__, (
            f".medusa.yml version {yml_version!r} != medusa.__version__ {medusa.__version__!r}"
        )

    def test_medusaconfig_default_version_matches_package(self):
        """MedusaConfig() default version must match medusa.__version__"""
        import medusa
        from medusa.config import MedusaConfig

        cfg = MedusaConfig()
        assert cfg.version == medusa.__version__, (
            f"MedusaConfig().version {cfg.version!r} != medusa.__version__ {medusa.__version__!r}"
        )

    def test_readme_version_line_matches_package(self):
        """README.md '**Version**:' footer line must match medusa.__version__"""
        import medusa

        readme = REPO_ROOT / 'README.md'
        assert readme.exists(), f"README.md not found at {readme}"

        content = readme.read_text(encoding='utf-8')

        # Match the specific "**Version**: X.Y.Z" footer pattern.
        # Be tolerant of surrounding whitespace; do NOT match lines inside
        # changelog history blocks (those use different formatting).
        match = re.search(r'^\*\*Version\*\*:\s*(\S+)', content, re.MULTILINE)
        assert match is not None, (
            "No '**Version**: <ver>' line found in README.md"
        )

        readme_version = match.group(1).strip()
        assert readme_version == medusa.__version__, (
            f"README **Version** line {readme_version!r} != medusa.__version__ {medusa.__version__!r}"
        )


class TestNoHardcodedOldVersion:
    """P1-4d: cli.py must not contain hardcoded '2026.5.1' version strings."""

    def test_cli_has_no_hardcoded_2026_5_1(self):
        """medusa/cli.py must not reference the old hardcoded version '2026.5.1'"""
        cli_file = REPO_ROOT / 'medusa' / 'cli.py'
        assert cli_file.exists(), f"cli.py not found at {cli_file}"

        content = cli_file.read_text(encoding='utf-8')
        # Use word-boundary-equivalent: the version literal with a trailing
        # non-digit so we don't accidentally match '2026.5.10', '2026.5.11', etc.
        occurrences = [
            (i + 1, line.rstrip())
            for i, line in enumerate(content.splitlines())
            if re.search(r'2026\.5\.1(?!\d)', line)
        ]
        assert not occurrences, (
            f"cli.py still contains hardcoded '2026.5.1' on lines: "
            + ", ".join(f"{ln}: {txt!r}" for ln, txt in occurrences)
        )


class TestRuleLoaderGetStats:
    """P1-4e: RuleLoader.get_stats() must work and report >= 40000 rules."""

    def test_get_stats_does_not_raise(self):
        """RuleLoader().load_all_rules() + .get_stats() must not raise any exception"""
        from medusa.rules import RuleLoader

        loader = RuleLoader()
        loader.load_all_rules()          # must not raise
        stats = loader.get_stats()       # must not raise
        assert isinstance(stats, dict), "get_stats() must return a dict"

    def test_get_stats_total_rules_gte_40000(self):
        """Total rule count from get_stats() must be >= 40,000 (guards the marketing claim)"""
        from medusa.rules import RuleLoader

        loader = RuleLoader()
        stats = loader.get_stats()

        total = stats.get('total_rules', 0)
        assert total >= 40000, (
            f"Rule count {total} is below the advertised 40,000+ threshold. "
            "Either rules failed to load or the claim needs updating."
        )

    def test_get_stats_contains_expected_keys(self):
        """get_stats() dict must contain 'total_rules', 'by_severity', and 'categories'"""
        from medusa.rules import RuleLoader

        loader = RuleLoader()
        stats = loader.get_stats()

        for key in ('total_rules', 'by_severity', 'categories'):
            assert key in stats, f"get_stats() missing expected key: {key!r}"
