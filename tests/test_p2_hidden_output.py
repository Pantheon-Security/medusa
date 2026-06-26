#!/usr/bin/env python3
"""
P2-5 gate: 'medusa output' dev command must be hidden from --help or removed.

Expected state: RED — `medusa output` is currently listed in `medusa --help`
because it is declared as @main.command() with no hidden=True.

Post-fix state (must go GREEN after the fix lands):
  - 'output' does NOT appear in the output of `medusa --help`
  - (Either hidden=True was set, or the command was removed entirely)
"""

import pytest
from click.testing import CliRunner

from medusa.cli import main


class TestOutputCommandHidden:
    """The 'output' dev command must not be listed in top-level help."""

    def test_output_not_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0, (
            f"medusa --help exited with code {result.exit_code}:\n{result.output}"
        )
        # 'output' must not appear as a listed command in the help text.
        # We check for 'output' as a command entry — the help format is:
        #   Commands:
        #     output    Development helper: ...
        # Avoid false-matching 'output' inside option descriptions like '--output'
        import re
        # Match 'output' at the start of a line or after whitespace, as a bare command name
        command_listing_pattern = re.compile(
            r'^\s{0,6}output\s', re.MULTILINE
        )
        assert not command_listing_pattern.search(result.output), (
            f"'output' command must not be listed in 'medusa --help'. "
            f"Got help output:\n{result.output}"
        )

    def test_output_command_absent_or_hidden(self):
        """If the command still exists, it must carry hidden=True on the Click command obj."""
        # Access the Click group's commands dict
        commands = main.commands if hasattr(main, 'commands') else {}
        if 'output' not in commands:
            # Removed entirely — that satisfies the gate
            return
        cmd = commands['output']
        assert getattr(cmd, 'hidden', False) is True, (
            "'output' command exists but is not hidden. Set hidden=True or remove the command."
        )
