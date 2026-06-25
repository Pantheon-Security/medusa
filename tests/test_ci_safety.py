#!/usr/bin/env python3
"""
Gate P1-1 — CI safety: scan abort never silently passes.

Asserts:
- The `scan` command exposes --yes / -y and --no-prompt flags.
- A deliberate interactive cancel (user answers "no") exits NON-ZERO.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch


def _get_scan_command():
    """Return the Click scan command object."""
    from medusa.cli import main
    # Walk the command group to find 'scan'
    scan_cmd = main.commands.get('scan')
    if scan_cmd is None:
        # Some Click versions expose via get_command
        scan_cmd = main.get_command(None, 'scan')
    return scan_cmd


class TestCISafetyFlags:
    """P1-1: --yes / --no-prompt flags must exist on the scan command."""

    def test_yes_flag_exists(self):
        """scan command must have a --yes flag"""
        scan_cmd = _get_scan_command()
        assert scan_cmd is not None, "scan command not found on CLI group"
        param_names = [p.name for p in scan_cmd.params]
        # Click stores the long option without leading dashes; 'yes' is the attr name
        assert 'yes' in param_names, f"--yes not found in scan params: {param_names}"

    def test_yes_short_flag_exists(self):
        """scan --yes must also be invocable as -y"""
        scan_cmd = _get_scan_command()
        assert scan_cmd is not None
        # Find the param with name 'yes' and verify '-y' is one of its option strings
        yes_param = next((p for p in scan_cmd.params if p.name == 'yes'), None)
        assert yes_param is not None, "--yes param not found"
        opts = list(yes_param.opts)
        assert '-y' in opts, f"-y short flag missing from yes param opts: {opts}"

    def test_no_prompt_flag_exists(self):
        """scan command must have a --no-prompt flag"""
        scan_cmd = _get_scan_command()
        assert scan_cmd is not None
        param_names = [p.name for p in scan_cmd.params]
        assert 'no_prompt' in param_names, f"--no-prompt not found in scan params: {param_names}"

    def test_help_lists_yes_flag(self, tmp_path):
        """--help output must mention --yes"""
        from medusa.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert '--yes' in result.output or '-y' in result.output, (
            "--yes / -y not visible in scan --help output"
        )

    def test_help_lists_no_prompt_flag(self, tmp_path):
        """--help output must mention --no-prompt"""
        from medusa.cli import main
        runner = CliRunner()
        result = runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert '--no-prompt' in result.output, "--no-prompt not visible in scan --help output"

    def test_yes_flag_accepted_without_error(self, tmp_path):
        """Passing --yes to scan must not produce 'no such option' error"""
        from medusa.cli import main
        runner = CliRunner(mix_stderr=False)
        # We don't need the scan to complete — just confirm the flag is parsed.
        # Use --no-report and a real (empty) tmp_path to short-circuit quickly.
        result = runner.invoke(main, ['scan', '--yes', '--no-report', str(tmp_path)])
        assert 'no such option' not in result.output.lower(), (
            f"--yes was rejected as unknown: {result.output}"
        )
        assert 'no such option' not in (result.stderr or '').lower()

    def test_no_prompt_flag_accepted_without_error(self, tmp_path):
        """Passing --no-prompt to scan must not produce 'no such option' error"""
        from medusa.cli import main
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(main, ['scan', '--no-prompt', '--no-report', str(tmp_path)])
        assert 'no such option' not in result.output.lower(), (
            f"--no-prompt was rejected as unknown: {result.output}"
        )
        assert 'no such option' not in (result.stderr or '').lower()


class TestScanAbortNonZero:
    """P1-1: A deliberate user cancel at the interactive prompt must exit non-zero.

    The cancel path is gated on:
      (a) model files being present in the scan target, AND
      (b) modelscan not being installed, AND
      (c) stdin being a tty (non-CI), AND
      (d) --yes / --no-prompt not being passed.

    Reliably triggering the prompt in CliRunner is hard because CliRunner
    always presents a non-tty stdin.  We therefore test the behaviour via
    targeted unit-level assertions on the CLI source and by patching the
    tty check.
    """

    def test_cancel_response_exits_nonzero_patched(self, tmp_path):
        """When the missing-modelscan prompt is shown and user says 'no', exit code must be non-zero.

        We patch sys.stdin.isatty to True and ai_tools_status to show modelscan
        missing, then create a model file so the critical warning fires, and feed
        'no' as input.  Expects exit code 2 (deliberate abort).
        """
        from medusa.cli import main

        # Create a .pkl model file to trigger the modelscan gate
        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b'\x80\x04\x95')

        runner = CliRunner()

        # get_ai_tools_status is imported locally inside scan(), so we patch it
        # at the source module.  CliRunner replaces sys.stdin with a non-tty
        # BytesIO; the CLI guard is `not sys.stdin.isatty()`.  We therefore
        # also patch medusa.cli.sys so that sys.stdin.isatty() returns True
        # inside the CLI module's execution context.
        import sys as _sys
        import types as _types

        fake_stdin = _types.SimpleNamespace(
            isatty=lambda: True,
            read=lambda n=-1: 'no\n',
            readline=lambda: 'no\n',
        )

        with patch('medusa.platform.installers.simple.get_ai_tools_status',
                   return_value={'modelscan': {'installed': False}}), \
             patch('medusa.cli.sys') as mock_sys:
            # Preserve everything on the real sys; only override stdin.isatty
            mock_sys.configure_mock(**{k: getattr(_sys, k) for k in dir(_sys) if not k.startswith('__')})
            mock_sys.stdin = fake_stdin
            mock_sys.exit = _sys.exit

            result = runner.invoke(
                main,
                ['scan', '--no-report', str(tmp_path)],
                input='no\n',
                catch_exceptions=False,
            )

        # A deliberate abort must NOT exit 0 — that would silently pass in CI
        assert result.exit_code != 0, (
            f"Deliberate cancel returned exit 0 — scan would silently pass in CI. "
            f"Output: {result.output}"
        )

    def test_abort_exit_code_is_two(self, tmp_path):
        """Deliberate cancel should use exit code 2 (distinct from findings=1 and error=3).

        NOTE: This test patches medusa.cli.sys.stdin.isatty() to simulate a real
        TTY so that the interactive prompt code path is reachable from CliRunner.
        If CliRunner's non-tty stdin check changes, this approach may need updating.
        """
        from medusa.cli import main
        import sys as _sys
        import types as _types

        model_file = tmp_path / "model.pkl"
        model_file.write_bytes(b'\x80\x04\x95')

        runner = CliRunner()

        fake_stdin = _types.SimpleNamespace(
            isatty=lambda: True,
            read=lambda n=-1: 'no\n',
            readline=lambda: 'no\n',
        )

        with patch('medusa.platform.installers.simple.get_ai_tools_status',
                   return_value={'modelscan': {'installed': False}}), \
             patch('medusa.cli.sys') as mock_sys:
            mock_sys.configure_mock(**{k: getattr(_sys, k) for k in dir(_sys) if not k.startswith('__')})
            mock_sys.stdin = fake_stdin
            mock_sys.exit = _sys.exit

            result = runner.invoke(
                main,
                ['scan', '--no-report', str(tmp_path)],
                input='no\n',
                catch_exceptions=False,
            )

        # exit 2 is the documented "deliberate user-abort" code
        assert result.exit_code == 2, (
            f"Expected exit code 2 for deliberate abort, got {result.exit_code}. "
            f"Output: {result.output}"
        )
