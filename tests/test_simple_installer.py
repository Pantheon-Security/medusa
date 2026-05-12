#!/usr/bin/env python3
"""
Tests for MEDUSA v2026.2 simplified installer.

Tests the simplified installer that only manages AI security tools.
"""
import pytest
import subprocess
import sys
import shutil
from unittest import mock
from pathlib import Path

from medusa.platform.installers.simple import (
    _in_virtualenv,
    get_pip_command,
    is_pip_available,
    is_tool_installed,
    get_ai_tools_status,
    get_detected_tools,
    get_optional_tools,
    install_ai_tools,
    AI_TOOLS,
)


class TestVirtualenvDetection:
    """Tests for virtualenv detection."""

    def test_in_virtualenv_with_real_prefix(self):
        """Test detection when sys.real_prefix exists."""
        with mock.patch('sys.real_prefix', '/usr', create=True):
            assert _in_virtualenv() is True

    def test_in_virtualenv_with_base_prefix(self):
        """Test detection when base_prefix != prefix."""
        with mock.patch('sys.base_prefix', '/usr/local'):
            with mock.patch('sys.prefix', '/home/user/.venv'):
                assert _in_virtualenv() is True

    def test_not_in_virtualenv(self):
        """Test detection when not in virtualenv."""
        # Remove real_prefix if it exists
        if hasattr(sys, 'real_prefix'):
            delattr(sys, 'real_prefix')

        # Make base_prefix == prefix
        with mock.patch('sys.base_prefix', '/usr'):
            with mock.patch('sys.prefix', '/usr'):
                assert _in_virtualenv() is False


class TestPipCommand:
    """Tests for pip command generation."""

    def test_pip_command_in_venv(self):
        """Test pip command uses sys.executable in venv."""
        with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
            cmd = get_pip_command()
            assert cmd == [sys.executable, '-m', 'pip']

    def test_pip_command_system_pip3(self):
        """Test pip command uses pip3 on system when available."""
        with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=False):
            with mock.patch('shutil.which') as mock_which:
                # pip3 exists
                def which_side_effect(tool):
                    return '/usr/bin/pip3' if tool == 'pip3' else None
                mock_which.side_effect = which_side_effect

                cmd = get_pip_command()
                assert cmd == ['/usr/bin/pip3']

    def test_pip_command_system_pip_fallback(self):
        """Test pip command falls back to sys.executable -m pip when pip/pip3 not on PATH."""
        import sys
        with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=False):
            with mock.patch('shutil.which', return_value=None):
                cmd = get_pip_command()
                assert cmd == [sys.executable, '-m', 'pip']


class TestPipAvailability:
    """Tests for pip availability detection."""

    def test_pip_available_pip3(self):
        """Test pip is detected when pip3 exists."""
        with mock.patch('shutil.which') as mock_which:
            def which_side_effect(tool):
                return '/usr/bin/pip3' if tool == 'pip3' else None
            mock_which.side_effect = which_side_effect

            assert is_pip_available() is True

    def test_pip_available_pip(self):
        """Test pip is detected when pip exists."""
        with mock.patch('shutil.which') as mock_which:
            def which_side_effect(tool):
                return '/usr/bin/pip' if tool == 'pip' else None
            mock_which.side_effect = which_side_effect

            assert is_pip_available() is True

    def test_pip_not_available(self):
        """Test pip is not available when neither pip nor pip3 exist."""
        with mock.patch('shutil.which', return_value=None):
            assert is_pip_available() is False


class TestToolInstallation:
    """Tests for tool installation checking."""

    def test_is_modelscan_installed_true(self):
        """Test checking if modelscan is installed (pip show succeeds)."""
        # Must mock shutil.which to None so the subprocess path is exercised
        # (is_tool_installed checks PATH first; on systems where modelscan is
        # installed it would short-circuit before calling subprocess.run)
        with mock.patch('medusa.platform.installers.simple.shutil.which', return_value=None):
            with mock.patch('subprocess.run') as mock_run:
                mock_run.return_value = mock.Mock(returncode=0)

                assert is_tool_installed('modelscan') is True

                # Verify pip show was called with the tool name
                args = mock_run.call_args[0][0]
                assert 'show' in args
                assert 'modelscan' in args

    def test_is_modelscan_installed_false(self):
        """Test checking if modelscan is not installed (pip show fails)."""
        with mock.patch('medusa.platform.installers.simple.shutil.which', return_value=None):
            with mock.patch('subprocess.run') as mock_run:
                mock_run.return_value = mock.Mock(returncode=1)

                assert is_tool_installed('modelscan') is False

    def test_is_modelscan_installed_exception(self):
        """Test checking modelscan when subprocess raises exception."""
        with mock.patch('medusa.platform.installers.simple.shutil.which', return_value=None):
            with mock.patch('subprocess.run', side_effect=Exception("pip error")):
                assert is_tool_installed('modelscan') is False

    def test_is_other_tool_installed(self):
        """Test checking if non-modelscan tool is installed via PATH."""
        with mock.patch('shutil.which', return_value='/usr/bin/bandit'):
            assert is_tool_installed('bandit') is True

        with mock.patch('shutil.which', return_value=None):
            assert is_tool_installed('bandit') is False

    def test_ai_tools_status(self):
        """Test getting AI tools status."""
        with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=True):
            status = get_ai_tools_status()

            assert 'modelscan' in status
            assert status['modelscan']['installed'] is True
            assert 'description' in status['modelscan']
            assert 'ML model security scanner' in status['modelscan']['description']
            assert status['modelscan']['required'] is True

    def test_ai_tools_status_not_installed(self):
        """Test AI tools status when tools not installed."""
        with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
            status = get_ai_tools_status()

            assert 'modelscan' in status
            assert status['modelscan']['installed'] is False


class TestDetectedTools:
    """Tests for detecting installed tools."""

    def test_detects_shellcheck(self):
        """Test detecting shellcheck."""
        with mock.patch('shutil.which') as mock_which:
            def which_side_effect(tool):
                return '/usr/bin/shellcheck' if tool == 'shellcheck' else None
            mock_which.side_effect = which_side_effect

            detected = get_detected_tools()
            assert 'shellcheck' in detected

    def test_detects_semgrep(self):
        """Test detecting semgrep."""
        with mock.patch('shutil.which') as mock_which:
            def which_side_effect(tool):
                return '/usr/local/bin/semgrep' if tool == 'semgrep' else None
            mock_which.side_effect = which_side_effect

            detected = get_detected_tools()
            assert 'semgrep' in detected

    def test_detects_multiple_tools(self):
        """Test detecting multiple tools."""
        tools_map = {
            'eslint': '/usr/local/bin/eslint',
            'semgrep': '/usr/local/bin/semgrep',
            'shellcheck': '/usr/bin/shellcheck',
        }

        with mock.patch('shutil.which', side_effect=lambda t: tools_map.get(t)):
            detected = get_detected_tools()
            assert 'eslint' in detected
            assert 'semgrep' in detected
            assert 'shellcheck' in detected

    def test_detects_no_tools(self):
        """Test when no optional tools are installed."""
        with mock.patch('shutil.which', return_value=None):
            detected = get_detected_tools()
            assert detected == []

    def test_get_optional_tools_format(self):
        """Test get_optional_tools returns proper format."""
        with mock.patch('shutil.which', return_value='/usr/bin/bandit'):
            tools = get_optional_tools()

            assert isinstance(tools, list)
            assert len(tools) > 0

            # Check first tool has correct structure
            first_tool = tools[0]
            assert 'name' in first_tool
            assert 'description' in first_tool
            assert 'installed' in first_tool
            assert isinstance(first_tool['installed'], bool)


class TestInstallAITools:
    """Tests for installing AI tools."""

    def test_install_ai_tools_no_pip(self):
        """Test install fails gracefully when neither pip nor pipx is available."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=False):
            with mock.patch('medusa.platform.installers.simple._has_pipx', return_value=False):
                with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=False):
                    result = install_ai_tools()

                    assert 'error' in result
                    assert 'pip' in result['error'].lower() or 'pipx' in result['error'].lower()

    def test_install_ai_tools_already_installed(self):
        """Test install skips tools already installed."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=True):
                result = install_ai_tools()

                assert 'modelscan' in result
                assert result['modelscan']['status'] == 'already_installed'

    def test_install_ai_tools_success_in_venv(self):
        """Test successful installation in virtualenv."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
                    with mock.patch('subprocess.run') as mock_run:
                        mock_run.return_value = mock.Mock(returncode=0, stderr='')

                        result = install_ai_tools(verbose=False)

                        assert 'modelscan' in result
                        assert result['modelscan']['status'] == 'installed'

                        # Verify command doesn't include --user in venv
                        cmd = mock_run.call_args[0][0]
                        assert '--user' not in cmd
                        assert '-q' in cmd  # Quiet mode

    def test_install_ai_tools_success_system(self):
        """Test successful installation on system (not virtualenv, no pipx/PEP668)."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=False):
                    # Disable PEP 668 + pipx so fallback uses pip --user
                    with mock.patch('medusa.platform.installers.simple._is_pep668_system', return_value=False):
                        with mock.patch('subprocess.run') as mock_run:
                            mock_run.return_value = mock.Mock(returncode=0, stderr='')

                            result = install_ai_tools(verbose=False)

                            assert 'modelscan' in result
                            assert result['modelscan']['status'] == 'installed'

                            cmd = mock_run.call_args[0][0]
                            assert '--user' in cmd

    def test_install_ai_tools_verbose(self):
        """Test installation with verbose output."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
                    with mock.patch('subprocess.run') as mock_run:
                        mock_run.return_value = mock.Mock(returncode=0, stderr='')

                        result = install_ai_tools(verbose=True)

                        # Verify -q flag is NOT present in verbose mode
                        cmd = mock_run.call_args[0][0]
                        assert '-q' not in cmd

    def test_install_ai_tools_failure(self):
        """Test installation failure handling."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
                    with mock.patch('subprocess.run') as mock_run:
                        mock_run.return_value = mock.Mock(
                            returncode=1,
                            stderr='ERROR: Could not find a version'
                        )

                        result = install_ai_tools()

                        assert 'modelscan' in result
                        assert result['modelscan']['status'] == 'failed'
                        assert 'error' in result['modelscan']

    def test_install_ai_tools_exception(self):
        """Test installation exception handling."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                with mock.patch('subprocess.run', side_effect=Exception("Network error")):
                    result = install_ai_tools()

                    assert 'modelscan' in result
                    assert result['modelscan']['status'] == 'failed'
                    assert 'Network error' in result['modelscan']['error']


class TestCLICommands:
    """Tests for CLI commands."""

    def test_install_check_flag(self):
        """Test medusa install --check."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()

        with mock.patch('medusa.platform.installers.simple.get_ai_tools_status') as mock_status:
            with mock.patch('medusa.platform.installers.simple.get_detected_tools', return_value=['bandit', 'semgrep']):
                mock_status.return_value = {
                    'modelscan': {
                        'installed': True,
                        'description': 'ML model security scanner',
                        'required': True
                    }
                }

                result = runner.invoke(main, ['install', '--check'])

                assert result.exit_code == 0
                assert 'AI Security Rules' in result.output or 'MEDUSA' in result.output

    def test_install_deprecated_all_flag(self):
        """Test medusa install --all shows deprecation."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ['install', '--all'])

        assert result.exit_code == 0
        assert 'deprecated' in result.output.lower()
        assert '2026.2' in result.output or 'ai-tools' in result.output.lower()

    def test_install_ai_tools_flag(self):
        """Test medusa install --ai-tools invokes installation logic."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()

        # CLI --ai-tools has inline install logic (doesn't call install_ai_tools()).
        # Mock is_tool_installed so all tools appear already installed → clean output.
        with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=True):
            with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
                result = runner.invoke(main, ['install', '--ai-tools'])

                assert result.exit_code == 0
                # At least one tool should be acknowledged
                assert 'modelscan' in result.output or 'installed' in result.output.lower()

    def test_uninstall_modelscan(self):
        """Test medusa uninstall modelscan."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()

        with mock.patch('subprocess.run') as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr='')

            # Use --yes to skip confirmation
            result = runner.invoke(main, ['uninstall', 'modelscan', '--yes'])

            assert result.exit_code == 0
            assert mock_run.called

            # Verify correct uninstall command
            cmd = mock_run.call_args[0][0]
            assert 'uninstall' in cmd
            assert 'modelscan' in cmd
            assert '-y' in cmd

    def test_uninstall_other_tool_deprecation(self):
        """Test medusa uninstall shellcheck shows deprecation."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ['uninstall', 'shellcheck', '--yes'])

        assert result.exit_code == 0
        assert "doesn't manage" in result.output or 'package manager' in result.output.lower()

    def test_uninstall_deprecated_all_flag(self):
        """Test medusa uninstall --all shows deprecation."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ['uninstall', '--all'])

        assert result.exit_code == 0
        assert 'deprecated' in result.output.lower()

    def test_uninstall_no_tool_specified(self):
        """Test medusa uninstall with no tool shows usage."""
        from click.testing import CliRunner
        from medusa.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ['uninstall'])

        assert result.exit_code == 0
        assert 'usage' in result.output.lower() or 'modelscan' in result.output.lower()


class TestAIToolsDefinition:
    """Tests for AI_TOOLS configuration."""

    def test_ai_tools_has_modelscan(self):
        """Test AI_TOOLS includes modelscan."""
        assert 'modelscan' in AI_TOOLS

    def test_modelscan_config_structure(self):
        """Test modelscan config has required fields."""
        modelscan = AI_TOOLS['modelscan']

        assert 'pip' in modelscan
        assert 'description' in modelscan
        assert 'required' in modelscan

        assert modelscan['pip'] == 'modelscan'
        assert modelscan['required'] is True

    def test_ai_tools_minimal(self):
        """Test AI_TOOLS contains expected tools and no unexpected extras."""
        # v2026.5.x: modelscan (required) + garak + llm-guard (optional)
        assert 'modelscan' in AI_TOOLS
        assert AI_TOOLS['modelscan']['required'] is True
        assert len(AI_TOOLS) <= 5  # Guard against unreviewed additions


# Integration test
class TestIntegration:
    """Integration tests combining multiple components."""

    def test_install_flow_venv(self):
        """Test complete install flow in virtualenv."""
        with mock.patch('medusa.platform.installers.simple.is_pip_available', return_value=True):
            with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
                # Mock is_tool_installed directly — its shutil.which check would
                # short-circuit and find the real tool before subprocess is tried.
                with mock.patch('medusa.platform.installers.simple.is_tool_installed', return_value=False):
                    with mock.patch('subprocess.run') as mock_run:
                        mock_run.return_value = mock.Mock(returncode=0, stderr='')

                        result = install_ai_tools()

                        assert 'modelscan' in result
                        assert result['modelscan']['status'] == 'installed'

    def test_status_check_flow(self):
        """Test complete status check flow."""
        with mock.patch('subprocess.run') as mock_run:
            mock_run.return_value = mock.Mock(returncode=0)

            with mock.patch('shutil.which') as mock_which:
                mock_which.side_effect = lambda t: f'/usr/bin/{t}' if t in ['shellcheck', 'semgrep'] else None

                # Get AI tools status
                ai_status = get_ai_tools_status()
                assert 'modelscan' in ai_status

                # Get detected tools
                detected = get_detected_tools()
                assert 'shellcheck' in detected
                assert 'semgrep' in detected

                # Get optional tools with install status
                optional = get_optional_tools()
                shellcheck_tool = next((t for t in optional if t['name'] == 'shellcheck'), None)
                assert shellcheck_tool is not None
                assert shellcheck_tool['installed'] is True
                assert 'url' in shellcheck_tool
