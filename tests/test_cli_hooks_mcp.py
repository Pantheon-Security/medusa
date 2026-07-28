"""CLI wiring tests for `medusa mcp` and `medusa hooks` (Phase 2).

These exercise the real command tree via Click's CliRunner and real filesystem
writes in an isolated temp cwd. The MCP server is never actually launched (it
blocks on stdio); we only assert its command/help renders.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from medusa.cli import main


def _git_init_cwd() -> None:
    """CR-024: pre-commit install requires a real git work tree (resolved via git,
    honoring core.hooksPath). A bare `.git` mkdir no longer suffices."""
    if not shutil.which("git"):
        pytest.skip("git not on PATH")
    subprocess.run(["git", "init", "-q"], check=True)


def test_help_lists_mcp_and_hooks():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "mcp" in result.output
    assert "hooks" in result.output


def test_mcp_help_renders_without_launching():
    # `medusa mcp --help` must work; the server itself blocks, so never run it.
    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "gatekeeper" in result.output.lower()


def test_mcp_server_forces_spawn_start_method():
    """B4 regression: the MCP server must use the 'spawn' multiprocessing start
    method so the scan Pool doesn't fork from the asyncio loop and deadlock.
    Checked in a subprocess so it doesn't mutate this test process's global
    start method."""
    import subprocess
    import sys

    code = (
        "import multiprocessing;"
        "from medusa.mcp import server;"
        "server._use_spawn_start_method();"
        "print(multiprocessing.get_start_method())"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "spawn"


def test_hooks_install_all_writes_every_config():
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Init a real repo so the pre-commit gate installs (vs. skipping).
        _git_init_cwd()

        result = runner.invoke(main, ["hooks", "install", "--all"])
        assert result.exit_code == 0, result.output

        assert Path(".claude/settings.json").exists()
        assert Path(".git/hooks/pre-commit").exists()
        assert Path(".cursor/mcp.json").exists()
        assert Path(".codex/config.toml").exists()


def test_hooks_status_reports_present_after_install():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _git_init_cwd()

        install = runner.invoke(main, ["hooks", "install", "--all"])
        assert install.exit_code == 0, install.output

        status = runner.invoke(main, ["hooks", "status"])
        assert status.exit_code == 0, status.output
        # All four configs should be reported present for the current directory.
        assert status.output.count("present") >= 4


def test_hooks_install_skips_pre_commit_without_git():
    runner = CliRunner()
    with runner.isolated_filesystem():
        # No .git dir: pre-commit should be skipped gracefully, others still write.
        result = runner.invoke(main, ["hooks", "install", "--all"])
        assert result.exit_code == 0, result.output
        assert "Skipping pre-commit" in result.output
        assert not Path(".git/hooks/pre-commit").exists()
        assert Path(".claude/settings.json").exists()
