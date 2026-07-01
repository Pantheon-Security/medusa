"""`medusa hooks` command group + `medusa mcp` command.

Wired into the main CLI via ``main.add_command(hooks)`` / ``main.add_command(mcp)``
in ``medusa/cli.py`` (precedent: ``cli_secrets.py``). This is a pure extraction
of the hook/MCP wiring commands out of the 4000-line ``cli.py`` god-file — no
command name, flag, or behavior changes (CR-030).

Commands:
    mcp                  — run the MCP gatekeeper server (scan_repo/scan_skill/…)
    hooks install ...    — install the Claude/Cursor/Codex hooks + MCP configs
    hooks status         — report which hooks/configs are present
"""

from __future__ import annotations

from pathlib import Path

import click


@click.command()
def mcp():
    """Run the MEDUSA MCP gatekeeper server (vet repos/skills/secrets for Claude Code, Cursor, ChatGPT/Codex)."""
    # Import is deferred so the (potentially heavier) MCP stack is only loaded
    # when the server is actually launched, not on every `medusa` invocation.
    from medusa.mcp.server import main as _mcp_main
    _mcp_main()


@click.group()
def hooks():
    """Install/inspect MEDUSA editor hooks + MCP gatekeeper configs."""


@hooks.command('install')
@click.option('--claude', is_flag=True, help='Install the Claude Code hooks (PreToolUse vet + SessionStart), the always-on vet skill, and the project MCP server')
@click.option('--cursor', is_flag=True, help='Install the Cursor MCP server entry')
@click.option('--codex', is_flag=True, help='Install the ChatGPT/Codex MCP server entry')
@click.option('--pre-commit', 'pre_commit', is_flag=True, help='Install the git pre-commit secrets gate')
@click.option('--claude-mcp', 'claude_mcp', is_flag=True,
              help='Register only the project .mcp.json medusa server (idempotent; used by the SessionStart hook)')
@click.option('--all', 'install_all_flag', is_flag=True, help='Install all of the above (default)')
@click.option('--global', '-g', 'is_global', is_flag=True,
              help='Install under your home directory (~) instead of the current directory')
def hooks_install(claude, cursor, codex, pre_commit, claude_mcp, install_all_flag, is_global):
    """Install MEDUSA hooks/MCP configs into this project (or ~ with --global).

    With no scope flag, installs everything (equivalent to --all).
    """
    from medusa.cli import console
    from medusa.hooks import install as hook_install

    base = Path.home() if is_global else Path.cwd()

    # No scope flag given → default to installing everything.
    if not any([claude, cursor, codex, pre_commit, claude_mcp, install_all_flag]):
        install_all_flag = True
    if install_all_flag:
        claude = cursor = codex = pre_commit = True

    console.print(f"[cyan]Installing MEDUSA hooks under[/cyan] {base}\n")
    written: list[Path] = []

    if claude:
        # Full Claude Code wiring: PreToolUse vet hook, SessionStart gatekeeper,
        # the always-on medusa-vet skill, and the project .mcp.json server.
        written.append(hook_install.install_claude_hook(base))
        written.append(hook_install.install_claude_sessionstart(base))
        written.append(hook_install.install_claude_skill(base))
        written.append(hook_install.install_claude_mcp(base))
    elif claude_mcp:
        # Registration-ensure only (invoked by the SessionStart hook).
        written.append(hook_install.install_claude_mcp(base))
    if cursor:
        written.append(hook_install.install_cursor_mcp(base))
    if codex:
        written.append(hook_install.install_codex_mcp(base))
    if pre_commit:
        # pre-commit only makes sense inside a git repo; skip gracefully otherwise.
        if (base / ".git").is_dir():
            written.append(hook_install.install_pre_commit(base))
        else:
            console.print(
                f"[yellow]Skipping pre-commit:[/yellow] no .git directory at {base}. "
                "Run this inside a git repository to install the secrets gate."
            )

    for path in written:
        console.print(f"  [dark_green]✓[/dark_green] {path}")
    if written:
        console.print(f"\n[dark_green]✅ Installed {len(written)} MEDUSA config(s)[/dark_green]")


@hooks.command('status')
def hooks_status():
    """Report which MEDUSA hooks/configs are present at the cwd (and ~)."""
    from medusa.cli import console
    # Detection is owned by the installer module (install.status) so this command
    # cannot drift from the config paths/structure the writers produce (CR-023).
    from medusa.hooks.install import status as _hook_status

    labels = [
        ("Claude PreToolUse hook (.claude/settings.json)", "claude_hook"),
        ("Git pre-commit secrets gate (.git/hooks/pre-commit)", "pre_commit"),
        ("Cursor MCP server (.cursor/mcp.json)", "cursor"),
        ("Codex MCP server (.codex/config.toml)", "codex"),
    ]

    for label, base in (("Current directory", Path.cwd()), ("Home (~)", Path.home())):
        state = _hook_status(base)
        console.print(f"\n[bold cyan]{label}:[/bold cyan] {base}")
        for name, key in labels:
            present = state.get(key, False)
            mark = "[dark_green]✓ present[/dark_green]" if present else "[dim]– absent[/dim]"
            console.print(f"  {mark}  {name}")
    console.print()
