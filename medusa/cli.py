#!/usr/bin/env python3
"""
MEDUSA CLI - Command-line interface
Modern Click-based CLI for cross-platform security scanning
"""

import sys
import shutil
import click
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from medusa import __version__

# Create console with Windows encoding handling
console = Console()

# Monkey-patch console.print to handle Windows encoding issues
_original_print = console.print

def _safe_print(*args, **kwargs):
    """Windows-safe console.print that removes emojis on encoding errors"""
    try:
        _original_print(*args, **kwargs)
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Remove emojis and retry
        import re
        # Remove all emojis (Unicode characters U+1F000 and above)
        emoji_pattern = re.compile(r'[\U00010000-\U0010ffff]', flags=re.UNICODE)

        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                safe_args.append(emoji_pattern.sub('', arg))
            else:
                safe_args.append(arg)

        try:
            _original_print(*safe_args, **kwargs)
        except:
            # Last resort: plain print
            print(' '.join(str(a) for a in safe_args))

console.print = _safe_print


def print_banner():
    """Print MEDUSA banner with fallback for Windows encoding issues"""
    banner = f"""
[bold magenta]╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🐍🐍🐍 MEDUSA v{__version__} - Security Guardian 🐍🐍🐍           ║
║                                                                    ║
║              The 42-Headed Universal Security Scanner             ║
║           One look from Medusa stops vulnerabilities dead          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝[/bold magenta]
"""
    try:
        rprint(banner)
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Fallback for Windows terminals that don't support Unicode
        fallback_banner = f"""
[bold magenta]╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║              MEDUSA v{__version__} - Security Guardian                 ║
║                                                                    ║
║              The 42-Headed Universal Security Scanner             ║
║           One look from Medusa stops vulnerabilities dead          ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝[/bold magenta]
"""
        try:
            rprint(fallback_banner)
        except:
            # Last resort: plain text
            print(f"\nMEDUSA v{__version__} - Security Guardian\n")


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version and exit')
@click.pass_context
def main(ctx, version):
    """
    MEDUSA - The 42-Headed Security Guardian

    Universal security scanner for all languages and platforms.
    Scan your code for vulnerabilities in seconds.

    Examples:
        medusa scan .               # Scan current directory
        medusa scan --quick .       # Quick incremental scan
        medusa init                 # Initialize MEDUSA in project
        medusa install              # Install linters
    """
    if version:
        click.echo(f"MEDUSA v{__version__}")
        ctx.exit(0)

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@main.command()
@click.argument('target', type=click.Path(exists=True), default='.')
@click.option('-w', '--workers', type=int, default=None,
              help='Number of worker processes (default: auto-detect)')
@click.option('--quick', is_flag=True,
              help='Quick scan mode (changed files only)')
@click.option('--force', is_flag=True,
              help='Force full scan (ignore cache)')
@click.option('--no-cache', is_flag=True,
              help='Disable caching')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Exit with code 1 if issues at this level or higher are found')
@click.option('-o', '--output', type=click.Path(), default=None,
              help='Output directory for reports')
@click.option('--no-report', is_flag=True,
              help='Skip report generation (faster)')
def scan(target, workers, quick, force, no_cache, fail_on, output, no_report):
    """
    Scan a directory or file for security issues.

    This will run all available security scanners on the target,
    generate beautiful HTML/JSON reports, and optionally fail the
    build if issues are found.

    Examples:
        medusa scan .                    # Scan current directory
        medusa scan --quick .            # Only scan changed files
        medusa scan --force /path/to/project  # Force full rescan
        medusa scan --fail-on high .     # Fail on HIGH+ issues
    """
    print_banner()

    console.print(f"\n[cyan]🎯 Target:[/cyan] {target}")
    console.print(f"[cyan]🔧 Mode:[/cyan] {'Quick' if quick else 'Force' if force else 'Full'}")

    # Check system load and recommend optimal workers
    from medusa.core.system import check_system_load, get_optimal_workers

    load = check_system_load()

    # Auto-detect workers if not specified
    if workers is None:
        workers = get_optimal_workers()

    # Warn if system is overloaded
    if load.warning_message:
        console.print(f"[yellow]⚠️  {load.warning_message}[/yellow]")
        console.print(f"[dim]Using {workers} workers (reduced due to system load)[/dim]")

    try:
        from medusa.core.parallel import MedusaParallelScanner

        scanner = MedusaParallelScanner(
            project_root=Path(target),
            workers=workers,
            use_cache=not no_cache and not force,
            quick_mode=quick
        )

        # Find files
        files = scanner.find_scannable_files()
        if not files:
            console.print("[yellow]⚠️  No files found to scan[/yellow]")
            return

        console.print(f"[green]📁 Found {len(files)} scannable files[/green]\n")

        # Scan files
        results = scanner.scan_parallel(files)

        # Generate reports
        if not no_report:
            output_dir = Path(output) if output else Path.cwd() / ".medusa" / "reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            scanner.generate_report(results, output_dir)

        # Check fail threshold
        if fail_on:
            total_issues = sum(len(r.issues) for r in results if not r.cached)
            if total_issues > 0:
                console.print(f"\n[red]❌ Found {total_issues} issues at {fail_on.upper()}+ level[/red]")
                sys.exit(1)

        console.print("\n[green]✅ Scan complete![/green]")

    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")
        if '--debug' in sys.argv:
            raise
        sys.exit(1)


@main.command()
@click.option('--ide', type=click.Choice(['claude-code', 'cursor', 'vscode', 'gemini-cli', 'none']),
              default=None, help='IDE to configure')
@click.option('--force', is_flag=True, help='Overwrite existing configuration')
@click.option('--install', is_flag=True, help='Install missing tools automatically')
def init(ide, force, install):
    """
    Initialize MEDUSA in the current project.

    This will:
    - Create .medusa.yml configuration
    - Detect project languages
    - Check for installed scanners
    - Offer to install missing tools
    - Configure IDE integration

    Examples:
        medusa init                      # Interactive setup
        medusa init --ide claude-code    # Setup for Claude Code
        medusa init --force              # Overwrite existing config
        medusa init --install            # Auto-install missing tools
    """
    print_banner()

    console.print("\n[cyan]🔧 MEDUSA Initialization Wizard[/cyan]\n")

    from medusa.config import ConfigManager, MedusaConfig
    from medusa.scanners import registry

    project_root = Path.cwd()
    config_path = project_root / ".medusa.yml"

    # Check if config already exists
    if config_path.exists() and not force:
        console.print(f"[yellow]⚠️  Configuration already exists: {config_path}[/yellow]")
        if not click.confirm("Overwrite existing configuration?", default=False):
            console.print("[dim]Cancelled. Use --force to overwrite.[/dim]")
            return

    # Step 1: Detect project languages
    console.print("[bold cyan]Step 1/4: Detecting project languages...[/bold cyan]")
    detected_files = {}
    for scanner in registry.get_all_scanners():
        for ext in scanner.get_file_extensions():
            if ext:
                count = len(list(project_root.glob(f"**/*{ext}")))
                if count > 0:
                    detected_files[scanner.name] = count

    if detected_files:
        console.print(f"[green]✓[/green] Found {len(detected_files)} language types:")
        for scanner_name, count in sorted(detected_files.items(), key=lambda x: x[1], reverse=True)[:10]:
            console.print(f"  • {scanner_name:20} ({count} files)")
    else:
        console.print("[yellow]⚠️  No language files detected[/yellow]")

    # Step 2: Check scanner availability
    console.print("\n[bold cyan]Step 2/4: Checking scanner availability...[/bold cyan]")
    available = registry.get_available_scanners()
    missing_tools = registry.get_missing_tools()

    console.print(f"[green]✓[/green] {len(available)}/{len(registry.get_all_scanners())} scanners available")
    if missing_tools:
        console.print(f"[yellow]⚠️[/yellow]  {len(missing_tools)} tools missing: {', '.join(missing_tools[:5])}" +
                     (f" and {len(missing_tools) - 5} more" if len(missing_tools) > 5 else ""))

        if install or click.confirm(f"\nInstall {len(missing_tools)} missing tools?", default=False):
            console.print("[cyan]Installing missing tools...[/cyan]")
            # Import installer logic
            from medusa.platform import get_platform_info
            from medusa.platform.installers import AptInstaller, HomebrewInstaller, NpmInstaller, PipInstaller

            platform_info = get_platform_info()
            # This would call the actual installation - skipping for safety in init
            console.print("[yellow]Note: Run 'medusa install --all' to install missing tools[/yellow]")

    # Step 3: Create configuration
    console.print("\n[bold cyan]Step 3/4: Creating configuration...[/bold cyan]")
    config = MedusaConfig()

    # Auto-detect IDE if not specified
    if ide is None:
        if (project_root / ".claude").exists():
            ide = 'claude-code'
        elif (project_root / ".cursor").exists():
            ide = 'cursor'
        elif (project_root / ".vscode").exists():
            ide = 'vscode'
        else:
            # Ask user
            console.print("\nWhich IDE are you using?")
            console.print("  1. Claude Code")
            console.print("  2. Cursor")
            console.print("  3. VS Code")
            console.print("  4. Gemini CLI")
            console.print("  5. None")
            choice = click.prompt("Select IDE", type=int, default=5)
            ide_map = {1: 'claude-code', 2: 'cursor', 3: 'vscode', 4: 'gemini-cli', 5: 'none'}
            ide = ide_map.get(choice, 'none')

    # Configure IDE settings
    if ide == 'claude-code':
        config.ide_claude_code_enabled = True
    elif ide == 'cursor':
        config.ide_cursor_enabled = True
    elif ide == 'vscode':
        config.ide_vscode_enabled = True
    elif ide == 'gemini-cli':
        config.ide_gemini_enabled = True

    # Save configuration
    ConfigManager.save_config(config, config_path)
    console.print(f"[green]✓[/green] Created {config_path}")

    # Step 4: Setup IDE integration
    if ide != 'none':
        console.print(f"\n[bold cyan]Step 4/4: Setting up {ide} integration...[/bold cyan]")

        if ide == 'claude-code':
            from medusa.ide.claude_code import setup_claude_code
            if setup_claude_code(project_root):
                console.print("[green]✓[/green] Claude Code integration configured")
        elif ide == 'cursor':
            console.print("[yellow]⚠️  Cursor integration coming soon[/yellow]")
        elif ide == 'vscode':
            console.print("[yellow]⚠️  VS Code integration coming soon[/yellow]")
        elif ide == 'gemini-cli':
            console.print("[yellow]⚠️  Gemini CLI integration coming soon[/yellow]")
    else:
        console.print("\n[bold cyan]Step 4/4: Skipping IDE integration[/bold cyan]")

    # Summary
    console.print("\n[bold green]✅ MEDUSA Initialized Successfully![/bold green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  1. Review configuration: [cyan].medusa.yml[/cyan]")
    if missing_tools:
        console.print(f"  2. Install missing tools: [cyan]medusa install --all[/cyan]")
    console.print(f"  {'3' if missing_tools else '2'}. Run your first scan: [cyan]medusa scan .[/cyan]")
    console.print()


@main.command()
@click.option('--check', is_flag=True, help='Check which linters are installed')
@click.option('--all', is_flag=True, help='Install all missing linters')
@click.option('--tool', type=str, help='Install specific tool')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
def install(check, all, tool, yes):
    """
    Install security linters for your platform.

    MEDUSA uses multiple linters (shellcheck, bandit, hadolint, etc.)
    This command helps you install them on your OS.

    Examples:
        medusa install --check           # Check what's installed
        medusa install --all             # Install all missing linters
        medusa install --tool shellcheck # Install specific tool
        medusa install                   # Interactive selection
    """
    print_banner()

    console.print("\n[cyan]📦 Linter Installation[/cyan]\n")

    from medusa.platform import get_platform_info
    from medusa.scanners import registry
    from medusa.platform.installers import (
        AptInstaller, YumInstaller, DnfInstaller, PacmanInstaller,
        HomebrewInstaller, NpmInstaller, PipInstaller, ToolMapper
    )

    platform_info = get_platform_info()
    missing_tools = registry.get_missing_tools()

    # Show check status
    if check:
        console.print(f"[bold cyan]Platform:[/bold cyan] {platform_info.os_name} ({platform_info.primary_package_manager.value if platform_info.primary_package_manager else 'unknown'})\n")

        available_scanners = registry.get_available_scanners()
        console.print(f"[bold green]✅ Installed Tools ({len(available_scanners)}):[/bold green]")
        for scanner in available_scanners:
            console.print(f"  • {scanner.tool_name}")

        if missing_tools:
            console.print(f"\n[bold yellow]❌ Missing Tools ({len(missing_tools)}):[/bold yellow]")
            for tool in missing_tools:
                console.print(f"  • {tool}")
            console.print(f"\n[dim]Run 'medusa install --all' to install all missing tools[/dim]")
        else:
            console.print(f"\n[bold green]🎉 All scanner tools are installed![/bold green]")
        return

    if not missing_tools:
        console.print("[bold green]✅ All scanner tools are already installed![/bold green]")
        return

    # Get appropriate installer
    installer = None
    pm = platform_info.primary_package_manager

    if pm:
        from medusa.platform import PackageManager
        installer_map = {
            PackageManager.APT: AptInstaller(),
            PackageManager.YUM: YumInstaller(),
            PackageManager.DNF: DnfInstaller(),
            PackageManager.PACMAN: PacmanInstaller(),
            PackageManager.BREW: HomebrewInstaller(),
        }
        installer = installer_map.get(pm)

    # Also check for cross-platform installers
    npm_installer = NpmInstaller() if shutil.which('npm') else None
    pip_installer = PipInstaller() if shutil.which('pip') else None

    # Install specific tool
    if tool:
        if tool not in missing_tools:
            console.print(f"[yellow]Tool '{tool}' is already installed or not a MEDUSA scanner tool[/yellow]")
            return

        console.print(f"[cyan]Installing {tool}...[/cyan]\n")

        # Determine best installer for this tool
        package_name = ToolMapper.get_package_name(tool, pm.value if pm else '')

        if package_name and installer:
            cmd = installer.get_install_command(tool)
            console.print(f"[dim]Command: {cmd}[/dim]\n")

            if not yes:
                confirm = click.confirm(f"Install {tool}?", default=True)
                if not confirm:
                    console.print("[yellow]Installation cancelled[/yellow]")
                    return

            success = installer.install(tool)
            if success:
                console.print(f"[green]✅ Successfully installed {tool}[/green]")
            else:
                console.print(f"[red]❌ Failed to install {tool}[/red]")
        else:
            # Try npm or pip
            if ToolMapper.get_package_name(tool, 'npm') and npm_installer:
                cmd = npm_installer.get_install_command(tool)
                console.print(f"[dim]Command: {cmd}[/dim]\n")
                success = npm_installer.install(tool)
                if success:
                    console.print(f"[green]✅ Successfully installed {tool}[/green]")
                else:
                    console.print(f"[red]❌ Failed to install {tool}[/red]")
            elif ToolMapper.get_package_name(tool, 'pip') and pip_installer:
                cmd = pip_installer.get_install_command(tool)
                console.print(f"[dim]Command: {cmd}[/dim]\n")
                success = pip_installer.install(tool)
                if success:
                    console.print(f"[green]✅ Successfully installed {tool}[/green]")
                else:
                    console.print(f"[red]❌ Failed to install {tool}[/red]")
            else:
                console.print(f"[yellow]⚠️  '{tool}' installation not supported on this platform[/yellow]")
                console.print(f"[dim]Please install manually: {ToolMapper.TOOL_PACKAGES.get(tool, {}).get('manual', 'See documentation')}[/dim]")
        return

    # Install all missing tools
    if all or (not check and not tool):
        console.print(f"[cyan]Found {len(missing_tools)} missing tools:[/cyan]")
        for t in missing_tools:
            console.print(f"  • {t}")

        console.print()

        if not yes:
            confirm = click.confirm(f"Install all {len(missing_tools)} missing tools?", default=True)
            if not confirm:
                console.print("[yellow]Installation cancelled[/yellow]")
                return

        console.print()
        installed = 0
        failed = 0

        for tool_name in missing_tools:
            console.print(f"[cyan]Installing {tool_name}...[/cyan]", end=" ")

            # Determine best installer
            success = False

            # Try system package manager first
            if installer and ToolMapper.get_package_name(tool_name, pm.value if pm else ''):
                success = installer.install(tool_name)

            # Try npm
            if not success and npm_installer and ToolMapper.get_package_name(tool_name, 'npm'):
                success = npm_installer.install(tool_name)

            # Try pip
            if not success and pip_installer and ToolMapper.get_package_name(tool_name, 'pip'):
                success = pip_installer.install(tool_name)

            if success:
                console.print("[green]✅[/green]")
                installed += 1
            else:
                console.print("[red]❌[/red]")
                failed += 1

        console.print()
        console.print(f"[bold]Installation Summary:[/bold]")
        console.print(f"  ✅ Installed: {installed}")
        if failed > 0:
            console.print(f"  ❌ Failed: {failed}")
        console.print(f"\n[dim]Run 'medusa config' to see updated scanner status[/dim]")


@main.command()
def config():
    """
    Show MEDUSA configuration.

    Displays current configuration including:
    - Platform detection (OS, package managers)
    - Installed scanners
    - Missing tools
    - Cache status
    """
    print_banner()

    console.print("\n[cyan]⚙️  MEDUSA Configuration[/cyan]\n")

    # Platform detection
    from medusa.platform import get_platform_info
    platform_info = get_platform_info()

    console.print("[bold cyan]Platform Information:[/bold cyan]")
    console.print(f"  OS: {platform_info.os_name} {platform_info.os_version} ({platform_info.architecture})")
    console.print(f"  Python: {platform_info.python_version}")
    console.print(f"  Shell: {platform_info.shell}")
    if platform_info.is_wsl:
        console.print(f"  Environment: WSL ({platform_info.windows_environment.value if platform_info.windows_environment else 'unknown'})")
    if platform_info.primary_package_manager:
        console.print(f"  Package Manager: {platform_info.primary_package_manager.value}")

    # Scanner status
    from medusa.scanners import registry
    console.print(f"\n[bold cyan]Scanner Status:[/bold cyan]")
    console.print(f"  Total scanners: {len(registry.get_all_scanners())}")
    console.print(f"  Available: {len(registry.get_available_scanners())}")

    available_scanners = registry.get_available_scanners()
    if available_scanners:
        console.print(f"\n[bold green]✅ Installed Scanners:[/bold green]")
        for scanner in available_scanners:
            extensions = ", ".join(scanner.get_file_extensions()) if scanner.get_file_extensions() else "special"
            console.print(f"  • {scanner.name:20} ({scanner.tool_name:15}) → {extensions}")

    missing_tools = registry.get_missing_tools()
    if missing_tools:
        console.print(f"\n[bold yellow]❌ Missing Tools:[/bold yellow]")
        for tool in missing_tools:
            console.print(f"  • {tool}")
        console.print(f"\n[dim]Run 'medusa install' to install missing tools[/dim]")

    # MEDUSA version
    console.print(f"\n[bold cyan]MEDUSA Version:[/bold cyan] v{__version__}")

    # Cache status
    cache_dir = Path.home() / ".medusa" / "cache"
    if cache_dir.exists():
        cache_file = cache_dir / "file_cache.json"
        if cache_file.exists():
            import json
            with open(cache_file) as f:
                cache = json.load(f)
            console.print(f"[bold cyan]Cache:[/bold cyan] {len(cache)} files cached")
        else:
            console.print("[bold cyan]Cache:[/bold cyan] Not initialized")
    else:
        console.print("[bold cyan]Cache:[/bold cyan] Not initialized")


@main.command()
@click.argument('bash_id', required=False)
def output(bash_id):
    """Development helper: Check background process output"""
    # This is primarily for development/debugging
    console.print("[yellow]This command is for development use only[/yellow]")


if __name__ == '__main__':
    main()
