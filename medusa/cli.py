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

# Force UTF-8 encoding for stdout/stderr on Windows to handle emojis
# This fixes UnicodeEncodeError on Windows terminals that default to cp1252
if sys.platform == 'win32':
    import io
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Create console with Windows encoding handling
console = Console()

# Monkey-patch console.print to handle Windows encoding issues
_original_print = console.print

def _safe_print(*args, **kwargs):
    """Windows-safe console.print that removes emojis and Unicode symbols on encoding errors"""
    try:
        _original_print(*args, **kwargs)
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Remove all Unicode characters that might fail on Windows cp1252
        import re
        # Remove emojis, symbols, and other non-Latin characters
        # Keep only ASCII printable + basic Latin chars
        unicode_pattern = re.compile(r'[^\x00-\x7F]+', flags=re.UNICODE)

        safe_args = []
        for arg in args:
            if isinstance(arg, str):
                # Remove Unicode, then clean up extra spaces
                cleaned = unicode_pattern.sub('', arg)
                cleaned = ' '.join(cleaned.split())  # Normalize whitespace
                safe_args.append(cleaned)
            else:
                safe_args.append(arg)

        try:
            _original_print(*safe_args, **kwargs)
        except:
            # Last resort: plain print with ASCII-only
            ascii_text = ' '.join(str(a).encode('ascii', 'ignore').decode('ascii') for a in safe_args)
            try:
                print(ascii_text)
            except:
                pass  # Give up silently

console.print = _safe_print


def _detect_file_types(target_path: Path) -> dict:
    """
    Quick scan to detect file types in target directory

    Returns:
        dict: {file_extension: count} mapping
    """
    from collections import Counter

    file_types = Counter()
    target = Path(target_path)

    # Quick scan - just count extensions
    for file_path in target.rglob('*'):
        if file_path.is_file() and not any(part.startswith('.') for part in file_path.parts):
            ext = file_path.suffix.lower()
            if ext:
                file_types[ext] += 1

    return dict(file_types)


def _get_needed_scanners(file_types: dict):
    """
    Determine which scanners are needed based on file types found

    Args:
        file_types: dict of {extension: count}

    Returns:
        tuple: (needed_scanners, available_scanners, missing_tools)
    """
    from medusa.scanners import registry

    all_scanners = registry.get_all_scanners()
    needed_scanners = []

    # Find scanners that match the file types we found
    for scanner in all_scanners:
        scanner_exts = scanner.get_file_extensions()
        for ext in file_types.keys():
            if ext in scanner_exts:
                if scanner not in needed_scanners:
                    needed_scanners.append(scanner)
                break

    # Check which are available vs missing
    available_scanners = []
    missing_tools = []

    for scanner in needed_scanners:
        if scanner.is_available():
            available_scanners.append(scanner)
        else:
            if scanner.tool_name not in missing_tools:
                missing_tools.append(scanner.tool_name)

    return needed_scanners, available_scanners, missing_tools


def _handle_batch_install(target, auto_install):
    """
    Handle batch installation mode - scan project, show summary, prompt once

    Args:
        target: Target directory to scan
        auto_install: Whether to auto-install without prompting
    """
    console.print("\n[cyan]🔍 Detecting project languages...[/cyan]")

    # Detect file types
    file_types = _detect_file_types(Path(target))

    if not file_types:
        return  # No files found

    # Get needed scanners
    needed_scanners, available_scanners, missing_tools = _get_needed_scanners(file_types)

    if not needed_scanners:
        return  # No scanners needed

    # Show summary
    total_files = sum(file_types.values())
    console.print(f"   Found {total_files} files across {len(file_types)} file types\n")

    # Show scanner status
    if needed_scanners:
        console.print("[bold cyan]📊 Scanner Status:[/bold cyan]")
        for scanner in needed_scanners:
            status = "✅" if scanner.is_available() else "❌"
            scanner_exts = scanner.get_file_extensions()
            exts = ', '.join(scanner_exts[:3])
            if len(scanner_exts) > 3:
                exts += f" (+{len(scanner_exts) - 3} more)"
            console.print(f"   {status} {scanner.name:25} ({scanner.tool_name:15}) → {exts}")

    # Prompt to install missing tools
    if missing_tools:
        console.print(f"\n[bold yellow]📦 Missing Tools ({len(missing_tools)}):[/bold yellow]")

        # Create mapping of tool -> description
        tool_descriptions = {
            scanner.tool_name: f"{scanner.name.replace('Scanner', '')} linter"
            for scanner in needed_scanners
            if not scanner.is_available()
        }

        for tool in missing_tools:
            description = tool_descriptions.get(tool, "security scanner")
            console.print(f"   • {tool:20} ([dim]{description}[/dim])")

        if auto_install:
            console.print("\n[cyan]Auto-installing missing tools...[/cyan]")
            install_tools = True
        else:
            install_tools = click.confirm(f"\nInstall {len(missing_tools)} missing tools?", default=True)

        if install_tools:
            _install_tools(missing_tools)
        else:
            console.print("[dim]Skipping installation. Some files may not be scanned.[/dim]")
    else:
        console.print(f"\n[green]✅ All required scanners are installed![/green]")

    console.print()


def _install_tools(tools: list, use_latest: bool = False):
    """
    Install a list of tools

    Args:
        tools: List of tool names to install
        use_latest: Whether to install latest versions (bypassing version pinning)
    """
    from medusa.platform import get_platform_info
    from medusa.platform.installers import (
        AptInstaller, DnfInstaller, PacmanInstaller,
        HomebrewInstaller, NpmInstaller, PipInstaller, ToolMapper
    )

    platform_info = get_platform_info()
    pm = platform_info.primary_package_manager

    # Get appropriate installer
    installer = None
    if pm:
        from medusa.platform import PackageManager
        installer_map = {
            PackageManager.APT: AptInstaller(),
            PackageManager.DNF: DnfInstaller(),
            PackageManager.PACMAN: PacmanInstaller(),
            PackageManager.BREW: HomebrewInstaller(),
        }
        installer = installer_map.get(pm)

    npm_installer = NpmInstaller() if shutil.which('npm') else None
    pip_installer = PipInstaller() if shutil.which('pip') or shutil.which('pip3') else None

    installed = 0
    failed = 0

    for tool in tools:
        console.print(f"[cyan]Installing {tool}...[/cyan] ", end="")

        success = False

        # Try platform package manager first
        if installer and ToolMapper.get_package_name(tool, pm.value if pm else ''):
            success = installer.install(tool)

        # Try npm for npm tools
        if not success and npm_installer and ToolMapper.is_npm_tool(tool):
            success = npm_installer.install(tool, use_latest=use_latest)

        # Try pip for python tools
        if not success and pip_installer and ToolMapper.is_python_tool(tool):
            success = pip_installer.install(tool, use_latest=use_latest)

        if success:
            console.print("[green]✅[/green]")
            installed += 1
        else:
            console.print("[red]❌[/red]")
            failed += 1

    if installed > 0:
        console.print(f"\n[green]✅ Installed {installed}/{len(tools)} tools[/green]")
    if failed > 0:
        console.print(f"[yellow]⚠️  {failed} tools failed to install (may need manual installation)[/yellow]")


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
@click.option('--install-mode', type=click.Choice(['batch', 'progressive', 'never']),
              default='batch',
              help='How to handle missing linters (batch=ask once, progressive=ask per tool, never=skip)')
@click.option('--auto-install', is_flag=True,
              help='Automatically install missing linters without prompting')
@click.option('--no-install', is_flag=True,
              help='Never prompt for installation (same as --install-mode never)')
def scan(target, workers, quick, force, no_cache, fail_on, output, no_report, install_mode, auto_install, no_install):
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

    # Handle install mode flags
    if no_install:
        install_mode = 'never'

    console.print(f"\n[cyan]🎯 Target:[/cyan] {target}")
    console.print(f"[cyan]🔧 Mode:[/cyan] {'Quick' if quick else 'Force' if force else 'Full'}")

    # Pre-scan for missing linters (batch mode)
    if install_mode == 'batch':
        _handle_batch_install(target, auto_install)

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
@click.option('--ide', multiple=True,
              type=click.Choice(['claude-code', 'cursor', 'gemini-cli', 'openai-codex', 'github-copilot', 'all', 'none']),
              default=None, help='IDE(s) to configure (can specify multiple)')
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
        medusa init                                    # Interactive setup
        medusa init --ide claude-code                  # Setup for Claude Code
        medusa init --ide gemini-cli --ide cursor      # Setup for multiple IDEs
        medusa init --ide all                          # Setup for all IDEs
        medusa init --force                            # Overwrite existing config
        medusa init --install                          # Auto-install missing tools
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

    # Convert ide tuple to list
    ide_list = list(ide) if ide else []

    # Handle 'all' option
    if 'all' in ide_list:
        ide_list = ['claude-code', 'cursor', 'gemini-cli', 'openai-codex', 'github-copilot']

    # Remove 'none' if present with other options
    if 'none' in ide_list and len(ide_list) > 1:
        ide_list.remove('none')

    # Auto-detect IDE if not specified
    if not ide_list or ide_list == ['none']:
        detected_ides = []
        if (project_root / ".claude").exists():
            detected_ides.append('claude-code')
        if (project_root / ".cursor").exists():
            detected_ides.append('cursor')
        if (project_root / ".gemini").exists():
            detected_ides.append('gemini-cli')
        if (project_root / "AGENTS.md").exists():
            detected_ides.append('openai-codex')
        if (project_root / ".github" / "copilot-instructions.md").exists():
            detected_ides.append('github-copilot')

        if detected_ides:
            console.print(f"\n[green]Detected IDE(s):[/green] {', '.join(detected_ides)}")
            if click.confirm("Use detected IDE configuration?", default=True):
                ide_list = detected_ides

        if not ide_list or ide_list == ['none']:
            # Ask user
            console.print("\nWhich IDE(s) are you using? (multiple selections allowed)")
            console.print("  1. Claude Code")
            console.print("  2. Cursor")
            console.print("  3. Gemini CLI")
            console.print("  4. OpenAI Codex")
            console.print("  5. GitHub Copilot")
            console.print("  6. All of the above")
            console.print("  7. None")
            choices = click.prompt("Select IDE(s) (comma-separated, e.g., 1,2,3)", type=str, default="7")

            choice_nums = [int(c.strip()) for c in choices.split(',') if c.strip().isdigit()]
            ide_map = {
                1: 'claude-code',
                2: 'cursor',
                3: 'gemini-cli',
                4: 'openai-codex',
                5: 'github-copilot',
                6: 'all',
                7: 'none'
            }

            ide_list = []
            for num in choice_nums:
                if num == 6:  # All
                    ide_list = ['claude-code', 'cursor', 'gemini-cli', 'openai-codex', 'github-copilot']
                    break
                elif num == 7:  # None
                    if len(choice_nums) == 1:
                        ide_list = ['none']
                    # Skip 'none' if other options selected
                elif num in ide_map:
                    ide_list.append(ide_map[num])

    # Configure IDE settings in config
    for selected_ide in ide_list:
        if selected_ide == 'claude-code':
            config.ide_claude_code_enabled = True
        elif selected_ide == 'cursor':
            config.ide_cursor_enabled = True
        elif selected_ide == 'gemini-cli':
            config.ide_gemini_enabled = True
        elif selected_ide == 'openai-codex':
            config.ide_openai_enabled = True
        elif selected_ide == 'github-copilot':
            config.ide_copilot_enabled = True

    # Save configuration
    ConfigManager.save_config(config, config_path)
    console.print(f"[green]✓[/green] Created {config_path}")

    # Step 4: Setup IDE integration
    if ide_list and ide_list != ['none']:
        console.print(f"\n[bold cyan]Step 4/4: Setting up IDE integration(s)...[/bold cyan]")

        from medusa.ide.claude_code import (
            setup_claude_code,
            setup_cursor,
            setup_gemini_cli,
            setup_openai_codex,
            setup_github_copilot
        )

        success_count = 0
        for selected_ide in ide_list:
            if selected_ide == 'claude-code':
                if setup_claude_code(project_root):
                    console.print("[green]✓[/green] Claude Code integration configured")
                    console.print("  • Created .claude/ directory with agents and commands")
                    console.print("  • Created CLAUDE.md project context")
                    success_count += 1
            elif selected_ide == 'cursor':
                if setup_cursor(project_root):
                    console.print("[green]✓[/green] Cursor integration configured")
                    console.print("  • Created .cursor/mcp-config.json for MCP support")
                    console.print("  • Reused .claude/ structure (Cursor is VS Code fork)")
                    success_count += 1
            elif selected_ide == 'gemini-cli':
                if setup_gemini_cli(project_root):
                    console.print("[green]✓[/green] Gemini CLI integration configured")
                    console.print("  • Created .gemini/commands/ with .toml files")
                    console.print("  • Created GEMINI.md project context")
                    success_count += 1
            elif selected_ide == 'openai-codex':
                if setup_openai_codex(project_root):
                    console.print("[green]✓[/green] OpenAI Codex integration configured")
                    console.print("  • Created AGENTS.md project context")
                    success_count += 1
            elif selected_ide == 'github-copilot':
                if setup_github_copilot(project_root):
                    console.print("[green]✓[/green] GitHub Copilot integration configured")
                    console.print("  • Created .github/copilot-instructions.md")
                    success_count += 1

        console.print(f"\n[green]✓[/green] Configured {success_count}/{len(ide_list)} IDE integration(s)")
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
@click.argument('tool', required=False)
@click.option('--check', is_flag=True, help='Check which linters are installed')
@click.option('--all', is_flag=True, help='Install all missing linters')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
@click.option('--use-latest', is_flag=True, help='Install latest versions (bypass version pinning)')
def install(tool, check, all, yes, use_latest):
    """
    Install security linters for your platform.

    MEDUSA uses multiple linters (shellcheck, bandit, hadolint, etc.)
    This command helps you install them on your OS.

    Examples:
        medusa install --check        # Check what's installed
        medusa install --all          # Install all missing linters
        medusa install shellcheck     # Install specific tool
        medusa install                # Interactive selection
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
                success = npm_installer.install(tool, use_latest=use_latest)
                if success:
                    console.print(f"[green]✅ Successfully installed {tool}[/green]")
                else:
                    console.print(f"[red]❌ Failed to install {tool}[/red]")
            elif ToolMapper.get_package_name(tool, 'pip') and pip_installer:
                cmd = pip_installer.get_install_command(tool)
                console.print(f"[dim]Command: {cmd}[/dim]\n")
                success = pip_installer.install(tool, use_latest=use_latest)
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
                success = npm_installer.install(tool_name, use_latest=use_latest)

            # Try pip
            if not success and pip_installer and ToolMapper.get_package_name(tool_name, 'pip'):
                success = pip_installer.install(tool_name, use_latest=use_latest)

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
@click.argument('tool', required=False)
@click.option('--all', is_flag=True, help='Uninstall all MEDUSA scanner tools')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
def uninstall(tool, all, yes):
    """
    Uninstall security scanner tools.

    Examples:
        medusa uninstall shellcheck  # Uninstall specific tool
        medusa uninstall --all       # Uninstall all tools
    """
    print_banner()

    console.print("\n[cyan]📦 Tool Uninstallation[/cyan]\n")

    from medusa.platform import get_platform_info
    from medusa.scanners import registry
    from medusa.platform.installers import (
        AptInstaller, YumInstaller, DnfInstaller, PacmanInstaller,
        HomebrewInstaller, NpmInstaller, PipInstaller, ToolMapper
    )

    platform_info = get_platform_info()

    # Get installed tools
    installed_tools = []
    for scanner in registry.get_all_scanners():
        if scanner.is_available():
            tool_name = scanner.command
            if tool_name and tool_name not in installed_tools:
                installed_tools.append(tool_name)

    if not installed_tools:
        console.print("[yellow]No MEDUSA scanner tools found to uninstall[/yellow]")
        return

    # Uninstall specific tool
    if tool:
        if tool not in installed_tools:
            console.print(f"[yellow]Tool '{tool}' is not installed or not a MEDUSA scanner tool[/yellow]")
            return

        if not yes:
            confirm = click.confirm(f"Uninstall {tool}?", default=False)
            if not confirm:
                console.print("[yellow]Uninstallation cancelled[/yellow]")
                return

        console.print(f"[cyan]Uninstalling {tool}...[/cyan] ", end="")

        # Get appropriate installer
        pm = platform_info.primary_package_manager
        installer = None

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

        npm_installer = NpmInstaller() if shutil.which('npm') else None
        pip_installer = PipInstaller() if shutil.which('pip') else None

        success = False

        # Try appropriate uninstaller
        if installer and ToolMapper.get_package_name(tool, pm.value if pm else ''):
            success = installer.uninstall(tool)
        elif npm_installer and ToolMapper.is_npm_tool(tool):
            success = npm_installer.uninstall(tool)
        elif pip_installer and ToolMapper.is_python_tool(tool):
            success = pip_installer.uninstall(tool)

        if success:
            console.print("[green]✅[/green]")
        else:
            console.print("[red]❌[/red]")
            console.print(f"[yellow]Note: You may need to uninstall {tool} manually[/yellow]")

    # Uninstall all tools
    elif all:
        console.print(f"[bold]Found {len(installed_tools)} installed tools:[/bold]")
        for t in installed_tools:
            console.print(f"  • {t}")
        console.print()

        if not yes:
            confirm = click.confirm(f"Uninstall all {len(installed_tools)} tools?", default=False)
            if not confirm:
                console.print("[yellow]Uninstallation cancelled[/yellow]")
                return

        # Get appropriate installer
        pm = platform_info.primary_package_manager
        installer = None

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

        npm_installer = NpmInstaller() if shutil.which('npm') else None
        pip_installer = PipInstaller() if shutil.which('pip') else None

        uninstalled = 0
        failed = 0

        for tool_name in installed_tools:
            console.print(f"[cyan]Uninstalling {tool_name}...[/cyan]", end=" ")

            success = False

            # Try appropriate uninstaller
            if installer and ToolMapper.get_package_name(tool_name, pm.value if pm else ''):
                success = installer.uninstall(tool_name)
            elif npm_installer and ToolMapper.is_npm_tool(tool_name):
                success = npm_installer.uninstall(tool_name)
            elif pip_installer and ToolMapper.is_python_tool(tool_name):
                success = pip_installer.uninstall(tool_name)

            if success:
                console.print("[green]✅[/green]")
                uninstalled += 1
            else:
                console.print("[red]❌[/red]")
                failed += 1

        console.print()
        console.print(f"[bold]Uninstallation Summary:[/bold]")
        console.print(f"  ✅ Uninstalled: {uninstalled}")
        if failed > 0:
            console.print(f"  ❌ Failed: {failed}")

    else:
        console.print("[yellow]Please specify a tool name or use --all[/yellow]")
        console.print(f"\n[bold]Currently installed tools:[/bold]")
        for t in installed_tools:
            console.print(f"  • {t}")
        console.print(f"\n[dim]Example: medusa uninstall shellcheck[/dim]")


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


@main.command()
@click.option('--check-updates', is_flag=True, help='Check for newer versions')
def versions(check_updates):
    """
    Show pinned tool versions from tool-versions.lock.

    Displays the versions of external security tools that MEDUSA will install.
    This ensures reproducible scans across environments.
    """
    from medusa.platform.version_manager import VersionManager
    from rich.table import Table

    vm = VersionManager()

    if not vm.is_locked():
        console.print("[yellow]⚠ No tool-versions.lock found[/yellow]")
        console.print("[dim]Run 'python scripts/capture_tool_versions.py' to create it[/dim]")
        return

    # Show metadata
    meta = vm.get_metadata()
    console.print(f"\n[bold cyan]MEDUSA Tool Versions[/bold cyan]")
    console.print(f"[dim]Lock file version: {meta.get('lockfile_version')}[/dim]")
    console.print(f"[dim]MEDUSA version: {meta.get('medusa_version')}[/dim]")
    console.print(f"[dim]Generated: {meta.get('generated_at', '').split('T')[0]}[/dim]\n")

    # Create table
    table = Table(title="Pinned Tool Versions", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="cyan")
    table.add_column("Tool", style="magenta")
    table.add_column("Version", style="green")

    all_versions = vm.get_all_versions()
    for category, tools in sorted(all_versions.items()):
        for i, (tool, version) in enumerate(sorted(tools.items())):
            cat_display = category.title() if i == 0 else ""
            table.add_row(cat_display, tool, version)

    console.print(table)

    total = sum(len(tools) for tools in all_versions.values())
    console.print(f"\n[bold]Total: {total} pinned tools[/bold]")
    console.print(f"[dim]Use --use-latest flag with 'medusa install' to bypass pinning[/dim]\n")


if __name__ == '__main__':
    main()
