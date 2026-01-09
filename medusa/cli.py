#!/usr/bin/env python3
"""
MEDUSA CLI - Command-line interface
Modern Click-based CLI for cross-platform security scanning
"""

import sys
import shutil
import subprocess
import click
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print as rprint

from medusa import __version__
from medusa.platform.install_manifest import get_manifest

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


def _safe_run_version_check(command: list, timeout: int = 5) -> tuple[bool, str]:
    """
    Safely run a version check command.

    Args:
        command: List of command and arguments
        timeout: Timeout in seconds

    Returns:
        Tuple of (success: bool, output: str)
    """
    import subprocess
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return (result.returncode == 0, result.stdout)
    except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
        return (False, "")


def _detect_tool_version(tool_name: str, package_manager: Optional[str] = None) -> Optional[str]:
    """
    Detect the installed version of a tool for manifest fingerprinting.

    This tries multiple common version flags and extracts semantic version numbers.
    Used to detect if a user has manually upgraded/modified a tool.

    Args:
        tool_name: Name of the tool to check
        package_manager: Optional package manager hint ('npm', 'pip', etc.) for faster detection

    Returns:
        Version string (e.g., "1.2.3") or None if version couldn't be detected
    """
    import subprocess
    import re
    import shutil
    import platform
    from medusa.platform.installers.base import ToolMapper

    # Strategy 1: Query package manager directly (most reliable, especially on Windows after fresh install)
    if package_manager == 'npm':
        try:
            # Get npm command (use npm.cmd on Windows)
            npm_cmd = 'npm.cmd' if platform.system() == 'Windows' else 'npm'
            package_name = ToolMapper.get_package_name(tool_name, 'npm')

            result = subprocess.run(
                [npm_cmd, 'list', '-g', '--depth=0', package_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False
            )

            if result.returncode == 0 or result.stdout:
                # Output format: "├── eslint@9.15.0" or "└── eslint@9.15.0"
                output = result.stdout
                match = re.search(rf'{re.escape(package_name)}@(\d+\.\d+\.\d+(?:\.\d+)?)', output)
                if match:
                    return match.group(1)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass  # Fall through to direct tool version check

    elif package_manager == 'pip':
        try:
            # Windows: use 'py -m pip', Unix: use 'pip3' or 'pip'
            if platform.system() == 'Windows':
                pip_cmd = ['py', '-m', 'pip']
            else:
                pip_cmd = ['pip3'] if shutil.which('pip3') else ['pip']

            package_name = ToolMapper.get_package_name(tool_name, 'pip')
            result = subprocess.run(
                pip_cmd + ['show', package_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False
            )

            if result.returncode == 0:
                # Output format: "Version: 1.2.3"
                match = re.search(r'^Version:\s*(\d+\.\d+\.\d+(?:\.\d+)?)', result.stdout, re.MULTILINE)
                if match:
                    return match.group(1)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass  # Fall through to direct tool version check

    # Strategy 2: Run the tool directly with version flags
    # Common version flags to try (in order of preference)
    version_flags = ['--version', '-v', '-V', 'version']

    for flag in version_flags:
        try:
            result = subprocess.run(
                [tool_name, flag],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
                shell=False
            )

            if result.returncode == 0:
                # Try both stdout and stderr (some tools output to stderr)
                output = result.stdout or result.stderr

                # Extract semantic version: matches "1.2.3" or "1.2.3.4"
                # Handles formats like "tool 1.2.3", "v1.2.3", or just "1.2.3"
                match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', output)
                if match:
                    return match.group(1)

        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError, FileNotFoundError):
            continue

    # Couldn't detect version
    return None


def _has_npm_available() -> bool:
    """
    Check if npm is available (handles Windows PATH refresh issues)

    On Windows, npm might be installed but not yet in PATH for the current session.
    This checks multiple sources to detect npm reliably.
    """
    # Quick check: is npm in PATH?
    if shutil.which('npm'):
        return True

    # Windows: Try running npm.cmd directly (avoids PowerShell execution policy issues)
    import platform
    if platform.system() == 'Windows':
        # First, check for npm.cmd (bypasses execution policy)
        if shutil.which('npm.cmd'):
            return True

        # Try running npm.cmd directly
        npm_cmd_path = shutil.which('npm.cmd')
        if npm_cmd_path:
            success, _ = _safe_run_version_check([npm_cmd_path, '--version'])
            if success:
                return True

        # Check common Windows install locations for npm.cmd
        common_paths = [
            Path(r'C:\Program Files\nodejs\npm.cmd'),
            Path(r'C:\Program Files (x86)\nodejs\npm.cmd'),
        ]
        for path in common_paths:
            if path.exists():
                return True

    return False


def _has_pip_available() -> bool:
    """
    Check if pip is available (handles Windows PATH refresh issues)

    On Windows, pip is always available via 'py -m pip' even if not in PATH.
    """
    import platform

    # Quick check: is pip in PATH?
    if shutil.which('pip') or shutil.which('pip3'):
        return True

    # Windows: Python's pip is always available via 'py -m pip'
    if platform.system() == 'Windows':
        py_path = shutil.which('py')
        if py_path:
            success, _ = _safe_run_version_check([py_path, '-m', 'pip', '--version'])
            if success:
                return True

    # Unix: Try python3 -m pip
    python3_path = shutil.which('python3')
    if python3_path:
        success, _ = _safe_run_version_check([python3_path, '-m', 'pip', '--version'])
        return success
    # python3 not available or pip not installed
    return False


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
        except Exception:
            # Last resort: plain print with ASCII-only
            ascii_text = ' '.join(str(a).encode('ascii', 'ignore').decode('ascii') for a in safe_args)
            try:
                print(ascii_text)
            except Exception:
                # Final fallback failed - cannot print to console
                # Silently continue to prevent crash during output
                return  # Explicit return instead of pass

console.print = _safe_print


def _generate_installation_guide(failed_tools: list, guide_path: Path, platform_info):
    """
    Generate a markdown guide for manually installing failed tools

    Args:
        failed_tools: List of (tool_name, reason) tuples
        guide_path: Path to write the guide
        platform_info: Platform information object
    """
    from datetime import datetime
    from medusa.platform.installers import ToolMapper

    # Tool installation info database
    TOOL_INSTALL_INFO = {
        'hlint': {
            'name': 'HLint',
            'ecosystem': 'Haskell',
            'why_failed': 'Requires Haskell toolchain (Stack or Cabal)',
            'windows': [
                '1. Install Haskell Stack:',
                '   ```powershell',
                '   winget install Haskell.Stack',
                '   ```',
                '2. Setup GHC (Haskell compiler):',
                '   ```powershell',
                '   stack setup',
                '   ```',
                '   ⚠️ This downloads ~2GB and takes 20-30 minutes',
                '3. Install hlint:',
                '   ```powershell',
                '   stack install hlint',
                '   ```',
            ],
            'docs': 'https://github.com/ndmitchell/hlint#readme',
        },
        'clj-kondo': {
            'name': 'clj-kondo',
            'ecosystem': 'Clojure',
            'why_failed': 'Requires Clojure ecosystem',
            'windows': [
                '1. Download the Windows binary:',
                '   https://github.com/clj-kondo/clj-kondo/releases',
                '2. Extract to a directory in your PATH',
                '3. Or use Scoop:',
                '   ```powershell',
                '   scoop install clj-kondo',
                '   ```',
            ],
            'docs': 'https://github.com/clj-kondo/clj-kondo#installation',
        },
        'mix': {
            'name': 'Mix',
            'ecosystem': 'Elixir',
            'why_failed': 'Requires Elixir language installation',
            'windows': [
                '1. Install Elixir:',
                '   ```powershell',
                '   choco install elixir',
                '   ```',
                '   ⚠️ Downloads ~150MB',
                '2. Mix is included with Elixir',
                '3. Verify:',
                '   ```powershell',
                '   mix --version',
                '   ```',
            ],
            'docs': 'https://elixir-lang.org/install.html#windows',
        },
        'luacheck': {
            'name': 'Luacheck',
            'ecosystem': 'Lua',
            'why_failed': 'Requires Lua and LuaRocks package manager',
            'windows': [
                '1. Install Lua:',
                '   ```powershell',
                '   choco install lua',
                '   ```',
                '2. Install LuaRocks:',
                '   ```powershell',
                '   choco install luarocks',
                '   ```',
                '3. Install luacheck:',
                '   ```powershell',
                '   luarocks install luacheck',
                '   ```',
            ],
            'docs': 'https://github.com/mpeterv/luacheck#installation',
        },
        'perlcritic': {
            'name': 'Perl::Critic',
            'ecosystem': 'Perl',
            'why_failed': 'Requires Perl and CPAN',
            'windows': [
                '1. Install Strawberry Perl:',
                '   ```powershell',
                '   choco install strawberryperl',
                '   ```',
                '2. Install Perl::Critic via CPAN:',
                '   ```powershell',
                '   cpan Perl::Critic',
                '   ```',
            ],
            'docs': 'https://metacpan.org/pod/Perl::Critic#INSTALLATION',
        },
        'scalastyle': {
            'name': 'Scalastyle',
            'ecosystem': 'Scala',
            'why_failed': 'Requires Scala/SBT ecosystem',
            'windows': [
                '1. Download scalastyle JAR:',
                '   https://www.scalastyle.org/',
                '2. Or install via Coursier:',
                '   ```powershell',
                '   cs install scalastyle',
                '   ```',
            ],
            'docs': 'https://www.scalastyle.org/',
        },
        'codenarc': {
            'name': 'CodeNarc',
            'ecosystem': 'Groovy',
            'why_failed': 'Requires Groovy ecosystem',
            'windows': [
                '1. Download from GitHub releases:',
                '   https://github.com/CodeNarc/CodeNarc/releases',
                '2. Or use if you have Gradle/Maven',
            ],
            'docs': 'https://github.com/CodeNarc/CodeNarc',
        },
        'swiftlint': {
            'name': 'SwiftLint',
            'ecosystem': 'Swift (macOS only)',
            'why_failed': 'Swift development is macOS/Linux only',
            'windows': [
                '⚠️ SwiftLint is not officially supported on Windows.',
                'Swift development requires macOS or Linux.',
            ],
            'docs': 'https://github.com/realm/SwiftLint',
        },
        'xmllint': {
            'name': 'xmllint',
            'ecosystem': 'libxml2',
            'why_failed': 'Part of libxml2 library, complex Windows setup',
            'windows': [
                '1. Install via MSYS2:',
                '   ```powershell',
                '   # Install MSYS2 first from https://www.msys2.org/',
                '   pacman -S mingw-w64-x86_64-libxml2',
                '   ```',
                '2. Or download pre-built binaries:',
                '   http://xmlsoft.org/downloads.html',
            ],
            'docs': 'http://xmlsoft.org/',
        },
        'checkmake': {
            'name': 'checkmake',
            'ecosystem': 'Go',
            'why_failed': 'Requires Go toolchain',
            'windows': [
                '1. Install Go:',
                '   ```powershell',
                '   winget install GoLang.Go',
                '   ```',
                '2. Install checkmake:',
                '   ```powershell',
                '   go install github.com/checkmake/checkmake/cmd/checkmake@latest',
                '   ```',
                '3. Add Go bin to PATH:',
                '   ```powershell',
                '   $env:PATH += ";$env:USERPROFILE\\go\\bin"',
                '   ```',
            ],
            'docs': 'https://github.com/checkmake/checkmake',
        },
    }

    # Generate markdown content
    content = f"""# MEDUSA Installation Guide
*Tools that couldn't be automatically installed*

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Platform: {platform_info.os_name} ({platform_info.os_type.value})

---

## Overview

MEDUSA attempted to install {len(failed_tools)} tools but they require additional ecosystem installations.
This guide provides manual installation instructions for each tool.

**Why these tools weren't auto-installed:**
- Require large ecosystem downloads (1-4 GB)
- Need platform-specific toolchains
- Have complex dependency chains
- Are ecosystem-specific (macOS only, etc.)

---

## Quick Reference

"""

    # Add table of tools
    content += "| Tool | Ecosystem | Why Not Installed |\n"
    content += "|------|-----------|-------------------|\n"

    for tool_name, reason in failed_tools:
        info = TOOL_INSTALL_INFO.get(tool_name, {})
        ecosystem = info.get('ecosystem', 'Unknown')
        why = info.get('why_failed', 'No installer available for this platform')
        content += f"| `{tool_name}` | {ecosystem} | {why} |\n"

    content += "\n---\n\n"

    # Add detailed instructions for each tool
    content += "## Detailed Installation Instructions\n\n"

    for tool_name, reason in failed_tools:
        info = TOOL_INSTALL_INFO.get(tool_name)

        if not info:
            # Generic fallback
            content += f"### {tool_name}\n\n"
            content += f"**Status:** No installer available for {platform_info.os_name}\n\n"

            # Try to get manual install command from ToolMapper
            manual_cmd = ToolMapper.TOOL_PACKAGES.get(tool_name, {}).get('manual', 'See tool documentation')
            content += f"**Manual Installation:**\n```bash\n{manual_cmd}\n```\n\n"
            continue

        # Detailed info available
        content += f"### {info['name']}\n\n"
        content += f"**Ecosystem:** {info['ecosystem']}\n\n"
        content += f"**Why it failed:** {info['why_failed']}\n\n"

        # Platform-specific instructions
        if platform_info.os_type.value == 'windows' and 'windows' in info:
            content += "**Installation Steps (Windows):**\n\n"
            for line in info['windows']:
                content += f"{line}\n"
            content += "\n"

        # Documentation link
        if 'docs' in info:
            content += f"**Official Documentation:** {info['docs']}\n\n"

        content += "---\n\n"

    # Add footer
    content += """## Additional Resources

- **MEDUSA Documentation:** https://github.com/pantheon-security/medusa
- **Report Issues:** https://github.com/pantheon-security/medusa/issues

## When You've Installed Tools

After manually installing any tools, run:
```bash
medusa config
```

This will show which scanners are now available.

---

*This guide was automatically generated by MEDUSA*
"""

    # Write the file
    with open(guide_path, 'w', encoding='utf-8') as f:
        f.write(content)


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
        if not file_path.is_file():
            continue

        # Skip hidden directories (but not hidden files like .env)
        # Check parent parts, not the file itself
        parent_parts = file_path.relative_to(target).parent.parts
        if any(part.startswith('.') for part in parent_parts):
            continue

        ext = file_path.suffix.lower()
        if ext:
            file_types[ext] += 1

        # Special case: .env files (no suffix, name is .env or starts with .env.)
        name = file_path.name.lower()
        if name == '.env' or name.startswith('.env.'):
            file_types['.env'] += 1

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


def _prompt_with_auto_all(message, default=True, auto_yes_all=None):
    """
    Prompt user with [Y/n/a] options where 'a' = auto-yes to all future prompts.

    Args:
        message: The prompt message
        default: Default value if user just presses enter
        auto_yes_all: Dict with 'enabled' key to track auto-yes-all state

    Returns:
        bool: True if yes, False if no
    """
    # If auto-yes-all is already enabled, return True immediately
    if auto_yes_all and auto_yes_all.get('enabled'):
        return True

    while True:
        response = click.prompt(
            message + " [Y/n/a]",
            default='Y' if default else 'n',
            show_default=False,
            type=str
        ).lower().strip()

        if response in ('y', 'yes', ''):
            return True
        elif response in ('n', 'no'):
            return False
        elif response == 'a':
            # Enable auto-yes-all mode
            if auto_yes_all is not None:
                auto_yes_all['enabled'] = True
            console.print("[dim]Auto-yes enabled for all remaining prompts[/dim]")
            return True
        else:
            console.print("[yellow]Please enter Y (yes), n (no), or a (all)[/yellow]")


def _handle_batch_install(target, auto_install):
    """
    Handle batch installation mode - scan project, show summary, prompt once

    Args:
        target: Target directory to scan
        auto_install: Whether to auto-install without prompting
    """
    from medusa.core.pattern_analyzer import CodePatternAnalyzer

    console.print("\n[cyan]🔍 Analyzing repository...[/cyan]")

    # Use CodePatternAnalyzer for smart detection
    analyzer = CodePatternAnalyzer()
    analysis = analyzer.analyze_repo(Path(target))

    if analysis.total_files == 0:
        return  # No files found

    # Show smart analysis summary
    top_languages = sorted(analysis.languages.items(), key=lambda x: -x[1])[:5]
    lang_str = ", ".join(f"{lang.title()} ({count} files)" for lang, count in top_languages)
    console.print(f"   [bold]Languages:[/bold] {lang_str}")

    if analysis.frameworks:
        frameworks_display = sorted(list(analysis.frameworks))[:6]
        fw_str = ", ".join(f.replace('_', ' ').title() for f in frameworks_display)
        if len(analysis.frameworks) > 6:
            fw_str += f" (+{len(analysis.frameworks) - 6} more)"
        console.print(f"   [bold]Frameworks:[/bold] {fw_str}")

    if analysis.security_context.has_ai_patterns:
        ai_frameworks = sorted(list(analysis.security_context.ai_frameworks))[:4]
        ai_str = ", ".join(f.replace('_', ' ').title() for f in ai_frameworks)
        console.print(f"   [bold]AI Patterns:[/bold] {ai_str}")

    console.print()

    # Get scanners based on CodePatternAnalyzer recommendations
    from medusa.scanners import registry
    all_scanners = registry.get_all_scanners()

    # Filter to only recommended scanners
    recommended_names = analysis.recommended_scanners
    needed_scanners = [s for s in all_scanners if s.name in recommended_names]

    # If no recommendations, fall back to file-type matching
    if not needed_scanners:
        file_types = _detect_file_types(Path(target))
        needed_scanners, _, _ = _get_needed_scanners(file_types)

    if not needed_scanners:
        return  # No scanners needed

    # Categorize scanners for cleaner display
    language_scanners = []
    ai_scanners = []
    infra_scanners = []

    ai_scanner_names = {
        'MCPConfigScanner', 'MCPServerScanner', 'AIContextScanner',
        'AgentMemoryScanner', 'RAGSecurityScanner', 'A2AScanner',
        'PromptLeakageScanner', 'ToolCallbackScanner', 'OWASPLLMScanner',
        'ModelAttackScanner', 'MultiAgentScanner', 'LLMOpsScanner',
        'VectorDBScanner', 'AgentReflectionScanner', 'AgentPlanningScanner',
        'ExcessiveAgencyScanner', 'PluginSecurityScanner', 'HyperparameterScanner',
        'PostQuantumScanner', 'SteganographyScanner', 'React2ShellScanner',
        'GarakScanner', 'LLMGuardScanner',
    }

    infra_scanner_names = {
        'DockerScanner', 'DockerComposeScanner', 'DockerMCPScanner',
        'KubernetesScanner', 'TerraformScanner', 'AnsibleScanner',
        'GitLeaksScanner', 'TrivyScanner', 'EnvScanner',
    }

    for scanner in needed_scanners:
        if scanner.name in ai_scanner_names:
            ai_scanners.append(scanner)
        elif scanner.name in infra_scanner_names:
            infra_scanners.append(scanner)
        else:
            language_scanners.append(scanner)

    # Show scanner status by category (compact)
    missing_tools = []

    def show_category(title, scanners, icon):
        if not scanners:
            return
        console.print(f"[bold cyan]{icon} {title}:[/bold cyan]")
        for scanner in scanners:
            status = "✅" if scanner.is_available() else "❌"
            if not scanner.is_available() and scanner.tool_name not in missing_tools:
                missing_tools.append(scanner.tool_name)
            console.print(f"   {status} {scanner.name:25} ({scanner.tool_name or 'built-in':15})")
        console.print()

    show_category("Language Scanners", language_scanners, "📝")
    show_category("AI Security Scanners", ai_scanners, "🤖")
    show_category("Infrastructure Scanners", infra_scanners, "🔧")

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
            # Check if running in non-interactive mode (CI environment)
            if not sys.stdin.isatty():
                console.print(f"\n[yellow]⚠️  Non-interactive mode detected (CI environment)[/yellow]")
                console.print(f"[yellow]   Skipping installation of {len(missing_tools)} tools[/yellow]")
                console.print(f"[dim]   Run with --auto-install to enable in CI[/dim]")
                install_tools = False
            else:
                console.print(f"\n[bold]Installation Options:[/bold]")
                console.print(f"  [green]1.[/green] Install these {len(missing_tools)} missing tools (recommended)")
                console.print(f"  [yellow]2.[/yellow] Skip installation (some files won't be scanned)")
                install_tools = click.confirm(f"\nInstall the {len(missing_tools)} missing tools listed above?", default=True)

        if install_tools:
            _install_tools(missing_tools)
        else:
            console.print("[dim]Skipping installation. Some files may not be scanned.[/dim]")
    else:
        console.print(f"\n[green]✅ All required scanners are installed![/green]")

    console.print()


def _check_runtime_dependencies(
    missing_tools: list,
    npm_tools_failed: list,
    platform_info,
    pm,
    use_latest: bool = False,
    yes: bool = False
) -> None:
    """
    Check for runtime dependencies (Node.js/npm, PHP, Java) and offer to install them.

    Args:
        missing_tools: List of all tools that were attempted to be installed
        npm_tools_failed: List of npm tools that failed due to missing npm
        platform_info: Platform information object
        pm: Package manager enum
        use_latest: Whether to install latest versions
        yes: Auto-accept prompts (--yes flag)
    """
    # Only run on Windows
    if platform_info.os_type.value != 'windows':
        return

    # Define which tools need which runtimes
    php_tools = {'phpstan'}
    java_tools = {'checkstyle', 'ktlint', 'scalastyle', 'codenarc'}

    # Check which runtime-dependent tools are in the missing list
    php_tools_missing = [t for t in missing_tools if t in php_tools]
    java_tools_missing = [t for t in missing_tools if t in java_tools]

    # ========================================
    # Node.js / npm auto-install
    # ========================================
    if npm_tools_failed:
        # Check if we've already attempted Node.js installation this session
        global _nodejs_install_attempted
        if '_nodejs_install_attempted' not in globals():
            _nodejs_install_attempted = False

        if _nodejs_install_attempted:
            console.print("")
            console.print(f"[yellow]⚠️  {len(npm_tools_failed)} tool{'s' if len(npm_tools_failed) > 1 else ''} require Node.js (npm)[/yellow]")
            console.print("[dim]   Node.js installation was already attempted. Please restart your terminal.[/dim]")
            return

        from medusa.platform import PackageManager
        if pm in (PackageManager.WINGET, PackageManager.CHOCOLATEY):
            console.print("")
            console.print(f"[yellow]⚠️  {len(npm_tools_failed)} tool{'s' if len(npm_tools_failed) > 1 else ''} require Node.js (npm)[/yellow]")

            # Check if running in non-interactive mode (CI environment)
            if not sys.stdin.isatty():
                console.print("[yellow]   Non-interactive mode detected, skipping Node.js installation[/yellow]")
                return  # Skip Node.js prompt in CI

            # Mark that we're attempting Node.js installation
            _nodejs_install_attempted = True

            # Prompt user
            if not yes:
                response = Prompt.ask(
                    "   Install Node.js via winget to enable these tools?",
                    choices=["y", "Y", "n", "N"],
                    default="y",
                    show_choices=False
                )
                install_nodejs = response.upper() == "Y"
            else:
                install_nodejs = True

            if install_nodejs:
                # First check if Node.js is already installed
                console.print("\n[cyan]Checking for existing Node.js installation...[/cyan]")
                nodejs_already_installed = False
                node_path = shutil.which('node')
                if node_path:
                    success, output = _safe_run_version_check([node_path, '--version'])
                    if success:
                        nodejs_already_installed = True
                        console.print(f"[green]✓[/green] Node.js found: {output.strip()}")
                        console.print("[yellow]   But npm not in PATH. Attempting to fix...[/yellow]")
                if not nodejs_already_installed:
                    console.print("[dim]   Node.js not found, installing...[/dim]")

                if not nodejs_already_installed:
                    console.print("\n[cyan]Installing Node.js via winget...[/cyan]")

                # Install Node.js via winget (even if already installed, to ensure npm is available)
                from medusa.platform.installers import WingetInstaller
                winget_installer = WingetInstaller()
                nodejs_success = False

                winget_path = shutil.which('winget')
                if winget_path:
                    try:
                        success, output = _safe_run_version_check(
                            [winget_path, 'install', '--id', 'OpenJS.NodeJS', '--accept-source-agreements', '--accept-package-agreements'],
                            timeout=120
                        )
                        output_lower = output.lower() if output else ''
                        nodejs_success = (
                            success or
                            'already installed' in output_lower or
                            'no available upgrade found' in output_lower
                        )

                        # Show winget output for debugging
                        if not success:
                            console.print(f"[dim]Winget output: {output[:300]}[/dim]")
                    except Exception as e:
                        nodejs_success = False
                        console.print(f"[red]Error during installation: {str(e)[:100]}[/red]")

                if nodejs_success:
                    console.print("[green]✅ Node.js installed successfully[/green]")

                    # Refresh PATH
                    from medusa.platform.installers.windows import refresh_windows_path
                    refresh_windows_path()
                    console.print("[dim]   PATH refreshed from registry[/dim]")

                    # Verify npm is now available
                    console.print("\n[cyan]Checking for npm...[/cyan]")
                    npm_path = shutil.which('npm.cmd') or shutil.which('npm')

                    if npm_path:
                        console.print(f"[green]✓[/green] npm found at: {npm_path}")
                        # Verify npm works
                        try:
                            success, output = _safe_run_version_check([npm_path, '--version'])
                            if success:
                                console.print(f"[green]✓[/green] npm version: {output.strip()}")
                            else:
                                console.print(f"[yellow]⚠[/yellow] npm found but returned error")
                        except Exception as e:
                            console.print(f"[yellow]⚠[/yellow] npm found but test failed: {str(e)[:50]}")
                    else:
                        console.print("[yellow]✗[/yellow] npm not found in PATH")
                        console.print("[dim]   This usually means you need to restart your terminal[/dim]")

                    # Retry npm tools
                    console.print("\n[cyan]Retrying npm tools...[/cyan]\n")
                    from medusa.platform.installers import NpmInstaller, ToolMapper
                    npm_installer = NpmInstaller() if npm_path else None

                    if npm_installer:
                        npm_installed = 0
                        for tool in npm_tools_failed:
                            console.print(f"[cyan]Installing {tool}...[/cyan]")
                            npm_package = ToolMapper.get_package_name(tool, 'npm')
                            console.print(f"  → Trying npm: {npm_package}")

                            if npm_installer.install(tool, use_latest=use_latest):
                                console.print(f"  [green]✅ Installed via npm[/green]\n")
                                npm_installed += 1
                                # Mark tool as installed in cache
                                from medusa.platform.tool_cache import ToolCache
                                cache = ToolCache()
                                cache.mark_installed(tool)
                            else:
                                console.print(f"  [red]❌ Failed[/red]\n")

                        if npm_installed > 0:
                            console.print(f"[green]✅ Installed {npm_installed}/{len(npm_tools_failed)} npm tools[/green]")
                    else:
                        console.print("[yellow]⚠️  npm still not available. Try restarting your terminal.[/yellow]")
                        console.print("[dim]   Node.js may need a terminal restart to be detected.[/dim]")
                        return
                else:
                    console.print("[red]❌ Failed to install Node.js[/red]")
                    console.print("[yellow]You can manually install Node.js from: https://nodejs.org[/yellow]")
                    return

    # ========================================
    # PHP auto-install
    # ========================================
    if php_tools_missing and not shutil.which('php'):
        console.print()
        console.print(f"[bold yellow]⚠️  {len(php_tools_missing)} tool{'s' if len(php_tools_missing) > 1 else ''} require PHP runtime:[/bold yellow]")
        for t in php_tools_missing:
            console.print(f"   • {t}")
        console.print()

        if not yes:
            response = Prompt.ask(
                "   Install PHP via winget to enable these tools?",
                choices=["y", "Y", "n", "N"],
                default="y",
                show_choices=False
            )
            install_php = response.upper() == "Y"
        else:
            install_php = True

        if install_php:
            console.print("\n[cyan]Installing PHP via winget...[/cyan]")
            from medusa.platform.installers import WingetInstaller
            winget_installer = WingetInstaller()
            winget_path = shutil.which('winget')

            if winget_path:
                try:
                    success, output = _safe_run_version_check(
                        [winget_path, 'install', '--id', 'PHP.PHP.8.4', '--accept-source-agreements', '--accept-package-agreements'],
                        timeout=120
                    )
                    output_lower = output.lower() if output else ''
                    php_success = (
                        success or
                        'already installed' in output_lower or
                        'no available upgrade found' in output_lower
                    )

                    if php_success:
                        console.print("[green]✅ PHP installed successfully[/green]")
                        console.print("[dim]   You may need to restart your terminal for PHP to be available[/dim]")
                    else:
                        console.print("[red]❌ Failed to install PHP[/red]")
                        console.print("[yellow]You can manually install PHP from: https://windows.php.net/download/[/yellow]")
                except Exception as e:
                    console.print(f"[red]Error during installation: {str(e)[:100]}[/red]")
            else:
                console.print("[red]❌ winget not found[/red]")
        else:
            console.print("[yellow]Skipping PHP installation[/yellow]")
            console.print("[dim]   phpstan will not work without PHP runtime[/dim]")

    # ========================================
    # Java runtime check (informational only)
    # ========================================
    if java_tools_missing and not shutil.which('java'):
        console.print()
        console.print(f"[bold yellow]⚠️  {len(java_tools_missing)} tool{'s' if len(java_tools_missing) > 1 else ''} require Java runtime (not auto-installed for security):[/bold yellow]")
        for t in java_tools_missing:
            tool_desc = {
                'checkstyle': 'Java linter',
                'ktlint': 'Kotlin linter',
                'scalastyle': 'Scala linter',
                'codenarc': 'Groovy linter'
            }.get(t, 'JVM linter')
            console.print(f"   • {t} ({tool_desc})")
        console.print()
        console.print("[dim]   If you install Java manually, these tools will become available.[/dim]")
        console.print("[dim]   We don't auto-install Java due to security concerns.[/dim]")


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
        HomebrewInstaller, WingetInstaller, ChocolateyInstaller, NpmInstaller, PipInstaller, ToolMapper
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
            PackageManager.WINGET: WingetInstaller(),
            PackageManager.CHOCOLATEY: ChocolateyInstaller(),
        }
        installer = installer_map.get(pm)

    # Smart installer detection (Windows PATH refresh workaround)
    npm_installer = NpmInstaller() if _has_npm_available() else None
    pip_installer = PipInstaller() if _has_pip_available() else None

    installed = 0
    failed = 0
    npm_tools_failed = []  # Track tools that failed due to missing npm

    for tool in tools:
        console.print(f"[cyan]Installing {tool}...[/cyan]")

        success = False
        attempted_installers = []

        # Try platform package manager first
        pm_package = ToolMapper.get_package_name(tool, pm.value if pm else '') if pm else None
        if installer and pm_package:
            console.print(f"  → Trying {pm.value}: {pm_package}")
            attempted_installers.append(pm.value)
            success = installer.install(tool)
            if success:
                console.print(f"  [green]✅ Installed via {pm.value}[/green]")
        elif pm:
            console.print(f"  ⊘ Not available in {pm.value}")

        # Try npm for npm tools
        if not success and ToolMapper.is_npm_tool(tool):
            if npm_installer:
                npm_package = ToolMapper.get_package_name(tool, 'npm')
                console.print(f"  → Trying npm: {npm_package}")
                attempted_installers.append('npm')
                success = npm_installer.install(tool, use_latest=use_latest)
                if success:
                    console.print(f"  [green]✅ Installed via npm[/green]")
            else:
                console.print(f"  ⊘ npm not available (install Node.js)")
                attempted_installers.append('npm (Node.js required)')
                npm_tools_failed.append(tool)  # Track this tool

        # Try pip for python tools
        if not success and ToolMapper.is_python_tool(tool):
            if pip_installer:
                pip_package = ToolMapper.get_package_name(tool, 'pip')
                console.print(f"  → Trying pip: {pip_package}")
                attempted_installers.append('pip')
                success = pip_installer.install(tool, use_latest=use_latest)
                if success:
                    console.print(f"  [green]✅ Installed via pip[/green]")
            else:
                console.print(f"  ⊘ pip not available")
                attempted_installers.append('pip (not available)')

        # Try ecosystem installers (cargo, go) for tools that need them
        if not success:
            from medusa.platform.installers.base import EcosystemDetector
            ecosystem = EcosystemDetector.detect_ecosystem(tool)
            if ecosystem:
                eco_name, eco_cmd = ecosystem
                console.print(f"  → Trying {eco_name}: {eco_cmd}")
                attempted_installers.append(eco_name)
                try:
                    import subprocess
                    result = subprocess.run(eco_cmd, shell=True, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        success = True
                        console.print(f"  [green]✅ Installed via {eco_name}[/green]")
                except Exception as e:
                    console.print(f"  [yellow]⚠ {eco_name} failed: {e}[/yellow]")

        # Try manual install script as last resort (Linux only)
        if not success and platform_info.os_type.value == 'linux':
            tool_info = ToolMapper.TOOL_PACKAGES.get(tool, {})
            manual_cmd = tool_info.get('manual')
            if manual_cmd and not manual_cmd.startswith('http'):  # Skip URLs, only run actual commands
                console.print(f"  → Trying manual install script")
                attempted_installers.append('manual')
                try:
                    import subprocess
                    result = subprocess.run(manual_cmd, shell=True, capture_output=True, text=True, timeout=300)
                    if result.returncode == 0:
                        success = True
                        console.print(f"  [green]✅ Installed via manual script[/green]")
                    else:
                        console.print(f"  [yellow]⚠ Manual install failed: {result.stderr[:100] if result.stderr else 'unknown error'}[/yellow]")
                except Exception as e:
                    console.print(f"  [yellow]⚠ Manual install failed: {e}[/yellow]")
            elif manual_cmd and manual_cmd.startswith('http'):
                console.print(f"  [dim]Manual install required: {manual_cmd}[/dim]")

        if success:
            installed += 1
            # Mark tool as installed in cache (prevents reinstall prompts on Windows)
            from medusa.platform.tool_cache import ToolCache
            cache = ToolCache()
            cache.mark_installed(tool)
        else:
            console.print(f"  [red]❌ Failed[/red] (tried: {', '.join(attempted_installers) if attempted_installers else 'no installers available'})")
            failed += 1

        console.print("")  # Blank line between tools

    if installed > 0:
        console.print(f"\n[green]✅ Installed {installed}/{len(tools)} tools[/green]")
    if failed > 0:
        console.print(f"[yellow]⚠️  {failed} tools failed to install (may need manual installation)[/yellow]")

    # Check for runtime dependencies (Node.js/npm, PHP, Java)
    _check_runtime_dependencies(
        missing_tools=tools,
        npm_tools_failed=npm_tools_failed,
        platform_info=platform_info,
        pm=pm,
        use_latest=use_latest,
        yes=False  # _install_tools doesn't have a yes parameter
    )


def print_banner():
    """Print MEDUSA banner with fallback for Windows encoding issues"""
    banner = f"""
[bold magenta]╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          🐍🐍🐍 MEDUSA v{__version__} - Security Guardian 🐍🐍🐍           ║
║                                                                    ║
║         Universal Scanner with 74 Specialized Analyzers           ║
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
║         Universal Scanner with 74 Specialized Analyzers           ║
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
    MEDUSA - Multi-Language Security Scanner

    Universal security scanner with 40+ specialized analyzers for all platforms.
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
@click.option('--format', 'output_formats', multiple=True,
              type=click.Choice(['json', 'html', 'markdown', 'all']),
              default=['json', 'html'],
              help='Output format(s): json, html, markdown, or all (can specify multiple)')
@click.option('--no-report', is_flag=True,
              help='Skip report generation (faster)')
@click.option('--install-mode', type=click.Choice(['batch', 'progressive', 'never']),
              default='batch',
              help='How to handle missing linters (batch=ask once, progressive=ask per tool, never=skip)')
@click.option('--auto-install', is_flag=True,
              help='Automatically install missing linters without prompting')
@click.option('--no-install', is_flag=True,
              help='Never prompt for installation (same as --install-mode never)')
def scan(target, workers, quick, force, no_cache, fail_on, output, output_formats, no_report, install_mode, auto_install, no_install):
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
    # Validate target is a directory (Issue #2 fix)
    target_path = Path(target)
    if not target_path.is_dir():
        console.print(f"[red]❌ Error: Target must be a directory, not a file[/red]")
        console.print(f"[yellow]   Got: {target_path}[/yellow]")
        console.print(f"[dim]   Tip: To scan a single file, specify its parent directory[/dim]")
        raise SystemExit(1)

    print_banner()

    # Handle install mode flags
    if no_install:
        install_mode = 'never'

    console.print(f"\n[cyan]🎯 Target:[/cyan] {target}")
    console.print(f"[cyan]🔧 Mode:[/cyan] {'Quick' if quick else 'Force' if force else 'Full'}")

    # Run CodePatternAnalyzer for smart scanner selection
    from medusa.core.pattern_analyzer import CodePatternAnalyzer

    console.print("\n[dim]Analyzing repository...[/dim]")
    analyzer = CodePatternAnalyzer()
    repo_analysis = analyzer.analyze_repo(Path(target))

    # Display analysis summary
    if repo_analysis.languages:
        top_langs = sorted(repo_analysis.languages.items(), key=lambda x: -x[1])[:5]
        lang_summary = ", ".join(f"{lang} ({count})" for lang, count in top_langs)
        console.print(f"[cyan]📊 Languages:[/cyan] {lang_summary}")

    if repo_analysis.frameworks:
        fw_list = sorted(repo_analysis.frameworks)[:8]
        fw_summary = ", ".join(fw_list)
        if len(repo_analysis.frameworks) > 8:
            fw_summary += f" (+{len(repo_analysis.frameworks) - 8} more)"
        console.print(f"[cyan]🔧 Frameworks:[/cyan] {fw_summary}")

    # Highlight AI patterns
    if repo_analysis.security_context.has_ai_patterns:
        ai_patterns = []
        if repo_analysis.security_context.has_mcp_config:
            ai_patterns.append("MCP")
        if repo_analysis.security_context.has_rag_patterns:
            ai_patterns.append("RAG")
        if repo_analysis.security_context.has_agent_patterns:
            ai_patterns.append("Agents")
        if ai_patterns:
            console.print(f"[magenta]🤖 AI Patterns:[/magenta] {', '.join(ai_patterns)} detected - AI security scanners enabled")

    # Show recommended vs skipped scanners
    console.print(f"[green]✓ Recommended scanners:[/green] {len(repo_analysis.recommended_scanners)}")
    console.print(f"[dim]✗ Skipped (not needed):[/dim] {len(repo_analysis.skip_scanners)}")

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

            # Handle 'all' format
            formats = list(output_formats)
            if 'all' in formats:
                formats = ['json', 'html', 'markdown']

            scanner.generate_report(results, output_dir, formats=formats)

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

    # Step 1: Analyze project with CodePatternAnalyzer
    console.print("[bold cyan]Step 1/4: Analyzing project structure...[/bold cyan]")

    from medusa.core.pattern_analyzer import CodePatternAnalyzer
    import json
    import hashlib
    from datetime import datetime

    analyzer = CodePatternAnalyzer()
    analysis = analyzer.analyze_repo(project_root)

    # Display summary
    if analysis.languages:
        top_languages = sorted(analysis.languages.items(), key=lambda x: -x[1])[:6]
        console.print(f"[green]✓[/green] Languages detected:")
        for lang, count in top_languages:
            console.print(f"  • {lang.title():20} ({count} files)")

        if analysis.frameworks:
            frameworks_display = sorted(list(analysis.frameworks))[:8]
            console.print(f"[green]✓[/green] Frameworks: {', '.join(f.replace('_', ' ').title() for f in frameworks_display)}")

        if analysis.security_context.has_ai_patterns:
            ai_patterns = sorted(list(analysis.security_context.ai_frameworks))[:5]
            console.print(f"[green]✓[/green] AI Patterns: {', '.join(f.replace('_', ' ').title() for f in ai_patterns)}")

        console.print(f"[green]✓[/green] Recommended scanners: {len(analysis.recommended_scanners)}")
        console.print(f"[dim]   Skipped (not needed): {len(analysis.skip_scanners)}[/dim]")
    else:
        console.print("[yellow]⚠️  No language files detected[/yellow]")

    # Save analysis to .medusa/analysis.json for future scans
    medusa_dir = project_root / ".medusa"
    medusa_dir.mkdir(exist_ok=True)

    # Build file hash index for change detection
    file_hashes = {}
    for file_path in project_root.rglob("*"):
        if file_path.is_file() and ".medusa" not in str(file_path):
            # Skip large files and common non-code directories
            skip_dirs = {'node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build'}
            if any(skip in file_path.parts for skip in skip_dirs):
                continue
            try:
                if file_path.stat().st_size < 1_000_000:  # <1MB
                    content_hash = hashlib.md5(file_path.read_bytes()).hexdigest()
                    rel_path = str(file_path.relative_to(project_root))
                    file_hashes[rel_path] = {
                        'hash': content_hash,
                        'size': file_path.stat().st_size,
                        'mtime': file_path.stat().st_mtime,
                    }
            except (OSError, PermissionError):
                pass

    # Save analysis
    analysis_data = {
        'version': '1.0',
        'created': datetime.now().isoformat(),
        'project_root': str(project_root),
        'analysis': analysis.to_dict(),
        'file_count': len(file_hashes),
        'file_hashes': file_hashes,
    }

    analysis_file = medusa_dir / "analysis.json"
    analysis_file.write_text(json.dumps(analysis_data, indent=2))
    console.print(f"[green]✓[/green] Saved analysis to .medusa/analysis.json ({len(file_hashes)} files indexed)")

    # For backwards compatibility, also build detected_files dict
    detected_files = {}
    for scanner in registry.get_all_scanners():
        if scanner.name in analysis.recommended_scanners:
            # Rough count based on extensions
            count = sum(1 for ext in scanner.get_file_extensions()
                       if ext and any(f.endswith(ext) for f in file_hashes.keys()))
            if count > 0:
                detected_files[scanner.name] = count

    # Step 2: Check scanner availability (only for recommended scanners)
    console.print("\n[bold cyan]Step 2/4: Checking scanner availability...[/bold cyan]")

    # Get only recommended scanners from CodePatternAnalyzer
    needed_scanners = [s for s in registry.get_all_scanners() if s.name in analysis.recommended_scanners]
    available_scanners = [s for s in needed_scanners if s.is_available()]
    missing_scanners = [s for s in needed_scanners if not s.is_available()]
    missing_tools = [s.tool_name for s in missing_scanners if s.tool_name]  # Filter None (built-in)

    console.print(f"[green]✓[/green] {len(available_scanners)}/{len(needed_scanners)} scanners available for your project")
    if missing_tools:
        console.print(f"[yellow]⚠️[/yellow]  {len(missing_tools)} tools missing for your project: {', '.join(missing_tools[:5])}" +
                     (f" and {len(missing_tools) - 5} more" if len(missing_tools) > 5 else ""))

        if install or click.confirm(f"\nInstall {len(missing_tools)} missing tools for your project?", default=False):
            console.print("[cyan]Installing missing tools...[/cyan]")
            # Call the install command directly with --all --yes
            import sys
            import subprocess

            cmd = [sys.executable, '-m', 'medusa', 'install', '--all', '--yes']
            result = subprocess.run(
                cmd,
                capture_output=False,
                text=True,
                check=False
            )
            if result.returncode != 0:
                console.print("[yellow]⚠️  Some tools may not have installed successfully[/yellow]")
                console.print("[dim]You can retry with: medusa install --all[/dim]")
            console.print()  # Extra newline for spacing

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
        from medusa.ide.backup import IDEBackupManager

        # Create backup manager for all IDE file modifications
        backup_manager = IDEBackupManager(project_root)
        backup_manager.start_backup_session()
        all_backed_up_files = []

        success_count = 0
        for selected_ide in ide_list:
            if selected_ide == 'claude-code':
                result = setup_claude_code(project_root, backup_manager)
                success = result[0]
                claude_md_created = result[1] if len(result) > 1 else True
                backed_up = result[2] if len(result) > 2 else []
                all_backed_up_files.extend(backed_up)
                if success:
                    console.print("[green]✓[/green] Claude Code integration configured")
                    console.print("  • Created .claude/ directory with agents and commands")
                    if claude_md_created:
                        console.print("  • Created CLAUDE.md project context")
                    else:
                        console.print("  • Preserved existing CLAUDE.md (not overwritten)")
                    success_count += 1
            elif selected_ide == 'cursor':
                result = setup_cursor(project_root, backup_manager)
                success = result[0]
                backed_up = result[1] if len(result) > 1 else []
                all_backed_up_files.extend(backed_up)
                if success:
                    console.print("[green]✓[/green] Cursor integration configured")
                    console.print("  • Created .cursor/mcp.json for MCP support")
                    console.print("  • Reused .claude/ structure (Cursor is VS Code fork)")
                    success_count += 1
            elif selected_ide == 'gemini-cli':
                result = setup_gemini_cli(project_root, backup_manager)
                success = result[0]
                backed_up = result[1] if len(result) > 1 else []
                all_backed_up_files.extend(backed_up)
                if success:
                    console.print("[green]✓[/green] Gemini CLI integration configured")
                    console.print("  • Created .gemini/commands/ with .toml files")
                    console.print("  • Created GEMINI.md project context")
                    success_count += 1
            elif selected_ide == 'openai-codex':
                result = setup_openai_codex(project_root, backup_manager)
                success = result[0]
                backed_up = result[1] if len(result) > 1 else []
                all_backed_up_files.extend(backed_up)
                if success:
                    console.print("[green]✓[/green] OpenAI Codex integration configured")
                    console.print("  • Created AGENTS.md project context")
                    success_count += 1
            elif selected_ide == 'github-copilot':
                result = setup_github_copilot(project_root, backup_manager)
                success = result[0]
                backed_up = result[1] if len(result) > 1 else []
                all_backed_up_files.extend(backed_up)
                if success:
                    console.print("[green]✓[/green] GitHub Copilot integration configured")
                    console.print("  • Created .github/copilot-instructions.md")
                    success_count += 1

        console.print(f"\n[green]✓[/green] Configured {success_count}/{len(ide_list)} IDE integration(s)")

        # Show backup information if files were backed up
        if all_backed_up_files:
            backup_path = backup_manager.get_backup_path()
            console.print(f"\n[yellow]📁 Backed up {len(all_backed_up_files)} existing file(s) to:[/yellow]")
            console.print(f"   [dim]{backup_path}[/dim]")
            console.print(f"   [dim]Use 'medusa backup --list' to view backups[/dim]")
            console.print(f"   [dim]Use 'medusa backup --restore' to rollback changes[/dim]")
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
@click.option('--list', '-l', 'list_backups', is_flag=True, help='List all backups for this project')
@click.option('--restore', '-r', 'restore_timestamp', default=None, help='Restore backup (latest if no timestamp given)')
@click.option('--restore-latest', is_flag=True, help='Restore the most recent backup')
@click.option('--dry-run', is_flag=True, help='Show what would be restored without actually restoring')
@click.option('--cleanup', is_flag=True, help='Remove old backups (keeps last 10)')
def backup(list_backups, restore_timestamp, restore_latest, dry_run, cleanup):
    """
    Manage IDE configuration backups.

    MEDUSA backs up your IDE configuration files before modifying them
    during `medusa init`. Use this command to view or restore backups.

    Examples:
        medusa backup --list           # List all backups
        medusa backup --restore-latest # Restore most recent backup
        medusa backup --restore 2024-01-15-143022  # Restore specific backup
        medusa backup --cleanup        # Remove old backups (keep last 10)
    """
    print_banner()

    from medusa.ide.backup import IDEBackupManager

    project_root = Path.cwd()
    backup_manager = IDEBackupManager(project_root)

    if list_backups:
        console.print("\n[cyan]📁 IDE Configuration Backups[/cyan]\n")
        backups = backup_manager.list_backups()

        if not backups:
            console.print(f"[yellow]No backups found for project '{backup_manager.project_name}'[/yellow]")
            console.print(f"[dim]Backups are created when you run 'medusa init' with IDE integration[/dim]")
            return

        console.print(f"[bold]Project:[/bold] {backup_manager.project_name}")
        console.print(f"[bold]Backup location:[/bold] {backup_manager.backup_base}\n")

        for i, backup_info in enumerate(backups):
            timestamp = backup_info.get('timestamp', 'unknown')
            files = backup_info.get('files', [])
            created = backup_info.get('created_at', '')

            marker = "[green]← latest[/green]" if i == 0 else ""
            console.print(f"[cyan]{timestamp}[/cyan] {marker}")
            if created:
                console.print(f"  Created: {created}")
            console.print(f"  Files: {len(files)}")
            for f in files[:5]:  # Show first 5 files
                console.print(f"    • {f}")
            if len(files) > 5:
                console.print(f"    [dim]... and {len(files) - 5} more[/dim]")
            console.print()

    elif restore_latest or restore_timestamp is not None:
        timestamp = restore_timestamp if restore_timestamp else None
        action = "Would restore" if dry_run else "Restoring"

        console.print(f"\n[cyan]🔄 {action} IDE Configuration Backup[/cyan]\n")

        try:
            restored = backup_manager.restore_backup(timestamp=timestamp, dry_run=dry_run)

            if not restored:
                console.print("[yellow]No files to restore in this backup[/yellow]")
                return

            for src, dest in restored:
                console.print(f"  {'Would restore' if dry_run else 'Restored'}: [dim]{dest}[/dim]")

            if dry_run:
                console.print(f"\n[yellow]Dry run - no files were modified[/yellow]")
                console.print(f"[dim]Remove --dry-run to actually restore these files[/dim]")
            else:
                console.print(f"\n[green]✓ Restored {len(restored)} file(s)[/green]")

        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            return

    elif cleanup:
        console.print("\n[cyan]🧹 Cleaning Up Old Backups[/cyan]\n")

        backups_before = len(backup_manager.list_backups())
        backup_manager.cleanup_old_backups(keep_count=10)
        backups_after = len(backup_manager.list_backups())

        removed = backups_before - backups_after
        if removed > 0:
            console.print(f"[green]✓ Removed {removed} old backup(s)[/green]")
        else:
            console.print("[dim]No old backups to remove (keeping last 10)[/dim]")

    else:
        # Default: show summary
        console.print("\n[cyan]📁 IDE Configuration Backups[/cyan]\n")
        backups = backup_manager.list_backups()

        if backups:
            console.print(f"Found [bold]{len(backups)}[/bold] backup(s) for project '{backup_manager.project_name}'")
            console.print(f"\nUse [cyan]medusa backup --list[/cyan] to see details")
            console.print(f"Use [cyan]medusa backup --restore-latest[/cyan] to restore")
        else:
            console.print(f"[yellow]No backups found for project '{backup_manager.project_name}'[/yellow]")
            console.print(f"[dim]Backups are created when you run 'medusa init' with IDE integration[/dim]")


@main.command()
@click.argument('tool', required=False)
@click.option('--check', is_flag=True, help='Check which linters are installed')
@click.option('--all', is_flag=True, help='Install all missing linters')
@click.option('--smart', is_flag=True, help='Smart install: only tools needed for current project')
@click.option('--target', type=click.Path(exists=True), help='Target directory for smart analysis (default: current dir)')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
@click.option('--use-latest', is_flag=True, help='Install latest versions (bypass version pinning)')
@click.option('--debug', is_flag=True, help='Show detailed debug output (especially for Windows Chocolatey installation)')
def install(tool, check, all, smart, target, yes, use_latest, debug):
    """
    Install security linters for your platform.

    MEDUSA uses multiple linters (shellcheck, bandit, hadolint, etc.)
    This command helps you install them on your OS.

    Examples:
        medusa install --check        # Check what's installed
        medusa install --all          # Install all missing linters
        medusa install --smart        # Smart install: only tools for this project
        medusa install shellcheck     # Install specific tool
        medusa install                # Interactive selection
    """
    print_banner()

    console.print("\n[cyan]📦 Linter Installation[/cyan]\n")

    # Smart installation mode - analyze repo first
    if smart:
        from pathlib import Path
        from medusa.core.pattern_analyzer import CodePatternAnalyzer

        target_path = Path(target) if target else Path.cwd()
        console.print(f"[cyan]🔍 Analyzing project: {target_path}[/cyan]\n")

        analyzer = CodePatternAnalyzer()
        repo_analysis = analyzer.analyze_repo(target_path)

        # Show analysis summary
        if repo_analysis.languages:
            top_langs = sorted(repo_analysis.languages.items(), key=lambda x: -x[1])[:5]
            lang_summary = ", ".join(f"{lang} ({count})" for lang, count in top_langs)
            console.print(f"[dim]📊 Languages:[/dim] {lang_summary}")

        if repo_analysis.frameworks:
            frameworks_list = sorted(repo_analysis.frameworks)
            if len(frameworks_list) > 6:
                console.print(f"[dim]🔧 Frameworks:[/dim] {', '.join(frameworks_list[:6])} (+{len(frameworks_list)-6} more)")
            else:
                console.print(f"[dim]🔧 Frameworks:[/dim] {', '.join(frameworks_list)}")

        if repo_analysis.security_context.has_ai_patterns:
            console.print("[dim]🤖 AI Patterns:[/dim] Detected - AI security scanners recommended")

        console.print()

        # Get recommended tool names for filtering
        recommended_tools = analyzer.get_recommended_tools(repo_analysis)
        skipped_tools = analyzer.get_skipped_tools(repo_analysis)

        console.print(f"[green]✓ Recommended tools:[/green] {len(recommended_tools)}")
        console.print(f"[yellow]✗ Skipped (not needed):[/yellow] {len(skipped_tools)}")
        console.print()

    from medusa.platform import get_platform_info
    from medusa.scanners import registry
    from medusa.platform.installers import (
        AptInstaller, YumInstaller, DnfInstaller, PacmanInstaller,
        HomebrewInstaller, WingetInstaller, ChocolateyInstaller, NpmInstaller, PipInstaller, ToolMapper
    )

    platform_info = get_platform_info()
    missing_tools = registry.get_missing_tools()

    # Filter missing tools if smart mode is enabled
    if smart:
        all_missing = len(missing_tools)
        missing_tools = [t for t in missing_tools if t in recommended_tools]
        skipped_count = all_missing - len(missing_tools)
        if skipped_count > 0:
            console.print(f"[dim]Filtered out {skipped_count} tools not needed for this project[/dim]\n")

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
            PackageManager.WINGET: WingetInstaller(),
            PackageManager.CHOCOLATEY: ChocolateyInstaller(debug=debug),
        }
        installer = installer_map.get(pm)

    # Also check for cross-platform installers
    npm_installer = NpmInstaller() if _has_npm_available() else None
    pip_installer = PipInstaller() if _has_pip_available() else None

    # Check if Chocolatey is available (for fallback installs)
    choco_installer = None
    if platform_info.os_type.value == 'windows':
        choco_installer = ChocolateyInstaller(debug=debug) if ChocolateyInstaller.is_chocolatey_installed() else None

    # Install specific tool
    if tool:
        if tool not in missing_tools:
            console.print(f"[yellow]Tool '{tool}' is already installed or not a MEDUSA scanner tool[/yellow]")
            return

        console.print(f"[cyan]Installing {tool}...[/cyan]\n")

        # Determine best installer for this tool
        package_name = ToolMapper.get_package_name(tool, pm.value if pm else '')

        # Check if tool already exists before installing
        manifest = get_manifest()
        was_already_installed = False
        for scanner in registry.get_all_scanners():
            if scanner.tool_name == tool and scanner.is_available():
                was_already_installed = True
                break

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
                # Detect installed version for manifest fingerprinting
                installed_version = _detect_tool_version(tool)
                # Record installation in manifest
                manifest.mark_installed(
                    tool_name=tool,
                    package_manager=pm.value if pm else 'unknown',
                    package_id=package_name,
                    version=installed_version,
                    already_existed=was_already_installed
                )
            else:
                console.print(f"[red]❌ Failed to install {tool}[/red]")
        else:
            # Try npm or pip
            npm_package = ToolMapper.get_package_name(tool, 'npm')
            pip_package = ToolMapper.get_package_name(tool, 'pip')

            if npm_package and npm_installer:
                cmd = npm_installer.get_install_command(tool)
                console.print(f"[dim]Command: {cmd}[/dim]\n")
                success = npm_installer.install(tool, use_latest=use_latest)
                if success:
                    console.print(f"[green]✅ Successfully installed {tool}[/green]")
                    # Detect installed version for manifest fingerprinting
                    installed_version = _detect_tool_version(tool, package_manager='npm')
                    # Record installation in manifest
                    manifest.mark_installed(
                        tool_name=tool,
                        package_manager='npm',
                        package_id=npm_package,
                        version=installed_version,
                        already_existed=was_already_installed
                    )
                else:
                    console.print(f"[red]❌ Failed to install {tool}[/red]")
            elif pip_package and pip_installer:
                cmd = pip_installer.get_install_command(tool)
                console.print(f"[dim]Command: {cmd}[/dim]\n")
                success = pip_installer.install(tool, use_latest=use_latest)
                if success:
                    console.print(f"[green]✅ Successfully installed {tool}[/green]")
                    # Detect installed version for manifest fingerprinting
                    installed_version = _detect_tool_version(tool, package_manager='pip')
                    # Record installation in manifest
                    manifest.mark_installed(
                        tool_name=tool,
                        package_manager='pip',
                        package_id=pip_package,
                        version=installed_version,
                        already_existed=was_already_installed
                    )
                else:
                    console.print(f"[red]❌ Failed to install {tool}[/red]")
            else:
                # Try ecosystem installers (cargo, go) as fallback
                from medusa.platform.installers.base import EcosystemDetector
                ecosystem = EcosystemDetector.detect_ecosystem(tool)
                if ecosystem:
                    eco_name, eco_cmd = ecosystem
                    console.print(f"[cyan]Trying {eco_name}: {eco_cmd}[/cyan]")
                    try:
                        import subprocess
                        result = subprocess.run(eco_cmd, shell=True, capture_output=True, text=True, timeout=300)
                        if result.returncode == 0:
                            console.print(f"[green]✅ Successfully installed {tool} via {eco_name}[/green]")
                            installed_version = _detect_tool_version(tool)
                            manifest.mark_installed(
                                tool_name=tool,
                                package_manager=eco_name,
                                package_id=eco_cmd,
                                version=installed_version,
                                already_existed=was_already_installed
                            )
                            return
                        else:
                            console.print(f"[yellow]⚠ {eco_name} failed: {result.stderr[:100] if result.stderr else 'unknown error'}[/yellow]")
                    except Exception as e:
                        console.print(f"[yellow]⚠ {eco_name} failed: {e}[/yellow]")

                # Try manual install script as last resort (Linux only)
                tool_info = ToolMapper.TOOL_PACKAGES.get(tool, {})
                manual_cmd = tool_info.get('manual')
                if manual_cmd and not manual_cmd.startswith('http') and platform_info.os_type.value == 'linux':
                    console.print(f"[cyan]Trying manual install script...[/cyan]")
                    try:
                        import subprocess
                        result = subprocess.run(manual_cmd, shell=True, capture_output=True, text=True, timeout=300)
                        if result.returncode == 0:
                            console.print(f"[green]✅ Successfully installed {tool} via manual script[/green]")
                            installed_version = _detect_tool_version(tool)
                            manifest.mark_installed(
                                tool_name=tool,
                                package_manager='manual',
                                package_id=manual_cmd[:50],
                                version=installed_version,
                                already_existed=was_already_installed
                            )
                            return
                        else:
                            console.print(f"[yellow]⚠ Manual install failed: {result.stderr[:100] if result.stderr else 'unknown error'}[/yellow]")
                    except Exception as e:
                        console.print(f"[yellow]⚠ Manual install failed: {e}[/yellow]")

                console.print(f"[yellow]⚠️  '{tool}' installation not supported on this platform[/yellow]")
                if manual_cmd:
                    console.print(f"[dim]Please install manually: {manual_cmd}[/dim]")
                else:
                    console.print(f"[dim]See documentation for installation instructions[/dim]")
        return

    # Install all missing tools
    if all or (not check and not tool):
        console.print(f"[cyan]Found {len(missing_tools)} missing tools:[/cyan]")
        for t in missing_tools:
            console.print(f"  • {t}")

        console.print()

        # Track auto-yes-all state (dict so it's mutable across function calls)
        auto_yes_all = {'enabled': yes}  # If --yes flag, start with auto-yes enabled

        if not yes:
            confirm = _prompt_with_auto_all(f"Install all {len(missing_tools)} missing tools?", default=True, auto_yes_all=auto_yes_all)
            if not confirm:
                console.print("[yellow]Installation cancelled[/yellow]")
                return

        console.print()

        # Track if we just installed chocolatey in this session
        chocolatey_just_installed = False

        # On Windows, check if chocolatey would be useful and offer to install it
        if platform_info.os_type.value == 'windows' and not ChocolateyInstaller.is_chocolatey_installed():
            # Check how many tools need chocolatey
            choco_tools = [t for t in missing_tools if ToolMapper.get_package_name(t, 'choco')]

            if choco_tools:
                console.print(f"[yellow]💡 {len(choco_tools)} tools can be installed via Chocolatey:[/yellow]")
                for t in choco_tools[:5]:  # Show first 5
                    console.print(f"  • {t}")
                if len(choco_tools) > 5:
                    console.print(f"  • ... and {len(choco_tools) - 5} more")
                console.print()

                install_choco = _prompt_with_auto_all("Install Chocolatey package manager? (Requires admin rights)", default=True, auto_yes_all=auto_yes_all)

                if install_choco:
                    console.print("[cyan]Installing Chocolatey...[/cyan]")
                    if debug:
                        console.print("[dim]Debug mode enabled - showing full output[/dim]")
                    if ChocolateyInstaller.install_chocolatey(debug=debug):
                        console.print("[green]✅ Chocolatey installed successfully![/green]")

                        # Refresh PATH so chocolatey is available immediately
                        from medusa.platform.installers.windows import refresh_windows_path
                        refresh_windows_path()
                        console.print("[dim]PATH refreshed - chocolatey is now available[/dim]\n")

                        # Mark that we just installed it
                        chocolatey_just_installed = True

                        # Initialize choco_installer now that it's available
                        choco_installer = ChocolateyInstaller(debug=debug)
                    else:
                        console.print("[red]❌ Failed to install Chocolatey (admin rights required)[/red]")
                        console.print("[dim]You can install manually: https://chocolatey.org/install[/dim]\n")
                else:
                    console.print("[yellow]Skipping Chocolatey installation[/yellow]\n")

        # ========================================
        # Pre-scan phase: Detect runtime dependencies
        # ========================================
        npm_tools_needed = []
        php_tools_needed = []
        go_tools_needed = []
        java_tools_needed = []

        for tool in missing_tools:
            # Check if tool needs npm
            npm_package = ToolMapper.get_package_name(tool, 'npm')
            if npm_package and not npm_installer:
                # Tool has npm package but npm isn't available
                npm_tools_needed.append(tool)

            # Check if tool needs PHP
            if tool == 'phpstan' and not shutil.which('php'):
                php_tools_needed.append(tool)

            # Check if tool needs Go
            if tool == 'checkmake' and not shutil.which('go'):
                go_tools_needed.append(tool)

            # Check if tool needs Java
            if tool in {'checkstyle', 'ktlint', 'scalastyle', 'codenarc'} and not shutil.which('java'):
                java_tools_needed.append(tool)

        # ========================================
        # Runtime installation phase
        # ========================================
        if npm_tools_needed or php_tools_needed or go_tools_needed or java_tools_needed:
            console.print("[bold]Runtime Dependencies Detected:[/bold]")

            # Node.js / npm
            if npm_tools_needed:
                console.print(f"  • Node.js needed for {len(npm_tools_needed)} tool{'s' if len(npm_tools_needed) > 1 else ''}: {', '.join(npm_tools_needed[:3])}{'...' if len(npm_tools_needed) > 3 else ''}")

            # PHP
            if php_tools_needed:
                console.print(f"  • PHP needed for {len(php_tools_needed)} tool{'s' if len(php_tools_needed) > 1 else ''}: {', '.join(php_tools_needed)}")

            # Go
            if go_tools_needed:
                console.print(f"  • Go needed for {len(go_tools_needed)} tool{'s' if len(go_tools_needed) > 1 else ''}: {', '.join(go_tools_needed)}")

            # Java (info only)
            if java_tools_needed:
                console.print(f"  • Java needed for {len(java_tools_needed)} tool{'s' if len(java_tools_needed) > 1 else ''}: {', '.join(java_tools_needed[:3])}{'...' if len(java_tools_needed) > 3 else ''} [dim](not auto-installed for security)[/dim]")

            console.print()

        # Install Node.js if needed
        if npm_tools_needed and platform_info.os_type.value == 'windows':
            from medusa.platform import PackageManager
            if pm in (PackageManager.WINGET, PackageManager.CHOCOLATEY):
                install_nodejs = _prompt_with_auto_all(f"Install Node.js to enable {len(npm_tools_needed)} npm tools?", default=True, auto_yes_all=auto_yes_all)

                if install_nodejs:
                    console.print("\n[cyan]Installing Node.js via winget...[/cyan]")
                    winget_path = shutil.which('winget')

                    if winget_path:
                        try:
                            success, output = _safe_run_version_check(
                                [winget_path, 'install', '--id', 'OpenJS.NodeJS', '--accept-source-agreements', '--accept-package-agreements'],
                                timeout=120
                            )
                            output_lower = output.lower() if output else ''
                            nodejs_success = (
                                success or
                                'already installed' in output_lower or
                                'no available upgrade found' in output_lower
                            )

                            if nodejs_success:
                                console.print("[green]✅ Node.js installed successfully[/green]")

                                # Refresh PATH
                                from medusa.platform.installers.windows import refresh_windows_path
                                refresh_windows_path()

                                # Re-initialize npm_installer now that npm is available
                                from medusa.platform.installers import NpmInstaller
                                npm_installer = NpmInstaller() if shutil.which('npm.cmd') or shutil.which('npm') else None
                                console.print(f"[green]✓[/green] npm is now available\n")
                            else:
                                console.print("[red]❌ Failed to install Node.js[/red]\n")
                        except Exception as e:
                            console.print(f"[red]Error: {str(e)[:100]}[/red]\n")
                    else:
                        console.print("[red]❌ winget not found[/red]\n")
                else:
                    console.print("[yellow]Skipping Node.js installation[/yellow]\n")

        # Install PHP if needed
        if php_tools_needed and platform_info.os_type.value == 'windows':
            from medusa.platform import PackageManager
            if pm in (PackageManager.WINGET, PackageManager.CHOCOLATEY):
                install_php = _prompt_with_auto_all(f"Install PHP to enable phpstan?", default=True, auto_yes_all=auto_yes_all)

                if install_php:
                    console.print("\n[cyan]Installing PHP via winget...[/cyan]")
                    winget_path = shutil.which('winget')

                    if winget_path:
                        try:
                            success, output = _safe_run_version_check(
                                [winget_path, 'install', '--id', 'PHP.PHP.8.4', '--accept-source-agreements', '--accept-package-agreements'],
                                timeout=120
                            )
                            output_lower = output.lower() if output else ''
                            php_success = (
                                success or
                                'already installed' in output_lower or
                                'no available upgrade found' in output_lower
                            )

                            if php_success:
                                console.print("[green]✅ PHP installed successfully[/green]")
                                console.print("[dim]   You may need to restart your terminal for PHP to be available[/dim]\n")
                            else:
                                console.print("[red]❌ Failed to install PHP[/red]\n")
                        except Exception as e:
                            console.print(f"[red]Error: {str(e)[:100]}[/red]\n")
                    else:
                        console.print("[red]❌ winget not found[/red]\n")
                else:
                    console.print("[yellow]Skipping PHP installation[/yellow]\n")

        # Install Go if needed
        if go_tools_needed and platform_info.os_type.value == 'windows':
            from medusa.platform import PackageManager
            if pm in (PackageManager.WINGET, PackageManager.CHOCOLATEY):
                install_go = _prompt_with_auto_all(f"Install Go to enable checkmake?", default=True, auto_yes_all=auto_yes_all)

                if install_go:
                    go_installed = False
                    console.print("\n[cyan]Installing Go via winget...[/cyan]")
                    winget_path = shutil.which('winget')

                    if winget_path:
                        try:
                            success, output = _safe_run_version_check(
                                [winget_path, 'install', '--id', 'GoLang.Go', '--accept-source-agreements', '--accept-package-agreements'],
                                timeout=120
                            )
                            output_lower = output.lower() if output else ''
                            go_success = (
                                success or
                                'already installed' in output_lower or
                                'no available upgrade found' in output_lower
                            )

                            if go_success:
                                console.print("[green]✅ Go installed successfully[/green]")
                                go_installed = True

                                # Refresh PATH
                                from medusa.platform.installers.windows import refresh_windows_path
                                refresh_windows_path()
                                console.print("[dim]   Go is now available for checkmake[/dim]\n")
                            else:
                                if debug:
                                    console.print(f"[dim]winget output: {output[:200]}[/dim]")
                                console.print("[yellow]⚠️  winget failed, trying choco fallback...[/yellow]")
                        except Exception as e:
                            if debug:
                                console.print(f"[dim]winget error: {str(e)[:100]}[/dim]")
                            console.print("[yellow]⚠️  winget failed, trying choco fallback...[/yellow]")
                    else:
                        console.print("[yellow]⚠️  winget not found, trying choco...[/yellow]")

                    # Fallback to Chocolatey if winget failed
                    if not go_installed and choco_installer:
                        console.print("[cyan]Installing Go via choco...[/cyan]")
                        if choco_installer.install('go'):
                            console.print("[green]✅ Go installed successfully via choco[/green]")
                            from medusa.platform.installers.windows import refresh_windows_path
                            refresh_windows_path()
                            console.print("[dim]   Go is now available for checkmake[/dim]\n")
                            go_installed = True
                        else:
                            console.print("[red]❌ Failed to install Go via choco[/red]\n")

                    if not go_installed:
                        console.print("[yellow]⚠️  Go installation failed - checkmake will not be available[/yellow]\n")
                else:
                    console.print("[yellow]Skipping Go installation[/yellow]\n")

        # Show Java message (no auto-install)
        if java_tools_needed:
            console.print(f"[yellow]⚠️  Java runtime required for {len(java_tools_needed)} tool{'s' if len(java_tools_needed) > 1 else ''}[/yellow]")
            console.print("[dim]   We don't auto-install Java due to security concerns[/dim]")
            console.print(f"[dim]   Tools: {', '.join(java_tools_needed)}[/dim]\n")

        # ========================================
        # Tool installation phase
        # ========================================
        installed = 0
        failed = 0
        failed_details = []  # Track why each tool failed
        npm_tools_failed = []  # Track npm tools that failed due to missing npm

        # Get manifest for tracking installations
        manifest = get_manifest()

        console.print("[bold]Installing Tools:[/bold]")
        for tool_name in missing_tools:
            console.print(f"[cyan]Installing {tool_name}...[/cyan]")

            # Determine best installer upfront (more professional, direct approach)
            best_installer = None
            installer_name = None
            package_name = None

            # Priority order: system PM → chocolatey (Windows) → npm → pip
            # Check which installers have this package available
            pm_package = ToolMapper.get_package_name(tool_name, pm.value if pm else '') if pm else None
            choco_package = None
            choco_installer = None

            # On Windows, also check chocolatey as secondary package manager
            if platform_info.os_type.value == 'windows':
                choco_package = ToolMapper.get_package_name(tool_name, 'choco')
                # Use chocolatey if it's installed OR if we just installed it in this session
                if choco_package and (chocolatey_just_installed or ChocolateyInstaller.is_chocolatey_installed()):
                    choco_installer = ChocolateyInstaller(debug=debug)

            npm_package = ToolMapper.get_package_name(tool_name, 'npm')
            pip_package = ToolMapper.get_package_name(tool_name, 'pip')

            # Debug output for troubleshooting
            if debug:
                console.print(f"[DEBUG] Tool: {tool_name}")
                console.print(f"[DEBUG] Primary PM: {pm.value if pm else 'None'}")
                console.print(f"[DEBUG] Installer: {installer.__class__.__name__ if installer else 'None'}")
                console.print(f"[DEBUG] PM package: {pm_package}")
                console.print(f"[DEBUG] Choco package: {choco_package}")
                console.print(f"[DEBUG] NPM package: {npm_package}")
                console.print(f"[DEBUG] PIP package: {pip_package}")

            # Pick the first available installer
            if installer and pm_package:
                best_installer = installer
                installer_name = pm.value
                package_name = pm_package
            elif choco_installer and choco_package:
                best_installer = choco_installer
                installer_name = 'choco'
                package_name = choco_package
            elif npm_installer and npm_package:
                best_installer = npm_installer
                installer_name = 'npm'
                package_name = npm_package
            elif pip_installer and pip_package:
                best_installer = pip_installer
                installer_name = 'pip'
                package_name = pip_package

            # Track npm tools that failed due to missing npm
            if npm_package and not npm_installer and not best_installer:
                npm_tools_failed.append(tool_name)

            # Install using the best installer
            if best_installer:
                console.print(f"  → Installing {tool_name} via {installer_name}: {package_name}")
                # Only npm and pip support use_latest parameter
                if installer_name in ('npm', 'pip'):
                    success = best_installer.install(tool_name, use_latest=use_latest)
                else:
                    success = best_installer.install(tool_name)

                # Fallback: If winget failed and choco is available, try choco for specific tools
                if not success and installer_name == 'winget' and choco_installer and choco_package:
                    if tool_name in {'cppcheck', 'cargo-clippy'}:
                        console.print(f"  [yellow]⚠️ winget failed, trying choco fallback...[/yellow]")
                        console.print(f"  → Installing {tool_name} via choco: {choco_package}")
                        success = choco_installer.install(tool_name)
                        if success:
                            installer_name = 'choco'  # Update for reporting

                if success:
                    # Special handling for rubocop: winget installs Ruby, then we need gem to install rubocop
                    if tool_name == 'rubocop' and installer_name == 'winget' and platform_info.os_type.value == 'windows':
                        console.print(f"  [green]✅ Ruby installed successfully[/green]")
                        console.print(f"  → Refreshing PATH to find gem...")

                        import time
                        time.sleep(3)  # Wait for Ruby installation to complete

                        # Refresh PATH from Windows registry
                        try:
                            import winreg
                            import os

                            # Read PATH from Windows registry
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 0, winreg.KEY_READ) as key:
                                system_path = winreg.QueryValueEx(key, 'PATH')[0]

                            # Read user PATH
                            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_READ) as key:
                                user_path = winreg.QueryValueEx(key, 'PATH')[0]

                            # Update current process PATH
                            os.environ['PATH'] = system_path + ';' + user_path

                            if debug:
                                console.print(f"[DEBUG] PATH refreshed from registry")
                        except Exception as e:
                            if debug:
                                console.print(f"[DEBUG] PATH refresh failed: {e}")

                        # Now try to find gem
                        gem_path = shutil.which('gem.cmd') or shutil.which('gem')

                        if gem_path:
                            console.print(f"  → Found gem: {gem_path}")
                            console.print(f"  → Installing rubocop via gem...")

                            try:
                                result = subprocess.run(
                                    [gem_path, 'install', 'rubocop'],
                                    capture_output=True,
                                    text=True,
                                    timeout=300,
                                    check=False
                                )

                                if result.returncode == 0:
                                    console.print(f"  [green]✅ rubocop installed via gem[/green]\n")
                                    installed += 1
                                    # Detect installed version for manifest fingerprinting
                                    installed_version = _detect_tool_version(tool_name)
                                    # Record installation in manifest
                                    manifest.mark_installed(
                                        tool_name=tool_name,
                                        package_manager='gem',
                                        package_id='rubocop',
                                        version=installed_version,
                                        already_existed=False
                                    )
                                else:
                                    console.print(f"  [red]❌ gem install failed: {result.stderr[:200]}[/red]\n")
                                    failed += 1
                                    failed_details.append((tool_name, f"gem install failed"))
                            except Exception as e:
                                console.print(f"  [red]❌ gem install error: {str(e)[:200]}[/red]\n")
                                failed += 1
                                failed_details.append((tool_name, f"gem error"))
                        else:
                            console.print(f"  [yellow]⚠️  gem not found after Ruby install[/yellow]")
                            console.print(f"  [yellow]⊘ Please restart terminal and run: gem install rubocop[/yellow]\n")
                            failed += 1
                            failed_details.append((tool_name, "gem not found"))
                    else:
                        console.print(f"  [green]✅ Installed successfully[/green]\n")
                        installed += 1
                        # Detect installed version for manifest fingerprinting
                        installed_version = _detect_tool_version(tool_name)
                        # Record installation in manifest
                        manifest.mark_installed(
                            tool_name=tool_name,
                            package_manager=installer_name,
                            package_id=package_name,
                            version=installed_version,
                            already_existed=False
                        )
                else:
                    console.print(f"  [red]❌ Installation failed[/red]")

                    # Try ecosystem detection as fallback
                    from medusa.platform.installers.base import EcosystemDetector

                    # Check if this tool has an ecosystem option
                    if tool_name in EcosystemDetector.ECOSYSTEM_MAP:
                        ecosystems = EcosystemDetector.ECOSYSTEM_MAP[tool_name]['ecosystems']
                        ecosystem_result = EcosystemDetector.detect_ecosystem(tool_name)

                        if ecosystem_result:
                            ecosystem_name, command = ecosystem_result
                            console.print(f"  → Trying ecosystem fallback: {ecosystem_name}... [green]✓ Found[/green]")
                            console.print(f"  → Installing {tool_name} via {ecosystem_name}...")

                            ecosystem_success, _, message = EcosystemDetector.try_ecosystem_install(tool_name)
                            if ecosystem_success:
                                console.print(f"  [green]✅ {message}[/green]\n")
                                installed += 1
                                # Detect installed version for manifest fingerprinting
                                installed_version = _detect_tool_version(tool_name)
                                # Record installation in manifest
                                manifest.mark_installed(
                                    tool_name=tool_name,
                                    package_manager=ecosystem_name,
                                    package_id=tool_name,
                                    version=installed_version,
                                    already_existed=False
                                )
                            else:
                                console.print(f"  [red]❌ {message}[/red]")
                                # Show helpful hint on macOS
                                if platform_info.os_type.value == 'darwin':
                                    from medusa.platform.installers.macos import HomebrewInstaller
                                    hint = HomebrewInstaller.get_install_hint(tool_name)
                                    if hint:
                                        console.print(f"  [dim]💡 {hint}[/dim]")
                                console.print()
                                failed += 1
                                failed_details.append((tool_name, f"{installer_name} → {ecosystem_name}"))
                        else:
                            # Ecosystem not found
                            console.print(f"  → Looking for {ecosystems[0]}... [red]✗ Not found[/red]")
                            # Show helpful hint on macOS
                            if platform_info.os_type.value == 'darwin':
                                from medusa.platform.installers.macos import HomebrewInstaller
                                hint = HomebrewInstaller.get_install_hint(tool_name)
                                if hint:
                                    console.print(f"  [dim]💡 {hint}[/dim]")
                            console.print(f"  [yellow]⊘ Review installation guide for manual setup[/yellow]\n")
                            failed += 1
                            failed_details.append((tool_name, installer_name))
                    else:
                        # No ecosystem option for this tool - show hint if available
                        if platform_info.os_type.value == 'darwin':
                            from medusa.platform.installers.macos import HomebrewInstaller
                            hint = HomebrewInstaller.get_install_hint(tool_name)
                            if hint:
                                console.print(f"  [dim]💡 {hint}[/dim]")
                        console.print()
                        failed += 1
                        failed_details.append((tool_name, installer_name))
            else:
                # On Windows, try custom PowerShell installers FIRST (more reliable than ecosystem)
                if platform_info.os_type.value == 'windows':
                    from medusa.platform.installers import WindowsCustomInstaller
                    if WindowsCustomInstaller.can_install(tool_name):
                        console.print(f"  → Using custom Windows installer...")
                        if WindowsCustomInstaller.install(tool_name, debug=debug):
                            console.print(f"  [green]✅ Installed successfully[/green]\n")
                            installed += 1
                            # Detect installed version for manifest fingerprinting
                            installed_version = _detect_tool_version(tool_name)
                            # Record installation in manifest
                            manifest.mark_installed(
                                tool_name=tool_name,
                                package_manager='powershell',
                                package_id=tool_name,
                                version=installed_version,
                                already_existed=False
                            )
                            continue  # Skip to next tool
                        else:
                            console.print(f"  [red]❌ Custom installer failed[/red]")
                            # Fall through to ecosystem check

                # Try ecosystem detection as fallback
                from medusa.platform.installers.base import EcosystemDetector

                # Special handling for rubocop: refresh PATH to find gem if Ruby is installed
                if tool_name == 'rubocop' and platform_info.os_type.value == 'windows':
                    if debug:
                        console.print(f"[DEBUG] Checking for Ruby and refreshing PATH for gem...")

                    # Refresh PATH from Windows registry to detect gem
                    try:
                        import winreg
                        import os
                        import time

                        # Read PATH from Windows registry
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 0, winreg.KEY_READ) as key:
                            system_path = winreg.QueryValueEx(key, 'PATH')[0]

                        # Read user PATH
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_READ) as key:
                            user_path = winreg.QueryValueEx(key, 'PATH')[0]

                        # Update current process PATH
                        os.environ['PATH'] = system_path + ';' + user_path

                        if debug:
                            console.print(f"[DEBUG] PATH refreshed from registry")
                    except Exception as e:
                        if debug:
                            console.print(f"[DEBUG] PATH refresh failed: {e}")

                ecosystem_result = EcosystemDetector.detect_ecosystem(tool_name)
                if ecosystem_result:
                    ecosystem_name, command = ecosystem_result
                    console.print(f"  → Looking for {ecosystem_name}... [green]✓ Found[/green]")
                    console.print(f"  → Installing {tool_name} via {ecosystem_name}...")

                    success, _, message = EcosystemDetector.try_ecosystem_install(tool_name)
                    if success:
                        console.print(f"  [green]✅ {message}[/green]\n")
                        installed += 1
                        # Detect installed version for manifest fingerprinting
                        installed_version = _detect_tool_version(tool_name)
                        # Record installation in manifest
                        manifest.mark_installed(
                            tool_name=tool_name,
                            package_manager=ecosystem_name,
                            package_id=tool_name,
                            version=installed_version,
                            already_existed=False
                        )
                    else:
                        console.print(f"  [red]❌ {message}[/red]\n")
                        failed += 1
                        failed_details.append((tool_name, ecosystem_name))
                else:
                    # Check if ecosystem exists but not found
                    if tool_name in EcosystemDetector.ECOSYSTEM_MAP:
                        ecosystems = EcosystemDetector.ECOSYSTEM_MAP[tool_name]['ecosystems']
                        console.print(f"  → Looking for {ecosystems[0]}... [red]✗ Not found[/red]")
                        console.print(f"  [yellow]⊘ Review installation guide for manual setup[/yellow]\n")
                    else:
                        console.print(f"  [yellow]⊘ No installer available for this platform[/yellow]\n")
                    failed += 1
                    failed_details.append((tool_name, 'no installer'))

        console.print()
        console.print(f"[bold]Installation Summary:[/bold]")
        console.print(f"  ✅ Installed: {installed}")
        if failed > 0:
            console.print(f"  ❌ Failed: {failed}")

        # Windows PATH refresh warning
        if installed > 0 and platform_info.os_type.value == 'windows':
            console.print(f"\n[bold yellow]⚠️  Windows PATH Update Required[/bold yellow]")
            console.print(f"[yellow]   Please restart your terminal for the installed tools to be detected[/yellow]")
            console.print(f"[dim]   Tools installed via winget/npm may not be in your PATH until you restart[/dim]")

        # Generate installation guide for failed tools
        if failed > 0:
            guide_path = Path.cwd() / ".medusa" / "installation-guide.md"
            guide_path.parent.mkdir(parents=True, exist_ok=True)
            _generate_installation_guide(failed_details, guide_path, platform_info)
            console.print(f"\n[cyan]📄 Installation guide created: {guide_path}[/cyan]")
            console.print(f"[dim]   See this file for manual installation instructions[/dim]")

        console.print(f"\n[dim]Run 'medusa config' to see updated scanner status[/dim]")


@main.command()
@click.argument('tool', required=False)
@click.option('--all', 'all_tools', is_flag=True, help='Uninstall all MEDUSA scanner tools')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
@click.option('--debug', is_flag=True, help='Show detailed debug output')
@click.option('--force', is_flag=True, help='Uninstall even if not installed by MEDUSA (use with caution)')
def uninstall(tool, all_tools, yes, debug, force):
    """
    Uninstall security scanner tools.

    Examples:
        medusa uninstall shellcheck  # Uninstall specific tool
        medusa uninstall --all       # Uninstall all tools
    """
    print_banner()

    console.print("\n[cyan]📦 Tool Uninstallation[/cyan]\n")

    if debug:
        console.print("[dim]Debug mode enabled - showing detailed output[/dim]\n")

    from medusa.platform import get_platform_info
    from medusa.scanners import registry
    from medusa.platform.installers import (
        AptInstaller, YumInstaller, DnfInstaller, PacmanInstaller,
        HomebrewInstaller, WingetInstaller, ChocolateyInstaller, NpmInstaller, PipInstaller, ToolMapper
    )

    platform_info = get_platform_info()

    if debug:
        console.print(f"[DEBUG] Platform: {platform_info.os_type.value}")
        console.print(f"[DEBUG] Primary PM: {platform_info.primary_package_manager}")

    # Get manifest
    manifest = get_manifest()

    # Get installed tools
    installed_tools = []
    skipped_tools = []  # Tools found but not installed by MEDUSA
    if debug:
        console.print("[DEBUG] Scanning for installed tools...")
    for scanner in registry.get_all_scanners():
        if scanner.is_available():
            tool_name = scanner.tool_name
            if tool_name and tool_name not in installed_tools:
                # Check if this tool was installed by MEDUSA or if --force is used
                was_medusa_installed = manifest.was_installed_by_medusa(tool_name)
                is_support_software = manifest.is_support_software(tool_name)

                # Version fingerprinting: Check if tool version changed since MEDUSA installed it
                version_changed = False
                if was_medusa_installed and not force:
                    manifest_info = manifest.get_tool_info(tool_name)
                    manifest_version = manifest_info.get('version') if manifest_info else None
                    # Get package manager from manifest to help version detection
                    pm_hint = manifest_info.get('package_manager') if manifest_info else None
                    current_version = _detect_tool_version(tool_name, package_manager=pm_hint)

                    if manifest_version and current_version and manifest_version != current_version:
                        version_changed = True
                        skipped_tools.append(tool_name)
                        if debug:
                            console.print(f"[DEBUG]   Skipped: {tool_name} (version changed: {manifest_version} → {current_version})")

                if not version_changed and (force or (was_medusa_installed and not is_support_software)):
                    installed_tools.append(tool_name)
                    if debug:
                        console.print(f"[DEBUG]   Found: {tool_name} (MEDUSA installed: {was_medusa_installed})")
                elif not version_changed:
                    skipped_tools.append(tool_name)
                    if debug:
                        reason = "support software" if is_support_software else "not installed by MEDUSA"
                        console.print(f"[DEBUG]   Skipped: {tool_name} ({reason})")

    if debug:
        console.print(f"[DEBUG] Total installed tools: {len(installed_tools)}")
        if skipped_tools:
            console.print(f"[DEBUG] Total skipped tools: {len(skipped_tools)}\n")
        else:
            console.print()

    # Show skipped tools message if not using --force
    if skipped_tools and not force:
        console.print(f"[yellow]ℹ️  Skipped {len(skipped_tools)} tools not installed by MEDUSA[/yellow]")
        console.print(f"[dim]   Use --force to uninstall them anyway[/dim]\n")

    if not installed_tools:
        if skipped_tools:
            console.print("[yellow]No MEDUSA-installed tools to uninstall[/yellow]")
            console.print(f"[dim]Found {len(skipped_tools)} tools that were not installed by MEDUSA[/dim]")
            console.print(f"[dim]Use --force to uninstall them[/dim]")
        else:
            console.print("[yellow]No MEDUSA scanner tools found to uninstall[/yellow]")
        return

    # Uninstall specific tool
    if tool:
        # Check if tool was skipped due to version change
        if tool in skipped_tools:
            # Check if it was version-related skip
            manifest_info = manifest.get_tool_info(tool)
            manifest_version = manifest_info.get('version') if manifest_info else None
            pm_hint = manifest_info.get('package_manager') if manifest_info else None
            current_version = _detect_tool_version(tool, package_manager=pm_hint)
            if manifest_version and current_version and manifest_version != current_version:
                console.print(f"[yellow]Tool '{tool}' version changed ({manifest_version} → {current_version})[/yellow]")
                console.print("[yellow]Skipping to protect your manual upgrade. Use --force to override.[/yellow]")
                return

        if tool not in installed_tools:
            console.print(f"[yellow]Tool '{tool}' is not installed or not a MEDUSA scanner tool[/yellow]")
            return

        if not yes:
            confirm = click.confirm(f"Uninstall {tool}?", default=False)
            if not confirm:
                console.print("[yellow]Uninstallation cancelled[/yellow]")
                return

        if debug:
            console.print(f"[DEBUG] Tool: {tool}")
            console.print(f"[DEBUG] Primary PM: {platform_info.primary_package_manager}")

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
                PackageManager.WINGET: WingetInstaller(),
                PackageManager.CHOCOLATEY: ChocolateyInstaller(),
            }
            installer = installer_map.get(pm)

        npm_installer = NpmInstaller() if _has_npm_available() else None
        pip_installer = PipInstaller() if _has_pip_available() else None

        success = False

        # Try appropriate uninstaller
        if installer and ToolMapper.get_package_name(tool, pm.value if pm else ''):
            if debug:
                pkg = ToolMapper.get_package_name(tool, pm.value)
                console.print(f"\n[DEBUG] Uninstalling via {pm.value}: {pkg}")
            success = installer.uninstall(tool)
        elif npm_installer and ToolMapper.is_npm_tool(tool):
            if debug:
                console.print(f"\n[DEBUG] Uninstalling via npm")
            success = npm_installer.uninstall(tool)
        elif pip_installer and ToolMapper.is_python_tool(tool):
            if debug:
                console.print(f"\n[DEBUG] Uninstalling via pip")
            success = pip_installer.uninstall(tool)

        if success:
            console.print("[green]✅[/green]")
            # Remove from manifest
            manifest.mark_uninstalled(tool)
        else:
            console.print("[red]❌[/red]")
            console.print(f"[yellow]Note: You may need to uninstall {tool} manually[/yellow]")

    # Uninstall all tools
    elif all_tools:
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
                PackageManager.WINGET: WingetInstaller(),
                PackageManager.CHOCOLATEY: ChocolateyInstaller(),
            }
            installer = installer_map.get(pm)

        npm_installer = NpmInstaller() if _has_npm_available() else None
        pip_installer = PipInstaller() if _has_pip_available() else None

        uninstalled = 0
        failed = 0

        for tool_name in installed_tools:
            if debug:
                console.print(f"\n[DEBUG] Processing: {tool_name}")
                console.print(f"[DEBUG]   PM package: {ToolMapper.get_package_name(tool_name, pm.value if pm else '')}")
                console.print(f"[DEBUG]   Is NPM tool: {ToolMapper.is_npm_tool(tool_name)}")
                console.print(f"[DEBUG]   Is Python tool: {ToolMapper.is_python_tool(tool_name)}")

            console.print(f"[cyan]Uninstalling {tool_name}...[/cyan]", end=" ")

            success = False

            # Try appropriate uninstaller
            if installer and ToolMapper.get_package_name(tool_name, pm.value if pm else ''):
                if debug:
                    pkg = ToolMapper.get_package_name(tool_name, pm.value)
                    console.print(f"\n[DEBUG]   Using {pm.value} to uninstall: {pkg}")
                    console.print(f"[DEBUG]   Command: winget uninstall --id {pkg} --silent --accept-source-agreements")
                success = installer.uninstall(tool_name)
                if debug and not success:
                    console.print(f"[DEBUG]   Uninstall failed - check winget output above")
            elif npm_installer and ToolMapper.is_npm_tool(tool_name):
                if debug:
                    console.print(f"\n[DEBUG]   Using npm to uninstall")
                success = npm_installer.uninstall(tool_name)
            elif pip_installer and ToolMapper.is_python_tool(tool_name):
                if debug:
                    console.print(f"\n[DEBUG]   Using pip to uninstall")
                success = pip_installer.uninstall(tool_name)

            if success:
                console.print("[green]✅[/green]")
                uninstalled += 1
                # Remove from manifest
                manifest.mark_uninstalled(tool_name)
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


@main.command()
@click.option('--ai', '-a', 'show_ai', is_flag=True, help='Show only AI/LLM security scanners')
@click.option('--available', '-v', 'show_available', is_flag=True, help='Show only available (installed) scanners')
def scanners(show_ai, show_available):
    """
    List all available MEDUSA scanners.

    Shows scanner name, underlying tool, file extensions, and installation status.

    Examples:
        medusa scanners              # List all 63 scanners
        medusa scanners --ai         # List only AI/LLM scanners
        medusa scanners --available  # List only installed scanners
    """
    from medusa.scanners import registry
    from rich.table import Table

    all_scanners = registry.get_all_scanners()

    # Filter for AI scanners if requested
    if show_ai:
        ai_keywords = ['ai', 'llm', 'agent', 'mcp', 'rag', 'memory', 'model', 'vector',
                       'garak', 'guard', 'owasp', 'prompt', 'a2a', 'multi', 'tool']
        all_scanners = [s for s in all_scanners
                        if any(kw in s.name.lower() for kw in ai_keywords)]

    # Filter for available only if requested
    if show_available:
        all_scanners = [s for s in all_scanners if s.is_available()]

    # Create table
    table = Table(title="MEDUSA Scanners", show_header=True, header_style="bold cyan")
    table.add_column("Scanner", style="cyan")
    table.add_column("Tool", style="magenta")
    table.add_column("Extensions", style="green", max_width=25)
    table.add_column("Status", style="yellow")

    installed = 0
    for scanner in sorted(all_scanners, key=lambda s: s.name):
        is_avail = scanner.is_available()
        if is_avail:
            installed += 1
        status = "[green]✓ Ready[/green]" if is_avail else "[dim]✗ Tool missing[/dim]"
        exts = ", ".join(scanner.get_file_extensions()[:5])
        if len(scanner.get_file_extensions()) > 5:
            exts += "..."
        table.add_row(scanner.name, scanner.tool_name, exts, status)

    console.print(table)
    console.print(f"\n[bold]Total: {len(all_scanners)} scanners[/bold] ({installed} ready, {len(all_scanners) - installed} need tools)")

    if show_ai:
        console.print("[dim]Showing AI/LLM scanners only. Remove --ai to see all.[/dim]")
    if not show_available and installed < len(all_scanners):
        console.print("[dim]Run 'medusa install --check' to see missing tools.[/dim]")


@main.command()
@click.argument('file_path')
@click.argument('scanner_name', required=False)
@click.option('--list', '-l', 'list_scanners', is_flag=True, help='List available scanners')
@click.option('--show', '-s', is_flag=True, help='Show current overrides')
@click.option('--remove', '-r', is_flag=True, help='Remove override for this file')
def override(file_path, scanner_name, list_scanners, show, remove):
    """
    Override scanner selection for specific files.

    MEDUSA uses confidence scoring to automatically choose the right scanner
    for YAML files (Ansible, Kubernetes, Docker Compose, or generic YAML).

    If it chooses wrong, use this command to correct it. The override will be
    saved in .medusa.yml and remembered for future scans.

    Examples:
        # Set docker-compose.dev.yml to use Docker Compose scanner
        medusa override docker-compose.dev.yml DockerComposeScanner

        # Show all available scanners
        medusa override . --list

        # Show current overrides
        medusa override . --show

        # Remove an override
        medusa override docker-compose.dev.yml --remove
    """
    from medusa.config import ConfigManager
    from medusa.scanners import registry
    from rich.table import Table

    # Load config
    config_path = ConfigManager.find_config()
    if config_path:
        config = ConfigManager.load_config(config_path)
    else:
        config_path = Path.cwd() / ".medusa.yml"
        config = ConfigManager.load_config(config_path)

    # List available scanners
    if list_scanners:
        table = Table(title="Available Scanners", show_header=True, header_style="bold cyan")
        table.add_column("Scanner Name", style="cyan")
        table.add_column("Tool", style="magenta")
        table.add_column("Extensions", style="green")
        table.add_column("Status", style="yellow")

        for scanner in sorted(registry.get_all_scanners(), key=lambda s: s.name):
            status = "✓ Installed" if scanner.is_available() else "✗ Not installed"
            exts = ", ".join(scanner.get_file_extensions())
            table.add_row(scanner.name, scanner.tool_name, exts, status)

        console.print(table)
        console.print(f"\n[dim]Use: medusa override <file> <scanner_name>[/dim]")
        return

    # Show current overrides
    if show:
        if not config.scanner_overrides:
            console.print("[yellow]No scanner overrides configured[/yellow]")
            console.print("[dim]Use: medusa override <file> <scanner_name>[/dim]")
            return

        table = Table(title="Scanner Overrides", show_header=True, header_style="bold cyan")
        table.add_column("File Pattern", style="cyan")
        table.add_column("Scanner", style="magenta")

        for file_pattern, scanner in sorted(config.scanner_overrides.items()):
            table.add_row(file_pattern, scanner)

        console.print(table)
        console.print(f"\n[dim]Total: {len(config.scanner_overrides)} override(s)[/dim]")
        return

    # Remove override
    if remove:
        if file_path in config.scanner_overrides:
            removed_scanner = config.scanner_overrides.pop(file_path)
            ConfigManager.save_config(config, config_path)
            console.print(f"[green]✓[/green] Removed override for [cyan]{file_path}[/cyan]")
            console.print(f"[dim]  (was: {removed_scanner})[/dim]")
        else:
            console.print(f"[yellow]No override found for {file_path}[/yellow]")
        return

    # Set override
    if not scanner_name:
        console.print("[red]Error: scanner_name required[/red]")
        console.print("[dim]Use --list to see available scanners[/dim]")
        return

    # Validate scanner exists
    scanner_exists = any(s.name == scanner_name for s in registry.get_all_scanners())
    if not scanner_exists:
        console.print(f"[red]Error: Scanner '{scanner_name}' not found[/red]")
        console.print("[dim]Use --list to see available scanners[/dim]")
        return

    # Add override
    config.scanner_overrides[file_path] = scanner_name
    ConfigManager.save_config(config, config_path)

    console.print(f"[green]✓[/green] Scanner override saved")
    console.print(f"  File: [cyan]{file_path}[/cyan]")
    console.print(f"  Scanner: [magenta]{scanner_name}[/magenta]")
    console.print(f"  Config: [dim]{config_path}[/dim]")
    console.print(f"\n[dim]This file will now always use {scanner_name} for scanning[/dim]")


@main.command()
@click.argument('target', default='.', type=click.Path(exists=True))
@click.option('--format', '-f', 'output_format', type=click.Choice(['spdx', 'cyclonedx', 'both']),
              default='cyclonedx', help='Output format (default: cyclonedx)')
@click.option('--output', '-o', type=click.Path(), help='Output file path (default: stdout or .medusa/sbom/)')
def sbom(target, output_format, output):
    """
    Generate Software Bill of Materials (SBOM) for a project.

    Analyzes dependencies from package managers (pip, npm, etc.) and
    generates SBOM in industry-standard formats.

    Supported formats:
    - CycloneDX (OWASP standard, default)
    - SPDX (ISO/IEC 5962:2021)

    Examples:
        medusa sbom .                    # Generate CycloneDX SBOM
        medusa sbom . --format spdx      # Generate SPDX SBOM
        medusa sbom . --format both      # Generate both formats
        medusa sbom . -o sbom.json       # Save to specific file
    """
    from pathlib import Path
    from datetime import datetime
    import json
    import uuid
    import hashlib

    print_banner()
    console.print("\n[cyan]📦 SBOM Generation[/cyan]\n")

    target_path = Path(target).resolve()
    console.print(f"[dim]Target: {target_path}[/dim]\n")

    # Detect dependencies from various package managers
    dependencies = []

    # Check for Python dependencies
    requirements_files = list(target_path.glob('**/requirements*.txt'))
    setup_py = target_path / 'setup.py'
    pyproject_toml = target_path / 'pyproject.toml'

    if pyproject_toml.exists():
        console.print("[cyan]Found:[/cyan] pyproject.toml")
        deps = _parse_pyproject_toml(pyproject_toml)
        dependencies.extend(deps)

    for req_file in requirements_files[:5]:  # Limit to first 5
        if 'node_modules' not in str(req_file) and '.venv' not in str(req_file):
            console.print(f"[cyan]Found:[/cyan] {req_file.relative_to(target_path)}")
            deps = _parse_requirements_txt(req_file)
            dependencies.extend(deps)

    # Check for Node.js dependencies
    package_json = target_path / 'package.json'
    if package_json.exists():
        console.print("[cyan]Found:[/cyan] package.json")
        deps = _parse_package_json(package_json)
        dependencies.extend(deps)

    # Check for package-lock.json for exact versions
    package_lock = target_path / 'package-lock.json'
    if package_lock.exists():
        console.print("[cyan]Found:[/cyan] package-lock.json")
        deps = _parse_package_lock(package_lock)
        dependencies.extend(deps)

    # Deduplicate dependencies (keep first occurrence with version info)
    seen = {}
    unique_deps = []
    for dep in dependencies:
        key = (dep['name'], dep['type'])
        if key not in seen:
            seen[key] = dep
            unique_deps.append(dep)
        elif dep.get('version') and not seen[key].get('version'):
            seen[key] = dep

    dependencies = unique_deps
    console.print(f"\n[green]✓ Found {len(dependencies)} dependencies[/green]\n")

    if not dependencies:
        console.print("[yellow]No dependencies found. Make sure you have:[/yellow]")
        console.print("  - requirements.txt / pyproject.toml (Python)")
        console.print("  - package.json / package-lock.json (Node.js)")
        return

    # Generate SBOM in requested format(s)
    output_dir = target_path / '.medusa' / 'sbom'
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format in ['cyclonedx', 'both']:
        sbom_data = _generate_cyclonedx(target_path, dependencies)
        if output and output_format == 'cyclonedx':
            output_path = Path(output)
        else:
            output_path = output_dir / 'sbom-cyclonedx.json'

        with open(output_path, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        console.print(f"[green]✓ CycloneDX SBOM:[/green] {output_path}")

    if output_format in ['spdx', 'both']:
        sbom_data = _generate_spdx(target_path, dependencies)
        if output and output_format == 'spdx':
            output_path = Path(output)
        else:
            output_path = output_dir / 'sbom-spdx.json'

        with open(output_path, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        console.print(f"[green]✓ SPDX SBOM:[/green] {output_path}")

    console.print(f"\n[dim]Components: {len(dependencies)}[/dim]")
    console.print(f"[dim]Use 'medusa scan' to check for vulnerabilities[/dim]")


def _parse_requirements_txt(path: Path) -> list:
    """Parse requirements.txt file"""
    deps = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Parse package==version, package>=version, etc.
                import re
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!~]+)?\s*([0-9a-zA-Z.*]+)?', line)
                if match:
                    name = match.group(1)
                    version = match.group(3) if match.group(3) else None
                    deps.append({
                        'name': name,
                        'version': version,
                        'type': 'pypi'
                    })
    except Exception:
        pass
    return deps


def _parse_pyproject_toml(path: Path) -> list:
    """Parse pyproject.toml for dependencies"""
    deps = []
    try:
        content = path.read_text()
        # Simple regex parsing for dependencies
        import re

        # Look for dependencies array
        in_deps = False
        for line in content.split('\n'):
            if 'dependencies' in line and '=' in line:
                in_deps = True
                continue
            if in_deps:
                if line.strip().startswith(']'):
                    in_deps = False
                    continue
                match = re.search(r'"([a-zA-Z0-9_-]+)([<>=!~]+)?([0-9a-zA-Z.*]+)?"', line)
                if match:
                    deps.append({
                        'name': match.group(1),
                        'version': match.group(3) if match.group(3) else None,
                        'type': 'pypi'
                    })
    except Exception:
        pass
    return deps


def _parse_package_json(path: Path) -> list:
    """Parse package.json for dependencies"""
    deps = []
    try:
        import json
        with open(path) as f:
            data = json.load(f)

        for dep_type in ['dependencies', 'devDependencies']:
            for name, version in data.get(dep_type, {}).items():
                # Clean version string (remove ^, ~, etc.)
                clean_version = version.lstrip('^~>=<')
                deps.append({
                    'name': name,
                    'version': clean_version if clean_version else None,
                    'type': 'npm',
                    'dev': dep_type == 'devDependencies'
                })
    except Exception:
        pass
    return deps


def _parse_package_lock(path: Path) -> list:
    """Parse package-lock.json for exact versions"""
    deps = []
    try:
        import json
        with open(path) as f:
            data = json.load(f)

        # v2/v3 lockfile format
        packages = data.get('packages', {})
        for pkg_path, info in packages.items():
            if not pkg_path or pkg_path == '':
                continue
            # Extract package name from path
            name = pkg_path.replace('node_modules/', '').split('/')[-1]
            if name.startswith('@'):
                # Scoped package
                parts = pkg_path.replace('node_modules/', '').split('/')
                if len(parts) >= 2:
                    name = f"{parts[-2]}/{parts[-1]}"

            deps.append({
                'name': name,
                'version': info.get('version'),
                'type': 'npm',
                'integrity': info.get('integrity')
            })
    except Exception:
        pass
    return deps


def _generate_cyclonedx(target_path: Path, dependencies: list) -> dict:
    """Generate CycloneDX 1.5 SBOM"""
    import uuid
    from datetime import datetime, timezone

    components = []
    for dep in dependencies:
        component = {
            'type': 'library',
            'name': dep['name'],
            'purl': f"pkg:{dep['type']}/{dep['name']}"
        }
        if dep.get('version'):
            component['version'] = dep['version']
            component['purl'] += f"@{dep['version']}"
        if dep.get('integrity'):
            component['hashes'] = [{
                'alg': 'SHA-512' if 'sha512-' in dep['integrity'] else 'SHA-256',
                'content': dep['integrity'].split('-')[-1] if '-' in dep['integrity'] else dep['integrity']
            }]
        components.append(component)

    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'version': 1,
        'metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'tools': [{
                'vendor': 'Pantheon Security',
                'name': 'MEDUSA',
                'version': '2025.9.0.0'
            }],
            'component': {
                'type': 'application',
                'name': target_path.name,
                'version': '0.0.0'
            }
        },
        'components': components
    }


def _generate_spdx(target_path: Path, dependencies: list) -> dict:
    """Generate SPDX 2.3 SBOM"""
    import uuid
    import hashlib
    from datetime import datetime, timezone

    packages = []
    for i, dep in enumerate(dependencies):
        pkg = {
            'SPDXID': f'SPDXRef-Package-{i+1}',
            'name': dep['name'],
            'downloadLocation': 'NOASSERTION',
            'filesAnalyzed': False
        }
        if dep.get('version'):
            pkg['versionInfo'] = dep['version']

        # Add external refs
        purl = f"pkg:{dep['type']}/{dep['name']}"
        if dep.get('version'):
            purl += f"@{dep['version']}"
        pkg['externalRefs'] = [{
            'referenceCategory': 'PACKAGE-MANAGER',
            'referenceType': 'purl',
            'referenceLocator': purl
        }]

        packages.append(pkg)

    doc_namespace = f'https://medusa.security/spdx/{target_path.name}-{uuid.uuid4()}'

    return {
        'spdxVersion': 'SPDX-2.3',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': f'{target_path.name}-sbom',
        'documentNamespace': doc_namespace,
        'creationInfo': {
            'created': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'creators': ['Tool: MEDUSA-2025.9.0.0'],
            'licenseListVersion': '3.19'
        },
        'packages': packages,
        'relationships': [
            {
                'spdxElementId': 'SPDXRef-DOCUMENT',
                'relatedSpdxElement': pkg['SPDXID'],
                'relationshipType': 'DESCRIBES'
            } for pkg in packages
        ]
    }


if __name__ == '__main__':
    main()
