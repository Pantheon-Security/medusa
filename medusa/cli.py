#!/usr/bin/env python3
"""
MEDUSA CLI - Command-line interface
Modern Click-based CLI for cross-platform security scanning
"""

import sys
import re
import shlex
import shutil
import subprocess
import tempfile
import click
from pathlib import Path
from typing import Optional
from rich.console import Console
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
    import re
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
        npm_cmd_path = shutil.which('npm.cmd')
        if npm_cmd_path:
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

# Module-level flag to track Node.js installation attempts within a session
_nodejs_install_attempted = False


def _summarize_skip_languages(analysis) -> str:
    """Summarize the languages whose scanners were skipped, for display."""
    from medusa.core.pattern_analyzer import CodePatternAnalyzer
    scanner_to_lang = {}
    for lang, scanner in CodePatternAnalyzer.LANGUAGE_TO_SCANNER.items():
        scanner_to_lang.setdefault(scanner, lang)
    skipped_langs = set()
    for scanner_name in analysis.skip_scanners:
        lang = scanner_to_lang.get(scanner_name)
        if lang:
            skipped_langs.add(lang)
    if not skipped_langs:
        return "matching"
    samples = sorted(skipped_langs)[:4]
    display = ", ".join(s.title() for s in samples)
    remaining = len(skipped_langs) - len(samples)
    if remaining > 0:
        display += f", +{remaining} more"
    return display


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

        # Special case: .env files with no extension (name is .env or starts with .env.)
        # Only apply when suffix is empty to avoid double-counting .env files
        name = file_path.name.lower()
        if not ext and (name == '.env' or name.startswith('.env.')):
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


def _handle_batch_install(target, analysis=None):
    """
    Handle batch installation mode - scan project, show summary, prompt once

    Args:
        target: Target directory to scan
        analysis: Optional pre-computed RepoAnalysis (avoids duplicate work)
    """
    if analysis is None:
        from medusa.core.pattern_analyzer import CodePatternAnalyzer
        console.print("\n[cyan]🔍 Analyzing repository...[/cyan]")
        analyzer = CodePatternAnalyzer()
        analysis = analyzer.analyze_repo(Path(target))

    if analysis.total_files == 0:
        return

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
        'PostQuantumScanner', 'SteganographyScanner',
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
            console.print(f"   {status} {scanner.name:25} ({scanner.tool_name or 'built-in'})")
        console.print()

    show_category("Language Scanners", language_scanners, "📝")
    show_category("AI Security Scanners", ai_scanners, "🤖")
    show_category("Infrastructure Scanners", infra_scanners, "🔧")

    # External linters are optional — just note if any are missing
    if missing_tools:
        console.print(f"\n[dim]{len(missing_tools)} optional external linter(s) not found ({', '.join(missing_tools[:3])}{'...' if len(missing_tools) > 3 else ''})[/dim]")
        console.print(f"[dim]Built-in AI rules will still scan. Run 'medusa install --check' for details.[/dim]")
    else:
        console.print(f"\n[dark_green]All recommended scanners are installed[/dark_green]")

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
                        console.print(f"[dark_green]✓[/dark_green] Node.js found: {output.strip()}")
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
                        # Use LTS version for stability, add --disable-interactivity for CI
                        success, output = _safe_run_version_check(
                            [winget_path, 'install', '--id', 'OpenJS.NodeJS.LTS', '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity'],
                            timeout=600  # 10 minute timeout for slow networks
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
                    console.print("[dark_green]✅ Node.js installed successfully[/dark_green]")

                    # Refresh PATH
                    from medusa.platform.installers.windows import refresh_windows_path
                    refresh_windows_path()
                    console.print("[dim]   PATH refreshed from registry[/dim]")

                    # Verify npm is now available
                    console.print("\n[cyan]Checking for npm...[/cyan]")
                    npm_path = shutil.which('npm.cmd') or shutil.which('npm')

                    if npm_path:
                        console.print(f"[dark_green]✓[/dark_green] npm found at: {npm_path}")
                        # Verify npm works
                        try:
                            success, output = _safe_run_version_check([npm_path, '--version'])
                            if success:
                                console.print(f"[dark_green]✓[/dark_green] npm version: {output.strip()}")
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
                                console.print(f"  [dark_green]✅ Installed via npm[/dark_green]\n")
                                npm_installed += 1
                                # Mark tool as installed in cache
                                from medusa.platform.tool_cache import ToolCache
                                cache = ToolCache()
                                cache.mark_installed(tool)
                            else:
                                console.print(f"  [red]❌ Failed[/red]\n")

                        if npm_installed > 0:
                            console.print(f"[dark_green]✅ Installed {npm_installed}/{len(npm_tools_failed)} npm tools[/dark_green]")
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

        if not yes and sys.stdin.isatty():
            response = Prompt.ask(
                "   Install PHP via winget to enable these tools?",
                choices=["y", "Y", "n", "N"],
                default="y",
                show_choices=False
            )
            install_php = response.upper() == "Y"
        else:
            install_php = yes

        if install_php:
            console.print("\n[cyan]Installing PHP via winget...[/cyan]")
            from medusa.platform.installers import WingetInstaller
            winget_installer = WingetInstaller()
            winget_path = shutil.which('winget')

            if winget_path:
                try:
                    # Add --disable-interactivity for CI and increase timeout for slow networks
                    success, output = _safe_run_version_check(
                        [winget_path, 'install', '--id', 'PHP.PHP.8.4', '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity'],
                        timeout=600  # 10 minute timeout for slow networks
                    )
                    output_lower = output.lower() if output else ''
                    php_success = (
                        success or
                        'already installed' in output_lower or
                        'no available upgrade found' in output_lower
                    )

                    if php_success:
                        console.print("[dark_green]✅ PHP installed successfully[/dark_green]")
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
                console.print(f"  [dark_green]✅ Installed via {pm.value}[/dark_green]")
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
                    console.print(f"  [dark_green]✅ Installed via npm[/dark_green]")
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
                    console.print(f"  [dark_green]✅ Installed via pip[/dark_green]")
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
                    result = subprocess.run(shlex.split(eco_cmd), capture_output=True, text=True, timeout=600)
                    if result.returncode == 0:
                        success = True
                        console.print(f"  [dark_green]✅ Installed via {eco_name}[/dark_green]")
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
                    result = subprocess.run(shlex.split(manual_cmd), capture_output=True, text=True, timeout=600)
                    if result.returncode == 0:
                        success = True
                        console.print(f"  [dark_green]✅ Installed via manual script[/dark_green]")
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
        console.print(f"\n[dark_green]✅ Installed {installed}/{len(tools)} tools[/dark_green]")
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
    """Print MEDUSA banner with large block-style ASCII logo"""
    logo = """[dark_green]
 ███╗   ███╗ ███████╗ ██████╗  ██╗   ██╗ ███████╗  █████╗
 ████╗ ████║ ██╔════╝ ██╔══██╗ ██║   ██║ ██╔════╝ ██╔══██╗
 ██╔████╔██║ █████╗   ██║  ██║ ██║   ██║ ███████╗ ███████║
 ██║╚██╔╝██║ ██╔══╝   ██║  ██║ ██║   ██║ ╚════██║ ██╔══██║
 ██║ ╚═╝ ██║ ███████╗ ██████╔╝ ╚██████╔╝ ███████║ ██║  ██║
 ╚═╝     ╚═╝ ╚══════╝ ╚═════╝   ╚═════╝  ╚══════╝ ╚═╝  ╚═╝[/dark_green]
"""
    # Version line: .2.0 in EXACT same cyan as Target:/Mode:
    version_parts = __version__.split('.', 1)  # Split: ['2026', '2.0']
    line2 = "78 Analyzers | 9,600+ Rules | AI Security Detection"

    try:
        # Use GLOBAL console - same one used for Target:/Mode:
        console.print(logo)
        if len(version_parts) == 2:
            # EXACT same [cyan] tag as Target:/Mode: line 1246
            padding = " " * 15
            console.print(f"{padding}v{version_parts[0]}[bright_cyan].{version_parts[1]}[/bright_cyan] - Security Scanner")
        else:
            console.print(f"v{__version__} - Security Scanner", justify="center")
        console.print(f"[dark_green]{line2:^58}[/dark_green]")
        console.print("")
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Fallback for Windows terminals that don't support Unicode
        try:
            rprint(f"[dark_green][bold]MEDUSA[/bold][/dark_green] [dim]v{__version__}[/dim] | [dark_green]78 Analyzers | 9,600+ Rules | AI Security Detection[/dark_green]")
            rprint("")
        except Exception:
            # Last resort: plain text
            print(f"\nMEDUSA v{__version__} - AI Security Scanner | 9,600+ Rules\n")


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version and exit')
@click.pass_context
def main(ctx, version):
    """
    MEDUSA - AI Security Scanner

    9,600+ AI security detection patterns with 78 specialized analyzers.
    Scan your code for vulnerabilities in seconds.

    Examples:
        medusa scan .                          # Scan current directory
        medusa scan --quick .                  # Quick incremental scan
        medusa scan . -e archive/ -e vendor/   # Exclude directories
        medusa init                            # Initialize MEDUSA in project
        medusa install                         # Install linters
    """
    from medusa.setup_path import check_and_warn
    check_and_warn()

    if version:
        click.echo(f"MEDUSA v{__version__}")
        ctx.exit(0)

    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@main.command()
@click.argument('target', type=click.Path(), default='.')
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
@click.option('-e', '--exclude', multiple=True,
              help='Exclude paths from scan (can specify multiple, e.g. --exclude archive/ --exclude scripts/)')
@click.option('-g', '--git', 'git_url', type=str, default=None,
              help='Clone and scan a remote git repo (URL or user/repo shorthand)')
def scan(target, workers, quick, force, no_cache, fail_on, output, output_formats, no_report, exclude, git_url):
    """
    Scan a directory or file for security issues.

    This will run all available security scanners on the target,
    generate beautiful HTML/JSON reports, and optionally fail the
    build if issues are found.

    Examples:
        medusa scan .                          # Scan current directory
        medusa scan --quick .                  # Only scan changed files
        medusa scan --force /path/to/project   # Force full rescan
        medusa scan --fail-on high .           # Fail on HIGH+ issues
        medusa scan . --exclude archive/       # Exclude a directory
        medusa scan . -e vendor/ -e scripts/   # Exclude multiple paths
        medusa scan --git user/repo            # Clone and scan a GitHub repo
        medusa scan -g https://github.com/u/r  # Clone and scan by URL
    """
    # Handle --git mode: clone remote repo and scan it
    if git_url:
        _scan_git_repo(
            git_url=git_url,
            workers=workers,
            quick=quick,
            force=force,
            no_cache=no_cache,
            fail_on=fail_on,
            output=output,
            output_formats=output_formats,
            no_report=no_report,
            exclude=exclude,
        )
        return

    # Validate target exists and is a directory (Issue #2 fix)
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error: Path '{target}' does not exist.[/red]")
        raise SystemExit(2)
    if not target_path.is_dir():
        console.print(f"[red]Error: Target must be a directory, not a file[/red]")
        console.print(f"[yellow]   Got: {target_path}[/yellow]")
        console.print(f"[dim]   Tip: To scan a single file, specify its parent directory[/dim]")
        raise SystemExit(1)

    print_banner()

    console.print(f"\n[cyan]🎯 Target:[/cyan] {target}")
    console.print(f"[cyan]🔧 Mode:[/cyan] {'Quick' if quick else 'Force' if force else 'Full'}")
    if exclude:
        console.print(f"[cyan]🚫 Excluding:[/cyan] {', '.join(exclude)}")

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

    # Show recommended scanners and what's missing
    from medusa.scanners import registry as _scan_reg
    from medusa.platform.installers.simple import EXTERNAL_TOOLS, get_install_hint, get_ai_tools_status

    all_scanners = _scan_reg.get_all_scanners()
    recommended_names = repo_analysis.recommended_scanners

    # Split recommended scanners into ready vs missing
    ready_scanners = []
    missing_scanners = []
    for s in all_scanners:
        if s.name not in recommended_names:
            continue
        if s.is_available():
            ready_scanners.append(s)
        elif s.get_tool_name() != 'python':
            missing_scanners.append(s)

    console.print()
    console.print(f"[dark_green]✓ Ready to scan:[/dark_green] {len(ready_scanners)} scanners")
    if repo_analysis.skip_scanners:
        console.print(f"[dim]  {len(repo_analysis.skip_scanners)} scanners skipped (no {_summarize_skip_languages(repo_analysis)} files found)[/dim]")

    # Check for CRITICAL missing tools (model files need modelscan, AI patterns need AI tools)
    model_exts = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.h5', '.hdf5', '.safetensors', '.joblib', '.ckpt', '.model', '.onnx', '.gguf'}
    has_model_files = any(ext.lower() in model_exts for ext in repo_analysis.file_extensions.keys())
    ai_status = get_ai_tools_status()
    modelscan_missing = not ai_status.get('modelscan', {}).get('installed', False)

    critical_warning = False
    if has_model_files and modelscan_missing:
        critical_warning = True
        console.print(f"\n[bold red]⚠️  CRITICAL: Model files detected but modelscan is NOT installed![/bold red]")
        console.print(f"[red]   Model files (.safetensors, .bin, .pkl, etc.) may contain malicious code.[/red]")
        console.print(f"[red]   Without modelscan, these files will NOT be scanned for security threats.[/red]")
        console.print(f"\n[yellow]   To install: [bold]medusa install --ai-tools[/bold][/yellow]")
        console.print(f"[yellow]               or: pip install modelscan[/yellow]")

    if missing_scanners and not critical_warning:
        console.print(f"\n[yellow]For best results, install {len(missing_scanners)} missing tool(s):[/yellow]")
        for s in missing_scanners:
            tool = s.get_tool_name()
            ext_info = EXTERNAL_TOOLS.get(tool, {})
            desc = ext_info.get('desc', s.name)
            hint = get_install_hint(tool)
            console.print(f"  [yellow]{tool}[/yellow] [dim]({desc})[/dim]")
            console.print(f"    [dim]{hint}[/dim]")

        if not sys.stdin.isatty():
            # Non-interactive (CI, subprocess, pipe) — auto-continue
            console.print("[dim]Non-interactive mode: continuing without optional tools.[/dim]\n")
        else:
            console.print(f"\n[bold yellow]Continue scan without these tools?[/bold yellow]")
            console.print("  [dim]yes[/dim] - Continue anyway (some files won't be fully scanned)")
            console.print("  [dim]no[/dim]  - Cancel and install the tools first")
            try:
                response = console.input("\n[bold yellow]Your choice (yes/no): [/bold yellow]").strip().lower()
                if response not in ('y', 'yes'):
                    console.print("\n[dim]Scan cancelled. Install the tools above and try again.[/dim]")
                    return
                console.print()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Scan cancelled.[/dim]")
                return

    # Ask Y/N if critical tools missing
    if critical_warning:
        console.print()
        if not sys.stdin.isatty():
            console.print("[dim]Non-interactive mode: continuing without modelscan.[/dim]\n")
        else:
            try:
                console.print("[bold yellow]Continue scan without modelscan?[/bold yellow]")
                console.print("  [dim]yes[/dim] - Continue anyway (model files won't be scanned)")
                console.print("  [dim]no[/dim]  - Cancel and install modelscan first")
                response = console.input("\n[bold yellow]Your choice (yes/no): [/bold yellow]").strip().lower()
                if response not in ('y', 'yes'):
                    console.print("\n[dim]Scan cancelled. Run 'medusa install --ai-tools' then try again.[/dim]")
                    return
                console.print()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Scan cancelled.[/dim]")
                return

    console.print()

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

    # Capture missing linters for post-scan recommendation
    # Only include linters relevant to detected languages (skip Go linters if no Go files, etc.)
    try:
        from medusa.scanners import registry as _sr
        ai_tool_names = {'modelscan', 'garak', 'llm-guard'}
        recommended_names = repo_analysis.recommended_scanners
        missing_linters = [
            s.get_tool_name() for s in _sr.get_unavailable_external_scanners()
            if s.get_tool_name() not in ai_tool_names
            and s.name in recommended_names
        ]
    except Exception:
        missing_linters = []

    try:
        from medusa.core.parallel import MedusaParallelScanner

        scanner = MedusaParallelScanner(
            project_root=Path(target),
            workers=workers,
            use_cache=not no_cache and not force,
            quick_mode=quick,
            extra_excludes=list(exclude) if exclude else None
        )

        # Find files
        files = scanner.find_scannable_files()
        if not files:
            console.print("[yellow]⚠️  No files found to scan[/yellow]")
            return

        console.print(f"[dark_green]Found {len(files)} scannable files[/dark_green]\n")

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

            scanner.generate_report(results, output_dir, formats=formats, missing_linters=missing_linters)

        # Check fail threshold — only count issues at or above the specified severity
        if fail_on:
            from medusa.scanners import Severity
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            threshold = Severity(fail_on.upper())
            threshold_index = severity_order.index(threshold)
            allowed_severities = {s for s in severity_order[:threshold_index + 1]}
            total_issues = sum(
                1 for r in results if not r.cached
                for issue in r.issues
                if issue.severity in allowed_severities
            )
            if total_issues > 0:
                console.print(f"\n[red]❌ Found {total_issues} issues at {fail_on.upper()}+ severity[/red]")
                sys.exit(1)

        console.print("\n[dark_green]✅ Scan complete![/dark_green]")

        # Post-scan: remind about missing linters for fuller coverage
        if missing_linters:
            console.print(f"\n[yellow]For fuller coverage, install missing linters and re-scan:[/yellow]")
            console.print(f"  [dim]{', '.join(missing_linters[:5])}{'...' if len(missing_linters) > 5 else ''}[/dim]")
            console.print(f"  [dim]Run 'medusa install --check' for details[/dim]")

    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")
        if '--debug' in sys.argv:
            raise
        sys.exit(1)


def _resolve_git_url(raw_url: str) -> str:
    """
    Resolve a git URL or GitHub/GitLab shorthand to a full clone URL.

    Accepts:
        - https://github.com/user/repo
        - https://github.com/user/repo.git
        - git@github.com:user/repo.git
        - user/repo  (shorthand -> https://github.com/user/repo)

    Returns:
        A validated HTTPS or SSH git URL.

    Raises:
        click.BadParameter if the URL is invalid.
    """
    url = raw_url.strip()

    # SSH URLs are valid as-is
    if url.startswith("git@"):
        return url

    # Full HTTPS URLs
    if url.startswith("https://") or url.startswith("http://"):
        return url

    # Shorthand: user/repo -> https://github.com/user/repo
    if re.match(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$', url):
        return f"https://github.com/{url}"

    raise click.BadParameter(
        f"Invalid git URL: '{url}'. "
        "Use a full URL (https://github.com/user/repo) or shorthand (user/repo)."
    )


# Priority files that indicate AI coding editor injection vectors
_PRIORITY_FILES: list[tuple[str, str, str]] = [
    # (glob pattern, severity color, description)
    # --- Critical: Known RCE / zero-click attack vectors ---
    (".cursorrules", "red", "Cursor AI injection vector (CVE-2025-54135)"),
    (".cursor/rules/*.mdc", "red", "Cursor AI rules directory"),
    (".cursor/mcp.json", "red", "Cursor MCP config (CurXecute RCE)"),
    (".clinerules/*.md", "red", "Cline auto-execution rules (Clinejection)"),
    (".clinerules/*.txt", "red", "Cline command payload file"),
    (".windsurfrules", "red", "Windsurf AI injection vector"),
    (".windsurf/rules/*", "red", "Windsurf workspace rules"),
    (".codex/config.toml", "red", "Codex CLI config (CVE-2025-61260 RCE)"),
    (".kiro/settings/mcp.json", "red", "Kiro MCP config (CVE-2026-0830 RCE)"),
    (".kiro/steering/*.md", "red", "Kiro custom agent instructions"),
    (".vscode/settings.json", "red", "VS Code settings (IDEsaster YOLO mode)"),
    ("*.code-workspace", "red", "VS Code workspace (IDEsaster override)"),
    ("mcp.json", "red", "MCP server configuration"),
    (".mcp.json", "red", "MCP server configuration"),
    (".mcp/config.json", "red", "MCP server configuration"),
    # --- High: AI editor instruction files ---
    ("GEMINI.md", "yellow", "Gemini CLI instructions"),
    (".gemini/settings.json", "yellow", "Gemini CLI configuration"),
    ("CLAUDE.md", "yellow", "Claude Code instructions"),
    ("AGENTS.md", "yellow", "OpenAI Codex agent instructions"),
    ("AGENT.md", "yellow", "Roo Code agent instructions"),
    ("SKILL.md", "yellow", "AI skill definitions (ToxicSkills)"),
    (".github/copilot-instructions.md", "yellow", "GitHub Copilot instructions"),
    (".github/instructions/*.instructions.md", "yellow", "Copilot scoped instructions"),
    ("CONVENTIONS.md", "yellow", "AI coding conventions (Aider)"),
    (".amazonq/rules/*.md", "yellow", "Amazon Q Developer rules"),
    (".augment/rules/*", "yellow", "Augment Code rules"),
    (".roo/rules/*.md", "yellow", "Roo Code rules"),
    (".roomodes", "yellow", "Roo Code project modes"),
    (".tabnine/guidelines/*.md", "yellow", "Tabnine guidelines"),
    (".continue/config.yaml", "yellow", "Continue.dev configuration"),
    (".cody.yml", "yellow", "Sourcegraph Cody configuration"),
    (".security.md", "yellow", "Security policy file"),
]


def _detect_priority_files(repo_dir: Path) -> list[tuple[Path, str, str]]:
    """
    Scan a cloned repository for high-risk AI coding editor files.

    Returns:
        List of (path, severity_color, description) for each found file.
    """
    import glob as _glob

    found: list[tuple[Path, str, str]] = []
    for pattern, color, desc in _PRIORITY_FILES:
        # Use glob to handle wildcard patterns
        matches = list(repo_dir.glob(pattern))
        for match in matches:
            if match.exists():
                rel = match.relative_to(repo_dir)
                found.append((rel, color, desc))
    return found


def _scan_git_repo(
    git_url: str,
    workers: Optional[int],
    quick: bool,
    force: bool,
    no_cache: bool,
    fail_on: Optional[str],
    output: Optional[str],
    output_formats: tuple[str, ...],
    no_report: bool,
    exclude: tuple[str, ...],
) -> None:
    """
    Clone a remote git repository and run the MEDUSA scan pipeline on it.

    This handles URL validation, shallow cloning, priority file detection,
    and cleanup of the temporary directory.
    """
    clone_url = _resolve_git_url(git_url)
    # Strip auth tokens from URL before any console output (https://token@host → https://host)
    _display_url = re.sub(r'https?://[^@\s]+@', 'https://', clone_url)

    print_banner()
    console.print(f"\n[cyan]Cloning repository...[/cyan]")
    console.print(f"[dim]  {_display_url}[/dim]\n")

    tmp_dir = tempfile.mkdtemp(prefix="medusa-git-")
    import atexit as _atexit
    _atexit.register(shutil.rmtree, tmp_dir, True)
    try:
        # Shallow clone for speed
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", clone_url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Strip auth tokens from error output (https://token@host → https://host)
            stderr = re.sub(r'https?://[^@\s]+@', 'https://', stderr)
            console.print(f"[red]Error: git clone failed[/red]")
            if stderr:
                console.print(f"[red]  {stderr}[/red]")
            raise SystemExit(1)

        console.print(f"[dark_green]Repository cloned to temporary directory[/dark_green]\n")

        # Priority file detection
        repo_path = Path(tmp_dir)
        priority_hits = _detect_priority_files(repo_path)

        if priority_hits:
            console.print("[bold yellow]HIGH-RISK FILES DETECTED:[/bold yellow]")
            for rel_path, color, desc in priority_hits:
                marker = "!!" if color == "red" else " >"
                console.print(f"  [{color}]{marker} {rel_path}[/{color}] [dim]-- {desc}[/dim]")
            console.print()
        else:
            console.print("[dim]No high-risk AI editor files detected.[/dim]\n")

        # Run the normal scan pipeline on the cloned repo
        # Import here to match the pattern used in the scan() function
        from medusa.core.pattern_analyzer import CodePatternAnalyzer

        console.print(f"[cyan]Target:[/cyan] {_display_url}")
        console.print(f"[cyan]Mode:[/cyan] {'Quick' if quick else 'Force' if force else 'Full'}")
        if exclude:
            console.print(f"[cyan]Excluding:[/cyan] {', '.join(exclude)}")

        console.print("\n[dim]Analyzing repository...[/dim]")
        analyzer = CodePatternAnalyzer()
        repo_analysis = analyzer.analyze_repo(repo_path)

        # Display analysis summary
        if repo_analysis.languages:
            top_langs = sorted(repo_analysis.languages.items(), key=lambda x: -x[1])[:5]
            lang_summary = ", ".join(f"{lang} ({count})" for lang, count in top_langs)
            console.print(f"[cyan]Languages:[/cyan] {lang_summary}")

        if repo_analysis.frameworks:
            fw_list = sorted(repo_analysis.frameworks)[:8]
            fw_summary = ", ".join(fw_list)
            if len(repo_analysis.frameworks) > 8:
                fw_summary += f" (+{len(repo_analysis.frameworks) - 8} more)"
            console.print(f"[cyan]Frameworks:[/cyan] {fw_summary}")

        if repo_analysis.security_context.has_ai_patterns:
            ai_patterns = []
            if repo_analysis.security_context.has_mcp_config:
                ai_patterns.append("MCP")
            if repo_analysis.security_context.has_rag_patterns:
                ai_patterns.append("RAG")
            if repo_analysis.security_context.has_agent_patterns:
                ai_patterns.append("Agents")
            if ai_patterns:
                console.print(f"[magenta]AI Patterns:[/magenta] {', '.join(ai_patterns)} detected - AI security scanners enabled")

        # Show ready scanners
        from medusa.scanners import registry as _scan_reg
        all_scanners = _scan_reg.get_all_scanners()
        recommended_names = repo_analysis.recommended_scanners
        ready_scanners = [s for s in all_scanners if s.name in recommended_names and s.is_available()]

        console.print()
        console.print(f"[dark_green]Ready to scan:[/dark_green] {len(ready_scanners)} scanners")
        if repo_analysis.skip_scanners:
            console.print(f"[dim]  {len(repo_analysis.skip_scanners)} scanners skipped (no {_summarize_skip_languages(repo_analysis)} files found)[/dim]")

        console.print()

        # Auto-detect workers
        from medusa.core.system import check_system_load, get_optimal_workers

        if workers is None:
            workers = get_optimal_workers()

        load = check_system_load()
        if load.warning_message:
            console.print(f"[yellow]{load.warning_message}[/yellow]")
            console.print(f"[dim]Using {workers} workers (reduced due to system load)[/dim]")

        # Capture missing linters for post-scan recommendation
        try:
            from medusa.scanners import registry as _sr
            ai_tool_names = {'modelscan', 'garak', 'llm-guard'}
            missing_linters = [
                s.get_tool_name() for s in _sr.get_unavailable_external_scanners()
                if s.get_tool_name() not in ai_tool_names
                and s.name in recommended_names
            ]
        except Exception:
            missing_linters = []

        # Run parallel scanner
        from medusa.core.parallel import MedusaParallelScanner

        scanner = MedusaParallelScanner(
            project_root=repo_path,
            workers=workers,
            use_cache=not no_cache and not force,
            quick_mode=quick,
            extra_excludes=list(exclude) if exclude else None,
        )

        files = scanner.find_scannable_files()
        if not files:
            console.print("[yellow]No files found to scan[/yellow]")
            return

        console.print(f"[dark_green]Found {len(files)} scannable files[/dark_green]\n")

        results = scanner.scan_parallel(files)

        # Generate reports
        if not no_report:
            output_dir = Path(output) if output else Path.cwd() / ".medusa" / "reports"
            output_dir.mkdir(parents=True, exist_ok=True)

            formats = list(output_formats)
            if 'all' in formats:
                formats = ['json', 'html', 'markdown']

            scanner.generate_report(results, output_dir, formats=formats, missing_linters=missing_linters)

        # Check fail threshold — only count issues at or above the specified severity
        if fail_on:
            from medusa.scanners import Severity
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            threshold = Severity(fail_on.upper())
            threshold_index = severity_order.index(threshold)
            allowed_severities = {s for s in severity_order[:threshold_index + 1]}
            total_issues = sum(
                1 for r in results if not r.cached
                for issue in r.issues
                if issue.severity in allowed_severities
            )
            if total_issues > 0:
                console.print(f"\n[red]Found {total_issues} issues at {fail_on.upper()}+ severity[/red]")
                sys.exit(1)

        console.print("\n[dark_green]Scan complete![/dark_green]")

        if missing_linters:
            console.print(f"\n[yellow]For fuller coverage, install missing linters and re-scan:[/yellow]")
            console.print(f"  [dim]{', '.join(missing_linters[:5])}{'...' if len(missing_linters) > 5 else ''}[/dim]")
            console.print(f"  [dim]Run 'medusa install --check' for details[/dim]")

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if '--debug' in sys.argv:
            raise
        sys.exit(1)
    finally:
        # Always clean up the temporary directory
        shutil.rmtree(tmp_dir, ignore_errors=True)
        console.print(f"\n[dim]Cleaned up temporary clone directory.[/dim]")


def _analyze_project(project_root: Path, console: Console) -> dict:
    """
    Analyze project structure, detect languages/frameworks, and build file hashes.

    Args:
        project_root: Root directory of the project
        console: Rich console for output

    Returns:
        Dict with keys: analysis, file_hashes, detected_files
    """
    from medusa.core.pattern_analyzer import CodePatternAnalyzer
    from medusa.scanners import registry
    import json
    import hashlib
    from datetime import datetime

    analyzer = CodePatternAnalyzer()
    analysis = analyzer.analyze_repo(project_root)

    # Display summary
    if analysis.languages:
        top_languages = sorted(analysis.languages.items(), key=lambda x: -x[1])[:6]
        console.print(f"[dark_green]✓[/dark_green] Languages detected:")
        for lang, count in top_languages:
            console.print(f"  • {lang.title():20} ({count} files)")

        if analysis.frameworks:
            frameworks_display = sorted(list(analysis.frameworks))[:8]
            console.print(f"[dark_green]✓[/dark_green] Frameworks: {', '.join(f.replace('_', ' ').title() for f in frameworks_display)}")

        if analysis.security_context.has_ai_patterns:
            ai_patterns = sorted(list(analysis.security_context.ai_frameworks))[:5]
            console.print(f"[dark_green]✓[/dark_green] AI Patterns: {', '.join(f.replace('_', ' ').title() for f in ai_patterns)}")

        console.print(f"[dark_green]✓[/dark_green] Recommended scanners: {len(analysis.recommended_scanners)}")
        if analysis.skip_scanners:
            console.print(f"[dim]   {len(analysis.skip_scanners)} scanners skipped (no {_summarize_skip_languages(analysis)} files found)[/dim]")
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
    console.print(f"[dark_green]✓[/dark_green] Saved analysis to .medusa/analysis.json ({len(file_hashes)} files indexed)")

    # For backwards compatibility, also build detected_files dict
    detected_files = {}
    for scanner in registry.get_all_scanners():
        if scanner.name in analysis.recommended_scanners:
            # Rough count based on extensions
            count = sum(1 for ext in scanner.get_file_extensions()
                       if ext and any(f.endswith(ext) for f in file_hashes.keys()))
            if count > 0:
                detected_files[scanner.name] = count

    return {
        'analysis': analysis,
        'file_hashes': file_hashes,
        'detected_files': detected_files,
    }


def _check_scanner_availability(analysis, do_install: bool, console: Console) -> list:
    """
    Check scanner availability for recommended scanners and optionally trigger install.

    Args:
        analysis: CodePatternAnalyzer result object
        do_install: Whether to auto-install without prompting (--install flag)
        console: Rich console for output

    Returns:
        List of missing tool names
    """
    from medusa.scanners import registry

    # Get only recommended scanners from CodePatternAnalyzer
    needed_scanners = [s for s in registry.get_all_scanners() if s.name in analysis.recommended_scanners]
    available_scanners = [s for s in needed_scanners if s.is_available()]
    missing_scanners = [s for s in needed_scanners if not s.is_available()]
    missing_tools = [s.tool_name for s in missing_scanners if s.tool_name]  # Filter None (built-in)

    console.print(f"[dark_green]✓[/dark_green] {len(available_scanners)}/{len(needed_scanners)} scanners available for your project")
    if missing_tools:
        console.print(f"[yellow]⚠️[/yellow]  {len(missing_tools)} tools missing for your project: {', '.join(missing_tools[:5])}" +
                     (f" and {len(missing_tools) - 5} more" if len(missing_tools) > 5 else ""))

        # Separate AI tools (auto-installable) from external linters (manual)
        ai_tool_names = {'modelscan', 'garak', 'llm-guard', 'llm_guard'}
        missing_ai_tools = [t for t in missing_tools if t in ai_tool_names]
        missing_linters = [t for t in missing_tools if t not in ai_tool_names]

        if missing_linters:
            console.print(f"\n[dim]External linters ({', '.join(missing_linters[:5])}"
                          + (f" and {len(missing_linters) - 5} more" if len(missing_linters) > 5 else "")
                          + ") — install via your package manager (pip, npm, apt, brew)[/dim]")

        if missing_ai_tools:
            if do_install or click.confirm(f"\nInstall {len(missing_ai_tools)} AI security tool(s) ({', '.join(missing_ai_tools)})?", default=False):
                console.print("[cyan]Installing AI security tools...[/cyan]")
                cmd = [sys.executable, '-m', 'medusa', 'install', '--ai-tools']
                result = subprocess.run(cmd, capture_output=False, text=True, check=False)
                if result.returncode != 0:
                    console.print("[yellow]⚠️  Some tools may not have installed successfully[/yellow]")
                    console.print("[dim]You can retry with: medusa install --ai-tools[/dim]")
                console.print()  # Extra newline for spacing

    return missing_tools


def _create_init_config(project_root: Path, ide, console: Console) -> tuple:
    """
    Create MEDUSA configuration with IDE detection and user prompts.

    Args:
        project_root: Root directory of the project
        ide: IDE tuple from Click option (may be None or empty)
        console: Rich console for output

    Returns:
        Tuple of (config_path, ide_list)
    """
    from medusa.config import ConfigManager, MedusaConfig

    config = MedusaConfig()

    # Convert ide tuple to list
    ide_list = list(ide) if ide else []

    # Handle 'all' option
    _ALL_IDE_NAMES = ['claude-code', 'cursor', 'gemini-cli', 'openai-codex', 'github-copilot']
    if 'all' in ide_list:
        ide_list = list(_ALL_IDE_NAMES)

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
            console.print(f"\n[dark_green]Detected IDE(s):[/dark_green] {', '.join(detected_ides)}")
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
                    ide_list = list(_ALL_IDE_NAMES)
                    break
                elif num == 7:  # None
                    if len(choice_nums) == 1:
                        ide_list = ['none']
                    # Skip 'none' if other options selected
                elif num in ide_map:
                    ide_list.append(ide_map[num])

    # Configure IDE settings in config
    _IDE_CONFIG_ATTRS = {
        'claude-code': 'ide_claude_code_enabled',
        'cursor': 'ide_cursor_enabled',
        'gemini-cli': 'ide_gemini_enabled',
        'openai-codex': 'ide_openai_enabled',
        'github-copilot': 'ide_copilot_enabled',
    }
    for selected_ide in ide_list:
        attr = _IDE_CONFIG_ATTRS.get(selected_ide)
        if attr:
            setattr(config, attr, True)

    # Determine config path (visible or legacy hidden)
    config_path = project_root / "medusa.yml"
    legacy_path = project_root / ".medusa.yml"
    if legacy_path.exists() and not config_path.exists():
        config_path = legacy_path

    # Save configuration
    ConfigManager.save_config(config, config_path)
    console.print(f"[dark_green]✓[/dark_green] Created {config_path}")

    return config_path, ide_list


def _setup_ide_integrations(project_root: Path, ide_list: list, console: Console) -> tuple:
    """
    Setup IDE integrations using a data-driven dispatch loop.

    Args:
        project_root: Root directory of the project
        ide_list: List of IDE identifiers to configure
        console: Rich console for output

    Returns:
        Tuple of (success_count, all_backed_up_files)
    """
    from medusa.ide.claude_code import (
        setup_claude_code,
        setup_cursor,
        setup_gemini_cli,
        setup_openai_codex,
        setup_github_copilot
    )
    from medusa.ide.backup import IDEBackupManager

    # Data-driven IDE setup dispatch table
    # Maps IDE key -> (setup_function, display_label, success_messages)
    IDE_SETUP = {
        'claude-code': (
            setup_claude_code,
            "Claude Code",
            [
                "Created .claude/ directory with agents and commands",
            ],
        ),
        'cursor': (
            setup_cursor,
            "Cursor",
            [
                "Created .cursor/mcp.json for MCP support",
                "Reused .claude/ structure (Cursor is VS Code fork)",
            ],
        ),
        'gemini-cli': (
            setup_gemini_cli,
            "Gemini CLI",
            [
                "Created .gemini/commands/ with .toml files",
                "Created GEMINI.md project context",
            ],
        ),
        'openai-codex': (
            setup_openai_codex,
            "OpenAI Codex",
            [
                "Created AGENTS.md project context",
            ],
        ),
        'github-copilot': (
            setup_github_copilot,
            "GitHub Copilot",
            [
                "Created .github/copilot-instructions.md",
            ],
        ),
    }

    # Create backup manager for all IDE file modifications
    backup_manager = IDEBackupManager(project_root)
    backup_manager.start_backup_session()
    all_backed_up_files = []

    success_count = 0
    for selected_ide in ide_list:
        setup_entry = IDE_SETUP.get(selected_ide)
        if not setup_entry:
            continue

        setup_func, label, messages = setup_entry
        result = setup_func(project_root, backup_manager)
        success = result[0]
        backed_up = result[-1] if len(result) > 1 and isinstance(result[-1], list) else []
        all_backed_up_files.extend(backed_up)

        if success:
            console.print(f"[dark_green]✓[/dark_green] {label} integration configured")

            # Claude Code has special handling for CLAUDE.md created vs preserved
            if selected_ide == 'claude-code':
                console.print("  • Created .claude/ directory with agents and commands")
                claude_md_created = result[1] if len(result) > 1 else True
                if claude_md_created:
                    console.print("  • Created CLAUDE.md project context")
                else:
                    console.print("  • Preserved existing CLAUDE.md (not overwritten)")
            else:
                for msg in messages:
                    console.print(f"  • {msg}")

            success_count += 1

    console.print(f"\n[dark_green]✓[/dark_green] Configured {success_count}/{len(ide_list)} IDE integration(s)")

    # Show backup information if files were backed up
    if all_backed_up_files:
        backup_path = backup_manager.get_backup_path()
        console.print(f"\n[yellow]📁 Backed up {len(all_backed_up_files)} existing file(s) to:[/yellow]")
        console.print(f"   [dim]{backup_path}[/dim]")
        console.print(f"   [dim]Use 'medusa backup --list' to view backups[/dim]")
        console.print(f"   [dim]Use 'medusa backup --restore' to rollback changes[/dim]")

    return success_count, all_backed_up_files


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

    project_root = Path.cwd()
    config_path = project_root / "medusa.yml"

    # Check if config already exists (visible or legacy hidden)
    legacy_path = project_root / ".medusa.yml"
    if legacy_path.exists() and not config_path.exists():
        config_path = legacy_path
    if config_path.exists() and not force:
        console.print(f"[yellow]⚠️  Configuration already exists: {config_path}[/yellow]")
        if not click.confirm("Overwrite existing configuration?", default=False):
            console.print("[dim]Cancelled. Use --force to overwrite.[/dim]")
            return

    # Step 1: Analyze project
    console.print("[bold cyan]Step 1/4: Analyzing project structure...[/bold cyan]")
    project_data = _analyze_project(project_root, console)
    analysis = project_data['analysis']

    # Step 2: Check scanner availability
    console.print("\n[bold cyan]Step 2/4: Checking scanner availability...[/bold cyan]")
    missing_tools = _check_scanner_availability(analysis, install, console)

    # Step 3: Create configuration
    console.print("\n[bold cyan]Step 3/4: Creating configuration...[/bold cyan]")
    config_path, ide_list = _create_init_config(project_root, ide, console)

    # Step 4: Setup IDE integration
    if ide_list and ide_list != ['none']:
        console.print(f"\n[bold cyan]Step 4/4: Setting up IDE integration(s)...[/bold cyan]")
        _setup_ide_integrations(project_root, ide_list, console)
    else:
        console.print("\n[bold cyan]Step 4/4: Skipping IDE integration[/bold cyan]")

    # Summary
    console.print("\n[bold dark_green]✅ MEDUSA Initialized Successfully![/bold dark_green]")
    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Review configuration: [cyan]{config_path.name}[/cyan]")
    if missing_tools:
        console.print(f"  2. Install AI security tools: [cyan]medusa install --ai-tools[/cyan]")
    step = 3 if missing_tools else 2
    console.print(f"  {step}. Run your first scan: [cyan]medusa scan .[/cyan]")
    console.print(f"  {step + 1}. Exclude directories: [cyan]medusa scan . -e archive/ -e vendor/[/cyan]")
    console.print(f"\n[dim]  Tip: Add permanent exclusions in {config_path.name} under 'exclude > paths'[/dim]")
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

            marker = "[dark_green]← latest[/dark_green]" if i == 0 else ""
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
                console.print(f"\n[dark_green]✓ Restored {len(restored)} file(s)[/dark_green]")

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
            console.print(f"[dark_green]✓ Removed {removed} old backup(s)[/dark_green]")
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
@click.option('--check', is_flag=True, help='Show installed and optional tools')
@click.option('--ai-tools', is_flag=True, help='Install AI security tools (modelscan, garak, llm-guard)')
@click.option('--debug', is_flag=True, help='Show diagnostic info (PATH, tool detection)')
@click.option('--all', 'install_all', is_flag=True, hidden=True, help='[DEPRECATED] Use --ai-tools instead')
def install(check, ai_tools, debug, install_all):
    """
    Install AI security tools and check detected linters.

    MEDUSA v2026.5.1 works out of the box with 9,600+ built-in AI security
    rules. External linters are optional — auto-detected if present.

    We only install AI-specific tools: modelscan, garak, llm-guard.

    Examples:
        medusa install --check      # Show what's installed/detected
        medusa install --ai-tools   # Install AI security tools
        medusa install --debug      # Diagnose tool detection issues
    """
    from medusa.platform.installers.simple import (
        install_ai_tools,
        get_ai_tools_status,
        get_detected_tools,
        get_optional_tools,
    )

    print_banner()

    # Debug diagnostics
    if debug:
        _debug_install()
        return

    # Handle deprecated --all flag
    if install_all:
        console.print("\n[yellow]--all is deprecated in MEDUSA v2026.5.1[/yellow]")
        console.print("[dim]MEDUSA now focuses on AI security rules (9,600+ patterns).[/dim]")
        console.print("[dim]External linters are optional - install them yourself if needed.[/dim]")
        console.print("\n[cyan]Use instead:[/cyan]")
        console.print("  medusa install --ai-tools    # Install AI security tools")
        console.print("  medusa install --check       # See detected tools")
        console.print()
        return

    # Show status
    if check or (not ai_tools and not install_all):
        _show_install_check()
        return

    # Install AI tools
    if ai_tools:
        from medusa.platform.installers.simple import AI_TOOLS, is_tool_installed, get_pip_command, is_pip_available, _in_virtualenv
        import subprocess as _sp

        console.print("\n[cyan]Installing AI Security Tools...[/cyan]\n")

        if not is_pip_available():
            console.print("[red]Error: pip not found. Please install Python/pip first.[/red]")
            return

        pip_cmd = get_pip_command()
        installed_count = 0
        failed_count = 0

        for tool_name, tool_info in AI_TOOLS.items():
            if is_tool_installed(tool_name):
                console.print(f"  [cyan]✓ {tool_name}[/cyan] — already installed")
                installed_count += 1
                continue

            console.print(f"  [dim]Installing {tool_name}...[/dim] ", end="")

            cmd = pip_cmd + ['install', tool_info['pip']]
            if not _in_virtualenv():
                cmd.append('--user')

            try:
                result = _sp.run(cmd, capture_output=True, text=True, timeout=600)
                if result.returncode == 0:
                    console.print(f"[dark_green]✓ installed[/dark_green]")
                    installed_count += 1
                else:
                    err = result.stderr.strip().split('\n')[-1] if result.stderr else 'unknown error'
                    console.print(f"[red]✗ failed[/red]")
                    console.print(f"    [dim]{err[:120]}[/dim]")
                    failed_count += 1
            except _sp.TimeoutExpired:
                console.print(f"[red]✗ timed out[/red]")
                failed_count += 1
            except Exception as e:
                console.print(f"[red]✗ {e}[/red]")
                failed_count += 1

        console.print()
        if failed_count == 0:
            console.print(f"[dark_green]All {installed_count} AI tools ready![/dark_green]")
        else:
            console.print(f"[yellow]{installed_count} installed, {failed_count} failed[/yellow]")
            console.print(f"[dim]Try running: pip install modelscan garak llm-guard[/dim]")


def _debug_install():
    """Dump full diagnostic info for troubleshooting tool detection."""
    import os

    from medusa.platform.detector import get_platform_info
    from medusa.platform.installers.simple import EXTERNAL_TOOLS
    from medusa.scanners import registry as scanner_registry

    console.print("\n[bold cyan]MEDUSA Install Diagnostics[/bold cyan]\n")

    # 1. Platform info
    info = get_platform_info()
    console.print("[bold]Platform:[/bold]")
    console.print(f"  OS:          {info.os_type.value}")
    console.print(f"  sys.platform: {sys.platform}")
    console.print(f"  Python:      {sys.version.split()[0]}")
    console.print(f"  Executable:  {sys.executable}")
    console.print(f"  In venv:     {sys.prefix != sys.base_prefix}")
    if sys.prefix != sys.base_prefix:
        console.print(f"  Venv path:   {sys.prefix}")
    console.print()

    # 2. PATH
    console.print("[bold]PATH directories:[/bold]")
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    for i, d in enumerate(path_dirs[:20]):
        exists = os.path.isdir(d)
        style = "" if exists else " [dim](missing)[/dim]"
        console.print(f"  {i+1:2}. {d}{style}")
    if len(path_dirs) > 20:
        console.print(f"  ... +{len(path_dirs) - 20} more")
    console.print()

    # 3. Key tools - check each one
    console.print("[bold]Tool Detection (key linters):[/bold]")
    key_tools = ['bandit', 'shellcheck', 'gitleaks', 'trivy',
                 'eslint', 'semgrep', 'cppcheck', 'modelscan', 'garak', 'llm-guard']
    for tool in key_tools:
        path = shutil.which(tool)
        if path:
            console.print(f"  [dark_green]{tool:16}[/dark_green] {path}")
        else:
            url = EXTERNAL_TOOLS.get(tool, {}).get('url', '')
            console.print(f"  [red]{tool:16}[/red] NOT FOUND  [dim]{url}[/dim]")
    console.print()

    # 4. Scanner registry status
    console.print("[bold]Scanner Registry:[/bold]")
    all_scanners = scanner_registry.get_all_scanners()
    available = scanner_registry.get_available_scanners()
    unavailable = scanner_registry.get_unavailable_external_scanners()
    console.print(f"  Total registered: {len(all_scanners)}")
    console.print(f"  Available:        {len(available)}")
    console.print(f"  Unavailable (ext): {len(unavailable)}")
    console.print()

    if unavailable:
        console.print("[bold]Unavailable External Scanners:[/bold]")
        for s in sorted(unavailable, key=lambda x: x.name):
            tool = s.get_tool_name()
            which_result = shutil.which(tool) if tool else None
            console.print(f"  {s.name:28} tool={tool:16} which={which_result or 'None'}")
        console.print()

    # 5. Windows-specific checks
    if sys.platform == 'win32':
        console.print("[bold]Windows-Specific:[/bold]")
        console.print(f"  WT_SESSION:    {os.environ.get('WT_SESSION', 'not set')}")
        console.print(f"  TERM_PROGRAM:  {os.environ.get('TERM_PROGRAM', 'not set')}")
        console.print(f"  COMSPEC:       {os.environ.get('COMSPEC', 'not set')}")

        choco_bin = os.path.expandvars(r'%ChocolateyInstall%\bin')
        console.print(f"  ChocolateyInstall: {os.environ.get('ChocolateyInstall', 'not set')}")
        if os.path.isdir(choco_bin):
            console.print(f"  Choco bin dir: {choco_bin} (exists)")
            in_path = any(choco_bin.lower() in p.lower() for p in path_dirs)
            console.print(f"  Choco in PATH: {'yes' if in_path else 'NO - this is the problem!'}")
        console.print()

    console.print("[dim]Copy this output and share it for debugging.[/dim]")


def _show_install_check():
    """Show environment audit, AI tools status, and detected linters."""
    from medusa.platform.installers.simple import (
        get_ai_tools_status, get_detected_tools, EXTERNAL_TOOLS,
        audit_environment, get_install_hint,
    )

    console.print(f"\n[bold dark_green]MEDUSA v2026.5.1 - AI Security Scanner[/bold dark_green]")
    console.print(f"[dim]Works out of the box with 9,600+ built-in AI security rules[/dim]\n")

    # ── Environment Audit ──
    audit = audit_environment()
    py = audit['python']
    pm = audit['package_manager']
    os_info = audit['os']

    console.print("[bold cyan]Environment[/bold cyan]")
    distro = os_info.get('distro', os_info.get('system', 'Unknown'))
    console.print(f"  OS:      {distro} ({os_info.get('machine', '')})")

    if py['optimal']:
        console.print(f"  Python:  [dark_green]{py['version']}[/dark_green]")
    elif py['ok']:
        console.print(f"  Python:  [yellow]{py['version']}[/yellow] [dim](recommended: {py['recommended']})[/dim]")
    else:
        console.print(f"  Python:  [red]{py['version']}[/red] [bold red]UPGRADE NEEDED (>= {py['min_required']})[/bold red]")

    if pm['in_virtualenv']:
        console.print(f"  Pkg Mgr: [dark_green]pip (virtualenv)[/dark_green]")
    elif pm['pep668']:
        if pm['pipx']:
            console.print(f"  Pkg Mgr: [dark_green]pipx[/dark_green] [dim](PEP 668 system)[/dim]")
        else:
            console.print(f"  Pkg Mgr: [red]pipx NOT INSTALLED[/red] [dim](PEP 668 blocks pip)[/dim]")
    else:
        console.print(f"  Pkg Mgr: pip")
    console.print()

    # ── AI Tools ──
    console.print("[bold cyan]AI Security Tools[/bold cyan]")
    for tool_name, tool_info in audit['tools'].items():
        if tool_info['installed']:
            console.print(f"  [dark_green]+ {tool_name}[/dark_green]")
        elif tool_info['compatible']:
            hint = get_install_hint(tool_name)
            console.print(f"  [yellow]- {tool_name}[/yellow] [dim]$ {hint}[/dim]")
        else:
            console.print(f"  [red]x {tool_name}[/red] [dim]{tool_info['issue']}[/dim]")
    console.print(f"  [dim]Run 'medusa install --ai-tools' to install[/dim]")
    console.print()

    # ── Detected external linters ──
    detected = get_detected_tools()
    not_detected = [t for t in EXTERNAL_TOOLS if t not in detected]

    console.print(f"[bold cyan]External Linters[/bold cyan] [dim](auto-detected, user-installed)[/dim]")
    if detected:
        console.print(f"  [dark_green]Detected ({len(detected)}):[/dark_green] {', '.join(sorted(detected))}")
    else:
        console.print(f"  [dim]None detected[/dim]")

    if not_detected:
        console.print(f"  [dim]Not found ({len(not_detected)}):[/dim] {', '.join(sorted(not_detected)[:10])}")
        if len(not_detected) > 10:
            console.print(f"  [dim]  +{len(not_detected) - 10} more[/dim]")
    console.print()

    # ── Actions ──
    if audit['actions']:
        critical = [a for a in audit['actions'] if a['priority'] == 'critical']
        warnings = [a for a in audit['actions'] if a['priority'] == 'warning']
        if critical or warnings:
            console.print("[bold cyan]Recommended Actions[/bold cyan]")
            for action in critical:
                console.print(f"  [bold red]!! {action['message']}[/bold red]")
                console.print(f"     [dim]$ {action['fix']}[/dim]")
            for action in warnings:
                console.print(f"  [yellow]!  {action['message']}[/yellow]")
                console.print(f"     [dim]$ {action['fix']}[/dim]")
            console.print()

    console.print("[dim]External linters are optional. Install via your package manager.[/dim]")


@main.command()
@click.argument('tool', required=False)
@click.option('--all', 'all_tools', is_flag=True, help='[DEPRECATED] Uninstall all tools')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompts')
def uninstall(tool, all_tools, yes):
    """
    Uninstall AI security tools.

    MEDUSA v2026.5.1 only manages modelscan. Use your package manager
    for other tools.

    Example:
        medusa uninstall modelscan
    """
    print_banner()

    # Handle deprecated --all flag
    if all_tools:
        console.print("\n[yellow]--all is deprecated in MEDUSA v2026.5.1[/yellow]")
        console.print("[dim]MEDUSA now only manages modelscan.[/dim]")
        console.print("[dim]See: docs/OPTIONAL_TOOLS.md for external tool guidance[/dim]\n")
        return

    # No tool specified
    if not tool:
        console.print("\n[cyan]Usage: medusa uninstall modelscan[/cyan]")
        console.print("[dim]MEDUSA v2026.5.1 only manages modelscan installation.[/dim]\n")
        return

    # Non-modelscan tool
    if tool != 'modelscan':
        console.print(f"\n[yellow]MEDUSA v2026.5.1 doesn't manage '{tool}'[/yellow]")
        console.print("[dim]Use your package manager to uninstall it.[/dim]")
        console.print("[dim]See: docs/OPTIONAL_TOOLS.md for guidance[/dim]\n")
        return

    # Uninstall modelscan
    from medusa.platform.installers.simple import get_pip_command

    if not yes:
        if not click.confirm("Uninstall modelscan?"):
            return

    console.print("\n[cyan]Uninstalling modelscan...[/cyan]")

    cmd = get_pip_command() + ['uninstall', '-y', 'modelscan']
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        console.print("[dark_green]modelscan uninstalled[/dark_green]\n")
    else:
        console.print(f"[red]Failed to uninstall: {result.stderr}[/red]\n")


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
        console.print(f"\n[bold dark_green]✅ Installed Scanners:[/bold dark_green]")
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
def output():
    """Development helper: Check background process output"""
    # This is primarily for development/debugging
    console.print("[yellow]This command is for development use only[/yellow]")


@main.command()
def versions():
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
        status = "[dark_green]✓ Ready[/dark_green]" if is_avail else "[dim]✗ Tool missing[/dim]"
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
    saved in medusa.yml and remembered for future scans.

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
        config_path = Path.cwd() / "medusa.yml"
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
            console.print(f"[dark_green]✓[/dark_green] Removed override for [cyan]{file_path}[/cyan]")
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

    console.print(f"[dark_green]✓[/dark_green] Scanner override saved")
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
    console.print(f"\n[dark_green]✓ Found {len(dependencies)} dependencies[/dark_green]\n")

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
        console.print(f"[dark_green]✓ CycloneDX SBOM:[/dark_green] {output_path}")

    if output_format in ['spdx', 'both']:
        sbom_data = _generate_spdx(target_path, dependencies)
        if output and output_format == 'spdx':
            output_path = Path(output)
        else:
            output_path = output_dir / 'sbom-spdx.json'

        with open(output_path, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        console.print(f"[dark_green]✓ SPDX SBOM:[/dark_green] {output_path}")

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
                'version': __version__
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
            'creators': [f'Tool: MEDUSA-{__version__}'],
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
