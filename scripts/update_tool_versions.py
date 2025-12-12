#!/usr/bin/env python3
"""
MEDUSA External Tool Version Updater

This script checks for updates to external security tools defined in tool-versions.lock
and can automatically update the lock file with new versions.

Supports:
- GitHub Releases (semgrep, trivy, gitleaks, etc.)
- npm Registry (eslint, prettier, etc.)
- PyPI (bandit, ruff, etc.)

Usage:
    python scripts/update_tool_versions.py              # Check for updates
    python scripts/update_tool_versions.py --update     # Apply updates to lock file
    python scripts/update_tool_versions.py --json       # Output as JSON
    python scripts/update_tool_versions.py --dry-run    # Show what would be updated
"""

import json
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional

# Rich for pretty output
try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Tool registry: maps tool names to their update sources
TOOL_REGISTRY = {
    # Python tools (PyPI)
    "python": {
        "source": "pypi",
        "tools": [
            "ansible-lint", "bandit", "black", "mccabe", "mypy", "prospector",
            "pydocstyle", "pyflakes", "pylint", "ruff", "safety", "sqlfluff",
            "vulture", "yamllint"
        ]
    },
    # AI Security tools (PyPI)
    "ai": {
        "source": "pypi",
        "tools": ["garak", "llm-guard", "modelscan"]
    },
    # JavaScript tools (npm)
    "javascript": {
        "source": "npm",
        "tools": [
            "eslint", "htmlhint", "jshint", "markdownlint-cli", "prettier",
            "standard", "stylelint", "typescript"
        ]
    },
    # Go tools (GitHub releases)
    "go": {
        "source": "github",
        "repos": {
            "golangci-lint": "golangci/golangci-lint",
            "staticcheck": "dominikh/go-tools"
        }
    },
    # Rust tools (special handling)
    "rust": {
        "source": "skip",  # clippy version tied to rustc
        "tools": ["clippy"]
    },
    # Shell tools (GitHub/system)
    "shell": {
        "source": "github",
        "repos": {
            "shellcheck": "koalaman/shellcheck",
            "bashate": None  # PyPI
        }
    },
    # Docker tools (GitHub)
    "docker": {
        "source": "github",
        "repos": {
            "hadolint": "hadolint/hadolint"
        }
    },
    # Terraform tools (GitHub + PyPI)
    "terraform": {
        "source": "github",
        "repos": {
            "tflint": "terraform-linters/tflint",
            "tfsec": "aquasecurity/tfsec",
            "checkov": None  # PyPI fallback
        }
    },
    # Kubernetes tools (GitHub)
    "kubernetes": {
        "source": "github",
        "repos": {
            "kube-linter": "stackrox/kube-linter",
            "kubeval": "instrumenta/kubeval"
        }
    },
    # Misc tools (GitHub)
    "misc": {
        "source": "github",
        "repos": {
            "gitleaks": "gitleaks/gitleaks",
            "semgrep": "semgrep/semgrep",
            "trivy": "aquasecurity/trivy"
        }
    }
}

# PyPI special package names (when PyPI name differs from tool name)
PYPI_PACKAGE_NAMES = {
    "llm-guard": "llm-guard",
    "ansible-lint": "ansible-lint",
    "markdownlint-cli": None,  # Not on PyPI (npm only)
    "garak": "garak",
    "modelscan": "modelscan",
    "bashate": "bashate",
    "checkov": "checkov",
}


def get_pypi_latest(package: str) -> Optional[str]:
    """Get latest version from PyPI JSON API"""
    # Map tool name to PyPI package name
    pypi_name = PYPI_PACKAGE_NAMES.get(package, package)
    if pypi_name is None:
        return None

    try:
        url = f"https://pypi.org/pypi/{pypi_name}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "MEDUSA-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("info", {}).get("version")
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return None


def get_npm_latest(package: str) -> Optional[str]:
    """Get latest version from npm registry"""
    try:
        url = f"https://registry.npmjs.org/{package}/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "MEDUSA-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("version")
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return None


def get_github_latest(repo: str) -> Optional[str]:
    """Get latest release version from GitHub API"""
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={
            "User-Agent": "MEDUSA-Updater/1.0",
            "Accept": "application/vnd.github.v3+json"
        })
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            tag = data.get("tag_name", "")
            # Strip common prefixes
            version = tag.lstrip("v").lstrip("V")
            return version if version else None
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return None


def parse_tool_versions_lock(lock_path: Path) -> dict:
    """Parse the tool-versions.lock TOML-like file"""
    if not lock_path.exists():
        return {}

    tools = {}
    current_section = None

    with open(lock_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Section headers
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
                if section.startswith('tools.'):
                    current_section = section.replace('tools.', '')
                else:
                    current_section = None
                continue

            # Key-value pairs in tool sections
            if current_section and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"')

                if current_section not in tools:
                    tools[current_section] = {}
                tools[current_section][key] = value

    return tools


def write_tool_versions_lock(lock_path: Path, tools: dict, medusa_version: str):
    """Write updated tool-versions.lock file"""
    timestamp = datetime.now().isoformat()

    lines = [
        "# MEDUSA Tool Versions Lock File",
        f"# Generated: {timestamp}",
        f"# MEDUSA Version: {medusa_version}",
        "#",
        "# This file pins specific versions of external security tools to ensure",
        "# reproducible scans across different environments and time periods.",
        "",
        "[metadata]",
        'lockfile_version = "1.0"',
        f'generated_at = "{timestamp}"',
        f'medusa_version = "{medusa_version}"',
        ""
    ]

    # Write each section
    section_order = ['python', 'javascript', 'go', 'rust', 'shell', 'docker', 'terraform', 'kubernetes', 'ai', 'misc']

    for section in section_order:
        if section in tools:
            lines.append(f"[tools.{section}]")
            for tool, version in sorted(tools[section].items()):
                lines.append(f'{tool} = "{version}"')
            lines.append("")

    with open(lock_path, 'w') as f:
        f.write('\n'.join(lines))


def get_latest_version(tool: str, category: str) -> Optional[str]:
    """Get the latest version for a tool based on its category"""
    registry = TOOL_REGISTRY.get(category, {})
    source = registry.get("source", "skip")

    if source == "skip":
        return None

    if source == "pypi":
        return get_pypi_latest(tool)

    if source == "npm":
        return get_npm_latest(tool)

    if source == "github":
        repos = registry.get("repos", {})
        repo = repos.get(tool)
        if repo:
            return get_github_latest(repo)
        # Fallback to PyPI for tools without GitHub repo specified
        return get_pypi_latest(tool)

    return None


def compare_versions(current: str, latest: str) -> int:
    """
    Compare two version strings.
    Returns: -1 if current < latest, 0 if equal, 1 if current > latest
    """
    def normalize(v: str) -> list:
        # Handle versions like "2025.1.1" or "1.2.3" or "0.0.302"
        parts = re.split(r'[.-]', v)
        result = []
        for p in parts:
            # Try to convert to int, keep as string if not numeric
            try:
                result.append((0, int(p)))
            except ValueError:
                result.append((1, p))
        return result

    try:
        curr_parts = normalize(current)
        latest_parts = normalize(latest)

        # Compare element by element
        for c, l in zip(curr_parts, latest_parts):
            if c < l:
                return -1
            if c > l:
                return 1

        # If all compared parts are equal, longer version is greater
        if len(curr_parts) < len(latest_parts):
            return -1
        if len(curr_parts) > len(latest_parts):
            return 1
        return 0
    except Exception:
        return 0  # Can't compare, assume equal


def check_tool_versions(do_update: bool = False, dry_run: bool = False, output_json: bool = False):
    """Main function to check and optionally update tool versions"""
    lock_path = Path(__file__).parent.parent / "medusa" / "tool-versions.lock"
    tools = parse_tool_versions_lock(lock_path)

    # Get MEDUSA version
    init_path = Path(__file__).parent.parent / "medusa" / "__init__.py"
    medusa_version = "unknown"
    if init_path.exists():
        with open(init_path) as f:
            for line in f:
                if line.startswith("__version__"):
                    medusa_version = line.split("=")[1].strip().strip('"\'')
                    break

    results = {
        "checked_at": datetime.now().isoformat(),
        "medusa_version": medusa_version,
        "updates_available": [],
        "up_to_date": [],
        "skipped": [],
        "errors": [],
        "updated": []
    }

    console = Console() if RICH_AVAILABLE else None

    if console and not output_json:
        console.print("\n[bold]MEDUSA External Tool Version Check[/bold]")
        console.print(f"Checking {sum(len(t) for t in tools.values())} tools...\n")

    # Check each tool
    for category, category_tools in tools.items():
        for tool, current_version in category_tools.items():
            # Skip known special cases
            if category == "rust":
                results["skipped"].append({
                    "tool": tool,
                    "category": category,
                    "current": current_version,
                    "reason": "Version tied to rustc"
                })
                continue

            # Get latest version
            latest = get_latest_version(tool, category)

            if latest is None:
                results["errors"].append({
                    "tool": tool,
                    "category": category,
                    "current": current_version,
                    "error": "Could not fetch latest version"
                })
                continue

            comparison = compare_versions(current_version, latest)

            if comparison < 0:
                # Update available
                results["updates_available"].append({
                    "tool": tool,
                    "category": category,
                    "current": current_version,
                    "latest": latest
                })

                if do_update and not dry_run:
                    tools[category][tool] = latest
                    results["updated"].append({
                        "tool": tool,
                        "category": category,
                        "from": current_version,
                        "to": latest
                    })
            else:
                results["up_to_date"].append({
                    "tool": tool,
                    "category": category,
                    "version": current_version
                })

    # Write updates if requested
    if do_update and not dry_run and results["updated"]:
        write_tool_versions_lock(lock_path, tools, medusa_version)

    # Output results
    if output_json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, do_update, dry_run)

    return results


def print_results(results: dict, did_update: bool, dry_run: bool):
    """Print results in a nice format"""
    if RICH_AVAILABLE:
        console = Console()

        # Header
        console.print(f"[bold]MEDUSA External Tool Version Check[/bold]")
        console.print(f"Version: {results['medusa_version']}")
        console.print(f"Checked: {results['checked_at']}\n")

        # Updates available
        if results['updates_available']:
            if dry_run:
                console.print("[bold yellow]📦 Updates Available (dry-run)[/bold yellow]")
            elif did_update:
                console.print("[bold green]✅ Updated Tools[/bold green]")
            else:
                console.print("[bold yellow]📦 Updates Available[/bold yellow]")

            table = Table()
            table.add_column("Tool")
            table.add_column("Category")
            table.add_column("Current")
            table.add_column("Latest")

            for u in results['updates_available']:
                table.add_row(u['tool'], u['category'], u['current'], u['latest'])
            console.print(table)

            if not did_update and not dry_run:
                console.print("\nRun with --update to apply updates")
                console.print("Run with --dry-run to preview changes\n")

        # Skipped tools
        if results['skipped']:
            console.print(f"\n[dim]Skipped {len(results['skipped'])} tools (special handling)[/dim]")

        # Errors
        if results['errors']:
            console.print(f"\n[yellow]⚠ Could not check {len(results['errors'])} tools[/yellow]")
            for e in results['errors']:
                console.print(f"  {e['tool']}: {e['error']}")

        # Summary
        total_updates = len(results['updates_available'])
        total_current = len(results['up_to_date'])
        total_updated = len(results['updated'])

        console.print()
        if total_updates == 0:
            console.print("[bold green]✅ All tools are up to date![/bold green]\n")
        else:
            status = f"{total_current} up-to-date, {total_updates} updates available"
            if total_updated:
                status += f", {total_updated} updated"
            console.print(f"[dim]Summary: {status}[/dim]\n")
    else:
        # Plain text output
        print(f"\nMEDUSA External Tool Version Check")
        print(f"Version: {results['medusa_version']}")
        print(f"Checked: {results['checked_at']}\n")

        if results['updates_available']:
            print("📦 UPDATES AVAILABLE:")
            for u in results['updates_available']:
                print(f"  {u['tool']} ({u['category']}): {u['current']} → {u['latest']}")

        if results['errors']:
            print("\n⚠ ERRORS:")
            for e in results['errors']:
                print(f"  {e['tool']}: {e['error']}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Check and update MEDUSA external tool versions")
    parser.add_argument('--update', action='store_true', help='Update tool-versions.lock with new versions')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be updated without making changes')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    check_tool_versions(do_update=args.update, dry_run=args.dry_run, output_json=args.json)


if __name__ == '__main__':
    main()
