#!/usr/bin/env python3
"""
MEDUSA Release Update Script

Combines version bumping with tool version updates.
Usage:
    python scripts/update_release.py patch        # 0.9.0.0 -> 0.9.1.0
    python scripts/update_release.py minor        # 0.9.0.0 -> 0.10.0.0
    python scripts/update_release.py major        # 0.9.0.0 -> 1.0.0.0
    python scripts/update_release.py --tools-only  # Just update tool versions
"""

import subprocess
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()


def run_command(cmd: list, description: str) -> bool:
    """Run a command and show status"""
    console.print(f"\n[cyan]→ {description}[/cyan]")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        console.print(f"[green]✓ {description} complete[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ {description} failed:[/red]")
        console.print(f"[red]{e.stderr}[/red]")
        return False


def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: python scripts/update_release.py [major|minor|patch|--tools-only][/red]")
        sys.exit(1)

    bump_type = sys.argv[1]
    tools_only = bump_type == '--tools-only'

    console.print(Panel.fit(
        "[bold cyan]MEDUSA Release Update[/bold cyan]\n\n"
        "This script will:\n"
        "1. Capture latest tool versions\n"
        "2. Bump MEDUSA version (if not --tools-only)\n"
        "3. Update all version references\n"
        "4. Show diff for review",
        border_style="cyan"
    ))

    # Step 1: Capture tool versions
    if not run_command(
        ['python3', 'scripts/capture_tool_versions.py'],
        "Capturing latest tool versions"
    ):
        sys.exit(1)

    # Step 2: Bump MEDUSA version (unless --tools-only)
    if not tools_only:
        if not run_command(
            ['python3', 'scripts/bump_version.py', bump_type],
            f"Bumping MEDUSA version ({bump_type})"
        ):
            sys.exit(1)

    # Step 3: Show what changed
    console.print("\n[bold cyan]Changes:[/bold cyan]")
    git_path = shutil.which('git') or 'git'
    subprocess.run([git_path, 'diff', 'tool-versions.lock'], check=False)

    if not tools_only:
        subprocess.run([git_path, 'diff', 'medusa/__init__.py'], check=False)
        subprocess.run([git_path, 'diff', 'pyproject.toml'], check=False)

    # Step 4: Summary
    console.print(Panel.fit(
        "[bold green]✓ Update Complete![/bold green]\n\n"
        "Next steps:\n"
        "1. Review changes above\n"
        "2. Run: git add tool-versions.lock medusa/__init__.py pyproject.toml\n"
        "3. Run: git commit -m 'release: Bump to vX.X.X with updated tool versions'\n"
        "4. Run: python -m build --wheel\n"
        "5. Run: twine upload dist/*",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
