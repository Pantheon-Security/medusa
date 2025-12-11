#!/usr/bin/env python3
"""
MEDUSA Dependency Checker & Auto-Updater

This script checks all dependencies for updates and can auto-update safe packages.
It reads from medusa/dependencies.json to know what's blocked and what's safe.

Usage:
    python scripts/check_dependencies.py          # Check for updates
    python scripts/check_dependencies.py --update # Auto-update safe packages
    python scripts/check_dependencies.py --json   # Output as JSON
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Rich for pretty output
try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def get_pypi_latest(package: str) -> Optional[str]:
    """Get latest version from PyPI"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "index", "versions", package],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            # Parse output like "package (1.2.3)"
            for line in result.stdout.split('\n'):
                if 'Available versions:' in line:
                    versions = line.split(':')[1].strip().split(',')
                    if versions:
                        return versions[0].strip()
        return None
    except Exception:
        return None


def get_pip_outdated() -> dict:
    """Get all outdated pip packages"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            return {p['name'].lower(): p for p in packages}
        return {}
    except Exception:
        return {}


def load_dependencies_manifest() -> dict:
    """Load the dependencies.json manifest"""
    manifest_path = Path(__file__).parent.parent / "medusa" / "dependencies.json"
    if manifest_path.exists():
        with open(manifest_path) as f:
            return json.load(f)
    return {}


def is_package_blocked(package: str, manifest: dict) -> Optional[dict]:
    """Check if a package is blocked from updating"""
    blocked = manifest.get('blocked', [])
    for b in blocked:
        if b['package'].lower() == package.lower():
            return b
    return None


def update_package(package: str) -> bool:
    """Update a single package"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", package],
            capture_output=True, text=True, timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def check_dependencies(do_update: bool = False, output_json: bool = False):
    """Main function to check and optionally update dependencies"""
    manifest = load_dependencies_manifest()
    outdated = get_pip_outdated()

    results = {
        "checked_at": datetime.now().isoformat(),
        "medusa_version": manifest.get('metadata', {}).get('medusa_version', 'unknown'),
        "updates_available": [],
        "blocked": [],
        "updated": [],
        "failed": []
    }

    # Check each outdated package
    for name, info in outdated.items():
        current = info['version']
        latest = info['latest_version']

        # Skip medusa-security itself
        if name == 'medusa-security':
            continue

        blocked = is_package_blocked(name, manifest)

        if blocked:
            results['blocked'].append({
                "package": name,
                "current": current,
                "latest": latest,
                "blocker": blocked.get('blocker', {}),
                "reason": blocked.get('notes', 'Blocked by dependency')
            })
        else:
            results['updates_available'].append({
                "package": name,
                "current": current,
                "latest": latest
            })

            if do_update:
                if update_package(name):
                    results['updated'].append({
                        "package": name,
                        "from": current,
                        "to": latest
                    })
                else:
                    results['failed'].append({
                        "package": name,
                        "from": current,
                        "to": latest
                    })

    # Output results
    if output_json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, do_update)

    return results


def print_results(results: dict, did_update: bool):
    """Print results in a nice format"""
    if RICH_AVAILABLE:
        console = Console()

        # Header
        console.print(f"\n[bold]MEDUSA Dependency Check[/bold]")
        console.print(f"Version: {results['medusa_version']}")
        console.print(f"Checked: {results['checked_at']}\n")

        # Blocked packages
        if results['blocked']:
            console.print("[bold red]⛔ Blocked Updates[/bold red]")
            table = Table()
            table.add_column("Package")
            table.add_column("Current")
            table.add_column("Latest")
            table.add_column("Blocker")
            table.add_column("Reason")

            for b in results['blocked']:
                blocker_info = b.get('blocker', {})
                blocker_pkg = blocker_info.get('package', 'Unknown')
                table.add_row(
                    b['package'],
                    b['current'],
                    b['latest'],
                    blocker_pkg,
                    b.get('reason', '')[:40]
                )
            console.print(table)
            console.print()

        # Available updates
        if results['updates_available'] and not did_update:
            console.print("[bold yellow]📦 Updates Available[/bold yellow]")
            table = Table()
            table.add_column("Package")
            table.add_column("Current")
            table.add_column("Latest")

            for u in results['updates_available']:
                table.add_row(u['package'], u['current'], u['latest'])
            console.print(table)
            console.print("\nRun with --update to apply safe updates\n")

        # Updated packages
        if results['updated']:
            console.print("[bold green]✅ Updated[/bold green]")
            for u in results['updated']:
                console.print(f"  {u['package']}: {u['from']} → {u['to']}")
            console.print()

        # Failed updates
        if results['failed']:
            console.print("[bold red]❌ Failed to Update[/bold red]")
            for f in results['failed']:
                console.print(f"  {f['package']}: {f['from']} → {f['to']}")
            console.print()

        # Summary
        total_available = len(results['updates_available'])
        total_blocked = len(results['blocked'])
        total_updated = len(results['updated'])

        if total_available == 0 and total_blocked == 0:
            console.print("[bold green]✅ All dependencies are up to date![/bold green]\n")
        else:
            console.print(f"[dim]Summary: {total_available} available, {total_blocked} blocked, {total_updated} updated[/dim]\n")

    else:
        # Plain text output
        print(f"\nMEDUSA Dependency Check")
        print(f"Version: {results['medusa_version']}")
        print(f"Checked: {results['checked_at']}\n")

        if results['blocked']:
            print("⛔ BLOCKED:")
            for b in results['blocked']:
                print(f"  {b['package']}: {b['current']} → {b['latest']} (blocked by {b.get('blocker', {}).get('package', '?')})")

        if results['updates_available'] and not did_update:
            print("\n📦 AVAILABLE UPDATES:")
            for u in results['updates_available']:
                print(f"  {u['package']}: {u['current']} → {u['latest']}")

        if results['updated']:
            print("\n✅ UPDATED:")
            for u in results['updated']:
                print(f"  {u['package']}: {u['from']} → {u['to']}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Check MEDUSA dependencies for updates")
    parser.add_argument('--update', action='store_true', help='Auto-update safe packages')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    args = parser.parse_args()

    check_dependencies(do_update=args.update, output_json=args.json)


if __name__ == '__main__':
    main()
