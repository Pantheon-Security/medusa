#!/usr/bin/env python3
"""
Generate tool package mappings and version lock file from CSV manifest.

This script reads tools-manifest.csv and generates:
1. Python code for TOOL_PACKAGES dictionary in base.py
2. TOML version lock file (tool-versions.lock)

Usage:
    python3 scripts/generate_tool_manifest.py [--output-python] [--output-toml]
"""

import csv
import sys
from pathlib import Path
from datetime import datetime


def read_manifest(csv_path: Path) -> list:
    """Read the tools manifest CSV file"""
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        return list(reader)


def generate_python_dict(tools: list) -> str:
    """Generate Python dictionary code for TOOL_PACKAGES"""
    lines = []
    lines.append("    # Mapping of tool -> package name for different package managers")
    lines.append("    TOOL_PACKAGES = {")

    for tool in sorted(tools, key=lambda t: t['tool_name']):
        name = tool['tool_name']
        lines.append(f"        '{name}': {{")

        # Add package manager mappings
        package_managers = ['apt', 'yum', 'dnf', 'pacman', 'brew', 'winget',
                          'choco', 'npm', 'pip', 'manual']

        for pm in package_managers:
            pkg_name = tool.get(pm, '').strip()
            if pkg_name:
                lines.append(f"            '{pm}': '{pkg_name}',")

        lines.append("        },")

    lines.append("    }")
    return '\n'.join(lines)


def generate_toml_lock(tools: list, medusa_version: str = "0.11.7") -> str:
    """Generate TOML version lock file"""
    lines = []
    lines.append("# MEDUSA Tool Versions Lock File")
    lines.append(f"# Generated: {datetime.now().isoformat()}")
    lines.append(f"# MEDUSA Version: {medusa_version}")
    lines.append("#")
    lines.append("# This file pins specific versions of external security tools to ensure")
    lines.append("# reproducible scans across different environments and time periods.")
    lines.append("")
    lines.append("[metadata]")
    lines.append('lockfile_version = "1.0"')
    lines.append(f'generated_at = "{datetime.now().isoformat()}"')
    lines.append(f'medusa_version = "{medusa_version}"')
    lines.append("")

    # Group by category
    categories = {}
    for tool in tools:
        category = tool.get('category', 'misc')
        if category not in categories:
            categories[category] = []
        categories[category].append(tool)

    # Write each category
    for category in sorted(categories.keys()):
        lines.append(f"[tools.{category}]")
        for tool in sorted(categories[category], key=lambda t: t['tool_name']):
            name = tool['tool_name']
            version = tool.get('version', '').strip()
            if version:
                # Add comment for tools with special binary names
                if name != name.replace('-', '_'):
                    comment = f"  # {name}"
                else:
                    comment = ""
                lines.append(f'{name.replace("-", "_")} = "{version}"{comment}')
        lines.append("")

    return '\n'.join(lines)


def generate_python_tool_sets(tools: list) -> str:
    """Generate Python sets for PYTHON_TOOLS and NPM_TOOLS"""
    python_tools = {t['tool_name'] for t in tools if t.get('pip', '').strip()}
    npm_tools = {t['tool_name'] for t in tools if t.get('npm', '').strip()}

    lines = []
    lines.append("    # Python tools that can be installed via pip as fallback")
    lines.append(f"    PYTHON_TOOLS = {{{', '.join(repr(t) for t in sorted(python_tools))}}}")
    lines.append("")
    lines.append("    # npm tools that can be installed via npm as fallback")
    lines.append(f"    NPM_TOOLS = {{{', '.join(repr(t) for t in sorted(npm_tools))}}}")

    return '\n'.join(lines)


def main():
    """Main entry point"""
    # Path to CSV
    csv_path = Path(__file__).parent.parent / "tools-manifest.csv"

    if not csv_path.exists():
        print(f"Error: {csv_path} not found!")
        sys.exit(1)

    # Read manifest
    print(f"Reading {csv_path}...")
    tools = read_manifest(csv_path)
    print(f"Found {len(tools)} tools")

    # Generate Python code
    if '--output-python' in sys.argv or len(sys.argv) == 1:
        print("\n" + "="*80)
        print("PYTHON CODE FOR base.py (TOOL_PACKAGES)")
        print("="*80)
        print(generate_python_tool_sets(tools))
        print()
        print(generate_python_dict(tools))
        print()

    # Generate TOML
    if '--output-toml' in sys.argv or len(sys.argv) == 1:
        print("\n" + "="*80)
        print("TOML VERSION LOCK FILE (tool-versions.lock)")
        print("="*80)
        print(generate_toml_lock(tools))
        print()

    # Write to files if requested
    if '--write' in sys.argv:
        # Write TOML
        toml_path = Path(__file__).parent.parent / "medusa" / "tool-versions.lock"
        print(f"\nWriting TOML to {toml_path}...")
        with open(toml_path, 'w') as f:
            f.write(generate_toml_lock(tools))
        print("✓ TOML file updated")

        print("\n⚠️  Note: Python code (base.py) must be manually updated")
        print("    Copy the generated TOOL_PACKAGES code into:")
        print("    medusa/platform/installers/base.py")


if __name__ == '__main__':
    main()
