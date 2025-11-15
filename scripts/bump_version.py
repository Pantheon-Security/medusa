#!/usr/bin/env python3
"""
MEDUSA Version Bump Script
Automatically updates version numbers across all project files
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

# Project root
PROJECT_ROOT = Path(__file__).parent.parent

# Files to update and their patterns
VERSION_FILES = {
    "medusa/__init__.py": [
        (r'__version__\s*=\s*"[^"]*"', '__version__ = "{version}"')
    ],
    "pyproject.toml": [
        (r'version\s*=\s*"[^"]*"', 'version = "{version}"')
    ],
    "Dockerfile": [
        (r'LABEL version="[^"]*"', 'LABEL version="{version}"')
    ],
    ".claude/claude.md": [
        (r'MEDUSA v[\d.]+', 'MEDUSA v{version}'),
        (r'version:\s*[\d.]+', 'version: {version}'),
        (r'Current Version\*\*:\s*[\d.]+', 'Current Version**: {version}'),
        (r'medusa_security-[\d.]+-py3', 'medusa_security-{version}-py3'),
    ],
}


def get_current_version() -> str:
    """Get current version from __init__.py"""
    init_file = PROJECT_ROOT / "medusa" / "__init__.py"
    content = init_file.read_text()
    match = re.search(r'__version__\s*=\s*"([^"]*)"', content)
    if match:
        return match.group(1)
    raise ValueError("Could not find current version in medusa/__init__.py")


def parse_version(version: str) -> Tuple[int, int, int, int]:
    """Parse version string into tuple (major, minor, patch, build)"""
    parts = version.split('.')
    if len(parts) != 4:
        raise ValueError(f"Version must be in format X.Y.Z.W, got: {version}")
    return tuple(int(p) for p in parts)


def bump_version(current: str, bump_type: str) -> str:
    """
    Bump version based on type

    Args:
        current: Current version (e.g., "0.8.0.0")
        bump_type: major, minor, patch, or build

    Returns:
        New version string
    """
    major, minor, patch, build = parse_version(current)

    if bump_type == "major":
        return f"{major + 1}.0.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}.0"
    elif bump_type == "build":
        return f"{major}.{minor}.{patch}.{build + 1}"
    else:
        raise ValueError(f"Invalid bump type: {bump_type}. Use: major, minor, patch, or build")


def update_file(file_path: Path, patterns: List[Tuple[str, str]], new_version: str, dry_run: bool = False) -> int:
    """
    Update version in a single file

    Returns:
        Number of replacements made
    """
    if not file_path.exists():
        print(f"  ⚠️  {file_path} does not exist, skipping")
        return 0

    content = file_path.read_text()
    original_content = content
    replacements = 0

    for pattern, replacement in patterns:
        replacement_str = replacement.format(version=new_version)
        new_content, count = re.subn(pattern, replacement_str, content)
        if count > 0:
            content = new_content
            replacements += count

    if replacements > 0:
        if not dry_run:
            file_path.write_text(content)
            print(f"  ✅ {file_path}: {replacements} replacement(s)")
        else:
            print(f"  🔍 {file_path}: would make {replacements} replacement(s)")
    else:
        print(f"  ⏭️  {file_path}: no changes")

    return replacements


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Bump MEDUSA version across all files")
    parser.add_argument("bump_type", nargs="?", choices=["major", "minor", "patch", "build"],
                        help="Type of version bump")
    parser.add_argument("--version", help="Set specific version (e.g., 1.0.0.0)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without changing it")
    parser.add_argument("--current", action="store_true", help="Show current version and exit")

    args = parser.parse_args()

    # Get current version
    try:
        current_version = get_current_version()
    except Exception as e:
        print(f"❌ Error reading current version: {e}")
        sys.exit(1)

    if args.current:
        print(f"Current version: {current_version}")
        return

    # Determine new version
    if args.version:
        new_version = args.version
        try:
            parse_version(new_version)  # Validate format
        except ValueError as e:
            print(f"❌ Invalid version format: {e}")
            sys.exit(1)
    elif args.bump_type:
        try:
            new_version = bump_version(current_version, args.bump_type)
        except ValueError as e:
            print(f"❌ Error bumping version: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    # Show version change
    print(f"\n{'🔍 DRY RUN - ' if args.dry_run else ''}Version bump: {current_version} → {new_version}\n")

    # Update all files
    total_replacements = 0
    for file_path_str, patterns in VERSION_FILES.items():
        file_path = PROJECT_ROOT / file_path_str
        replacements = update_file(file_path, patterns, new_version, args.dry_run)
        total_replacements += replacements

    # Summary
    print(f"\n{'Would update' if args.dry_run else 'Updated'} {total_replacements} version reference(s)")

    if not args.dry_run and total_replacements > 0:
        print(f"\n✅ Version bumped to {new_version}")
        print("\nNext steps:")
        print(f"  1. Review changes: git diff")
        print(f"  2. Rebuild wheel: python -m build")
        print(f"  3. Commit: git add -u && git commit -m 'Version bump: {current_version} → {new_version}'")
        print(f"  4. Tag: git tag v{new_version}")
        print(f"  5. Push: git push && git push --tags")


if __name__ == "__main__":
    main()
