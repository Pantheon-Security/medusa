#!/usr/bin/env python3
"""
MEDUSA Version Manager

Manages pinned versions of external security tools from tool-versions.lock file.
"""

import toml
from pathlib import Path
from typing import Dict, Optional
from rich.console import Console

console = Console()


class VersionManager:
    """Manages pinned versions of external tools"""

    def __init__(self, lock_file: Optional[Path] = None):
        """
        Initialize version manager.

        Args:
            lock_file: Path to tool-versions.lock file (default: project root)
        """
        if lock_file is None:
            # Find lock file in package directory
            lock_file = Path(__file__).parent.parent / "tool-versions.lock"

        self.lock_file = lock_file
        self.versions = self._load_versions()

    def _load_versions(self) -> Dict:
        """Load pinned versions from lock file"""
        if not self.lock_file.exists():
            console.print(
                f"[yellow]Warning: tool-versions.lock not found at {self.lock_file}[/yellow]"
            )
            return {}

        try:
            with open(self.lock_file) as f:
                data = toml.load(f)
                return data.get('tools', {})
        except Exception as e:
            console.print(f"[red]Error loading tool-versions.lock: {e}[/red]")
            return {}

    def get_version(self, tool: str) -> Optional[str]:
        """
        Get pinned version for a tool.

        Args:
            tool: Tool name (e.g., 'bandit', 'eslint')

        Returns:
            Version string or None if not pinned
        """
        # Search across all tool categories
        for category in self.versions.values():
            if tool in category:
                return category[tool]

            # Also try with common variations
            # e.g., 'markdownlint-cli' might be stored as 'markdownlint-cli'
            for key in category:
                if tool.lower() == key.lower() or tool.replace('-', '_') == key.replace('-', '_'):
                    return category[key]

        return None

    def get_package_spec(self, tool: str, package_name: str, pm: str, use_latest: bool = False) -> str:
        """
        Get package specification with version.

        Args:
            tool: Tool name
            package_name: Package name for the package manager
            pm: Package manager ('pip', 'npm', 'cargo', etc.)
            use_latest: If True, return package without version (use latest)

        Returns:
            Package specification (e.g., 'bandit==1.7.5' or 'eslint@8.56.0')
        """
        if use_latest:
            return package_name

        # Try looking up by tool name first, then by package name
        version = self.get_version(tool)
        if not version and tool != package_name:
            version = self.get_version(package_name)

        if not version:
            # No version pinned, warn and use latest
            console.print(
                f"[yellow]⚠ No pinned version for '{tool}' or '{package_name}', using latest[/yellow]"
            )
            return package_name

        # Format version string based on package manager
        if pm == 'pip':
            return f"{package_name}=={version}"
        elif pm == 'npm':
            return f"{package_name}@{version}"
        elif pm == 'cargo':
            return f"{package_name}@{version}"
        elif pm == 'gem':
            return f"{package_name}:{version}"
        else:
            # Unknown package manager, just return package name
            return package_name

    def get_all_versions(self) -> Dict:
        """
        Get all pinned versions organized by category.

        Returns:
            Dictionary of {category: {tool: version}}
        """
        return self.versions

    def get_metadata(self) -> Dict:
        """
        Get metadata from lock file.

        Returns:
            Dictionary with lockfile_version, generated_at, medusa_version
        """
        if not self.lock_file.exists():
            return {}

        try:
            with open(self.lock_file) as f:
                data = toml.load(f)
                return data.get('metadata', {})
        except:
            return {}

    def is_locked(self) -> bool:
        """Check if tool versions are locked (lock file exists)"""
        return self.lock_file.exists() and bool(self.versions)
