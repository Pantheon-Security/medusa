#!/usr/bin/env python3
"""
MEDUSA Install Manifest Manager
Tracks tools installed by MEDUSA to prevent accidental uninstallation of user tools
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List


class InstallManifest:
    """Manages the MEDUSA install manifest"""

    def __init__(self, manifest_path: Optional[Path] = None):
        """Initialize manifest manager

        Args:
            manifest_path: Path to manifest file (defaults to ~/.medusa/installed_tools.json)
        """
        if manifest_path is None:
            # Use ~/.medusa/installed_tools.json by default
            home = Path.home()
            medusa_dir = home / '.medusa'
            medusa_dir.mkdir(parents=True, exist_ok=True)
            self.manifest_path = medusa_dir / 'installed_tools.json'
        else:
            self.manifest_path = manifest_path

        self.data = self._load()

    def _load(self) -> Dict:
        """Load manifest from disk"""
        default_data = {'tools': {}, 'version': '1.0'}

        if not self.manifest_path.exists():
            return default_data

        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
                # Ensure 'tools' key exists (handle old/malformed manifests)
                if 'tools' not in data:
                    data['tools'] = {}
                return data
        except (json.JSONDecodeError, IOError):
            # Corrupted manifest, start fresh
            return default_data

    def _save(self):
        """Save manifest to disk"""
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.manifest_path, 'w') as f:
            json.dump(self.data, f, indent=2)

    def mark_installed(self, tool_name: str, package_manager: str,
                      package_id: Optional[str] = None, version: Optional[str] = None,
                      already_existed: bool = False):
        """Mark a tool as installed

        Args:
            tool_name: Name of the tool (e.g., 'shellcheck')
            package_manager: Package manager used (e.g., 'winget', 'pip', 'npm')
            package_id: Package ID/name in the package manager
            version: Version installed
            already_existed: True if tool was already installed (MEDUSA didn't install it)
        """
        self.data['tools'][tool_name] = {
            'installed_by_medusa': not already_existed,
            'installed_at': datetime.utcnow().isoformat(),
            'package_manager': package_manager,
            'package_id': package_id or tool_name,
            'version': version,
        }

        if already_existed:
            self.data['tools'][tool_name]['note'] = 'Pre-existing installation'

        self._save()

    def mark_uninstalled(self, tool_name: str):
        """Remove a tool from the manifest

        Args:
            tool_name: Name of the tool
        """
        if tool_name in self.data['tools']:
            del self.data['tools'][tool_name]
            self._save()

    def was_installed_by_medusa(self, tool_name: str) -> bool:
        """Check if a tool was installed by MEDUSA

        Args:
            tool_name: Name of the tool

        Returns:
            True if MEDUSA installed it, False otherwise
        """
        tool_info = self.data['tools'].get(tool_name, {})
        return tool_info.get('installed_by_medusa', False)

    def get_medusa_installed_tools(self) -> List[str]:
        """Get list of tools installed by MEDUSA

        Returns:
            List of tool names
        """
        return [
            name for name, info in self.data['tools'].items()
            if info.get('installed_by_medusa', False)
        ]

    def get_all_tracked_tools(self) -> List[str]:
        """Get list of all tracked tools (including pre-existing)

        Returns:
            List of tool names
        """
        return list(self.data['tools'].keys())

    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get installation info for a tool

        Args:
            tool_name: Name of the tool

        Returns:
            Tool info dict or None if not found
        """
        return self.data['tools'].get(tool_name)

    def is_support_software(self, tool_name: str) -> bool:
        """Check if a tool is support software (runtime/compiler)

        Args:
            tool_name: Name of the tool

        Returns:
            True if it's support software that should not be uninstalled
        """
        # List of support software that should never be auto-uninstalled
        support_tools = {
            'python', 'python3', 'pip', 'pip3',
            'ruby', 'gem',
            'node', 'npm', 'npx',
            'go', 'cargo', 'rustc', 'rustup',
            'java', 'javac', 'maven', 'gradle',
            'dotnet', 'csc',
            'php', 'composer',
            'perl', 'cpan',
            'elixir', 'mix',
            'dart', 'pub',
            'swift', 'swiftc',
            'r', 'Rscript',
        }
        return tool_name.lower() in support_tools


# Global manifest instance
_manifest = None


def get_manifest() -> InstallManifest:
    """Get the global install manifest instance"""
    global _manifest
    if _manifest is None:
        _manifest = InstallManifest()
    return _manifest
