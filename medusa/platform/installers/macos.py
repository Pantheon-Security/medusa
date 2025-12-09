#!/usr/bin/env python3
"""
MEDUSA macOS Installer
Package installer for macOS using Homebrew
"""

import subprocess
from medusa.platform.installers.base import BaseInstaller, ToolMapper


class HomebrewInstaller(BaseInstaller):
    """macOS package installer using Homebrew"""

    # Tools that need special handling on macOS
    SPECIAL_INSTALLS = {
        'dart': {'tap': 'dart-lang/dart', 'package': 'dart'},
        'swiftlint': {'cask': True, 'package': 'swiftlint'},
        'codenarc': {'gradle': True, 'url': 'https://github.com/CodeNarc/CodeNarc'},
    }

    def __init__(self):
        super().__init__('brew')

    def _tap_if_needed(self, tap: str) -> bool:
        """Add a homebrew tap if not already present"""
        try:
            # Check if tap exists
            result = self.run_command(['brew', 'tap'], check=False)
            if tap in result.stdout:
                return True
            # Add tap
            result = self.run_command(['brew', 'tap', tap], check=False)
            return result.returncode == 0
        except:
            return False

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using brew (no sudo needed)"""
        if not self.pm_path:
            return False

        # Check for special install handling
        if package in self.SPECIAL_INSTALLS:
            special = self.SPECIAL_INSTALLS[package]

            # Handle taps (e.g., dart needs dart-lang/dart tap)
            if 'tap' in special:
                if not self._tap_if_needed(special['tap']):
                    return False

            # Handle cask installs (e.g., swiftlint on Apple Silicon)
            if special.get('cask'):
                try:
                    # First try regular install
                    result = self.run_command(['brew', 'install', special['package']], check=False)
                    if result.returncode == 0:
                        return True
                    # Fall back to cask
                    result = self.run_command(['brew', 'install', '--cask', special['package']], check=False)
                    return result.returncode == 0
                except:
                    return False

            # Use special package name if specified
            package_name = special.get('package', package)
        else:
            package_name = ToolMapper.get_package_name(package, 'brew')

        if not package_name:
            return False

        cmd = ['brew', 'install', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via brew"""
        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return False

        try:
            result = self.run_command(['brew', 'list', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using brew (no sudo needed)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return False

        cmd = ['brew', 'uninstall', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'brew')
        if not package_name:
            return f"# Package '{package}' not available via Homebrew"
        return f"brew install {package_name}"
