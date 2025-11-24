#!/usr/bin/env python3
"""
MEDUSA macOS Installer
Package installer for macOS using Homebrew
"""

from medusa.platform.installers.base import BaseInstaller, ToolMapper


class HomebrewInstaller(BaseInstaller):
    """macOS package installer using Homebrew"""

    def __init__(self):
        super().__init__('brew')

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using brew (no sudo needed)"""
        if not self.pm_path:
            return False

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
