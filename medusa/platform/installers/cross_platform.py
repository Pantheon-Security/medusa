#!/usr/bin/env python3
"""
MEDUSA Cross-Platform Installers
Package installers that work on multiple platforms (npm, pip)
"""

from medusa.platform.installers.base import BaseInstaller, ToolMapper


class NpmInstaller(BaseInstaller):
    """Cross-platform npm installer"""

    def __init__(self):
        super().__init__('npm')

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using npm (global)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        cmd = ['npm', 'install', '-g', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if npm package is installed globally"""
        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        try:
            result = self.run_command(['npm', 'list', '-g', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return f"# Package '{package}' not available via npm"
        return f"npm install -g {package_name}"


class PipInstaller(BaseInstaller):
    """Cross-platform pip installer"""

    def __init__(self):
        super().__init__('pip')

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using pip"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        cmd = ['pip', 'install', package_name]
        if sudo:
            cmd = ['sudo'] + cmd

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if pip package is installed"""
        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        try:
            result = self.run_command(['pip', 'show', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return f"# Package '{package}' not available via pip"
        prefix = "sudo " if sudo else ""
        return f"{prefix}pip install {package_name}"
