#!/usr/bin/env python3
"""
MEDUSA Windows Installers
Package installers for Windows using winget and Chocolatey
"""

import subprocess
import shutil
from medusa.platform.installers.base import BaseInstaller, ToolMapper


class WingetInstaller(BaseInstaller):
    """Windows package installer using winget"""

    def __init__(self):
        super().__init__('winget')

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using winget (no admin rights needed for user scope)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            return False

        cmd = ['winget', 'install', '--id', package_name, '--accept-source-agreements', '--accept-package-agreements']

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via winget"""
        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            return False

        try:
            result = self.run_command(['winget', 'list', '--id', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using winget"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            return False

        cmd = ['winget', 'uninstall', '--id', package_name]

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            return f"# Package '{package}' not available via winget"
        return f"winget install --id {package_name}"


class ChocolateyInstaller(BaseInstaller):
    """Windows package installer using Chocolatey"""

    def __init__(self):
        super().__init__('choco')

    @staticmethod
    def is_chocolatey_installed() -> bool:
        """Check if Chocolatey is installed"""
        return shutil.which('choco') is not None

    @staticmethod
    def install_chocolatey() -> bool:
        """
        Install Chocolatey package manager
        Runs the official Chocolatey installation script
        """
        try:
            # Official Chocolatey install command
            install_script = (
                "Set-ExecutionPolicy Bypass -Scope Process -Force; "
                "[System.Net.ServicePointManager]::SecurityProtocol = "
                "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
                "iex ((New-Object System.Net.WebClient).DownloadString("
                "'https://community.chocolatey.org/install.ps1'))"
            )

            cmd = [
                'powershell',
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command',
                install_script
            ]

            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def install(self, package: str, sudo: bool = False) -> bool:
        """Install package using choco"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'choco')
        if not package_name:
            return False

        cmd = ['choco', 'install', package_name, '-y']

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via choco"""
        package_name = ToolMapper.get_package_name(package, 'choco')
        if not package_name:
            return False

        try:
            result = self.run_command(['choco', 'list', '--local-only', package_name], check=False)
            # Check if package appears in output
            return package_name.lower() in result.stdout.lower() if hasattr(result, 'stdout') else False
        except:
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using choco"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'choco')
        if not package_name:
            return False

        cmd = ['choco', 'uninstall', package_name, '-y']

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'choco')
        if not package_name:
            return f"# Package '{package}' not available via Chocolatey"
        return f"choco install {package_name} -y"
