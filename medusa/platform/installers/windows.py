#!/usr/bin/env python3
"""
MEDUSA Windows Installers
Package installers for Windows using winget and Chocolatey
"""

import subprocess
import shutil
import os
import sys
from medusa.platform.installers.base import BaseInstaller, ToolMapper


def refresh_windows_path() -> bool:
    """
    Refresh PATH environment variable from Windows registry.
    This makes newly installed tools available in the current process.
    Returns True if successful, False otherwise.
    """
    if sys.platform != 'win32':
        return False

    try:
        import winreg

        # Get system PATH
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            ) as key:
                system_path = winreg.QueryValueEx(key, 'Path')[0]
        except:
            system_path = ''

        # Get user PATH
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment') as key:
                user_path = winreg.QueryValueEx(key, 'Path')[0]
        except:
            user_path = ''

        # Also add common winget install locations
        windows_apps = os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\WindowsApps')

        # Combine all paths, removing duplicates while preserving order
        paths = []
        for path_str in [user_path, system_path]:
            for path in path_str.split(';'):
                path = path.strip()
                if path and path not in paths:
                    paths.append(path)

        # Ensure WindowsApps is included
        if windows_apps not in paths:
            paths.insert(0, windows_apps)

        # Update current process PATH
        os.environ['PATH'] = ';'.join(paths)
        return True
    except Exception:
        return False


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
            result = self.run_command(cmd, check=False)  # Don't throw on non-zero
            output = result.stdout.lower() if hasattr(result, 'stdout') else ''

            # Success if:
            # - Exit code is 0, OR
            # - Package is already installed (exit code may be non-zero but this is still success)
            success = (
                result.returncode == 0 or
                'already installed' in output or
                'no available upgrade found' in output
            )

            # If install succeeded (or package already installed), refresh PATH
            # This makes the tool available in current session
            if success:
                refresh_windows_path()

            return success
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
            success = result.returncode == 0

            # If install succeeded, refresh PATH
            # This makes the tool available in current session
            if success:
                refresh_windows_path()

            return success
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
