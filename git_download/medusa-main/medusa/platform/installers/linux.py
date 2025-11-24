#!/usr/bin/env python3
"""
MEDUSA Linux Installers
Package installers for various Linux distributions
"""

from typing import List
import shutil

from medusa.platform.installers.base import BaseInstaller, ToolMapper


class AptInstaller(BaseInstaller):
    """Debian/Ubuntu package installer using apt"""

    def __init__(self):
        super().__init__('apt')

    def install(self, package: str, sudo: bool = True) -> bool:
        """Install package using apt with pip fallback for Python tools"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'apt')

        # Try apt first if package mapping exists
        if package_name:
            cmd = []
            if sudo:
                cmd.append('sudo')
            cmd.extend(['apt', 'install', '-y', package_name])

            try:
                result = self.run_command(cmd, check=False)
                if result.returncode == 0:
                    return True
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                # Package manager command failed - try fallbacks
                pass

        # Fallback to pip for Python tools
        if ToolMapper.is_python_tool(package):
            try:
                pip_cmd = ['pip3', 'install', package]
                result = self.run_command(pip_cmd, check=False)
                return result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                # pip install failed - try npm fallback
                pass

        # Fallback to npm for npm tools
        if ToolMapper.is_npm_tool(package):
            if shutil.which('npm'):
                try:
                    npm_cmd = ['npm', 'install', '-g', package]
                    result = self.run_command(npm_cmd, check=False)
                    return result.returncode == 0
                except (subprocess.SubprocessError, FileNotFoundError, OSError):
                    # npm install failed
                    pass

        return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via dpkg"""
        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return False

        try:
            result = self.run_command(['dpkg', '-l', package_name], check=False)
            return result.returncode == 0 and 'ii' in result.stdout
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using apt"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['apt', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'apt')
        if not package_name:
            return f"# Package '{package}' not available via apt"
        prefix = "sudo " if sudo else ""
        return f"{prefix}apt install -y {package_name}"


class YumInstaller(BaseInstaller):
    """RHEL/CentOS package installer using yum"""

    def __init__(self):
        super().__init__('yum')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['yum', 'install', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        try:
            result = self.run_command(['rpm', '-q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using yum"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['yum', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'yum')
        if not package_name:
            return f"# Package '{package}' not available via yum"
        prefix = "sudo " if sudo else ""
        return f"{prefix}yum install -y {package_name}"


class DnfInstaller(BaseInstaller):
    """Fedora/RHEL 8+ package installer using dnf"""

    def __init__(self):
        super().__init__('dnf')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['dnf', 'install', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        try:
            result = self.run_command(['rpm', '-q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using dnf"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['dnf', 'remove', '-y', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'dnf')
        if not package_name:
            return f"# Package '{package}' not available via dnf"
        prefix = "sudo " if sudo else ""
        return f"{prefix}dnf install -y {package_name}"


class PacmanInstaller(BaseInstaller):
    """Arch Linux package installer using pacman"""

    def __init__(self):
        super().__init__('pacman')

    def install(self, package: str, sudo: bool = True) -> bool:
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['pacman', '-S', '--noconfirm', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        try:
            result = self.run_command(['pacman', '-Q', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall package using pacman"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return False

        cmd = []
        if sudo:
            cmd.append('sudo')
        cmd.extend(['pacman', '-R', '--noconfirm', package_name])

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = True) -> str:
        package_name = ToolMapper.get_package_name(package, 'pacman')
        if not package_name:
            return f"# Package '{package}' not available via pacman"
        prefix = "sudo " if sudo else ""
        return f"{prefix}pacman -S --noconfirm {package_name}"
