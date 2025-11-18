#!/usr/bin/env python3
"""
MEDUSA Cross-Platform Installers
Package installers that work on multiple platforms (npm, pip)
"""

from medusa.platform.installers.base import BaseInstaller, ToolMapper
from medusa.platform.version_manager import VersionManager


class NpmInstaller(BaseInstaller):
    """Cross-platform npm installer"""

    def __init__(self):
        super().__init__('npm')
        self.version_mgr = VersionManager()

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        """Install package using npm (global)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        # Get versioned package spec
        package_spec = self.version_mgr.get_package_spec(package, package_name, 'npm', use_latest)

        cmd = ['npm', 'install', '-g', package_spec]

        try:
            result = self.run_command(cmd, check=False)
            if result.returncode == 0:
                return True

            # Print actual error for debugging
            if result.stderr:
                from rich.console import Console
                console = Console()
                console.print(f"[yellow]npm install error: {result.stderr.strip()[:200]}[/yellow]")
            return False
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"[yellow]npm install exception: {str(e)[:200]}[/yellow]")
            return False

    def is_installed(self, package: str) -> bool:
        """Check if npm package is installed globally"""
        import shutil

        # First, check if the tool binary is actually in PATH (most reliable)
        tool_binary = shutil.which(package)
        if tool_binary:
            return True

        # Fallback: check npm list output (npm list may return non-zero due to peer deps)
        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        try:
            result = self.run_command(['npm', 'list', '-g', package_name], check=False)
            # Check output text, not just return code
            if result.stdout:
                output = result.stdout.lower()
                return package_name.lower() in output or package.lower() in output
            return False
        except:
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using npm (global)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        cmd = ['npm', 'uninstall', '-g', package_name]

        try:
            result = self.run_command(cmd, check=True)
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
        self.version_mgr = VersionManager()

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        """Install package using pip"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        # Get versioned package spec
        package_spec = self.version_mgr.get_package_spec(package, package_name, 'pip', use_latest)

        cmd = ['pip', 'install', package_spec]
        if sudo:
            cmd = ['sudo'] + cmd

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def is_installed(self, package: str) -> bool:
        """Check if pip package is installed"""
        import shutil

        # First, check if the tool binary is actually in PATH (most reliable)
        tool_binary = shutil.which(package)
        if tool_binary:
            return True

        # Fallback: check pip show (reliable for Python packages)
        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        try:
            result = self.run_command(['pip', 'show', package_name], check=False)
            return result.returncode == 0
        except:
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using pip"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        cmd = ['pip', 'uninstall', '-y', package_name]
        if sudo:
            cmd = ['sudo'] + cmd

        try:
            result = self.run_command(cmd, check=True)
            return result.returncode == 0
        except:
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return f"# Package '{package}' not available via pip"
        prefix = "sudo " if sudo else ""
        return f"{prefix}pip install {package_name}"
