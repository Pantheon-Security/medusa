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
        # Windows: Use npm.cmd to bypass PowerShell execution policy issues
        import platform
        import shutil
        from pathlib import Path

        if platform.system() == 'Windows':
            # Try to find npm.cmd in PATH first
            npm_path = shutil.which('npm.cmd')

            # If not in PATH, check common install locations (handles PATH refresh issue)
            if not npm_path:
                common_paths = [
                    Path(r'C:\Program Files\nodejs\npm.cmd'),
                    Path(r'C:\Program Files (x86)\nodejs\npm.cmd'),
                ]
                for path in common_paths:
                    if path.exists():
                        npm_path = str(path)
                        break

            # Use full path if found, otherwise npm.cmd
            npm_cmd = npm_path if npm_path else 'npm.cmd'
        else:
            npm_cmd = 'npm'

        super().__init__(npm_cmd)
        self.version_mgr = VersionManager()

        # Store the actual command to use (full path or command name)
        self.npm_cmd = npm_cmd

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        """Install package using npm (global)"""
        if not self.pm_path:
            return False

        package_name = ToolMapper.get_package_name(package, 'npm')
        if not package_name:
            return False

        # Get versioned package spec
        package_spec = self.version_mgr.get_package_spec(package, package_name, 'npm', use_latest)

        cmd = [self.npm_cmd, 'install', '-g', package_spec]

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
            result = self.run_command([self.npm_cmd, 'list', '-g', package_name], check=False)
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

        cmd = [self.npm_cmd, 'uninstall', '-g', package_name]

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

        # Detect if we're on Windows and should use 'py -m pip'
        import platform
        self.is_windows = platform.system() == 'Windows'

    def _get_pip_cmd(self):
        """Get the appropriate pip command for this platform"""
        if self.is_windows:
            # Windows: Use 'py -m pip' which always works
            return ['py', '-m', 'pip']
        else:
            # Unix: Use 'pip' or 'pip3'
            import shutil
            if shutil.which('pip3'):
                return ['pip3']
            return ['pip']

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        """Install package using pip"""
        if not self.pm_path and not self.is_windows:
            return False

        package_name = ToolMapper.get_package_name(package, 'pip')
        if not package_name:
            return False

        # Get versioned package spec
        package_spec = self.version_mgr.get_package_spec(package, package_name, 'pip', use_latest)

        cmd = self._get_pip_cmd() + ['install', package_spec]
        if sudo and not self.is_windows:
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
            cmd = self._get_pip_cmd() + ['show', package_name]
            result = self.run_command(cmd, check=False)
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
