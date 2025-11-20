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
        # First, check if the tool binary is actually in PATH (most reliable)
        tool_binary = shutil.which(package)
        if tool_binary:
            return True

        # Fallback: check winget list output (winget may report non-zero even when installed)
        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            return False

        try:
            result = self.run_command(['winget', 'list', '--id', package_name], check=False)
            # Check output text, not just return code
            if result.stdout:
                output = result.stdout.lower()
                return package_name.lower() in output or package.lower() in output
            return False
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

    def __init__(self, debug: bool = False):
        super().__init__('choco')
        self.debug = debug

    @staticmethod
    def is_chocolatey_installed() -> bool:
        """Check if Chocolatey is installed"""
        # Check if choco is in PATH
        if shutil.which('choco'):
            return True

        # On Windows, also check the default install location
        # (PATH might not be refreshed in current session)
        default_path = r'C:\ProgramData\chocolatey\bin\choco.exe'
        if os.path.exists(default_path):
            return True

        return False

    @staticmethod
    def install_chocolatey(debug: bool = False) -> bool:
        """
        Install Chocolatey package manager
        Runs the official Chocolatey installation script
        Note: Must be run from an admin PowerShell

        Args:
            debug: If True, shows all PowerShell output for debugging (default: False)
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

            # Run directly in current PowerShell (user must be admin already)
            cmd = [
                'powershell',
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command',
                install_script
            ]

            if debug:
                print(f"[DEBUG] Running command: {' '.join(cmd)}")
                print("[DEBUG] This will download and run the Chocolatey install script...")
                print("[DEBUG] PowerShell output below:")
                print("-" * 60)

            # Run and wait for completion
            # In debug mode: show all output, don't capture it
            # In normal mode: capture output to keep it clean
            if debug:
                result = subprocess.run(cmd, check=False, text=True, timeout=300)
            else:
                result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)

            if debug:
                print("-" * 60)
                print(f"[DEBUG] Command exit code: {result.returncode}")

            # Verify chocolatey was actually installed by checking for the executable
            # Wait a moment for installation to finalize
            import time
            if debug:
                print("[DEBUG] Waiting 3 seconds for installation to finalize...")
            time.sleep(3)

            # Refresh PATH to pick up chocolatey
            if debug:
                print("[DEBUG] Refreshing Windows PATH from registry...")
            refresh_windows_path()

            # Check if choco is now accessible
            if debug:
                print("[DEBUG] Checking if 'choco' is in PATH...")
            choco_exe = shutil.which('choco')
            if debug:
                print(f"[DEBUG] shutil.which('choco') returned: {choco_exe}")

            if not choco_exe:
                # Check default install location
                default_path = r'C:\ProgramData\chocolatey\bin\choco.exe'
                if debug:
                    print(f"[DEBUG] Checking default location: {default_path}")
                if os.path.exists(default_path):
                    choco_exe = default_path
                    if debug:
                        print(f"[DEBUG] Found at default location!")
                elif debug:
                    print(f"[DEBUG] NOT found at default location")

            if debug:
                print(f"[DEBUG] Final result: chocolatey {'INSTALLED' if choco_exe else 'NOT INSTALLED'}")

            return choco_exe is not None
        except Exception as e:
            if debug:
                print(f"[DEBUG] Exception during installation: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
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
            if self.debug:
                print(f"[DEBUG] Running: {' '.join(cmd)}")
                print("[DEBUG] Chocolatey output:")
                print("-" * 60)
                # Don't capture output in debug mode - let it show
                result = subprocess.run(cmd, check=False, text=True)
                print("-" * 60)
                print(f"[DEBUG] Exit code: {result.returncode}")
            else:
                # Normal mode - capture output
                result = self.run_command(cmd, check=True)

            success = result.returncode == 0

            # If install succeeded, refresh PATH
            # This makes the tool available in current session
            if success:
                refresh_windows_path()

            return success
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Exception during install: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
            return False

    def is_installed(self, package: str) -> bool:
        """Check if package is installed via choco"""
        # First, check if the tool binary is actually in PATH (most reliable)
        tool_binary = shutil.which(package)
        if tool_binary:
            return True

        # Fallback: check choco list output
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


class WindowsCustomInstaller:
    """
    Custom Windows installer that runs bundled .bat scripts for tools
    that aren't available via winget or chocolatey
    """

    # Tools that have custom .bat installers
    SUPPORTED_TOOLS = {
        'phpstan': 'install-phpstan.cmd',
        'ktlint': 'install-ktlint.cmd',
        'checkstyle': 'install-checkstyle.cmd',
        'clj-kondo': 'install-clj-kondo.cmd',
        'scalastyle': 'install-scalastyle.cmd',
        'codenarc': 'install-codenarc.cmd',
        'checkmake': 'install-checkmake.cmd',
    }

    @staticmethod
    def can_install(tool: str) -> bool:
        """Check if tool has a custom Windows installer"""
        return tool in WindowsCustomInstaller.SUPPORTED_TOOLS

    @staticmethod
    def install(tool: str, debug: bool = False) -> bool:
        """Run the custom .bat installer for the tool"""
        if not WindowsCustomInstaller.can_install(tool):
            return False

        script_name = WindowsCustomInstaller.SUPPORTED_TOOLS[tool]

        # Get the script path (bundled with the package)
        try:
            from importlib.resources import files
            script_file = files('medusa').joinpath(f'platform/installers/windows_scripts/{script_name}')
            script_path = str(script_file)
        except Exception as e:
            if debug:
                print(f"[DEBUG] Failed to find installer script: {e}")
            return False

        if not os.path.exists(script_path):
            if debug:
                print(f"[DEBUG] Installer script not found: {script_path}")
            return False

        if debug:
            print(f"[DEBUG] Running custom installer: {script_path}")

        try:
            # Run the .bat script via cmd.exe (safer than shell=True)
            result = subprocess.run(
                ['cmd', '/c', script_path],
                shell=False,
                check=False,
                capture_output=not debug,  # Show output in debug mode
                text=True
            )

            if debug:
                print(f"[DEBUG] Installer exit code: {result.returncode}")

            # Refresh PATH after installation
            if result.returncode == 0:
                refresh_windows_path()

            return result.returncode == 0

        except Exception as e:
            if debug:
                print(f"[DEBUG] Exception running installer: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
            return False
