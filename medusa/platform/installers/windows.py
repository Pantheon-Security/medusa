#!/usr/bin/env python3
"""
MEDUSA Windows Installers
Package installers for Windows using winget and Chocolatey
"""

import subprocess
import shutil
import os
import sys
from rich.console import Console
from medusa.platform.installers.base import BaseInstaller, ToolMapper

# Create console for debug output
_debug_console = Console(stderr=True)


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
        except (OSError, WindowsError):
            system_path = ''

        # Get user PATH
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment') as key:
                user_path = winreg.QueryValueEx(key, 'Path')[0]
        except (OSError, WindowsError):
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

        # Validate package name (winget IDs can contain alphanumeric, dash, underscore, dot)
        if not package_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
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
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as e:
            # Installation failed
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
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        """Uninstall package using winget"""
        if not self.pm_path:
            _debug_console.print("[dim][DEBUG] winget path not found[/dim]")
            return False

        package_name = ToolMapper.get_package_name(package, 'winget')
        if not package_name:
            _debug_console.print(f"[dim][DEBUG] No winget package mapping for {package}[/dim]")
            return False

        # Validate package name
        if not package_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            _debug_console.print(f"[dim][DEBUG] Invalid package name: {package_name}[/dim]")
            return False

        cmd = ['winget', 'uninstall', '--id', package_name, '--silent', '--accept-source-agreements']

        try:
            result = self.run_command(cmd, check=False)  # Don't throw on non-zero
            output = result.stdout.lower() if hasattr(result, 'stdout') else ''

            _debug_console.print(f"[yellow][DEBUG] Winget uninstall {package_name}[/yellow]")
            _debug_console.print(f"[dim]  Command: {' '.join(cmd)}[/dim]")
            _debug_console.print(f"[dim]  Return code: {result.returncode}[/dim]")
            _debug_console.print(f"[dim]  Stdout: {result.stdout[:300] if result.stdout else 'None'}[/dim]")
            _debug_console.print(f"[dim]  Stderr: {result.stderr[:300] if hasattr(result, 'stderr') and result.stderr else 'None'}[/dim]")

            # Success if:
            # - Exit code is 0, OR
            # - Package was successfully uninstalled
            success = (
                result.returncode == 0 or
                'successfully uninstalled' in output or
                'uninstalled successfully' in output
            )

            return success
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as e:
            _debug_console.print(f"[red][DEBUG] Exception during uninstall: {e}[/red]")
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
                'powershell.exe',
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

        # Validate package name contains only safe characters (alphanumeric, dash, underscore, dot)
        if not package_name.replace('-', '').replace('_', '').replace('.', '').isalnum():
            if self.debug:
                print(f"[DEBUG] Invalid package name: {package_name}")
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
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
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
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError):
            return False

    def get_install_command(self, package: str, sudo: bool = False) -> str:
        package_name = ToolMapper.get_package_name(package, 'choco')
        if not package_name:
            return f"# Package '{package}' not available via Chocolatey"
        return f"choco install {package_name} -y"


class WindowsCustomInstaller:
    """
    Custom Windows installer that runs bundled PowerShell scripts for tools
    that aren't available via winget or chocolatey
    """

    # Tools that have custom PowerShell installers
    SUPPORTED_TOOLS = {
        'clj-kondo': 'install-clj-kondo.ps1',
        'ktlint': 'install-ktlint.ps1',
        'checkstyle': 'install-checkstyle.ps1',
        'phpstan': 'install-phpstan.ps1',
        'taplo': 'install-taplo.ps1',
        # Legacy tools (no longer have installers - provide manual instructions)
        'scalastyle': None,
        'codenarc': None,
        'checkmake': None,  # No Windows binaries available
    }

    # Tools available via chocolatey (try this first to avoid antivirus false positives)
    CHOCOLATEY_PACKAGES = {
        # Note: clj-kondo is NOT in chocolatey - removed
    }

    @staticmethod
    def can_install(tool: str) -> bool:
        """Check if tool has a custom Windows installer"""
        return tool in WindowsCustomInstaller.SUPPORTED_TOOLS

    @staticmethod
    def install(tool: str, debug: bool = False) -> bool:
        """Run the custom PowerShell installer for the tool"""
        if not WindowsCustomInstaller.can_install(tool):
            return False

        script_name = WindowsCustomInstaller.SUPPORTED_TOOLS.get(tool)

        # If no script available, show manual instructions
        if not script_name:
            print(f"\n⚠️  Unable to automatically install {tool}")
            print(f"\nPlease install manually:")

            if tool in ['codenarc', 'scalastyle', 'checkmake']:
                print(f"  Install via package manager or download from official website")
                if tool == 'checkmake':
                    print(f"  Note: checkmake requires Go toolchain (go install github.com/mrtazz/checkmake/cmd/checkmake@latest)")

            print(f"\nAfter installation, add to PATH and run: medusa install --check")
            return False

        # Try to run PowerShell installer
        try:
            if debug:
                print(f"[DEBUG] Running PowerShell installer: {script_name}")

            # Get script path from package
            import importlib.resources
            try:
                # Python 3.9+
                script_content = importlib.resources.files('medusa.platform.installers.windows_scripts').joinpath(script_name).read_text(encoding='utf-8')
            except AttributeError:
                # Python 3.8 fallback
                import importlib_resources
                script_content = importlib_resources.files('medusa.platform.installers.windows_scripts').joinpath(script_name).read_text(encoding='utf-8')

            # Write script to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(script_content)
                temp_script = f.name

            if debug:
                print(f"[DEBUG] Script written to: {temp_script}")

            # Find PowerShell executable
            powershell_exe = shutil.which('powershell.exe')
            if not powershell_exe:
                # Try common locations if which() fails
                common_paths = [
                    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                    r'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe',
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        powershell_exe = path
                        break

            if not powershell_exe:
                if debug:
                    print(f"[DEBUG] PowerShell not found in PATH or common locations")
                raise FileNotFoundError("PowerShell executable not found")

            if debug:
                print(f"[DEBUG] Using PowerShell: {powershell_exe}")

            # Run PowerShell script
            ps_args = [
                powershell_exe,
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', temp_script
            ]

            if debug:
                ps_args.append('-Debug')

            if debug:
                print(f"[DEBUG] Running: {' '.join(ps_args)}")

            result = subprocess.run(
                ps_args,
                capture_output=False if debug else True,
                text=True,
                timeout=300,
                check=False
            )

            # Clean up temp file
            try:
                os.remove(temp_script)
            except (OSError, PermissionError):
                # Ignore cleanup errors - temp file will be cleaned by OS
                if debug:
                    print(f"[DEBUG] Could not remove temp file: {temp_script}")

            if result.returncode == 0:
                if debug:
                    print(f"[DEBUG] Successfully installed {tool} via PowerShell script")
                return True
            else:
                if debug:
                    print(f"[DEBUG] PowerShell script failed with exit code: {result.returncode}")
                return False

        except Exception as e:
            if debug:
                print(f"[DEBUG] PowerShell installer error: {e}")
                import traceback
                traceback.print_exc()

            # Fall back to manual instructions
            print(f"\n⚠️  Automatic installation failed")
            print(f"\nPlease install manually:")
            if tool == 'clj-kondo':
                print(f"  Download from: https://github.com/clj-kondo/clj-kondo/releases")
            elif tool == 'ktlint':
                print(f"  Download from: https://github.com/pinterest/ktlint/releases")
            elif tool == 'checkstyle':
                print(f"  Download from: https://github.com/checkstyle/checkstyle/releases")
            elif tool == 'phpstan':
                print(f"  Option 1 (Composer): composer global require phpstan/phpstan")
                print(f"  Option 2 (Manual): Download from https://github.com/phpstan/phpstan/releases")
            print(f"\nAfter installation, add to PATH and run: medusa install --check")
            return False
