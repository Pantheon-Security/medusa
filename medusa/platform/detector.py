#!/usr/bin/env python3
"""
MEDUSA Platform Detection
Detects operating system, package managers, and environment details
"""

import platform
import shutil
import subprocess
import os
from pathlib import Path
from typing import Optional, List, Dict
from enum import Enum
from dataclasses import dataclass


class OSType(Enum):
    """Operating system types"""
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class PackageManager(Enum):
    """Package manager types"""
    APT = "apt"              # Debian/Ubuntu
    YUM = "yum"              # RHEL/CentOS (old)
    DNF = "dnf"              # Fedora/RHEL 8+
    PACMAN = "pacman"        # Arch Linux
    ZYPPER = "zypper"        # openSUSE
    BREW = "brew"            # macOS/Linux Homebrew
    CHOCOLATEY = "choco"     # Windows
    SCOOP = "scoop"          # Windows
    WINGET = "winget"        # Windows 11
    NPM = "npm"              # Node.js (cross-platform)
    PIP = "pip"              # Python (cross-platform)
    CARGO = "cargo"          # Rust (cross-platform)
    UNKNOWN = "unknown"


class WindowsEnvironment(Enum):
    """Windows environment types"""
    WSL2 = "wsl2"            # Windows Subsystem for Linux
    WSL1 = "wsl1"            # Windows Subsystem for Linux (older)
    GIT_BASH = "git-bash"    # Git for Windows bash
    POWERSHELL = "powershell"
    CMD = "cmd"
    NATIVE = "native"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    """Complete platform information"""
    os_type: OSType
    os_name: str
    os_version: str
    architecture: str
    package_managers: List[PackageManager]
    primary_package_manager: Optional[PackageManager]
    windows_environment: Optional[WindowsEnvironment]
    is_wsl: bool
    python_version: str
    shell: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for display"""
        return {
            'os_type': self.os_type.value,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'architecture': self.architecture,
            'package_managers': [pm.value for pm in self.package_managers],
            'primary_package_manager': self.primary_package_manager.value if self.primary_package_manager else None,
            'windows_environment': self.windows_environment.value if self.windows_environment else None,
            'is_wsl': self.is_wsl,
            'python_version': self.python_version,
            'shell': self.shell,
        }


class PlatformDetector:
    """
    Detect platform details: OS, package managers, environment
    """

    def __init__(self):
        self.info: Optional[PlatformInfo] = None

    def detect(self) -> PlatformInfo:
        """
        Perform full platform detection

        Returns:
            PlatformInfo with all detected details
        """
        os_type = self._detect_os()
        is_wsl = self._is_wsl()
        windows_env = self._detect_windows_environment() if os_type == OSType.WINDOWS or is_wsl else None

        self.info = PlatformInfo(
            os_type=os_type,
            os_name=platform.system(),
            os_version=platform.release(),
            architecture=platform.machine(),
            package_managers=self._detect_package_managers(),
            primary_package_manager=self._get_primary_package_manager(os_type),
            windows_environment=windows_env,
            is_wsl=is_wsl,
            python_version=platform.python_version(),
            shell=self._detect_shell(),
        )

        return self.info

    def _detect_os(self) -> OSType:
        """Detect operating system type"""
        system = platform.system().lower()

        if system == 'linux':
            return OSType.LINUX
        elif system == 'darwin':
            return OSType.MACOS
        elif system == 'windows':
            return OSType.WINDOWS
        else:
            return OSType.UNKNOWN

    def _is_wsl(self) -> bool:
        """Check if running in Windows Subsystem for Linux"""
        # WSL has /proc/version with "Microsoft" or "WSL"
        if Path('/proc/version').exists():
            try:
                with open('/proc/version', 'r') as f:
                    version = f.read().lower()
                    return 'microsoft' in version or 'wsl' in version
            except (IOError, OSError, PermissionError):
                # Failed to read /proc/version - not in WSL or no permissions
                pass
        return False

    def _detect_windows_environment(self) -> WindowsEnvironment:
        """Detect Windows environment type"""
        # Check for WSL
        if self._is_wsl():
            # Check WSL version
            if os.environ.get('WSL_DISTRO_NAME'):
                # WSL2 sets this environment variable
                return WindowsEnvironment.WSL2
            return WindowsEnvironment.WSL1

        # Check for Git Bash
        if 'MSYSTEM' in os.environ or 'MINGW' in os.environ.get('MSYSTEM_PREFIX', ''):
            return WindowsEnvironment.GIT_BASH

        # Check for PowerShell
        if 'PSModulePath' in os.environ:
            return WindowsEnvironment.POWERSHELL

        # Check for CMD
        if 'PROMPT' in os.environ and 'COMSPEC' in os.environ:
            return WindowsEnvironment.CMD

        # Native Windows
        if platform.system().lower() == 'windows':
            return WindowsEnvironment.NATIVE

        return WindowsEnvironment.UNKNOWN

    def _detect_package_managers(self) -> List[PackageManager]:
        """Detect all available package managers"""
        managers = []

        # System package managers
        package_manager_commands = {
            PackageManager.APT: 'apt',
            PackageManager.YUM: 'yum',
            PackageManager.DNF: 'dnf',
            PackageManager.PACMAN: 'pacman',
            PackageManager.ZYPPER: 'zypper',
            PackageManager.BREW: 'brew',
            PackageManager.CHOCOLATEY: 'choco',
            PackageManager.SCOOP: 'scoop',
            PackageManager.WINGET: 'winget',
        }

        for pm, cmd in package_manager_commands.items():
            if shutil.which(cmd):
                managers.append(pm)

        # Language package managers (always check these)
        if shutil.which('npm'):
            managers.append(PackageManager.NPM)
        if shutil.which('pip') or shutil.which('pip3'):
            managers.append(PackageManager.PIP)
        if shutil.which('cargo'):
            managers.append(PackageManager.CARGO)

        return managers if managers else [PackageManager.UNKNOWN]

    def _get_primary_package_manager(self, os_type: OSType) -> Optional[PackageManager]:
        """Get the primary/recommended package manager for the OS"""
        available = self._detect_package_managers()

        if os_type == OSType.LINUX:
            # Check Linux distribution
            distro = self._get_linux_distro()
            if 'ubuntu' in distro or 'debian' in distro:
                return PackageManager.APT if PackageManager.APT in available else None
            elif 'fedora' in distro or 'rhel' in distro:
                return PackageManager.DNF if PackageManager.DNF in available else PackageManager.YUM if PackageManager.YUM in available else None
            elif 'arch' in distro:
                return PackageManager.PACMAN if PackageManager.PACMAN in available else None
            elif 'suse' in distro:
                return PackageManager.ZYPPER if PackageManager.ZYPPER in available else None

        elif os_type == OSType.MACOS:
            return PackageManager.BREW if PackageManager.BREW in available else None

        elif os_type == OSType.WINDOWS:
            # Prefer in order: winget (built-in, modern), chocolatey, scoop
            if PackageManager.WINGET in available:
                return PackageManager.WINGET
            elif PackageManager.CHOCOLATEY in available:
                return PackageManager.CHOCOLATEY
            elif PackageManager.SCOOP in available:
                return PackageManager.SCOOP

        return None

    def _get_linux_distro(self) -> str:
        """Get Linux distribution name"""
        # Try /etc/os-release (standard)
        if Path('/etc/os-release').exists():
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            return line.split('=')[1].strip().strip('"').lower()
            except (IOError, OSError, PermissionError, FileNotFoundError):
                # Failed to read /etc/os-release - fallback to platform detection
                pass

        # Fallback to platform
        return platform.platform().lower()

    def _detect_shell(self) -> str:
        """Detect current shell"""
        shell = os.environ.get('SHELL', '')
        if shell:
            return Path(shell).name

        # Windows fallback
        if platform.system().lower() == 'windows':
            if 'PSModulePath' in os.environ:
                return 'powershell'
            return 'cmd'

        return 'unknown'

    def get_install_command(self, package: str, pm: Optional[PackageManager] = None) -> str:
        """
        Get the install command for a package

        Args:
            package: Package name to install
            pm: Package manager to use (None = use primary)

        Returns:
            Command string to install the package
        """
        if pm is None:
            pm = self.info.primary_package_manager if self.info else None

        if pm is None:
            return f"# No package manager detected. Please install {package} manually."

        commands = {
            PackageManager.APT: f"sudo apt install -y {package}",
            PackageManager.YUM: f"sudo yum install -y {package}",
            PackageManager.DNF: f"sudo dnf install -y {package}",
            PackageManager.PACMAN: f"sudo pacman -S --noconfirm {package}",
            PackageManager.ZYPPER: f"sudo zypper install -y {package}",
            PackageManager.BREW: f"brew install {package}",
            PackageManager.CHOCOLATEY: f"choco install {package} -y",
            PackageManager.SCOOP: f"scoop install {package}",
            PackageManager.WINGET: f"winget install {package}",
            PackageManager.NPM: f"npm install -g {package}",
            PackageManager.PIP: f"pip install {package}",
            PackageManager.CARGO: f"cargo install {package}",
        }

        return commands.get(pm, f"# Install {package} using {pm.value}")


# Global detector instance
_detector: Optional[PlatformDetector] = None


def get_platform_info() -> PlatformInfo:
    """Get cached platform information"""
    global _detector
    if _detector is None or _detector.info is None:
        _detector = PlatformDetector()
        _detector.detect()
    return _detector.info


def detect_platform() -> PlatformInfo:
    """Force fresh platform detection"""
    global _detector
    _detector = PlatformDetector()
    return _detector.detect()
