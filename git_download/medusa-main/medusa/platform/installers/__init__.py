"""
MEDUSA Platform-Specific Installers
Linter installation for Linux, macOS, and Windows
"""

from medusa.platform.installers.base import BaseInstaller, ToolMapper
from medusa.platform.installers.linux import (
    AptInstaller,
    YumInstaller,
    DnfInstaller,
    PacmanInstaller,
)
from medusa.platform.installers.macos import HomebrewInstaller
from medusa.platform.installers.windows import WingetInstaller, ChocolateyInstaller, WindowsCustomInstaller
from medusa.platform.installers.cross_platform import NpmInstaller, PipInstaller

__all__ = [
    'BaseInstaller',
    'ToolMapper',
    'AptInstaller',
    'YumInstaller',
    'DnfInstaller',
    'PacmanInstaller',
    'HomebrewInstaller',
    'WingetInstaller',
    'ChocolateyInstaller',
    'WindowsCustomInstaller',
    'NpmInstaller',
    'PipInstaller',
]
