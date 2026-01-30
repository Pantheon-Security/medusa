"""
MEDUSA v2026.2 Simplified Installers

In v2026.2, MEDUSA only manages modelscan via pip.
Use simple.py for the new API.
"""

from .simple import (
    install_ai_tools,
    get_ai_tools_status,
    get_detected_tools,
    get_optional_tools,
    is_tool_installed,
    get_pip_command,
)

# Deprecated exports for backward compatibility
from .base import BaseInstaller, ToolMapper, PlatformFilter, EcosystemDetector
from .linux import AptInstaller, YumInstaller, DnfInstaller, PacmanInstaller
from .macos import HomebrewInstaller
from .windows import WingetInstaller, ChocolateyInstaller, WindowsCustomInstaller
from .cross_platform import NpmInstaller, PipInstaller

__all__ = [
    # New v2026.2 API
    'install_ai_tools',
    'get_ai_tools_status',
    'get_detected_tools',
    'get_optional_tools',
    'is_tool_installed',
    'get_pip_command',
    # Deprecated (kept for backward compat)
    'BaseInstaller',
    'ToolMapper',
    'PlatformFilter',
    'EcosystemDetector',
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
