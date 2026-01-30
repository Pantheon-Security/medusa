#!/usr/bin/env python3
"""
MEDUSA Windows Installers

DEPRECATED in MEDUSA v2026.2
Use medusa.platform.installers.simple instead.
"""


class WingetInstaller:
    """DEPRECATED: Windows package installer using winget. Use simple.py instead."""

    def __init__(self):
        self.last_error = None

    def install(self, package: str, sudo: bool = False) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        return False


class ChocolateyInstaller:
    """DEPRECATED: Windows package installer using Chocolatey. Use simple.py instead."""

    def __init__(self, debug: bool = False):
        self.debug = debug

    def install(self, package: str, sudo: bool = False) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        return False

    @staticmethod
    def is_chocolatey_installed() -> bool:
        """DEPRECATED: Returns False."""
        return False

    @staticmethod
    def install_chocolatey(debug: bool = False) -> bool:
        """DEPRECATED: Returns False."""
        return False


class WindowsCustomInstaller:
    """DEPRECATED: Custom Windows installer. Use simple.py instead."""

    SUPPORTED_TOOLS = {}

    @staticmethod
    def can_install(tool: str) -> bool:
        """DEPRECATED: Returns False."""
        return False

    @staticmethod
    def install(tool: str, debug: bool = False) -> bool:
        """DEPRECATED: Returns False."""
        return False


def refresh_windows_path() -> bool:
    """DEPRECATED: No-op function for backward compatibility."""
    return False
