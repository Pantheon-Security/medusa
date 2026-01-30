#!/usr/bin/env python3
"""
MEDUSA macOS Installer

DEPRECATED in MEDUSA v2026.2
Use medusa.platform.installers.simple instead.
"""


class HomebrewInstaller:
    """DEPRECATED: macOS package installer using Homebrew. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = False) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        return False

    @classmethod
    def get_install_hint(cls, tool: str) -> str:
        """DEPRECATED: Returns empty string."""
        return ''
