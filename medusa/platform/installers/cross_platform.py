#!/usr/bin/env python3
"""
MEDUSA Cross-Platform Installers

DEPRECATED in MEDUSA v2026.2
Use medusa.platform.installers.simple instead.
"""


class NpmInstaller:
    """DEPRECATED: Cross-platform npm installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        return False


class PipInstaller:
    """DEPRECATED: Cross-platform pip installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = False, use_latest: bool = False) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = False) -> bool:
        return False
