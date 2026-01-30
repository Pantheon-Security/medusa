#!/usr/bin/env python3
"""
MEDUSA Linux Installers

DEPRECATED in MEDUSA v2026.2
Use medusa.platform.installers.simple instead.
"""


class AptInstaller:
    """DEPRECATED: Debian/Ubuntu package installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = True) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        return False


class YumInstaller:
    """DEPRECATED: RHEL/CentOS package installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = True) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        return False


class DnfInstaller:
    """DEPRECATED: Fedora/RHEL 8+ package installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = True) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        return False


class PacmanInstaller:
    """DEPRECATED: Arch Linux package installer. Use simple.py instead."""

    def __init__(self):
        pass

    def install(self, package: str, sudo: bool = True) -> bool:
        return False

    def is_installed(self, package: str) -> bool:
        return False

    def uninstall(self, package: str, sudo: bool = True) -> bool:
        return False
