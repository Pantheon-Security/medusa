#!/usr/bin/env python3
"""
MEDUSA Base Installer Class

DEPRECATED in MEDUSA v2026.2
Use medusa.platform.installers.simple instead.

This module is kept for backward compatibility only.
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseInstaller(ABC):
    """
    DEPRECATED: Abstract base class for platform-specific installers.

    Use medusa.platform.installers.simple instead in v2026.2+.
    """

    def __init__(self, package_manager: str):
        self.package_manager = package_manager
        self.pm_path = None

    @abstractmethod
    def install(self, package: str, sudo: bool = True) -> bool:
        """Install a package."""
        pass

    @abstractmethod
    def is_installed(self, package: str) -> bool:
        """Check if a package is installed."""
        pass

    @abstractmethod
    def uninstall(self, package: str, sudo: bool = True) -> bool:
        """Uninstall a package."""
        pass


class PlatformFilter:
    """DEPRECATED: Platform filter stub for backward compatibility."""

    UNSUPPORTED_WINDOWS = set()
    UNSUPPORTED_MACOS = set()
    UNSUPPORTED_LINUX = set()

    @classmethod
    def is_supported(cls, tool_name: str, os_type: str = None) -> bool:
        """Always returns True - deprecated."""
        return True

    @classmethod
    def filter_tools(cls, tools: list, os_type: str = None) -> list:
        """Returns tools unchanged - deprecated."""
        return tools


class EcosystemDetector:
    """DEPRECATED: Ecosystem detector stub for backward compatibility."""

    ECOSYSTEM_MAP = {}

    @classmethod
    def detect_ecosystem(cls, tool: str) -> Optional[tuple]:
        """Always returns None - deprecated."""
        return None

    @classmethod
    def try_ecosystem_install(cls, tool: str) -> tuple:
        """Always fails - deprecated."""
        return (False, '', 'Deprecated in v2026.2')


class ToolMapper:
    """
    DEPRECATED: Tool mapper stub for backward compatibility.

    In v2026.2, MEDUSA only manages modelscan via pip.
    Use medusa.platform.installers.simple instead.
    """

    # Empty - no longer mapping 60+ tools
    PYTHON_TOOLS = {'modelscan'}
    NPM_TOOLS = set()
    # SECURITY: TOOL_PACKAGES entries are executed via subprocess. This dict MUST
    # remain hardcoded at import time — never load or merge values from disk, user
    # input, or config files, or any addition becomes RCE-as-the-developer-user.
    TOOL_PACKAGES = {}

    @classmethod
    def get_package_name(cls, tool: str, package_manager: str) -> Optional[str]:
        """Returns None - deprecated."""
        return None

    @classmethod
    def get_install_method(cls, tool: str, package_manager: str) -> str:
        """Returns 'unavailable' - deprecated."""
        return 'unavailable'

    @classmethod
    def is_python_tool(cls, tool: str) -> bool:
        """Check if tool is a Python tool (only modelscan now)."""
        return tool in cls.PYTHON_TOOLS

    @classmethod
    def is_npm_tool(cls, tool: str) -> bool:
        """Check if tool is an npm tool (none now)."""
        return tool in cls.NPM_TOOLS
