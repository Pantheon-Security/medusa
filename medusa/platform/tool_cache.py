#!/usr/bin/env python3
"""
MEDUSA Tool Installation Cache
Tracks installed tools to prevent reinstallation prompts in same session
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Set, Optional


class ToolCache:
    """Cache for tracking installed tools"""

    def __init__(self, cache_dir: Path = None):
        """
        Initialize tool cache

        Args:
            cache_dir: Directory to store cache file (default: user home directory)
        """
        if cache_dir is None:
            # Use user-wide cache directory instead of current directory
            # This prevents cache misses when running from different directories
            import os
            import platform

            if platform.system() == 'Windows':
                # Windows: Use %LOCALAPPDATA%\MEDUSA
                cache_dir = Path(os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))) / 'MEDUSA'
            else:
                # Unix: Use ~/.medusa
                cache_dir = Path.home() / '.medusa'

        cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = cache_dir / "installed_tools.json"
        self._cache = self._load_cache()

    def _load_cache(self) -> dict:
        """Load cache from disk"""
        if not self.cache_file.exists():
            return {}

        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, indent=2)
        except (IOError, OSError, PermissionError) as e:
            # Fail silently if we can't save cache - not critical for functionality
            # Cache is a performance optimization, not required for operation
            pass

    def mark_installed(self, tool: str):
        """
        Mark a tool as installed

        Args:
            tool: Tool name (e.g., 'shellcheck')
        """
        self._cache[tool] = {
            'installed_at': datetime.now().isoformat(),
            'session': True  # Installed in current session
        }
        self._save_cache()

    def is_cached(self, tool: str) -> bool:
        """
        Check if tool is in cache (was recently installed)

        Args:
            tool: Tool name to check

        Returns:
            True if tool is cached as installed
        """
        return tool in self._cache

    def get_cached_tools(self) -> Set[str]:
        """
        Get set of all cached tools

        Returns:
            Set of tool names
        """
        return set(self._cache.keys())

    def clear(self):
        """Clear the cache"""
        self._cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()

    def remove(self, tool: str):
        """
        Remove a tool from cache

        Args:
            tool: Tool name to remove
        """
        if tool in self._cache:
            del self._cache[tool]
            self._save_cache()
