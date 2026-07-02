#!/usr/bin/env python3
"""
MEDUSA Configuration Management
Handles .medusa.yml configuration files
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from medusa import __version__


class ConfigError(Exception):
    """Raised when a config file exists but cannot be parsed/validated.

    P3-5: distinct from the absent-config case (which silently uses defaults).
    A present-but-broken `.medusa.yml` must fail loudly so a configured CI
    `fail_on` is never silently dropped. Callers (CLI) should catch this and
    print a prominent error / exit non-zero rather than scanning with defaults.
    """


@dataclass
class MedusaConfig:
    """MEDUSA configuration structure"""

    # Version (derives from the package version, single source of truth)
    version: str = field(default_factory=lambda: __version__)

    # Scanner configuration
    scanners_enabled: List[str] = field(default_factory=list)  # Empty = all
    scanners_disabled: List[str] = field(default_factory=list)
    scanner_overrides: Dict[str, str] = field(default_factory=dict)  # file_path -> scanner_name

    # Severity settings
    fail_on: str = "high"  # critical, high, medium, low

    # Exclusion patterns - these are directories/paths that should NEVER be scanned
    # Users download MEDUSA to scan THEIR code, not third-party dependencies
    exclude_paths: List[str] = field(default_factory=lambda: [
        # === JavaScript/Node.js dependencies ===
        "node_modules/",
        "bower_components/",

        # === Python virtual environments & dependencies ===
        "venv/",
        ".venv/",
        "env/",
        ".env/",
        "*-env/",           # Matches any-env/, medusa-env/, etc.
        "*_env/",           # Matches any_env/, python_env/, etc.
        "virtualenv/",
        ".virtualenv/",
        "site-packages/",   # CRITICAL: pip installed packages
        "dist-packages/",   # System-wide Python packages
        "lib/python*/",     # Virtual env lib directories
        "lib64/python*/",

        # === Ruby dependencies ===
        "vendor/bundle/",
        ".bundle/",

        # === Go dependencies ===
        "vendor/",

        # === Rust dependencies ===
        "target/",

        # === Java/Kotlin/Scala dependencies ===
        ".gradle/",
        ".m2/",
        "build/libs/",

        # === .NET dependencies ===
        "packages/",
        "bin/Debug/",
        "bin/Release/",
        "obj/",

        # === PHP dependencies (covered by vendor/ above) ===

        # === Version control ===
        ".git/",
        ".svn/",
        ".hg/",

        # === Build/cache directories ===
        "__pycache__/",
        "*.egg-info/",
        "dist/",
        "build/",
        ".tox/",
        ".nox/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".cache/",
        ".coverage/",
        "htmlcov/",
        ".eggs/",

        # === IDE/Editor directories ===
        ".idea/",
        ".vscode/",
        "*.xcworkspace/",
        "*.xcodeproj/",

        # === Test fixtures (intentionally insecure) ===
        "tests/fixtures/",
        "test/fixtures/",
        "test-fixtures/",
        "__fixtures__/",

        # === MEDUSA's own files (don't scan ourselves) ===
        ".medusa/",
    ])

    exclude_files: List[str] = field(default_factory=lambda: [
        "*.min.js",
        "*.min.css",
        "*.bundle.js",
        "*.map",
        # MEDUSA's own config files (don't scan ourselves)
        ".medusa.yml",
        "medusa.yml",
        ".medusa-suppress.yml",
    ])

    # IDE integration settings
    ide_claude_code_enabled: bool = False
    ide_claude_code_auto_scan: bool = True
    ide_claude_code_inline_annotations: bool = True

    ide_cursor_enabled: bool = False
    ide_vscode_enabled: bool = False
    ide_gemini_enabled: bool = False
    ide_openai_enabled: bool = False
    ide_copilot_enabled: bool = False

    # Scan settings
    workers: Optional[int] = None  # None = auto-detect
    cache_enabled: bool = True

    # Vet OWNER OVERRIDES (P1-trust-safety, Phase 3).
    # A list of path globs (relative to the scan root) marking known-benign
    # security-content files. Findings under an allowlisted path are excluded
    # from the `medusa vet` install VERDICT (same treatment as test-data dirs) —
    # they are still scanned and still counted, they just do not gate the
    # install decision. This affects ONLY the vet verdict, never `medusa scan`
    # output. SECURITY: this list is honored only from the USER's config (loaded
    # from CWD upward), never from a scanned target's own .medusa.yml, so an
    # untrusted repo cannot allowlist away its own malice. Default: empty.
    vet_allowlist: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MedusaConfig':
        """Create config from dictionary"""
        config = cls()

        # Basic settings
        config.version = data.get('version', config.version)
        config.fail_on = data.get('fail_on', config.fail_on)
        config.workers = data.get('workers', config.workers)
        config.cache_enabled = data.get('cache_enabled', config.cache_enabled)

        # Scanners.  `or {}` (not a default arg) so a present-but-null YAML key
        # (`scanners:` with no value → None) doesn't raise AttributeError and
        # silently discard the user's entire config.
        scanners = data.get('scanners') or {}
        config.scanners_enabled = scanners.get('enabled', [])
        config.scanners_disabled = scanners.get('disabled', [])
        config.scanner_overrides = scanners.get('overrides', {})

        # Exclusions - MERGE user paths with mandatory exclusions (don't replace)
        exclude = data.get('exclude') or {}
        if 'paths' in exclude:
            # Start with user's paths
            user_paths = set(exclude['paths'])
            # Add mandatory exclusions that MUST always be excluded
            mandatory = {
                'site-packages/', 'dist-packages/', 'node_modules/',
                'lib/python*/', 'lib64/python*/', '__pycache__/',
                '.git/', '.svn/', '.hg/', 'tests/fixtures/', 'test/fixtures/',
            }
            # Merge: user paths + mandatory
            config.exclude_paths = list(user_paths | mandatory)
        if 'files' in exclude:
            config.exclude_files = exclude['files']

        # Vet owner-overrides allowlist. Validate like other list fields: must be
        # a list of path-glob strings. A present-but-null key (`vet_allowlist:`
        # with no value -> None) is treated as "unset" (keep the empty default).
        vet_allowlist = data.get('vet_allowlist')
        if vet_allowlist is not None:
            if not isinstance(vet_allowlist, list) or not all(
                isinstance(g, str) for g in vet_allowlist
            ):
                raise ValueError(
                    "vet_allowlist must be a list of path glob strings "
                    "(e.g. ['skills/**', 'agents/*.md'])"
                )
            config.vet_allowlist = vet_allowlist

        # IDE settings
        ide = data.get('ide') or {}
        claude = ide.get('claude_code') or {}
        config.ide_claude_code_enabled = claude.get('enabled', False)
        config.ide_claude_code_auto_scan = claude.get('auto_scan', True)
        config.ide_claude_code_inline_annotations = claude.get('inline_annotations', True)

        cursor = ide.get('cursor') or {}
        config.ide_cursor_enabled = cursor.get('enabled', False)

        vscode = ide.get('vscode', {})
        config.ide_vscode_enabled = vscode.get('enabled', False)

        gemini = ide.get('gemini_cli', {})
        config.ide_gemini_enabled = gemini.get('enabled', False)

        openai = ide.get('openai', {})
        config.ide_openai_enabled = openai.get('enabled', False)

        copilot = ide.get('copilot', {})
        config.ide_copilot_enabled = copilot.get('enabled', False)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for YAML export"""
        return {
            'version': self.version,
            'scanners': {
                'enabled': self.scanners_enabled,
                'disabled': self.scanners_disabled,
                'overrides': self.scanner_overrides,
            },
            'fail_on': self.fail_on,
            'exclude': {
                'paths': self.exclude_paths,
                'files': self.exclude_files,
            },
            'ide': {
                'claude_code': {
                    'enabled': self.ide_claude_code_enabled,
                    'auto_scan': self.ide_claude_code_auto_scan,
                    'inline_annotations': self.ide_claude_code_inline_annotations,
                },
                'cursor': {
                    'enabled': self.ide_cursor_enabled,
                },
                'vscode': {
                    'enabled': self.ide_vscode_enabled,
                },
                'gemini_cli': {
                    'enabled': self.ide_gemini_enabled,
                },
                'openai': {
                    'enabled': self.ide_openai_enabled,
                },
                'copilot': {
                    'enabled': self.ide_copilot_enabled,
                },
            },
            'workers': self.workers,
            'cache_enabled': self.cache_enabled,
            'vet_allowlist': self.vet_allowlist,
        }


class ConfigManager:
    """Manage MEDUSA configuration files"""

    DEFAULT_CONFIG_NAME = "medusa.yml"
    LEGACY_CONFIG_NAME = ".medusa.yml"

    @staticmethod
    def find_config(start_path: Path = None) -> Optional[Path]:
        """
        Find medusa.yml by walking up directory tree.

        Checks for medusa.yml first (visible), then .medusa.yml (legacy/hidden).

        Args:
            start_path: Starting directory (default: current directory)

        Returns:
            Path to config file or None if not found
        """
        current = start_path or Path.cwd()

        # Walk up directory tree
        while current != current.parent:
            # Prefer visible config (medusa.yml)
            visible = current / ConfigManager.DEFAULT_CONFIG_NAME
            if visible.exists():
                return visible
            # Fall back to hidden config (.medusa.yml)
            hidden = current / ConfigManager.LEGACY_CONFIG_NAME
            if hidden.exists():
                return hidden
            current = current.parent

        return None

    @staticmethod
    def load_config(config_path: Path = None) -> MedusaConfig:
        """
        Load configuration from .medusa.yml

        Args:
            config_path: Path to config file (default: search from current dir)

        Returns:
            MedusaConfig object
        """
        if config_path is None:
            config_path = ConfigManager.find_config()

        # Return default config if no file found. Absent config -> defaults is a
        # supported, silent path.
        if config_path is None or not config_path.exists():
            return MedusaConfig()

        # P3-5: a config file EXISTS, so the user clearly intends to configure
        # MEDUSA (e.g. a CI `fail_on`). If it cannot be parsed we must NOT
        # silently fall back to defaults — that would let a typo in `.medusa.yml`
        # quietly disable the configured fail threshold and pass CI. Surface the
        # parse error loudly and refuse to continue with the wrong config.
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            # Pull the exact line/column out of the PyYAML error when available.
            mark = getattr(e, 'problem_mark', None)
            where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
            raise ConfigError(
                f"Invalid YAML in config file {config_path}{where}: {e}\n"
                f"Fix the syntax error or remove {config_path.name} to use defaults."
            ) from e
        except OSError as e:
            raise ConfigError(
                f"Could not read config file {config_path}: {e}"
            ) from e

        # Empty file (`safe_load` -> None) is a benign no-op: an empty config
        # means "use defaults", same as no file.
        if data is None:
            return MedusaConfig()

        if not isinstance(data, dict):
            raise ConfigError(
                f"Invalid config file {config_path}: expected a YAML mapping at "
                f"the top level, got {type(data).__name__}.\n"
                f"Fix the structure or remove {config_path.name} to use defaults."
            )

        try:
            return MedusaConfig.from_dict(data)
        except (TypeError, ValueError, AttributeError) as e:
            raise ConfigError(
                f"Invalid config values in {config_path}: {e}\n"
                f"Fix the offending key or remove {config_path.name} to use defaults."
            ) from e

    @staticmethod
    def save_config(config: MedusaConfig, config_path: Path) -> bool:
        """
        Save configuration to .medusa.yml

        Args:
            config: MedusaConfig object
            config_path: Path where to save

        Returns:
            True if successful
        """
        try:
            # Create directory if needed
            config_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert to dict and save as YAML
            with open(config_path, 'w') as f:
                yaml.dump(
                    config.to_dict(),
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    indent=2
                )

            return True

        except Exception as e:
            print(f"Error: Failed to save config to {config_path}: {e}")
            return False

    @staticmethod
    def create_default_config(project_root: Path) -> Path:
        """
        Create default .medusa.yml in project root

        Args:
            project_root: Project directory

        Returns:
            Path to created config file
        """
        config = MedusaConfig()
        config_path = project_root / ConfigManager.DEFAULT_CONFIG_NAME

        ConfigManager.save_config(config, config_path)

        return config_path
