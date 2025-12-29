#!/usr/bin/env python3
"""
MEDUSA Base Scanner Class
Abstract base class for all security scanner implementations
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess
import shutil


class Severity(Enum):
    """Issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScannerIssue:
    """Individual security issue found by scanner"""
    severity: Severity
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    code: Optional[str] = None
    rule_id: Optional[str] = None
    cwe_id: Optional[int] = None
    cwe_link: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'severity': self.severity.value,
            'message': self.message,
            'line': self.line,
            'column': self.column,
            'code': self.code,
            'rule_id': self.rule_id,
            'cwe_id': self.cwe_id,
            'cwe_link': self.cwe_link,
        }


@dataclass
class ScannerResult:
    """Result from scanning a file"""
    scanner_name: str
    file_path: str
    issues: List[ScannerIssue]
    scan_time: float
    success: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'scanner': self.scanner_name,
            'file': self.file_path,
            'issues': [issue.to_dict() for issue in self.issues],
            'scan_time': self.scan_time,
            'success': self.success,
            'error': self.error_message,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all MEDUSA scanners

    Each scanner implements:
    - File type detection (which files it can scan)
    - Tool availability check (is the scanner installed?)
    - Scanning logic (how to run the scanner)
    - Result parsing (how to interpret scanner output)
    """

    def __init__(self):
        self.name = self.__class__.__name__
        self.tool_name = self.get_tool_name()
        self.tool_path = self._find_tool()

    @abstractmethod
    def get_tool_name(self) -> str:
        """
        Return the name of the CLI tool this scanner uses
        Example: 'bandit', 'shellcheck', 'yamllint'
        """
        pass

    @abstractmethod
    def get_file_extensions(self) -> List[str]:
        """
        Return list of file extensions this scanner handles
        Example: ['.py'], ['.sh', '.bash'], ['.yml', '.yaml']
        """
        pass

    @abstractmethod
    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a single file and return results

        Args:
            file_path: Path to file to scan

        Returns:
            ScannerResult with issues found
        """
        pass

    def can_scan(self, file_path: Path) -> bool:
        """
        Check if this scanner can handle the given file

        Args:
            file_path: Path to file to check

        Returns:
            True if this scanner can scan the file
        """
        return file_path.suffix in self.get_file_extensions()

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Analyze file content and return confidence (0-100) that this scanner
        should handle it. Used to intelligently choose between competing scanners
        for the same file extension (e.g., Ansible vs Kubernetes vs generic YAML).

        Default implementation: low confidence for generic scanners.
        Override in specific scanners (Ansible, Kubernetes) for content-based detection.

        Args:
            file_path: Path to file to analyze

        Returns:
            0-100 confidence score (higher = more confident)
            - 0-20: Low confidence (generic fallback only)
            - 21-50: Medium confidence (some indicators present)
            - 51-80: High confidence (strong indicators)
            - 81-100: Very high confidence (definite match)
        """
        # Default: return low confidence if file extension matches
        if self.can_scan(file_path):
            return 20  # Generic fallback score
        return 0  # Can't scan this file at all

    def is_available(self) -> bool:
        """
        Check if the scanner tool is installed and available

        Returns:
            True if tool is available
        """
        return self.tool_path is not None

    def _find_tool(self) -> Optional[Path]:
        """
        Find the scanner tool in system PATH or active virtual environment

        Returns:
            Path to tool executable, or None if not found
        """
        import os
        import sys

        # WINDOWS FIX: Check installation cache first (handles PATH refresh issue)
        # On Windows, tools installed in current session may not be in PATH yet
        from medusa.platform.tool_cache import ToolCache
        cache = ToolCache()
        if cache.is_cached(self.tool_name):
            # Tool was installed in this session, trust the cache
            # Return a dummy path to indicate it's available
            return Path(f'<cached:{self.tool_name}>')

        # Check virtual environment first
        # Method 1: VIRTUAL_ENV environment variable (set when venv is activated)
        venv_path = os.getenv('VIRTUAL_ENV')

        # Method 2: Detect venv from sys.prefix (works even when not activated)
        if not venv_path and hasattr(sys, 'prefix') and hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                venv_path = sys.prefix

        if venv_path:
            venv_bin = Path(venv_path) / 'bin' / self.tool_name
            if venv_bin.exists() and os.access(str(venv_bin), os.X_OK):
                return venv_bin

        # Fall back to system PATH
        tool_path = shutil.which(self.tool_name)
        return Path(tool_path) if tool_path else None

    def _find_config_file(self, file_path: Path, config_name: str) -> Optional[Path]:
        """
        Find a config file by walking up from the file being scanned.

        Args:
            file_path: The file being scanned
            config_name: Name of config file to find (e.g., '.bandit', '.eslintrc')

        Returns:
            Path to config file if found, None otherwise
        """
        # Start from the file's directory
        current = file_path.parent if file_path.is_file() else file_path

        # Walk up to root looking for config
        while current != current.parent:
            config_path = current / config_name
            if config_path.exists():
                return config_path
            current = current.parent

        # Check root directory
        config_path = current / config_name
        if config_path.exists():
            return config_path

        return None

    def _run_command(self, cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Run a command and return the result

        Args:
            cmd: Command and arguments to run
            timeout: Timeout in seconds

        Returns:
            CompletedProcess result
        """
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

    def get_install_instructions(self) -> str:
        """
        Get installation instructions for this scanner's tool

        Returns:
            Human-readable install instructions
        """
        return f"Install {self.tool_name} to enable {self.name} scanning"


class RuleBasedScanner(BaseScanner):
    """
    Base class for scanners that use YAML rules from medusa/rules/

    Provides:
    - Automatic rule loading from YAML files
    - Pattern matching against loaded rules
    - Issue creation with full metadata (OWASP, CWE, MITRE)
    """

    # Subclasses should define which rule files to load
    RULE_FILES: List[str] = []  # e.g., ['ai_security/prompt_injection.yaml']
    RULE_CATEGORIES: List[str] = []  # e.g., ['prompt_injection', 'jailbreaking']

    def __init__(self):
        super().__init__()
        self._rules = None
        self._rules_loaded = False

    def _load_rules(self):
        """Lazy-load rules from YAML files"""
        if self._rules_loaded:
            return

        from medusa.rules import RuleLoader
        loader = RuleLoader()
        all_rules = loader.load_all_rules()

        # Filter rules by category or file
        self._rules = []
        for rule in all_rules:
            # Match by category
            if self.RULE_CATEGORIES and rule.category in self.RULE_CATEGORIES:
                self._rules.append(rule)
            # Or match by rule ID prefix
            elif hasattr(self, 'RULE_ID_PREFIXES'):
                for prefix in self.RULE_ID_PREFIXES:
                    if rule.id.startswith(prefix):
                        self._rules.append(rule)
                        break

        self._rules_loaded = True

    @property
    def rules(self):
        """Get loaded rules (loads on first access)"""
        if not self._rules_loaded:
            self._load_rules()
        return self._rules

    def _scan_with_rules(self, lines: List[str], file_path: Path = None) -> List[ScannerIssue]:
        """
        Scan lines using loaded YAML rules

        Args:
            lines: List of file lines to scan
            file_path: Optional path for context

        Returns:
            List of ScannerIssue objects
        """
        import re
        issues = []

        for rule in self.rules:
            for i, line in enumerate(lines, 1):
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Map severity string to enum
                            severity_map = {
                                'CRITICAL': Severity.CRITICAL,
                                'HIGH': Severity.HIGH,
                                'MEDIUM': Severity.MEDIUM,
                                'LOW': Severity.LOW,
                                'INFO': Severity.INFO,
                            }
                            severity = severity_map.get(rule.severity, Severity.MEDIUM)

                            # Extract CWE number from string like "CWE-94"
                            cwe_id = None
                            cwe_link = None
                            if rule.cwe:
                                cwe_match = re.search(r'CWE-(\d+)', rule.cwe)
                                if cwe_match:
                                    cwe_id = int(cwe_match.group(1))
                                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

                            issues.append(ScannerIssue(
                                severity=severity,
                                message=rule.message,
                                line=i,
                                rule_id=rule.id,
                                cwe_id=cwe_id,
                                cwe_link=cwe_link
                            ))
                            break  # One issue per line per rule
                    except re.error:
                        # Skip invalid regex patterns
                        continue

        return issues


class ScannerRegistry:
    """
    Registry of all available scanners
    Automatically discovers and manages scanner instances
    """

    def __init__(self):
        self.scanners: List[BaseScanner] = []

    def register(self, scanner: BaseScanner):
        """Register a scanner instance"""
        self.scanners.append(scanner)

    def get_scanner_for_file(self, file_path: Path, config=None) -> Optional[BaseScanner]:
        """
        Find the appropriate scanner for a file using confidence scoring.

        This intelligently chooses between competing scanners (e.g., Ansible vs
        Kubernetes vs YAML) by analyzing file content and selecting the scanner
        with the highest confidence score.

        User overrides (from .medusa.yml) take precedence over confidence scoring,
        allowing manual corrections that are remembered for future scans.

        Args:
            file_path: Path to file
            config: Optional MedusaConfig with scanner overrides

        Returns:
            Scanner instance that can handle the file, or None
        """
        # Check for user-specified override first
        if config and config.scanner_overrides:
            # Try both absolute and relative paths
            file_str = str(file_path)
            relative_path = str(file_path.relative_to(Path.cwd())) if file_path.is_absolute() else file_str

            for override_path, scanner_name in config.scanner_overrides.items():
                # Match if either absolute path or relative path matches
                if file_str.endswith(override_path) or relative_path == override_path:
                    # Find scanner by name
                    for scanner in self.scanners:
                        if scanner.name == scanner_name and scanner.is_available():
                            return scanner

        # No override found, use confidence scoring
        best_scanner = None
        best_confidence = 0

        for scanner in self.scanners:
            # Only consider scanners that are installed
            if not scanner.is_available():
                continue

            # Only consider scanners that can handle this file extension
            if not scanner.can_scan(file_path):
                continue

            # Get confidence score from content analysis
            confidence = scanner.get_confidence_score(file_path)

            # Track the scanner with highest confidence
            if confidence > best_confidence:
                best_confidence = confidence
                best_scanner = scanner

        return best_scanner

    def get_all_scanners(self) -> List[BaseScanner]:
        """Get all registered scanners"""
        return self.scanners

    def get_available_scanners(self) -> List[BaseScanner]:
        """Get only scanners with tools installed"""
        return [s for s in self.scanners if s.is_available()]

    def get_missing_tools(self) -> List[str]:
        """Get list of scanner tools that are not installed"""
        # Also check cache to prevent reinstalling tools that were just installed
        # but aren't yet in PATH (Windows PATH refresh issue)
        from medusa.platform.tool_cache import ToolCache
        cache = ToolCache()
        cached_tools = cache.get_cached_tools()

        missing = []
        for scanner in self.scanners:
            # Skip if tool is available OR in cache
            if scanner.is_available() or scanner.tool_name in cached_tools:
                continue
            missing.append(scanner.tool_name)

        return missing
