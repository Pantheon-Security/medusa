#!/usr/bin/env python3
"""
MEDUSA Base Scanner Class
Abstract base class for all security scanner implementations
"""

from abc import ABC, abstractmethod
from bisect import bisect_left
from time import perf_counter
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import re
import subprocess
import shutil


class Severity(Enum):
    """Issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Module-level constants hoisted out of the inner loop (Task 1.3)
_SEVERITY_MAP = {
    'CRITICAL': Severity.CRITICAL,
    'HIGH': Severity.HIGH,
    'MEDIUM': Severity.MEDIUM,
    'LOW': Severity.LOW,
    'INFO': Severity.INFO,
}
_CWE_RE = re.compile(r'CWE-(\d+)')


def _build_line_offsets(content: str) -> List[int]:
    """Build sorted list of newline positions for O(log n) line lookups."""
    return [i for i, c in enumerate(content) if c == '\n']


def _get_line_number(offsets: List[int], pos: int) -> int:
    """Get 1-based line number for a character position using binary search."""
    return bisect_left(offsets, pos) + 1


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
    rule_url: Optional[str] = None

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
            'rule_url': self.rule_url,
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


# Compiled regexes for defensive file context detection
_DEFENSIVE_FILE_RE = re.compile(
    r'(?:^|/)(?:'
    r'(?:response|input|output|tool|request|schema|data)?[_-]?validator'
    r'|(?:secrets?|credential|token|key)[_-]?scanner'
    r'|audit[_-]?log(?:ger)?'
    r'|(?:file|secure)[_-]?permissions?'
    r'|(?:tool|input|output|request)[_-]?validation'
    r'|(?:content|safety|toxicity)[_-]?(?:filter|checker|moderator)'
    r'|(?:data|input|output)[_-]?sanitiz(?:er|ation)'
    r'|(?:rate|api)[_-]?limiter'
    r'|cert[_-]?pinning'
    r'|settings[_-]?manager'
    r')\.(?:ts|js|py)$', re.IGNORECASE
)
_COMPLIANCE_DIR_RE = re.compile(
    r'(?:^|/)compliance/', re.IGNORECASE
)
_AUTH_LAYER_RE = re.compile(
    r'authenticate(?:MCPRequest|Request)?'
    r'|(?:tool|request)[_-]?validation'
    r'|(?:verify|validate)(?:Auth|Token|Session|Permission)'
    r'|requireAuth|isAuthorized|checkPermission',
    re.IGNORECASE
)
# Issue messages that are FP-prone in defensive/compliance/auth contexts
_DEFENSIVE_FP_MESSAGES = re.compile(
    r'(?i)(?:'
    r'Prompt injection'
    r'|Private Key'
    r'|Credentials? passed'
    r'|Sensitive (?:file|data) (?:exfiltration|in)'
    r'|Destructive operation without'
    r'|Code execution without'
    r'|Data modification without'
    r'|Process execution without'
    r'|Tool restrictions disabled'
    r'|unrestricted tool access'
    r')'
)
_COMPLIANCE_FP_MESSAGES = re.compile(
    r'(?i)(?:'
    r'PII (?:potentially )?in response'
    r'|Path traversal: File (?:read|write)'
    r'|LLM output returned without toxicity'
    r')'
)
_AUTH_LAYER_FP_MESSAGES = re.compile(
    r'(?i)(?:'
    r'Destructive operation without'
    r'|Tool execution without before_tool_callback'
    r'|No after_tool_callback'
    r'|Over-privileged MCP tool'
    r'|Data modification without'
    r')'
)


def is_defensive_security_file(file_path: Path) -> bool:
    """Check if a file is a defensive security tool (validator, scanner, audit logger, etc.)."""
    return bool(_DEFENSIVE_FILE_RE.search(str(file_path)))


def is_compliance_file(file_path: Path) -> bool:
    """Check if a file is in a compliance directory (GDPR, DSAR, data erasure, etc.)."""
    return bool(_COMPLIANCE_DIR_RE.search(str(file_path)))


def has_auth_layer(content: str) -> bool:
    """Check if file content contains an authentication/validation layer."""
    return bool(_AUTH_LAYER_RE.search(content[:20000]))


def filter_contextual_fps(
    issues: List[ScannerIssue],
    file_path: Path,
    content: str,
) -> List[ScannerIssue]:
    """
    Filter out false positives based on file context.

    Removes findings that are FP-prone when the file is:
    - A defensive security tool (validators, scanners, audit loggers)
    - In a compliance directory (GDPR handlers, data export, evidence)
    - Part of an MCP server with its own auth/validation layer
    """
    is_defensive = is_defensive_security_file(file_path)
    is_compliance = is_compliance_file(file_path)
    has_auth = has_auth_layer(content)

    if not is_defensive and not is_compliance and not has_auth:
        return issues

    filtered = []
    for issue in issues:
        msg = issue.message
        # Defensive security files: suppress detection-pattern-on-detection-tool FPs
        if is_defensive and _DEFENSIVE_FP_MESSAGES.search(msg):
            continue
        # Compliance files: suppress GDPR-required behavior FPs
        if is_compliance and _COMPLIANCE_FP_MESSAGES.search(msg):
            continue
        # Auth layer present: suppress "missing validation" FPs
        if has_auth and _AUTH_LAYER_FP_MESSAGES.search(msg):
            continue
        filtered.append(issue)

    return filtered


class BaseScanner(ABC):
    """
    Abstract base class for all MEDUSA scanners

    Each scanner implements:
    - File type detection (which files it can scan)
    - Tool availability check (is the scanner installed?)
    - Scanning logic (how to run the scanner)
    - Result parsing (how to interpret scanner output)
    """

    # When True, this scanner may run on files over MAX_SCAN_FILE_SIZE because
    # it samples/caps internally. Default False: oversized files are skipped to
    # avoid multi-minute regex hangs on large data files.
    supports_large_files = False

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

    def reset(self) -> None:
        """Reset any per-file state. Called before each file scan. Override when a scanner
        accumulates instance-level state (lists, counters) that must not bleed between files."""
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

    def get_confidence_score(self, file_path: Path, content_head: Optional[str] = None) -> int:
        """
        Analyze file content and return confidence (0-100) that this scanner
        should handle it. Used to intelligently choose between competing scanners
        for the same file extension (e.g., Ansible vs Kubernetes vs generic YAML).

        Default implementation: low confidence for generic scanners.
        Override in specific scanners (Ansible, Kubernetes) for content-based detection.

        Args:
            file_path: Path to file to analyze
            content_head: Optional pre-read first 8KB of file content.
                If provided, scanners should use this instead of reading
                the file themselves, avoiding redundant I/O.

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
        import shutil
        from medusa.platform.tool_cache import ToolCache
        cache = ToolCache()
        if cache.is_cached(self.tool_name):
            real_path = shutil.which(self.tool_name)
            if real_path:
                return Path(real_path)
            # Cache is stale — remove it and fall through to full discovery
            cache.remove(self.tool_name)

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

    def _reject_if_dash_prefixed(
        self, file_path: Path, start_time: float
    ) -> Optional['ScannerResult']:
        """
        Argv injection defense (defense-in-depth).

        If a file's basename starts with '-', external tools may re-parse it as
        a CLI option (e.g., '--config=https://evil/rce.yaml' would fetch a
        remote rule file). The primary defense is the '--' separator before
        the path positional; this helper is a secondary guard that refuses to
        invoke any external tool for such filenames.

        Args:
            file_path: Path to file about to be scanned.
            start_time: time.time() captured at scan entry (for scan_time).

        Returns:
            An error ScannerResult if the basename starts with '-', else None.
        """
        import time
        if file_path.name.startswith('-'):
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=(
                    "Skipped (argv injection defense): filename starts with '-'"
                ),
            )
        return None

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

    def is_available(self) -> bool:
        """Rule-based scanners are always available (no external tool needed)."""
        return True

    def _load_rules(self):
        """Lazy-load rules from YAML files"""
        if self._rules_loaded:
            return

        from medusa.rules import get_loader
        loader = get_loader()
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

    # Maximum number of lines to scan with regex rules.
    # Files with more lines than this are data files / generated code
    # and scanning them is both slow and unlikely to find real issues.
    MAX_RULE_SCAN_LINES = 50_000

    def _scan_with_rules(self, lines: List[str], file_path: Path = None) -> List[ScannerIssue]:
        """
        Scan lines using loaded YAML rules

        Args:
            lines: List of file lines to scan
            file_path: Optional path for context

        Returns:
            List of ScannerIssue objects
        """
        issues = []

        # Cap the number of lines we process to avoid hanging on huge
        # data files that happen to match a scannable extension.
        if len(lines) > self.MAX_RULE_SCAN_LINES:
            path_str = str(file_path) if file_path else "<unknown>"
            print(f"⚠️  Skipped regex scan of {path_str} ({len(lines):,} lines exceeds {self.MAX_RULE_SCAN_LINES:,} line limit)")
        scan_lines = lines[:self.MAX_RULE_SCAN_LINES] if len(lines) > self.MAX_RULE_SCAN_LINES else lines

        # Pre-filter rules by file type to avoid unnecessary matching
        file_str = str(file_path) if file_path else ""
        applicable_rules = [r for r in self.rules if r.matches_file_type(file_str)]

        # Rule diagnostics (opt-in, --trace-rules): collected only when enabled.
        # Lazy import avoids a base<-core import cycle; timing is per-RULE (not
        # per-search) so normal scans pay nothing.
        from medusa.core import rule_diag
        _diag = rule_diag._DIAG

        _fine = _diag is not None and _diag.fine
        for rule in applicable_rules:
            _t0 = perf_counter() if _diag else 0.0
            if _fine:
                # Per-rule breadcrumb (targeted single-file re-scan, MEDUSA_TRACE_FINE=1):
                # names the exact rule when a single match hangs uninterruptibly.
                _diag.beat(f"RULE {rule.id} {self.name} @ {file_path}")
            for i, line in enumerate(scan_lines, 1):
                for _pidx, compiled in enumerate(rule._compiled_patterns):
                    try:
                        if compiled.search(line):
                            if _diag:
                                _diag.trace(rule.id, self.name, file_path, i, line, _pidx, rule.severity)
                            severity = _SEVERITY_MAP.get(rule.severity.value, Severity.MEDIUM)

                            # Extract CWE number from string like "CWE-94"
                            cwe_id = None
                            cwe_link = None
                            if rule.cwe:
                                cwe_match = _CWE_RE.search(rule.cwe)
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
            if _diag:
                _diag.record_time(rule.id, self.name, file_path, (perf_counter() - _t0) * 1000.0)

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

    def get_scanner_for_file(self, file_path: Path, config=None,
                             content_head: Optional[str] = None) -> Optional[BaseScanner]:
        """
        Find the appropriate scanner for a file using confidence scoring.

        This intelligently chooses between competing scanners (e.g., Ansible vs
        Kubernetes vs YAML) by analyzing file content and selecting the scanner
        with the highest confidence score.

        User overrides (from medusa.yml) take precedence over confidence scoring,
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
            confidence = scanner.get_confidence_score(file_path, content_head=content_head)

            # Track the scanner with highest confidence
            if confidence > best_confidence:
                best_confidence = confidence
                best_scanner = scanner

        return best_scanner

    def get_scanners_for_file(self, file_path: Path, config=None,
                              content_head: Optional[str] = None) -> List[BaseScanner]:
        """
        Find ALL applicable scanners for a file.

        Returns every available scanner that can handle this file type,
        sorted by confidence (highest first). This ensures YAML-rule-based
        AI security scanners run alongside external tools like Semgrep.

        Args:
            file_path: Path to file
            config: Optional MedusaConfig with scanner overrides
            content_head: Optional pre-read first 8KB of file content,
                passed through to get_confidence_score() to avoid
                redundant file reads across multiple scanners.

        Returns:
            List of scanner instances, sorted by confidence descending
        """
        applicable = []

        for scanner in self.scanners:
            if not scanner.is_available():
                continue
            if not scanner.can_scan(file_path):
                continue

            confidence = scanner.get_confidence_score(file_path, content_head=content_head)
            if confidence > 0:
                applicable.append((confidence, scanner))

        # Sort by confidence descending
        applicable.sort(key=lambda x: x[0], reverse=True)
        return [scanner for _, scanner in applicable]

    def get_all_scanners(self) -> List[BaseScanner]:
        """Get all registered scanners"""
        return self.scanners

    def get_available_scanners(self) -> List[BaseScanner]:
        """Get only scanners with tools installed"""
        return [s for s in self.scanners if s.is_available()]

    def get_unavailable_external_scanners(self) -> List[BaseScanner]:
        """Get scanners that are registered but whose external tools are not installed.
        Excludes built-in scanners (tool_name == 'python') since those always work."""
        return [
            s for s in self.scanners
            if not s.is_available() and s.get_tool_name() != 'python'
        ]

    def get_missing_tools(self) -> List[str]:
        """Get list of scanner tools that are not installed"""
        # Check cache to prevent reinstalling tools that were just installed
        # but aren't yet in PATH (Windows PATH refresh issue)
        from medusa.platform.tool_cache import ToolCache
        from medusa.platform.installers.base import PlatformFilter
        cache = ToolCache()
        cached_tools = cache.get_cached_tools()

        # Also check manifest for tools installed by MEDUSA previously
        # (handles case where cache wasn't populated in older versions)
        try:
            from medusa.platform.install_manifest import get_manifest
            manifest = get_manifest()
            manifest_tools = set(manifest.get_installed_tools())
            # Sync manifest tools to cache for future runs
            for tool in manifest_tools:
                if tool not in cached_tools:
                    cache.mark_installed(tool)
            cached_tools = cached_tools.union(manifest_tools)
        except Exception:
            manifest_tools = set()

        missing = []
        for scanner in self.scanners:
            # Skip if tool is available OR in cache/manifest
            if scanner.is_available() or scanner.tool_name in cached_tools:
                continue
            # Skip if tool is not supported on this platform
            if not PlatformFilter.is_supported(scanner.tool_name):
                continue
            missing.append(scanner.tool_name)

        return missing
