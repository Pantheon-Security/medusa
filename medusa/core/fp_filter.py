#!/usr/bin/env python3
"""
MEDUSA False Positive Filter

Intelligent post-scan filter to reduce false positives using:
1. Security wrapper pattern detection
2. Docstring/comment exclusion
3. Context-aware class analysis
4. Known-safe pattern database
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import yaml


class FPPatternSchemaError(ValueError):
    """Raised when an FP pattern YAML file has invalid schema."""


class FPReason(Enum):
    """Reason a finding was classified as likely false positive"""
    SECURITY_WRAPPER = "security_wrapper"  # Credential wrapped in secure class
    DOCSTRING = "docstring"  # Found in docstring/comment
    SECURITY_MODULE = "security_module"  # File is a security module
    SAFE_PATTERN = "safe_pattern"  # Matches known safe pattern
    PARAMETER_TO_SECURE = "parameter_to_secure"  # Parameter passed to secure handler
    TEST_FILE = "test_file"  # In test file
    EXAMPLE_FILE = "example_file"  # In example/docs
    UTILITY_FILE = "utility_file"  # In tools/scripts/utils directory
    CACHE_KEY = "cache_key"  # Hash used for cache key generation (non-crypto)
    DUPLICATE_DETECTION = "duplicate_detection"  # Hash for file similarity (non-crypto)
    INTENTIONAL_WEAK = "intentional_weak"  # Self-documenting insecure usage
    MOCK_FILE = "mock_file"  # Mock/fake/stub test utilities
    TEST_DOCKERFILE = "test_dockerfile"  # Test/CI Dockerfile
    CODE_STYLE = "code_style"  # Code style / linting (not security)
    ML_COMMON = "ml_common"  # Common ML/data science pattern (not vuln)
    BUILD_OUTPUT = "build_output"  # Finding in build/compiled output
    GENERATED_CODE = "generated_code"  # Finding in auto-generated code
    KNOWN_PATTERN = "known_pattern"  # Known FP from benchmark analysis
    DEFENSIVE_SECURITY = "defensive_security"  # Security tool flagging its own detection code
    MCP_PROTOCOL = "mcp_protocol"  # Standard MCP protocol behavior with proper auth
    COMPLIANCE_CODE = "compliance_code"  # GDPR/DSAR/compliance code doing its legal job
    DESCRIPTION_STRING = "description_string"  # Tool description / documentation string
    INFRASTRUCTURE_CODE = "infrastructure_code"  # Internal infra (logging, cert-pinning, SIEM)


@dataclass
class FilterResult:
    """Result of FP filtering on a finding"""
    is_likely_fp: bool = False
    confidence: float = 0.0  # 0-1, how confident we are it's FP
    reason: Optional[FPReason] = None
    explanation: str = ""
    original_severity: str = ""
    adjusted_severity: Optional[str] = None


@dataclass
class FPPattern:
    """A known false positive pattern"""
    name: str
    scanner: Optional[str]  # Which scanner this applies to (None = any scanner)
    pattern: str  # Regex pattern to match in code
    context_pattern: Optional[str] = None  # Pattern in surrounding context
    file_pattern: Optional[str] = None  # File path pattern
    file_pattern_negate: bool = False  # If True, filter when file does NOT match
    reason: FPReason = FPReason.SAFE_PATTERN
    confidence: float = 0.8
    description: Optional[str] = None  # Human-readable explanation
    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False, init=False)
    _compiled_file: Optional[re.Pattern] = field(default=None, repr=False, init=False)
    _compiled_context: Optional[re.Pattern] = field(default=None, repr=False, init=False)

    def __post_init__(self):
        if self.pattern:
            self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
        if self.file_pattern:
            self._compiled_file = re.compile(self.file_pattern, re.IGNORECASE)
        if self.context_pattern:
            self._compiled_context = re.compile(self.context_pattern, re.IGNORECASE)


class FalsePositiveFilter:
    """
    Intelligent false positive filter for MEDUSA scan results
    """

    # Security wrapper classes that PROTECT credentials (Python and TypeScript)
    SECURITY_WRAPPERS = {
        # Python
        'SecureString', 'SecureCredential', 'SecurePassword', 'SecureToken',
        'ProtectedString', 'EncryptedString', 'SafeCredential',
        'SecretString', 'SecureMemory', 'ActiveCredential',
        # Common crypto/security libraries
        'Fernet', 'AESGCM', 'ChaCha20Poly1305',
        'PasswordHasher', 'Argon2Hasher', 'BcryptHasher',
        # TypeScript/JavaScript
        'SecureObject', 'CryptoKey', 'SecureBuffer',
    }

    # Methods that indicate secure handling (Python and TypeScript)
    SECURITY_METHODS = {
        'wipe', 'secure_wipe', 'clear', 'destroy', 'encrypt', 'decrypt',
        'hash', 'hash_password', 'verify_password', 'protect', 'secure',
        'zero_memory', 'scrub', 'sanitize', 'mask',
        # TypeScript/JavaScript
        'dispose', 'cleanup', 'zeroFill', 'secureWipe',
    }

    # File patterns that indicate security modules (not vulnerabilities)
    SECURITY_MODULE_PATTERNS = [
        r'secure[_-]?memory', r'secure[_-]?storage', r'secure[_-]?credential',
        r'crypto', r'encryption', r'security[_/]', r'auth[_/]',
        r'password[_-]?hash', r'secret[_-]?manager',
        # TypeScript naming patterns
        r'secure-memory', r'secure-storage', r'utils/secure',
    ]

    # Pre-compiled alternation regexes for hot-path methods
    # _check_security_wrapper: single regex instead of iterating SECURITY_WRAPPERS
    _WRAPPER_RE = re.compile(
        r'(?:' + '|'.join(re.escape(w) for w in SECURITY_WRAPPERS) + r')\s*\(',
    )
    # _check_security_wrapper: single regex instead of iterating SECURITY_METHODS
    _METHOD_RE = re.compile(
        r'\.(?:' + '|'.join(re.escape(m) for m in SECURITY_METHODS) + r')\s*\(',
    )
    # _check_security_module: single bare-substring regex (case-insensitive)
    # replacing 19 separate `method in context.lower()` scans. Same semantics
    # (substring presence), one pass — NOT _METHOD_RE, which requires `.m(` syntax.
    _SECURITY_METHOD_SUBSTR_RE = re.compile(
        '|'.join(re.escape(m) for m in SECURITY_METHODS), re.IGNORECASE
    )
    # _check_security_module: single regex instead of iterating SECURITY_MODULE_PATTERNS
    _SECURITY_MODULE_RE = re.compile(
        '|'.join(SECURITY_MODULE_PATTERNS),
        re.IGNORECASE,
    )
    # _check_test_file: pre-compiled pattern groups
    _TEST_FILE_RE = re.compile(
        '|'.join([
            r'[/]tests?[/_]', r'_test\.py$', r'test_.*\.py$',
            r'[/]specs?[/_]', r'\.spec\.(js|ts|tsx|jsx)$',
            r'__tests__', r'[/]fixtures?[/_]',
            r'\.test\.(js|ts|tsx|jsx)$',
            r'\.e2e\.test\.', r'\.live\.test\.', r'\.fuzz\.test\.',
            r'test[-_]helper',
            r'_test\.go$',
            r'testdata[/_]',
            r'src/test/resources[/_]',
        ])
    )
    _MOCK_FILE_RE = re.compile(
        '|'.join([
            r'mock[s]?\.go$', r'_mock\.go$', r'mock_.*\.go$',
            r'fake[s]?\.go$', r'_fake\.go$', r'fake_.*\.go$',
            r'stub[s]?\.go$', r'_stub\.go$',
            r'mocks?[/_]', r'fakes?[/_]', r'stubs?[/_]',
            r'\.mock\.(js|ts)$', r'__mocks__[/_]',
        ])
    )
    _EXAMPLE_FILE_RE = re.compile(
        '|'.join([
            r'examples?[/_]',
            r'samples?[/_]',
            r'demos?[/_]',
            r'tutorials?[/_]',
            r'quickstart[/_]',
            r'getting[_-]?started[/_]',
        ])
    )
    _TOOLS_FILE_RE = re.compile(
        '|'.join([
            r'tools?[/_]',
            r'scripts?[/_]',
            r'utils?[/_]',
            r'helpers?[/_]',
            r'contrib[/_]',
        ])
    )

    # Known FP patterns - loaded from medusa/core/fp_patterns/*.yaml
    # via load_known_fp_patterns() (see bottom of file)
    KNOWN_FP_PATTERNS: List[FPPattern] = []


    def __init__(self, source_root: Optional[Path] = None, screening: bool = False):
        """
        Initialize the FP filter

        Args:
            source_root: Root directory of source code for context analysis
            screening: Target-vetting mode (e.g. `medusa scan --git` pre-install
                screening). When True, real attack / high-severity security
                findings are NOT suppressed merely for living in tools/, tests/,
                examples/, or dataset files — in a poisoned/vulnerable target
                those directories ARE the attack surface. Default False keeps the
                precision-tight behavior for scanning your own clean codebase
                (no clean-code false-positive regression).
        """
        self.source_root = source_root or Path.cwd()
        self.screening = screening
        self._file_cache: Dict[str, List[str]] = {}
        self._class_cache: Dict[str, Dict] = {}

    def filter_finding(
        self,
        finding: Dict,
        source_context: Optional[List[str]] = None
    ) -> FilterResult:
        """
        Analyze a finding and determine if it's likely a false positive

        Args:
            finding: The finding dict from scanner
            source_context: Optional list of source lines around the finding

        Returns:
            FilterResult with FP analysis
        """
        result = FilterResult(original_severity=finding.get('severity', 'MEDIUM'))

        file_path = finding.get('file', '')
        line_num = finding.get('line') or 0
        scanner = finding.get('scanner', '').lower()
        issue = finding.get('issue', '')

        # Load source context if not provided
        if source_context is None:
            source_context = self._get_source_context(file_path, line_num)

        # Check each filter in order of confidence
        checks = [
            self._check_security_module,
            self._check_docstring,
            self._check_security_wrapper,
            self._check_known_patterns,
        ]

        # Screening mode: when vetting a target repo (not scanning your own clean
        # code), do not let the test/example/utility-file heuristic bury a real
        # attack or high-severity security finding — in a vulnerable/poisoned
        # repo those locations (tools_plugins/, datasets, jailbreak .md/.csv) are
        # exactly where the malicious content lives. The genuinely-safe checks
        # (security-module self-detection, real docstrings, known FP patterns)
        # still run in all modes.
        severity = (finding.get('severity') or 'MEDIUM').upper()
        relax_context_fp = self.screening and severity in ('CRITICAL', 'HIGH')
        if not relax_context_fp:
            checks.append(self._check_test_file)

        for check in checks:
            check_result = check(finding, source_context)
            if check_result.is_likely_fp and check_result.confidence > result.confidence:
                result = check_result
                result.original_severity = finding.get('severity', 'MEDIUM')

        # Adjust severity based on confidence
        if result.is_likely_fp:
            result.adjusted_severity = self._adjust_severity(
                result.original_severity,
                result.confidence
            )

        return result

    def filter_findings(self, findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Filter a list of findings, separating likely FPs

        Args:
            findings: List of finding dicts

        Returns:
            Tuple of (filtered_findings, likely_fps)
        """
        filtered = []
        likely_fps = []

        for finding in findings:
            result = self.filter_finding(finding)

            # Add filter metadata to finding
            finding['fp_analysis'] = {
                'is_likely_fp': result.is_likely_fp,
                'confidence': result.confidence,
                'reason': result.reason.value if result.reason else None,
                'explanation': result.explanation,
            }

            if result.is_likely_fp and result.confidence >= 0.8:
                likely_fps.append(finding)
            else:
                # Adjust severity if moderate confidence FP
                if result.adjusted_severity:
                    finding['original_severity'] = finding.get('severity')
                    finding['severity'] = result.adjusted_severity
                filtered.append(finding)

        return filtered, likely_fps

    def _check_security_module(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check if finding is in a security module (which handles secrets safely)"""
        raw_path = finding.get('file', '')
        # Use relative path so parent directory names (e.g. "mcp-security/")
        # don't match security[_/] and cause over-suppression.
        try:
            file_path = str(Path(raw_path).relative_to(self.source_root)).lower()
        except (ValueError, TypeError):
            file_path = raw_path.lower()

        if self._SECURITY_MODULE_RE.search(file_path):
            # Additional check: does the file have security methods?
            full_context = '\n'.join(context)
            has_security_methods = bool(self._SECURITY_METHOD_SUBSTR_RE.search(full_context))

            if has_security_methods:
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.85,
                    reason=FPReason.SECURITY_MODULE,
                    explanation=f"File appears to be a security module implementing credential protection (contains security methods like wipe/encrypt)"
                )

        return FilterResult()

    def _check_docstring(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check if finding is in a docstring or comment (multi-language)"""
        # MCP/agent scanners: docstrings ARE the attack surface (tool descriptions)
        scanner = finding.get('scanner', '').lower()
        if scanner in ('mcpserverscanner', 'mcp_server_scanner', 'mcp-server-scanner',
                        'mcpconfigscanner', 'toolcallbackscanner', 'multiagentscanner'):
            return FilterResult()

        line_num = finding.get('line') or 0

        if not context or line_num <= 0:
            return FilterResult()

        # Get the specific line (adjust for 0-indexing)
        line_idx = min(line_num - 1, len(context) - 1)
        if line_idx < 0:
            return FilterResult()

        line = context[line_idx] if line_idx < len(context) else ""
        stripped = line.strip()

        # --- Single-line comment detection (all languages) ---

        # Python / Shell / Ruby / Perl / YAML
        if stripped.startswith('#'):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is in a # comment line"
            )

        # C-family / Go / Java / TypeScript / Rust / Swift / Kotlin
        if stripped.startswith('//'):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is in a // comment line"
            )

        # SQL / Lua / Haskell (-- prefix)
        if stripped.startswith('-- ') or stripped.startswith('--\t') or stripped == '--':
            return FilterResult(
                is_likely_fp=True,
                confidence=0.93,
                reason=FPReason.DOCSTRING,
                explanation="Finding is in a -- comment line"
            )

        # HTML / XML comment
        if stripped.startswith('<!--'):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.93,
                reason=FPReason.DOCSTRING,
                explanation="Finding is in an HTML/XML <!-- --> comment"
            )

        # JSDoc / Javadoc continuation line (starts with *)
        if stripped.startswith('* ') or stripped.startswith('*/') or stripped == '*':
            for i in range(line_idx - 1, max(line_idx - 30, -1), -1):
                if i >= len(context):
                    continue
                prev = context[i].strip()
                if prev.startswith('/*'):
                    return FilterResult(
                        is_likely_fp=True,
                        confidence=0.95,
                        reason=FPReason.DOCSTRING,
                        explanation="Finding is in a /* ... */ block comment"
                    )
                if prev.endswith('*/'):
                    break

        # --- Block comment detection: /* ... */ ---
        in_block_comment = False
        for i in range(line_idx, -1, -1):
            if i >= len(context):
                continue
            check_line = context[i]
            if i < line_idx and '*/' in check_line:
                break
            if '/*' in check_line:
                if check_line.count('/*') > check_line.count('*/'):
                    in_block_comment = True
                break

        if in_block_comment:
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is inside a /* ... */ block comment"
            )

        # --- Python docstring detection ---
        # Count triple-quote delimiters over the prefix WITHOUT building one big
        # joined string per finding. Summing per-line counts is identical: a
        # `"""`/`'''` token never spans a newline, and join inserts only '\n'.
        prefix = context[:line_idx + 1]
        triple_double = sum(ln.count('"""') for ln in prefix)
        triple_single = sum(ln.count("'''") for ln in prefix)

        if triple_double % 2 == 1 or triple_single % 2 == 1:
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is inside a Python docstring"
            )

        # Check for inline docstring on the line
        if '"""' in line or "'''" in line:
            issue_keywords = ['password', 'credential', 'secret', 'token', 'key']
            for keyword in issue_keywords:
                if keyword in finding.get('issue', '').lower():
                    if keyword in line.lower() and ('"""' in line or "'''" in line):
                        return FilterResult(
                            is_likely_fp=True,
                            confidence=0.90,
                            reason=FPReason.DOCSTRING,
                            explanation=f"Finding appears to be in docstring (keyword '{keyword}' in quoted string)"
                        )

        return FilterResult()

    def _check_security_wrapper(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check if credential is being passed to a security wrapper"""
        line_num = finding.get('line') or 0

        if not context or line_num <= 0:
            return FilterResult()

        # Get lines around the finding
        start_idx = max(0, line_num - 5)
        end_idx = min(len(context), line_num + 5)
        local_context = '\n'.join(context[start_idx:end_idx])

        # Check for security wrapper usage (pre-compiled alternation regex)
        wrapper_match = self._WRAPPER_RE.search(local_context)
        if wrapper_match:
            matched_text = wrapper_match.group(0).rstrip('(').rstrip()
            return FilterResult(
                is_likely_fp=True,
                confidence=0.90,
                reason=FPReason.SECURITY_WRAPPER,
                explanation=f"Credential is wrapped in security class '{matched_text}' for protection"
            )

        # Check for security method calls (pre-compiled alternation regex)
        method_match = self._METHOD_RE.search(local_context)
        if method_match:
            matched_text = method_match.group(0).lstrip('.').rstrip('(').rstrip()
            return FilterResult(
                is_likely_fp=True,
                confidence=0.80,
                reason=FPReason.SECURITY_WRAPPER,
                explanation=f"Code uses security method '{matched_text}' for credential protection"
            )

        return FilterResult()

    def _check_known_patterns(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check against known FP patterns"""
        scanner = finding.get('scanner', '').lower()
        file_path = finding.get('file', '')
        issue_text = finding.get('issue', '')
        line_num = finding.get('line') or 0

        # Screening mode: for real attack/high-severity findings, skip the
        # *file-location* context guards (docs / tests / examples / utility) that
        # exist to silence attack signatures in a clean codebase's docs/datasets.
        # When vetting a target those locations are the attack surface. The
        # content-safety guards (security wrappers, safe patterns, rule-definition
        # files) still apply.
        relax_context_fp = (
            self.screening
            and str(finding.get('severity', '')).upper() in ('CRITICAL', 'HIGH')
        )

        # Get the line and surrounding context (may be empty for external tools)
        line = ""
        broader_context = ""
        if context:
            line_idx = min(line_num - 1, len(context) - 1) if line_num and line_num > 0 else 0
            line = context[line_idx] if 0 <= line_idx < len(context) else ""
            start_idx = max(0, line_idx - 20)
            end_idx = min(len(context), line_idx + 10)
            broader_context = '\n'.join(context[start_idx:end_idx])

        best_result = FilterResult()

        # Use pre-bucketed dict: only check patterns for this scanner + universal patterns.
        # Avoids iterating all 514 patterns per finding (reduces to ~30-50 candidates).
        candidates = (
            self._FP_BY_SCANNER.get(scanner, []) +
            self._FP_BY_SCANNER.get('_any_', [])
        )

        _CONTEXT_FP_REASONS = {
            FPReason.DOCSTRING, FPReason.TEST_FILE,
            FPReason.EXAMPLE_FILE, FPReason.UTILITY_FILE,
        }
        for fp_pattern in candidates:

            # Screening: don't let a file-location guard bury a real attack finding
            if relax_context_fp and fp_pattern.reason in _CONTEXT_FP_REASONS:
                continue

            # Skip if this pattern can't beat current best
            if fp_pattern.confidence <= best_result.confidence:
                continue

            # Check file pattern (supports negation via file_pattern_negate)
            if fp_pattern._compiled_file:
                matches_file = bool(fp_pattern._compiled_file.search(file_path))
                if fp_pattern.file_pattern_negate:
                    # Filter when file does NOT match the pattern
                    if matches_file:
                        continue
                else:
                    # Normal: filter when file DOES match the pattern
                    if not matches_file:
                        continue

            # Check main pattern against source line OR issue text
            compiled = fp_pattern._compiled_pattern
            line_match = line and compiled and compiled.search(line)
            issue_match = issue_text and compiled and compiled.search(issue_text)
            if not line_match and not issue_match:
                continue

            # Check context pattern if specified
            if fp_pattern._compiled_context:
                if not broader_context or not fp_pattern._compiled_context.search(broader_context):
                    continue

            # Pattern matched - track best (highest confidence) match
            best_result = FilterResult(
                is_likely_fp=True,
                confidence=fp_pattern.confidence,
                reason=fp_pattern.reason,
                explanation=f"Matches known safe pattern: {fp_pattern.name}"
            )

        return best_result

    def _check_test_file(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check if finding is in a test file, mock file, or example directory"""
        raw_path = finding.get('file', '')
        # Use path relative to scan root so the repo name itself doesn't
        # trigger demo/test/example heuristics (e.g. "mcp-exploit-demo/server.py"
        # should NOT match the demo/ pattern).
        try:
            file_path = str(Path(raw_path).relative_to(self.source_root)).lower()
        except (ValueError, TypeError):
            file_path = raw_path.lower()

        # Mock/fake file patterns (highest confidence, check first)
        if self._MOCK_FILE_RE.search(file_path):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.92,  # High confidence for mock files
                reason=FPReason.MOCK_FILE,
                explanation="Finding is in a mock/fake/stub file (test infrastructure)"
            )

        # Test file patterns
        if self._TEST_FILE_RE.search(file_path):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.85,  # Test files overwhelmingly contain test data
                reason=FPReason.TEST_FILE,
                explanation="Finding is in a test file (may contain intentional test credentials)"
            )

        # Example/demo/sample directory patterns
        if self._EXAMPLE_FILE_RE.search(file_path):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.80,  # Examples/demos are educational, not production
                reason=FPReason.EXAMPLE_FILE,
                explanation="Finding is in an example/demo directory (educational code)"
            )

        # Tools/scripts directory patterns (lower confidence)
        if self._TOOLS_FILE_RE.search(file_path):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.50,  # Low confidence - tools may have real issues
                reason=FPReason.UTILITY_FILE,
                explanation="Finding is in a tools/scripts directory (utility code)"
            )

        return FilterResult()

    def _get_source_context(
        self,
        file_path: str,
        line_num: int,
        context_lines: int = 50
    ) -> List[str]:
        """Load source file and return lines around the finding"""
        if not file_path:
            return []

        # Check cache
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        # Try to load file
        try:
            full_path = self.source_root / file_path
            if not full_path.exists():
                full_path = Path(file_path)

            if full_path.exists():
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    self._file_cache[file_path] = lines
                    return lines
        except Exception:
            pass

        return []

    def _adjust_severity(self, original: str, fp_confidence: float) -> Optional[str]:
        """Adjust severity based on FP confidence"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

        try:
            idx = severity_order.index(original.upper())
        except ValueError:
            return None

        # Higher confidence = more reduction
        if fp_confidence >= 0.9:
            reduction = 2
        elif fp_confidence >= 0.7:
            reduction = 1
        else:
            reduction = 0

        new_idx = min(idx + reduction, len(severity_order) - 1)
        return severity_order[new_idx]

    def get_stats(self, filtered: List[Dict], fps: List[Dict]) -> Dict:
        """Get statistics from pre-computed filter results (avoids double-filtering)"""
        total = len(filtered) + len(fps)

        fp_by_reason = {}
        for f in fps:
            reason = f.get('fp_analysis', {}).get('reason', 'unknown')
            fp_by_reason[reason] = fp_by_reason.get(reason, 0) + 1

        fp_by_scanner = {}
        for f in fps:
            scanner = f.get('scanner', 'unknown')
            fp_by_scanner[scanner] = fp_by_scanner.get(scanner, 0) + 1

        return {
            'total_findings': total,
            'likely_fps': len(fps),
            'retained': len(filtered),
            'fp_rate': len(fps) / total if total else 0,
            'by_reason': fp_by_reason,
            'by_scanner': fp_by_scanner,
        }


# Convenience function
def filter_scan_results(
    findings: List[Dict],
    source_root: Optional[Path] = None
) -> Tuple[List[Dict], List[Dict], Dict]:
    """
    Filter scan results for false positives

    Args:
        findings: List of finding dicts from scan
        source_root: Root directory of source code

    Returns:
        Tuple of (filtered_findings, likely_fps, stats)
    """
    fp_filter = FalsePositiveFilter(source_root)
    filtered, fps = fp_filter.filter_findings(findings)
    stats = fp_filter.get_stats(filtered, fps)
    return filtered, fps, stats


# -------------------------------------------------------------------------
# YAML loader for the known-FP pattern database.
#
# The data lives in medusa/core/fp_patterns/*.yaml (one file per scanner,
# plus _universal.yaml for patterns that apply to any scanner). This loader
# parses them into FPPattern objects preserving file-order and entry-order.
# -------------------------------------------------------------------------

_FP_PATTERN_REQUIRED_KEYS = {"name", "pattern", "reason", "confidence"}
_FP_PATTERN_OPTIONAL_KEYS = {
    "context_pattern",
    "file_pattern",
    "file_pattern_negate",
    "description",
}
_FP_PATTERN_ALLOWED_KEYS = _FP_PATTERN_REQUIRED_KEYS | _FP_PATTERN_OPTIONAL_KEYS
_FP_FILE_ALLOWED_KEYS = {"scanner", "patterns"}


def load_known_fp_patterns(
    patterns_dir: Optional[Path] = None,
) -> List[FPPattern]:
    """
    Load KNOWN_FP_PATTERNS from the per-scanner YAML database.

    Args:
        patterns_dir: Directory containing *.yaml files. Defaults to
            ``medusa/core/fp_patterns/`` relative to this module.

    Returns:
        Flat list of FPPattern objects in deterministic order:
        filename ASCII-sorted, then source order within each file.

    Raises:
        FPPatternSchemaError: If a YAML file violates the schema.
    """
    if patterns_dir is None:
        patterns_dir = Path(__file__).parent / "fp_patterns"

    patterns: List[FPPattern] = []

    # Sorted ASCII (default sorted() is bytewise) so _universal.yaml (underscore
    # prefix, 0x5F) sorts before letters.
    yaml_files = sorted(patterns_dir.glob("*.yaml"))

    for yaml_path in yaml_files:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data is None:
            # Empty file; skip silently.
            continue

        if not isinstance(data, dict):
            raise FPPatternSchemaError(
                f"{yaml_path.name}: top-level YAML must be a mapping, got {type(data).__name__}"
            )

        unknown_top = set(data.keys()) - _FP_FILE_ALLOWED_KEYS
        if unknown_top:
            raise FPPatternSchemaError(
                f"{yaml_path.name}: unknown top-level keys: {sorted(unknown_top)}"
            )

        scanner = data.get("scanner")  # None for _universal
        if scanner is not None and not isinstance(scanner, str):
            raise FPPatternSchemaError(
                f"{yaml_path.name}: 'scanner' must be a string or null, got {type(scanner).__name__}"
            )

        entries = data.get("patterns") or []
        if not isinstance(entries, list):
            raise FPPatternSchemaError(
                f"{yaml_path.name}: 'patterns' must be a list, got {type(entries).__name__}"
            )

        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise FPPatternSchemaError(
                    f"{yaml_path.name}[{idx}]: pattern entry must be a mapping, "
                    f"got {type(entry).__name__}"
                )

            entry_keys = set(entry.keys())
            missing = _FP_PATTERN_REQUIRED_KEYS - entry_keys
            if missing:
                raise FPPatternSchemaError(
                    f"{yaml_path.name}[{idx}] (name={entry.get('name')!r}): "
                    f"missing required keys: {sorted(missing)}"
                )

            unknown = entry_keys - _FP_PATTERN_ALLOWED_KEYS
            if unknown:
                raise FPPatternSchemaError(
                    f"{yaml_path.name}[{idx}] (name={entry.get('name')!r}): "
                    f"unknown keys: {sorted(unknown)}"
                )

            reason_name = entry["reason"]
            if not isinstance(reason_name, str):
                raise FPPatternSchemaError(
                    f"{yaml_path.name}[{idx}] (name={entry.get('name')!r}): "
                    f"'reason' must be a string, got {type(reason_name).__name__}"
                )
            try:
                reason = FPReason[reason_name]
            except KeyError:
                raise FPPatternSchemaError(
                    f"{yaml_path.name}[{idx}] (name={entry.get('name')!r}): "
                    f"'reason' must be one of {sorted(m.name for m in FPReason)}, "
                    f"got {reason_name!r}"
                )

            kwargs = {
                "name": entry["name"],
                "scanner": scanner,  # top-level is authoritative
                "pattern": entry["pattern"],
                "context_pattern": entry.get("context_pattern"),
                "file_pattern": entry.get("file_pattern"),
                "file_pattern_negate": entry.get("file_pattern_negate", False),
                "reason": reason,
                "confidence": entry["confidence"],
                "description": entry.get("description"),
            }
            patterns.append(FPPattern(**kwargs))

    return patterns


# Load the known-FP pattern database from per-scanner YAML files in
# medusa/core/fp_patterns/. See load_known_fp_patterns() above.
KNOWN_FP_PATTERNS = load_known_fp_patterns()
FalsePositiveFilter.KNOWN_FP_PATTERNS = KNOWN_FP_PATTERNS

# Pre-bucket patterns by scanner name to avoid iterating all patterns per finding.
# Patterns with no scanner restriction go into '_any_'.
_fp_by_scanner: Dict[str, list] = {}
for _p in KNOWN_FP_PATTERNS:
    _key = (_p.scanner or '').lower() or '_any_'
    _fp_by_scanner.setdefault(_key, []).append(_p)
FalsePositiveFilter._FP_BY_SCANNER = _fp_by_scanner
