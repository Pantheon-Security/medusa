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


class FPReason(Enum):
    """Reason a finding was classified as likely false positive"""
    SECURITY_WRAPPER = "security_wrapper"  # Credential wrapped in secure class
    DOCSTRING = "docstring"  # Found in docstring/comment
    SECURITY_MODULE = "security_module"  # File is a security module
    SAFE_PATTERN = "safe_pattern"  # Matches known safe pattern
    PARAMETER_TO_SECURE = "parameter_to_secure"  # Parameter passed to secure handler
    TEST_FILE = "test_file"  # In test file
    EXAMPLE_FILE = "example_file"  # In example/docs
    CACHE_KEY = "cache_key"  # Hash used for cache key generation (non-crypto)
    DUPLICATE_DETECTION = "duplicate_detection"  # Hash for file similarity (non-crypto)
    INTENTIONAL_WEAK = "intentional_weak"  # Self-documenting insecure usage
    MOCK_FILE = "mock_file"  # Mock/fake/stub test utilities
    TEST_DOCKERFILE = "test_dockerfile"  # Test/CI Dockerfile


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
    scanner: str  # Which scanner this applies to
    pattern: str  # Regex pattern to match in code
    context_pattern: Optional[str] = None  # Pattern in surrounding context
    file_pattern: Optional[str] = None  # File path pattern
    reason: FPReason = FPReason.SAFE_PATTERN
    confidence: float = 0.8


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

    # Known FP patterns by scanner
    KNOWN_FP_PATTERNS: List[FPPattern] = [
        # agentmemoryscanner - security wrapper patterns
        FPPattern(
            name="credential_to_secure_wrapper",
            scanner="agentmemoryscanner",
            pattern=r'(credential|password|secret|token)\s*[=:]\s*(SecureString|SecureCredential|SecurePassword)',
            reason=FPReason.SECURITY_WRAPPER,
            confidence=0.95,
        ),
        FPPattern(
            name="secure_class_parameter",
            scanner="agentmemoryscanner",
            pattern=r'def\s+__init__\s*\([^)]*\b(credential|password|secret|token)\s*:',
            context_pattern=r'class\s+Secure|class\s+Protected|class\s+Safe',
            reason=FPReason.PARAMETER_TO_SECURE,
            confidence=0.90,
        ),
        FPPattern(
            name="credential_in_docstring",
            scanner="agentmemoryscanner",
            pattern=r'("""|\'\'\'|#).*\b(credential|password|secret|token)\b',
            reason=FPReason.DOCSTRING,
            confidence=0.95,
        ),
        # TypeScript security class constructor
        FPPattern(
            name="ts_secure_class_constructor",
            scanner="agentmemoryscanner",
            pattern=r'constructor\s*\([^)]*\b(credential|password|secret|token)\s*:',
            context_pattern=r'class\s+Secure|class\s+Protected|export\s+class\s+Secure',
            reason=FPReason.PARAMETER_TO_SECURE,
            confidence=0.90,
        ),
        # TypeScript new SecureClass instantiation
        FPPattern(
            name="ts_new_secure_wrapper",
            scanner="agentmemoryscanner",
            pattern=r'new\s+(SecureString|SecureCredential|SecureObject)\s*\(',
            reason=FPReason.SECURITY_WRAPPER,
            confidence=0.95,
        ),
        # TypeScript/JS test placeholders
        FPPattern(
            name="ts_test_placeholder",
            scanner="agentmemoryscanner",
            pattern=r'(test|placeholder|dummy|mock|example|sample).*[\'\"](password|secret|token|credential)',
            file_pattern=r'\.(test|spec)\.(ts|js)$|tests?/',
            reason=FPReason.TEST_FILE,
            confidence=0.90,
        ),
        # TypeScript JSDoc comments
        FPPattern(
            name="ts_jsdoc_credential",
            scanner="agentmemoryscanner",
            pattern=r'(/\*\*|\*|//).*\b(credential|password|secret|token)\b',
            reason=FPReason.DOCSTRING,
            confidence=0.95,
        ),

        # pythonscanner - subprocess patterns
        FPPattern(
            name="subprocess_hardcoded_command",
            scanner="pythonscanner",
            pattern=r'subprocess\.(run|call|Popen)\s*\(\s*\[[\'"]\w+',
            reason=FPReason.SAFE_PATTERN,
            confidence=0.70,  # Lower - still review
        ),
        FPPattern(
            name="try_except_pass_cleanup",
            scanner="pythonscanner",
            pattern=r'except.*:\s*pass',
            context_pattern=r'(finally|__del__|cleanup|close|shutdown|teardown)',
            reason=FPReason.SAFE_PATTERN,
            confidence=0.60,
        ),

        # aicontextscanner - documentation patterns
        FPPattern(
            name="upload_in_docs",
            scanner="aicontextscanner",
            pattern=r'(upload|publish|push)\s+(to\s+)?(pypi|npm|registry)',
            file_pattern=r'\.(md|rst|txt)$|README|CHANGELOG|docs/',
            reason=FPReason.DOCSTRING,
            confidence=0.90,
        ),

        # =========================================================================
        # Go/Semgrep: Non-cryptographic hash usage (cache keys, dedup, temp files)
        # Source: FileBrowser FP analysis 2026-01-04
        # =========================================================================

        # MD5/SHA1 for cache key generation (directory sharding like git)
        FPPattern(
            name="go_hash_cache_key",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            context_pattern=r'(filepath\.Join|cache|Cache|cacheKey|cacheHash|\.dir)',
            reason=FPReason.CACHE_KEY,
            confidence=0.90,
        ),
        # Hash output used for directory sharding (hash[:1], hash[1:3])
        FPPattern(
            name="go_hash_directory_sharding",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            context_pattern=r'hash\[:\d+\]|hash\[\d+:\d+\]',
            reason=FPReason.CACHE_KEY,
            confidence=0.92,
        ),
        # MD5/SHA1 for temp file naming in uploads
        FPPattern(
            name="go_hash_upload_temp",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            context_pattern=r'(uploadID|tempFile|chunkID|uploads/|temp/)',
            reason=FPReason.CACHE_KEY,
            confidence=0.88,
        ),
        # MD5 for duplicate file detection (partial file sampling)
        FPPattern(
            name="go_md5_duplicate_detection",
            scanner="semgrepscanner",
            pattern=r'md5\.(New|Sum)',
            context_pattern=r'(Duplicate|Dedup|Similar|partial|sample|8192)',
            file_pattern=r'(duplicate|dedup)',
            reason=FPReason.DUPLICATE_DETECTION,
            confidence=0.90,
        ),
        # MD5/SHA1 for preview/thumbnail cache
        FPPattern(
            name="go_hash_preview_cache",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            file_pattern=r'(preview|thumbnail|cache)',
            context_pattern=r'(cacheKey|cacheHash|AlbumArt|ModTime)',
            reason=FPReason.CACHE_KEY,
            confidence=0.88,
        ),

        # =========================================================================
        # Go: Mock/test files using math/rand
        # =========================================================================

        # math/rand in mock files (test utilities)
        FPPattern(
            name="go_mathrand_mock_file",
            scanner="semgrepscanner",
            pattern=r'math/rand|"math/rand"',
            file_pattern=r'(mock|Mock|_mock|mocks/|fake|Fake|stub)',
            reason=FPReason.MOCK_FILE,
            confidence=0.92,
        ),
        # math/rand in functions with Mock/Fake/Stub in name
        FPPattern(
            name="go_mathrand_mock_func",
            scanner="semgrepscanner",
            pattern=r'math/rand|"math/rand"',
            context_pattern=r'func\s+(Create)?Mock|func\s+Fake|func\s+Stub|func\s+Random(Path|Term|Extension)',
            reason=FPReason.MOCK_FILE,
            confidence=0.88,
        ),
        # math/rand with self-documenting "Insecure" function name
        FPPattern(
            name="go_mathrand_insecure_named",
            scanner="semgrepscanner",
            pattern=r'math/rand|"math/rand"',
            context_pattern=r'func\s+Insecure|func\s+NonSecure|func\s+Weak',
            reason=FPReason.INTENTIONAL_WEAK,
            confidence=0.95,
        ),
        # math/rand aliased when crypto/rand also imported
        FPPattern(
            name="go_mathrand_with_crypto",
            scanner="semgrepscanner",
            pattern=r'math\s+"math/rand"',
            context_pattern=r'"crypto/rand"',
            reason=FPReason.INTENTIONAL_WEAK,
            confidence=0.90,
        ),

        # =========================================================================
        # Docker: Test/CI Dockerfiles with :latest tag
        # =========================================================================

        # Playwright test Dockerfiles
        FPPattern(
            name="docker_playwright_latest",
            scanner="dockermcpscanner",
            pattern=r':latest',
            file_pattern=r'Dockerfile\.(playwright|test|dev|ci)',
            reason=FPReason.TEST_DOCKERFILE,
            confidence=0.85,
        ),
        # Dockerfiles in test directories
        FPPattern(
            name="docker_test_dir_latest",
            scanner="dockermcpscanner",
            pattern=r':latest',
            file_pattern=r'(test|tests|e2e|ci)/.*(Dockerfile|dockerfile)',
            reason=FPReason.TEST_DOCKERFILE,
            confidence=0.85,
        ),

        # =========================================================================
        # Go: User-selectable checksum algorithms
        # =========================================================================

        # Function offering multiple hash algorithms (user choice)
        FPPattern(
            name="go_multi_algorithm_checksum",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            context_pattern=r'sha256\.New|sha512\.New|map\[string\]hash\.Hash',
            reason=FPReason.SAFE_PATTERN,
            confidence=0.88,
        ),
        # Checksum function with algorithm parameter
        FPPattern(
            name="go_checksum_algo_param",
            scanner="semgrepscanner",
            pattern=r'(md5|sha1)\.(New|Sum)',
            context_pattern=r'func\s+\w*(Checksum|Hash|Digest)\s*\([^)]*algo',
            reason=FPReason.SAFE_PATTERN,
            confidence=0.85,
        ),
    ]

    def __init__(self, source_root: Optional[Path] = None):
        """
        Initialize the FP filter

        Args:
            source_root: Root directory of source code for context analysis
        """
        self.source_root = source_root or Path.cwd()
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
        line_num = finding.get('line', 0)
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
            self._check_test_file,
        ]

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
        file_path = finding.get('file', '').lower()

        for pattern in self.SECURITY_MODULE_PATTERNS:
            if re.search(pattern, file_path, re.IGNORECASE):
                # Additional check: does the file have security methods?
                full_context = '\n'.join(context)
                has_security_methods = any(
                    method in full_context.lower()
                    for method in self.SECURITY_METHODS
                )

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
        """Check if finding is in a docstring or comment"""
        line_num = finding.get('line', 0)

        if not context or line_num <= 0:
            return FilterResult()

        # Get the specific line (adjust for 0-indexing)
        line_idx = min(line_num - 1, len(context) - 1)
        if line_idx < 0:
            return FilterResult()

        line = context[line_idx] if line_idx < len(context) else ""

        # Check if line is a comment
        stripped = line.strip()
        if stripped.startswith('#'):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is in a comment line"
            )

        # Check if we're inside a docstring
        # Look for docstring markers before and after
        full_text = '\n'.join(context[:line_idx + 1])

        # Count docstring markers
        triple_double = full_text.count('"""')
        triple_single = full_text.count("'''")

        # If odd number of markers, we're inside a docstring
        if triple_double % 2 == 1 or triple_single % 2 == 1:
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.DOCSTRING,
                explanation="Finding is inside a docstring"
            )

        # Check for inline docstring on the line
        if '"""' in line or "'''" in line:
            # Check if it's a single-line docstring containing the keyword
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
        line_num = finding.get('line', 0)

        if not context or line_num <= 0:
            return FilterResult()

        # Get lines around the finding
        start_idx = max(0, line_num - 5)
        end_idx = min(len(context), line_num + 5)
        local_context = '\n'.join(context[start_idx:end_idx])

        # Check for security wrapper usage
        for wrapper in self.SECURITY_WRAPPERS:
            # Pattern: credential = SecureWrapper(...)
            if re.search(rf'{wrapper}\s*\(', local_context):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.90,
                    reason=FPReason.SECURITY_WRAPPER,
                    explanation=f"Credential is wrapped in security class '{wrapper}' for protection"
                )

        # Check for security method calls
        for method in self.SECURITY_METHODS:
            if re.search(rf'\.{method}\s*\(', local_context):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.80,
                    reason=FPReason.SECURITY_WRAPPER,
                    explanation=f"Code uses security method '{method}' for credential protection"
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
        line_num = finding.get('line', 0)

        if not context:
            return FilterResult()

        # Get the line and surrounding context
        line_idx = min(line_num - 1, len(context) - 1) if line_num > 0 else 0
        line = context[line_idx] if 0 <= line_idx < len(context) else ""

        # Broader context for context_pattern matching
        start_idx = max(0, line_idx - 20)
        end_idx = min(len(context), line_idx + 10)
        broader_context = '\n'.join(context[start_idx:end_idx])

        for fp_pattern in self.KNOWN_FP_PATTERNS:
            # Check scanner match
            if fp_pattern.scanner and fp_pattern.scanner != scanner:
                continue

            # Check file pattern
            if fp_pattern.file_pattern:
                if not re.search(fp_pattern.file_pattern, file_path, re.IGNORECASE):
                    continue

            # Check main pattern on the line
            if not re.search(fp_pattern.pattern, line, re.IGNORECASE):
                continue

            # Check context pattern if specified
            if fp_pattern.context_pattern:
                if not re.search(fp_pattern.context_pattern, broader_context, re.IGNORECASE):
                    continue

            # Pattern matched
            return FilterResult(
                is_likely_fp=True,
                confidence=fp_pattern.confidence,
                reason=fp_pattern.reason,
                explanation=f"Matches known safe pattern: {fp_pattern.name}"
            )

        return FilterResult()

    def _check_test_file(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Check if finding is in a test file, mock file, or example directory"""
        file_path = finding.get('file', '').lower()

        # Test file patterns
        test_patterns = [
            r'test[s]?[/_]', r'_test\.py$', r'test_.*\.py$',
            r'spec[s]?[/_]', r'\.spec\.(js|ts)$',
            r'__tests__', r'fixtures?[/_]',
            # Go test files
            r'_test\.go$',
            # testdata directories
            r'testdata[/_]',
            # Test resources (Java/Kotlin)
            r'src/test/resources[/_]',
        ]

        # Mock/fake file patterns (higher confidence FP)
        mock_patterns = [
            r'mock[s]?\.go$', r'_mock\.go$', r'mock_.*\.go$',
            r'fake[s]?\.go$', r'_fake\.go$', r'fake_.*\.go$',
            r'stub[s]?\.go$', r'_stub\.go$',
            r'mocks?[/_]', r'fakes?[/_]', r'stubs?[/_]',
            # JS/TS mocks
            r'\.mock\.(js|ts)$', r'__mocks__[/_]',
        ]

        # Example/demo/sample directory patterns
        example_patterns = [
            r'examples?[/_]',
            r'samples?[/_]',
            r'demos?[/_]',
            r'tutorials?[/_]',
            r'quickstart[/_]',
            r'getting[_-]?started[/_]',
        ]

        # Tools/scripts directory patterns (lower confidence)
        tools_patterns = [
            r'tools?[/_]',
            r'scripts?[/_]',
            r'utils?[/_]',
            r'helpers?[/_]',
            r'contrib[/_]',
        ]

        for pattern in mock_patterns:
            if re.search(pattern, file_path):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.88,  # Higher confidence for mock files
                    reason=FPReason.MOCK_FILE,
                    explanation="Finding is in a mock/fake/stub file (test infrastructure)"
                )

        for pattern in test_patterns:
            if re.search(pattern, file_path):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.70,  # Lower confidence - some test vulns are real
                    reason=FPReason.TEST_FILE,
                    explanation="Finding is in a test file (may contain intentional test credentials)"
                )

        for pattern in example_patterns:
            if re.search(pattern, file_path):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.65,  # Lower confidence - examples may have real issues
                    reason=FPReason.EXAMPLE_FILE,
                    explanation="Finding is in an example/demo directory (educational code)"
                )

        for pattern in tools_patterns:
            if re.search(pattern, file_path):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.50,  # Low confidence - tools may have real issues
                    reason=FPReason.EXAMPLE_FILE,
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

    def get_stats(self, findings: List[Dict]) -> Dict:
        """Get statistics about FP filtering"""
        filtered, fps = self.filter_findings(findings)

        fp_by_reason = {}
        for f in fps:
            reason = f.get('fp_analysis', {}).get('reason', 'unknown')
            fp_by_reason[reason] = fp_by_reason.get(reason, 0) + 1

        fp_by_scanner = {}
        for f in fps:
            scanner = f.get('scanner', 'unknown')
            fp_by_scanner[scanner] = fp_by_scanner.get(scanner, 0) + 1

        return {
            'total_findings': len(findings),
            'likely_fps': len(fps),
            'retained': len(filtered),
            'fp_rate': len(fps) / len(findings) if findings else 0,
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
    stats = fp_filter.get_stats(findings)
    return filtered, fps, stats
