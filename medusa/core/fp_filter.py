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

from medusa.core.vet_tiers import (  # CR-008: canonical malice-prefix set
    NEVER_GENERIC_FP_PREFIXES as _VET_NEVER_GENERIC_FP_PREFIXES,
)


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
    INLINE_SUPPRESSION = "inline_suppression"  # Author opt-out via `medusa:ignore` comment
    SIGNATURE_DATA = "signature_data"  # Security-rule / signature definition file (data, not code)
    PATTERN_LITERAL = "pattern_literal"  # Match is inside an attack-pattern literal constant


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

    # Inline suppression: an author opts a single line out of scanning with a
    # `medusa:ignore` comment. Accepts the Python/shell (`#`) and
    # Rust/PHP/JS/C-family (`//`) comment styles, with optional trailing reason
    # text (e.g. `# medusa:ignore - test fixture`). Matched against the source
    # line the finding is on.
    _INLINE_SUPPRESS_RE = re.compile(r'(?:#|//)\s*medusa:ignore\b', re.IGNORECASE)

    # Deliberate, high-precision attack signatures that fire only on
    # instruction-bearing / clearly-malicious content. The generic context FP
    # heuristics (generated-code, config/data-file, test-file…) must not bury
    # these. (MCP tool-metadata poisoning lives in mcp.json, which the
    # generated-code heuristic wrongly treats as auto-generated.)
    # These are the differentiated "install-decision" malice detectors that drive
    # the vet verdict (scan_api). They fire only on their own narrow targets
    # (.claude/ settings, mcp.json metadata, SKILL.md manifests, taint flows), NOT
    # on the rule corpus, so the generic context heuristics must never bury them —
    # a poisoned .claude/ hook or SKILL.md is a true positive, not "config data".
    # (ATKSIG/OSV are intentionally NOT here: they rely on the rule-corpus/data-
    # file recognition below to avoid firing on MEDUSA's own signature corpus.)
    # CR-008: canonical in medusa.core.vet_tiers (shared with scan_api's signal
    # prefixes) so the two malice sets can't drift out of sync — a prefix added to
    # one but not the other used to silently flip a finding hard-block <-> dropped.
    _NEVER_GENERIC_FP_PREFIXES = _VET_NEVER_GENERIC_FP_PREFIXES

    # --- B1: security-rule / signature-definition data-file recognition ---
    #
    # A security tool's own rule corpus (and any user who VENDORS such a corpus)
    # is DATA, not application code: the attack strings inside it ARE the rule
    # definitions, so a scanner matching them on itself is a false positive.
    #
    # Two independent signals mark a file as a rule/signature definition:
    #   (1) it lives under a rules/signatures/patterns/attack_signatures dir, or
    #   (2) its YAML/JSON content matches a rule-definition schema.
    # Either is sufficient. Path-only matching keeps it cheap for the common case
    # and language-agnostic; the content schema catches rule files that live
    # elsewhere.

    # Directory-name signal (matched on the path RELATIVE to scan root so the
    # repo name itself can't trip it). Trailing separator required so we match a
    # directory component, not a substring like "myrulestore.py".
    _SIGNATURE_DIR_RE = re.compile(
        r'(?:^|/)(?:rules?|signatures?|attack[_-]?signatures?|patterns?'
        r'|rulesets?|detections?|fp[_-]?patterns?)/',
        re.IGNORECASE,
    )
    # Only data/serialized-rule extensions qualify for path-based suppression.
    # A .py under rules/ is still executable code and must NOT be blanket-cleared
    # here (B2 handles pattern-literal .py separately, conservatively).
    _SIGNATURE_DATA_EXT_RE = re.compile(r'\.(ya?ml|json|toml)$', re.IGNORECASE)
    # Content schema: a rule-definition document tends to declare an id/rule_id
    # together with severity/patterns/message. Require at least two distinct
    # rule-schema keys so an arbitrary config YAML with a stray `severity:` line
    # is not mistaken for a rule corpus.
    _RULE_SCHEMA_KEY_RE = re.compile(
        r'^\s*-?\s*(rule_?id|id|patterns?|severity|message|cwe|owasp|detection)\s*:',
        re.IGNORECASE | re.MULTILINE,
    )

    # --- B2: pattern-literal source recognition ---
    #
    # A scanner defines its attack signatures as module-level constants, e.g.
    #   COMMAND_INJECTION_PATTERNS = [ r'os\.system\(', r'subprocess.*shell=True' ]
    # Matching one of those literal strings is a self-match on data, not a vuln
    # in executable logic. We suppress ONLY when the finding's line sits inside
    # such a literal collection (a NAME ending in _PATTERNS/_SIGNATURES/_RULES/
    # _REGEXES/_INDICATORS assigned a list/dict/tuple/set), and the matched line
    # is a string literal element — never the executable code around it.
    # An UPPERCASE module-level constant (optional leading underscore for a
    # module-private name) assigned a collection literal. The NAME's purpose is
    # checked separately against _PATTERN_LITERAL_NAME_TOKENS so a leading-underscore
    # or denylist-by-name constant (FX-H03/#25b: `_BLOCKED_HOSTS = {...}` — a security
    # DENYLIST, matched literally as the SSRF-defense the handover flagged) is covered,
    # not only the `_PATTERNS`/`_SIGNATURES` suffix forms.
    _PATTERN_LITERAL_ASSIGN_RE = re.compile(
        r'^\s*(?P<name>_?[A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*[\[\{\(]',
    )
    # Purpose tokens (matched per underscore-delimited token of the name, so no
    # substring over-match like ORIGINAL/GHOST): a datum inside one of these
    # collections is signature/denylist DATA, not executable logic.
    # CR-017: the ALLOW-side network tokens (ALLOW/ALLOWED/ALLOWLIST/WHITELIST,
    # HOST/HOSTS, DOMAIN/DOMAINS, ORIGIN/ORIGINS) were REMOVED. A string literal
    # inside `ALLOWED_HOSTS = ['*']` / `CORS_ALLOWED_ORIGINS = ['*']` is NOT
    # denylist DATA — the `'*'` there IS the permissive-config vulnerability, so
    # suppressing it as a "pattern literal" blinded the scanner to the finding.
    # The DENY-side defense-data tokens (BLOCK*/DENY*/BLACKLIST — the SSRF-defense
    # denylists of FX-H03) stay: a datum in `_BLOCKED_HOSTS` really is defense data.
    _PATTERN_LITERAL_NAME_TOKENS = frozenset({
        'PATTERN', 'PATTERNS', 'SIGNATURE', 'SIGNATURES', 'RULE', 'RULES',
        'REGEX', 'REGEXES', 'REGEXPS', 'INDICATOR', 'INDICATORS',
        'KEYWORD', 'KEYWORDS', 'PAYLOAD', 'PAYLOADS',
        'BLOCK', 'BLOCKED', 'BLOCKLIST', 'BLACKLIST',
        'DENY', 'DENIED', 'DENYLIST',
    })
    # A line that is (predominantly) a quoted string literal element, optionally a
    # raw/byte/format string, with an optional trailing comma — i.e. a datum in a
    # collection literal, not a statement that calls/executes anything.
    _STRING_LITERAL_LINE_RE = re.compile(
        r'^\s*[rRbBfFuU]{0,2}(["\']).*\1\s*,?\s*(?:#.*)?$'
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
        # CR-022: memoise the rule-schema-key SET per file_path. Without it,
        # _check_signature_data_file re-joins the context and re-runs the schema
        # regex once PER FINDING — O(findings x file_size) on a large YAML/JSON.
        # Caching the key set (not just a bool) keeps the suppression decision AND
        # its explanation identical while collapsing the cost to one scan per file.
        # Instance-scoped (like _file_cache), never shared across filter instances.
        self._schema_cache: Dict[str, frozenset] = {}

    def _relax_context(self, finding: Dict) -> bool:
        """CR-033: the ONE definition of the screening context-FP relaxation.

        In screening (target-vet) mode a CRITICAL/HIGH finding must not be buried
        by the test/example/utility-file heuristic — in a poisoned repo those dirs
        ARE the attack surface. The decision was previously computed independently
        in ``filter_finding`` and the pattern-scan loop with two slightly different
        default handlings; folding it here removes the drift risk. The effective
        condition (``screening and severity in {CRITICAL, HIGH}``) is unchanged.
        """
        severity = str(finding.get('severity') or 'MEDIUM').upper()
        return self.screening and severity in ('CRITICAL', 'HIGH')

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

        # High-signal, self-guarded attack signatures must NOT be second-guessed
        # by the generic context heuristics. E.g. a poisoned mcp.json (hidden
        # directive in tool metadata) was being read as "generated_code" and
        # silently dropped. These detectors only fire on instruction-bearing
        # content, so honor an explicit `medusa:ignore` but otherwise always
        # report.
        rule_id = finding.get('rule_id') or ''
        if rule_id.startswith(self._NEVER_GENERIC_FP_PREFIXES):
            inline = self._check_inline_suppression(finding, source_context)
            return inline if inline.is_likely_fp else FilterResult(
                original_severity=finding.get('severity', 'MEDIUM'))

        # Check each filter in order of confidence. Inline suppression is an
        # explicit author opt-out (`medusa:ignore`) so it runs first and applies
        # in every mode, including screening.
        checks = [
            self._check_inline_suppression,
            self._check_signature_data_file,
            self._check_pattern_literal,
            self._check_security_module,
            self._check_docstring,
            self._check_security_wrapper,
            self._check_shell_sanitized,
            self._check_known_patterns,
        ]

        # Screening mode: when vetting a target repo (not scanning your own clean
        # code), do not let the test/example/utility-file heuristic bury a real
        # attack or high-severity security finding — in a vulnerable/poisoned
        # repo those locations (tools_plugins/, datasets, jailbreak .md/.csv) are
        # exactly where the malicious content lives. The genuinely-safe checks
        # (security-module self-detection, real docstrings, known FP patterns)
        # still run in all modes.
        relax_context_fp = self._relax_context(finding)   # CR-033: single source
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

    def _check_inline_suppression(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Suppress a finding whose source line carries a `medusa:ignore` comment.

        Honors `# medusa:ignore` (Python/shell) and `// medusa:ignore`
        (Rust/PHP/JS/C-family). This is an explicit author opt-out, so it gets
        the highest confidence and wins over every other check.
        """
        # A target-controlled `medusa:ignore` must NOT suppress findings while
        # VETTING an untrusted repo (screening): an attacker would append it to
        # every malicious line to force SAFE. The author opt-out applies only when
        # scanning your OWN code (screening=False).
        if self.screening:
            return FilterResult()
        line_num = finding.get('line') or 0
        if not context or line_num <= 0:
            return FilterResult()

        line_idx = min(line_num - 1, len(context) - 1)
        if line_idx < 0:
            return FilterResult()

        line = context[line_idx] if line_idx < len(context) else ""
        if self._INLINE_SUPPRESS_RE.search(line):
            return FilterResult(
                is_likely_fp=True,
                confidence=1.0,
                reason=FPReason.INLINE_SUPPRESSION,
                explanation="Finding suppressed by inline 'medusa:ignore' comment on this line"
            )

        return FilterResult()

    def _check_signature_data_file(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """B1: Suppress findings in security-rule / signature DEFINITION files.

        Such a file is data, not application code — the attack strings it
        contains ARE the rule definitions, so any scanner matching them is a
        false positive. A file qualifies when EITHER:
          * it lives under a rules/signatures/patterns/attack_signatures-style
            directory AND has a data extension (.yaml/.json/.toml), OR
          * its content matches a rule-definition schema (>= 2 distinct
            rule-schema keys such as id/rule_id/patterns/severity/message).

        This is a content/data guard, not a file-location guard, so it applies
        in screening mode too: a vendored security ruleset is data wherever it
        is being scanned.
        """
        raw_path = finding.get('file', '')
        # Relative path so the repo/scan-root name can't itself trip the dir match.
        try:
            rel_path = str(Path(raw_path).relative_to(self.source_root))
        except (ValueError, TypeError):
            rel_path = raw_path
        norm_path = rel_path.replace('\\', '/')

        in_signature_dir = bool(self._SIGNATURE_DIR_RE.search(norm_path))
        is_data_ext = bool(self._SIGNATURE_DATA_EXT_RE.search(norm_path))

        # Path signal: a serialized-rule file under a rules/signatures dir.
        if in_signature_dir and is_data_ext:
            return FilterResult(
                is_likely_fp=True,
                confidence=0.95,
                reason=FPReason.SIGNATURE_DATA,
                explanation=(
                    "File is a security-rule/signature definition (data file under "
                    "a rules/signatures/patterns directory), not application code"
                ),
            )

        # Content signal: rule-definition schema inside a data file anywhere.
        # Only inspect data-extension files — we never want to schema-match a .py.
        if is_data_ext and context:
            # CR-022: memoise the schema-key set per file_path — the join+finditer
            # is otherwise redone for every finding on the same (large) data file.
            cache_key = raw_path or norm_path
            schema_keys = self._schema_cache.get(cache_key)
            if schema_keys is None:
                blob = '\n'.join(context)
                schema_keys = frozenset(
                    m.group(1).lower().replace('_', '')
                    for m in self._RULE_SCHEMA_KEY_RE.finditer(blob)
                )
                self._schema_cache[cache_key] = schema_keys
            # Require an identity key plus a rule-detail key so a generic config
            # with a lone `severity:` does not qualify.
            has_identity = bool(schema_keys & {'ruleid', 'id'})
            has_detail = bool(
                schema_keys & {'patterns', 'pattern', 'severity', 'message',
                               'cwe', 'owasp', 'detection'}
            )
            if has_identity and has_detail and len(schema_keys) >= 2:
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.90,
                    reason=FPReason.SIGNATURE_DATA,
                    explanation=(
                        "File content matches a security-rule definition schema "
                        f"(keys: {', '.join(sorted(schema_keys))}); treated as data"
                    ),
                )

        return FilterResult()

    def _check_pattern_literal(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """B2: Suppress findings whose match is inside an attack-pattern literal.

        A scanner declares its signatures as module-level constants, e.g.
        ``COMMAND_INJECTION_PATTERNS = [r'os\\.system\\(', ...]``. Matching one of
        those literal strings is a self-match on data, not a vulnerability in
        executable logic.

        GUARD against over-suppression: we suppress ONLY when BOTH hold —
          (1) the finding's own line is a plain quoted string-literal element
              (a datum in a collection, not a statement that executes anything),
          (2) walking upward, that line is inside a collection assigned to a NAME
              ending in _PATTERNS/_SIGNATURES/_RULES/_REGEXES/etc., with no
              intervening top-level statement closing the literal.
        A real ``eval(user_input)`` or ``subprocess.run(..., shell=True)`` in
        normal code is NOT a bare string literal, so it never matches (1).
        """
        # Only Python source — the literal/assignment heuristics are Python-shaped.
        raw_path = finding.get('file', '')
        if not raw_path.endswith('.py'):
            return FilterResult()

        line_num = finding.get('line') or 0
        if not context or line_num <= 0:
            return FilterResult()

        line_idx = min(line_num - 1, len(context) - 1)
        if line_idx < 0:
            return FilterResult()

        line = context[line_idx] if line_idx < len(context) else ""

        # (1) The matched line must itself be a quoted string-literal element.
        # This is the core guard: executable code (eval(...), subprocess.run(...))
        # is not a bare quoted string, so it is excluded here.
        if not self._STRING_LITERAL_LINE_RE.match(line):
            return FilterResult()

        # (2) Walk upward to confirm we're inside a *_PATTERNS-style collection
        # literal. Stop if we hit a line that looks like a top-level/dedented
        # statement (def/class/import or an unindented non-data line) before
        # finding the assignment — that means the literal has already closed.
        cur_indent = len(line) - len(line.lstrip())
        for i in range(line_idx - 1, max(line_idx - 200, -1), -1):
            prev = context[i] if i < len(context) else ""
            stripped = prev.strip()
            if not stripped:
                continue
            m = self._PATTERN_LITERAL_ASSIGN_RE.match(prev)
            if m and any(t in self._PATTERN_LITERAL_NAME_TOKENS
                         for t in m.group('name').strip('_').split('_')):
                return FilterResult(
                    is_likely_fp=True,
                    confidence=0.85,
                    reason=FPReason.PATTERN_LITERAL,
                    explanation=(
                        "Match is a string literal inside a signature / denylist "
                        "constant (e.g. *_PATTERNS/_SIGNATURES/_BLOCKED_HOSTS); "
                        "definition or defense DATA, not executable logic"
                    ),
                )
            prev_indent = len(prev) - len(prev.lstrip())
            # A dedented statement (def/class/import or anything less-indented
            # than our element) below the assignment means the collection has
            # closed; stop searching to avoid a false attribution.
            if prev_indent < cur_indent and (
                stripped.startswith(('def ', 'class ', 'import ', 'from '))
                or stripped.endswith(':')
                or '=' in stripped.split('#', 1)[0]
            ):
                break

        return FilterResult()

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

    # A command-injection finding is a FALSE POSITIVE when every value
    # interpolated into the command was passed through `shlex.quote()` — that is
    # precisely the documented, correct defence against shell injection, so
    # flagging it punishes code for defending itself. pentest-mcp was hard-blocked
    # by SIX rules all pointing at one line that is properly sanitised:
    #     url = shlex.quote(url); wordlist = shlex.quote(wordlist)
    #     os.system(f"gobuster dir -u {url} -w {wordlist} -o /tmp/out.txt")
    # Deliberately strict: EVERY interpolated name must be quoted (a single
    # unquoted variable keeps the finding), so partial sanitisation never hides a
    # real injection.
    _SHELL_INJECTION_RE = re.compile(
        r'command\s+injection|shell\s+injection|shell=True|os\.system|'
        r'unsanitiz|shell\s+execution|shell\s+invocation', re.IGNORECASE)
    _SHLEX_QUOTE_ASSIGN_RE = re.compile(
        r'(\w+)\s*=\s*(?:shlex|pipes)\.quote\s*\(')
    _FSTRING_VAR_RE = re.compile(r'\{\s*(\w+)\s*[^}]*\}')
    # The command handed to the shell as a BARE NAME rather than an inline
    # f-string — `os.system(command)` after `command = f"hashcat -m {t} {h} …"`.
    # Without this the finding line carries no `{…}` at all, so the sanitisation
    # check bailed immediately and pentest-mcp's hashcat / sqlmap servers stayed
    # hard-blocked despite quoting every interpolated value one line earlier.
    _SHELL_CALL_BARE_RE = re.compile(
        r'(?:os\.(?:system|popen)|subprocess\.(?:run|call|check_call|check_output|Popen))'
        r'\s*\(\s*([A-Za-z_]\w*)\s*[,)]')

    _DEF_RE = re.compile(r'^\s*(?:async\s+)?def\s')

    @classmethod
    def _enclosing_block_start(cls, context: List[str], line_num: int) -> int:
        """0-based index of the `def` enclosing ``line_num``, else a 40-line window.

        Bounded the same way as before (never look back further than 40 lines) so a
        huge function cannot make this scan the whole file.
        """
        floor = max(0, line_num - 40)
        for i in range(min(line_num, len(context)) - 1, floor - 1, -1):
            if cls._DEF_RE.match(context[i]):
                return i
        return floor

    @staticmethod
    def _assigned_exactly_once(name: str, above: str) -> bool:
        """True if ``name`` is bound exactly once in ``above`` and never appended
        to. Resolving a composed command through its f-string is only sound while
        that f-string IS the value; a second binding or a `+=` can splice in
        unsanitised input after the fact."""
        n = re.escape(name)
        if re.search(rf'^\s*{n}\s*\+=', above, re.MULTILINE):
            return False
        return len(re.findall(rf'^\s*{n}\s*=(?!=)', above, re.MULTILINE)) == 1

    def _check_shell_sanitized(
        self,
        finding: Dict,
        context: List[str]
    ) -> FilterResult:
        """Suppress a shell/command-injection finding whose interpolated values
        were all `shlex.quote()`-sanitised (the correct defence)."""
        blob = f"{finding.get('rule_id') or ''} {finding.get('issue') or ''} " \
               f"{finding.get('message') or ''}"
        if not self._SHELL_INJECTION_RE.search(blob):
            return FilterResult()

        line_num = finding.get('line') or 0
        if not context or line_num <= 0:
            return FilterResult()

        line = context[line_num - 1] if line_num - 1 < len(context) else ""
        interpolated = set(self._FSTRING_VAR_RE.findall(line))
        if not interpolated:
            # No inline interpolation — the command may still have been composed
            # into a local and passed by name. Seed from that name and let the
            # composition resolution below judge the values it was built from.
            bare = self._SHELL_CALL_BARE_RE.search(line)
            if not bare:
                return FilterResult()
            interpolated = {bare.group(1)}

        # Names sanitised anywhere in the enclosing region above the finding.
        # Scoped to the enclosing function where one is visible: a `shlex.quote()`
        # in the PREVIOUS function says nothing about this one, and a flat 40-line
        # window let a neighbouring helper's sanitisation vouch for an unquoted
        # interpolation here (fail-open). It also made the verdict depend on how
        # far up the file the previous `def` happened to sit.
        above = '\n'.join(context[self._enclosing_block_start(context, line_num):line_num])
        quoted = set(self._SHLEX_QUOTE_ASSIGN_RE.findall(above))
        # Resolve ONE level of composition: `os.system(f"{command} ...")` where
        # `command = f"gobuster -u {url} -w {wordlist}"` must be judged on url /
        # wordlist, not on the opaque name `command`.
        for name in list(interpolated):
            if name in quoted:
                continue
            if not self._assigned_exactly_once(name, above):
                # Rebound or appended to (`command += user_input`) — the f-string
                # is not the whole story, so refuse to resolve it. Fail closed.
                continue
            m = re.search(rf'\b{re.escape(name)}\s*=\s*f["\']([^"\']*)["\']', above)
            if m:
                interpolated.discard(name)
                interpolated.update(self._FSTRING_VAR_RE.findall(m.group(1)))

        if interpolated and interpolated.issubset(quoted):
            return FilterResult(
                is_likely_fp=True,
                confidence=0.85,
                reason=FPReason.SECURITY_WRAPPER,
                explanation=(
                    "Shell command is built from shlex.quote()-sanitised values ("
                    + ", ".join(sorted(interpolated))
                    + ") — that is the correct injection defence, not a vulnerability"
                ),
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
        relax_context_fp = self._relax_context(finding)   # CR-033: single source

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

            # CR-020: nor a PATH-only catch-all suppressor (e.g. `vendor_dir_finding`:
            # any finding under vendor/ node_modules/ site-packages/ → "not
            # actionable"). When VETTING a stranger's repo those trees ARE where a
            # payload hides, so a HIGH/CRITICAL there must still surface. Scoped to a
            # path-based rule whose CONTENT pattern is a catch-all (`.*`), so
            # content-specific safe-patterns are untouched; regular (non-screening)
            # scans keep the vendor suppression intact.
            if (relax_context_fp
                    and fp_pattern.reason == FPReason.SAFE_PATTERN
                    and fp_pattern.file_pattern
                    and (fp_pattern.pattern or "").strip() in (".*", ".+", "")):
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
