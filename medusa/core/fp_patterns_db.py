#!/usr/bin/env python3
"""
MEDUSA False Positive Patterns Database

This module contains the KNOWN_FP_PATTERNS list -- 514 declarative FPPattern
objects used by FalsePositiveFilter in fp_filter.py.

Extracted from fp_filter.py to keep the data separate from the filter logic.
"""

from typing import List

from medusa.core.fp_filter import FPPattern, FPReason


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

    # =========================================================================
    # Trivy: AVD-DS findings on non-Dockerfile config files (Scanner Bug)
    # Source: IOTstack, go8, FastAPI-boilerplate FP analysis 2026-01-11
    # =========================================================================

    # Trivy AVD-DS findings on YAML config files (not Dockerfiles)
    FPPattern(
        name="trivy_avd_on_golangci_yaml",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'\.golangci\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    FPPattern(
        name="trivy_avd_on_yarnrc",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'\.yarnrc\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    FPPattern(
        name="trivy_avd_on_precommit",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'\.pre-commit-config\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    FPPattern(
        name="trivy_avd_on_mkdocs",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'mkdocs\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    FPPattern(
        name="trivy_avd_on_pyproject",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'pyproject\.toml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    FPPattern(
        name="trivy_avd_on_taskfile",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'Taskfile\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),

    # =========================================================================
    # Gitleaks: Documentation false positives
    # Source: FastAPI-boilerplate, Dashy FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="gitleaks_apikey_in_docs",
        scanner="gitleaksscanner",
        pattern=r'generic-api-key',
        file_pattern=r'(docs?[/\\]|README|\.md$)',
        reason=FPReason.DOCSTRING,
        confidence=0.90,
    ),
    FPPattern(
        name="gitleaks_curl_auth_in_docs",
        scanner="gitleaksscanner",
        pattern=r'curl-auth-header',
        file_pattern=r'(docs?[/\\]|README|\.md$|getting-started)',
        reason=FPReason.DOCSTRING,
        confidence=0.92,
    ),
    FPPattern(
        name="gitleaks_jwt_in_docs",
        scanner="gitleaksscanner",
        pattern=r'generic-api-key',
        file_pattern=r'(first-run|tutorial|example|quickstart)',
        context_pattern=r'eyJ[A-Za-z0-9_-]+',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.90,
    ),

    # =========================================================================
    # Trivy: Template and example directory false positives
    # Source: IOTstack FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="trivy_avd_in_templates_dir",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'\.templates?[/\\]',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.85,
    ),
    FPPattern(
        name="trivy_avd_in_service_yml",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'service\.ya?ml$',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.85,
    ),
    FPPattern(
        name="trivy_avd_in_scripts_dir",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'scripts?[/\\].*Dockerfile',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.75,
    ),

    # =========================================================================
    # Trivy: Empty/placeholder environment variable secrets
    # Source: IOTstack FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="docker_empty_password_env",
        scanner="trivyscanner",
        pattern=r'AVD-DS-0031',
        context_pattern=r'ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\s*["\']?\s*["\']?\s*$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
    ),
    FPPattern(
        name="docker_mqtt_password_placeholder",
        scanner="trivyscanner",
        pattern=r'AVD-DS-0031',
        context_pattern=r'MQTT_PASSWORD\s*["\']?\s*["\']?',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
    ),

    # =========================================================================
    # Trivy: Kubernetes manifest best practices (AVD-KSV-*)
    # Source: Flame FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="trivy_ksv_in_k8s_examples",
        scanner="trivyscanner",
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'k8s[/\\](base|overlays|examples?)',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.80,
    ),
    FPPattern(
        name="trivy_ksv_in_deployment_yaml",
        scanner="trivyscanner",
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'k8s[/\\].*deployment\.ya?ml$',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.80,
    ),

    # =========================================================================
    # Docker: .docker directory development files
    # Source: Flame FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="trivy_avd_in_dot_docker",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'\.docker[/\\]',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.75,
    ),
    FPPattern(
        name="trivy_avd_dev_dockerfile",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'Dockerfile\.(dev|multiarch|test|ci|build)',
        reason=FPReason.TEST_DOCKERFILE,
        confidence=0.80,
    ),

    # =========================================================================
    # Official example/sample repositories (docker/awesome-compose, etc.)
    # Source: docker/awesome-compose FP analysis 2026-01-11
    # =========================================================================

    FPPattern(
        name="trivy_avd_in_compose_examples",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'(awesome-compose|compose-examples|docker-samples)[/\\]',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.85,
    ),
    FPPattern(
        name="trivy_avd_on_compose_yaml",
        scanner="trivyscanner",
        pattern=r'AVD-DS-\d+',
        file_pattern=r'compose\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
    ),
    FPPattern(
        name="trivy_cve_on_compose_yaml",
        scanner="trivyscanner",
        pattern=r'CVE-\d+-\d+',
        file_pattern=r'compose\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
    ),

    # =========================================================================
    # Content-Based Safe Patterns (Non-Secret Content)
    # Source: Agent0 FP analysis 2026-01-15
    # =========================================================================

    # Masked/redacted values (10+ asterisks)
    FPPattern(
        name="masked_asterisks",
        scanner="gitleaksscanner",
        pattern=r'\*{10,}',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    # Windows line endings / ShellCheck SC1017
    FPPattern(
        name="crlf_line_ending",
        scanner="gitleaksscanner",
        pattern=r'carriage return|SC1017',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
    ),
    # HTML-encoded masked values in reports
    FPPattern(
        name="html_encoded_mask",
        scanner="gitleaksscanner",
        pattern=r'(&quot;|&#x27;|&#39;)\*{5,}',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
    ),
    # Sentry DSNs are public by design
    FPPattern(
        name="sentry_dsn",
        scanner="gitleaksscanner",
        pattern=r'sentry[_.-]?(key|dsn|io)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
    ),
    # Values explicitly marked as example/test/mock
    FPPattern(
        name="example_marker",
        scanner="gitleaksscanner",
        pattern=r'["\'][^"\'"]*(example|sample|test|dummy|fake|mock)[^"\'"]*(key|token|secret|password)',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.92,
    ),
    # Obvious placeholder markers
    FPPattern(
        name="placeholder_text",
        scanner="gitleaksscanner",
        pattern=r'(YOUR_|REPLACE_|EXAMPLE_|CHANGEME|TODO:|FIXME:)[A-Z_]*',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),
    # FedAuth session cookies in forensic captures
    FPPattern(
        name="fedauth_cookie",
        scanner="gitleaksscanner",
        pattern=r'FedAuth=[A-Za-z0-9+/=]{20,}',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
    ),
    # Bash environment variable references (not hardcoded)
    FPPattern(
        name="env_var_bash",
        scanner="gitleaksscanner",
        pattern=r'\$\{[A-Z_][A-Z0-9_]*\}',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
    ),
    # Windows environment variable references
    FPPattern(
        name="env_var_windows",
        scanner="gitleaksscanner",
        pattern=r'%[A-Z_][A-Z0-9_]*%',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
    ),
    # Explicitly redacted content markers
    FPPattern(
        name="redacted_marker",
        scanner="gitleaksscanner",
        pattern=r'(REDACTED|MASKED|\[REMOVED\]|\[HIDDEN\]|XXXXXXX)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
    ),

    # =========================================================================
    # YAML/Code Style Linting (not security findings)
    # Source: 85-repo benchmark FP analysis 2026-02-09
    # =========================================================================

    # yamllint/semgrep style findings that aren't security issues
    FPPattern(
        name="yaml_trailing_spaces",
        scanner="semgrepscanner",
        pattern=r'trailing spaces',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_wrong_indentation",
        scanner="semgrepscanner",
        pattern=r'wrong indentation',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_truthy_value",
        scanner="semgrepscanner",
        pattern=r'truthy value should be',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_missing_doc_start",
        scanner="semgrepscanner",
        pattern=r'missing document start',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_no_newline_eof",
        scanner="semgrepscanner",
        pattern=r'no new line character',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_spaces_before_comment",
        scanner="semgrepscanner",
        pattern=r'too few spaces before comment',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="yaml_line_too_long",
        scanner="semgrepscanner",
        pattern=r'line too long',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="shell_double_quote",
        scanner="semgrepscanner",
        pattern=r'Double quote to prevent globbing',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),
    # DockerComposeScanner also passes through yamllint findings
    FPPattern(
        name="docker_yaml_trailing_spaces",
        scanner="dockercomposescanner",
        pattern=r'trailing spaces',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="docker_yaml_wrong_indentation",
        scanner="dockercomposescanner",
        pattern=r'wrong indentation',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="docker_yaml_missing_doc_start",
        scanner="dockercomposescanner",
        pattern=r'missing document start',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="docker_yaml_line_too_long",
        scanner="dockercomposescanner",
        pattern=r'line too long',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),
    FPPattern(
        name="docker_yaml_no_newline",
        scanner="dockercomposescanner",
        pattern=r'no new line character',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
    ),

    # =========================================================================
    # Assert Usage in ML/Data Science Code (not security)
    # Source: 85-repo benchmark - assert is standard in ML pipelines
    # =========================================================================

    FPPattern(
        name="semgrep_assert_usage",
        scanner="semgrepscanner",
        pattern=r'Use of assert detected',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
    ),
    FPPattern(
        name="pi_assert_usage",
        scanner="promptinjectioncodescanner",
        pattern=r'Use of assert detected',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
    ),
    FPPattern(
        name="agent_assert_usage",
        scanner="agentmemoryscanner",
        pattern=r'Use of assert detected',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
    ),
    FPPattern(
        name="rag_assert_usage",
        scanner="ragsecurityscanner",
        pattern=r'Use of assert detected',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
    ),

    # =========================================================================
    # Random Number Generator in ML Code (not crypto context)
    # Source: 85-repo benchmark - random.seed() is standard ML reproducibility
    # =========================================================================

    FPPattern(
        name="semgrep_random_ml",
        scanner="semgrepscanner",
        pattern=r'Standard pseudo-random generators are not suitable',
        file_pattern=r'(train|eval|dataset|model|attack|benchmark|experiment)',
        reason=FPReason.ML_COMMON,
        confidence=0.80,
    ),
    FPPattern(
        name="pi_random_ml",
        scanner="promptinjectioncodescanner",
        pattern=r'Standard pseudo-random generators are not suitable',
        file_pattern=r'(train|eval|dataset|model|attack|benchmark|experiment)',
        reason=FPReason.ML_COMMON,
        confidence=0.80,
    ),

    # =========================================================================
    # Source: OpenClaw FP analysis 2026-02-10
    # Total estimated FP reduction: ~28,000+ findings across 29,323 total
    # =========================================================================

    # --- 1. Lockfile exclusion (~2,272 findings) ---
    FPPattern(
        name="lockfile_finding",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(pnpm-lock|yarn\.lock|package-lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|composer\.lock)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Findings in dependency lockfiles are not actionable security issues",
    ),

    # --- 3. Generic "tool capability" patterns in TypeScript/JavaScript (~16,700 findings) ---
    FPPattern(
        name="semgrep_generic_code_execution",
        scanner="semgrepscanner",
        pattern=r'^Code execution$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),
    FPPattern(
        name="semgrep_generic_data_modification",
        scanner="semgrepscanner",
        pattern=r'^Data modification$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),
    FPPattern(
        name="semgrep_generic_destructive_op",
        scanner="semgrepscanner",
        pattern=r'^Destructive operation$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),
    FPPattern(
        name="semgrep_generic_process_execution",
        scanner="semgrepscanner",
        pattern=r'^Process execution$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),
    FPPattern(
        name="semgrep_generic_file_write",
        scanner="semgrepscanner",
        pattern=r'^File write$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),
    FPPattern(
        name="semgrep_generic_file_deletion",
        scanner="semgrepscanner",
        pattern=r'^File deletion$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Generic tool capability finding on normal TypeScript/JavaScript code",
    ),

    # --- 4. "No PQC library imports" suppression (~309 findings) ---
    FPPattern(
        name="pqc_not_crypto_file",
        scanner=None,
        pattern=r'No PQC library imports',
        file_pattern=r'(crypt|cipher|sign|tls|ssl|certificate|key_exchange)',
        file_pattern_negate=True,
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="PQC advisory is only relevant for files performing cryptographic operations",
    ),

    # --- 5. Documentation directory awareness (~200 findings) ---
    FPPattern(
        name="docs_dir_prompt_injection",
        scanner="markdownscanner",
        pattern=r'(prompt|jailbreak|injection|system prompt|developer mode|uncensored|unrestricted)',
        file_pattern=r'(^|/)docs?/',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.88,
        description="Documentation about security topics is not an attack",
    ),
    FPPattern(
        name="docs_dir_memory_poisoning",
        scanner="agentmemoryscanner",
        pattern=r'memory poisoning|memory state',
        file_pattern=r'(^|/)docs?/',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.88,
        description="Documentation about memory poisoning is educational, not an attack",
    ),

    # --- 6. CJK/i18n false positives ---
    FPPattern(
        name="cjk_base64_detection",
        scanner="aicontextscanner",
        pattern=r'(Base64|leetspeak|obfuscat|encoded)',
        file_pattern=r'(zh[-_]|ja[-_]|ko[-_]|chinese|japanese|korean|i18n|locale|lang)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="CJK documentation triggers false Base64/encoding detections",
    ),

    # --- 7. Markdown code fence false positives ---
    FPPattern(
        name="markdown_code_fence_execution",
        scanner="aicontextscanner",
        pattern=r'(backtick command|PowerShell subexpression|SQL comment)',
        file_pattern=r'\.(md|mdx|rst)$',
        reason=FPReason.DOCSTRING,
        confidence=0.85,
        description="Code examples in markdown files are not executable attacks",
    ),

    # --- 8. "Patterns match" finding on security controls ---
    FPPattern(
        name="semgrep_validation_pattern_match",
        scanner="semgrepscanner",
        pattern=r'^(Validation|Rate Limit|Audit) Patterns match$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic 'Patterns match' finding fires on security controls, not vulnerabilities",
    ),

    # --- 9. PAIR attack word collision ---
    FPPattern(
        name="pair_attack_word_collision",
        scanner=None,
        pattern=r'PAIR prompt refinement',
        context_pattern=r'(pair|Pair)(ing|ed|s)\b',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Word 'pairing/paired/pairs' collides with PAIR attack detection",
    ),

    # --- 10. AWS key false match on camelCase ---
    FPPattern(
        name="aws_key_camelcase_collision",
        scanner=None,
        pattern=r'AWS Secret Access Key',
        context_pattern=r'(dispatcher|Dispatcher|Handler|handler|Manager|manager|Controller|controller)\b',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Long camelCase identifiers mismatched as AWS secret keys",
    ),

    # --- 11. Chrome/browser API matched as MCP ---
    FPPattern(
        name="chrome_api_mcp_collision",
        scanner=None,
        pattern=r'MCP123.*Update without verification',
        context_pattern=r'chrome\.(windows|tabs|runtime|extension)\.(update|create|remove)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Chrome extension API calls matched as MCP tool updates",
    ),

    # --- 12. Plugin SDK import matched as unrestricted ---
    FPPattern(
        name="plugin_sdk_import_unrestricted",
        scanner="semgrepscanner",
        pattern=r'Plugin marked as public/unrestricted',
        context_pattern=r'import\s+(type\s+)?.*from\s+[\'\"](openclaw|@openclaw)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Plugin SDK import statement triggers unrestricted plugin finding",
    ),

    # --- 13. Secret-dependent array index in non-crypto ---
    FPPattern(
        name="side_channel_non_crypto",
        scanner=None,
        pattern=r'Secret-dependent array index|cache attack risk',
        file_pattern=r'\.(ts|js|tsx|jsx|py|rb)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Cache timing side-channel is only relevant in cryptographic implementations",
    ),

    # --- 14. Line-too-long findings from any scanner ---
    FPPattern(
        name="line_too_long_any",
        scanner=None,
        pattern=r'line too long',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
        description="Line length is a code style issue, not a security finding",
    ),

    # --- 15. Vendor/node_modules directory ---
    FPPattern(
        name="vendor_dir_finding",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)(vendor|node_modules|\.pnpm|site-packages|\.venv|third_party|external)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Findings in vendored/third-party code are not actionable",
    ),

    # =================================================================
    # Source: OpenClaw FP analysis 2026-02-10 (final pass)
    # =================================================================

    # --- 16. MCP-004 .env pattern matches process.env in TS/JS ---
    FPPattern(
        name="semgrep_dotenv_code_not_file_ts",
        scanner="semgrepscanner",
        pattern=r'^Tool accesses sensitive system files$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="MCP-004 .env pattern in TS/JS matches process.env, not file access",
    ),

    # --- 17. Adversarial suffix: comment separator lines ---
    FPPattern(
        name="adversarial_suffix_comment_separator",
        scanner=None,
        pattern=r'adversarial suffix.*long special character',
        context_pattern=r'^\s*(?://|/\*|#|\*)\s*[=\-~*#_]{15,}',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Comment separator lines (// ====...) are not adversarial suffixes",
    ),

    # --- 18. Adversarial suffix: regex literals in source code ---
    FPPattern(
        name="adversarial_suffix_regex_literal",
        scanner=None,
        pattern=r'adversarial suffix.*long special character',
        context_pattern=r'(?:/[^/\n]{10,}/[gimsuy]*|(?:RegExp|\.match|\.replace|\.test|\.search|\.exec)\s*\()',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs|py)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Regex literals contain dense special characters that are not adversarial",
    ),

    # --- 19. Adversarial suffix: ASCII art and box-drawing chars ---
    FPPattern(
        name="adversarial_suffix_ascii_art",
        scanner=None,
        pattern=r'adversarial suffix.*long special character',
        context_pattern=r'[\u2500-\u259F]{10,}|[\u2580-\u259F]{5,}|\|[-:]{3,}\|',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.93,
        description="ASCII art, box-drawing, and markdown table separators are not adversarial",
    ),

    # --- 20. Agent safety: file-level import at line 1 ---
    FPPattern(
        name="agent_file_level_import_line1",
        scanner="semgrepscanner",
        pattern=r'(Inter-agent messages without validation|Agent delegation without privilege|Agent interactions without audit|Unrestricted agent spawning)',
        context_pattern=r'^import\s',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="File-level agent finding fires on import statement, not agent logic",
    ),

    # --- 21. Agent safety: type/interface definitions ---
    FPPattern(
        name="agent_type_definition",
        scanner="semgrepscanner",
        pattern=r'(agent safety|Agent action|Agent with|Agent without|Agent handoff|Agent delegation|Agent interaction|Inter-agent|Auto-execution|human approval|Unrestricted agent|agent spawning)',
        context_pattern=r'^\s*(export\s+)?(type|interface)\s+\w+',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Agent safety finding on TypeScript type/interface, not executable code",
    ),

    # --- 22. Chat history export: TS export keyword collision ---
    FPPattern(
        name="chat_export_ts_keyword",
        scanner="semgrepscanner",
        pattern=r'Chat history export',
        context_pattern=r'^\s*export\s+(type|interface|const|function|async\s+function|default|class|\{)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="TypeScript 'export' keyword collides with chat history export detection",
    ),

    # --- 23. Plugin code execution: import statements ---
    FPPattern(
        name="plugin_exec_import_statement",
        scanner="semgrepscanner",
        pattern=r'Plugin with code execution',
        context_pattern=r'^\s*(import\s+(type\s+)?|type\s+\w+)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Plugin execution finding on import/type statement, not actual execution",
    ),

    # --- 24. MCP123: crypto .update() not MCP update ---
    FPPattern(
        name="mcp123_crypto_hash_update",
        scanner="semgrepscanner",
        pattern=r'MCP123.*Update without verification',
        context_pattern=r'(createH(ash|mac)|crypto\.|decipher\.|cipher\.)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Crypto hash/HMAC .update() is not an MCP tool update",
    ),

    # --- 25. MCP123: UI spinner/progress .update() ---
    FPPattern(
        name="mcp123_ui_spinner_update",
        scanner="semgrepscanner",
        pattern=r'MCP123.*Update without verification',
        context_pattern=r'(spin\.update|progress\.update|onProgress|requestUpdate|emitUpdate|draftStream\.update)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="UI spinner/progress .update() is not an MCP tool update",
    ),

    # --- 26. MCP123: messaging platform updates ---
    FPPattern(
        name="mcp123_messaging_update",
        scanner="semgrepscanner",
        pattern=r'MCP123.*Update without verification',
        context_pattern=r'(shouldSkipUpdate|sendPresenceUpdate|stringifyUpdate)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Messaging platform update/presence is not an MCP tool update",
    ),

    # --- 27. MCP119: URL construction for logging ---
    FPPattern(
        name="mcp119_localhost_log_url",
        scanner="semgrepscanner",
        pattern=r'MCP119.*Custom URI scheme',
        context_pattern=r'(console\.log|\.log\(|listening on|\.info\(|new URL\(req\.url)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="URL construction for server logging, not template injection",
    ),

    # --- 28. Raw response: normalize/sanitize function ---
    FPPattern(
        name="raw_response_normalize_function",
        scanner="semgrepscanner",
        pattern=r'Returning raw response without sanitization',
        context_pattern=r'(normalize|parse|trim|sanitize|clean|strip|split|replace|humanize|format)\w*\s*\(',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="'return raw' inside normalize/parse function - the function IS the sanitization",
    ),

    # --- 29. Plugin return: error message mentioning secret name ---
    FPPattern(
        name="plugin_return_error_message",
        scanner="semgrepscanner",
        pattern=r'Sensitive data in plugin return',
        context_pattern=r'return\s+["\'\x60].*\b(require|not configured|can only be used|missing|invalid)\b',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Return of error message mentioning secret name, not actual secret data",
    ),

    # --- 30. Timing: comparison against string literal ---
    FPPattern(
        name="timing_literal_string_compare",
        scanner="semgrepscanner",
        pattern=r'(constant-time compare|timing attack risk)',
        context_pattern=r'===?\s*["\'][a-zA-Z_*-]+["\']|["\'][a-zA-Z_*-]+["\']\s*===?',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Timing comparison to hardcoded string literal is not exploitable",
    ),

    # --- 31. Timing: typeof type guard ---
    FPPattern(
        name="timing_typeof_check",
        scanner="semgrepscanner",
        pattern=r'(constant-time compare|timing attack risk)',
        context_pattern=r'typeof\s+\w+(\.\w+)*\s*===?\s*["\']',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="typeof type guard is not a secret comparison",
    ),

    # --- 32. Zero-width: .trim() is not sanitization ---
    FPPattern(
        name="zero_width_trim_only",
        scanner="semgrepscanner",
        pattern=r'zero-width character filtering',
        context_pattern=r'\.trim\(\)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description=".trim() is whitespace removal, not input sanitization",
    ),

    # --- 33. AVD-DS on non-Dockerfile files ---
    FPPattern(
        name="avd_ds_on_non_dockerfile",
        scanner=None,
        pattern=r'AVD-DS-\d+',
        file_pattern=r'(Dockerfile|dockerfile|\.dockerfile)',
        file_pattern_negate=True,
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Docker-specific AVD-DS findings on non-Dockerfile files",
    ),

    # --- 34. CVE findings on tsconfig files ---
    FPPattern(
        name="cve_on_tsconfig",
        scanner="datasetinjectionscanner",
        pattern=r'CVE-\d+-\d+',
        file_pattern=r'tsconfig.*\.json$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="CVE findings incorrectly attributed to TypeScript config files",
    ),

    # --- 35. MarkdownScanner: tool definitions in docs ---
    FPPattern(
        name="markdown_tool_defs_in_docs",
        scanner="markdownscanner",
        pattern=r'Tool definitions included in response',
        file_pattern=r'(^|/)docs?/',
        reason=FPReason.DOCSTRING,
        confidence=0.88,
        description="Documentation discussing tool definitions is not a data leak",
    ),

    # --- 36. MarkdownScanner: Chrome extension Developer mode ---
    FPPattern(
        name="markdown_chrome_developer_mode",
        scanner="markdownscanner",
        pattern=r'developer mode',
        file_pattern=r'chrome[-_]?extension',
        reason=FPReason.DOCSTRING,
        confidence=0.92,
        description="Chrome extension docs mentioning Developer mode is standard procedure",
    ),

    # --- 37. AgentMemoryScanner: generic capability on memory files ---
    FPPattern(
        name="agent_memory_generic_capability",
        scanner="agentmemoryscanner",
        pattern=r'^(Code execution|Process execution|Data modification|Destructive operation)$',
        file_pattern=r'memory[-_/]',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Generic capability finding on memory system implementation code",
    ),

    # --- 38. Sensitive data: NPM dependency name with auth ---
    FPPattern(
        name="sensitive_data_npm_dep_name",
        scanner="criticalcvescanner",
        pattern=r'Potential sensitive data in key.*dependencies',
        file_pattern=r'package\.json$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="NPM dependency named 'auth' is a package name, not a credential",
    ),

    # =================================================================
    # SCANNER-AGNOSTIC: Build output, generated, minified, IDE
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 39. Build output: dist/ ---
    FPPattern(
        name="build_output_dist",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)dist/',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.92,
        description="Findings in dist/ build output are not actionable",
    ),
    # --- 40. Build output: .next/.nuxt/.svelte-kit/.output ---
    FPPattern(
        name="build_output_framework_cache",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)\.(next|nuxt|svelte-kit|output)/',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="Framework build cache (.next/.nuxt/.svelte-kit) is compiled output",
    ),
    # --- 41. Build output: target/classes|release|debug ---
    FPPattern(
        name="build_output_target",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)target/(classes|release|debug|site|generated)/',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.92,
        description="Java/Rust target/ build output is not source",
    ),
    # --- 42. Generated code: markers in content ---
    FPPattern(
        name="generated_code_marker",
        scanner=None,
        pattern=r'.*',
        context_pattern=r'(Code generated.*DO NOT EDIT|@generated|@auto-generated|DO NOT EDIT|DO NOT MODIFY|GENERATED FILE|AUTO[ -]?GENERATED|THIS FILE IS GENERATED)',
        reason=FPReason.GENERATED_CODE,
        confidence=0.92,
        description="File contains auto-generation marker - fix the generator, not the output",
    ),
    # --- 43. Generated code: protobuf output ---
    FPPattern(
        name="generated_code_protobuf",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.(pb|pb2)\.go$|_pb2\.py$|_pb\.ts$|\.pb\.h$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.95,
        description="Protobuf-generated file (*.pb.go, *_pb2.py, etc.)",
    ),
    # --- 44. Generated code: GraphQL/codegen ---
    FPPattern(
        name="generated_code_graphql",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'generated\.(ts|tsx|js)$|__generated__/',
        reason=FPReason.GENERATED_CODE,
        confidence=0.92,
        description="GraphQL/codegen generated TypeScript/JavaScript file",
    ),
    # --- 45. Minified JS/CSS ---
    FPPattern(
        name="minified_js_css",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.min\.(js|css)$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="Minified file - fix the source, not the minified output",
    ),
    # --- 46. Bundled JS ---
    FPPattern(
        name="bundled_js",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.(bundle|chunk)\.(js|mjs|cjs)$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.93,
        description="Bundled JavaScript (webpack/rollup output) - fix the source module",
    ),
    # --- 47. IDE config dirs ---
    FPPattern(
        name="ide_config_dir",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)\.(idea|vscode|eclipse|cursor)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.93,
        description="IDE configuration directory is not application source code",
    ),
    # --- 48. Coverage/report output ---
    FPPattern(
        name="coverage_output_dir",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)(htmlcov|\.nyc_output|\.coverage)/',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="Test coverage output directory is not source code",
    ),
    # --- 49. LCOV coverage data ---
    FPPattern(
        name="coverage_lcov_file",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.lcov$|lcov\.info$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="LCOV coverage data file is not source code",
    ),
    # --- 50. go.sum lockfile ---
    FPPattern(
        name="lockfile_go_sum",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)go\.sum$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="go.sum dependency checksums are not actionable security issues",
    ),
    # --- 51. Database migration SQL patterns ---
    FPPattern(
        name="migration_sql_patterns",
        scanner=None,
        pattern=r'(SQL injection|Raw SQL|string concatenation.*sql)',
        file_pattern=r'(^|/)(migrations?|alembic|db/migrate|prisma/migrations|flyway|liquibase)/.*\.(sql|py|rb|ts|js)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.75,
        description="SQL patterns in database migration files are intentional DDL/DML",
    ),

    # =================================================================
    # TOOLCALLBACKSCANNER: Generic destructive patterns
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 52. ToolCallback: generic destructive on TS/JS ---
    FPPattern(
        name="toolcb_destruct_generic_ts",
        scanner="toolcallbackscanner",
        pattern=r'^(Code execution|Destructive operation|Data modification|Process execution|File write|File deletion)$',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Generic destructive keywords in TS/JS without tool execution context",
    ),
    # --- 53. ToolCallback: validation pattern on auth code ---
    FPPattern(
        name="toolcb_validation_on_auth",
        scanner="toolcallbackscanner",
        pattern=r'^(Validation Patterns match|Audit Patterns match|Rate Limit Patterns match)$',
        context_pattern=r'(isAuthorized|authorize|checkPermission|runSecurityAudit|SecurityAudit|RateLimit|quotaInfo)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Security control implementation code detected as missing security control",
    ),
    # --- 54. ToolCallback: PAIR vs pairing collision ---
    FPPattern(
        name="toolcb_pair_pairing",
        scanner="toolcallbackscanner",
        pattern=r'PAIR prompt refinement',
        context_pattern=r'(pairing|Pairing|PAIRING|pairingRequest|device-pair)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="PAIR attack detection collides with device pairing feature",
    ),

    # =================================================================
    # PLUGINSECURITYSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 55. Plugin: PLG003 on TS import statements ---
    FPPattern(
        name="plugin_plg003_ts_import",
        scanner="pluginsecurityscanner",
        pattern=r'Plugin marked as public/unrestricted',
        context_pattern=r'import\s+(type\s+)?.*from\s+[\'"]',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Plugin SDK import collides with unrestricted plugin detection",
    ),
    # --- 56. Plugin: PLG004 TS export keyword ---
    FPPattern(
        name="plugin_plg004_ts_export",
        scanner="pluginsecurityscanner",
        pattern=r'Chat history export functionality',
        context_pattern=r'^\s*export\s+(type|interface|const|function|async\s+function|default|class|\{)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="TypeScript export keyword collides with chat export detection",
    ),
    # --- 57. Plugin: PLG008 error message about token ---
    FPPattern(
        name="plugin_plg008_error_msg",
        scanner="pluginsecurityscanner",
        pattern=r'Sensitive data in plugin return',
        context_pattern=r'return\s+["\'\x60].*\b(can only be used|is required|not configured|not found|missing|invalid)\b',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Error message mentioning credential name, not returning actual secret",
    ),
    # --- 58. Plugin: PLG006 on import/type ---
    FPPattern(
        name="plugin_plg006_import",
        scanner="pluginsecurityscanner",
        pattern=r'Plugin with code execution',
        context_pattern=r'^\s*(import\s+(type\s+)?|type\s+\w+)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Plugin execution finding on import/type statement",
    ),

    # =================================================================
    # EXCESSIVEAGENCYSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 59. EXA006: User-Agent HTTP header collision ---
    FPPattern(
        name="exa_useragent_header",
        scanner="excessiveagencyscanner",
        pattern=r'Agent with network access',
        context_pattern=r'["\']User-Agent["\']',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="HTTP User-Agent header string collides with agent network access",
    ),
    # --- 60. EXA005: string truncation not file truncation ---
    FPPattern(
        name="exa_truncate_string",
        scanner="excessiveagencyscanner",
        pattern=r'Destructive file operation',
        context_pattern=r'(truncate\w*Text|truncate\w*Tool|truncate\w*String|truncateOversized|TRUNCATION_SUFFIX)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="String truncation utility, not destructive file truncation",
    ),
    # --- 61. EXA004: auto-compaction not auto-execution ---
    FPPattern(
        name="exa_auto_compaction",
        scanner="excessiveagencyscanner",
        pattern=r'Auto-execution without human approval',
        context_pattern=r'(auto-?compact|autoCompact|compaction)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Auto-compaction (context management) is not autonomous execution",
    ),
    # --- 62. EXA006: function param named 'api' ---
    FPPattern(
        name="exa_api_parameter",
        scanner="excessiveagencyscanner",
        pattern=r'Agent with network access',
        context_pattern=r'(function\s+register\w+Tools\s*\(\s*api|api:\s*\w+Plugin)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Function parameter named api (plugin API object) is not network access",
    ),

    # =================================================================
    # MCPSERVERSCANNER / MCP PATTERNS
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 63. MCP123: generic .update() methods ---
    FPPattern(
        name="mcp123_generic_update",
        scanner="semgrepscanner",
        pattern=r'MCP123.*Update without verification',
        context_pattern=r'(emitUpdate|stringifyUpdate|surfaceUpdate|sessionTranscript|updatePrefs|runUpdate|dataModelUpdate)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Generic .update() (state, config, transcript) is not MCP tool update",
    ),
    # --- 64. PowerShell subexpression on bash $() ---
    FPPattern(
        name="powershell_bash_subshell",
        scanner="semgrepscanner",
        pattern=r'PowerShell subexpression',
        context_pattern=r'(#!/bin/(sh|bash)|dirname\s+"\$0"|node\s+"\$\()',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Bash $() subshell syntax misidentified as PowerShell subexpression",
    ),
    # --- 65. Confused deputy: token counting code ---
    FPPattern(
        name="mcp_confused_deputy_token_count",
        scanner="semgrepscanner",
        pattern=r'Confused deputy.*token',
        context_pattern=r'(tokenCount|systemTokens|contextTokens|injectedChars|contextWeight)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Token counting code is not confused deputy pattern",
    ),

    # =================================================================
    # MULTIAGENTSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 66. Multi-agent file-level on import/type ---
    FPPattern(
        name="multiagent_file_level_import",
        scanner=None,
        pattern=r'(Inter-agent messages without validation|Agent delegation without privilege|Agent interactions without audit|Agent handoff.*without authentication)',
        context_pattern=r'^(import\s|export\s|from\s|type\s|interface\s)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="File-level agent safety finding on import/type, not agent logic",
    ),
    # --- 67. Multi-agent base64 on Nostr hex keys ---
    FPPattern(
        name="multiagent_nostr_base64",
        scanner=None,
        pattern=r'Multi-agent.*encoded communication.*base64',
        file_pattern=r'nostr',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Nostr bech32/hex keys misidentified as encoded agent communication",
    ),

    # =================================================================
    # OWASPLLMSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 68. Zero-width on TS/JS broadly ---
    FPPattern(
        name="zero_width_ts_js_advisory",
        scanner=None,
        pattern=r'zero-width character filtering',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Zero-width character advisory on TS/JS is informational, not a vulnerability",
    ),
    # --- 69. Raw response: return variable named raw ---
    FPPattern(
        name="raw_response_return_raw_var",
        scanner=None,
        pattern=r'Returning raw response without sanitization',
        context_pattern=r'return\s+raw\b|return\s+raw\.',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Variable named raw returned after transformation is not unsanitized",
    ),
    # --- 70. Prompt extraction in documentation ---
    FPPattern(
        name="prompt_extraction_docs",
        scanner=None,
        pattern=r'(Prompt extraction|prompt extraction)',
        file_pattern=r'(^|/)docs?/|\.md$',
        reason=FPReason.DOCSTRING,
        confidence=0.90,
        description="Documentation discussing prompts is not a prompt extraction attack",
    ),
    # --- 71. Prompt injection in test files ---
    FPPattern(
        name="prompt_injection_test",
        scanner=None,
        pattern=r'(Prompt injection|prompt injection)',
        file_pattern=r'\.(test|spec)\.(ts|js|tsx|jsx)$|__tests__/',
        reason=FPReason.TEST_FILE,
        confidence=0.88,
        description="Prompt injection strings in test files are test payloads",
    ),
    # --- 72. System prompt leakage: config label ---
    FPPattern(
        name="system_prompt_config_label",
        scanner="semgrepscanner",
        pattern=r'System Prompt Leakage',
        context_pattern=r'(label:\s*["\']|description:\s*["\']|placeholder:\s*["\']|tooltip:\s*["\'])',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Config form label mentioning system prompt is UI metadata, not leakage",
    ),

    # =================================================================
    # STEGANOGRAPHYSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 73. Steg: .trim() not zero-width filtering ---
    FPPattern(
        name="steg_trim_not_sanitization",
        scanner="steganographyscanner",
        pattern=r'zero-width character filtering',
        context_pattern=r'\.(trim|strip)\(\)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description=".trim()/.strip() is whitespace removal, not zero-width filtering gap",
    ),
    # --- 74. Steg: role markers on TS object properties ---
    FPPattern(
        name="steg_role_marker_ts_property",
        scanner="steganographyscanner",
        pattern=r'Role markers in user content',
        context_pattern=r'^\s*(system|assistant|lastAssistant|includeSystem|addSystem)\s*[:=,{]',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="TS object property named system:/assistant: is not role marker injection",
    ),
    # --- 75. Steg: base64 schema definitions ---
    FPPattern(
        name="steg_base64_schema_def",
        scanner="steganographyscanner",
        pattern=r'Data URI with base64',
        context_pattern=r'(z\.(string|enum)|schema|Schema|type\s*:)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Schema definitions for base64 data types are not payloads",
    ),

    # =================================================================
    # POSTQUANTUMSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 76. PQC: array key iteration in TS/JS ---
    FPPattern(
        name="pqc_array_key_iteration",
        scanner="postquantumscanner",
        pattern=r'(Secret-dependent array index|cache attack risk)',
        context_pattern=r'(\[key\b|\.entries\(\)|Object\.keys|for\s*\(\s*const\s+\[key)',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Object key iteration is not secret-dependent array index",
    ),
    # --- 77. PQC: typeof/literal string compare ---
    FPPattern(
        name="pqc_typeof_compare",
        scanner="postquantumscanner",
        pattern=r'(Direct secret comparison|timing attack|constant-time compare)',
        context_pattern=r'(typeof\s+\w+|===?\s*["\'][a-zA-Z_*]+["\'])',
        file_pattern=r'\.(ts|js|tsx|jsx|mjs|cjs)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="typeof checks and literal comparisons are not timing attacks",
    ),

    # =================================================================
    # LLMOPSSCANNER
    # Source: Gap analysis 2026-02-10
    # =================================================================

    # --- 78. LLMOps: config files with deploy keyword ---
    FPPattern(
        name="llmops_infra_config",
        scanner="llmopsscanner",
        pattern=r'(Model deployment without monitoring|No drift detection|Model operations without audit)',
        file_pattern=r'\.(toml|ya?ml|json)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="LLMOps rules fire on infrastructure config with deploy keyword",
    ),

    # =================================================================
    # BENCHMARK FP: modelcontextprotocol/servers, anthropics/claude-cookbooks
    # Source: Benchmark scan review 2026-02-10
    # =================================================================

    # --- 79. Binary/serialized files trigger false unicode analysis ---
    FPPattern(
        name="binary_file_homoglyph",
        scanner="agentmemoryscanner",
        file_pattern=r'\.(pkl|bin|dat|model|pt|onnx|h5|safetensors|parquet|arrow)$',
        pattern=r'(homoglyph|mixed.script|unicode)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Binary/serialized files trigger false unicode analysis",
    ),

    # --- 80. Documentation JSON data files mention API keys as topics ---
    FPPattern(
        name="api_key_in_data_json",
        scanner="agentmemoryscanner",
        file_pattern=r'/data/.*\.json$',
        pattern=r'API key found',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Documentation JSON data files mention API keys as topics",
    ),

    # --- 81. Documentation JSON data files reference tokens as concepts ---
    FPPattern(
        name="secret_token_in_data_json",
        scanner="agentmemoryscanner",
        file_pattern=r'/data/.*\.json$',
        pattern=r'Secret.*token found',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.92,
        description="Documentation JSON data files reference tokens as concepts",
    ),

    # --- 82. Documentation/dataset JSON files trigger injection patterns ---
    FPPattern(
        name="dataset_injection_in_data_json",
        scanner="agentmemoryscanner",
        file_pattern=r'/data/.*\.json$',
        pattern=r'(Dataset injection|Data exfiltration)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.92,
        description="Documentation/dataset JSON files trigger injection patterns",
    ),

    # --- 83. Data JSON files trigger hidden tag detection ---
    FPPattern(
        name="hidden_tag_in_data_json",
        scanner="agentmemoryscanner",
        file_pattern=r'/data/.*\.json$',
        pattern=r'Hidden tag',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Data JSON files trigger hidden tag detection",
    ),

    # --- 84. ML/vectordb code uses pickle for local caching ---
    FPPattern(
        name="pickle_in_vectordb_eval",
        scanner="agentmemoryscanner",
        file_pattern=r'(vectordb|vector_db|evaluation).*\.py$',
        pattern=r'(pickle|deserialization)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="ML/vectordb code uses pickle for local caching",
    ),

    # --- 85. Boolean/None literals matched as password values ---
    FPPattern(
        name="password_boolean_literal",
        scanner=None,
        pattern=r"Possible hardcoded password: '(True|False|None)'",
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Boolean/None literals matched as password values",
    ),

    # --- 86. Internal scripts use f-string paths with trusted variables ---
    FPPattern(
        name="fstring_path_in_scripts",
        scanner="semgrepscanner",
        file_pattern=r'(scripts/|evaluation/|hooks/|utils/|skills/|tools/)',
        pattern=r'Path traversal.*f-string',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Internal scripts use f-string paths with trusted variables",
    ),

    # --- 87. Prompt builder files legitimately return prompt variables ---
    FPPattern(
        name="returning_prompt_in_prompt_file",
        scanner=None,
        file_pattern=r'prompts?\.py$',
        pattern=r'Directly returning prompt',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Prompt builder files legitimately return prompt variables",
    ),

    # --- 88. Memory tool implementation flagged as attack against itself ---
    FPPattern(
        name="memory_poisoning_on_memory_tool",
        scanner=None,
        file_pattern=r'memory[-_]?tool',
        pattern=r'Memory poisoning',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Memory tool implementation flagged as attack against itself",
    ),

    # --- 89. NPM package.json 'author' field matches 'auth' substring ---
    FPPattern(
        name="sensitive_data_author_package_json",
        scanner="criticalcvescanner",
        file_pattern=r'package\.json$',
        pattern=r"sensitive data.*key 'author'",
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.98,
        description="NPM package.json 'author' field matches 'auth' substring",
    ),

    # --- 90. Evaluation harness data triggers injection patterns ---
    FPPattern(
        name="dataset_injection_in_eval",
        scanner="datasetinjectionscanner",
        file_pattern=r'evaluation/',
        pattern=r'(Dataset injection|Data exfiltration)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="Evaluation harness data triggers injection patterns",
    ),

    # --- 91. Evaluation code intentionally passes user input to LLMs ---
    FPPattern(
        name="pic004_in_evaluation",
        scanner="promptinjectioncodescanner",
        file_pattern=r'(evaluation/|inference_adapter|lambda_function)',
        pattern=r'PIC004',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Evaluation code intentionally passes user input to LLMs",
    ),

    # --- 92. VectorDB/evaluation code has intentional embedding pipelines ---
    FPPattern(
        name="embedding_pipeline_in_eval",
        scanner=None,
        file_pattern=r'(vectordb|evaluation|embedding)',
        pattern=r'(Embedding pipeline|No minimum relevance threshold)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="VectorDB/evaluation code has intentional embedding pipelines",
    ),

    # =================================================================
    # BENCHMARK FP: ollama, qdrant, burn, livebook, chroma, langchain (2026-02-10)
    # =================================================================

    # --- 93. AVD-KSV on Docker Compose files ---
    FPPattern(
        name="avd_ksv_on_docker_compose",
        scanner=None,
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'docker-compose.*\.(ya?ml|yml)$|compose\.(ya?ml|yml)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Kubernetes AVD-KSV findings on Docker Compose files (not k8s manifests)",
    ),

    # --- 94. AVD-KSV on non-Kubernetes YAML ---
    FPPattern(
        name="avd_ksv_not_k8s_manifest",
        scanner=None,
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'(deployment|statefulset|daemonset|pod|replicaset|job|cronjob|k8s|kube|helm|chart)',
        file_pattern_negate=True,
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="AVD-KSV Kubernetes findings on files that are not Kubernetes manifests",
    ),

    # --- 95. CVE on docker-compose YAML ---
    FPPattern(
        name="cve_on_docker_compose_yaml",
        scanner=None,
        pattern=r'CVE-\d+-\d+',
        file_pattern=r'docker-compose.*\.(ya?ml|yml)$|compose\.(ya?ml|yml)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="CVE dependency findings incorrectly attributed to Docker Compose files",
    ),

    # --- 96. API key param in Python library code ---
    FPPattern(
        name="api_key_param_in_python_lib",
        scanner=None,
        pattern=r'API key found in memory config',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Python library code referencing api_key as parameter/config field",
    ),

    # --- 97. Go unsafe package ---
    FPPattern(
        name="go_unsafe_package",
        scanner="semgrepscanner",
        pattern=r'unsafe package',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Go unsafe package usage is standard for CGo interop and low-level system code",
    ),

    # --- 98. CVE on tooling config JSON ---
    FPPattern(
        name="cve_on_tooling_config_json",
        scanner=None,
        pattern=r'CVE-\d+-\d+',
        file_pattern=r'(tsconfig|\.prettierrc|openapitools|typedoc|vercel|components|turbo|CMakePresets|pydoc-markdown)\.(json|ya?ml)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="CVE findings incorrectly attributed to tooling config files",
    ),

    # --- 99. Build output in static/assets ---
    FPPattern(
        name="build_output_static_assets",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(^|/)static/(assets|js|css)/',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.90,
        description="Static assets directory contains bundled/compiled output",
    ),

    # --- 100. Tool definitions in LLM library ---
    FPPattern(
        name="tool_defs_in_llm_library",
        scanner=None,
        pattern=r'Tool definitions included in response',
        file_pattern=r'(langchain|llama_?index|openai|anthropic|crewai|autogen).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="LLM framework library code defines tool schemas by design",
    ),

    # --- 101. Memory poisoning on state file in LLM frameworks ---
    FPPattern(
        name="memory_poisoning_state_file_python",
        scanner=None,
        pattern=r'[Mm]emory poisoning.*agent state file target',
        file_pattern=r'(langchain|crewai|autogen|llama_?index).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="LLM framework library code legitimately manages agent state files",
    ),

    # --- 102. Sensitive data in plugin return for Python libs ---
    FPPattern(
        name="sensitive_data_plugin_return_python_lib",
        scanner=None,
        pattern=r'Sensitive data in plugin return',
        file_pattern=r'(langchain|chromadb|llama_?index|embedding_function).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="LLM/embedding library code returning API response data",
    ),

    # --- 103. Training config on OpenAPI spec ---
    FPPattern(
        name="training_config_on_openapi",
        scanner="semgrepscanner",
        pattern=r'(Training config|Downloading training)',
        file_pattern=r'(openapi|swagger)\.(json|ya?ml)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="OpenAPI/Swagger spec files contain URLs that are API definitions",
    ),

    # --- 104. MCP123 on Python .update() methods ---
    FPPattern(
        name="mcp123_python_update_method",
        scanner=None,
        pattern=r'MCP123.*Update without verification',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Python dict.update()/ORM.update() are standard operations",
    ),

    # --- 105. YAML missing comment space ---
    FPPattern(
        name="yaml_missing_comment_space",
        scanner="semgrepscanner",
        pattern=r'missing starting space in comment',
        reason=FPReason.CODE_STYLE,
        confidence=0.95,
        description="YAML comment style is not a security issue",
    ),

    # --- 106. Secret/token param in Python ---
    FPPattern(
        name="secret_token_param_in_python_lib",
        scanner=None,
        pattern=r'Secret/token found in memory config',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Python library code referencing token as parameter/config field",
    ),

    # --- 107. Memory poisoning on storage implementations ---
    FPPattern(
        name="memory_poisoning_on_storage_impl",
        scanner=None,
        pattern=r'Memory Poisoning.*Persistent memory storage',
        file_pattern=r'(store|storage|cache|persist|segment|collection|vectorstore|in_memory).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="Storage/cache implementations flagged for persisting data",
    ),

    # --- 108. Agent logging on callback code ---
    FPPattern(
        name="agent_logging_on_callback_code",
        scanner=None,
        pattern=r'Agent action without logging',
        file_pattern=r'(callback|tracer|handler|logger|monitor).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="Callback/tracer code IS the logging infrastructure",
    ),

    # --- 109. Path traversal f-string in LLM libs ---
    FPPattern(
        name="path_traversal_fstring_python_lib",
        scanner=None,
        pattern=r'Path traversal.*f-string',
        file_pattern=r'(langchain|chromadb|llama_?index).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="LLM framework library f-string paths use trusted config variables",
    ),

    # --- 110. Context overflow on text processing ---
    FPPattern(
        name="context_overflow_on_text_processing",
        scanner=None,
        pattern=r'Context window overflow',
        file_pattern=r'(langchain|text.?split|chunk|tokeniz|prompt).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Text processing/splitting library code handles large inputs by design",
    ),

    # --- 111. Agent network access on API client code ---
    FPPattern(
        name="agent_network_on_api_client",
        scanner=None,
        pattern=r'Agent with network access',
        file_pattern=r'(langchain|chromadb|api|client|embedding_function).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="API client/embedding library code makes HTTP calls by design",
    ),

    # --- 112-117. ShellCheck code style findings ---
    FPPattern(
        name="shellcheck_quote_word_splitting",
        scanner="semgrepscanner",
        pattern=r'Quote this to prevent word splitting',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck word splitting advisory is code quality, not security",
    ),
    FPPattern(
        name="shellcheck_declare_assign",
        scanner="semgrepscanner",
        pattern=r'Declare and assign separately',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck declare/assign advisory is code quality, not security",
    ),
    FPPattern(
        name="shellcheck_posix_sh",
        scanner="semgrepscanner",
        pattern=r'In POSIX sh,',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck POSIX portability advisory is not a security issue",
    ),
    FPPattern(
        name="shellcheck_target_shell",
        scanner="semgrepscanner",
        pattern=r'Tips depend on target shell',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck shell detection advisory is not a security issue",
    ),
    FPPattern(
        name="shellcheck_single_quotes",
        scanner="semgrepscanner",
        pattern=r"Expressions don't expand in single quotes",
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck quoting advisory is code quality, not security",
    ),
    FPPattern(
        name="shellcheck_appears_unused",
        scanner="semgrepscanner",
        pattern=r'appears unused\.',
        reason=FPReason.CODE_STYLE,
        confidence=0.88,
        description="ShellCheck unused variable advisory is code quality, not security",
    ),

    # --- 118. Direct secret comparison in Go ---
    FPPattern(
        name="direct_secret_compare_go",
        scanner=None,
        pattern=r'Direct secret comparison',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Go == comparisons are typically for config values/enums, not crypto secrets",
    ),

    # --- 119. Secret-dependent array index in Go ---
    FPPattern(
        name="secret_array_index_go",
        scanner=None,
        pattern=r'Secret-dependent array index',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Go array indexing in non-crypto code is not a side-channel risk",
    ),

    # --- 120. All findings on OpenAPI/Swagger spec files ---
    FPPattern(
        name="findings_on_openapi_spec",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'(openapi|swagger)\.(json|ya?ml)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="OpenAPI/Swagger spec files are API documentation, not executable code",
    ),

    # --- 121. Hidden div in TSX/JSX ---
    FPPattern(
        name="hidden_div_tsx_jsx",
        scanner=None,
        pattern=r'Hidden div element',
        file_pattern=r'\.(tsx|jsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="React components use hidden divs for conditional rendering",
    ),

    # --- 122. Docker Compose scanner validation error ---
    FPPattern(
        name="docker_compose_validation_error",
        scanner="dockercomposescanner",
        pattern=r'Docker Compose validation error',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Scanner internal Docker Compose validation error is not a security finding",
    ),

    # --- 123-124. AVD/CVE on bandit.yaml and pnpm-workspace ---
    FPPattern(
        name="avd_cve_on_bandit_yaml",
        scanner=None,
        pattern=r'(AVD-\w+-\d+|CVE-\d+-\d+)',
        file_pattern=r'bandit\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="AVD/CVE findings on bandit linter config are scanner artifacts",
    ),
    FPPattern(
        name="cve_on_pnpm_workspace",
        scanner=None,
        pattern=r'(AVD-\w+-\d+|CVE-\d+-\d+)',
        file_pattern=r'pnpm-workspace\.ya?ml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="AVD/CVE findings on pnpm workspace config are scanner artifacts",
    ),

    # =========================================================================
    # BENCHMARK FP: transformers, vllm - Python ML (2026-02-10)
    # =========================================================================

    # 125: ML special token "hardcoded password"
    FPPattern(
        name="hardcoded_password_ml_special_token",
        scanner=None,
        pattern=r"Possible hardcoded password: '(<[^>]*>|\[?[A-Z_]+\]?|[a-z_]+_token[a-z_]*|[a-z_]*token_id[a-z_]*|[a-z_]*_index|embeddings[a-z_.]*|all_zeros|[0-9]+|[<|].*[|>])'",
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.92,
        description="ML tokenizer special tokens matched as passwords",
    ),

    # 126: Dropout disabled in ML model/config
    FPPattern(
        name="dropout_disabled_ml_code",
        scanner=None,
        pattern=r'Dropout disabled.*overfitting',
        file_pattern=r'(model|config|layer|attention|transform|encoder|decoder|head|block|architecture|backbone).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.90,
        description="Dropout=0 in ML model code is valid configuration",
    ),

    # 127: Sensitive data in plugin return for Python
    FPPattern(
        name="sensitive_data_plugin_return_python",
        scanner=None,
        pattern=r'Sensitive data in plugin return',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Python function return values are not plugin data exfiltration",
    ),

    # 128: Memory poisoning agent state in Python ML
    FPPattern(
        name="memory_poisoning_agent_state_python_ml",
        scanner=None,
        pattern=r'Memory poisoning.*agent state file',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Python ML code managing model state is not agent memory poisoning",
    ),

    # 129: MCP rug pull on Python .update()
    FPPattern(
        name="mcp_rug_pull_python_update",
        scanner=None,
        pattern=r'MCP rug pull.*trojaned update',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Python dict.update()/config.update() is standard, not MCP poisoning",
    ),

    # 130: HF Hub from_pretrained
    FPPattern(
        name="hf_hub_from_pretrained_ml_lib",
        scanner=None,
        pattern=r'Unsafe Hugging Face Hub download.*from_pretrained',
        file_pattern=r'(transformers|diffusers|tokenizers|huggingface|vllm|model|convert|config).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="from_pretrained() in ML library code is core functionality",
    ),

    # 131: HF Hub hf_hub_download
    FPPattern(
        name="hf_hub_download_ml_lib",
        scanner=None,
        pattern=r'Unsafe Hugging Face Hub download.*hf_hub_download',
        file_pattern=r'(transformers|diffusers|tokenizers|huggingface|vllm|convert).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="hf_hub_download() in ML library code is core functionality",
    ),

    # 132: HF Hub snapshot_download
    FPPattern(
        name="hf_hub_snapshot_download_ml_lib",
        scanner=None,
        pattern=r'Unsafe Hugging Face Hub download.*snapshot_download',
        file_pattern=r'(transformers|diffusers|huggingface|vllm).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="snapshot_download() in ML library code is core functionality",
    ),

    # 133: Adapter from non-standard source
    FPPattern(
        name="adapter_nonstandard_source_ml_lib",
        scanner=None,
        pattern=r'Adapter from non-standard source',
        file_pattern=r'(transformers|diffusers|peft|vllm|model|convert|adapter).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML library code implementing adapter loading",
    ),

    # 134: Path check without realpath in Python
    FPPattern(
        name="path_check_no_realpath_python",
        scanner=None,
        pattern=r'Path check without realpath.*symlink',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Python ML code path checks are for config/model paths",
    ),

    # 135: Path traversal f-string in Python ML
    FPPattern(
        name="path_traversal_fstring_python_ml",
        scanner=None,
        pattern=r'Path traversal.*f-string.*unvalidated',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Python f-string path construction with config variables",
    ),

    # 136: AWS Secret Access Key in Python
    FPPattern(
        name="aws_secret_key_python_ml",
        scanner=None,
        pattern=r'AWS Secret Access Key',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Long Python identifiers with access/secret/key substrings",
    ),

    # 137: Embedding pipeline caching disabled
    FPPattern(
        name="embedding_cache_disabled_ml",
        scanner=None,
        pattern=r'Embedding pipeline.*caching disabled',
        file_pattern=r'(model|embed|encoder|attention|layer|transform).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Embedding caching settings in ML model code are training config",
    ),

    # 138: Download without integrity verification
    FPPattern(
        name="download_no_integrity_ml",
        scanner=None,
        pattern=r'Download without integrity verification',
        file_pattern=r'(transformers|diffusers|huggingface|vllm|convert|download).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML framework download code uses hub-level integrity",
    ),

    # 139: External/unencrypted HTTP source
    FPPattern(
        name="external_http_source_ml_converter",
        scanner=None,
        pattern=r'(External HTTP source|Unencrypted HTTP source)',
        file_pattern=r'(convert|download|hub|pretrained|checkpoint).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="ML converter scripts reference model URLs",
    ),

    # 140: AVD-DS via GitLeaksScanner
    FPPattern(
        name="avd_ds_via_gitleaks",
        scanner="gitleaksscanner",
        pattern=r'AVD-DS-\d+',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Docker AVD-DS findings via GitLeaksScanner are misattribution",
    ),

    # 141: Path traversal: File open in Python
    FPPattern(
        name="path_traversal_file_open_python",
        scanner=None,
        pattern=r'Path traversal: File open.*unvalidated',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Python open() with config-derived paths is standard file I/O",
    ),

    # 142: Hardcoded credential in ML code
    FPPattern(
        name="hardcoded_credential_python_ml",
        scanner=None,
        pattern=r'Hardcoded credential in code',
        file_pattern=r'(tokeniz|model|config|convert|ggml|vocab|encode|decode|special_token).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML tokenizer/model string literals are not credentials",
    ),

    # 143: Direct secret comparison in Python
    FPPattern(
        name="direct_secret_compare_python",
        scanner=None,
        pattern=r'Direct secret comparison.*constant-time',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Python == comparisons on config values are not secret comparisons",
    ),

    # 144: GSI reasoning attack in ML code
    FPPattern(
        name="gsi_reasoning_ml_code",
        scanner=None,
        pattern=r'GSI.*reasoning attack',
        file_pattern=r'(model|attention|encoder|decoder|layer|head|transform|block).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML model implementation is not a generative style injection attack",
    ),

    # 145: GPU memory not cleared
    FPPattern(
        name="gpu_memory_not_cleared_ml",
        scanner=None,
        pattern=r'GPU memory not explicitly cleared',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="GPU memory lifecycle managed at framework level",
    ),

    # 146: ChatML/control tokens in tokenizer code
    FPPattern(
        name="chatml_control_tokens_tokenizer",
        scanner=None,
        pattern=r'(ChatML control tokens|control token injection)',
        file_pattern=r'(tokeniz|ggml|vocab|convert|chat_template|special_token).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.90,
        description="Tokenizer code defining ChatML tokens is not injection",
    ),

    # 147: Constant zero initialization
    FPPattern(
        name="constant_zero_init_ml",
        scanner=None,
        pattern=r'Constant zero initialization',
        file_pattern=r'(model|layer|init|weight|embed|attention|linear).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.90,
        description="Zero initialization is standard ML weight init strategy",
    ),

    # 148: Supply chain pre-trained model
    FPPattern(
        name="supply_chain_pretrained_ml_lib",
        scanner=None,
        pattern=r'Supply Chain.*Pre-trained model loaded',
        file_pattern=r'(transformers|diffusers|vllm|model|convert|pretrained).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML library loading pretrained models is its core purpose",
    ),

    # 149: Pickle usage in Python ML
    FPPattern(
        name="pickle_usage_python_ml",
        scanner=None,
        pattern=r'(pickle|Pickle.*deseriali|Pickle.*unsafe)',
        file_pattern=r'(transformers|vllm|model|dataset|tokeniz|cache|checkpoint|convert).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.80,
        description="Pickle in ML library code is standard for model serialization",
    ),

    # 150: Subprocess in Python ML scripts
    FPPattern(
        name="subprocess_python_ml_scripts",
        scanner=None,
        pattern=r'subprocess.*(?:call|untrusted|security)',
        file_pattern=r'(benchmark|test_|setup|build|install|script|utils|docker|ci_).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Subprocess in ML build/test scripts use hardcoded commands",
    ),

    # 151: Memory poisoning shared/unbounded
    FPPattern(
        name="memory_poisoning_shared_unbounded_ml",
        scanner=None,
        pattern=r'Memory Poisoning.*(?:Shared memory|Unbounded memory)',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="ML inference uses shared GPU memory and unbounded caches by design",
    ),

    # 152: Ray framework detected
    FPPattern(
        name="ray_framework_detected_ml",
        scanner=None,
        pattern=r'LO011.*Ray.*(?:framework|cluster)',
        file_pattern=r'(vllm|ray|distributed|parallel|worker|executor).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Ray is standard distributed compute for ML inference",
    ),

    # 153: LoRA adapter without verification
    FPPattern(
        name="lora_adapter_ml_lib",
        scanner=None,
        pattern=r'LO014.*LoRA adapter',
        file_pattern=r'(transformers|peft|vllm|model|adapter|lora).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="ML library implementing LoRA loading is adapter infrastructure",
    ),

    # 154: Multimodal concatenation
    FPPattern(
        name="multimodal_concatenation_ml",
        scanner=None,
        pattern=r'Multimodal concatenation',
        file_pattern=r'(model|processor|feature|pipeline|multimodal|vision|audio|image).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Multimodal ML models concatenate modalities by design",
    ),

    # ── BENCHMARK FP: milvus (Go/C++/Python vector DB) ──────────────────

    # 155: Bundled/minified JS assets are compiled output
    FPPattern(
        name="bundled_minified_js",
        scanner=None,
        pattern=r'.',
        file_pattern=r'(webui|dist|build)/assets/.*\.js$|\.min\.(js|css)$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.95,
        description="Bundled/minified JS assets are compiled output, not source code",
    ),

    # 156: ShellCheck suggestion to use mapfile/read -a
    FPPattern(
        name="shellcheck_mapfile_read",
        scanner="semgrepscanner",
        pattern=r'Prefer mapfile or read -a',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # 157: egrep deprecated suggestion
    FPPattern(
        name="shellcheck_egrep_deprecated",
        scanner="semgrepscanner",
        pattern=r'egrep is non-standard and deprecated',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # 158: Quote to prevent word splitting
    FPPattern(
        name="shellcheck_word_splitting",
        scanner="semgrepscanner",
        pattern=r'Quote to prevent word splitting',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 159: Useless echo suggestion
    FPPattern(
        name="shellcheck_useless_echo",
        scanner="semgrepscanner",
        pattern=r'Useless echo\?',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # 160: Use variable substitution suggestion
    FPPattern(
        name="shellcheck_variable_replace",
        scanner="semgrepscanner",
        pattern=r'See if you can use \$\{variable',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # 161: Don't use variables in printf format
    FPPattern(
        name="shellcheck_printf_variable",
        scanner="semgrepscanner",
        pattern=r"Don't use variables in the printf",
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 162: Can only exit with status 0-255
    FPPattern(
        name="shellcheck_exit_status",
        scanner="semgrepscanner",
        pattern=r'Can only exit with status 0-255',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # 163: Use find -print0 | xargs -0
    FPPattern(
        name="shellcheck_find_xargs",
        scanner="semgrepscanner",
        pattern=r"find \.\. -print0 \| xargs",
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 164: Word outside quotes nesting suggestion
    FPPattern(
        name="shellcheck_single_quotes",
        scanner="semgrepscanner",
        pattern=r'This word is outside of quotes',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 165: Loop will only run once (bad quoting)
    FPPattern(
        name="shellcheck_loop_once",
        scanner="semgrepscanner",
        pattern=r'This loop will only ever run once',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 166: Kubernetes security findings in CI/Jenkins configs
    FPPattern(
        name="avd_ksv_in_ci_directory",
        scanner="semgrepscanner",
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'(ci|jenkins|\.github|\.gitlab)/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="K8s security rules on CI/CD pod configs, not production workloads",
    ),

    # 167: subprocess in developer CLI tools
    FPPattern(
        name="developer_tool_subprocess",
        scanner="semgrepscanner",
        pattern=r'subprocess call|Starting a process|partial executable path',
        file_pattern=r'tools/|cmd/tools/|scripts/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Developer tools naturally use subprocess for CLI operations",
    ),

    # 168: urllib/url open in developer tools
    FPPattern(
        name="developer_tool_urllib",
        scanner="semgrepscanner",
        pattern=r'urllib|url open|Audit url open',
        file_pattern=r'tools/|cmd/tools/|scripts/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Developer tools use urllib for downloading/API access",
    ),

    # 169: try/except/pass in tools
    FPPattern(
        name="developer_tool_try_except_pass",
        scanner="semgrepscanner",
        pattern=r'Try, Except, Pass',
        file_pattern=r'tools/|cmd/tools/|scripts/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
    ),

    # 170: Path traversal in tools/scripts
    FPPattern(
        name="developer_tool_path_traversal",
        scanner="semgrepscanner",
        pattern=r'Path traversal',
        file_pattern=r'tools/|cmd/tools/|scripts/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
    ),

    # 171: Base64 in Go streaming/protocol code (not AI)
    FPPattern(
        name="go_base64_streaming",
        scanner=None,
        pattern=r'Base64 content in prompt',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Base64 in Go code is protocol encoding, not AI prompt injection",
    ),

    # 172: Go math/rand in non-cryptographic context
    FPPattern(
        name="go_math_rand_non_crypto",
        scanner="semgrepscanner",
        pattern=r'Do not use.*math/rand.*Use.*crypto/rand',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="math/rand is fine for non-cryptographic uses like shuffling, sampling",
    ),

    # 173: API key/URL in embedding provider code
    FPPattern(
        name="embedding_provider_api_key",
        scanner=None,
        pattern=r'(API key found|External HTTP source|Password found) in memory',
        file_pattern=r'embedding.*provider|provider.*embedding',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Embedding providers naturally handle API keys and external HTTP endpoints",
    ),

    # 174: Role markers in non-AI Go code
    FPPattern(
        name="role_markers_in_go",
        scanner=None,
        pattern=r'Role markers in user content|role confusion attack',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Go RBAC/privilege code uses 'role' terminology but isn't AI-related",
    ),

    # 175: PowerShell detection on non-PowerShell files
    FPPattern(
        name="powershell_on_non_windows",
        scanner=None,
        pattern=r'PowerShell subexpression',
        file_pattern=r'\.(sh|go|py|js|ts|rb)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="PowerShell subexpression pattern triggers on shell/JS $ syntax",
    ),

    # 176: YAML duplicate key warnings
    FPPattern(
        name="yaml_duplicate_key",
        scanner="semgrepscanner",
        pattern=r'duplication of key.*in mapping',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
    ),

    # 177: YAML blank line warnings
    FPPattern(
        name="yaml_blank_lines",
        scanner="semgrepscanner",
        pattern=r'too many blank lines',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
    ),

    # =========================================================================
    # BENCHMARK FP: 14-repo comprehensive analysis (2026-02-10)
    # Category 1: Widen existing patterns for JS/TS/Go coverage
    # =========================================================================

    # 178: Sensitive data in plugin return - JS/TS coverage
    FPPattern(
        name="sensitive_data_plugin_return_js_ts",
        scanner=None,
        pattern=r'Sensitive data in plugin return',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JS/TS function return values are not plugin data exfiltration",
    ),

    # 179: Dropout disabled - broader Python filename coverage
    FPPattern(
        name="dropout_disabled_any_python",
        scanner=None,
        pattern=r'Dropout disabled.*overfitting',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Dropout=0 in any Python ML code is valid configuration",
    ),

    # 180: Memory poisoning agent state - JSON coverage
    FPPattern(
        name="memory_poisoning_agent_state_json",
        scanner=None,
        pattern=r'Memory poisoning.*agent state file',
        file_pattern=r'\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JSON config files managing state are not agent memory poisoning",
    ),

    # 181: MCP update without verification - JS/TS coverage
    FPPattern(
        name="mcp_update_no_verify_js_ts",
        scanner=None,
        pattern=r'Update without verification',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JS/TS object update methods are not MCP trojaned updates",
    ),

    # 182: MCP download without integrity - JS/TS coverage
    FPPattern(
        name="mcp_download_no_integrity_js_ts",
        scanner=None,
        pattern=r'Download without integrity',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JS/TS download code in libraries uses framework-level integrity",
    ),

    # 183: AWS Secret Access Key - JS/TS coverage
    FPPattern(
        name="aws_secret_key_js_ts",
        scanner=None,
        pattern=r'AWS Secret Access Key',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JS/TS identifiers containing aws/secret/key are config variables",
    ),

    # 184: Tool definitions in response - JSON/MD coverage
    FPPattern(
        name="tool_definitions_in_response_json_md",
        scanner=None,
        pattern=r'Tool definitions included in response',
        file_pattern=r'\.(json|md|markdown)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="JSON/MD files with tool schemas are documentation, not response leakage",
    ),

    # 185: Secret/token in memory config - Go/JSON coverage
    FPPattern(
        name="secret_in_memory_config_go_json",
        scanner=None,
        pattern=r'Secret.*found in memory config',
        file_pattern=r'\.(go|json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Go/JSON config variable names containing 'secret' are not hardcoded secrets",
    ),

    # 186: API key in memory config - JSON/Go/MD coverage
    FPPattern(
        name="api_key_in_memory_config_json_go_md",
        scanner=None,
        pattern=r'API key found in memory config',
        file_pattern=r'\.(json|go|md|markdown)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="JSON/Go/MD files with API key variable names are config schemas",
    ),

    # 187: External HTTP source - Go coverage
    FPPattern(
        name="external_http_source_go",
        scanner=None,
        pattern=r'External HTTP source',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Go code referencing HTTP endpoints is standard API client code",
    ),

    # 188: Direct secret comparison - Go coverage (companion to #118)
    FPPattern(
        name="direct_secret_compare_go_generic",
        scanner=None,
        pattern=r'Direct secret comparison.*constant-time',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Go == comparisons in non-crypto code are not timing attacks",
    ),

    # 189: Path traversal template literal - JS/TS coverage
    FPPattern(
        name="path_traversal_template_literal_js_ts",
        scanner=None,
        pattern=r'Path traversal.*[tT]emplate literal',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="JS/TS template literals for paths with config variables",
    ),

    # 190: Path traversal Path object - JS/TS coverage
    FPPattern(
        name="path_traversal_path_object_js_ts",
        scanner=None,
        pattern=r'Path traversal.*Path object',
        file_pattern=r'\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="JS/TS Path API usage with config-derived paths",
    ),

    # =========================================================================
    # Category 2: Completely new FP patterns
    # =========================================================================

    # 191: Poutine security tool output files
    FPPattern(
        name="poutine_security_output",
        scanner=None,
        pattern=r'(GitHub App Token|Asymmetric Private Key|AWS Access Key)',
        file_pattern=r'\.poutine\.ya?ml$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="Poutine security analysis output contains embedded patterns, not real secrets",
    ),

    # 192: Files referenced by Poutine reports
    FPPattern(
        name="poutine_referenced_configs",
        scanner=None,
        pattern=r'(GitHub App Token|Asymmetric Private Key)',
        file_pattern=r'(codecov|cubic|lefthook|renovate|tsconfig)\.(ya?ml|json)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="CI/build configs often referenced in security reports, not actual secrets",
    ),

    # 193: LLM cached context files
    FPPattern(
        name="llm_cached_context_files",
        scanner=None,
        pattern=r'.',
        file_pattern=r'codebase_chunks\.json$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.95,
        description="LLM context cache files are derived from source, not separate vulnerabilities",
    ),

    # 194: HuggingFace convert scripts (broad catch-all)
    FPPattern(
        name="hf_convert_scripts_broad",
        scanner=None,
        pattern=r'(from_pretrained|hf_hub_download|Dropout disabled|GPU memory|Unencrypted HTTP|download without integrity)',
        file_pattern=r'convert.*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="HF model conversion scripts contain expected ML patterns",
    ),

    # 195: Embedding pipeline caching disabled - broader coverage
    FPPattern(
        name="embedding_cache_disabled_any_python",
        scanner=None,
        pattern=r'Embedding pipeline.*caching disabled',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Embedding caching settings in any Python ML code are valid config",
    ),

    # 196: Go unsafe package usage
    FPPattern(
        name="go_unsafe_package",
        scanner=None,
        pattern=r'(unsafe|Use of unsafe|Blocklisted import unsafe)',
        file_pattern=r'\.go$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Go unsafe package is commonly used for performance optimizations",
    ),

    # 197: Bundled diagram JavaScript in Livebook
    FPPattern(
        name="bundled_diagram_js_livebook",
        scanner=None,
        pattern=r'SQL.*concatenation',
        file_pattern=r'(architectureDiagram|blockDiagram|classDiagram|erDiagram|flowchart|gantt|gitGraph|mindmap|pie|quadrantChart|requirementDiagram|sankey|sequenceDiagram|stateDiagram|timeline|xyChart|zenuml)-.*\.js$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.95,
        description="Bundled diagram rendering libraries contain embedded SQL-like syntax",
    ),

    # 198: GSI (Generative Style Injection) in Python libraries
    FPPattern(
        name="gsi_in_python_libraries",
        scanner=None,
        pattern=r'GSI|Generative Style Injection',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="GSI patterns in ML libraries are implementation code, not attacks",
    ),

    # 199: Input sanitization without zero-width filtering
    FPPattern(
        name="input_sanitization_no_zerowidth",
        scanner=None,
        pattern=r'Input sanitization without zero-width character filtering',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="General library input validation doesn't need zero-width filtering",
    ),

    # 200: Agent action without logging
    FPPattern(
        name="agent_action_no_logging_library_code",
        scanner=None,
        pattern=r'Agent action without logging',
        file_pattern=r'\.(py|js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Generic library code with actions is not agent orchestration",
    ),

    # 201: Agent with network access
    FPPattern(
        name="agent_with_network_library_code",
        scanner=None,
        pattern=r'Agent with network access',
        file_pattern=r'\.(py|js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Generic library code with HTTP clients is not autonomous agent code",
    ),

    # 202: Information Disclosure - hardcoded credential (ML tokens)
    FPPattern(
        name="hardcoded_credential_ml_tokens",
        scanner=None,
        pattern=r'Information Disclosure.*[hH]ardcoded credential',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="ML token strings in Python are not security credentials",
    ),

    # 203: subprocess call in build/dev scripts
    FPPattern(
        name="subprocess_in_build_scripts",
        scanner=None,
        pattern=r'subprocess call',
        file_pattern=r'(setup|build|install|test_|benchmark|script|ci_|docker).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="subprocess in build/test scripts uses hardcoded safe commands",
    ),

    # 204: Starting process with partial executable path
    FPPattern(
        name="partial_executable_path_build",
        scanner=None,
        pattern=r'Starting a process with a partial executable path',
        file_pattern=r'(setup|build|install|test_|benchmark|script|ci_|docker).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Build/dev scripts use PATH-resolved executables safely",
    ),

    # 205: Kubernetes AVD-KSV in CI/example YAML
    FPPattern(
        name="avd_ksv_in_non_production_yaml",
        scanner=None,
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'(pre-commit-config|\.pre-commit|example|sample|template|test).*\.(ya?ml|json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="K8s security findings in pre-commit/example files, not production configs",
    ),

    # 206: Kubernetes AVD-KSV in embedded YAML (broader)
    FPPattern(
        name="avd_ksv_broad",
        scanner=None,
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'\.(ya?ml|json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="K8s security patterns often trigger on non-K8s YAML configs",
    ),

    # 207: AWS AVD patterns in example/template files
    FPPattern(
        name="avd_aws_in_examples",
        scanner=None,
        pattern=r'AVD-AWS-\d+',
        file_pattern=r'(example|sample|template|test|fixture).*\.(ya?ml|json|tf)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="AWS security findings in example/template files are not production issues",
    ),

    # 208: AVD-AWS patterns (broader)
    FPPattern(
        name="avd_aws_broad",
        scanner=None,
        pattern=r'AVD-AWS-\d+',
        file_pattern=r'\.(ya?ml|json|tf)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.70,
        description="AWS security patterns in config files may be infrastructure-as-code",
    ),

    # 209: AVD-DS (Dockerfile) patterns in GitLeaks
    FPPattern(
        name="avd_ds_dockerfile_patterns",
        scanner="gitleaksscanner",
        pattern=r'(RUN cd|apt-get.*missing.*--no-install-recommends|COPY.*--chown)',
        file_pattern=r'(Dockerfile|\.dockerfile)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.80,
        description="Dockerfile style recommendations via GitLeaks are not secrets",
    ),

    # 210: Quantum/PQC warnings in crypto libraries
    FPPattern(
        name="quantum_pqc_warnings_crypto_lib",
        scanner=None,
        pattern=r'(quantum|post-quantum|PQC|quantum-vulnerable)',
        file_pattern=r'(crypto|tls|cipher|hash|rsa|ecdsa|vault).*\.(go|py|js|ts)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="Quantum warnings on current crypto libraries are future-looking, not current vulns",
    ),

    # 211: Docker Compose findings on non-compose YAML
    FPPattern(
        name="docker_compose_on_non_compose_yaml",
        scanner="dockercomposescanner",
        pattern=r'.',
        file_pattern=r'\.(ya?ml)$',
        file_pattern_negate=False,
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.70,
        description="DockerComposeScanner triggers on many YAML files that aren't docker-compose",
    ),

    # 212: Docker Compose findings on specific non-compose files
    FPPattern(
        name="docker_compose_on_ci_configs",
        scanner="dockercomposescanner",
        pattern=r'.',
        file_pattern=r'(\.github|\.gitlab|ci|jenkins|pre-commit|renovate|dependabot|codecov).*\.(ya?ml|json)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="CI/CD configs are not Docker Compose files",
    ),

    # 213: Token in memory config - broader pattern
    FPPattern(
        name="token_in_memory_config_broad",
        scanner=None,
        pattern=r'Token found in memory config',
        file_pattern=r'\.(py|pyi|go|json|md|markdown)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Variable names containing 'token' in config code are not hardcoded tokens",
    ),

    # 214: Path check without realpath - broader Python coverage
    FPPattern(
        name="path_check_no_realpath_python_broad",
        scanner=None,
        pattern=r'Path check without realpath',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Python path checks in library code are for config/data paths, not security boundaries",
    ),

    # 215: Unencrypted HTTP in Python libraries
    FPPattern(
        name="unencrypted_http_python_lib",
        scanner=None,
        pattern=r'Unencrypted HTTP',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="HTTP references in library code may be internal/localhost or legacy",
    ),

    # 216: Model deleted but GPU memory not cleared
    FPPattern(
        name="model_deleted_gpu_memory_not_cleared",
        scanner=None,
        pattern=r'Model deleted but GPU memory not explicitly cleared',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="GPU memory lifecycle is managed at framework/runtime level",
    ),

    # 217: HuggingFace patterns in generic Python files
    FPPattern(
        name="hf_patterns_generic_python",
        scanner=None,
        pattern=r'(Unsafe Hugging Face Hub download|Adapter from non-standard source)',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.75,
        description="HF Hub usage in any Python ML code is standard practice",
    ),

    # 218: Supply chain patterns in ML libraries
    FPPattern(
        name="supply_chain_ml_library_broad",
        scanner=None,
        pattern=r'Supply Chain',
        file_pattern=r'(transformers|vllm|langchain|llama|model|pretrained|checkpoint).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.80,
        description="Supply chain warnings in ML libraries are inherent to model loading",
    ),

    # 219: Pickle in dataset/cache files
    FPPattern(
        name="pickle_in_datasets_cache",
        scanner=None,
        pattern=r'[pP]ickle',
        file_pattern=r'(dataset|cache|checkpoint|data_).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="Pickle in dataset/cache code is standard ML serialization",
    ),

    # 220: Memory patterns in ML inference
    FPPattern(
        name="memory_patterns_ml_inference",
        scanner=None,
        pattern=r'(Shared memory|Unbounded memory|Memory not cleared)',
        file_pattern=r'(model|infer|generate|pipeline|engine|worker|executor).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.80,
        description="Memory management in ML inference code uses framework-level controls",
    ),

    # 221: Distributed framework patterns (Ray, etc.)
    FPPattern(
        name="distributed_framework_patterns",
        scanner=None,
        pattern=r'(Ray.*framework|Ray.*cluster|distributed.*compute)',
        file_pattern=r'(ray|distributed|parallel|worker|executor|vllm).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Distributed compute frameworks like Ray are standard ML infrastructure",
    ),

    # 222: Adapter/LoRA patterns in ML
    FPPattern(
        name="adapter_lora_patterns_ml",
        scanner=None,
        pattern=r'(LoRA adapter|Adapter.*verification|PEFT)',
        file_pattern=r'(adapter|lora|peft|model|config).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="LoRA/adapter code in ML libraries is model customization infrastructure",
    ),

    # 223: Multimodal patterns in ML
    FPPattern(
        name="multimodal_patterns_ml",
        scanner=None,
        pattern=r'Multimodal',
        file_pattern=r'(vision|audio|image|video|processor|feature|multimodal).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Multimodal patterns in ML libraries are feature extraction code",
    ),

    # 224: Control tokens in chat template code
    FPPattern(
        name="control_tokens_chat_template",
        scanner=None,
        pattern=r'control token',
        file_pattern=r'(chat.*template|template.*chat|jinja|prompt.*format).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Control token handling in chat template code is formatting logic",
    ),

    # 225: Weight initialization patterns
    FPPattern(
        name="weight_init_patterns_ml",
        scanner=None,
        pattern=r'(Constant zero initialization|Random.*initialization)',
        file_pattern=r'(init|weight|layer|model|module).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Weight initialization strategies are standard ML model setup",
    ),

    # 226: Try/except/pass in library code (not just tools)
    FPPattern(
        name="try_except_pass_library",
        scanner="semgrepscanner",
        pattern=r'Try, Except, Pass',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.75,
        description="Try/except/pass is used for graceful degradation in libraries",
    ),

    # 227: urllib/requests audit in library code
    FPPattern(
        name="urllib_audit_library",
        scanner=None,
        pattern=r'(Audit url open|urllib.*open)',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="HTTP libraries in Python code are standard for API clients",
    ),

    # 228: Assert usage in non-test code
    FPPattern(
        name="assert_usage_library",
        scanner="semgrepscanner",
        pattern=r'Use of assert',
        file_pattern=r'\.(py|pyi)$',
        file_pattern_negate=False,
        reason=FPReason.CODE_STYLE,
        confidence=0.70,
        description="Assert statements in library code are for developer invariants",
    ),

    # 229: Eval/exec audit in ML code
    FPPattern(
        name="eval_exec_ml_code",
        scanner=None,
        pattern=r'(eval|exec).*audit',
        file_pattern=r'(config|model|tokeniz|convert|arch).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.75,
        description="eval/exec in ML config/architecture code is for dynamic model construction",
    ),

    # 230: Base64 content patterns in non-AI contexts
    FPPattern(
        name="base64_non_ai_context",
        scanner=None,
        pattern=r'Base64 content',
        file_pattern=r'\.(go|rs|c|cpp|h)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Base64 in system languages is protocol/encoding, not AI prompt injection",
    ),

    # 231: ShellCheck SC2155 (declare and assign)
    FPPattern(
        name="shellcheck_sc2155",
        scanner="semgrepscanner",
        pattern=r'SC2155',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck SC2155 is declare/assign style advisory",
    ),

    # 232: ShellCheck SC2086 (word splitting)
    FPPattern(
        name="shellcheck_sc2086",
        scanner="semgrepscanner",
        pattern=r'SC2086',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
        description="ShellCheck SC2086 is quoting style advisory",
    ),

    # 233: Sensitive data in logs/debug
    FPPattern(
        name="sensitive_data_logs_ml",
        scanner=None,
        pattern=r'Sensitive data in (logs|debug|print)',
        file_pattern=r'(debug|log|test_|util).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Debug/test code logging data is for development, not production",
    ),

    # 234: Hardcoded IP address in config
    FPPattern(
        name="hardcoded_ip_in_config",
        scanner=None,
        pattern=r'Hardcoded IP address',
        file_pattern=r'(config|settings|example|test|default).*\.(py|pyi|json|ya?ml)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Hardcoded IPs in config/example files are defaults (localhost, etc.)",
    ),

    # 235: Timing attack patterns in non-crypto code
    FPPattern(
        name="timing_attack_non_crypto",
        scanner=None,
        pattern=r'timing attack|constant-time',
        file_pattern=r'(model|config|util|helper|test_).*\.(py|pyi|go)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="Timing considerations in non-crypto code are performance, not security",
    ),

    # 236: Role confusion in RBAC code
    FPPattern(
        name="role_confusion_rbac",
        scanner=None,
        pattern=r'role confusion',
        file_pattern=r'(auth|rbac|permission|access|policy).*\.(py|go|js|ts)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.78,
        description="Role terminology in RBAC code is access control, not AI role injection",
    ),

    # 237: Privileged operation patterns in system code
    FPPattern(
        name="privileged_operation_system",
        scanner=None,
        pattern=r'Privileged operation',
        file_pattern=r'(system|daemon|service|admin|root).*\.(py|go|c|rs)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.75,
        description="Privileged operations in system code are expected functionality",
    ),

    # 238: ShellCheck prefer (( expr )) over let
    FPPattern(
        name="shellcheck_prefer_arithmetic",
        scanner="semgrepscanner",
        pattern=r"prefer \(\( expr \)\)",
        file_pattern=r'\.(sh|bash|zsh)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.92,
        description="ShellCheck style suggestion - not a security issue",
    ),

    # 239: ShellCheck prefer $() over backticks
    FPPattern(
        name="shellcheck_prefer_dollar_paren",
        scanner="semgrepscanner",
        pattern=r'Use \$\(\.\.\.\) notation instead of legacy backticks',
        reason=FPReason.CODE_STYLE,
        confidence=0.92,
        description="ShellCheck style suggestion - not a security issue",
    ),

    # 240: ShellCheck literal brace warnings
    FPPattern(
        name="shellcheck_literal_braces",
        scanner="semgrepscanner",
        pattern=r'[{}] is literal\.',
        file_pattern=r'\.(sh|bash|zsh)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck brace literal warning - not a security issue",
    ),

    # 241: Batch size of 1 in ML library code
    FPPattern(
        name="batch_size_1_ml_library",
        scanner=None,
        pattern=r'Batch size of 1',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Batch size=1 in ML library code is valid for inference/testing",
    ),

    # 242: Inefficient batch size in ML code
    FPPattern(
        name="inefficient_batch_size_ml",
        scanner=None,
        pattern=r'inefficient batch size',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Batch size choices in ML library code are design decisions, not vulnerabilities",
    ),

    # 243: Agent action without logging in agent framework libraries
    FPPattern(
        name="agent_action_no_logging_framework",
        scanner=None,
        pattern=r'Agent action without logging',
        file_pattern=r'(langchain|llama_index|crewai|autogen|agent|callback|handler|iterator|executor).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Agent framework library code implements its own logging patterns",
    ),

    # 244: Agent with network access in framework/library code
    FPPattern(
        name="agent_network_access_framework",
        scanner=None,
        pattern=r'Agent with network access',
        file_pattern=r'(langchain|llama_index|crewai|autogen|agent|client|api|service|tool).*\.(py|pyi|js|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Agent framework code providing HTTP/API functionality is expected",
    ),

    # 245: Agent without before_tool_callback in framework code
    FPPattern(
        name="agent_before_tool_framework",
        scanner=None,
        pattern=r'Agent without before_tool',
        file_pattern=r'(langchain|llama_index|crewai|autogen|agent|executor|runner).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Agent framework base classes don't need before_tool_callback",
    ),

    # 246: subprocess security consideration warning
    FPPattern(
        name="subprocess_security_consideration",
        scanner="semgrepscanner",
        pattern=r'Consider possible security implications.*subprocess',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="General subprocess awareness advisory, not an actual vulnerability",
    ),

    # 247: Glob pattern for file enumeration in dev/build tools
    FPPattern(
        name="glob_enumeration_dev_tools",
        scanner="semgrepscanner",
        pattern=r'Glob pattern for file enumeration',
        file_pattern=r'(script|tool|util|build|generate|check|validate|lint|format|ci|test|setup|install|deploy|Makefile|manage).*\.(py|sh|js|ts)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Glob patterns in dev/build tools are standard file operations",
    ),

    # 248: Direct file read in dev/build tools
    FPPattern(
        name="direct_file_read_dev_tools",
        scanner="semgrepscanner",
        pattern=r'Direct file read without path validation',
        file_pattern=r'(script|tool|util|build|generate|check|validate|lint|format|ci|test|setup|install|deploy|manage).*\.(py|sh|js|ts)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="File reads in dev/build tools operate on trusted local files",
    ),

    # 249: requests without timeout in library code
    FPPattern(
        name="requests_no_timeout_library",
        scanner="semgrepscanner",
        pattern=r'Call to requests without timeout',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Missing timeout in library code is a quality issue, not a security vulnerability",
    ),

    # 250: OCR text to LLM in ML model code
    FPPattern(
        name="ocr_text_llm_ml_model",
        scanner=None,
        pattern=r'OCR text to LLM',
        file_pattern=r'(model|vision|ocr|image|multimodal|processor|pipeline|auto).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="OCR/vision handling in ML model code is core functionality",
    ),

    # 251: Reasoning-based RAG exploitation in ML models
    FPPattern(
        name="rag_exploitation_ml_model",
        scanner=None,
        pattern=r'Reasoning-based RAG exploitation',
        file_pattern=r'(model|transform|gemma|llama|gpt|bert|t5|modular|attention).*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Reasoning patterns in ML model code are model architecture, not RAG attacks",
    ),

    # 252: Misinformation/fact-checking disabled in ML config
    FPPattern(
        name="misinformation_risk_ml_config",
        scanner=None,
        pattern=r'Misinformation Risk.*Fact-checking',
        file_pattern=r'\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="Grounding/fact-checking config in ML library code is a design choice",
    ),

    # 253: Unsafe PyTorch load in convert scripts
    FPPattern(
        name="unsafe_pytorch_load_convert",
        scanner=None,
        pattern=r'Use of unsafe PyTorch load',
        file_pattern=r'convert.*\.(py|pyi)$',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="torch.load() in ML conversion scripts is core ML functionality",
    ),

    # 254: MCP tool name shadows in TypeScript/JS tooling
    FPPattern(
        name="mcp_tool_shadow_ts_tooling",
        scanner="semgrepscanner",
        pattern=r'MCP120.*Tool name shadows',
        file_pattern=r'\.(ts|js|tsx|jsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Tool naming in TS/JS utility code is not MCP tool shadowing",
    ),

    # 255: Prompt extraction in LLM framework code
    FPPattern(
        name="prompt_extraction_llm_framework",
        scanner=None,
        pattern=r'Prompt extraction.*print/repeat system instructions',
        file_pattern=r'(langchain|llama_index|prompt|template|chain|agent|ai|llm).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="LLM framework code handling prompts is expected functionality",
    ),

    # 256: Prompt exposed in error message in LLM libraries
    FPPattern(
        name="prompt_in_error_llm_lib",
        scanner=None,
        pattern=r'Prompt exposed in error message',
        file_pattern=r'(langchain|llama_index|openai|anthropic|llm|chain|agent).*\.(py|pyi)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="LLM library error handling with prompt context is standard behavior",
    ),

    # 257: Locale/i18n JSON files with sensitive key names (mastodon)
    FPPattern(
        name="locale_i18n_sensitive_keys",
        scanner=None,
        pattern=r'Potential sensitive data in key',
        file_pattern=r'(locales?/|/locales?/|^locales?/).*\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="i18n translation keys containing words like 'auth', 'password' are not sensitive data",
    ),

    # 258: Ruby linter config files (mastodon)
    FPPattern(
        name="ruby_linter_config",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.(rubocop|rubocop_todo|annotaterb|haml-lint|reek|brakeman)\.ya?ml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Ruby linter and tool configuration files",
    ),

    # 259: Yarn config files (mastodon)
    FPPattern(
        name="yarn_config",
        scanner=None,
        pattern=r'.*',
        file_pattern=r'\.yarnrc\.ya?ml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Yarn package manager configuration",
    ),

    # 260: NPM CVEs in package.json (mastodon)
    FPPattern(
        name="npm_cve_in_config_files",
        scanner=None,
        pattern=r'CVE-202\d',
        file_pattern=r'(package\.json|\.ya?ml|crowdin|scalingo|jsconfig|app\.json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="CVE reports in config/manifest files picked up by wrong scanner",
    ),

    # 261: MCP119 URI scheme in web app routing (mastodon)
    FPPattern(
        name="mcp119_web_app_routing",
        scanner=None,
        pattern=r'MCP119:.*Custom URI scheme.*template injection',
        file_pattern=r'.*\.(ts|tsx|js|jsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Standard web app deep linking/custom protocol handlers, not MCP",
    ),

    # 262: Zero-width Unicode in i18n/UI code (mastodon)
    FPPattern(
        name="zero_width_unicode_i18n",
        scanner=None,
        pattern=r'Zero-width (Unicode|character)',
        file_pattern=r'(locales?/|components?/|ui/|emoji/|stories\.).*\.(ts|tsx|js|jsx|json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Zero-width chars are normal in i18n, emoji, and UI component code",
    ),

    # 263: Full-width ASCII in UI input components (mastodon)
    FPPattern(
        name="full_width_ascii_ui_input",
        scanner=None,
        pattern=r'Full-width ASCII characters detected.*obfuscation',
        file_pattern=r'(compose|input|textarea|autosuggest|handled_link)\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="UI text input components handle full-width chars for CJK input",
    ),

    # 264: Goal hijacking in locale/i18n files (mastodon)
    FPPattern(
        name="goal_hijacking_i18n",
        scanner=None,
        pattern=r'Goal hijacking:.*instruction override',
        file_pattern=r'(locales?/|/locales?/|^locales?/|lint|config).*\.(json|ya?ml)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Translation strings are not goal hijacking attempts",
    ),

    # 265: Chat history export in conversation UI (mastodon)
    FPPattern(
        name="chat_history_export_social_app",
        scanner=None,
        pattern=r'Chat history export functionality',
        file_pattern=r'(conversation|message|chat).*\.(js|jsx|ts|tsx)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Conversation management is core functionality in social media apps",
    ),

    # 266: Weak MCP token in web push/service workers (mastodon)
    FPPattern(
        name="weak_mcp_token_web_push",
        scanner=None,
        pattern=r'Weak MCP token handling',
        file_pattern=r'(web_push|push_notification|service_worker|logging|worker).*\.(js|ts)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Web push notification tokens and service worker tokens, not MCP tokens",
    ),

    # 267: Private key pattern in Ruby/tool config files (mastodon)
    FPPattern(
        name="private_key_config_template",
        scanner=None,
        pattern=r'Asymmetric Private Key:.*private-key',
        file_pattern=r'(\.(annotaterb|rubocop(_todo)?|haml-lint|config|lint)\.ya?ml|crowdin\.yml|scalingo\.json|app\.json|jsconfig\.json)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Key patterns in tool configuration and manifest files",
    ),

    # 268: Gradle wrapper batch script lint (OpenSearch)
    FPPattern(
        name="gradlew_bat_lint",
        scanner="gitleaksscanner",
        pattern=r'(Errorlevel|ECHO OFF|capitalization|BAT extension|file header|Magic numbers)',
        file_pattern=r'gradlew\.bat$',
        reason=FPReason.CODE_STYLE,
        confidence=0.92,
        description="Gradle wrapper batch script style issues are not security findings",
    ),

    # 269: CI config files (codecov, circleci, etc.)
    FPPattern(
        name="ci_config_secrets",
        scanner=None,
        pattern=r'(Service-account|API Key|Token)',
        file_pattern=r'(codecov|circleci|\.travis|\.github/workflows)\.ya?ml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="CI service account references in CI config files are expected",
    ),

    # 270: YAML bracket spacing style
    FPPattern(
        name="yaml_bracket_spacing",
        scanner="semgrepscanner",
        pattern=r'too many spaces inside brackets',
        reason=FPReason.CODE_STYLE,
        confidence=0.92,
        description="YAML bracket spacing is a style issue, not security",
    ),
    # 271: CI/CD config files - AVD-AZU false positives
    FPPattern(
        name="avd_azu_in_cicd_configs",
        scanner=None,
        pattern=r'AVD-AZU-\d+',
        file_pattern=r'\.(poutine|codecov|cubic|lefthook|renovate)\.ya?ml$|renovate\.json$|tsconfig\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.92,
        description="Azure security rules matching CI/CD config files that aren't Azure configs",
    ),
    # 272: GitHub PAT detection in CI/CD configs
    FPPattern(
        name="github_pat_in_cicd_configs",
        scanner=None,
        pattern=r'GitHub Personal Access Token|github-pat',
        file_pattern=r'\.(poutine|codecov|cubic|lefthook|renovate)\.ya?ml$|renovate\.json$|tsconfig\.json$|package\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="GitHub PAT pattern matching in CI/CD configs that reference tokens by name",
    ),
    # 273: GCP service account in CI/CD configs
    FPPattern(
        name="gcp_service_account_in_configs",
        scanner=None,
        pattern=r'(GCP|Google).*[Ss]ervice.account|gcp-service-account',
        file_pattern=r'\.(poutine|codecov|cubic|lefthook|renovate)\.ya?ml$|renovate\.json$|tsconfig\.json$|package\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="GCP service account pattern matching config files that reference accounts by name",
    ),
    # 274: Docker HEALTHCHECK/WORKDIR lint
    FPPattern(
        name="docker_low_value_lint",
        scanner="trivyscanner",
        pattern=r'AVD-DS-0026.*HEALTHCHECK|AVD-DS-0013.*RUN cd',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
        description="Low-value Docker lint findings are style not security",
    ),

    # =========================================================================
    # HashiCorp Vault benchmark FP patterns (275-285)
    # Source: Vault FP analysis 2026-02-11 (~640 FPs in 746 findings)
    # =========================================================================

    # 275: AVD-AWS rules matching non-Terraform YAML config files
    FPPattern(
        name="avd_aws_in_non_terraform_yaml",
        scanner=None,
        pattern=r'AVD-AWS-\d+',
        file_pattern=r'buf\.(gen\.)?ya?ml$|\.golangci\.ya?ml$|aws-nuke\.ya?ml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.92,
        description="AVD-AWS rules matching non-Terraform YAML config files (protobuf, linter configs)",
    ),

    # 276: AVD-KSV rules in Kubernetes test fixture JSON files
    FPPattern(
        name="avd_ksv_in_k8s_test_fixtures",
        scanner=None,
        pattern=r'AVD-KSV-\d+',
        file_pattern=r'(testing|test|fixture|mock|fake)/.*\.json$',
        reason=FPReason.TEST_FILE,
        confidence=0.92,
        description="AVD-KSV rules in Kubernetes test fixture JSON files",
    ),

    # 277: npm package CVEs/GHSAs incorrectly matched against non-package config files
    # Updated: 2026-02-11 - Added GHSA- matching (GitHub Security Advisories use GHSA- not CVE-)
    FPPattern(
        name="npm_cves_in_non_package_configs",
        scanner=None,
        pattern=r'(clean-css|brace-expansion|tmp@|webpack@).*(CVE-|GHSA-)|(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}).*(clean-css|brace-expansion|tmp@|webpack@)',
        file_pattern=r'buf\.(gen\.)?ya?ml$|\.golangci\.ya?ml$|jsconfig\.json$|jsdoc2md\.json$|metadata\.json$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="npm package CVEs/GHSAs incorrectly matched against non-package YAML/JSON config files",
    ),

    # 278: Vault UI Ember.js adapter/component security findings
    FPPattern(
        name="vault_ui_ember_adapter_findings",
        scanner="semgrepscanner",
        pattern=r'Sensitive data in plugin return|Path traversal.*Template literal|MCP123.*without (verification|integrity)|Plugin with database access',
        file_pattern=r'(^|/)ui/(app|lib)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Vault UI Ember.js adapter/component findings - REST API calls, not security issues",
    ),

    # 279: Credential-related labels in UI forms and test mock data
    FPPattern(
        name="credential_labels_in_ui_code",
        scanner="semgrepscanner",
        pattern=r'AWS Secret Access Key|Generic API Key|Hardcoded Password',
        file_pattern=r'(^|/)ui/(app|lib|mirage)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Credential-related labels in UI forms and test mock data, not real secrets",
    ),

    # 280: PQC/quantum crypto warnings in cryptographic library code
    # Updated: 2026-02-11 - Widened file_pattern to cover all Vault source dirs;
    # made scanner-agnostic (RAGSecurityScanner also emits PQC warnings)
    FPPattern(
        name="pqc_warnings_in_crypto_library",
        scanner=None,
        pattern=r'quantum.vulnerable|migrate to NIST PQC|Shor.s algorithm|Go elliptic curve|Go ECDSA key|RSA.*(2048|4096).*key size|RSA key type usage|X25519 key exchange',
        file_pattern=r'sdk/|vault/|physical/|command/|builtin/|helper/|ui/(app|lib|mirage)/',
        reason=FPReason.SECURITY_MODULE,
        confidence=0.90,
        description="PQC/quantum vulnerability warnings in security tool crypto implementation code",
    ),

    # 281: Secret/token handling in Vault's core cache/auth code
    FPPattern(
        name="secrets_in_vault_cache_code",
        scanner="semgrepscanner",
        pattern=r'Secret/token found in memory|Password found in memory',
        file_pattern=r'(cache|vault|seal|barrier|token|auth|credential|agentproxy).*\.go$',
        reason=FPReason.SECURITY_MODULE,
        confidence=0.88,
        description="Secret/token storage in Vault's core cache and auth modules - intentional design",
    ),

    # 282: ShellCheck style suggestions - "Instead of 'let expr'" variant
    FPPattern(
        name="shellcheck_style_let_expr",
        scanner="semgrepscanner",
        pattern=r"Instead of 'let expr'.*prefer",
        file_pattern=r'\.(sh|bash|zsh)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.92,
        description="ShellCheck style suggestion for let expressions - not a security issue",
    ),

    # 283: Security findings in test helpers, mock data, and fixture files
    FPPattern(
        name="security_findings_in_test_mocks",
        scanner="semgrepscanner",
        pattern=r'Long base64 string|Agent (action without logging|with secrets manager|with credential access)',
        file_pattern=r'(test|mirage|fixture|helper|mock|fake|spec).*\.(go|js|ts)$',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="Security findings in test helpers, mock data, and fixture files",
    ),

    # 284: MCP server findings in non-MCP Go/JS code
    FPPattern(
        name="mcp_findings_in_non_mcp_code",
        scanner="semgrepscanner",
        pattern=r'MCP server without authentication',
        file_pattern=r'(vault|hashicorp|consul).*\.(go|js|ts)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="MCP-specific findings in non-MCP server code (Vault, Consul, etc.)",
    ),

    # 285: Timing attack warnings in security tool crypto implementation
    FPPattern(
        name="timing_attack_in_crypto_library",
        scanner="semgrepscanner",
        pattern=r'Secret-dependent conditional.*timing attack',
        file_pattern=r'builtin/logical/|sdk/(helper|logical|physical)/|vault/seal/|vault/barrier/',
        reason=FPReason.SECURITY_MODULE,
        confidence=0.85,
        description="Timing attack warnings in security tool's crypto implementation",
    ),

    # 286: Findings inside MEDUSA's own scan output files
    # Added: 2026-02-11
    # Reason: Vault re-scan found 374 FPs (329 PII + 44 API Key + 1 Private Key) inside
    #         a previous medusa scan output JSON/HTML file that was in the scan path.
    FPPattern(
        name="findings_in_medusa_scan_output",
        scanner=None,
        pattern=r'.',
        file_pattern=r'medusa-scan-\d{8}-\d{6}\.(json|html)$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.95,
        description="Findings inside MEDUSA's own scan output files should be excluded",
    ),

    # 287: PII detection in Vault UI components (credential config forms)
    # Added: 2026-02-11
    # Reason: 17 PII findings in ui/lib/ components that handle LDAP config forms,
    #         Shamir DR token flow, and confirm-leave decorators - not real PII exposure.
    FPPattern(
        name="pii_in_vault_ui_components",
        scanner=None,
        pattern=r'PII detected in LLM context',
        file_pattern=r'(^|/)ui/(app|lib)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="PII detection in Vault UI components - credential config forms, not real PII exposure",
    ),

    # =====================================================================
    # LlamaIndex benchmark FP patterns (288-297)
    # Added: 2026-02-11
    # Reason: LlamaIndex is an LLM/RAG framework LIBRARY. Its core code
    #         constructs prompts, processes LLM output, embeds content, and
    #         handles user input by design. Scanner flags these as vulns, but
    #         they are intentional framework functionality - not security issues.
    #         2,123 findings, ~1,800+ are false positives (94% in llama-index-*/).
    # =====================================================================

    # 288: LLM Guard warnings in LLM framework library code (486 findings)
    # "LLM output returned without toxicity check" (318)
    # "LLM API calls detected without input/output guards" (168)
    FPPattern(
        name="llm_guard_in_llm_framework",
        scanner=None,
        pattern=r'LLM output returned without toxicity|LLM API calls detected without input.output guards',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.90,
        description="LLM guard/toxicity warnings in LLM framework library code - framework doesn't guard itself",
    ),

    # 289: PII detection in LLM/RAG framework code (316 findings)
    # "PII detected in LLM context: Street address" (290)
    # "PII detected in LLM context: Date of birth" (26)
    FPPattern(
        name="pii_detection_in_llm_framework",
        scanner=None,
        pattern=r'PII detected in LLM context',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="PII detection in LLM framework code - framework processes user data by design",
    ),

    # 290: RAG security findings in RAG framework code (177 findings)
    # "LLM response used without output filtering" (84)
    # "RAG content used in prompt without sanitization" (46)
    # "External HTTP source" (52)
    # "RAG poisoning - embedding user-controlled content" (26)
    # "Retrieval filtering disabled" (15)
    FPPattern(
        name="rag_security_in_rag_framework",
        scanner=None,
        pattern=r'LLM response used without output|RAG content used in prompt|External HTTP source|RAG poisoning.*embedding|Retrieval filtering disabled',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="RAG security warnings in RAG framework library - framework implements RAG by design",
    ),

    # 291: Prompt injection findings in prompt framework code (213 findings)
    # "Role markers in user content" (32), "Context window overflow" (31),
    # "User input directly in f-string prompt" (25), "Prompt Injection: User input interpolated" (24),
    # "Directly returning prompt variable" (14), "System prompt interpolated in f-string" (8),
    # "PIC004: User input variable as message content" (13), "Refusal induction pattern" (8),
    # "Full-width ASCII characters detected" (8), "Potential adversarial suffix" (43),
    # "Returning raw response without sanitization" (7)
    FPPattern(
        name="prompt_injection_in_prompt_framework",
        scanner=None,
        pattern=r'Role markers in user content|Context window overflow|User input.*f-string prompt|User input interpolated in prompt|Directly returning prompt|System prompt interpolated|User input variable as message content|Refusal induction|Full-width ASCII|adversarial suffix|Returning raw response without',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Prompt injection warnings in LLM prompt framework - framework constructs prompts by design",
    ),

    # 292: requests without timeout in HTTP-based integrations (134 findings)
    # "Call to requests without timeout" - bandit B113 style
    # In LLM API clients, web readers, embedding providers
    FPPattern(
        name="requests_no_timeout_in_integrations",
        scanner="promptinjectioncodescanner",
        pattern=r'Call to requests without timeout',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]|integrations/',
        reason=FPReason.CODE_STYLE,
        confidence=0.82,
        description="Requests timeout warnings in LLM integration code - low security value for library code",
    ),

    # 293: Memory/agent findings in memory framework code (106 findings)
    # "Memory Poisoning: Persistent memory storage" (24+)
    # "Password found in memory config" (18)
    # "MCP server without authentication" (44)
    # "Weak MCP token handling" (10)
    # "Agent action without logging" (from AgentMemoryScanner)
    FPPattern(
        name="memory_agent_in_agent_framework",
        scanner=None,
        pattern=r'Memory Poisoning.*Persistent|Password found in memory|MCP server without authentication|Weak MCP token|Agent action without logging|Agent with (secrets manager|credential) access',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="Agent/memory security findings in agent framework library - framework implements memory/agents by design",
    ),

    # 294: BeautifulSoup and HTML parsing in document loaders (17 findings)
    # "BeautifulSoup without comment stripping"
    # Document/web readers legitimately parse HTML
    FPPattern(
        name="beautifulsoup_in_document_readers",
        scanner=None,
        pattern=r'BeautifulSoup without comment',
        file_pattern=r'(reader|loader|parser|scraper|html|web).*\.py$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="BeautifulSoup HTML parsing in document reader/loader code",
    ),

    # 295: Try/Except/Pass style lint in framework (32 findings)
    # "Try, Except, Pass detected" (24)
    # "Try, Except, Continue detected" (8)
    FPPattern(
        name="try_except_pass_in_framework",
        scanner=None,
        pattern=r'Try, Except, (Pass|Continue) detected',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.CODE_STYLE,
        confidence=0.82,
        description="Try/except code style findings in framework - not security issues",
    ),

    # 296: Glob pattern and download findings in framework (14 findings)
    # "Glob pattern for file enumeration" (7)
    # "MCP123: Download without integrity" (7)
    FPPattern(
        name="file_ops_in_framework",
        scanner=None,
        pattern=r'Glob pattern for file enumeration|MCP123.*Download without integrity',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="File operation warnings in LLM framework code",
    ),

    # 297: Base64 and encoding findings in framework (9 findings)
    # "Potential Base64 encoded content"
    FPPattern(
        name="base64_in_llm_framework",
        scanner=None,
        pattern=r'Potential Base64 encoded content',
        file_pattern=r'(llama[-_]index|langchain|transformers|vllm|litellm|haystack|autogen|crewai)[-/]',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Base64 encoding in LLM framework data processing code",
    ),

    # =====================================================================
    # IR/Security automation project FP patterns (298-317)
    # Added: 2026-02-11
    # Source: Real-world scan of internal IR/security automation project
    # on macOS. 20 categories spanning ~3,200+ false positives.
    # =====================================================================

    # 298: ShellCheck style warnings in .sh files (1,174 findings)
    # Issues: "Literal carriage return", "read without -r will mangle",
    # "Check exit code directly", "Use find instead of ls",
    # "sudo doesn't affect redirects", "ShellCheck can't follow non-constant source",
    # "This flag is used as a command name"
    FPPattern(
        name="shellcheck_style_in_sh_files",
        scanner="semgrepscanner",
        pattern=r'Literal carriage return|read without -r will mangle|Check exit code directly|Use find instead of ls|sudo doesn.t affect redirects|ShellCheck can.t follow non-constant source|This flag is used as a command name',
        file_pattern=r'\.(sh|bash|zsh)$',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="ShellCheck style warnings in shell scripts are code quality, not security vulnerabilities",
    ),

    # 299: Findings in JSON data files (579 findings)
    # All findings where file ends in .json - audit caches, process dumps,
    # config files, plugin manifests.
    FPPattern(
        name="findings_in_json_data_files",
        scanner=None,
        pattern=r'.',
        file_pattern=r'\.json$',
        reason=FPReason.GENERATED_CODE,
        confidence=0.85,
        description="JSON data files contain data that matches security patterns but aren't exploitable code",
    ),

    # 300: Sensitive data in JSON key names (502 findings)
    # Issue: "Potential sensitive data in key" - regex matches key names
    # containing substrings like 'auth' (in 'author'), 'token' (in 'token_type'),
    # 'secret' (in 'delinea_secret_name'), 'password' (in 'password_emails')
    FPPattern(
        name="sensitive_data_in_json_key_names",
        scanner=None,
        pattern=r'Potential sensitive data in key',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Key name substring matching produces massive FPs ('auth' in 'author', 'token' in 'token_type', etc.)",
    ),

    # 301: Database migration SQL files (413 findings)
    # Issues: "Destructive operation", "Data modification", "Code execution",
    # "Audit Patterns match", "MCP audit logging disabled"
    FPPattern(
        name="migration_sql_destructive_ops",
        scanner=None,
        pattern=r'^(Destructive operation|Data modification|Code execution|Audit Patterns match|MCP audit logging disabled)$',
        file_pattern=r'(^|/)(migrations?|database/migrations?)/',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="SQL migrations contain DROP/DELETE/ALTER statements by definition - these are expected",
    ),

    # 302: Try/Except/Pass and Try/Except/Continue (152 findings)
    # Broader catch-all for any scanner reporting this as security issue
    FPPattern(
        name="try_except_pass_continue_any_scanner",
        scanner=None,
        pattern=r'Try, Except, (Pass|Continue) detected',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
        description="Python try/except/pass or continue is a code style issue, not a security vulnerability",
    ),

    # 303: PII Street address regex false positive (143 findings)
    # Issue: "PII detected in LLM context: Street address"
    # Regex for street addresses matches too many code patterns
    FPPattern(
        name="pii_street_address_regex_fp",
        scanner=None,
        pattern=r'PII detected in LLM context: Street address',
        file_pattern=r'\.(py|js|ts|tsx|jsx|go|rb|rs)$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Regex for street addresses matches too many non-PII code patterns",
    ),

    # 304: Email sending operational findings (117 findings)
    # Issue: "Email sending" flagged as security issue
    FPPattern(
        name="email_sending_operational",
        scanner=None,
        pattern=r'^Email sending$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Email sending is normal application behavior, not a security vulnerability",
    ),

    # 305: Findings in markdown files (78 findings)
    # Issues: "Potential Base64 encoded content", "adversarial suffix",
    # "Base64 encoded payload", "Obfuscation: hex encoding", "Jailbreak", etc.
    FPPattern(
        name="security_patterns_in_markdown",
        scanner=None,
        pattern=r'Base64 encoded|adversarial suffix|Obfuscation.*hex|Jailbreak|encoded payload',
        file_pattern=r'\.(md|mdx|markdown)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Documentation files are not executable - patterns found in docs aren't real vulnerabilities",
    ),

    # 306: Adversarial suffix in non-attack context (50 findings)
    # Issue: "Potential adversarial suffix: long special character sequence"
    # Broader catch-all for any file type
    FPPattern(
        name="adversarial_suffix_broad",
        scanner=None,
        pattern=r'adversarial suffix.*long special character',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Regex for adversarial suffixes matches normal special character sequences in code/docs",
    ),

    # 307: Base64 in AI context scanner (46 findings)
    # Issues: "Potential Base64 encoded content", "Base64 encoded payload detected"
    FPPattern(
        name="base64_in_ai_context_scanner",
        scanner="aicontextscanner",
        pattern=r'Base64 encoded (content|payload)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Base64 encoding is used legitimately everywhere (auth tokens, image data, etc.)",
    ),

    # 308: Temp file insecure usage (43 findings)
    # Issue: "Probable insecure usage of temp file/directory."
    # Bandit B108 - flags any use of /tmp
    FPPattern(
        name="temp_file_insecure_usage",
        scanner=None,
        pattern=r'insecure usage of temp file',
        reason=FPReason.CODE_STYLE,
        confidence=0.80,
        description="Bandit B108 flags any use of /tmp, which is normal in many applications",
    ),

    # 309: Glob pattern for file enumeration - broad (35 findings)
    # Issue: "Glob pattern for file enumeration"
    # Already partially covered by #247, this is a broader catch-all
    FPPattern(
        name="glob_pattern_enumeration_broad",
        scanner=None,
        pattern=r'Glob pattern for file enumeration',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="File globbing is standard programming practice, not a vulnerability",
    ),

    # 310: File deletion operational (34 findings)
    # Issue: "File deletion"
    FPPattern(
        name="file_deletion_operational",
        scanner=None,
        pattern=r'^File deletion$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="File deletion is standard application behavior, not inherently a security vulnerability",
    ),

    # 311: Model advisory (monitoring/drift/audit) (32 findings)
    # Issues: "Model deployment without monitoring", "No drift detection for deployed model",
    # "Model operations without audit logging", "Misinformation Risk: Fact-checking/grounding disabled"
    FPPattern(
        name="model_advisory_best_practices",
        scanner=None,
        pattern=r'Model deployment without monitoring|No drift detection for deployed model|Model operations without audit logging',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="ML ops best practice recommendations, not security vulnerabilities",
    ),

    # 312: subprocess import warning (31 findings)
    # Issue: "Consider possible security implications associated with the subprocess module."
    # Bandit B404 - just importing subprocess is not a vulnerability.
    # Broader than #246 (covers all scanners, not just semgrepscanner)
    FPPattern(
        name="subprocess_import_warning_any_scanner",
        scanner=None,
        pattern=r'Consider possible security implications.*subprocess',
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="Bandit B404 - importing subprocess is not a vulnerability; the usage matters",
    ),

    # 313: Docker INFO level findings (26 findings)
    # Issues: "Review exposed ports for security", "Pin versions in apt get install"
    FPPattern(
        name="docker_info_level_advisories",
        scanner=None,
        pattern=r'Review exposed ports for security|Pin versions in apt.get install',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Informational Docker best practices are advisories, not security vulnerabilities",
    ),

    # 314: Partial executable path (12 findings) + Hardcoded password 'test' (9 findings)
    # + Binding to all interfaces (9 findings) + Dead code (6 findings)
    # Merged low-impact code quality patterns
    FPPattern(
        name="partial_executable_path_any",
        scanner=None,
        pattern=r'Starting a process with a partial executable path',
        reason=FPReason.CODE_STYLE,
        confidence=0.80,
        description="Partial executable path is a code quality consideration, not a security vulnerability",
    ),
    FPPattern(
        name="hardcoded_password_test_literal",
        scanner=None,
        pattern=r"Possible hardcoded password: '(test|Test|TEST)'",
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="The word 'test' matching as a hardcoded password is a classic false positive",
    ),
    FPPattern(
        name="binding_all_interfaces",
        scanner=None,
        pattern=r'Possible binding to all interfaces',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Binding to 0.0.0.0 is common in development and containerized environments",
    ),
    FPPattern(
        name="dead_code_function_never_invoked",
        scanner=None,
        pattern=r'This function is never invoked',
        reason=FPReason.CODE_STYLE,
        confidence=0.85,
        description="Dead code detection is code quality analysis, not a security vulnerability",
    ),

    # =====================================================================
    # Agent0 security operations platform FP patterns (318-327)
    # Added: 2026-02-12
    # Source: Real-world scan of Agent0 security automation platform.
    # Categories: backdoor trigger word collision, defusedxml alias,
    # env var access, OS import, f-string non-prompt, PII in services,
    # FastAPI unprotected endpoints, timing comparison, base64 decode,
    # autoescape in non-HTML.
    # =====================================================================

    # 318: "trigger" word flagged as backdoor indicator (6 findings)
    # HTMX: HX-Trigger, hx-trigger; APScheduler: IntervalTrigger, CronTrigger;
    # Structlog: trigger= metadata; Forensic: item.trigger, task.trigger
    FPPattern(
        name="backdoor_trigger_word_collision",
        scanner=None,
        pattern=r'(?i)backdoor.*trigger|trigger.*pattern',
        context_pattern=r'(?i)(HX-Trigger|hx-trigger|IntervalTrigger|CronTrigger|DateTrigger|structlog|trigger\s*=|item\.trigger|task\.trigger)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Word 'trigger' in HTMX headers, APScheduler, structlog, and audit fields is not a backdoor indicator",
    ),

    # 319: defusedxml import alias - ET aliased to defusedxml.ElementTree (always FP)
    # Scanner flags ET.fromstring() as insecure xml.etree.ElementTree but can't
    # resolve that ET is aliased to defusedxml.ElementTree.
    FPPattern(
        name="defusedxml_import_alias",
        scanner="semgrepscanner",
        pattern=r'(?i)xml\.etree\.ElementTree|insecure XML|XXE',
        file_pattern=r'\.py$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Scanner flags ET.fromstring() as insecure XML but cannot resolve defusedxml import alias",
    ),

    # 320: Agent accessing standard non-secret environment variables (4 findings)
    # os.getenv() for HOSTNAME, HOME, PATH, TZ, LANG, USER, TERM, SHELL, PWD,
    # DISPLAY, LC_ALL, PYTHONPATH, NODE_ENV, PORT - these are non-secret.
    FPPattern(
        name="agent_env_var_non_secret",
        scanner=None,
        pattern=r'(?i)agent.*env.var|accessing.*environment',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Accessing standard non-secret env vars (HOSTNAME, HOME, PATH, TZ, etc.) is not data exfiltration",
    ),

    # 321: OS import flagged without subprocess usage
    # Scanner flags 'import os' as dangerous in plugin/service code when it's
    # only used for os.getenv(), os.path, os.makedirs() - no subprocess execution.
    FPPattern(
        name="os_import_no_subprocess",
        scanner=None,
        pattern=r'(?i)OS.*subprocess.*plugin|subprocess.*plugin.*code',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="import os flagged for subprocess risk but only used for os.getenv/os.path/os.makedirs",
    ),

    # 322: Prompt injection f-string in non-prompt contexts (27+22 findings)
    # f-strings building cost tracking entries, triage scores/narratives,
    # log messages, dictionary/data construction, HTML reports, audit narratives,
    # query descriptions, CLI output - not LLM prompts.
    FPPattern(
        name="prompt_injection_fstring_non_prompt",
        scanner=None,
        pattern=r'(?i)prompt.injection.*f-string|f-string.*prompt|user.input.*f-string|User input (interpolated|assigned directly).*prompt',
        file_pattern=r'(cost_track|triage_scor|_scoring\.py|_tracker\.py|narrative|report_gen|insider|openclaw|views_invest|identity_exec|script)',
        reason=FPReason.CODE_STYLE,
        confidence=0.82,
        description="f-strings in cost tracking, triage scoring, report generation, audit narratives, query descriptions, and CLI output are not LLM prompt injection",
    ),

    # 323: PII detection in internal service pipelines (4 findings)
    # Email addresses used in internal enrichment/lookup services -
    # service-to-service data flows, not external PII exposure.
    FPPattern(
        name="pii_in_internal_service_pipelines",
        scanner=None,
        pattern=r'(?i)PII.*detected.*email|email.*address.*PII|PII.*LLM.*context',
        file_pattern=r'(enrichment|executor|okta|lookup|correlation)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Email addresses in internal enrichment/lookup services are service-to-service data flows, not PII exposure",
    ),

    # 324: Unprotected endpoint with FastAPI Depends (19 findings)
    # Scanner flags FastAPI router functions as "Unprotected Model Endpoint"
    # because it can't trace Depends(get_current_user) DI chain.
    FPPattern(
        name="unprotected_endpoint_fastapi_depends",
        scanner=None,
        pattern=r'(?i)unprotected.*model.*endpoint|unprotected.*endpoint',
        file_pattern=r'routers/',
        reason=FPReason.CODE_STYLE,
        confidence=0.80,
        description="FastAPI router endpoints use Depends(get_current_user) DI chain that scanner cannot trace",
    ),

    # 325: Non-constant-time comparison on non-secret data (1 finding)
    # String comparison flagged as timing attack vector when comparing against
    # default password literals like 'changeme', not hashed passwords.
    FPPattern(
        name="timing_attack_non_secret_literal",
        scanner=None,
        pattern=r'(?i)non-constant.time|timing.attack.*comparison',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="String comparison against default literals like 'changeme' is not a timing attack vector",
    ),

    # 326: Base64 decoding from trusted API sources (1 finding)
    # base64 decoding flagged as 'untrusted input' when data comes from
    # authenticated API responses (e.g., CrowdStrike RTR).
    FPPattern(
        name="base64_decode_trusted_api",
        scanner=None,
        pattern=r'(?i)base64.*decod.*untrusted|untrusted.*base64',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Base64 decoding from authenticated API responses (CrowdStrike RTR, etc.) is trusted input",
    ),

    # 327: Jinja2 autoescape=False for non-HTML templates (1 finding)
    # autoescape=False flagged as XSS risk when templates are used for LLM
    # prompt construction, not HTML rendering.
    FPPattern(
        name="autoescape_false_non_html",
        scanner=None,
        pattern=r'(?i)autoescape.*false|autoescape.*disabled',
        file_pattern=r'(prompt|template)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Jinja2 autoescape=False for LLM prompt templates is not an XSS risk (not rendering HTML)",
    ),

    # =========================================================================
    # Agent0 (FastAPI security operations platform) FP patterns
    # Source: Agent0 benchmark scan 2026-02-13
    # =========================================================================

    # 328: Security platform credential access (90 findings)
    # Security operations platforms legitimately require credential access to
    # integrate with CrowdStrike, Rapid7, Okta, Vault, etc.
    FPPattern(
        name="security_platform_credential_access",
        scanner=None,
        pattern=r'Agent with (credential|secrets?\s*manager) access',
        file_pattern=r'(secrets|vault|executor|enrichment|service|playbook)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Security operations platforms legitimately require credential access to integrate with CrowdStrike, Rapid7, Okta, Vault, etc.",
    ),

    # 329: Forensic tool execution (56 findings)
    # Forensic tool agents execute tools by design - code execution IS the
    # feature, protected by authentication and RBAC.
    FPPattern(
        name="forensic_tool_execution",
        scanner=None,
        pattern=r'(Code|Process|Tool|Data) (execution|modification) without (validation|confirmation)',
        file_pattern=r'(tools.agent|sub.agent|forensic)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Forensic tool agents execute tools by design - code execution IS the feature, protected by authentication and RBAC",
    ),

    # 330: Sensitive system files / env vars (54 findings)
    # Reading environment variables (os.environ) and config files from known
    # paths is standard application behavior, not accessing sensitive files.
    FPPattern(
        name="sensitive_system_files_env_vars",
        scanner=None,
        pattern=r'Tool accesses sensitive system files',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Reading environment variables (os.environ) and config files from known paths is standard application behavior, not a tool accessing sensitive files",
    ),

    # 331: LLM output toxicity on non-LLM output (75 findings)
    # Most flagged returns are API response formatting, report generation, or
    # script output - not LLM output. Standard function returns misidentified.
    # Also covers security operations responses containing alert data and
    # investigation results where toxicity checking is irrelevant.
    FPPattern(
        name="llm_output_toxicity_non_llm",
        scanner=None,
        pattern=r'(LLM output.*without toxicity|toxicity (check|filter)|without toxicity)',
        file_pattern=r'(executor|enrichment|hunter|toolkit|report|script|triage|analyst|soc|security|alert|incident|investigation)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Most flagged returns are API response formatting, report generation, security operations output, or script output - not LLM output. Toxicity checking is for consumer chatbots, not internal SOC tools",
    ),

    # 332: MCP findings on non-MCP FastAPI endpoints (69 findings)
    # FastAPI REST API endpoints misidentified as MCP servers. Application uses
    # JWT auth, structlog audit logging, and TLS - not MCP protocol.
    FPPattern(
        name="mcp_on_non_mcp_fastapi",
        scanner=None,
        pattern=r'MCP (audit logging|server without auth|connection without TLS|token)',
        context_pattern=r'(fastapi|FastAPI|app\s*=\s*FastAPI|from fastapi)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="FastAPI REST API endpoints misidentified as MCP servers. Application uses JWT auth, structlog audit logging, and TLS - not MCP protocol",
    ),

    # 333: PII in archive/template files (31 findings)
    # Archive files contain test/template data with placeholder PII.
    # CloudFormation templates use variable placeholders that look like PII fields.
    FPPattern(
        name="pii_in_archive_templates",
        scanner=None,
        pattern=r'PII detected in LLM context',
        file_pattern=r'(archive/|docs/legacy/|template|\.ya?ml$)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Archive files contain test/template data with placeholder PII. CloudFormation templates use variable placeholders that look like PII fields. Not sent to LLM",
    ),

    # 334: Path traversal on config loading (19 findings)
    # Path() used for config file loading from known paths, code search
    # indexing, or input validation - not user-supplied paths.
    FPPattern(
        name="path_traversal_config_loading",
        scanner=None,
        pattern=r'Path traversal.*Path object',
        file_pattern=r'(code_search|validation|config|index)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Path() used for config file loading from known paths, code search indexing, or input validation - not user-supplied paths",
    ),

    # 335: Defense code flagged as attack (13 findings)
    # Security defense code contains injection patterns for DETECTION
    # (regex patterns to strip attacks). Scanner flags the defense strings.
    # Also covers PowerShell IOC signatures in detection rules.
    FPPattern(
        name="defense_code_flagged_as_attack",
        scanner=None,
        pattern=r'(Prompt Obfuscation.*Llama|instruction override attempt|UPPERCASE variant|Directly returning prompt variable|PowerShell|EncodedCommand|WindowStyle|execution.?policy)',
        file_pattern=r'(ai_engine|sanitiz|detect|defense|guard|init_prompts|powershell_analyzer|triage_scoring|ioc|indicator)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Security defense code contains injection patterns for DETECTION (regex patterns to strip attacks, PowerShell IOC signatures). Scanner flags the defense strings as attacks",
    ),

    # 336: Bash heredoc parse failure (9 findings)
    # Semgrep bash parser limitation with heredocs containing CRLF line endings
    # or complex quoting. Valid bash scripts that execute correctly.
    FPPattern(
        name="bash_heredoc_parse_failure",
        scanner=None,
        pattern=r"(Couldn't (parse|find end token).*here document|Here document was not correctly)",
        reason=FPReason.CODE_STYLE,
        confidence=0.90,
        description="Semgrep bash parser limitation with heredocs containing CRLF line endings or complex quoting. Valid bash scripts that execute correctly",
    ),

    # 337: Vault secret key names (12 findings)
    # These are Vault secret KEY NAMES (the path to look up in HashiCorp Vault),
    # not actual passwords or secrets. E.g., M365_CLIENT_SECRET is the Vault key name.
    FPPattern(
        name="vault_secret_key_names",
        scanner=None,
        pattern=r'Possible hardcoded password.*([A-Z_]+_SECRET|[A-Z_]+_PASSWORD|[A-Z_]+_KEY)',
        file_pattern=r'(secrets|vault|config)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="These are Vault secret KEY NAMES (the path to look up in HashiCorp Vault), not actual passwords or secrets",
    ),

    # 338: Subprocess calls in CLI scripts (9 findings)
    # Subprocess calls in CLI utility scripts and forensic tools use hardcoded
    # commands, not user-supplied input. Scripts are not web-accessible.
    FPPattern(
        name="subprocess_cli_scripts",
        scanner=None,
        pattern=r'subprocess call.*check.*(execution|untrusted)',
        file_pattern=r'(script|forensic|model_scanner)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Subprocess calls in CLI utility scripts and forensic tools use hardcoded commands, not user-supplied input. Scripts are not web-accessible",
    ),

    # 339: MEDUSA config self-scan (19 findings)
    # MEDUSA flagging its own .medusa.yml and .medusa-suppress.yml config files.
    # Rule descriptions in config look like "prompt injection patterns" to scanner.
    FPPattern(
        name="medusa_config_self_scan",
        scanner="semgrepscanner",
        pattern=r'Potential prompt injection pattern',
        file_pattern=r'\.medusa.*\.yml$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="MEDUSA flagging its own .medusa.yml and .medusa-suppress.yml config files. Rule descriptions in config look like prompt injection patterns to the scanner",
    ),

    # 340: MCP token handling on OAuth/bearer tokens (8 findings)
    # Standard OAuth2/bearer token patterns in Okta, Delinea, M365, auth modules
    # flagged as "weak MCP token handling". These aren't MCP tokens at all.
    FPPattern(
        name="mcp_token_handling_oauth",
        scanner="semgrepscanner",
        pattern=r'MCP token',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Standard OAuth2/bearer token patterns in Okta, Delinea, M365, auth modules flagged as weak MCP token handling. These are not MCP tokens",
    ),

    # 341: MCP server without authentication on non-MCP services (5 findings)
    # FastAPI service config and Alembic migrations wrongly identified as
    # "MCP servers". All endpoints use Depends(get_current_user).
    FPPattern(
        name="mcp_server_auth_non_mcp",
        scanner=None,
        pattern=r'MCP server without authentication',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="FastAPI service config and Alembic migrations wrongly identified as MCP servers. All endpoints use Depends(get_current_user) authentication",
    ),

    # 342: CLI argparse output flagged as LLM output (4 findings)
    # CLI tools using args.output from argparse flagged as "LLM output as file
    # path". No LLM involved - this is standard argparse CLI output handling.
    FPPattern(
        name="cli_argparse_output_as_llm",
        scanner="semgrepscanner",
        pattern=r'LLM output.*(?:file path|path traversal)',
        context_pattern=r'argparse|args\.output|ArgumentParser',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="CLI tools using args.output from argparse flagged as LLM output as file path. No LLM involved - standard argparse CLI output handling",
    ),

    # 343: Auto-execution in automated triage (13 findings)
    # Automated triage scoring and AI-assisted analysis flagged for
    # "auto-execution without approval". All actions require authenticated
    # analyst initiation.
    FPPattern(
        name="auto_execution_triage",
        scanner=None,
        pattern=r'[Aa]uto.?execution',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.80,
        description="Automated triage scoring and AI-assisted analysis flagged for auto-execution without approval. All actions require authenticated analyst initiation",
    ),

    # 344: Tool execution in forensic orchestration (8 findings)
    # Forensic tool orchestration agents executing KAPE/UAC tools flagged for
    # "tool definitions included in response" or missing callbacks. Tool
    # execution IS the intended feature, already gated by ToolCallbackScanner.
    FPPattern(
        name="tool_execution_orchestration",
        scanner="semgrepscanner",
        pattern=r'Tool (?:definitions? included|execution without)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Forensic tool orchestration agents executing KAPE/UAC tools. Tool execution IS the feature. Already gated by ToolCallbackScanner but SemgrepScanner duplicates",
    ),

    # 345: TLS/SSL findings in diagnostic scripts (7 findings)
    # Diagnostic utility scripts that intentionally disable TLS to diagnose
    # certificate issues. Not production code - these are troubleshooting tools.
    FPPattern(
        name="tls_diagnostic_scripts",
        scanner=None,
        pattern=r'(?:TLS|SSL|verify|certificate)',
        file_pattern=r'(?:fix_ssl|test_ssl|diagnos|ssl_check|tls_test)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Diagnostic utility scripts that intentionally disable TLS to diagnose certificate issues. Not production code - these are troubleshooting tools",
    ),

    # 346: Docker Compose env substitution flagged as hardcoded password (1 finding)
    # Docker Compose ${DB_PASSWORD} environment variable substitution flagged
    # as "hardcoded password". Scanner can't parse ${} substitution syntax.
    FPPattern(
        name="docker_compose_env_substitution",
        scanner="semgrepscanner",
        pattern=r'[Hh]ardcoded.*password',
        file_pattern=r'docker-compose\.(?:production|prod)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Docker Compose ${DB_PASSWORD} environment variable substitution flagged as hardcoded password. Scanner cannot parse ${} substitution syntax",
    ),

    # 347: Prompt logged in admin/export scripts (3 findings)
    # Admin export scripts that print Azure DevOps/Okta data to console for
    # auditing. No prompts or system instructions involved - these are admin
    # audit export tools.
    FPPattern(
        name="prompt_logged_admin_scripts",
        scanner="semgrepscanner",
        pattern=r'[Pp]rompt logged|[Ii]nformation [Dd]isclosure.*[Pp]rompt',
        file_pattern=r'(?:export_|admin_|audit_)',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.82,
        description="Admin export scripts that print Azure DevOps/Okta data to console for auditing. No prompts or system instructions involved",
    ),

    # 348: Toxicity check in chat platform extensions (32 findings)
    # Chat platform adapter extensions (feishu, discord, telegram, slack, etc.)
    # return JSON API responses or relay messages between platforms. These are
    # infrastructure adapters, NOT raw LLM completions needing toxicity moderation.
    FPPattern(
        name="toxicity_check_chat_extensions",
        scanner="semgrepscanner",
        pattern=r'(?:toxicity check|content moderation)',
        file_pattern=r'extensions?/',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.90,
        description="Chat platform adapter extensions (feishu, discord, telegram, slack, etc.) relay messages between platforms. They are infrastructure code, not raw LLM completions needing toxicity moderation",
    ),

    # 349: LLM API calls at line 1 -- import statements (25 findings)
    # Scanners fire "LLM API calls detected without input/output guards" at
    # line 1 of files that merely import LLM provider SDKs. The actual code
    # is an import/require statement, not an unguarded API call.
    FPPattern(
        name="llm_api_import_statement",
        scanner=None,
        pattern=r'LLM API calls detected without input.?output guards',
        context_pattern=r'^\s*(?:import\s|from\s\S+\s+import\s|(?:const|let|var)\s+.*=\s*require\()',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.92,
        description="Finding fires at line 1 on import statements (import type, from ... import, require), not actual unguarded LLM API calls",
    ),

    # 350: PII Date of birth in Graph API / bash tool types (17 findings)
    # Scanner flags TypeScript interface fields like displayName, aadObjectId
    # as PII, but these are type definitions and output parsing code, not
    # actual personal data being sent to an LLM.
    FPPattern(
        name="pii_typescript_type_definitions",
        scanner="semgrepscanner",
        pattern=r'PII detected in LLM context.*[Dd]ate of birth',
        file_pattern=r'(?:graph-upload|messenger|message-handler|bash-tools|errors)(?:\.\w+)+$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.88,
        description="Pattern matches TypeScript interface field names like displayName and aadObjectId as personal data when they are actually type definitions and output parsing, not real PII",
    ),

    # 351: Discord client ID in documentation (2 findings)
    # Documentation YAML config examples use placeholder IDs like
    # "discord:987654321012345678" as illustrative examples, not real credentials.
    FPPattern(
        name="discord_client_id_docs",
        scanner="markdownscanner",
        pattern=r'[Dd]iscord client.?id',
        file_pattern=r'docs?/.*\.md$',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.95,
        description="Documentation examples with placeholder Discord IDs in YAML config snippets, not real credentials",
    ),

    # 352: Token smuggling in system prompt enforcement (1 finding)
    # Legitimate security boundary definitions in system prompts that instruct
    # the agent to refuse non-sanctioned tasks. These are defensive prompts,
    # not obfuscation attacks.
    FPPattern(
        name="token_smuggling_system_prompt_defense",
        scanner="aicontextscanner",
        pattern=r'[Oo]bfuscation.*token smuggling|[Tt]oken smuggling.*split words',
        file_pattern=r'(?:system-prompt|system_prompt)\.md$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.85,
        description="Legitimate security boundary definition in a system prompt instructing the agent to refuse non-Prose tasks. This is a defensive prompt, not an obfuscation attack",
    ),

    # =========================================================================
    # Category A: Defensive Security Code (21 findings)
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis
    # Reason: Security tools (validators, scanners, audit loggers) are flagged
    # for the detection regexes/patterns they contain. A secrets scanner that
    # has a regex for "BEGIN RSA PRIVATE KEY" is NOT leaking a key; a response
    # validator with a regex for "ignore previous instructions" is NOT prompt
    # injection. These patterns are broad and apply to any security tooling.
    # =========================================================================

    # 353: Prompt injection detection regex in response validators
    # Files named *-validator*, *response-validator*, *input-validator* contain
    # detection regexes for prompt injection patterns. The scanner matches on
    # the regex string itself (e.g. /ignore.*previous.*instructions/), which
    # is the DETECTION code, not an actual injection attempt.
    FPPattern(
        name="prompt_injection_in_validator_regex",
        scanner=None,
        pattern=r'[Pp]rompt injection|instruction override|disregard previous|forget previous',
        file_pattern=r'(?:response|input|prompt|content)[_-]?validat(?:or|ion)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.92,
        description="Prompt injection detection regex in a validator/sanitizer file. The file contains detection patterns, not actual injection attempts",
    ),

    # 354: Private key detection regex in secrets scanners
    # Files named *secrets-scanner*, *secret-detector*, *credential-scanner*
    # contain regex patterns that match PEM headers like "BEGIN RSA PRIVATE KEY".
    # The scanner matches the regex string as if it were an actual private key.
    FPPattern(
        name="private_key_regex_in_secrets_scanner",
        scanner=None,
        pattern=r'[Pp]rivate [Kk]ey',
        file_pattern=r'(?:secret|credential|key|token)[s]?[_-]?(?:scanner|detector|checker|finder|scrubber|redact)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.93,
        description="Private key detection regex in a secrets scanner/detector file. The regex pattern is used for detection, not an actual leaked key",
    ),

    # 355: Sensitive file exfiltration in secrets scanners
    # Secrets scanners reference sensitive file paths (.env, .pem, id_rsa) in
    # their detection patterns. The scanner flags this as "exfiltration" when
    # the file is actually the detection tool itself.
    FPPattern(
        name="sensitive_file_ref_in_secrets_scanner",
        scanner=None,
        pattern=r'[Ss]ensitive file exfiltration|[Ss]ensitive file.*tool',
        file_pattern=r'(?:secret|credential|key|token)[s]?[_-]?(?:scanner|detector|checker|finder|scrubber|redact)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.93,
        description="Secrets scanner references sensitive file patterns for detection. The file IS the security tool, not performing exfiltration",
    ),

    # 356: Credential handling in redaction/sanitization functions
    # Functions named redact*, sanitize*, mask*, scrub* that handle credentials
    # are REMOVING sensitive data, not leaking it. Common in security modules,
    # audit loggers, and validation tools.
    FPPattern(
        name="credential_in_redaction_function",
        scanner=None,
        pattern=r'[Cc]redentials? passed to agent|[Cc]redential',
        context_pattern=r'(?:redact|sanitize|mask|scrub|censor|strip|remove|clean)[A-Za-z]*\s*[\(=:]|REDACTED|\[REDACTED\]|\*{3,}',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Credential reference appears in a redaction/sanitization function that REMOVES sensitive data rather than leaking it",
    ),

    # 357: Destructive operation / code execution in audit loggers
    # Audit logger files contain functions like logConfigChange, logRetention,
    # logDeletion. The scanner sees "delete", "remove", "execute" keywords in
    # function names and flags them, but these are LOGGING operations.
    FPPattern(
        name="destructive_op_in_audit_logger",
        scanner=None,
        pattern=r'[Dd]estructive operation|[Cc]ode execution|[Ff]ile deletion|[Dd]ata modification|[Pp]rocess execution',
        file_pattern=r'(?:audit|event)[_-]?log(?:ger|ging)?',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Destructive operation / code execution finding in an audit logger file. The file LOGS events, it does not perform destructive operations",
    ),

    # 358: Path traversal in secure file writing functions
    # Files named *file-permissions*, *secure-write*, *safe-file* implement
    # secure file operations (permission enforcement, path validation). The
    # scanner flags the writeFile call but misses that the function IS the
    # security control.
    FPPattern(
        name="path_traversal_in_secure_file_module",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:file[_-]?permissions?|secure[_-]?(?:write|file|io)|safe[_-]?file|file[_-]?(?:security|safety|guard))',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Path traversal finding in a secure file permissions/writing module. The file IS the security control that validates paths and enforces permissions",
    ),

    # 359: Credential handling in tool validation modules
    # Files named *tool-validation*, *input-validation* sanitize tool inputs
    # including credential parameters. The scanner sees credential keywords
    # but the code is sanitizing/validating, not leaking.
    FPPattern(
        name="credential_in_tool_validation",
        scanner=None,
        pattern=r'[Cc]redentials? passed to agent|[Cc]redential',
        file_pattern=r'(?:tool|input|param(?:eter)?|request)[_-]?validat(?:or|ion)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.88,
        description="Credential reference in a tool/input validation module. The code validates and sanitizes inputs, not leaking credentials",
    ),

    # 360: Dynamic schema finding in tool validation modules
    # Tool validation files may contain schema construction logic that the
    # scanner flags as "dynamic schema / time-based conditional behavior".
    # This is normal validation infrastructure.
    FPPattern(
        name="dynamic_schema_in_validation",
        scanner=None,
        pattern=r'[Dd]ynamic schema|time-based conditional',
        file_pattern=r'(?:tool|input|param(?:eter)?|request|schema)[_-]?validat(?:or|ion)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.85,
        description="Dynamic schema finding in a validation module. Schema construction in validators is expected behavior, not a vulnerability",
    ),

    # =========================================================================
    # Category B: MCP Protocol Behavior (25 findings)
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis
    # Reason: MCP servers follow the Model Context Protocol which requires
    # specific patterns (tool definitions, request handlers, client-confirmed
    # operations). When the server has its own validation layer (e.g.
    # authenticateMCPRequest), these protocol-standard patterns are not vulns.
    # =========================================================================

    # 361: Tool definitions included in response - standard MCP list_tools
    # MCP protocol REQUIRES servers to return tool definitions via list_tools.
    # getToolDefinitions() / listTools() / tool schemas are protocol-mandated.
    FPPattern(
        name="mcp_tool_definitions_in_response",
        scanner="mcpserverscanner",
        pattern=r'[Tt]ool definitions? included in response',
        context_pattern=r'(?:getToolDefinitions?|listTools?|ListToolsRequestSchema|tool_definitions?|filterTools?|ToolSchema)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.90,
        description="MCP protocol requires servers to return tool definitions via list_tools handler. This is standard protocol behavior, not a vulnerability",
    ),

    # 362: Destructive operation without validation in MCP switch/case handlers
    # MCP servers dispatch tool calls via switch/case on tool name. The MCP
    # client provides confirmation for destructive operations. When the server
    # has authentication (authenticateMCPRequest / validateRequest), flagging
    # each case as "no validation" is incorrect.
    FPPattern(
        name="mcp_destructive_op_with_auth",
        scanner="mcpserverscanner",
        pattern=r'[Dd]estructive operation without validation|[Dd]ata modification without validation',
        context_pattern=r'(?:authenticat(?:e|ion)|validateRequest|verifyAuth|checkPermission|authorize|isAuthorized)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.88,
        description="MCP server has authentication/authorization layer. Destructive operations are validated by the auth middleware, not unvalidated",
    ),

    # 363: Tool execution without before_tool_callback
    # MCP servers using setRequestHandler(CallToolRequestSchema) with their
    # own auth/validation layer do not need the specific before_tool_callback
    # pattern. This is a protocol implementation choice.
    FPPattern(
        name="mcp_tool_exec_with_own_validation",
        scanner="mcpserverscanner",
        pattern=r'[Tt]ool execution without before_tool_callback|No after_tool_callback',
        context_pattern=r'(?:authenticat(?:e|ion)|validateRequest|verifyAuth|checkPermission|authorize|tool[_-]?validat)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP server implements its own validation layer instead of before_tool_callback. Server-side auth is an equivalent security control",
    ),

    # 364: Data leak channel: webhook in HMAC-signed webhook systems
    # Webhook infrastructure with HMAC signing, event filtering, and
    # configurable endpoints is a legitimate feature, not a data leak.
    FPPattern(
        name="webhook_with_hmac_signing",
        scanner=None,
        pattern=r'[Dd]ata [Ll]eak [Cc]hannel.*webhook|webhook.*[Dd]ata [Ll]eak',
        context_pattern=r'(?:hmac|HMAC|createHmac|hmacSign|signPayload|webhook[_-]?(?:secret|signing|signature))',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Webhook system uses HMAC signing for payload integrity. Signed webhooks with configurable event filtering are a secure feature, not a data leak channel",
    ),

    # 365: Data leak channel: webhook as intentional user-configured feature
    # Webhook dispatchers, webhook managers, and configure_webhook tool
    # handlers are intentional features that users configure themselves.
    FPPattern(
        name="webhook_dispatcher_intentional",
        scanner=None,
        pattern=r'[Dd]ata [Ll]eak [Cc]hannel.*(?:webhook|sensitive data sent to webhook)',
        file_pattern=r'webhook[_-]?(?:dispatch|manager|handler|service|client)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Webhook dispatcher/manager is an intentional user-configured feature. Users configure their own webhook endpoints, this is not a data leak",
    ),

    # 366: Over-privileged MCP tool access with settings-based filtering
    # MCP servers that implement tool filtering via settings profiles or
    # permission systems are NOT over-privileged. The scanner misses the
    # filtering layer.
    FPPattern(
        name="mcp_tool_access_with_filtering",
        scanner="mcpserverscanner",
        pattern=r'[Oo]ver-privileged MCP tool access',
        context_pattern=r'(?:filterTools?|settings[_-]?manager|tool[_-]?(?:filter|whitelist|allowlist)|enabledTools?|disabledTools?|profile)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP server implements tool filtering via settings/profiles. Tool access is restricted by configuration, not over-privileged",
    ),

    # 367: Agent with network access - MCP servers require network by design
    # MCP servers are network services. Flagging "agent with network access"
    # on an MCP server is tautological.
    FPPattern(
        name="mcp_server_network_access",
        scanner=None,
        pattern=r'[Aa]gent with network access',
        context_pattern=r'(?:McpServer|MCPServer|createServer|StdioServerTransport|SSEServerTransport|server\.connect|mcp[_-]?server)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP servers are network services by design. Flagging network access on an MCP server is tautological",
    ),

    # 368: Agent with network access in cert-pinning / TLS security modules
    # Certificate pinning, TLS verification, and network security modules
    # ARE the network security controls. Flagging them is circular.
    FPPattern(
        name="network_access_in_cert_security",
        scanner=None,
        pattern=r'[Aa]gent with network access|[Aa]gent without.*validation',
        file_pattern=r'(?:cert[_-]?pinn(?:ing|er)|tls[_-]?(?:verify|valid|config)|ssl[_-]?(?:verify|valid|config)|network[_-]?security)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.88,
        description="Network access finding in a certificate pinning / TLS security module. The file IS the network security control",
    ),

    # 369: Code execution / process execution in MCP server error handlers
    # MCP server error handlers (catch blocks, log.error) are flagged as
    # "code execution" or "process execution". Error logging is not code exec.
    FPPattern(
        name="mcp_error_handler_code_exec",
        scanner="mcpserverscanner",
        pattern=r'[Cc]ode execution without validation|[Pp]rocess execution without validation',
        context_pattern=r'(?:catch\s*\(|\.error\s*\(|log\.error|console\.error|handleError|onError)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Code/process execution finding in an error handler. Error logging and catch blocks are not code execution vulnerabilities",
    ),

    # 370: Agent with download/upload capability - intentional MCP tool features
    # MCP tools that provide download/upload as user-facing features (e.g.
    # download_audio, export_data) are intentional, not capability escalation.
    FPPattern(
        name="mcp_download_upload_feature",
        scanner=None,
        pattern=r'[Aa]gent with download.?upload capability',
        context_pattern=r'(?:download_audio|export_data|upload_file|download_file|save_file|fetch_resource|download_document)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="Download/upload is an intentional user-facing MCP tool feature, not unauthorized capability escalation",
    ),

    # =========================================================================
    # Category C: Compliance Code (8 findings)
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis
    # Reason: GDPR compliance code (DSAR handlers, data erasure, data export,
    # evidence collectors) handles PII and performs file operations because
    # it is LEGALLY REQUIRED to do so. Flagging DSAR responses for containing
    # PII or data erasure for writing files defeats the purpose.
    # =========================================================================

    # 371: PII in response in DSAR handlers
    # GDPR Article 15 REQUIRES Data Subject Access Requests to return all
    # stored PII to the data subject. Flagging this is contradicting the law.
    FPPattern(
        name="pii_in_dsar_handler",
        scanner=None,
        pattern=r'PII.*(?:in response|potentially in response)|[Ii]nformation [Dd]isclosure.*PII',
        file_pattern=r'(?:dsar|data[_-]?subject|gdpr|privacy)[_-]?(?:handler|controller|service|processor|request)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.92,
        description="GDPR DSAR handlers are legally required to return PII to data subjects. Flagging PII in DSAR responses contradicts legal requirements",
    ),

    # 372: Path traversal in data erasure / secure wipe
    # GDPR Article 17 (Right to Erasure) requires secure data deletion.
    # Secure wipe functions write random data over files before deletion.
    # This is a legally mandated security operation.
    FPPattern(
        name="path_traversal_in_data_erasure",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:data[_-]?erasure|secure[_-]?(?:wipe|delete|erase)|gdpr[_-]?(?:delete|erase|cleanup))',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.90,
        description="Data erasure module performs secure file operations as required by GDPR Article 17 (Right to Erasure). File writes are part of secure wipe procedure",
    ),

    # 373: Path traversal in data export / GDPR portability
    # GDPR Article 20 (Right to Data Portability) requires exporting user
    # data. Data export modules read stored data to produce export packages.
    FPPattern(
        name="path_traversal_in_data_export",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:data[_-]?export|data[_-]?portability|gdpr[_-]?export|user[_-]?export)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.90,
        description="Data export module reads stored data as required by GDPR Article 20 (Right to Data Portability). File reads are necessary for producing export packages",
    ),

    # 374: Path traversal in evidence/audit evidence collectors
    # Compliance evidence collectors read logs, configs, and audit trails
    # to produce compliance reports. These file reads are the core function.
    FPPattern(
        name="path_traversal_in_evidence_collector",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:evidence[_-]?collect|audit[_-]?collect|compliance[_-]?(?:collect|evidence|report|gather))',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.88,
        description="Evidence collector reads logs and audit trails to produce compliance reports. File reads are the core function of compliance evidence gathering",
    ),

    # 375: Broad compliance directory filter for path traversal
    # Any file in a compliance/ directory performing file reads/writes is
    # likely doing so for legitimate compliance reasons.
    FPPattern(
        name="path_traversal_in_compliance_dir",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'compliance[/\\]',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.83,
        description="File operation in a compliance directory. Compliance modules handle file I/O for legal data handling requirements",
    ),

    # 376: LLM output toxicity check in compliance modules
    # Compliance tools return structured compliance data (audit logs, DSAR
    # responses, evidence reports). These are not raw LLM completions and
    # do not need toxicity moderation.
    FPPattern(
        name="toxicity_check_in_compliance",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'compliance[/\\]|(?:dsar|data[_-]?(?:erasure|export)|evidence[_-]?collect)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.88,
        description="Compliance modules return structured compliance data (DSAR responses, audit logs), not raw LLM completions. Toxicity moderation is not applicable to legal compliance output",
    ),

    # 377: MCP audit logging disabled in compliance modules
    # Compliance modules may implement their own audit logging infrastructure
    # that is separate from MCP's built-in logging. The scanner does not
    # recognize the custom logging as equivalent.
    FPPattern(
        name="mcp_audit_disabled_in_compliance",
        scanner=None,
        pattern=r'MCP audit logging disabled|[Ll]ogging.*audit.*disabled',
        file_pattern=r'(?:evidence[_-]?collect|compliance[/\\]|audit[_-]?log|query[_-]?log)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.85,
        description="Compliance module implements its own audit logging infrastructure. Custom logging is equivalent to MCP built-in audit logging",
    ),

    # =========================================================================
    # Category D: Documentation Strings (5 findings)
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis
    # Reason: MCP tool description strings and constant arrays listing tool
    # names contain keywords like "API KEY", "authentication", "credential"
    # as documentation. These are metadata strings, not actual credentials
    # or injection attempts.
    # =========================================================================

    # 378: Agent credential access from tool description mentioning API KEY
    # MCP tool definitions contain description strings like "REQUIRES
    # GEMINI_API_KEY" or "NO API KEY REQUIRED". These are documentation,
    # not credential access.
    FPPattern(
        name="credential_in_tool_description",
        scanner=None,
        pattern=r'[Aa]gent with credential access|[Cc]redential',
        context_pattern=r'(?:description\s*[:=]|inputSchema|toolDescription|DESCRIPTION|tool_description)\s*[`\'"]',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.88,
        description="Credential keyword appears in a tool description/documentation string, not actual credential access. MCP tool descriptions naturally reference authentication requirements",
    ),

    # 379: Agent credential access from tool name arrays / constants
    # Arrays listing tool names (GEMINI_TOOLS, TOOL_NAMES, availableTools)
    # are configuration, not credential access.
    FPPattern(
        name="credential_in_tool_name_array",
        scanner=None,
        pattern=r'[Aa]gent with credential access',
        context_pattern=r'(?:TOOLS|TOOL_NAMES|availableTools|enabledTools|toolList|tools\s*[:=]\s*\[)',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.85,
        description="Credential finding triggered by a tool name array/constant. Arrays listing tool names are configuration, not credential access",
    ),

    # 380: Prompt injection in tool definition description fields
    # MCP tool definitions file (definitions.ts, tool-schema.ts) with
    # description fields containing LLM-related keywords are metadata.
    FPPattern(
        name="prompt_injection_in_tool_definition",
        scanner=None,
        pattern=r'[Pp]rompt injection|instruction override',
        file_pattern=r'(?:definitions?|tool[_-]?schema|tool[_-]?spec)[/\\.]',
        context_pattern=r'(?:description\s*[:=]|inputSchema|properties|parameters)',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.85,
        description="Prompt injection finding in a tool definition file. Tool descriptions/schemas naturally contain LLM-related keywords as documentation",
    ),

    # =========================================================================
    # Category E: Context-Lacking / Infrastructure Code (39 findings)
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis
    # Reason: Infrastructure code (logging, SIEM, cert-pinning, change logs)
    # performs internal file operations on its own config/log files. These are
    # not path traversal vulnerabilities. Also, MCP tool result returns are
    # flagged as "LLM output without toxicity check" when they are structured
    # data responses, not raw LLM completions.
    # =========================================================================

    # 381: Path traversal in SIEM exporters / log readers
    # SIEM exporters read their own log files for forwarding to SIEM systems.
    # These are internal operations on known file paths.
    FPPattern(
        name="path_traversal_in_siem_exporter",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:siem[_-]?export|log[_-]?(?:export|forward|ship|collect|rotat))',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.88,
        description="SIEM exporter/log forwarder reads its own log files for forwarding. File reads are internal operations on known log paths",
    ),

    # 382: Path traversal in change log / changelog readers
    # Change log modules read their own log files to display change history.
    FPPattern(
        name="path_traversal_in_change_log",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:change[_-]?log|changelog|migration[_-]?log|version[_-]?log)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.85,
        description="Change log module reads its own log files to display change history. File reads are internal operations on known paths",
    ),

    # 383: Path traversal in query loggers
    # Query loggers read/write their own log files for analytics and audit.
    FPPattern(
        name="path_traversal_in_query_logger",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:query[_-]?log(?:ger)?|sql[_-]?log|db[_-]?log)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.85,
        description="Query logger reads/writes its own log files for analytics. File operations are internal logging infrastructure",
    ),

    # 384: Path traversal in PDF chunker / document processor
    # Document processing modules (PDF chunkers, text extractors) read input
    # files as their core function. The file path comes from the user's
    # explicit tool call, not from untrusted input.
    FPPattern(
        name="path_traversal_in_doc_processor",
        scanner=None,
        pattern=r'[Pp]ath traversal.*[Ff]ile (?:write|read)|[Ff]ile (?:write|read).*unvalidated',
        file_pattern=r'(?:pdf[_-]?chunk|doc[_-]?process|text[_-]?extract|document[_-]?pars)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.83,
        description="Document processing module reads files as its core function. File paths come from explicit user tool calls, not untrusted input",
    ),

    # 385: LLM output toxicity check on MCP tool result returns
    # MCP tool handlers return structured JSON results (content arrays with
    # type/text fields). These are tool outputs, not raw LLM completions.
    # Toxicity moderation applies to LLM-generated text, not tool results.
    FPPattern(
        name="toxicity_check_on_mcp_tool_result",
        scanner="mcpserverscanner",
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        context_pattern=r'(?:return\s*\{|content\s*:\s*\[|type\s*:\s*[\'"]text[\'"]|TextContent|toolResult|ToolResponse)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP tool handler returns structured JSON results. Tool outputs are structured data, not raw LLM completions needing toxicity moderation",
    ),

    # 386: LLM output toxicity check in response validators
    # Response validators that CHECK content for safety are flagged for not
    # having a toxicity check. The validator IS the toxicity/safety check.
    FPPattern(
        name="toxicity_check_in_response_validator",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:response|output|content)[_-]?(?:validat|filter|moderat|sanitiz|check)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Response validator/content filter IS the safety check. Flagging the safety checker for not having a safety check is circular",
    ),

    # 387: LLM API calls without guards at import statements (broader)
    # Scanner fires "LLM API calls detected without input/output guards" at
    # files that import or reference LLM libraries, particularly at line 1
    # where import statements live. Broader than pattern 349 (any scanner).
    FPPattern(
        name="llm_api_calls_at_import_line",
        scanner=None,
        pattern=r'LLM API calls detected without input.?output guards',
        file_pattern=r'compliance[/\\]|(?:dsar|evidence|data[_-]?(?:erasure|export))',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.85,
        description="LLM API guard finding in compliance code that does not make LLM API calls. Scanner triggered on import statements or module-level config",
    ),

    # 388: Sensitive data in MCP logs - intentional debug/startup logging
    # MCP servers log startup configuration (enabled tools, port, transport)
    # for debugging. This is standard server behavior, not data leakage.
    FPPattern(
        name="sensitive_data_in_mcp_startup_logs",
        scanner=None,
        pattern=r'[Ss]ensitive data in MCP logs|[Ss]ensitive data in.*logs',
        context_pattern=r'(?:console\.log|log\.info|log\.debug|logger\.info|logger\.debug).*(?:start|init|config|listen|port|transport|enabled)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.83,
        description="MCP server logs startup configuration (enabled tools, port, transport) for debugging. This is standard server startup logging, not data leakage",
    ),

    # 389: Sensitive data in MCP logs - run discovery / notebook metadata
    # Logging notebook IDs or run metadata for debugging is not sensitive
    # data leakage. These are internal identifiers.
    FPPattern(
        name="sensitive_data_in_discovery_logs",
        scanner=None,
        pattern=r'[Ss]ensitive data in MCP logs',
        file_pattern=r'(?:run[_-]?discover|notebook[_-]?creat|discovery)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.83,
        description="Logging notebook IDs or run metadata for debugging. Internal identifiers are not sensitive data",
    ),

    # 390: Data URI with base64 in resource handlers / icon files
    # MCP resource handlers return data URIs (data:image/png;base64,...) for
    # icons and thumbnails. These are standard web resource patterns.
    FPPattern(
        name="data_uri_in_resource_handler",
        scanner=None,
        pattern=r'[Dd]ata URI with base64',
        file_pattern=r'(?:resource[_-]?handler|icon|thumbnail|image[_-]?(?:util|handler|serve))',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Data URI with base64 in resource handlers or icon files. Base64-encoded images are standard web resource patterns, not payload injection",
    ),

    # 391: Model extraction risk in Gemini client query logging
    # Gemini client files that log queries for debugging/analytics. Query
    # logging for a user's own API calls is standard observability, not
    # model extraction.
    FPPattern(
        name="model_extraction_in_api_client",
        scanner=None,
        pattern=r'[Mm]odel [Ee]xtraction [Rr]isk|[Qq]uery logging.*model extraction',
        file_pattern=r'(?:gemini|openai|anthropic|llm|ai)[_-]?client',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.83,
        description="Query logging in an API client is standard observability for the user's own API calls. This is not model extraction attack infrastructure",
    ),

    # 392: Misinformation risk / fact-checking disabled in API clients
    # API client configuration files may disable grounding/fact-checking
    # for certain use cases. This is a configuration choice, not a vuln.
    FPPattern(
        name="misinformation_risk_in_api_client",
        scanner=None,
        pattern=r'[Mm]isinformation [Rr]isk|[Ff]act.?checking.*disabled|[Gg]rounding disabled',
        file_pattern=r'(?:gemini|openai|anthropic|llm|ai)[_-]?client',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Fact-checking/grounding configuration in an API client. Disabling grounding for specific use cases is a configuration choice documented in the code",
    ),

    # 393: Direct document parsing in API clients
    # API clients that parse documents (PDF, HTML) as part of their core
    # function. The scanner warns about passing parsed output to code
    # execution, but API clients process documents for analysis, not exec.
    FPPattern(
        name="direct_doc_parsing_in_api_client",
        scanner=None,
        pattern=r'[Dd]irect document parsing|document parsing.*code execution',
        file_pattern=r'(?:gemini|openai|anthropic|llm|ai)[_-]?client',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.83,
        description="API client parses documents as its core function. Document analysis results are not passed to code execution",
    ),

    # 394: LLM output toxicity check on chat history / conversation display
    # Chat history tools return stored conversation data. This is retrieval
    # of previously stored messages, not new LLM output.
    FPPattern(
        name="toxicity_check_on_chat_history",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:chat[_-]?histor|conversation[_-]?(?:log|histor|display)|message[_-]?histor)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Chat history tools return previously stored conversations. This is data retrieval, not new LLM output needing toxicity moderation",
    ),

    # 395: LLM output toxicity check on system/status tool definitions
    # System status tools, health checks, and diagnostic tools return
    # operational data, not LLM-generated content.
    FPPattern(
        name="toxicity_check_on_system_tools",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:system|status|health|diagnostic|monitor)[_-]?(?:tool|handler|check)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="System/status tools return operational data (uptime, health metrics), not LLM-generated content needing toxicity moderation",
    ),

    # 396: Agent action without logging in large handler files
    # Large MCP handler files may have some actions without explicit log
    # statements on the same line, but the handler infrastructure includes
    # centralized logging. Low confidence - only for INFO severity.
    FPPattern(
        name="agent_action_without_logging_handlers",
        scanner=None,
        pattern=r'[Aa]gent action without logging',
        file_pattern=r'handler',
        context_pattern=r'(?:log\.|logger\.|console\.log|audit|AuditLogger|createLogger)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.80,
        description="Handler file has centralized logging infrastructure. Individual actions may not have per-line logging but are covered by the centralized audit system",
    ),

    # 397: Agent with filesystem write/delete in MCP tool handlers
    # MCP tool handlers that implement file management tools (save, delete,
    # organize) are providing intentional user-facing features.
    FPPattern(
        name="filesystem_access_in_mcp_handlers",
        scanner=None,
        pattern=r'[Aa]gent with filesystem (?:write|delete|read)',
        context_pattern=r'(?:handleTool|toolHandler|case\s+[\'"]|CallToolRequestSchema|setRequestHandler)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP tool handler provides filesystem operations as intentional user-facing features. These are tool capabilities, not unauthorized access",
    ),

    # 398: Secret-dependent conditional in browser session / auth code
    # Timing attack warnings on secret comparisons in browser automation
    # sessions where the secret is compared against a known value during
    # session setup, not in a security-critical auth path.
    FPPattern(
        name="timing_attack_in_browser_session",
        scanner=None,
        pattern=r'[Ss]ecret-dependent conditional.*timing attack|timing attack risk',
        file_pattern=r'(?:browser[_-]?session|puppeteer|playwright|automation)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Timing attack warning in browser automation session. Session setup comparisons are not in a security-critical authentication path",
    ),

    # 399: Logging/audit disabled in browser session
    # Browser automation sessions may disable verbose logging for performance.
    # The application has centralized audit logging elsewhere.
    FPPattern(
        name="logging_disabled_in_browser_session",
        scanner=None,
        pattern=r'[Ll]ogging.*audit.*disabled|[Aa]udit.*disabled',
        file_pattern=r'(?:browser[_-]?session|puppeteer|playwright|automation)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.80,
        description="Browser automation session may disable verbose logging for performance. Centralized audit logging is handled elsewhere in the application",
    ),

    # 400: LLM output toxicity on browser session responses
    # Browser automation sessions return page content and screenshots.
    # These are web page captures, not LLM-generated text.
    FPPattern(
        name="toxicity_check_on_browser_session",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:browser[_-]?session|puppeteer|playwright|automation[_-]?(?:handler|session))',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Browser automation sessions return page content and screenshots. Web page captures are not LLM-generated text needing toxicity moderation",
    ),

    # 401: LLM output toxicity in Gemini/LLM client response handling
    # The LLM client itself is where the response is received. If the app
    # has a response validator, toxicity checking happens at a different
    # layer. Flagging the raw client is noise when the app has validators.
    FPPattern(
        name="toxicity_check_in_llm_client",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:gemini|openai|anthropic|llm|ai)[_-]?client',
        context_pattern=r'(?:response[_-]?validat|content[_-]?filter|safety[_-]?check|moderat)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.83,
        description="LLM client has a response validator/content filter layer for toxicity checking. Flagging the raw API client when validators exist is redundant",
    ),

    # 402: LLM output toxicity on data-erasure completion results
    # Data erasure modules return completion status messages, not LLM text.
    FPPattern(
        name="toxicity_check_on_data_erasure",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:data[_-]?erasure|secure[_-]?(?:wipe|delete|erase))',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.88,
        description="Data erasure module returns completion status, not LLM-generated text. Erasure confirmation messages do not need toxicity moderation",
    ),

    # 403: LLM output toxicity on ask-question tool definitions
    # Tool definition files for question-answering tools contain description
    # strings about the tool's purpose, not LLM output.
    FPPattern(
        name="toxicity_check_on_tool_definitions",
        scanner=None,
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'(?:definitions?|tool[_-]?(?:schema|spec|def))[/\\.]',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.83,
        description="Tool definition file contains description strings, not LLM output. Tool schema metadata does not need toxicity moderation",
    ),

    # 404: LLM output toxicity on MCP handler result returns (SemgrepScanner)
    # SemgrepScanner version of toxicity check on MCP handlers. The handlers
    # return structured tool results, not raw LLM completions.
    FPPattern(
        name="toxicity_check_on_mcp_handlers_semgrep",
        scanner="semgrepscanner",
        pattern=r'LLM output.*without toxicity check|toxicity check.*content moderation',
        file_pattern=r'handler',
        context_pattern=r'(?:return\s*\{|content\s*:\s*\[|toolResult|handleTool|case\s+[\'"])',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP handler returns structured tool results via SemgrepScanner. Tool outputs are structured data, not raw LLM completions needing toxicity moderation",
    ),

    # =========================================================================
    # Supplementary patterns for remaining MCP server entry-point FPs
    # Added: 2026-02-15
    # Source: notebooklm-mcp-secure FP analysis - remaining missed FPs
    # Reason: MCP server index/entry files have auth at the top but switch/case
    # tool dispatch throughout. The auth is beyond the 20-line context window
    # for findings in the middle/bottom of the file. These patterns match the
    # structural signature of MCP server entry points (case "tool_name":).
    # =========================================================================

    # 405: Destructive/data modification ops in MCP switch/case dispatchers
    # MCP server files that dispatch via switch(name) { case "tool_name": }
    # pattern. Each case delegates to a named handler method. The auth layer
    # at the top of the file validates all requests before dispatch.
    FPPattern(
        name="mcp_switch_case_destructive_op",
        scanner="mcpserverscanner",
        pattern=r'[Dd]estructive operation without validation|[Dd]ata modification without validation',
        context_pattern=r'case\s+[\'"](?:remove|delete|update|create|modify|drop|purge|reset|clear|wipe)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP server dispatches tool calls via switch/case pattern. Each case delegates to a handler. Authentication is enforced at the request handler level before dispatch",
    ),

    # 406: Tool execution without before_tool_callback in MCP servers
    # MCP servers that use setRequestHandler(CallToolRequestSchema) with
    # their own auth do not need before_tool_callback. Broader pattern
    # matching the MCP server file structure (imports + handler setup).
    FPPattern(
        name="mcp_tool_exec_no_callback_broad",
        scanner="mcpserverscanner",
        pattern=r'[Tt]ool execution without before_tool_callback|No after_tool_callback',
        context_pattern=r'(?:CallToolRequestSchema|ListToolsRequestSchema|setRequestHandler|McpServer|StdioServerTransport)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP server uses setRequestHandler with CallToolRequestSchema. The server framework handles request routing with its own auth layer, not requiring before/after_tool_callback",
    ),

    # 407: Over-privileged MCP tool access in MCP server entry point
    # MCP server entry points that expose tools via list_tools are flagged
    # as "over-privileged" when the server defines many tools. When the
    # server has settings-based tool filtering, this is not over-privileged.
    FPPattern(
        name="mcp_overprivileged_in_entry_point",
        scanner="mcpserverscanner",
        pattern=r'[Oo]ver-privileged MCP tool access',
        context_pattern=r'(?:case\s+[\'"]|switch\s*\(\s*(?:name|toolName|tool_name)|CallToolRequestSchema)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP server entry point dispatches tools via switch/case. Tool access is part of the MCP server's design, not over-privileged when tools are filtered by settings",
    ),

    # 408: Data Leak Channel: webhook in MCP tool handler configure_webhook
    # The configure_webhook tool handler dispatches to a webhook system.
    # The handler file itself is not the webhook infrastructure but the
    # MCP tool that configures user-specified webhooks.
    FPPattern(
        name="webhook_data_leak_in_mcp_handler",
        scanner=None,
        pattern=r'[Dd]ata [Ll]eak [Cc]hannel.*(?:webhook|sensitive data sent to webhook)',
        context_pattern=r'(?:configure_webhook|addWebhook|updateWebhook|webhook.*secret|dispatcher\.)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Webhook configuration in an MCP tool handler. The handler configures user-specified webhooks with HMAC secrets, not leaking data to unauthorized endpoints",
    ),

    # 409: Data Leak Channel: webhook in MCP server entry point
    # MCP server index.ts dispatches configure_webhook to handler.
    # The case statement is just routing, not a data leak.
    FPPattern(
        name="webhook_data_leak_in_entry_point",
        scanner=None,
        pattern=r'[Dd]ata [Ll]eak [Cc]hannel.*(?:webhook|sensitive data sent to webhook)',
        context_pattern=r'case\s+[\'"]configure_webhook',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="MCP server dispatches configure_webhook tool to handler. The switch/case routing is not a data leak channel",
    ),

    # 410: Tool definitions included in response - allTools array return
    # Tool definition aggregator files that collect tool definitions from
    # sub-modules and return them as an array. This is standard MCP behavior.
    FPPattern(
        name="mcp_tool_definitions_aggregator",
        scanner="mcpserverscanner",
        pattern=r'[Tt]ool definitions? included in response',
        context_pattern=r'(?:allTools|getTools|toolList|\.map\(|\.filter\(|spread.*tools|\.\.\..*[Tt]ools)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.88,
        description="Tool definition aggregator collects and returns tool definitions from sub-modules. This is standard MCP list_tools protocol behavior",
    ),

    # 411: Agent with credential access in tool description template literal
    # Tool definition files use template literals that mention API keys or
    # auth in their description text. The text is documentation for users.
    FPPattern(
        name="credential_access_in_tool_template",
        scanner=None,
        pattern=r'[Aa]gent with credential access',
        context_pattern=r'(?:API[_\s]?KEY|GEMINI_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY).*(?:required|needed|not needed|NO.*KEY)',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.88,
        description="Tool description template mentions API key requirements as documentation. References to 'API KEY required/not needed' are user-facing documentation, not credential access",
    ),

    # 412: Agent with download/upload in tool definition files
    # Tool definition files that describe download/upload capabilities
    # are documenting the tool's purpose, not unauthorized capabilities.
    FPPattern(
        name="download_upload_in_tool_definition",
        scanner=None,
        pattern=r'[Aa]gent with download.?upload capability',
        file_pattern=r'(?:definitions?|tool[_-]?(?:schema|spec|def))[/\\.]',
        reason=FPReason.DESCRIPTION_STRING,
        confidence=0.83,
        description="Download/upload capability documented in a tool definition file. Tool definitions describe intended capabilities, not unauthorized access",
    ),

    # 413: Agent with filesystem write/delete in MCP tool handlers
    # MCP handler files that implement file management as intentional tool
    # features. Broader version of pattern 397 for SemgrepScanner.
    FPPattern(
        name="filesystem_access_in_tool_handlers",
        scanner="semgrepscanner",
        pattern=r'[Aa]gent with filesystem (?:write|delete|read)',
        file_pattern=r'handler',
        context_pattern=r'(?:handleTool|toolHandler|case\s+[\'"]|handleConfigure|handleCreate|handleDelete|handleUpdate)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP handler provides filesystem operations as intentional user-facing tool features. These are documented tool capabilities, not unauthorized access",
    ),

    # 414: Agent with network access in settings/config managers
    # Settings managers configure tool access and server behavior. They
    # reference network-related settings as part of configuration, not
    # as unauthorized network access.
    FPPattern(
        name="network_access_in_settings_manager",
        scanner=None,
        pattern=r'[Aa]gent with network access',
        file_pattern=r'(?:settings|config)[_-]?(?:manager|handler|service|store)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.80,
        description="Settings/config manager references network settings as part of server configuration. Configuration code is not unauthorized network access",
    ),

    # 415: Trivy duplicate low-severity finding for same Dockerfile line
    # Trivy sometimes reports the same Dockerfile issue at two severity
    # levels (HIGH AVD-DS-XXXX and LOW informational). The LOW duplicate
    # with generic wording is noise when the specific AVD finding exists.
    FPPattern(
        name="trivy_low_duplicate_dockerfile",
        scanner="trivyscanner",
        pattern=r'Avoid additional packages',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.80,
        description="Trivy LOW-severity duplicate of a specific AVD finding on the same Dockerfile line. The specific AVD finding is retained",
    ),

    # 416: No after_tool_callback at file-level (line 1) in MCP servers
    # MCPServerScanner emits "No after_tool_callback for output validation
    # detected" at line 1 as a file-level finding. MCP servers that have
    # their own response validation layer do not need this specific callback.
    FPPattern(
        name="mcp_no_after_callback_file_level",
        scanner="mcpserverscanner",
        pattern=r'No after_tool_callback for output validation',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.80,
        description="File-level finding for missing after_tool_callback. MCP servers can implement response validation through their own layer (response validators, output sanitizers) instead of the specific callback pattern",
    ),

    # 417: Agent with filesystem write/delete in handler result returns
    # SemgrepScanner flags handler return statements near delete/file
    # operations. When the context shows a structured tool result return
    # (success/data/error), the operation is an intentional MCP tool feature.
    FPPattern(
        name="filesystem_in_handler_result_return",
        scanner="semgrepscanner",
        pattern=r'[Aa]gent with filesystem (?:write|delete|read)',
        file_pattern=r'handler',
        context_pattern=r'(?:deleteFile|delete_document|removeFile|success\s*:\s*true|deleted\s*:\s*true|\.delete\()',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.83,
        description="MCP handler returns structured result for a file delete operation. The delete is an intentional tool feature with success/error handling",
    ),

    # 418: MCP handler return result flagged for toxicity check
    # SemgrepScanner flags generic return statements in MCP handlers with
    # "LLM output returned without toxicity check". MCP handlers return tool
    # execution results to the client, not LLM-generated output. Toxicity
    # filtering is applied to LLM responses, not structured tool results.
    FPPattern(
        name="mcp_handler_return_result_toxicity",
        scanner="semgrepscanner",
        pattern=r'toxicity check|content moderation',
        file_pattern=r'handler',
        context_pattern=r'return\s+(?:result|response|output)',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.85,
        description="MCP handler returns tool execution result. This is structured data from tool execution (file contents, database results, etc.), not LLM-generated text requiring toxicity filtering",
    ),

    # 419: Raw SQL on JSONL/file logger modules (no database)
    # Semgrep flags string interpolation in logging/file-writing code as SQL
    # concatenation when the module name contains "query" or "log" but the
    # module has zero SQL/database imports — it's a JSONL file logger.
    FPPattern(
        name="raw_sql_on_file_logger",
        scanner="semgrepscanner",
        pattern=r'Raw SQL',
        file_pattern=r'(?:query[_-]?log|log[_-]?query|file[_-]?log|jsonl)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Raw SQL finding on a file/JSONL logger module that has no SQL database — string interpolation in log statements is not SQL injection",
    ),

    # 420: Raw SQL on filesystem cleanup/utility modules (no database)
    # Semgrep flags template literals in log.success() or fs.rm() calls
    # as SQL concatenation in cleanup utilities that only do filesystem I/O.
    FPPattern(
        name="raw_sql_on_cleanup_utility",
        scanner="semgrepscanner",
        pattern=r'Raw SQL',
        file_pattern=r'(?:cleanup|clean[_-]?up|purge|janitor|sweeper|garbage)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Raw SQL finding on a filesystem cleanup utility — template literals in log statements and fs operations are not SQL injection",
    ),

    # =================================================================
    # SEMGREPSCANNER: RepoMiner FP tuning (2026-02-16)
    # Source: RepoMiner scan analysis
    # =================================================================

    # 421: Toxicity check on CLI terminal output (console.print, print, click.echo)
    # Semgrep flags console.print(f"Found {count} repos") as "LLM output
    # without toxicity check". Terminal/CLI output is not LLM-generated text.
    FPPattern(
        name="toxicity_check_on_cli_output",
        scanner="semgrepscanner",
        pattern=r'toxicity check|content moderation',
        file_pattern=r'cli\.py',
        context_pattern=r'(?:console\.print|click\.echo|print)\s*\(',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Toxicity check finding on CLI terminal output (console.print/click.echo) — this is formatted terminal text, not LLM-generated content",
    ),

    # 422: Toxicity check on MCP parameter description strings
    # Semgrep flags description="Maximum results to return" as "LLM output
    # without toxicity check". Static MCP/FastMCP parameter descriptions
    # are schema metadata, not LLM output.
    FPPattern(
        name="toxicity_check_on_mcp_description",
        scanner="semgrepscanner",
        pattern=r'toxicity check|content moderation',
        file_pattern=r'(?:mcp|server)\.py',
        context_pattern=r'description\s*=\s*["\']',
        reason=FPReason.MCP_PROTOCOL,
        confidence=0.90,
        description="Toxicity check on static MCP parameter description string — schema metadata is not LLM-generated content requiring moderation",
    ),

    # 423: Pseudo-random for retry backoff jitter
    # Semgrep flags random.uniform(0, 1) as "not suitable for security".
    # Using random for retry jitter/backoff delay is standard practice and
    # has no security implications — it's for load distribution, not crypto.
    FPPattern(
        name="random_for_retry_jitter",
        scanner="semgrepscanner",
        pattern=r'pseudo-random|random.*not suitable',
        context_pattern=r'(?:retry|backoff|delay|jitter|attempt|2\s*\*\*\s*attempt)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="random.uniform() used for retry backoff jitter — standard load distribution pattern, not security/cryptographic use",
    ),

    # 424: MCP audit logging finding in general logging utility modules
    # Semgrep/YAML rules flag "MCP audit logging disabled" in modules named
    # logging.py that are general-purpose logging utilities, not MCP servers.
    FPPattern(
        name="mcp_audit_on_logging_utility",
        scanner=None,
        pattern=r'MCP audit logging disabled',
        file_pattern=r'(?:^|/)(?:utils?/)?logging\.py$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="MCP audit logging finding on a general-purpose logging utility — module provides logging infrastructure, not MCP server functionality",
    ),

    # 425: Prompt injection detection patterns in security/defense files
    # Security modules (security.py, sanitizer.py, input_filter.py) contain
    # prompt injection strings as *detection patterns*, not as attacks.
    # "ignore previous instructions" in security.py is a defensive blocklist.
    FPPattern(
        name="prompt_injection_in_security_module",
        scanner=None,
        pattern=r'(?:prompt injection|ignore previous|disregard previous|forget previous|instruction override)',
        file_pattern=r'(?:^|/)(?:security|sanitiz|input[_-]?filter|content[_-]?filter|prompt[_-]?guard|injection[_-]?detect)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.92,
        description="Prompt injection pattern found in a security/defense module — these are detection patterns in a blocklist, not actual injection attempts",
    ),

    # 426: "Agent with network access" on HTTP user_agent config fields
    # Semgrep matches the word "agent" in user_agent (HTTP User-Agent header)
    # combined with nearby HTTP/network config fields. A static Pydantic
    # config default for User-Agent strings is not an autonomous AI agent.
    FPPattern(
        name="agent_network_on_user_agent_config",
        scanner="semgrepscanner",
        pattern=r'[Aa]gent with network access',
        file_pattern=r'config\.py',
        context_pattern=r'user[_-]?agent',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="'Agent with network access' triggered by HTTP User-Agent header config — user_agent is an HTTP header string, not an autonomous AI agent",
    ),

    # 427: Prompt injection on Rich console.print() / CLI terminal output
    # Semgrep flags f-string interpolation in console.print() or
    # progress.console.print() as "user input in prompt string". Rich
    # terminal output is local display, not LLM prompt construction.
    FPPattern(
        name="prompt_injection_on_terminal_output",
        scanner="semgrepscanner",
        pattern=r'[Pp]rompt [Ii]njection.*input interpolated|[Uu]ser input interpolated in prompt',
        context_pattern=r'(?:console\.print|progress\.console|click\.echo|rich\.print|print)\s*\(',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Prompt injection finding on terminal output (Rich console.print / click.echo) — local CLI display is not LLM prompt construction",
    ),

    # 428: Prompt injection on API error message interpolation
    # Semgrep flags interpolation of API response messages into exception
    # constructors as "user input in prompt string". Error propagation from
    # upstream HTTPS APIs (GitHub, etc.) into structured error responses is
    # standard error handling, not prompt injection.
    FPPattern(
        name="prompt_injection_on_api_error_message",
        scanner="semgrepscanner",
        pattern=r'[Pp]rompt [Ii]njection.*input interpolated|[Uu]ser input interpolated in prompt',
        file_pattern=r'(?:sources?|api|client|github|gitlab|bitbucket)',
        context_pattern=r'(?:Error|Exception|raise|throw)\s*\(',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Prompt injection finding on API error message interpolation — upstream API responses propagated into exceptions are standard error handling, not LLM prompt construction",
    ),

    # 429: Prompt injection false positive on SQL LIKE parameter construction
    # OWASPLLMScanner pattern `f"...{query}..."` matches SQL LIKE patterns
    # like `f"%{query}%"` where `query` is a database search term used with
    # parameterized queries (? placeholders), not LLM prompt construction.
    FPPattern(
        name="prompt_injection_on_sql_like_param",
        scanner="owaspllmscanner",
        pattern=r'[Pp]rompt [Ii]njection.*input interpolated|[Uu]ser input interpolated in prompt',
        file_pattern=r'(?:database|db|dao|repo|query|model|storage)',
        context_pattern=r'(?:LIKE\s*\?|WHERE\s|SELECT\s|INSERT\s|params|execute|cursor)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Prompt injection finding on SQL LIKE parameter construction — f-string builds a LIKE pattern value passed via parameterized query, not LLM prompt interpolation",
    ),

    # 430: Hardcoded password false positive on empty string comparison
    # PythonScanner flags `if github_token == ""` as "Possible hardcoded password"
    # because it sees an empty string near a credential variable name. The code is
    # actually checking if a token is empty to set it to None, not hardcoding a password.
    FPPattern(
        name="hardcoded_password_on_empty_string_check",
        scanner="pythonscanner",
        pattern=r'[Hh]ardcoded password.*(?:\'\'|"")',
        context_pattern=r'(?:==\s*""|==\s*\'\'|is\s+None|=\s*None)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="Hardcoded password finding on empty string comparison — code checks if a token/key is empty to null it out, not hardcoding a credential",
    ),

    # 431: AIC-EXFIL-005 fires on .key as part of Python .keys() dict method
    # The pattern (?i)(id_rsa|id_ed25519|\.pem|\.key|authorized_keys) matches
    # DICT_NAME.keys() calls because .key matches the \.key part of the pattern
    FPPattern(
        name="ssh_key_pattern_on_dict_keys_method",
        scanner=None,
        pattern=r'Exfiltration instruction - SSH key access',
        context_pattern=r'\.keys\(\)|_names\.keys|_map\.keys|dict\.keys',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="AIC-EXFIL-005 SSH key pattern fires on .keys() Python dict method — .key matches the .key part of the pattern",
    ),

    # 432: AIC-EXFIL-005 fires on .key file extension in legitimate config/doc references
    FPPattern(
        name="ssh_key_pattern_on_key_variable_names",
        scanner=None,
        pattern=r'Exfiltration instruction - SSH key access',
        context_pattern=r'(?:CLASS_NAMES|METHOD_NAMES|FUNCTION_NAMES|_keys\b|key_name|key_type|api_key|key_func|lookup_key)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="AIC-EXFIL-005 SSH key pattern fires on key-related variable/constant names in application code",
    ),

    # 433: MEDUSA-GENAI-SCAN-012 fires on all from_pretrained() calls in ML research code
    # The rule detects model loading without supply chain scanning, but research/adversarial ML
    # repos legitimately load models for research purposes without needing supply chain checks
    FPPattern(
        name="supply_chain_scan_on_research_ml_code",
        scanner=None,
        pattern=r'LLM model loading or ML library installation without supply chain',
        file_pattern=r'(?:attack|adversar|benchmark|test|eval|research|experiment)',
        reason=FPReason.ML_COMMON,
        confidence=0.90,
        description="MEDUSA-GENAI-SCAN-012 fires on model loading in research/adversarial ML code — supply chain scanning not applicable to research repos",
    ),

    # 434: LLMOPS-LORA_SEC-005 fires on from_pretrained calls in adversarial NLP research
    # Research code loads models from HuggingFace for adversarial attack testing - not a vulnerability
    FPPattern(
        name="lora_adapter_on_textattack_style_research",
        scanner=None,
        pattern=r'adapter from non-standard source',
        file_pattern=r'(?:attack|adversar|benchmark|test|eval|research|experiment)',
        reason=FPReason.ML_COMMON,
        confidence=0.88,
        description="LLMOPS-LORA_SEC-005 fires on from_pretrained in adversarial NLP research code — legitimate research model loading",
    ),

    # 435: LLMOPS-GPU_MEMO-003 fires on standard PyTorch .to("cuda") in ML research scripts
    # TrojanNN, backdoor attack repos and similar ML security research routinely use
    # model.to("cuda") / pipe.to("cuda") / self.model.to("cuda"). This is idiomatic
    # PyTorch and is not a security concern in research/benchmark code — the rule is
    # aimed at production inference services that omit cleanup, not training scripts.
    # Added: 2026-02-25
    FPPattern(
        name="gpu_memo_003_standard_pytorch_to_cuda",
        scanner="llmopsscanner",
        pattern=r'Model moved to GPU - ensure proper cleanup after inference',
        context_pattern=r'(?:model|pipe|self\.model|net|module|trainer)\s*=\s*(?:model|pipe|self\.model|net|module|trainer)\s*\.\s*to\s*\(\s*["\']cuda|\.to\s*\(\s*device\s*\)',
        file_pattern=r'(?:attack|adversar|backdoor|poison|trojan|benchmark|research|experiment|train|eval|notebook|demo)',
        reason=FPReason.ML_COMMON,
        confidence=0.87,
        description="LLMOPS-GPU_MEMO-003 fires on standard PyTorch .to('cuda')/.to(device) in ML research/training scripts — not a production inference cleanup issue",
    ),

    # 436: LLMOPS-GPU_MEMO-003 fires on .to("cuda") when no cleanup concern exists
    # Broader catch for any .to("cuda") that matches the standard reassignment idiom:
    #   model = model.to("cuda")
    #   pipe = pipe.to("cuda")
    # These are safe because Python garbage collection handles the CPU tensor reference.
    # The filter applies to any .py file where the line follows the standard reassignment
    # pattern, giving the scanner a fallback when the file path does not contain research
    # keywords but the code context is clearly idiomatic PyTorch.
    # Added: 2026-02-25
    FPPattern(
        name="gpu_memo_003_standard_reassignment_to_cuda",
        scanner="llmopsscanner",
        pattern=r'Model moved to GPU - ensure proper cleanup after inference',
        context_pattern=r'\b(?:model|pipe|net|module|self\.\w+)\s*=\s*(?:model|pipe|net|module|self\.\w+)\s*\.\s*to\s*\(\s*["\']cuda["\']',
        file_pattern=r'\.py$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="LLMOPS-GPU_MEMO-003 fires on standard PyTorch reassignment idiom 'model = model.to(\"cuda\")' — idiomatic pattern, not an inference cleanup gap",
    ),

    # =========================================================================
    # 437-502: FP patterns for newly wired scanner categories (v2026.5.0)
    # Added: 2026-03-18
    # =========================================================================

    # 437: voice_audio_attacks rules fire on audio processing libraries
    FPPattern(
        name="voice_audio_standard_processing",
        scanner="modelattackscanner",
        pattern=r'(?:voice|audio|speech).*(?:attack|adversarial|perturbation)',
        context_pattern=r'(?:librosa|soundfile|scipy\.io\.wavfile|torchaudio)\.',
        file_pattern=r'(?:audio|speech|voice|sound).*\.py$',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Audio attack rules fire on standard audio processing code",
    ),

    # 438: watermarking_bypass rules fire on legitimate watermark implementations
    FPPattern(
        name="watermark_implementation_code",
        scanner="modelattackscanner",
        pattern=r'(?:watermark|watermarking).*(?:bypass|remove|evasion)',
        context_pattern=r'(?:class\s+Watermark|def\s+(?:add|embed|apply)_watermark)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Watermark bypass rules fire on watermark implementation code",
    ),

    # 439: dp_attacks rules fire on differential privacy implementations
    FPPattern(
        name="dp_implementation_code",
        scanner="modelattackscanner",
        pattern=r'(?:differential.privacy|dp).*(?:attack|vulnerability)',
        context_pattern=r'(?:opacus|tensorflow_privacy|dp_sgd|PrivacyEngine|make_private)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="DP attack rules fire on differential privacy implementation/defense code",
    ),

    # 440: model_extraction rules fire on model export code
    FPPattern(
        name="model_extraction_export_code",
        scanner="modelattackscanner",
        pattern=r'(?:model.*extract|extraction.*model)',
        context_pattern=r'(?:torch\.save|model\.save|export_model|save_pretrained)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Model extraction rules fire on legitimate model export/save code",
    ),

    # 441: multimodal_attacks rules fire on standard multimodal pipelines
    FPPattern(
        name="multimodal_standard_pipeline",
        scanner="modelattackscanner",
        pattern=r'(?:multimodal|multi.modal).*(?:attack|adversarial)',
        context_pattern=r'(?:CLIPProcessor|Blip2|LlavaForConditionalGeneration|ViltProcessor)',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Multimodal attack rules fire on standard vision-language pipeline code",
    ),

    # 442: privacy_attacks rules fire on privacy-preserving ML
    FPPattern(
        name="privacy_preserving_ml",
        scanner="modelattackscanner",
        pattern=r'(?:privacy|membership.inference|model.inversion)',
        context_pattern=r'(?:class\s+Privacy|def\s+protect|anonymize|k_anonymity|l_diversity)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Privacy attack rules fire on privacy-preserving ML defense code",
    ),

    # 443: finetuning_security rules fire on standard fine-tuning code
    FPPattern(
        name="finetuning_standard_training",
        scanner="modelattackscanner",
        pattern=r'(?:fine.?tun|finetun).*(?:security|attack|poisoning)',
        context_pattern=r'(?:Trainer|TrainingArguments|SFTTrainer|AutoModelFor)',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Fine-tuning security rules fire on standard HuggingFace training code",
    ),

    # 444: synthetic_data_poisoning rules fire on synthetic data generation
    FPPattern(
        name="synthetic_data_generation",
        scanner="modelattackscanner",
        pattern=r'(?:synthetic.*data|data.*synthetic).*(?:poison|attack)',
        context_pattern=r'(?:faker|Faker|SDV|CTGAN|synthetic_data|DataSynthesizer)',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Synthetic data poisoning rules fire on legitimate data generation libraries",
    ),

    # 445: reasoning_attacks rules fire on CoT/reasoning chain code
    FPPattern(
        name="reasoning_chain_implementation",
        scanner="owaspllmscanner",
        pattern=r'(?:reasoning|chain.of.thought).*(?:attack|manipulation)',
        context_pattern=r'(?:chain_of_thought|reasoning_chain|think_step_by_step|CoT)',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="Reasoning attack rules fire on CoT/reasoning implementation code",
    ),

    # 446: slopsquatting rules fire on legitimate package references
    FPPattern(
        name="slopsquatting_known_packages",
        scanner="owaspllmscanner",
        pattern=r'(?:slopsquat|hallucinated.*package)',
        file_pattern=r'(?:requirements|setup\.py|pyproject\.toml|package\.json)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Slopsquatting rules fire on legitimate dependency management files",
    ),

    # 447: ml_supply_chain rules fire on standard pip/npm install
    FPPattern(
        name="ml_supply_chain_standard_install",
        scanner="owaspllmscanner",
        pattern=r'(?:supply.chain|package.*install).*(?:attack|hijack)',
        context_pattern=r'(?:pip install|npm install|requirements\.txt|package\.json)',
        file_pattern=r'(?:Dockerfile|Makefile|\.github|CI|ci)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.85,
        description="Supply chain rules fire on standard CI/CD package installation",
    ),

    # 448: dependency_intent_validation rules fire on lockfiles
    FPPattern(
        name="dependency_intent_validation_lockfile",
        scanner="owaspllmscanner",
        pattern=r'(?:dependency|package).*(?:intent|validation|integrity)',
        file_pattern=r'(?:package-lock|yarn\.lock|Pipfile\.lock|poetry\.lock)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Dependency validation rules fire on lockfiles which already pin versions",
    ),

    # 449: provenance_attribution rules fire on license/attribution code
    FPPattern(
        name="provenance_license_code",
        scanner="owaspllmscanner",
        pattern=r'(?:provenance|attribution).*(?:missing|lack|absent)',
        context_pattern=r'(?:license|LICENSE|SPDX|copyright|Copyright)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.88,
        description="Provenance rules fire on code that already has license/attribution",
    ),

    # 450: guardrail_bypass rules fire on guardrail implementations
    FPPattern(
        name="guardrail_implementation_code",
        scanner="owaspllmscanner",
        pattern=r'(?:guardrail|content.filter).*(?:bypass|evasion)',
        context_pattern=r'(?:class\s+Guardrail|def\s+(?:check|validate|filter)_(?:input|output)|NeMoGuardrails|guardrails\.ai)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Guardrail bypass rules fire on guardrail implementation/defense code",
    ),

    # 451: long_context_attacks rules fire on context window management
    FPPattern(
        name="long_context_management",
        scanner="owaspllmscanner",
        pattern=r'(?:long.context|context.window).*(?:attack|overflow)',
        context_pattern=r'(?:max_tokens|context_length|truncat|sliding_window|chunk_size)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Long context attack rules fire on standard context window management code",
    ),

    # 452: post_quantum_crypto rules fire on standard crypto libraries
    FPPattern(
        name="post_quantum_standard_crypto",
        scanner="owaspllmscanner",
        pattern=r'(?:post.quantum|quantum.*crypto|lattice.*based)',
        context_pattern=r'(?:from\s+cryptography|import\s+(?:rsa|ecdsa|ed25519)|openssl)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Post-quantum crypto rules fire on standard cryptographic library usage",
    ),

    # 453: security_tool_evasion rules fire on security scanning code
    FPPattern(
        name="security_tool_evasion_scanner_code",
        scanner="aicontextscanner",
        pattern=r'(?:security.*tool|scanner|antivirus).*(?:evasion|bypass|disable)',
        context_pattern=r'(?:class\s+Scanner|def\s+scan|security_check|run_scan|medusa)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.92,
        description="Security tool evasion rules fire on security scanner implementation code",
    ),

    # 454: coding_editor_attacks rules fire on IDE extension/plugin code
    FPPattern(
        name="coding_editor_extension_code",
        scanner="aicontextscanner",
        pattern=r'(?:editor|ide|vscode|cursor).*(?:attack|exploit)',
        context_pattern=r'(?:vscode\.ExtensionContext|activate\s*\(|registerCommand|extension\.ts)',
        file_pattern=r'(?:extension|plugin|addon)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Coding editor attack rules fire on legitimate IDE extension code",
    ),

    # 455: ai_ide_repo_poisoning rules fire on IDE config files
    FPPattern(
        name="ai_ide_config_files",
        scanner="aicontextscanner",
        pattern=r'(?:repo.*poison|cursorrules|claude\.md).*(?:inject|malicious)',
        file_pattern=r'(?:\.cursorrules|CLAUDE\.md|\.github/copilot)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Repo poisoning rules fire on the legitimate AI config files they're meant to protect",
    ),

    # 456: prompt_injection_attacks rules fire on input validation code
    FPPattern(
        name="prompt_injection_input_validation",
        scanner="aicontextscanner",
        pattern=r'(?:prompt.*inject|injection.*detect)',
        context_pattern=r'(?:def\s+(?:sanitize|validate|check|filter)|class\s+(?:Input|Prompt)(?:Validator|Filter|Guard))',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Prompt injection rules fire on input validation/defense code",
    ),

    # 457: ai_red_teaming rules fire on red team tool implementations
    FPPattern(
        name="ai_red_teaming_tool_code",
        scanner="aicontextscanner",
        pattern=r'(?:red.team|adversarial.test)',
        context_pattern=r'(?:class\s+RedTeam|def\s+(?:run_attack|test_model|evaluate_safety)|garak|pyrit)',
        file_pattern=r'(?:red_team|adversarial|safety_eval)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.88,
        description="Red teaming rules fire on legitimate safety evaluation tool code",
    ),

    # 458: agentic_patterns rules fire on standard agent frameworks
    FPPattern(
        name="agentic_standard_framework",
        scanner="multiagentscanner",
        pattern=r'(?:agent.*pattern|agentic.*pattern)',
        context_pattern=r'(?:from\s+(?:langchain|crewai|autogen)|class\s+Agent|BaseAgent)',
        reason=FPReason.ML_COMMON,
        confidence=0.82,
        description="Agentic pattern rules fire on standard agent framework usage",
    ),

    # 459: agent_identity_impersonation rules fire on agent identity management
    FPPattern(
        name="agent_identity_management_code",
        scanner="multiagentscanner",
        pattern=r'(?:agent.*identity|identity.*agent).*(?:impersonat|spoof)',
        context_pattern=r'(?:class\s+AgentIdentity|agent_id|verify_identity|authenticate_agent)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.88,
        description="Agent identity impersonation rules fire on identity management/verification code",
    ),

    # 460: sandbox_execution_boundaries rules fire on sandbox implementation
    FPPattern(
        name="sandbox_implementation_code",
        scanner="multiagentscanner",
        pattern=r'(?:sandbox.*escape|escape.*sandbox|boundary.*violation)',
        context_pattern=r'(?:class\s+Sandbox|def\s+(?:create|setup)_sandbox|RestrictedPython|jail|chroot)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Sandbox escape rules fire on sandbox implementation/setup code",
    ),

    # 461: agentic_exploitation rules fire on agent security testing
    FPPattern(
        name="agentic_exploitation_test_code",
        scanner="multiagentscanner",
        pattern=r'(?:agentic.*exploit|agent.*vulnerability)',
        file_pattern=r'(?:test|spec|benchmark|eval)',
        reason=FPReason.TEST_FILE,
        confidence=0.88,
        description="Agentic exploitation rules fire on agent security test/benchmark code",
    ),

    # 462: acp_vulnerabilities rules fire on ACP protocol implementations
    FPPattern(
        name="acp_protocol_implementation",
        scanner="multiagentscanner",
        pattern=r'(?:acp|agent.communication.protocol).*(?:vulnerab|attack)',
        context_pattern=r'(?:class\s+ACP|protocol_version|agent_capability|AgentCard)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="ACP vulnerability rules fire on protocol implementation code",
    ),

    # 463: inference_infrastructure rules fire on model serving code
    FPPattern(
        name="inference_infra_serving_code",
        scanner="llmopsscanner",
        pattern=r'(?:inference.*infrastructure|serving.*vulnerability)',
        context_pattern=r'(?:FastAPI|uvicorn|gunicorn|triton|TensorRT|vLLM|text_generation)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.85,
        description="Inference infrastructure rules fire on standard model serving frameworks",
    ),

    # 464: vector_db_attacks rules fire on vector DB client code
    FPPattern(
        name="vector_db_client_code",
        scanner="ragsecurityscanner",
        pattern=r'(?:vector.*db|vectordb).*(?:attack|poison|inject)',
        context_pattern=r'(?:chromadb|pinecone|weaviate|qdrant|milvus|faiss)\.(?:Client|connect|insert|add)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="Vector DB attack rules fire on standard vector database client usage",
    ),

    # 465: web_security rules fire on security middleware
    FPPattern(
        name="web_security_middleware",
        scanner="websecurityscanner",
        pattern=r'(?:web.*security|security.*header|csrf)',
        context_pattern=r'(?:SecurityMiddleware|CSRFMiddleware|helmet|cors|@require_csrf)',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.90,
        description="Web security rules fire on security middleware that implements the defense",
    ),

    # 466: compliance rules fire on compliance implementation code
    FPPattern(
        name="compliance_implementation_code",
        scanner="owaspllmscanner",
        pattern=r'(?:compliance|gdpr|hipaa|sox|pci).*(?:violation|missing|absent)',
        context_pattern=r'(?:class\s+Compliance|def\s+check_compliance|audit_log|data_retention)',
        reason=FPReason.COMPLIANCE_CODE,
        confidence=0.88,
        description="Compliance rules fire on compliance implementation/enforcement code",
    ),

    # 467: ai_security rules fire on security research papers/docs
    FPPattern(
        name="ai_security_research_docs",
        scanner="owaspllmscanner",
        pattern=r'(?:ai.*security|ml.*vulnerability)',
        file_pattern=r'(?:README|SECURITY|docs/|paper|research)\.(?:md|rst|txt)$',
        reason=FPReason.DOCSTRING,
        confidence=0.92,
        description="AI security rules fire on documentation/research files discussing security",
    ),

    # 468-502: Generic FP patterns for newly active scanners

    # 468: Test files should not trigger security rules from new scanners
    FPPattern(
        name="new_scanner_test_file_py",
        scanner="modelattackscanner",
        pattern=r'(?:attack|exploit|vulnerability|poison|injection)',
        file_pattern=r'(?:test_|_test\.py$|tests/|spec/)',
        context_pattern=r'(?:def\s+test_|class\s+Test|@pytest|unittest|assert)',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="Model attack scanner rules fire on security test files",
    ),
    FPPattern(
        name="new_scanner_test_file_js",
        scanner="aicontextscanner",
        pattern=r'(?:attack|exploit|injection|bypass)',
        file_pattern=r'(?:\.test\.|\.spec\.|__tests__|tests/)',
        context_pattern=r'(?:describe\s*\(|it\s*\(|expect\s*\(|jest|mocha)',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="AI context scanner rules fire on JavaScript test files",
    ),

    # 470: Docstrings mentioning attacks
    FPPattern(
        name="docstring_attack_mention_py",
        scanner="modelattackscanner",
        pattern=r'(?:attack|exploit|vulnerability|adversarial)',
        context_pattern=r'(?:"""|\'\'\')\s*.*(?:attack|exploit|vulnerability)',
        reason=FPReason.DOCSTRING,
        confidence=0.88,
        description="Attack keywords in Python docstrings are not actual vulnerabilities",
    ),
    FPPattern(
        name="docstring_attack_mention_multi",
        scanner="multiagentscanner",
        pattern=r'(?:attack|exploit|vulnerability|hijack)',
        context_pattern=r'(?:"""|\'\'\'|/\*\*)\s*.*(?:attack|exploit|vulnerability)',
        reason=FPReason.DOCSTRING,
        confidence=0.88,
        description="Attack keywords in docstrings/comments are not actual vulnerabilities",
    ),

    # 472: YAML/JSON rule definition files
    FPPattern(
        name="yaml_rule_definition_file",
        scanner="aicontextscanner",
        pattern=r'(?:injection|attack|exploit|malicious)',
        file_pattern=r'(?:rules/|scanners/|patterns/).*\.yaml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Security scanner rule definition files contain attack patterns by design",
    ),
    FPPattern(
        name="yaml_rule_definition_file_model",
        scanner="modelattackscanner",
        pattern=r'(?:poison|backdoor|attack|adversarial)',
        file_pattern=r'(?:rules/|scanners/|patterns/).*\.yaml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Security scanner rule definition files contain attack patterns by design",
    ),
    FPPattern(
        name="yaml_rule_definition_file_owasp",
        scanner="owaspllmscanner",
        pattern=r'(?:injection|jailbreak|bypass|exfiltration)',
        file_pattern=r'(?:rules/|scanners/|patterns/).*\.yaml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Security scanner rule definition files contain attack patterns by design",
    ),
    FPPattern(
        name="yaml_rule_definition_file_rag",
        scanner="ragsecurityscanner",
        pattern=r'(?:poison|attack|injection|manipulation)',
        file_pattern=r'(?:rules/|scanners/|patterns/).*\.yaml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Security scanner rule definition files contain attack patterns by design",
    ),
    FPPattern(
        name="yaml_rule_definition_file_multi",
        scanner="multiagentscanner",
        pattern=r'(?:hijack|exploit|malicious|worm)',
        file_pattern=r'(?:rules/|scanners/|patterns/).*\.yaml$',
        reason=FPReason.KNOWN_PATTERN,
        confidence=0.95,
        description="Security scanner rule definition files contain attack patterns by design",
    ),

    # 477: Example/demo code
    FPPattern(
        name="example_demo_code_model",
        scanner="modelattackscanner",
        pattern=r'(?:attack|exploit|adversarial|poison)',
        file_pattern=r'(?:example|demo|tutorial|notebook|quickstart)',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.82,
        description="Model attack rules fire on example/demo code",
    ),
    FPPattern(
        name="example_demo_code_owasp",
        scanner="owaspllmscanner",
        pattern=r'(?:injection|jailbreak|exfiltration)',
        file_pattern=r'(?:example|demo|tutorial|notebook|quickstart)',
        reason=FPReason.EXAMPLE_FILE,
        confidence=0.82,
        description="OWASP LLM rules fire on example/demo code",
    ),

    # 479: Build/CI output
    FPPattern(
        name="build_output_model",
        scanner="modelattackscanner",
        pattern=r'(?:attack|vulnerability|exploit)',
        file_pattern=r'(?:dist/|build/|\.next/|__pycache__|node_modules/)',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.92,
        description="Model attack rules fire on build output directories",
    ),

    # 480: Generated code
    FPPattern(
        name="generated_code_attack_patterns",
        scanner="modelattackscanner",
        pattern=r'(?:attack|vulnerability|exploit)',
        context_pattern=r'(?:Generated|Auto-generated|DO NOT EDIT|@generated)',
        reason=FPReason.GENERATED_CODE,
        confidence=0.90,
        description="Attack rules fire on auto-generated code files",
    ),

    # 481: Markdown/documentation files
    FPPattern(
        name="markdown_security_docs_model",
        scanner="modelattackscanner",
        pattern=r'(?:attack|vulnerability|adversarial|backdoor|poison)',
        file_pattern=r'\.md$',
        reason=FPReason.DOCSTRING,
        confidence=0.85,
        description="Model attack rules fire on Markdown documentation files",
    ),
    FPPattern(
        name="markdown_security_docs_owasp",
        scanner="owaspllmscanner",
        pattern=r'(?:injection|jailbreak|exfiltration|bypass)',
        file_pattern=r'\.md$',
        reason=FPReason.DOCSTRING,
        confidence=0.85,
        description="OWASP LLM rules fire on Markdown documentation files",
    ),
    FPPattern(
        name="markdown_security_docs_multi",
        scanner="multiagentscanner",
        pattern=r'(?:hijack|exploit|worm|impersonation)',
        file_pattern=r'\.md$',
        reason=FPReason.DOCSTRING,
        confidence=0.85,
        description="Multi-agent rules fire on Markdown documentation files",
    ),

    # 484: Standard package version strings (DIV-001/DIV-002 FPs)
    FPPattern(
        name="div_package_version_pypi",
        scanner="owaspllmscanner",
        pattern=r'(?:dependency|package|version).*(?:intent|validation)',
        context_pattern=r'(?:\d+\.\d+\.\d+|>=|<=|~=|==)',
        file_pattern=r'(?:requirements|setup\.py|pyproject|Pipfile|poetry)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Dependency intent validation fires on standard version specifiers",
    ),
    FPPattern(
        name="div_package_version_npm",
        scanner="owaspllmscanner",
        pattern=r'(?:dependency|package|version).*(?:intent|validation)',
        context_pattern=r'(?:\^|\~)\d+\.\d+',
        file_pattern=r'(?:package\.json|package-lock)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Dependency intent validation fires on npm semver ranges",
    ),

    # 486: moe_vulnerabilities rules fire on MoE architecture code
    FPPattern(
        name="moe_standard_architecture",
        scanner="modelattackscanner",
        pattern=r'(?:mixture.of.experts|moe).*(?:vulnerab|attack)',
        context_pattern=r'(?:class\s+MoE|SwitchTransformer|MixtralForCausalLM|expert_capacity)',
        reason=FPReason.ML_COMMON,
        confidence=0.85,
        description="MoE vulnerability rules fire on standard MoE architecture implementations",
    ),

    # 487: code_gen_security rules fire on code generation tools
    FPPattern(
        name="code_gen_standard_tools",
        scanner="aicontextscanner",
        pattern=r'(?:code.*gen|codegen).*(?:security|vulnerability)',
        context_pattern=r'(?:copilot|cursor|codewhisperer|codex|starcoder)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Code gen security rules fire on standard code generation tool references",
    ),

    # 488: supply_chain rules fire on security scanning CI steps
    FPPattern(
        name="supply_chain_ci_security_scan",
        scanner="owaspllmscanner",
        pattern=r'(?:supply.chain|dependency).*(?:attack|compromise)',
        file_pattern=r'(?:\.github/workflows|\.gitlab-ci|Jenkinsfile|\.circleci)',
        context_pattern=r'(?:security|scan|audit|check|snyk|dependabot)',
        reason=FPReason.INFRASTRUCTURE_CODE,
        confidence=0.88,
        description="Supply chain rules fire on CI security scanning configurations",
    ),

    # 489: GenAI security rules fire on defense implementations
    FPPattern(
        name="genai_security_defense_code",
        scanner="owaspllmscanner",
        pattern=r'(?:genai|generative.ai).*(?:security|vulnerability)',
        context_pattern=r'(?:class\s+(?:Safety|Security|Guard)|def\s+(?:validate|protect|defend))',
        reason=FPReason.DEFENSIVE_SECURITY,
        confidence=0.88,
        description="GenAI security rules fire on safety/defense implementation code",
    ),

    # 490: UCP security rules fire on payment processing code
    FPPattern(
        name="ucp_payment_processing",
        scanner="owaspllmscanner",
        pattern=r'(?:ucp|universal.checkout|payment).*(?:security|vulnerability)',
        context_pattern=r'(?:stripe|paypal|adyen|payment_intent|checkout_session)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.85,
        description="UCP security rules fire on standard payment processing integrations",
    ),

    # 491-502: Additional scanner-specific test/doc FP patterns

    FPPattern(
        name="llmops_test_file",
        scanner="llmopsscanner",
        pattern=r'(?:infrastructure|deployment|serving).*(?:attack|vulnerability)',
        file_pattern=r'(?:test_|_test\.py$|tests/)',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="LLMOps scanner rules fire on test files",
    ),
    FPPattern(
        name="rag_security_test_file",
        scanner="ragsecurityscanner",
        pattern=r'(?:vector|embedding|retrieval|rag).*(?:attack|poison)',
        file_pattern=r'(?:test_|_test\.py$|tests/)',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="RAG security scanner rules fire on test files",
    ),
    FPPattern(
        name="web_security_test_file",
        scanner="websecurityscanner",
        pattern=r'(?:csrf|xss|injection|ssrf)',
        file_pattern=r'(?:test_|_test\.py$|tests/)',
        context_pattern=r'(?:def\s+test_|class\s+Test|@pytest|assert)',
        reason=FPReason.TEST_FILE,
        confidence=0.85,
        description="Web security scanner rules fire on test files",
    ),

    # 494: Vendor/third-party code
    FPPattern(
        name="vendor_code_model",
        scanner="modelattackscanner",
        pattern=r'(?:attack|vulnerability|exploit)',
        file_pattern=r'(?:vendor/|third.party/|external/|lib/)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="Attack rules fire on vendor/third-party code directories",
    ),
    FPPattern(
        name="vendor_code_owasp",
        scanner="owaspllmscanner",
        pattern=r'(?:injection|jailbreak|bypass)',
        file_pattern=r'(?:vendor/|third.party/|external/|lib/)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.82,
        description="OWASP LLM rules fire on vendor/third-party code directories",
    ),

    # 496: Config file category rules (minified JS, lock files, etc.)
    FPPattern(
        name="minified_js_security_rules",
        scanner="owaspllmscanner",
        pattern=r'(?:injection|bypass|exfiltration)',
        file_pattern=r'\.min\.js$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="OWASP LLM rules fire on minified JavaScript files",
    ),
    FPPattern(
        name="minified_js_model_rules",
        scanner="modelattackscanner",
        pattern=r'(?:attack|exploit)',
        file_pattern=r'\.min\.js$',
        reason=FPReason.BUILD_OUTPUT,
        confidence=0.95,
        description="Model attack rules fire on minified JavaScript files",
    ),

    # =========================================================================
    # 499-510: FP patterns from canopy security scan handover (v2026.5.0)
    # Source: /home/ross/Documents/projects/canopy/docs/security-scan-handover.md
    # Added: 2026-03-18
    # =========================================================================

    # 499: "Tool definitions included in response" fires on Vue/React UI navigation arrays
    FPPattern(
        name="tool_definitions_vue_navigation",
        scanner="promptleakagescanner",
        pattern=r'Tool definitions included in response',
        file_pattern=r'(?:constants|getters|store|router|navigation|menu)\.(js|ts)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Tool definition leak rule fires on Vue/React UI navigation arrays that use 'tools' keyword for UI features, not LLM tool schemas",
    ),

    # 500: JS template literals (backticks) flagged as server-side template injection
    FPPattern(
        name="ssti_js_template_literal",
        scanner="owaspllmscanner",
        pattern=r'Server-side template injection via user-supplied format string',
        file_pattern=r'(?:router|routes|navigation)\.(ts|js|tsx|jsx)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="SSTI rule fires on JavaScript template literals in client-side Vue/React router files — no server-side template engine present",
    ),

    # 501: Vue Router redirect flagged as "env variable injection via AI prompt"
    FPPattern(
        name="env_injection_vue_router",
        scanner="owaspllmscanner",
        pattern=r'Environment variable injection or exfiltration via AI prompt',
        file_pattern=r'(?:router|routes)\.(ts|js|tsx|jsx)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Env injection rule fires on Vue/React router redirect paths using template literals — no AI prompt construction",
    ),

    # 502: i18n translation key lookup flagged as "adversarial suffix/token injection"
    FPPattern(
        name="adversarial_suffix_i18n",
        scanner="owaspllmscanner",
        pattern=r'Adversarial suffix, token injection, or chat template injection',
        context_pattern=r'(?:i18n|t\(|translate|intl|formatMessage|\$t\()',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.92,
        description="Adversarial suffix rule fires on i18n translation key lookups like i18n.global.t('general.user') — User: is a locale key, not a prompt prefix",
    ),

    # 503: Material Design icon names flagged as PII (e.g., 'cake' → date of birth)
    FPPattern(
        name="pii_material_icons",
        scanner="llmguardscanner",
        pattern=r'PII detected.*(?:Date of birth|birthday|personal)',
        file_pattern=r'(?:icon|material|font|glyph)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.95,
        description="PII detection fires on Material Design icon name arrays — 'cake' is an icon identifier, not a birthday/DOB field",
    ),

    # 504: "User:" pattern in object property names (not prompt prefixes)
    FPPattern(
        name="adversarial_suffix_object_key",
        scanner="owaspllmscanner",
        pattern=r'Adversarial suffix, token injection, or chat template injection',
        context_pattern=r'(?:User|Admin|System|Assistant)\s*:\s*(?:i18n|t\(|["\'])',
        file_pattern=r'\.(ts|js|tsx|jsx|vue)$',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Adversarial suffix rule fires on JS/TS object property names like {User: 'value'} — these are object keys, not prompt role prefixes",
    ),

    # 505: "Tool definitions" in Vuex/Redux store getters
    FPPattern(
        name="tool_definitions_state_management",
        scanner="promptleakagescanner",
        pattern=r'Tool definitions included in response',
        context_pattern=r'(?:getters|computed|mapGetters|useStore|createStore|Vuex|Redux)',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.90,
        description="Tool definition leak rule fires on Vuex/Redux state management code that returns UI tool/feature metadata",
    ),

    # 506: Client-side SPA code flagged with server-side rules
    FPPattern(
        name="ssti_spa_frontend",
        scanner="owaspllmscanner",
        pattern=r'Server-side template injection',
        file_pattern=r'(?:src/(?:components|views|pages|router|store|utils|hooks)/)',
        context_pattern=r'(?:import.*(?:vue|react|angular|svelte)|from\s+["\'](?:vue|react|@angular))',
        reason=FPReason.SAFE_PATTERN,
        confidence=0.88,
        description="Server-side template injection rule fires on client-side SPA framework code (Vue/React/Angular) — no server-side rendering",
    ),
]

