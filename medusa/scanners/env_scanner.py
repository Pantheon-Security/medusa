#!/usr/bin/env python3
"""
MEDUSA Environment File Scanner
Scans .env files for hardcoded secrets and security issues
"""

import math
import re
import time
from pathlib import Path
from typing import List, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class EnvScanner(BaseScanner):
    """
    Environment file scanner for secrets detection

    Checks for:
    - Hardcoded API keys (AWS, GitHub, Stripe, OpenAI, etc.)
    - Database credentials in URLs
    - High-entropy strings (likely secrets)
    - Sensitive variable names with values
    - Debug/development flags in production
    """

    # Known secret patterns with regex and severity
    SECRET_PATTERNS = [
        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', Severity.CRITICAL),
        (r'[0-9a-zA-Z/+]{40}', 'AWS Secret Access Key (potential)', Severity.HIGH),

        # GitHub
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', Severity.CRITICAL),
        (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token', Severity.CRITICAL),
        (r'ghu_[0-9a-zA-Z]{36}', 'GitHub User Token', Severity.CRITICAL),
        (r'ghs_[0-9a-zA-Z]{36}', 'GitHub Server Token', Severity.CRITICAL),
        (r'ghr_[0-9a-zA-Z]{36}', 'GitHub Refresh Token', Severity.CRITICAL),

        # OpenAI / Anthropic
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key', Severity.CRITICAL),
        (r'sk-ant-[a-zA-Z0-9-]{80,}', 'Anthropic API Key', Severity.CRITICAL),

        # Stripe
        (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Secret Key', Severity.CRITICAL),
        (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Secret Key', Severity.HIGH),
        (r'rk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Restricted Key', Severity.CRITICAL),

        # Google
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', Severity.HIGH),

        # Slack
        (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'Slack Token', Severity.CRITICAL),

        # Twilio
        (r'SK[0-9a-fA-F]{32}', 'Twilio API Key', Severity.HIGH),

        # SendGrid
        (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'SendGrid API Key', Severity.CRITICAL),

        # Mailgun
        (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key', Severity.HIGH),

        # Private keys
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key', Severity.CRITICAL),
        (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', Severity.CRITICAL),

        # JWT
        (r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*', 'JWT Token', Severity.HIGH),

        # Database URLs with credentials
        (r'(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@', 'Database URL with credentials', Severity.CRITICAL),
    ]

    # Sensitive variable names that should be flagged if they have values
    SENSITIVE_VAR_NAMES = {
        # Critical - likely passwords/secrets
        'password': Severity.CRITICAL,
        'passwd': Severity.CRITICAL,
        'pwd': Severity.HIGH,
        'secret': Severity.CRITICAL,
        'secret_key': Severity.CRITICAL,
        'private_key': Severity.CRITICAL,
        'encryption_key': Severity.CRITICAL,
        'signing_key': Severity.CRITICAL,

        # High - API keys and tokens
        'api_key': Severity.HIGH,
        'apikey': Severity.HIGH,
        'api_secret': Severity.CRITICAL,
        'access_key': Severity.HIGH,
        'access_token': Severity.HIGH,
        'auth_token': Severity.HIGH,
        'token': Severity.MEDIUM,
        'bearer': Severity.HIGH,

        # High - Credentials
        'credential': Severity.HIGH,
        'credentials': Severity.HIGH,
        'client_secret': Severity.CRITICAL,
        'app_secret': Severity.CRITICAL,

        # Database
        'database_url': Severity.HIGH,
        'database_password': Severity.CRITICAL,
        'db_password': Severity.CRITICAL,
        'db_pass': Severity.CRITICAL,
        'redis_password': Severity.CRITICAL,
        'mongo_password': Severity.CRITICAL,
        'postgres_password': Severity.CRITICAL,
        'mysql_password': Severity.CRITICAL,
    }

    # Debug/development flags that shouldn't be in production
    DEBUG_FLAGS = {
        'debug': ['true', '1', 'yes', 'on'],
        'development': ['true', '1', 'yes', 'on'],
        'dev_mode': ['true', '1', 'yes', 'on'],
        'testing': ['true', '1', 'yes', 'on'],
        'test_mode': ['true', '1', 'yes', 'on'],
    }

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.env']

    def get_file_patterns(self) -> List[str]:
        """Match .env files and variants"""
        return [
            '.env',
            '.env.local',
            '.env.development',
            '.env.production',
            '.env.staging',
            '.env.test',
            '.env.example',  # Sometimes has real values by mistake
            '*.env',
        ]

    def can_scan(self, file_path: Path) -> bool:
        """
        Check if this scanner can handle .env files.
        Override because .env files have special naming patterns.
        """
        name = file_path.name.lower()
        # Match .env, .env.*, *.env
        return (name == '.env' or
                name.startswith('.env.') or
                name.endswith('.env'))

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan .env file for secrets and security issues"""
        start_time = time.time()
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE
                if '=' not in line:
                    continue

                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()

                # Remove quotes from value
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                # Skip empty values or common placeholders
                placeholder_patterns = [
                    '', '""', "''",
                    # Generic placeholders
                    'your-key-here', 'your_key_here', 'your-secret-here',
                    'xxx', 'XXX', 'xxxxxxxx',
                    'changeme', 'CHANGEME', 'change-me', 'change_me',
                    'replace-me', 'replace_me', 'REPLACE_ME',
                    'todo', 'TODO', 'fixme', 'FIXME',
                    'example', 'EXAMPLE', 'sample', 'SAMPLE',
                    'placeholder', 'PLACEHOLDER',
                    'your-value', 'your_value',
                    'insert-here', 'insert_here',
                    'fill-in', 'fill_in',
                    # Template syntax
                    '<your-key>', '<YOUR_KEY>', '<secret>',
                    '<password>', '<api-key>', '<token>',
                    # Common defaults
                    'password', 'secret', 'test', 'development',
                    'localhost', '127.0.0.1',
                    'none', 'None', 'NONE', 'null', 'NULL',
                    'false', 'False', 'FALSE',
                    'undefined', 'UNDEFINED',
                    # Docker/compose defaults
                    'postgres', 'mysql', 'redis', 'mongo',
                ]
                # Also skip if starts with variable reference or looks like a template
                if not value or value.lower() in [p.lower() for p in placeholder_patterns] or \
                   value.startswith('${') or value.startswith('$(') or \
                   value.startswith('%') or value.startswith('$') or \
                   (value.startswith('<') and value.endswith('>')):
                    continue

                # Check 1: Known secret patterns in value
                pattern_matched = False
                for pattern, description, severity in self.SECRET_PATTERNS:
                    if re.search(pattern, value):
                        issues.append(ScannerIssue(
                            severity=severity,
                            message=f"Hardcoded {description} detected in '{key}'",
                            line=line_num,
                            rule_id=f"env-secret-{description.lower().replace(' ', '-')}",
                        ))
                        pattern_matched = True
                        break  # Don't double-report

                # Check 2: Sensitive variable names with non-empty values
                # Skip if we already found a known pattern (avoid noise)
                key_lower = key.lower()
                if not pattern_matched:
                    for sensitive_name, severity in self.SENSITIVE_VAR_NAMES.items():
                        if sensitive_name in key_lower:
                            # Don't flag if it looks like a reference/placeholder
                            if not (value.startswith('${') or value.startswith('$(')):
                                issues.append(ScannerIssue(
                                    severity=severity,
                                    message=f"Sensitive variable '{key}' has hardcoded value",
                                    line=line_num,
                                    rule_id=f"env-sensitive-var-{sensitive_name}",
                                ))
                            break

                # Check 3: High entropy strings (likely secrets)
                if len(value) >= 16:
                    entropy = self._calculate_entropy(value)
                    if entropy > 4.5:  # High entropy threshold
                        # Check if already flagged
                        already_flagged = any(
                            issue.line == line_num for issue in issues
                        )
                        if not already_flagged:
                            issues.append(ScannerIssue(
                                severity=Severity.MEDIUM,
                                message=f"High-entropy string in '{key}' (entropy: {entropy:.2f}) - possible secret",
                                line=line_num,
                                rule_id="env-high-entropy",
                            ))

                # Check 4: Debug flags
                for debug_var, true_values in self.DEBUG_FLAGS.items():
                    if debug_var in key_lower and value.lower() in true_values:
                        issues.append(ScannerIssue(
                            severity=Severity.MEDIUM,
                            message=f"Debug/development flag '{key}' is enabled - ensure this is not production",
                            line=line_num,
                            rule_id="env-debug-enabled",
                        ))

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.
        Higher entropy = more random = more likely to be a secret.
        """
        if not string:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(string)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def get_install_instructions(self) -> str:
        return "Environment file scanning is built-in (no installation required)"
