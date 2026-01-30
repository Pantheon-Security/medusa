#!/usr/bin/env python3
"""
Web Security Scanner

Detects common web application vulnerabilities in Python (Flask, Django) code:
- SSL/TLS certificate verification disabled
- Flask/Django debug mode enabled
- Open redirect vulnerabilities
- Hardcoded secrets
- SQL injection patterns
- Command injection patterns
- Insecure deserialization
- Server-Side Request Forgery (SSRF) patterns
"""

import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class WebSecurityScanner(RuleBasedScanner):
    """
    Web Security Scanner for Python web applications.

    Targets Flask and Django applications for common web vulnerabilities
    that are often missed by AI-focused scanners.
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['WEB-']

    # Categories to load from YAML
    RULE_CATEGORIES = [
        'ssl_verification', 'network_exposure', 'debug_mode',
        'secrets_exposure', 'open_redirect', 'host_header_injection',
        'csrf_protection', 'sql_injection', 'command_injection',
        'path_traversal', 'deserialization', 'ssrf'
    ]

    # Python web framework indicators
    FLASK_INDICATORS = [
        r'from\s+flask\s+import',
        r'import\s+flask',
        r'Flask\s*\(',
        r'@app\.route',
        r'Blueprint\s*\(',
    ]

    DJANGO_INDICATORS = [
        r'from\s+django',
        r'import\s+django',
        r'INSTALLED_APPS',
        r'MIDDLEWARE',
        r'urlpatterns',
    ]

    REQUESTS_INDICATORS = [
        r'import\s+requests',
        r'from\s+requests\s+import',
        r'requests\.(get|post|put|delete|patch|head|options)',
        r'httpx\.(get|post|put)',
        r'urllib\.request',
    ]

    # WEB-SSRF: Server-Side Request Forgery patterns
    SSRF_PATTERNS: List[Tuple[str, str, 'Severity']] = [
        # URL from user input without validation
        (r'(?:fetch|axios|request|urllib|requests\.get)\s*\(\s*(?:url|uri|input|param|user)',
         'SSRF risk - URL from user input without validation', Severity.HIGH),
        (r'(?:fetch|axios|request)\s*\(\s*f["\']',
         'SSRF risk - URL constructed with f-string', Severity.HIGH),
        (r'(?:fetch|axios|request)\s*\([^)]*\+',
         'SSRF risk - URL with string concatenation', Severity.HIGH),

        # Internal network access patterns
        (r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)',
         'Internal/private IP address - potential SSRF target', Severity.MEDIUM),
        (r'(?:fetch|request|urllib)\s*\([^)]*(?:metadata|169\.254\.169\.254)',
         'SSRF - cloud metadata endpoint access', Severity.CRITICAL),

        # DNS rebinding indicators
        (r'(?:dns|resolve|lookup)\s*\([^)]*(?:user|input|param)',
         'DNS lookup with user input (rebinding risk)', Severity.MEDIUM),
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        """Return the name of the tool (built-in Python scanner)"""
        return "python"

    def get_file_extensions(self) -> List[str]:
        """Return list of file extensions this scanner handles"""
        return [".py"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Return high confidence for Flask/Django/web framework files.
        This ensures WebSecurityScanner runs on web apps instead of generic Semgrep.
        """
        import re

        if file_path.suffix.lower() not in self.get_file_extensions():
            return 0

        try:
            content = file_path.read_text(errors='ignore')[:5000]  # Check first 5KB
        except IOError:
            return 0

        # Check for Flask indicators
        for pattern in self.FLASK_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                return 90  # Higher than Semgrep's 75

        # Check for Django indicators
        for pattern in self.DJANGO_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                return 90

        # Check for requests library (for SSL verification checks)
        for pattern in self.REQUESTS_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                return 85

        return 0  # Let other scanners handle non-web Python files

    def should_scan(self, file_path: Path) -> bool:
        """Check if file should be scanned (is Python)"""
        return file_path.suffix.lower() in self.get_file_extensions()

    def _check_framework_context(self, content: str) -> dict:
        """Detect which web frameworks are in use"""
        import re
        context = {
            'flask': False,
            'django': False,
            'requests': False,
        }

        for pattern in self.FLASK_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                context['flask'] = True
                break

        for pattern in self.DJANGO_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                context['django'] = True
                break

        for pattern in self.REQUESTS_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                context['requests'] = True
                break

        return context

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """
        Scan a Python file for web security issues.

        Args:
            file_path: Path to Python file
            content: Optional pre-loaded file content

        Returns:
            ScannerResult object
        """
        start_time = time.time()
        issues = []

        try:
            if content is None:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
        except IOError as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e)
            )

        # Check if this file uses web frameworks/requests
        context = self._check_framework_context(content)

        # Only scan files that have web-related code
        if any(context.values()):
            lines = content.split('\n')

            # Use YAML rules for detection
            rule_issues = self._scan_with_rules(lines, file_path)
            issues.extend(rule_issues)

            # Hardcoded SSRF pattern detection for web framework code
            if context['requests'] or context['flask'] or context['django']:
                ssrf_issues = self._scan_ssrf_patterns(content, lines)
                issues.extend(ssrf_issues)

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True
        )

    def _scan_ssrf_patterns(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for SSRF patterns in web application code."""
        import re
        issues = []
        for i, line in enumerate(lines, 1):
            for pattern, message, severity in self.SSRF_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id="WEB-SSRF",
                        severity=severity,
                        message=f"SSRF: {message}",
                        line=i,
                        column=1,
                        cwe_id=918,
                        cwe_link="https://cwe.mitre.org/data/definitions/918.html"
                    ))
                    break  # One issue per line
        return issues

    def _scan_with_rules(self, lines: List[str], file_path: Path = None) -> List[ScannerIssue]:
        """
        Scan lines using loaded YAML rules
        """
        import re
        issues = []
        seen_issues = set()  # Deduplicate

        for rule in self.rules:
            for i, line in enumerate(lines, 1):
                for pattern in rule.patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Create unique key to avoid duplicates
                            key = (rule.id, i, str(file_path))
                            if key in seen_issues:
                                continue
                            seen_issues.add(key)

                            # Map severity
                            severity_map = {
                                'CRITICAL': Severity.CRITICAL,
                                'HIGH': Severity.HIGH,
                                'MEDIUM': Severity.MEDIUM,
                                'LOW': Severity.LOW,
                                'INFO': Severity.INFO,
                            }
                            severity_str = rule.severity.value if hasattr(rule.severity, 'value') else str(rule.severity)
                            severity = severity_map.get(severity_str, Severity.MEDIUM)

                            # Extract CWE ID as integer if possible
                            cwe_id = None
                            if rule.cwe:
                                try:
                                    cwe_id = int(rule.cwe.replace('CWE-', ''))
                                except (ValueError, AttributeError):
                                    pass

                            issues.append(ScannerIssue(
                                severity=severity,
                                message=rule.message,
                                line=i,
                                code=line.strip(),
                                rule_id=rule.id,
                                cwe_id=cwe_id,
                            ))
                            break  # One match per rule per line
                    except re.error:
                        continue  # Skip invalid patterns

        return issues
