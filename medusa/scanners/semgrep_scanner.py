#!/usr/bin/env python3
"""
MEDUSA Semgrep Scanner
Advanced SAST using Semgrep with security-focused rulesets
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SemgrepScanner(BaseScanner):
    """
    Static Application Security Testing using Semgrep

    Semgrep detects:
    - SQL injection
    - XSS vulnerabilities
    - Command injection
    - Path traversal
    - Insecure deserialization
    - SSRF vulnerabilities
    - Authentication/Authorization issues
    - Cryptographic weaknesses
    - And thousands more patterns across 30+ languages

    Uses the 'p/security-audit' ruleset by default for comprehensive coverage.

    Reference: https://semgrep.dev/
    """

    # Languages Semgrep supports well
    SUPPORTED_EXTENSIONS = [
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.cs', '.c', '.cpp', '.h', '.hpp', '.rs', '.swift', '.kt', '.scala',
        '.lua', '.bash', '.sh', '.yaml', '.yml', '.json', '.tf', '.hcl'
    ]

    def get_tool_name(self) -> str:
        return "semgrep"

    def get_file_extensions(self) -> List[str]:
        return self.SUPPORTED_EXTENSIONS

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Semgrep has comprehensive rules - use high confidence for supported files.
        """
        if file_path.suffix in self.SUPPORTED_EXTENSIONS:
            return 75  # High confidence for comprehensive SAST
        return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a single file using Semgrep with security rules

        Args:
            file_path: Path to file to scan

        Returns:
            ScannerResult with security findings
        """
        start_time = time.time()
        issues = []

        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"{self.tool_name} not installed"
            )

        try:
            # Run Semgrep with security-audit ruleset
            cmd = [
                str(self.tool_path),
                'scan',
                '--config', 'p/security-audit',  # Comprehensive security rules
                '--json',
                '--quiet',
                '--no-git-ignore',  # Scan all files
                str(file_path)
            ]

            result = self._run_command(cmd, timeout=120)

            # Parse JSON output
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    results = data.get('results', [])

                    for finding in results:
                        severity = self._map_severity(finding)

                        # Extract finding details
                        check_id = finding.get('check_id', 'unknown')
                        message = finding.get('extra', {}).get('message', 'Security issue detected')

                        # Get line info
                        start_info = finding.get('start', {})
                        line = start_info.get('line')
                        col = start_info.get('col')

                        # Get code snippet
                        code_lines = finding.get('extra', {}).get('lines', '')

                        # Extract CWE if available
                        metadata = finding.get('extra', {}).get('metadata', {})
                        cwe = metadata.get('cwe', [])
                        cwe_id = None
                        cwe_link = None
                        if cwe and isinstance(cwe, list) and len(cwe) > 0:
                            # Parse CWE from format like "CWE-89: SQL Injection"
                            cwe_str = cwe[0] if isinstance(cwe[0], str) else str(cwe[0])
                            if 'CWE-' in cwe_str:
                                try:
                                    cwe_num = cwe_str.split('CWE-')[1].split(':')[0].split(' ')[0]
                                    cwe_id = int(cwe_num)
                                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                                except (ValueError, IndexError):
                                    pass

                        scanner_issue = ScannerIssue(
                            severity=severity,
                            message=message,
                            line=line,
                            column=col,
                            code=code_lines[:200] if code_lines else None,
                            rule_id=check_id,
                            cwe_id=cwe_id,
                            cwe_link=cwe_link
                        )
                        issues.append(scanner_issue)

                except json.JSONDecodeError:
                    pass

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

    def _map_severity(self, finding: dict) -> Severity:
        """
        Map Semgrep severity to MEDUSA severity

        Semgrep uses: ERROR, WARNING, INFO
        """
        extra = finding.get('extra', {})
        semgrep_severity = extra.get('severity', 'WARNING').upper()

        # Also check metadata for OWASP/CWE info to boost severity
        metadata = extra.get('metadata', {})
        owasp = metadata.get('owasp', [])

        severity_map = {
            'ERROR': Severity.CRITICAL,
            'WARNING': Severity.HIGH,
            'INFO': Severity.MEDIUM,
        }

        base_severity = severity_map.get(semgrep_severity, Severity.MEDIUM)

        # Boost to CRITICAL if it's a top OWASP category
        critical_owasp = ['A01', 'A02', 'A03']  # Broken Access, Crypto, Injection
        if any(o.startswith(tuple(critical_owasp)) for o in owasp if isinstance(o, str)):
            if base_severity != Severity.CRITICAL:
                return Severity.CRITICAL

        return base_severity

    def get_install_instructions(self) -> str:
        return (
            "Install Semgrep:\n"
            "  pip install semgrep\n"
            "  OR brew install semgrep (macOS)\n"
            "  OR docker pull returntocorp/semgrep"
        )
