#!/usr/bin/env python3
"""
MEDUSA Python Scanner
Scans Python files for security issues using Bandit
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PythonScanner(BaseScanner):
    """
    Python security scanner using Bandit

    Bandit finds common security issues in Python code:
    - SQL injection vulnerabilities
    - Hardcoded passwords
    - Use of insecure functions (eval, exec, etc.)
    - Weak cryptography
    - And much more...
    """

    def get_tool_name(self) -> str:
        return "bandit"

    def get_file_extensions(self) -> List[str]:
        return ['.py']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan Python file with Bandit

        Args:
            file_path: Path to Python file

        Returns:
            ScannerResult with security issues found
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
            # Run Bandit with JSON output
            # Look for .bandit config file in project root or parent directories
            cmd = [str(self.tool_path), '-f', 'json']

            # Check for .bandit config file
            config_file = self._find_config_file(file_path, '.bandit')
            if config_file:
                cmd.extend(['-c', str(config_file)])

            cmd.append(str(file_path))
            result = self._run_command(cmd, timeout=30)

            # Bandit returns exit code 1 if issues found (not an error)
            if result.returncode in (0, 1):
                data = json.loads(result.stdout)

                # Check if file is in a test directory (filter B101 assert issues)
                file_path_str = str(file_path).lower()
                is_test_file = any(test_dir in file_path_str for test_dir in
                                   ['tests/', 'test/', '__tests__/', 'spec/', 'testing/',
                                    'test_', '_test.py', 'tests.py', 'conftest.py'])

                # Parse Bandit results
                for issue in data.get('results', []):
                    test_id = issue.get('test_id', '')

                    # Filter out B101 (assert) in test files - assert is expected there
                    if test_id == 'B101' and is_test_file:
                        continue

                    severity = self._map_severity(issue.get('issue_severity', 'LOW'))

                    scanner_issue = ScannerIssue(
                        severity=severity,
                        message=issue.get('issue_text', 'Unknown issue'),
                        line=issue.get('line_number'),
                        code=issue.get('code', '').strip(),
                        rule_id=test_id,
                        cwe_id=issue.get('issue_cwe', {}).get('id') if isinstance(issue.get('issue_cwe'), dict) else None,
                        cwe_link=issue.get('issue_cwe', {}).get('link') if isinstance(issue.get('issue_cwe'), dict) else None,
                    )
                    issues.append(scanner_issue)

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except json.JSONDecodeError as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Failed to parse Bandit output: {e}"
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

    def _map_severity(self, bandit_severity: str) -> Severity:
        """
        Map Bandit severity to MEDUSA severity

        Bandit uses: HIGH, MEDIUM, LOW
        We map: HIGH -> CRITICAL, MEDIUM -> HIGH, LOW -> MEDIUM
        """
        severity_map = {
            'HIGH': Severity.CRITICAL,
            'MEDIUM': Severity.HIGH,
            'LOW': Severity.MEDIUM,
        }
        return severity_map.get(bandit_severity.upper(), Severity.LOW)

    def get_install_instructions(self) -> str:
        return "Install Bandit: pip install bandit"
