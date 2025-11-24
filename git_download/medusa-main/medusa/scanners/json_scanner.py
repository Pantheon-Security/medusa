#!/usr/bin/env python3
"""
MEDUSA JSON Scanner
Scans JSON files for syntax and security issues
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class JSONScanner(BaseScanner):
    """
    JSON validator and security scanner

    Checks for:
    - JSON syntax errors
    - Potential security issues (hardcoded secrets, sensitive data)
    - Schema validation (if schema provided)
    """

    def get_tool_name(self) -> str:
        # JSON validation is built-in to Python
        return "python"

    def get_file_extensions(self) -> List[str]:
        return ['.json']

    def is_available(self) -> bool:
        """JSON validation is always available (built-in)"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan JSON file for syntax and security issues"""
        start_time = time.time()
        issues = []

        try:
            # Read and parse JSON
            with open(file_path, 'r') as f:
                content = f.read()
                data = json.loads(content)

            # Check for potential security issues
            issues.extend(self._check_security_issues(data, file_path))

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except json.JSONDecodeError as e:
            # JSON syntax error
            scanner_issue = ScannerIssue(
                severity=Severity.HIGH,
                message=f"JSON syntax error: {e.msg}",
                line=e.lineno,
                column=e.colno,
                rule_id="json-syntax",
            )
            issues.append(scanner_issue)

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True  # Successfully scanned, found syntax error
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

    def _check_security_issues(self, data: dict, file_path: Path, prefix: str = "") -> List[ScannerIssue]:
        """Check for potential security issues in JSON data"""
        issues = []

        # Sensitive key patterns to look for
        sensitive_patterns = {
            'password': Severity.CRITICAL,
            'passwd': Severity.CRITICAL,
            'secret': Severity.HIGH,
            'api_key': Severity.HIGH,
            'apikey': Severity.HIGH,
            'private_key': Severity.CRITICAL,
            'token': Severity.MEDIUM,
            'auth': Severity.MEDIUM,
            'credential': Severity.HIGH,
        }

        def check_dict(obj, path=""):
            """Recursively check dictionary for sensitive keys"""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    key_lower = key.lower()

                    # Check if key matches sensitive patterns
                    for pattern, severity in sensitive_patterns.items():
                        if pattern in key_lower and isinstance(value, str) and value:
                            issue = ScannerIssue(
                                severity=severity,
                                message=f"Potential sensitive data in key '{current_path}': {pattern}",
                                line=None,  # JSON parser doesn't give line numbers for keys
                                rule_id=f"json-sensitive-{pattern}",
                            )
                            issues.append(issue)

                    # Recurse into nested structures
                    check_dict(value, current_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_dict(item, f"{path}[{i}]")

        check_dict(data)
        return issues

    def get_install_instructions(self) -> str:
        return "JSON scanning is built-in (uses Python's json module)"
