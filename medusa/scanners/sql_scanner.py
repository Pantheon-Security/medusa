#!/usr/bin/env python3
"""
MEDUSA SQL Scanner
Security scanner for SQL files using SQLFluff
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SQLScanner(BaseScanner):
    """Scanner for SQL files using SQLFluff"""

    def get_tool_name(self) -> str:
        return "sqlfluff"

    def get_file_extensions(self) -> List[str]:
        return [".sql"]

    def is_available(self) -> bool:
        """Check if SQLFluff is installed"""
        return shutil.which("sqlfluff") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a SQL file with SQLFluff"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="SQLFluff not installed. Install with: pip install sqlfluff"
            )

        try:
            # Run SQLFluff lint with JSON output
            result = self._run_command([str(self.tool_path), "lint",
                    "--format", "json",
                    "--dialect", "ansi",  # Default to ANSI SQL
                    str(file_path)
                ], timeout=30
            )

            # SQLFluff returns non-zero when issues are found
            if result.returncode not in [0, 1]:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"SQLFluff failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # SQLFluff output structure: [{"filepath": "...", "violations": [...]}]
            for file_data in data:
                for violation in file_data.get("violations", []):
                    issues.append(ScannerIssue(
                        line=violation.get("line_no", 0),
                        column=violation.get("line_pos", 0),
                        severity=self._determine_severity(
                            violation.get("code", ""),
                            violation.get("description", "")
                        ),
                        code=violation.get("code", "unknown"),
                        message=violation.get("description", "Unknown issue"),
                        rule_url=f"https://docs.sqlfluff.com/en/stable/rules.html#{violation.get('code', '').lower()}"
                    ))

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time, success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="SQLFluff timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse SQLFluff output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _determine_severity(self, code: str, description: str) -> Severity:
        """Determine severity based on rule code and description"""
        description_lower = description.lower()

        # Security-critical issues
        if any(word in description_lower for word in [
            'sql injection', 'unsafe', 'security', 'vulnerability',
            'unquoted', 'concatenation'
        ]):
            return Severity.CRITICAL

        # Parsing and syntax errors
        if code.startswith('PRS') or code.startswith('LXR'):
            return Severity.HIGH

        # Layout and style issues
        if code.startswith('LT') or code.startswith('CP'):
            return Severity.LOW

        # Convention issues
        if code.startswith('CV'):
            return Severity.INFO

        # Aliasing issues
        if code.startswith('AL'):
            return Severity.MEDIUM

        # Reference issues
        if code.startswith('RF'):
            return Severity.MEDIUM

        # Default
        return Severity.MEDIUM
