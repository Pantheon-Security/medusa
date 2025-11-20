#!/usr/bin/env python3
"""
MEDUSA Kotlin Scanner
Code quality scanner for Kotlin files using ktlint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class KotlinScanner(BaseScanner):
    """Scanner for Kotlin files using ktlint"""

    def get_tool_name(self) -> str:
        return "ktlint"

    def get_file_extensions(self) -> List[str]:
        return [".kt", ".kts"]

    def is_available(self) -> bool:
        """Check if ktlint is installed"""
        return shutil.which("ktlint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Kotlin file with ktlint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="ktlint not installed. Install with: brew install ktlint"
            )

        try:
            # Run ktlint with JSON output
            result = self._run_command([str(self.tool_path),
                    "--reporter=json",
                    str(file_path)
                ], timeout=30
            )

            # ktlint returns non-zero when issues are found
            if result.returncode not in [0, 1]:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"ktlint failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # ktlint output structure: [{"file": "...", "errors": [...]}]
            for file_data in data:
                for error in file_data.get("errors", []):
                    issues.append(ScannerIssue(
                        line=error.get("line", 0),
                        column=error.get("column", 0),
                        severity=Severity.MEDIUM,  # ktlint doesn't provide severity
                        code=error.get("rule", "unknown"),
                        message=error.get("message", "Unknown issue"),
                        rule_url="https://pinterest.github.io/ktlint/rules/standard/"
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
                scan_time=time.time() - start_time, error_message="ktlint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse ktlint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )
