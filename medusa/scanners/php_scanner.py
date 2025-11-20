#!/usr/bin/env python3
"""
MEDUSA PHP Scanner
Security scanner for PHP files using PHPStan
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PHPScanner(BaseScanner):
    """Scanner for PHP files using PHPStan"""

    def get_tool_name(self) -> str:
        return "phpstan"

    def get_file_extensions(self) -> List[str]:
        return [".php"]

    def is_available(self) -> bool:
        """Check if PHPStan is installed"""
        return shutil.which("phpstan") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a PHP file with PHPStan"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="PHPStan not installed. Install with: composer global require phpstan/phpstan"
            )

        try:
            # Run PHPStan with JSON output
            result = self._run_command([str(self.tool_path), "analyse",
                    "--error-format=json",
                    "--no-progress",
                    "--level=max",
                    str(file_path)
                ], timeout=30
            )

            # PHPStan returns non-zero when issues are found
            if result.returncode not in [0, 1]:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"PHPStan failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # PHPStan output structure: {"files": {"path": {"messages": [...]}}}
            files = data.get("files", {})
            for file_data in files.values():
                for message in file_data.get("messages", []):
                    issues.append(ScannerIssue(
                        line=message.get("line", 0),
                        column=0,  # PHPStan doesn't provide column info
                        severity=self._determine_severity(message.get("message", "")),
                        code="phpstan",
                        message=message.get("message", "Unknown issue"),
                        rule_url="https://phpstan.org/user-guide/rule-levels"
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
                scan_time=time.time() - start_time, error_message="PHPStan timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse PHPStan output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _determine_severity(self, message: str) -> Severity:
        """Determine severity based on message content"""
        message_lower = message.lower()

        # Security-related keywords
        if any(word in message_lower for word in ['sql injection', 'xss', 'csrf', 'security', 'unsafe']):
            return Severity.CRITICAL

        # Type safety issues
        if any(word in message_lower for word in ['undefined', 'null', 'type mismatch', 'incompatible']):
            return Severity.HIGH

        # Code quality issues
        if any(word in message_lower for word in ['unused', 'deprecated', 'unreachable']):
            return Severity.MEDIUM

        # Default
        return Severity.LOW
