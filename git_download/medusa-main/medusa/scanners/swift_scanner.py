#!/usr/bin/env python3
"""
MEDUSA Swift Scanner
Code quality scanner for Swift files using SwiftLint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SwiftScanner(BaseScanner):
    """Scanner for Swift files using SwiftLint"""

    def get_tool_name(self) -> str:
        return "swiftlint"

    def get_file_extensions(self) -> List[str]:
        return [".swift"]

    def is_available(self) -> bool:
        """Check if SwiftLint is installed"""
        return shutil.which("swiftlint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Swift file with SwiftLint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="SwiftLint not installed. Install with: brew install swiftlint"
            )

        try:
            # Run SwiftLint with JSON output
            result = self._run_command([str(self.tool_path), "lint",
                    "--reporter", "json",
                    "--path", str(file_path)
                ], timeout=30
            )

            # SwiftLint returns non-zero when issues are found
            if result.returncode not in [0, 2]:  # 0 = success, 2 = violations found
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"SwiftLint failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # SwiftLint output structure: [{"rule_id": "...", "line": ..., ...}]
            for violation in data:
                issues.append(ScannerIssue(
                    line=violation.get("line", 0),
                    column=violation.get("character", 0),
                    severity=self._map_severity(violation.get("severity", "warning")),
                    code=violation.get("rule_id", "unknown"),
                    message=violation.get("reason", "Unknown issue"),
                    rule_url=f"https://realm.github.io/SwiftLint/{violation.get('rule_id', '')}.html"
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
                scan_time=time.time() - start_time, error_message="SwiftLint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse SwiftLint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, swiftlint_severity: str) -> Severity:
        """Map SwiftLint severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
        }
        return severity_map.get(swiftlint_severity.lower(), Severity.MEDIUM)
