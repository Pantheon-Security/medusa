#!/usr/bin/env python3
"""
MEDUSA CSS Scanner
Security and style scanner for CSS files using Stylelint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class CSSScanner(BaseScanner):
    """Scanner for CSS files using Stylelint"""

    def get_tool_name(self) -> str:
        return "stylelint"

    def get_file_extensions(self) -> List[str]:
        return [".css", ".scss", ".sass", ".less"]

    def is_available(self) -> bool:
        """Check if Stylelint is installed"""
        return shutil.which("stylelint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a CSS file with Stylelint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Stylelint not installed. Install with: npm install -g stylelint"
            )

        try:
            # Run Stylelint with JSON output
            result = self._run_command([str(self.tool_path),
                    str(file_path),
                    "--formatter", "json"
                ], timeout=30
            )

            # Stylelint returns non-zero when issues are found
            if result.returncode not in [0, 2]:  # 0 = no errors, 2 = errors found
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"Stylelint failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # Stylelint output structure: [{"source": "...", "warnings": [...]}]
            for file_data in data:
                for warning in file_data.get("warnings", []):
                    issues.append(ScannerIssue(
                        line=warning.get("line", 0),
                        column=warning.get("column", 0),
                        severity=self._map_severity(warning.get("severity", "warning")),
                        code=warning.get("rule", "unknown"),
                        message=warning.get("text", "Unknown issue"),
                        rule_url=f"https://stylelint.io/user-guide/rules/{warning.get('rule', '')}"
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
                scan_time=time.time() - start_time, error_message="Stylelint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse Stylelint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, stylelint_severity: str) -> Severity:
        """Map Stylelint severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
        }
        return severity_map.get(stylelint_severity.lower(), Severity.LOW)
