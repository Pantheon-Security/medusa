#!/usr/bin/env python3
"""
MEDUSA HTML Scanner
Security and quality scanner for HTML files using HTMLHint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class HTMLScanner(BaseScanner):
    """Scanner for HTML files using HTMLHint"""

    def get_tool_name(self) -> str:
        return "htmlhint"

    def get_file_extensions(self) -> List[str]:
        return [".html", ".htm"]

    def is_available(self) -> bool:
        """Check if HTMLHint is installed"""
        return shutil.which("htmlhint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan an HTML file with HTMLHint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="HTMLHint not installed. Install with: npm install -g htmlhint"
            )

        try:
            # Run HTMLHint with JSON output
            result = self._run_command([str(self.tool_path),
                    str(file_path),
                    "--format", "json"
                ], timeout=30
            )

            # HTMLHint returns non-zero when issues are found
            if result.returncode not in [0, 1]:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"HTMLHint failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # HTMLHint output structure: [{"file": "...", "messages": [...]}]
            for file_data in data:
                for message in file_data.get("messages", []):
                    issues.append(ScannerIssue(
                        line=message.get("line", 0),
                        column=message.get("col", 0),
                        severity=self._map_severity(message.get("type", "warning")),
                        code=message.get("rule", {}).get("id", "unknown"),
                        message=message.get("message", "Unknown issue"),
                        rule_url=f"https://htmlhint.com/docs/user-guide/rules/{message.get('rule', {}).get('id', '')}"
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
                scan_time=time.time() - start_time, error_message="HTMLHint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse HTMLHint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, htmlhint_type: str) -> Severity:
        """Map HTMLHint severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
        }
        return severity_map.get(htmlhint_type.lower(), Severity.MEDIUM)
