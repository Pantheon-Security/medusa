#!/usr/bin/env python3
"""
MEDUSA C/C++ Scanner
Security and quality scanner for C/C++ files using cppcheck
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class CppScanner(BaseScanner):
    """Scanner for C/C++ files using cppcheck"""

    def get_tool_name(self) -> str:
        return "cppcheck"

    def get_file_extensions(self) -> List[str]:
        return [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]

    def is_available(self) -> bool:
        """Check if cppcheck is installed"""
        return shutil.which("cppcheck") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a C/C++ file with cppcheck"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message="cppcheck not installed. Install with: apt install cppcheck"
            )

        try:
            # Run cppcheck with JSON output
            result = subprocess.run(
                [
                    "cppcheck",
                    "--enable=all",
                    "--template=gcc",
                    "--quiet",
                    str(file_path)
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            issues = []

            # cppcheck outputs to stderr in gcc format: file:line:column: severity: message [id]
            for line in result.stderr.splitlines():
                if not line.strip() or "Checking" in line:
                    continue

                try:
                    # Parse gcc format
                    parts = line.split(":", 4)
                    if len(parts) < 5:
                        continue

                    file_part = parts[0]
                    line_num = int(parts[1])
                    col_num = int(parts[2]) if parts[2].isdigit() else 0
                    severity_and_msg = parts[3] + ":" + parts[4]

                    # Extract severity and message
                    if ": " in severity_and_msg:
                        severity_str, message = severity_and_msg.split(": ", 1)
                        severity_str = severity_str.strip()

                        # Extract rule ID from message
                        rule_id = "unknown"
                        if "[" in message and "]" in message:
                            rule_id = message[message.rfind("[")+1:message.rfind("]")]
                            message = message[:message.rfind("[")].strip()

                        issues.append(ScannerIssue(
                            line=line_num,
                            column=col_num,
                            severity=self._map_severity(severity_str),
                            code=rule_id,
                            message=message,
                            rule_url=f"https://cppcheck.sourceforge.io/manual.html"
                        ))

                except (ValueError, IndexError):
                    continue

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message="cppcheck timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, cppcheck_severity: str) -> Severity:
        """Map cppcheck severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.CRITICAL,
            'warning': Severity.HIGH,
            'style': Severity.MEDIUM,
            'performance': Severity.MEDIUM,
            'portability': Severity.LOW,
            'information': Severity.INFO,
        }
        return severity_map.get(cppcheck_severity.lower(), Severity.MEDIUM)
