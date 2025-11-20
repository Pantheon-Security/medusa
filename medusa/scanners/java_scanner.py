#!/usr/bin/env python3
"""
MEDUSA Java Scanner
Code quality scanner for Java files using Checkstyle
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from defusedxml import ElementTree as ET

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class JavaScanner(BaseScanner):
    """Scanner for Java files using Checkstyle"""

    def get_tool_name(self) -> str:
        return "checkstyle"

    def get_file_extensions(self) -> List[str]:
        return [".java"]

    def is_available(self) -> bool:
        """Check if Checkstyle is installed"""
        # Checkstyle can be installed as a jar or via package managers
        return shutil.which("checkstyle") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Java file with Checkstyle"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Checkstyle not installed. Install with: apt install checkstyle"
            )

        try:
            # Run Checkstyle with XML output
            result = self._run_command([
                str(self.tool_path),
                "-f", "xml",
                str(file_path)
            ], timeout=30)

            issues = []

            # Parse XML output
            try:
                # Using defusedxml if available, fallback to standard ET (parsing trusted checkstyle output)
                root = ET.fromstring(result.stdout)

                # Checkstyle XML: <checkstyle><file><error line="X" column="Y" severity="Z" message="..." source="..."/></file></checkstyle>
                for file_elem in root.findall(".//file"):
                    for error in file_elem.findall("error"):
                        line = int(error.get("line", 0))
                        column = int(error.get("column", 0))
                        severity = error.get("severity", "warning")
                        message = error.get("message", "Unknown issue")
                        source = error.get("source", "unknown")

                        # Extract rule name from source (e.g., com.puppycrawl.tools.checkstyle.checks.naming.TypeName)
                        rule_id = source.split(".")[-1] if source else "unknown"

                        issues.append(ScannerIssue(
                            line=line,
                            column=column,
                            severity=self._map_severity(severity),
                            code=rule_id,
                            message=message,
                            rule_url=f"https://checkstyle.sourceforge.io/config_{rule_id.lower()}.html"
                        ))

            except ET.ParseError as e:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"Failed to parse Checkstyle XML output: {e}"
                )

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
                scan_time=time.time() - start_time, error_message="Checkstyle timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, checkstyle_severity: str) -> Severity:
        """Map Checkstyle severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
        }
        return severity_map.get(checkstyle_severity.lower(), Severity.MEDIUM)
