#!/usr/bin/env python3
"""
MEDUSA Scala Scanner
Code quality scanner for Scala using Scalastyle
"""

import shutil, time
import subprocess
from pathlib import Path
from typing import List

from defusedxml import ElementTree as ET

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ScalaScanner(BaseScanner):
    """Scanner for Scala files using Scalastyle"""

    def get_tool_name(self) -> str:
        return "scalastyle"

    def get_file_extensions(self) -> List[str]:
        return [".scala"]

    def is_available(self) -> bool:
        """Check if Scalastyle is installed"""
        return shutil.which("scalastyle") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Scala file with Scalastyle"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Scalastyle not installed. Install with: brew install scalastyle"
            )

        try:
            # Run Scalastyle with XML output
            result = self._run_command([str(self.tool_path),
                    "-q",  # Quiet mode
                    "--xmlOutput", "-",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # Parse XML output
            try:
                # Using defusedxml if available, fallback to standard ET (parsing trusted scalastyle output)
                root = ET.fromstring(result.stdout)

                # Scalastyle XML: <checkstyle><file><error line="X" column="Y" severity="Z" message="..." source="..."/></file></checkstyle>
                for file_elem in root.findall(".//file"):
                    for error in file_elem.findall("error"):
                        line = int(error.get("line", 0))
                        column = int(error.get("column", 0))
                        severity = error.get("severity", "warning")
                        message = error.get("message", "Unknown issue")
                        source = error.get("source", "unknown")

                        # Extract rule name from source
                        rule_id = source.split(".")[-1] if source else "unknown"

                        issues.append(ScannerIssue(
                            line=line,
                            column=column,
                            severity=self._map_severity(severity),
                            code=rule_id,
                            message=message,
                            rule_url=f"http://www.scalastyle.org/rules-1.0.0.html"
                        ))

            except ET.ParseError as e:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"Failed to parse Scalastyle XML: {e}"
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
                scan_time=time.time() - start_time, error_message="Scalastyle timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, scalastyle_severity: str) -> Severity:
        """Map Scalastyle severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
        }
        return severity_map.get(scalastyle_severity.lower(), Severity.MEDIUM)
