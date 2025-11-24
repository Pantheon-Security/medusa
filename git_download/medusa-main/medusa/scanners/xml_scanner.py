#!/usr/bin/env python3
"""
MEDUSA XML Scanner
Syntax validation for XML files using xmllint
"""

import shutil, time
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class XMLScanner(BaseScanner):
    """Scanner for XML files using xmllint"""

    def get_tool_name(self) -> str:
        return "xmllint"

    def get_file_extensions(self) -> List[str]:
        return [".xml", ".xsd", ".xsl", ".xslt"]

    def is_available(self) -> bool:
        """Check if xmllint is installed"""
        return shutil.which("xmllint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan an XML file with xmllint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="xmllint not installed. Install with: apt install libxml2-utils"
            )

        try:
            # Run xmllint with validation
            result = self._run_command([str(self.tool_path),
                    "--noout",  # Don't output the XML
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # xmllint outputs errors to stderr in format: file:line: error: message
            for line in result.stderr.splitlines():
                if not line.strip():
                    continue

                try:
                    # Parse: file.xml:10: parser error : expected '>'
                    parts = line.split(":", 3)
                    if len(parts) >= 3:
                        line_num = int(parts[1]) if parts[1].isdigit() else 0
                        message = parts[2] + (":" + parts[3] if len(parts) > 3 else "")

                        severity = Severity.HIGH if "error" in message.lower() else Severity.MEDIUM

                        issues.append(ScannerIssue(
                            line=line_num,
                            column=0,
                            severity=severity,
                            code="xml-parse",
                            message=message.strip(),
                            rule_url="https://www.w3.org/TR/xml/"
                        ))
                except (ValueError, IndexError):
                    continue

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
                scan_time=time.time() - start_time, error_message="xmllint timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )
