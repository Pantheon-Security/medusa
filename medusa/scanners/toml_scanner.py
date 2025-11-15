#!/usr/bin/env python3
"""
MEDUSA TOML Scanner
Format and syntax scanner for TOML files using taplo
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class TOMLScanner(BaseScanner):
    """Scanner for TOML files using taplo"""

    def get_tool_name(self) -> str:
        return "taplo"

    def get_file_extensions(self) -> List[str]:
        return [".toml"]

    def is_available(self) -> bool:
        """Check if taplo is installed"""
        return shutil.which("taplo") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a TOML file with taplo"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message="taplo not installed. Install with: cargo install taplo-cli"
            )

        try:
            # Run taplo check
            result = subprocess.run(
                [
                    "taplo", "check",
                    str(file_path)
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            issues = []

            # taplo outputs errors to stderr
            for line in result.stderr.splitlines():
                if "error" in line.lower() or "warning" in line.lower():
                    # Parse error messages
                    issues.append(ScannerIssue(
                        line=0,  # taplo doesn't always provide line numbers
                        column=0,
                        severity=Severity.HIGH if "error" in line.lower() else Severity.MEDIUM,
                        code="toml-format",
                        message=line.strip(),
                        rule_url="https://taplo.tamasfe.dev/"
                    ))

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
                error_message="taplo timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message=f"Scan failed: {e}"
            )
