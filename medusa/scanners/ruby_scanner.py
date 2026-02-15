#!/usr/bin/env python3
"""
MEDUSA Ruby Scanner
Security scanner for Ruby files using RuboCop
"""

import json, time
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class RubyScanner(BaseScanner):
    """Scanner for Ruby files using RuboCop"""

    def get_tool_name(self) -> str:
        return "rubocop"

    def get_file_extensions(self) -> List[str]:
        return [".rb", ".rake", ".gemspec"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a Ruby file with RuboCop"""
        start_time = time.time()
        if not self.is_available():
            from medusa.platform.installers.simple import get_install_hint
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"RuboCop not installed. Install: {get_install_hint('rubocop')}"
            )

        try:
            # Run RuboCop with JSON output
            result = self._run_command([str(self.tool_path), "--format", "json", str(file_path)], timeout=30
            )

            # RuboCop returns non-zero when issues are found
            if result.returncode not in [0, 1]:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"RuboCop failed: {result.stderr}"
                )

            # Parse JSON output
            data = json.loads(result.stdout)
            issues = []

            # RuboCop output structure: {"files": [{"path": "...", "offenses": [...]}]}
            for file_data in data.get("files", []):
                for offense in file_data.get("offenses", []):
                    issues.append(ScannerIssue(
                        line=offense.get("location", {}).get("line", 0),
                        column=offense.get("location", {}).get("column", 0),
                        severity=self._map_severity(offense.get("severity", "info")),
                        code=offense.get("cop_name", "unknown"),
                        message=offense.get("message", "Unknown issue"),
                        rule_url=f"https://docs.rubocop.org/rubocop/cops_{offense.get('cop_name', '').lower()}.html"
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
                scan_time=time.time() - start_time, error_message="RuboCop timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse RuboCop output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, rubocop_severity: str) -> Severity:
        """Map RuboCop severity to MEDUSA severity"""
        severity_map = {
            'fatal': Severity.CRITICAL,
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'convention': Severity.LOW,
            'refactor': Severity.INFO,
            'info': Severity.INFO,
        }
        return severity_map.get(rubocop_severity.lower(), Severity.LOW)
