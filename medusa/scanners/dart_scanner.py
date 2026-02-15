#!/usr/bin/env python3
"""
MEDUSA Dart Scanner
Code analysis for Dart using dart analyze
"""

import subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class DartScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "dart"

    def get_file_extensions(self) -> List[str]:
        return [".dart"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            from medusa.platform.installers.simple import get_install_hint
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Dart not installed. Install: {get_install_hint('dart')}")

        try:
            result = self._run_command([str(self.tool_path), "analyze", str(file_path)], timeout=30)
            issues = []
            for line in result.stdout.splitlines():
                if "•" in line and "|" in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        message = parts[1].strip()
                        issues.append(ScannerIssue(line=0, column=0, severity=Severity.MEDIUM,
                            code="dart-analyze", message=message, rule_url="https://dart.dev/tools/linter-rules"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
