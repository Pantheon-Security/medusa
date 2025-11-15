#!/usr/bin/env python3
"""
MEDUSA Nginx Scanner
Security scanner for Nginx configs using gixy
"""

import json, shutil, subprocess
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class NginxScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "gixy"

    def get_file_extensions(self) -> List[str]:
        return [".conf"]  # Nginx config files

    def is_available(self) -> bool:
        return shutil.which("gixy") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], success=False,
                error_message="gixy not installed. Install with: pip install gixy")

        try:
            result = subprocess.run(["gixy", str(file_path)], capture_output=True, text=True, timeout=30)
            issues = []
            for line in result.stdout.splitlines():
                if "[" in line and "]" in line:
                    severity_str = line[line.find("[")+1:line.find("]")]
                    message = line[line.find("]")+1:].strip()
                    severity = Severity.HIGH if "error" in severity_str.lower() else Severity.MEDIUM
                    issues.append(ScannerIssue(line=0, column=0, severity=severity,
                        code="gixy", message=message, rule_url="https://github.com/yandex/gixy"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], success=False,
                error_message=f"Scan failed: {e}")
