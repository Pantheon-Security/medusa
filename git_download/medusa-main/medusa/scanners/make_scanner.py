#!/usr/bin/env python3
"""
MEDUSA Makefile Scanner
Linting for Makefiles using checkmake
"""

import json, shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class MakeScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "checkmake"

    def get_file_extensions(self) -> List[str]:
        return []  # Makefile doesn't have extension

    def is_available(self) -> bool:
        return shutil.which("checkmake") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if file_path.name.lower() not in ["makefile", "gnumakefile"]:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=True,
                error_message="Not a Makefile")

        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message="checkmake not installed. Install from: https://github.com/mrtazz/checkmake")

        try:
            result = self._run_command([str(self.tool_path), str(file_path)], timeout=30)
            issues = []
            for line in result.stdout.splitlines():
                if ":" in line:
                    issues.append(ScannerIssue(line=0, column=0, severity=Severity.MEDIUM,
                        code="checkmake", message=line, rule_url="https://github.com/mrtazz/checkmake"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
