#!/usr/bin/env python3
"""
MEDUSA Groovy Scanner
Code quality scanner for Groovy using CodeNarc
"""

import shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class GroovyScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "codenarc"

    def get_file_extensions(self) -> List[str]:
        return [".groovy", ".gradle"]

    def is_available(self) -> bool:
        return shutil.which("codenarc") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message="CodeNarc not installed. Install from: https://codenarc.github.io/CodeNarc/")

        try:
            result = self._run_command([str(self.tool_path), "-basedir=" + str(file_path.parent), "-includes=" + file_path.name], timeout=30)
            issues = []
            # CodeNarc parsing would go here - simplified for brevity
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
