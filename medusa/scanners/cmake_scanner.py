#!/usr/bin/env python3
"""
MEDUSA CMake Scanner
Linting for CMake files using cmake-lint
"""

import shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class CMakeScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "cmakelang"

    def get_file_extensions(self) -> List[str]:
        return [".cmake"]

    def is_available(self) -> bool:
        return shutil.which("cmake-lint") is not None or shutil.which("cmakelint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            from medusa.platform.installers.simple import get_install_hint
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"cmake-lint not installed. Install: {get_install_hint('cmake-lint')}")

        try:
            cmd = shutil.which("cmake-lint") or shutil.which("cmakelint") or "cmakelint"
            result = self._run_command([cmd, str(file_path)], timeout=30)
            issues = []
            for line in result.stdout.splitlines():
                if ":" in line:
                    issues.append(ScannerIssue(line=0, column=0, severity=Severity.LOW,
                        code="cmake-lint", message=line, rule_url="https://github.com/cmake-lint/cmake-lint"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
