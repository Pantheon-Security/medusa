#!/usr/bin/env python3
"""
MEDUSA Zig Scanner
Compiler-based checking for Zig using zig ast-check
"""

import shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class ZigScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "zig"

    def get_file_extensions(self) -> List[str]:
        return [".zig"]

    def is_available(self) -> bool:
        return shutil.which("zig") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message="Zig not installed. Install from: https://ziglang.org/download/")

        try:
            result = self._run_command([str(self.tool_path), "ast-check", str(file_path)], timeout=30)
            issues = []
            for line in result.stderr.splitlines():
                if "error:" in line:
                    issues.append(ScannerIssue(line=0, column=0, severity=Severity.HIGH,
                        code="zig-ast", message=line.strip(), rule_url="https://ziglang.org/documentation/"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
