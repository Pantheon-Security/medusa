#!/usr/bin/env python3
"""
MEDUSA Vim Script Scanner
Linting for Vim script using Vint
"""

import json, shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class VimScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "vim-vint"

    def get_file_extensions(self) -> List[str]:
        return [".vim"]

    def is_available(self) -> bool:
        return shutil.which("vint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message="Vint not installed. Install with: pip install vim-vint")

        try:
            result = self._run_command([str(self.tool_path), str(file_path)], timeout=30)
            issues = []
            for line in result.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 3)
                    if len(parts) >= 3:
                        try:
                            issues.append(ScannerIssue(line=int(parts[1]), column=int(parts[2]) if parts[2].isdigit() else 0,
                                severity=Severity.MEDIUM, code="vint", message=parts[3] if len(parts) > 3 else "Issue",
                                rule_url="https://github.com/Vimjas/vint"))
                        except (ValueError, IndexError):
                            # Skip malformed vint output lines that can't be parsed
                            pass
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
