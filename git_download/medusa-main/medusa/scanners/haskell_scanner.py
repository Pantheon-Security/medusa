#!/usr/bin/env python3
"""
MEDUSA Haskell Scanner
Code quality scanner for Haskell using HLint
"""

import json, time
import shutil
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class HaskellScanner(BaseScanner):
    """Scanner for Haskell files using HLint"""

    def get_tool_name(self) -> str:
        return "hlint"

    def get_file_extensions(self) -> List[str]:
        return [".hs", ".lhs"]

    def is_available(self) -> bool:
        return shutil.which("hlint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="HLint not installed. Install with: cabal install hlint"
            )

        try:
            result = self._run_command([str(self.tool_path), str(file_path), "--json"], timeout=30
            )

            issues = []
            if result.stdout.strip():
                data = json.loads(result.stdout)
                for item in data:
                    issues.append(ScannerIssue(
                        line=item.get("startLine", 0),
                        column=item.get("startColumn", 0),
                        severity=self._map_severity(item.get("severity", "Warning")),
                        code=item.get("hint", "unknown"),
                        message=item.get("to", item.get("hint", "Unknown issue")),
                        rule_url="https://github.com/ndmitchell/hlint"
                    ))

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time, success=True
            )

        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, hlint_severity: str) -> Severity:
        severity_map = {
            'Error': Severity.HIGH,
            'Warning': Severity.MEDIUM,
            'Suggestion': Severity.LOW,
        }
        return severity_map.get(hlint_severity, Severity.MEDIUM)
