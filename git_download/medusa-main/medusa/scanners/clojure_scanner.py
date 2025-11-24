#!/usr/bin/env python3
"""
MEDUSA Clojure Scanner
Code quality scanner for Clojure using clj-kondo
"""

import json, shutil, subprocess, time
from pathlib import Path
from typing import List
from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

class ClojureScanner(BaseScanner):
    def get_tool_name(self) -> str:
        return "clj-kondo"

    def get_file_extensions(self) -> List[str]:
        return [".clj", ".cljs", ".cljc", ".edn"]

    def is_available(self) -> bool:
        return shutil.which("clj-kondo") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        if not self.is_available():
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message="clj-kondo not installed. Install from: https://github.com/clj-kondo/clj-kondo")

        try:
            result = self._run_command([str(self.tool_path), "--lint", str(file_path), "--config", "{:output {:format :json}}"], timeout=30)
            issues = []
            if result.stdout.strip():
                data = json.loads(result.stdout)
                for finding in data.get("findings", []):
                    issues.append(ScannerIssue(line=finding.get("row", 0), column=finding.get("col", 0),
                        severity=Severity.MEDIUM, code=finding.get("type", "unknown"),
                        message=finding.get("message", "Unknown"), rule_url="https://github.com/clj-kondo/clj-kondo"))
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=issues, scan_time=time.time() - start_time, success=True)
        except Exception as e:
            return ScannerResult(file_path=file_path, scanner_name=self.name, issues=[], scan_time=time.time() - start_time, success=False,
                error_message=f"Scan failed: {e}")
