#!/usr/bin/env python3
"""
MEDUSA Elixir Scanner
Code quality scanner for Elixir using Credo
"""

import json, time
import shutil
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ElixirScanner(BaseScanner):
    """Scanner for Elixir files using Credo"""

    def get_tool_name(self) -> str:
        return "mix"  # Credo runs via mix

    def get_file_extensions(self) -> List[str]:
        return [".ex", ".exs"]

    def is_available(self) -> bool:
        """Check if mix (Elixir) is installed"""
        return shutil.which("mix") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan an Elixir file with Credo"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Elixir not installed. Install from: https://elixir-lang.org/install.html"
            )

        try:
            # Run credo via mix
            result = self._run_command([str(self.tool_path), "credo", str(file_path), "--format", "json"], timeout=30,
                cwd=file_path.parent
            )

            issues = []

            if result.stdout.strip():
                data = json.loads(result.stdout)
                for issue in data.get("issues", []):
                    issues.append(ScannerIssue(
                        line=issue.get("line_no", 0),
                        column=issue.get("column", 0),
                        severity=self._map_severity(issue.get("priority", 0)),
                        code=issue.get("check", "unknown"),
                        message=issue.get("message", "Unknown issue"),
                        rule_url="https://hexdocs.pm/credo/"
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

    def _map_severity(self, priority: int) -> Severity:
        """Map Credo priority to MEDUSA severity"""
        if priority >= 10:
            return Severity.CRITICAL
        elif priority >= 5:
            return Severity.HIGH
        elif priority >= 1:
            return Severity.MEDIUM
        else:
            return Severity.LOW
