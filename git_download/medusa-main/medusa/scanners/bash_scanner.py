#!/usr/bin/env python3
"""
MEDUSA Bash Scanner
Scans shell scripts for issues using ShellCheck
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class BashScanner(BaseScanner):
    """
    Shell script security and quality scanner using ShellCheck

    ShellCheck finds:
    - Security issues (unquoted variables, command injection)
    - Portability problems
    - Syntax errors
    - Common mistakes and anti-patterns
    """

    def get_tool_name(self) -> str:
        return "shellcheck"

    def get_file_extensions(self) -> List[str]:
        return ['.sh', '.bash', '.ksh', '.zsh']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan shell script with ShellCheck

        Args:
            file_path: Path to shell script

        Returns:
            ScannerResult with issues found
        """
        start_time = time.time()
        issues = []

        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"{self.tool_name} not installed"
            )

        try:
            # Run ShellCheck with JSON output
            cmd = [str(self.tool_path), '-f', 'json', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # ShellCheck returns exit code 1 if issues found (not an error)
            if result.returncode in (0, 1):
                data = json.loads(result.stdout)

                # Parse ShellCheck results
                for issue in data:
                    severity = self._map_severity(issue.get('level', 'info'))

                    scanner_issue = ScannerIssue(
                        severity=severity,
                        message=issue.get('message', 'Unknown issue'),
                        line=issue.get('line'),
                        column=issue.get('column'),
                        rule_id=f"SC{issue.get('code', '0000')}",
                        code=None,  # ShellCheck doesn't provide code snippet in JSON
                    )
                    issues.append(scanner_issue)

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except json.JSONDecodeError as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Failed to parse ShellCheck output: {e}"
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, shellcheck_level: str) -> Severity:
        """
        Map ShellCheck severity to MEDUSA severity

        ShellCheck uses: error, warning, info, style
        """
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
            'style': Severity.INFO,
        }
        return severity_map.get(shellcheck_level.lower(), Severity.INFO)

    def get_install_instructions(self) -> str:
        return """Install ShellCheck:
  - Ubuntu/Debian: sudo apt install shellcheck
  - macOS: brew install shellcheck
  - Other: https://github.com/koalaman/shellcheck#installing"""
