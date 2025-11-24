#!/usr/bin/env python3
"""
MEDUSA Go Scanner
Scans Go files using golangci-lint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class GoScanner(BaseScanner):
    """
    Go security and quality scanner using golangci-lint

    Checks for:
    - Security issues (gosec)
    - Code quality (go vet, staticcheck)
    - Performance issues
    - Best practices
    """

    def get_tool_name(self) -> str:
        return "golangci-lint"

    def get_file_extensions(self) -> List[str]:
        return ['.go']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan Go file with golangci-lint"""
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
            # Run golangci-lint with JSON output
            cmd = [str(self.tool_path), 'run', '--out-format=json', str(file_path)]
            result = self._run_command(cmd, timeout=60)  # Go linting can be slow

            # golangci-lint returns non-zero if issues found
            if result.returncode in (0, 1) and result.stdout.strip():
                data = json.loads(result.stdout)

                for issue in data.get('Issues', []):
                    # golangci-lint doesn't have severity levels, use linter name
                    severity = self._map_severity(issue.get('FromLinter', ''))

                    scanner_issue = ScannerIssue(
                        severity=severity,
                        message=issue.get('Text', 'Unknown issue'),
                        line=issue.get('Pos', {}).get('Line'),
                        column=issue.get('Pos', {}).get('Column'),
                        rule_id=issue.get('FromLinter'),
                    )
                    issues.append(scanner_issue)

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except json.JSONDecodeError:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message="Failed to parse golangci-lint output"
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

    def _map_severity(self, linter_name: str) -> Severity:
        """Map golangci-lint linter to severity"""
        # Security-focused linters get higher severity
        high_severity_linters = {'gosec', 'gas'}
        medium_severity_linters = {'govet', 'staticcheck', 'errcheck'}

        if linter_name.lower() in high_severity_linters:
            return Severity.HIGH
        elif linter_name.lower() in medium_severity_linters:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def get_install_instructions(self) -> str:
        return """Install golangci-lint:
  - macOS/Linux: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
  - Other: https://golangci-lint.run/usage/install/"""
