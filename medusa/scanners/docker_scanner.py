#!/usr/bin/env python3
"""
MEDUSA Docker Scanner
Scans Dockerfiles for best practices and security issues using hadolint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class DockerScanner(BaseScanner):
    """
    Dockerfile linter using hadolint

    Checks for:
    - Security vulnerabilities
    - Best practice violations
    - Deprecated instructions
    - Optimization opportunities
    """

    def get_tool_name(self) -> str:
        return "hadolint"

    def get_file_extensions(self) -> List[str]:
        # Hadolint works with Dockerfiles (no extension typically)
        return []

    def can_scan(self, file_path: Path) -> bool:
        """Override to check if file is a Dockerfile"""
        filename = file_path.name.lower()
        return (
            filename == 'dockerfile' or
            filename.startswith('dockerfile.') or
            filename.endswith('.dockerfile')
        )

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan Dockerfile with hadolint

        Args:
            file_path: Path to Dockerfile

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
            # Run hadolint with JSON output
            cmd = [str(self.tool_path), '-f', 'json', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # hadolint returns non-zero if issues found
            if result.returncode in (0, 1):
                # hadolint outputs JSON array
                try:
                    data = json.loads(result.stdout) if result.stdout.strip() else []

                    for issue in data:
                        severity = self._map_severity(issue.get('level', 'info'))

                        scanner_issue = ScannerIssue(
                            severity=severity,
                            message=issue.get('message', 'Unknown issue'),
                            line=issue.get('line'),
                            column=issue.get('column'),
                            rule_id=issue.get('code'),
                        )
                        issues.append(scanner_issue)
                except json.JSONDecodeError:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
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

    def _map_severity(self, hadolint_level: str) -> Severity:
        """
        Map hadolint severity to MEDUSA severity

        hadolint uses: error, warning, info, style
        """
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'info': Severity.LOW,
            'style': Severity.INFO,
        }
        return severity_map.get(hadolint_level.lower(), Severity.INFO)

    def get_install_instructions(self) -> str:
        return """Install hadolint:
  - Ubuntu/Debian: wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && chmod +x /usr/local/bin/hadolint
  - macOS: brew install hadolint
  - Other: https://github.com/hadolint/hadolint#install"""
