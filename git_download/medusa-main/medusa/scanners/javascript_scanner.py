#!/usr/bin/env python3
"""
MEDUSA JavaScript Scanner
Scans JavaScript/TypeScript files using ESLint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class JavaScriptScanner(BaseScanner):
    """
    JavaScript/TypeScript security scanner using ESLint

    Checks for:
    - Security vulnerabilities
    - Code quality issues
    - Best practices violations
    """

    def get_tool_name(self) -> str:
        return "eslint"

    def get_file_extensions(self) -> List[str]:
        return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan JavaScript/TypeScript file with ESLint"""
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
            # Run ESLint with JSON output
            cmd = [str(self.tool_path), '-f', 'json', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # ESLint returns non-zero if issues found
            if result.returncode in (0, 1) and result.stdout.strip():
                data = json.loads(result.stdout)

                # ESLint returns array of file results
                for file_result in data:
                    for message in file_result.get('messages', []):
                        severity = self._map_severity(message.get('severity', 1))

                        scanner_issue = ScannerIssue(
                            severity=severity,
                            message=message.get('message', 'Unknown issue'),
                            line=message.get('line'),
                            column=message.get('column'),
                            rule_id=message.get('ruleId'),
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
                error_message="Failed to parse ESLint output"
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

    def _map_severity(self, eslint_severity: int) -> Severity:
        """Map ESLint severity (1=warning, 2=error) to MEDUSA severity"""
        return Severity.HIGH if eslint_severity == 2 else Severity.MEDIUM

    def get_install_instructions(self) -> str:
        return "Install ESLint: npm install -g eslint"
