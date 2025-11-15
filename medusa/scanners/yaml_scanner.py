#!/usr/bin/env python3
"""
MEDUSA YAML Scanner
Scans YAML files for syntax and style issues using yamllint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class YAMLScanner(BaseScanner):
    """
    YAML linter using yamllint

    Checks for:
    - Syntax errors
    - Formatting issues
    - Indentation problems
    - Duplicate keys
    - Security-relevant misconfigurations
    """

    def get_tool_name(self) -> str:
        return "yamllint"

    def get_file_extensions(self) -> List[str]:
        return ['.yml', '.yaml']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan YAML file with yamllint

        Args:
            file_path: Path to YAML file

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
            # Run yamllint with parsable format
            cmd = [str(self.tool_path), '-f', 'parsable', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # yamllint returns exit code 1 if issues found (not an error)
            if result.returncode in (0, 1):
                # Parse yamllint output (format: file:line:col: [level] message (rule))
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue

                    try:
                        # Parse format: file:line:col: [level] message (rule)
                        parts = line.split(':', 3)
                        if len(parts) >= 4:
                            line_num = int(parts[1])
                            col_num = int(parts[2])
                            message_part = parts[3].strip()

                            # Extract level and message
                            if message_part.startswith('['):
                                level_end = message_part.index(']')
                                level = message_part[1:level_end]
                                message = message_part[level_end+1:].strip()

                                # Extract rule name if present
                                rule_id = None
                                if '(' in message and message.endswith(')'):
                                    rule_start = message.rindex('(')
                                    rule_id = message[rule_start+1:-1]
                                    message = message[:rule_start].strip()

                                severity = self._map_severity(level)

                                scanner_issue = ScannerIssue(
                                    severity=severity,
                                    message=message,
                                    line=line_num,
                                    column=col_num,
                                    rule_id=rule_id,
                                )
                                issues.append(scanner_issue)
                    except (ValueError, IndexError):
                        # Skip malformed lines
                        continue

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

    def _map_severity(self, yamllint_level: str) -> Severity:
        """
        Map yamllint severity to MEDUSA severity

        yamllint uses: error, warning
        """
        severity_map = {
            'error': Severity.MEDIUM,
            'warning': Severity.LOW,
        }
        return severity_map.get(yamllint_level.lower(), Severity.INFO)

    def get_install_instructions(self) -> str:
        return "Install yamllint: pip install yamllint"
