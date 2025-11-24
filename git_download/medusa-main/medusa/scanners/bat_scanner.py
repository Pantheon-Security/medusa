#!/usr/bin/env python3
"""
MEDUSA Windows Batch Scanner
Security and quality scanner for Windows batch files using Blinter
"""

import re
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class BatScanner(BaseScanner):
    """
    Windows batch file security scanner using Blinter

    Blinter finds:
    - Security vulnerabilities (command injection, path traversal)
    - Syntax errors and bad practices
    - Performance issues
    - Style and formatting problems
    - Windows compatibility issues
    """

    def get_tool_name(self) -> str:
        return "blinter"

    def get_file_extensions(self) -> List[str]:
        return ['.bat', '.cmd']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan batch file with Blinter

        Args:
            file_path: Path to batch file

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
                error_message=f"{self.tool_name} not installed. Install with: pip install Blinter"
            )

        try:
            # Run Blinter
            cmd = [str(self.tool_path), str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # Parse Blinter output (text-based format)
            # Format: Line <num>: <title> (<rule_id>)
            if result.stdout:
                issues = self._parse_blinter_output(result.stdout)

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

    def _parse_blinter_output(self, output: str) -> List[ScannerIssue]:
        """Parse Blinter's text output into ScannerIssues"""
        issues = []

        # Pattern to match: Line <num>: <title> (<rule_id>)
        line_pattern = re.compile(r'^Line (\d+):\s+(.+?)\s+\(([^)]+)\)$', re.MULTILINE)

        # Find all issue headers
        matches = line_pattern.finditer(output)

        for match in matches:
            line_num = int(match.group(1))
            title = match.group(2).strip()
            rule_id = match.group(3).strip()

            # Extract explanation, recommendation, and context if available
            # These appear after the line header with specific prefixes
            start_pos = match.end()

            # Find the next issue or end of output
            next_match = line_pattern.search(output, start_pos)
            end_pos = next_match.start() if next_match else len(output)

            issue_block = output[start_pos:end_pos]

            # Extract explanation (optional)
            explanation_match = re.search(r'- Explanation:\s*(.+?)(?=\n-|\n\n|$)', issue_block, re.DOTALL)
            explanation = explanation_match.group(1).strip() if explanation_match else ""

            # Build message from title and explanation
            message = title
            if explanation:
                message = f"{title}: {explanation}"

            # Determine severity from rule ID
            severity = self._map_severity(rule_id)

            issues.append(ScannerIssue(
                severity=severity,
                message=message,
                line=line_num,
                column=0,  # Blinter doesn't provide column numbers in text output
                rule_id=rule_id,
                code=None,
            ))

        return issues

    def _map_severity(self, rule_id: str) -> Severity:
        """
        Map Blinter rule ID to MEDUSA severity

        Blinter uses:
        - E001-E999: Error Level (will cause script failure)
        - W001-W999: Warning Level (bad practices)
        - S001-S999: Style Level (formatting)
        - SEC001+: Security Level (security issues)
        - P001-P999: Performance
        """
        if rule_id.startswith('E'):
            return Severity.HIGH
        elif rule_id.startswith('SEC'):
            return Severity.CRITICAL
        elif rule_id.startswith('W'):
            return Severity.MEDIUM
        elif rule_id.startswith('P'):
            return Severity.MEDIUM
        elif rule_id.startswith('S'):
            return Severity.LOW
        else:
            return Severity.INFO

    def get_install_instructions(self) -> str:
        return """Install Blinter:
  - pip: pip install Blinter
  - More info: https://github.com/tboy1337/Blinter"""
