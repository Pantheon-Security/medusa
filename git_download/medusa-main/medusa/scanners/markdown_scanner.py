#!/usr/bin/env python3
"""
MEDUSA Markdown Scanner
Scans Markdown files for style and formatting issues using markdownlint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class MarkdownScanner(BaseScanner):
    """
    Markdown linter using markdownlint-cli

    Checks for:
    - Style consistency
    - Formatting issues
    - Broken links
    - Heading structure
    """

    def get_tool_name(self) -> str:
        return "markdownlint-cli"

    def get_file_extensions(self) -> List[str]:
        return ['.md', '.markdown']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan Markdown file with markdownlint

        Args:
            file_path: Path to Markdown file

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
            # Run markdownlint with JSON output
            cmd = [str(self.tool_path), '-j', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # markdownlint returns non-zero if issues found
            if result.returncode in (0, 1) and result.stdout.strip():
                try:
                    # markdownlint output: {filename: [errors]}
                    data = json.loads(result.stdout)

                    for filename, file_issues in data.items():
                        for issue in file_issues:
                            scanner_issue = ScannerIssue(
                                severity=Severity.LOW,  # markdownlint doesn't have severity levels
                                message=issue.get('ruleDescription', 'Style issue'),
                                line=issue.get('lineNumber'),
                                rule_id=issue.get('ruleNames', [''])[0] if issue.get('ruleNames') else None,
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

    def get_install_instructions(self) -> str:
        return """Install markdownlint-cli:
  - npm install -g markdownlint-cli
  - Or via system package manager"""
