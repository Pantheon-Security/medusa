#!/usr/bin/env python3
"""
MEDUSA GraphQL Scanner
Schema validation and linting for GraphQL using graphql-schema-linter
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class GraphQLScanner(BaseScanner):
    """Scanner for GraphQL schema files using graphql-schema-linter"""

    def get_tool_name(self) -> str:
        return "graphql-schema-linter"

    def get_file_extensions(self) -> List[str]:
        return [".graphql", ".gql"]

    def is_available(self) -> bool:
        """Check if graphql-schema-linter is installed"""
        return shutil.which("graphql-schema-linter") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a GraphQL schema file"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="graphql-schema-linter not installed. Install with: npm install -g graphql-schema-linter"
            )

        try:
            # Run graphql-schema-linter
            result = self._run_command([str(self.tool_path),
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # Parse output format: file:line:column error message (rule-name)
            for line in result.stdout.splitlines():
                if not line.strip() or "error" not in line.lower():
                    continue

                try:
                    # Extract line/column and message
                    if ":" in line:
                        parts = line.split()
                        message = " ".join(parts[1:])

                        # Extract rule name if present
                        rule_id = "graphql-lint"
                        if "(" in message and ")" in message:
                            rule_id = message[message.rfind("(")+1:message.rfind(")")]

                        issues.append(ScannerIssue(
                            line=0,  # graphql-schema-linter doesn't always provide line numbers
                            column=0,
                            severity=Severity.MEDIUM,
                            code=rule_id,
                            message=message,
                            rule_url="https://github.com/cjoudrey/graphql-schema-linter"
                        ))
                except (ValueError, IndexError):
                    continue

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time, success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="graphql-schema-linter timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )
