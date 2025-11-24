#!/usr/bin/env python3
"""
MEDUSA Protobuf Scanner
Linting and style checking for Protocol Buffer files using buf
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ProtobufScanner(BaseScanner):
    """Scanner for Protocol Buffer files using buf"""

    def get_tool_name(self) -> str:
        return "buf"

    def get_file_extensions(self) -> List[str]:
        return [".proto"]

    def is_available(self) -> bool:
        """Check if buf is installed"""
        return shutil.which("buf") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a .proto file with buf"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="buf not installed. Install from: https://buf.build/docs/installation"
            )

        try:
            # Run buf lint
            result = self._run_command([str(self.tool_path), "lint",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # buf output format: file:line:column:message
            for line in result.stderr.splitlines():
                if not line.strip():
                    continue

                try:
                    # Parse: example.proto:10:5:Field name "userId" should be "user_id"
                    parts = line.split(":", 3)
                    if len(parts) >= 4:
                        line_num = int(parts[1]) if parts[1].isdigit() else 0
                        col_num = int(parts[2]) if parts[2].isdigit() else 0
                        message = parts[3].strip()

                        issues.append(ScannerIssue(
                            line=line_num,
                            column=col_num,
                            severity=Severity.MEDIUM,
                            code="buf-lint",
                            message=message,
                            rule_url="https://buf.build/docs/lint/overview"
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
                scan_time=time.time() - start_time, error_message="buf timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )
