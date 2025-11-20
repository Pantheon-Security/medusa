#!/usr/bin/env python3
"""
MEDUSA TypeScript Scanner
Type-checking and linting for TypeScript using tsc compiler
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class TypeScriptScanner(BaseScanner):
    """Scanner for TypeScript files using tsc (TypeScript compiler)"""

    def get_tool_name(self) -> str:
        return "typescript"

    def get_file_extensions(self) -> List[str]:
        return [".ts", ".tsx"]

    def is_available(self) -> bool:
        """Check if TypeScript compiler is installed"""
        return shutil.which("tsc") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a TypeScript file with tsc"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, success=False, error_message="TypeScript not installed. Install with: npm install -g typescript"
            )

        try:
            # Run tsc with --noEmit (type checking only) and pretty output
            result = self._run_command([str(self.tool_path),
                    "--noEmit",
                    "--pretty", "false",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # tsc output format: file(line,col): error TS####: message
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue

                try:
                    # Parse: file.ts(10,5): error TS2304: Cannot find name 'foo'.
                    if "(" in line and "): " in line:
                        file_and_pos, rest = line.split("): ", 1)
                        pos_part = file_and_pos.split("(")[1]
                        line_num, col_num = pos_part.split(",")

                        # Parse error/warning and code
                        if ": TS" in rest:
                            severity_and_code, message = rest.split(": TS", 1)
                            code_and_message = message.split(": ", 1)
                            if len(code_and_message) == 2:
                                code, msg = code_and_message
                                code = f"TS{code}"
                            else:
                                code = "TS" + message.split(":")[0]
                                msg = message

                            issues.append(ScannerIssue(
                                line=int(line_num),
                                column=int(col_num),
                                severity=self._map_severity(severity_and_code.strip()),
                                code=code,
                                message=msg.strip(),
                                rule_url=f"https://typescript-eslint.io/rules/{code.lower()}"
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
                scan_time=time.time() - start_time, success=False, error_message="TypeScript compiler timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, success=False, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, tsc_level: str) -> Severity:
        """Map TypeScript severity to MEDUSA severity"""
        if "error" in tsc_level.lower():
            return Severity.HIGH
        elif "warning" in tsc_level.lower():
            return Severity.MEDIUM
        else:
            return Severity.LOW
