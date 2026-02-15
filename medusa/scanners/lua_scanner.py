#!/usr/bin/env python3
"""
MEDUSA Lua Scanner
Code quality scanner for Lua using luacheck
"""

import time
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class LuaScanner(BaseScanner):
    """Scanner for Lua files using luacheck"""

    def get_tool_name(self) -> str:
        return "luacheck"

    def get_file_extensions(self) -> List[str]:
        return [".lua"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a Lua file with luacheck"""
        start_time = time.time()
        if not self.is_available():
            from medusa.platform.installers.simple import get_install_hint
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"luacheck not installed. Install: {get_install_hint('luacheck')}"
            )

        try:
            # Run luacheck with formatter
            result = self._run_command([str(self.tool_path),
                    "--formatter", "plain",
                    "--codes",  # Include error codes
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # luacheck output format: file:line:column: (W###) message
            for line in result.stdout.splitlines():
                if not line.strip() or "Total:" in line or "OK" in line:
                    continue

                try:
                    # Parse: example.lua:10:5: (W211) unused variable 'x'
                    parts = line.split(":", 3)
                    if len(parts) >= 4:
                        line_num = int(parts[1]) if parts[1].isdigit() else 0
                        col_num = int(parts[2]) if parts[2].isdigit() else 0
                        rest = parts[3].strip()

                        # Extract code and message
                        code = "luacheck"
                        message = rest
                        if "(" in rest and ")" in rest:
                            code = rest[rest.find("(")+1:rest.find(")")]
                            message = rest[rest.find(")")+1:].strip()

                        severity = self._map_severity(code)

                        issues.append(ScannerIssue(
                            line=line_num,
                            column=col_num,
                            severity=severity,
                            code=code,
                            message=message,
                            rule_url="https://luacheck.readthedocs.io/en/stable/warnings.html"
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
                scan_time=time.time() - start_time, error_message="luacheck timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, code: str) -> Severity:
        """Map luacheck warning code to MEDUSA severity"""
        # E### = error, W### = warning
        if code.startswith("E"):
            return Severity.HIGH
        elif code.startswith("W6") or code.startswith("W1"):
            return Severity.MEDIUM
        else:
            return Severity.LOW
