#!/usr/bin/env python3
"""
MEDUSA Solidity Scanner
Security and best practices scanner for Solidity smart contracts using solhint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SolidityScanner(BaseScanner):
    """Scanner for Solidity smart contracts using solhint"""

    def get_tool_name(self) -> str:
        return "solhint"

    def get_file_extensions(self) -> List[str]:
        return [".sol"]

    def is_available(self) -> bool:
        """Check if solhint is installed"""
        return shutil.which("solhint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Solidity file with solhint"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="solhint not installed. Install with: npm install -g solhint"
            )

        try:
            # Run solhint with JSON output
            result = self._run_command([str(self.tool_path),
                    "--formatter", "json",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # Parse JSON output
            if result.stdout.strip():
                data = json.loads(result.stdout)

                # solhint returns array of issues
                for item in data:
                    issues.append(ScannerIssue(
                        line=item.get("line", 0),
                        column=item.get("column", 0),
                        severity=self._map_severity(item.get("severity", 2)),
                        code=item.get("ruleId", "unknown"),
                        message=item.get("message", "Unknown issue"),
                        rule_url=f"https://github.com/protofire/solhint/blob/master/docs/rules/{item.get('ruleId', '')}.md"
                    ))

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
                scan_time=time.time() - start_time, error_message="solhint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse solhint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, solhint_severity: int) -> Severity:
        """Map solhint severity (1=warning, 2=error) to MEDUSA severity"""
        if solhint_severity >= 2:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
