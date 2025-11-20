#!/usr/bin/env python3
"""
MEDUSA PowerShell Scanner
Security and best practices scanner for PowerShell using PSScriptAnalyzer
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PowerShellScanner(BaseScanner):
    """Scanner for PowerShell files using PSScriptAnalyzer"""

    def get_tool_name(self) -> str:
        return "PSScriptAnalyzer"

    def get_file_extensions(self) -> List[str]:
        return [".ps1", ".psm1", ".psd1"]

    def is_available(self) -> bool:
        """Check if PowerShell and PSScriptAnalyzer are installed"""
        # Check for pwsh (PowerShell Core) or powershell (Windows PowerShell)
        return shutil.which("pwsh") is not None or shutil.which("powershell") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a PowerShell file with PSScriptAnalyzer"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, success=False, error_message="PowerShell not installed. Install from: https://github.com/PowerShell/PowerShell"
            )

        # Use pwsh if available, otherwise powershell
        ps_cmd = "pwsh" if shutil.which("pwsh") else "powershell"

        try:
            # Run PSScriptAnalyzer via PowerShell
            ps_script = f"""
            if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {{
                throw "PSScriptAnalyzer not installed"
            }}
            Invoke-ScriptAnalyzer -Path '{file_path}' | ConvertTo-Json
            """

            result = self._run_command([ps_cmd, "-NoProfile", "-Command", ps_script], timeout=30
            )

            # Check for module not installed error
            if "PSScriptAnalyzer not installed" in result.stderr:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, success=False, error_message="PSScriptAnalyzer not installed. Install with: Install-Module -Name PSScriptAnalyzer"
                )

            if result.returncode != 0 and not result.stdout:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, success=False, error_message=f"PSScriptAnalyzer failed: {result.stderr}"
                )

            issues = []

            # Parse JSON output
            if result.stdout.strip():
                data = json.loads(result.stdout)

                # Handle single object or array
                if not isinstance(data, list):
                    data = [data] if data else []

                for item in data:
                    issues.append(ScannerIssue(
                        line=item.get("Line", 0),
                        column=item.get("Column", 0),
                        severity=self._map_severity(item.get("Severity", "Warning")),
                        code=item.get("RuleName", "unknown"),
                        message=item.get("Message", "Unknown issue"),
                        rule_url=f"https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/rules/{item.get('RuleName', '')}"
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
                scan_time=time.time() - start_time, success=False, error_message="PSScriptAnalyzer timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, success=False, error_message=f"Failed to parse PSScriptAnalyzer output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, success=False, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, ps_severity: str) -> Severity:
        """Map PSScriptAnalyzer severity to MEDUSA severity"""
        severity_map = {
            'Error': Severity.HIGH,
            'Warning': Severity.MEDIUM,
            'Information': Severity.LOW,
        }
        return severity_map.get(ps_severity, Severity.MEDIUM)
