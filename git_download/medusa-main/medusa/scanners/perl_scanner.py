#!/usr/bin/env python3
"""
MEDUSA Perl Scanner
Code quality and security scanner for Perl using Perl::Critic
"""

import shutil, time
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PerlScanner(BaseScanner):
    """Scanner for Perl files using Perl::Critic (perlcritic)"""

    def get_tool_name(self) -> str:
        return "perlcritic"

    def get_file_extensions(self) -> List[str]:
        return [".pl", ".pm", ".t"]

    def is_available(self) -> bool:
        """Check if perlcritic is installed"""
        return shutil.which("perlcritic") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan a Perl file with perlcritic"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Perl::Critic not installed. Install with: cpan Perl::Critic"
            )

        try:
            # Run perlcritic with verbose output
            result = self._run_command([str(self.tool_path),
                    "--verbose", "%f:%l:%c:%s:%p:%m\n",
                    "--nocolor",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # perlcritic verbose format: file:line:col:severity:policy:message
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue

                try:
                    parts = line.split(":", 5)
                    if len(parts) < 6:
                        continue

                    file_part, line_num, col_num, severity, policy, message = parts

                    # Extract policy name (last part after ::)
                    policy_name = policy.split("::")[-1] if "::" in policy else policy

                    issues.append(ScannerIssue(
                        line=int(line_num),
                        column=int(col_num),
                        severity=self._map_severity(int(severity)),
                        code=policy_name,
                        message=message.strip(),
                        rule_url=f"https://metacpan.org/pod/{policy}"
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
                scan_time=time.time() - start_time, error_message="perlcritic timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, perlcritic_severity: int) -> Severity:
        """Map Perl::Critic severity (1-5) to MEDUSA severity"""
        # Perl::Critic uses 1=gentle to 5=brutal
        if perlcritic_severity >= 5:
            return Severity.CRITICAL
        elif perlcritic_severity >= 4:
            return Severity.HIGH
        elif perlcritic_severity >= 3:
            return Severity.MEDIUM
        elif perlcritic_severity >= 2:
            return Severity.LOW
        else:
            return Severity.INFO
