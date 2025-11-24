#!/usr/bin/env python3
"""
MEDUSA Terraform Scanner
Scans Terraform files using tflint
"""

import json
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class TerraformScanner(BaseScanner):
    """
    Terraform linter using tflint

    Checks for:
    - Terraform syntax errors
    - AWS/Azure/GCP provider issues
    - Security misconfigurations
    - Best practices
    """

    def get_tool_name(self) -> str:
        return "tflint"

    def get_file_extensions(self) -> List[str]:
        return ['.tf', '.tfvars']

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan Terraform file with tflint"""
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
            # Run tflint with JSON output
            cmd = [str(self.tool_path), '--format=json', str(file_path)]
            result = self._run_command(cmd, timeout=30)

            # tflint returns non-zero if issues found
            if result.returncode in (0, 2) and result.stdout.strip():
                data = json.loads(result.stdout)

                for issue in data.get('issues', []):
                    severity = self._map_severity(issue.get('rule', {}).get('severity', 'warning'))

                    scanner_issue = ScannerIssue(
                        severity=severity,
                        message=issue.get('message', 'Unknown issue'),
                        line=issue.get('range', {}).get('start', {}).get('line'),
                        column=issue.get('range', {}).get('start', {}).get('column'),
                        rule_id=issue.get('rule', {}).get('name'),
                    )
                    issues.append(scanner_issue)

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except json.JSONDecodeError:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message="Failed to parse tflint output"
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

    def _map_severity(self, tflint_severity: str) -> Severity:
        """Map tflint severity to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'notice': Severity.LOW,
        }
        return severity_map.get(tflint_severity.lower(), Severity.LOW)

    def get_install_instructions(self) -> str:
        return """Install tflint:
  - macOS: brew install tflint
  - Linux: curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash
  - Other: https://github.com/terraform-linters/tflint#installation"""
