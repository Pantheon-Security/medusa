#!/usr/bin/env python3
"""
MEDUSA Ansible Scanner
Best practices and security scanner for Ansible playbooks using ansible-lint
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class AnsibleScanner(BaseScanner):
    """Scanner for Ansible playbooks using ansible-lint"""

    def get_tool_name(self) -> str:
        return "ansible-lint"

    def get_file_extensions(self) -> List[str]:
        return [".yml", ".yaml"]  # Ansible playbooks

    def is_available(self) -> bool:
        """Check if ansible-lint is installed"""
        return shutil.which("ansible-lint") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan an Ansible playbook with ansible-lint"""
        # Only scan files that look like Ansible playbooks
        if not self._is_ansible_file(file_path):
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Not an Ansible playbook"
            )

        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="ansible-lint not installed. Install with: pip install ansible-lint"
            )

        try:
            # Run ansible-lint with JSON output
            result = self._run_command([str(self.tool_path),
                    "--format", "json",
                    "--nocolor",
                    str(file_path)
                ], timeout=30
            )

            issues = []

            # Parse JSON output
            if result.stdout.strip():
                data = json.loads(result.stdout)

                # ansible-lint output is an array of violations
                for item in data:
                    issues.append(ScannerIssue(
                        line=item.get("linenumber", item.get("line", 0)),
                        column=item.get("column", 0),
                        severity=self._map_severity(item.get("severity", "MEDIUM")),
                        code=item.get("rule", {}).get("id", item.get("tag", "unknown")),
                        message=item.get("message", "Unknown issue"),
                        rule_url=f"https://ansible-lint.readthedocs.io/rules/{item.get('rule', {}).get('id', '')}"
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
                scan_time=time.time() - start_time, error_message="ansible-lint timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse ansible-lint output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Analyze file content to determine confidence this is an Ansible playbook.

        Scoring:
        - hosts: +30 (strong indicator)
        - tasks: +30 (strong indicator)
        - roles: +20 (good indicator)
        - playbook in content: +10
        - "- name:" pattern: +10 (YAML list with name keys)

        Returns:
            0-100 confidence score
        """
        if not self.can_scan(file_path):
            return 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars for analysis

            score = 0

            # Strong Ansible indicators
            if 'hosts:' in content:
                score += 30
            if 'tasks:' in content:
                score += 30
            if 'roles:' in content:
                score += 20

            # Additional indicators
            if 'playbook' in content.lower():
                score += 10
            if '- name:' in content:
                score += 10

            return min(score, 100)  # Cap at 100

        except Exception:
            # If we can't read the file, return low score
            return 0

    def _is_ansible_file(self, file_path: Path) -> bool:
        """Check if file is an Ansible playbook (legacy method)"""
        return self.get_confidence_score(file_path) > 50

    def _map_severity(self, ansible_severity: str) -> Severity:
        """Map ansible-lint severity to MEDUSA severity"""
        severity_map = {
            'VERY_HIGH': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'VERY_LOW': Severity.INFO,
            'INFO': Severity.INFO,
        }
        return severity_map.get(ansible_severity.upper(), Severity.MEDIUM)
