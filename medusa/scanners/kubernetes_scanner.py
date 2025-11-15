#!/usr/bin/env python3
"""
MEDUSA Kubernetes Scanner
Security and best practices scanner for Kubernetes manifests using kube-linter
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class KubernetesScanner(BaseScanner):
    """Scanner for Kubernetes manifests using kube-linter"""

    def get_tool_name(self) -> str:
        return "kube-linter"

    def get_file_extensions(self) -> List[str]:
        return [".yaml", ".yml"]  # Kubernetes manifests

    def is_available(self) -> bool:
        """Check if kube-linter is installed"""
        return shutil.which("kube-linter") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a Kubernetes manifest with kube-linter"""
        # Only scan files that look like Kubernetes manifests
        if not self._is_k8s_file(file_path):
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=True,  # Not an error, just not a K8s file
                error_message="Not a Kubernetes manifest"
            )

        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message="kube-linter not installed. Install from: https://github.com/stackrox/kube-linter"
            )

        try:
            # Run kube-linter with JSON output
            result = subprocess.run(
                [
                    "kube-linter", "lint",
                    "--format", "json",
                    str(file_path)
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            issues = []

            # Parse JSON output
            if result.stdout.strip():
                data = json.loads(result.stdout)

                # kube-linter output: {"Reports": [...]}
                for report in data.get("Reports", []):
                    diagnostic = report.get("Diagnostic", {})
                    issues.append(ScannerIssue(
                        line=diagnostic.get("Range", {}).get("Start", {}).get("Line", 0),
                        column=diagnostic.get("Range", {}).get("Start", {}).get("Column", 0),
                        severity=self._map_severity(report.get("Level", "Warning")),
                        code=report.get("Check", "unknown"),
                        message=diagnostic.get("Message", "Unknown issue"),
                        rule_url=f"https://docs.kubelinter.io/#/generated/checks?id={report.get('Check', '')}"
                    ))

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message="kube-linter timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message=f"Failed to parse kube-linter output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _is_k8s_file(self, file_path: Path) -> bool:
        """Check if file is a Kubernetes manifest"""
        try:
            with open(file_path, 'r') as f:
                content = f.read(500)  # Read first 500 chars
                # Look for Kubernetes keywords
                k8s_keywords = ['apiVersion:', 'kind:', 'metadata:', 'spec:']
                return sum(1 for keyword in k8s_keywords if keyword in content) >= 2
        except:
            return False

    def _map_severity(self, k8s_level: str) -> Severity:
        """Map kube-linter severity to MEDUSA severity"""
        severity_map = {
            'Error': Severity.CRITICAL,
            'Warning': Severity.MEDIUM,
            'Info': Severity.LOW,
        }
        return severity_map.get(k8s_level, Severity.MEDIUM)
