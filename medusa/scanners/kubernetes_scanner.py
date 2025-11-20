#!/usr/bin/env python3
"""
MEDUSA Kubernetes Scanner
Security and best practices scanner for Kubernetes manifests using kube-linter
"""

import json, time
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
        start_time = time.time()
        """Scan a Kubernetes manifest with kube-linter"""
        # Only scan files that look like Kubernetes manifests
        if not self._is_k8s_file(file_path):
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="Not a Kubernetes manifest"
            )

        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="kube-linter not installed. Install from: https://github.com/stackrox/kube-linter"
            )

        try:
            # Run kube-linter with JSON output
            result = self._run_command([str(self.tool_path), "lint",
                    "--format", "json",
                    str(file_path)
                ], timeout=30
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
                scan_time=time.time() - start_time, success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="kube-linter timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse kube-linter output: {e}"
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
        Analyze file content to determine confidence this is a Kubernetes manifest.

        Scoring:
        - apiVersion: +35 (strongest K8s indicator)
        - kind: +35 (strongest K8s indicator)
        - metadata: +15 (common but not unique to K8s)
        - spec: +15 (common but not unique to K8s)
        - Requires apiVersion + kind for high confidence

        Returns:
            0-100 confidence score
        """
        if not self.can_scan(file_path):
            return 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars for analysis

            score = 0
            has_api_version = 'apiVersion:' in content
            has_kind = 'kind:' in content

            # Core Kubernetes indicators (both required for high confidence)
            if has_api_version:
                score += 35
            if has_kind:
                score += 35

            # Supporting indicators
            if 'metadata:' in content:
                score += 15
            if 'spec:' in content:
                score += 15

            # Require both apiVersion and kind for reasonable confidence
            # This prevents false positives on generic YAML
            if not (has_api_version and has_kind):
                score = min(score, 30)  # Cap at low score without both

            return min(score, 100)  # Cap at 100

        except Exception:
            # If we can't read the file, return low score
            return 0

    def _is_k8s_file(self, file_path: Path) -> bool:
        """Check if file is a Kubernetes manifest (legacy method)"""
        return self.get_confidence_score(file_path) > 50

    def _map_severity(self, k8s_level: str) -> Severity:
        """Map kube-linter severity to MEDUSA severity"""
        severity_map = {
            'Error': Severity.CRITICAL,
            'Warning': Severity.MEDIUM,
            'Info': Severity.LOW,
        }
        return severity_map.get(k8s_level, Severity.MEDIUM)
