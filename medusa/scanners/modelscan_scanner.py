#!/usr/bin/env python3
"""
MEDUSA ModelScan Integration Scanner
Wraps Protect AI's ModelScan for ML model security scanning

Detects malicious code in serialized ML models:
- Pickle-based code injection attacks
- Malicious PyTorch models (.pt, .pth, .bin)
- Compromised TensorFlow/Keras models (.h5, SavedModel)
- Unsafe content in Safetensors metadata

Based on: https://github.com/protectai/modelscan
"""

import json
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ModelScanScanner(BaseScanner):
    """
    ModelScan Integration Scanner

    Wraps Protect AI's ModelScan CLI to detect:
    - MS001: Malicious pickle operations
    - MS002: Unsafe PyTorch model code
    - MS003: Compromised TensorFlow/Keras models
    - MS004: Suspicious Safetensors metadata
    - MS005: Generic unsafe operators

    Requires: pip install modelscan
    """

    # Model file extensions to scan
    MODEL_EXTENSIONS = [
        ".pkl", ".pickle",           # Pickle files
        ".pt", ".pth", ".bin",       # PyTorch models
        ".h5", ".hdf5",              # Keras/TensorFlow HDF5
        ".safetensors",              # Safetensors format
        ".joblib",                   # Joblib serialized
        ".npy", ".npz",              # NumPy arrays (can contain pickled objects)
        ".ckpt",                     # Checkpoints
        ".model",                    # Generic model files
    ]

    # Severity mapping from ModelScan to MEDUSA
    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }

    def __init__(self):
        super().__init__()
        self._modelscan_available = None

    def get_tool_name(self) -> str:
        return "modelscan"

    def get_file_extensions(self) -> List[str]:
        return self.MODEL_EXTENSIONS

    def is_available(self) -> bool:
        """Check if modelscan CLI is available"""
        if self._modelscan_available is None:
            self._modelscan_available = shutil.which("modelscan") is not None
        return self._modelscan_available

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a single model file using ModelScan"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """
        Scan a model file for malicious code using ModelScan

        Args:
            file_path: Path to the model file
            content: Ignored - ModelScan needs the actual file

        Returns:
            ScannerResult with any security issues found
        """
        start_time = time.time()
        issues: List[ScannerIssue] = []

        # Check file extension
        if file_path.suffix.lower() not in self.MODEL_EXTENSIONS:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        # Check if ModelScan is available
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
                error="ModelScan not installed. Run: pip install modelscan",
            )

        try:
            # Run ModelScan CLI with JSON output
            result = subprocess.run(
                ["modelscan", "scan", "-p", str(file_path), "-r", "json"],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for large models
            )

            # Parse JSON output
            if result.stdout:
                try:
                    scan_result = json.loads(result.stdout)
                    issues.extend(self._parse_modelscan_output(scan_result, file_path))
                except json.JSONDecodeError:
                    # ModelScan may output non-JSON on errors
                    if "unsafe" in result.stdout.lower() or "malicious" in result.stdout.lower():
                        issues.append(ScannerIssue(
                            rule_id="MS001",
                            severity=Severity.CRITICAL,
                            message=f"ModelScan detected unsafe content: {result.stdout[:200]}",
                            file_path=file_path,
                            line=1,
                            column=1,
                            suggestion="Do not load this model. Inspect manually or use safetensors format.",
                        ))

            # Check stderr for warnings
            if result.stderr and "error" in result.stderr.lower():
                # Don't fail the scan, just note the error
                pass

            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error="ModelScan timed out (model file may be too large)",
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _parse_modelscan_output(self, scan_result: dict, file_path: Path) -> List[ScannerIssue]:
        """Parse ModelScan JSON output into ScannerIssues"""
        issues = []

        # ModelScan output structure
        # {
        #   "summary": {"total_issues": N, ...},
        #   "issues": [{"severity": "CRITICAL", "description": "...", ...}]
        # }

        if "issues" in scan_result:
            for issue in scan_result["issues"]:
                severity_str = issue.get("severity", "HIGH").upper()
                severity = self.SEVERITY_MAP.get(severity_str, Severity.HIGH)

                # Determine rule ID based on issue type
                rule_id = self._get_rule_id(issue)

                description = issue.get("description", "Unsafe operation detected")
                operator = issue.get("operator", "")
                module = issue.get("module", "")

                message = f"ModelScan: {description}"
                if operator:
                    message += f" (operator: {operator})"
                if module:
                    message += f" [module: {module}]"

                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion=self._get_suggestion(rule_id),
                    cwe_id=502,  # CWE-502: Deserialization of Untrusted Data
                    cwe_url="https://cwe.mitre.org/data/definitions/502.html",
                ))

        # Check for scan errors that indicate issues
        if "errors" in scan_result:
            for error in scan_result["errors"]:
                if "unsafe" in str(error).lower():
                    issues.append(ScannerIssue(
                        rule_id="MS005",
                        severity=Severity.HIGH,
                        message=f"ModelScan error indicates potential issue: {error}",
                        file_path=file_path,
                        line=1,
                        column=1,
                        suggestion="Inspect model manually before loading",
                    ))

        return issues

    def _get_rule_id(self, issue: dict) -> str:
        """Determine rule ID based on issue characteristics"""
        description = issue.get("description", "").lower()
        operator = issue.get("operator", "").lower()

        if "pickle" in description or "reduce" in operator:
            return "MS001"  # Pickle-based attack
        elif "torch" in description or "pytorch" in description:
            return "MS002"  # PyTorch model attack
        elif "keras" in description or "tensorflow" in description or "h5" in description:
            return "MS003"  # TensorFlow/Keras attack
        elif "safetensor" in description or "metadata" in description:
            return "MS004"  # Safetensors metadata issue
        else:
            return "MS005"  # Generic unsafe operator

    def _get_suggestion(self, rule_id: str) -> str:
        """Get remediation suggestion based on rule ID"""
        suggestions = {
            "MS001": "Pickle files can execute arbitrary code. Convert to safetensors format or verify model source.",
            "MS002": "PyTorch model contains unsafe operations. Use torch.load(..., weights_only=True) or convert to safetensors.",
            "MS003": "TensorFlow/Keras model may be compromised. Verify model source and consider re-training.",
            "MS004": "Safetensors metadata contains suspicious content. Inspect metadata manually.",
            "MS005": "Model contains unsafe operator. Do not load in production without verification.",
        }
        return suggestions.get(rule_id, "Verify model source and integrity before loading.")
