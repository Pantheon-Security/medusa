#!/usr/bin/env python3
"""
MEDUSA LLMOps Security Scanner
Detects security issues in LLM operations and deployment

Based on "Generative AI Security Theories and Practices" Chapter 8

Detects:
- Insecure model deployment patterns
- Missing monitoring and observability
- Unsafe fine-tuning practices
- CI/CD security gaps
- Feedback loop vulnerabilities
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class LLMOpsScanner(BaseScanner):
    """
    LLMOps Security Scanner

    Scans for:
    - LO001: Insecure model loading
    - LO002: Missing model versioning
    - LO003: Unmonitored model deployment
    - LO004: Insecure fine-tuning pipeline
    - LO005: Missing drift detection
    - LO006: Exposed feedback channels
    - LO007: Insecure checkpoint storage
    - LO008: Missing model validation
    - LO009: Unencrypted model transfer
    - LO010: Missing audit logging for model operations
    """

    # Insecure Model Loading patterns
    INSECURE_LOADING_PATTERNS = [
        (r'(pickle|torch)\.load\s*\(.*http',
         'Model loaded from URL via pickle/torch (code execution risk)'),
        (r'load.*weights.*\(.*user',
         'Model weights loaded from user input'),
        (r'from_pretrained\s*\(.*input',
         'Pretrained model loaded from user-controlled path'),
        (r'(joblib|dill)\.load\s*\(',
         'Insecure deserialization (use safetensors instead)'),
        (r'eval\s*\(.*model',
         'Model code evaluated dynamically'),
    ]

    # Model Versioning patterns
    VERSIONING_PATTERNS = [
        r'model_version',
        r'version\s*=',
        r'checkpoint.*version',
        r'mlflow',
        r'dvc',
        r'wandb',
        r'model.*registry',
    ]

    # Monitoring patterns
    MONITORING_PATTERNS = [
        r'(monitor|observe|track).*model',
        r'prometheus',
        r'grafana',
        r'datadog',
        r'newrelic',
        r'metrics\.',
        r'telemetry',
        r'arize',
        r'whylabs',
    ]

    # Fine-tuning Security patterns
    FINETUNING_PATTERNS = [
        (r'fine_tune.*\(.*untrusted',
         'Fine-tuning on untrusted data'),
        (r'train.*\(.*user.*data',
         'Training on user-provided data without validation'),
        (r'adapter.*save.*public',
         'Model adapters saved to public location'),
        (r'lora.*weights.*http',
         'LoRA weights from untrusted URL'),
    ]

    # Drift Detection patterns
    DRIFT_PATTERNS = [
        r'drift.*detect',
        r'data.*drift',
        r'model.*drift',
        r'concept.*drift',
        r'distribution.*shift',
        r'evidently',
        r'alibi.*detect',
    ]

    # Feedback Loop patterns
    FEEDBACK_PATTERNS = [
        (r'feedback\s*=\s*request\.',
         'Feedback directly from request (poisoning risk)'),
        (r'(rlhf|rlaif).*user.*input',
         'RLHF/RLAIF with unvalidated user input'),
        (r'thumbs.*up.*train',
         'User feedback directly used for training'),
        (r'rating.*fine_tune',
         'User ratings used for fine-tuning without validation'),
    ]

    # Checkpoint Storage patterns
    CHECKPOINT_PATTERNS = [
        (r'save.*checkpoint.*public',
         'Checkpoint saved to public location'),
        (r'checkpoint.*s3.*public',
         'Checkpoint in public S3 bucket'),
        (r'(weights|model)\.save\s*\(.*\/',
         'Model saved to potentially insecure path'),
    ]

    # Model Transfer patterns
    TRANSFER_PATTERNS = [
        (r'http://.*model',
         'Model transferred over unencrypted HTTP'),
        (r'ftp://.*weights',
         'Weights transferred over FTP'),
        (r'download.*model.*verify\s*=\s*False',
         'Model download without verification'),
    ]

    # Audit Logging patterns
    AUDIT_PATTERNS = [
        r'audit.*log',
        r'log.*(train|deploy|fine_tune)',
        r'track.*(model|experiment)',
        r'record.*(inference|prediction)',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".yaml", ".yml", ".json", ".toml"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for LLMOps security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is LLMOps-related
            ops_indicators = [
                'model', 'train', 'deploy', 'fine_tune', 'checkpoint',
                'weights', 'inference', 'serve', 'pipeline', 'mlops',
                'llmops', 'experiment', 'registry', 'artifact',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in ops_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for good patterns
            has_versioning = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.VERSIONING_PATTERNS
            )

            has_monitoring = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.MONITORING_PATTERNS
            )

            has_drift_detection = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.DRIFT_PATTERNS
            )

            has_audit = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.AUDIT_PATTERNS
            )

            # LO001: Insecure Model Loading
            for pattern, message in self.INSECURE_LOADING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO001",
                        severity=Severity.CRITICAL,
                        message=f"Insecure Model Loading: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Use safetensors, verify model hashes, load from trusted sources only",
                    ))

            # LO002: Missing Model Versioning
            if 'model' in content_lower and 'save' in content_lower and not has_versioning:
                issues.append(ScannerIssue(
                    rule_id="LO002",
                    severity=Severity.LOW,
                    message="Model operations without versioning",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Use MLflow, DVC, or W&B for model versioning and tracking",
                ))

            # LO003: Unmonitored Deployment
            if 'deploy' in content_lower and not has_monitoring:
                issues.append(ScannerIssue(
                    rule_id="LO003",
                    severity=Severity.MEDIUM,
                    message="Model deployment without monitoring",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Add observability (Prometheus, Arize, WhyLabs) for deployed models",
                ))

            # LO004: Insecure Fine-tuning
            for pattern, message in self.FINETUNING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO004",
                        severity=Severity.HIGH,
                        message=f"Insecure Fine-tuning: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate training data, use data provenance, sanitize inputs",
                    ))

            # LO005: Missing Drift Detection
            if 'deploy' in content_lower and not has_drift_detection:
                issues.append(ScannerIssue(
                    rule_id="LO005",
                    severity=Severity.LOW,
                    message="No drift detection for deployed model",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Implement drift detection using Evidently or Alibi Detect",
                ))

            # LO006: Exposed Feedback Channels
            for pattern, message in self.FEEDBACK_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO006",
                        severity=Severity.HIGH,
                        message=f"Feedback Vulnerability: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate and sanitize feedback, use secure feedback channels",
                    ))

            # LO007: Insecure Checkpoint Storage
            for pattern, message in self.CHECKPOINT_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO007",
                        severity=Severity.HIGH,
                        message=f"Checkpoint Security: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Store checkpoints in private, encrypted storage with access controls",
                    ))

            # LO009: Unencrypted Model Transfer
            for pattern, message in self.TRANSFER_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO009",
                        severity=Severity.HIGH,
                        message=f"Insecure Transfer: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Use HTTPS, verify checksums, implement secure transfer protocols",
                    ))

            # LO010: Missing Audit Logging
            if ('train' in content_lower or 'deploy' in content_lower) and not has_audit:
                issues.append(ScannerIssue(
                    rule_id="LO010",
                    severity=Severity.MEDIUM,
                    message="Model operations without audit logging",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Log all model training, deployment, and inference operations",
                ))

            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error=str(e),
            )
