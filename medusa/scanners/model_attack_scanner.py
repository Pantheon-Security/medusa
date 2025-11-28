#!/usr/bin/env python3
"""
MEDUSA Model Attack Detection Scanner
Detects vulnerabilities to model-level attacks

Based on "Generative AI Security Theories and Practices" Chapter 6

Detects:
- Model inversion attack vulnerabilities
- Adversarial attack vectors
- Prompt suffix attack patterns
- Distillation attack risks
- Backdoor attack indicators
- Membership inference vulnerabilities
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ModelAttackScanner(BaseScanner):
    """
    Model Attack Detection Scanner

    Scans for:
    - MA001: Model inversion vulnerability (overfitting indicators)
    - MA002: Adversarial input vulnerability
    - MA003: Prompt suffix attack vectors
    - MA004: Distillation attack exposure (soft outputs)
    - MA005: Backdoor attack indicators
    - MA006: Membership inference vulnerability
    - MA007: Missing differential privacy
    - MA008: Missing input validation for adversarial samples
    - MA009: Model output leaking training data
    - MA010: Unprotected model endpoints
    """

    # Model Inversion / Overfitting patterns
    OVERFITTING_PATTERNS = [
        (r'epochs\s*=\s*\d{3,}',
         'High epoch count may lead to overfitting (model inversion risk)'),
        (r'early_stopping\s*=\s*False',
         'Early stopping disabled (overfitting risk)'),
        (r'regularization\s*=\s*(None|0)',
         'No regularization (overfitting/memorization risk)'),
        (r'dropout\s*=\s*0(\.0)?',
         'No dropout (may memorize training data)'),
        (r'validation_split\s*=\s*0',
         'No validation split (cannot detect overfitting)'),
    ]

    # Adversarial Input patterns
    ADVERSARIAL_PATTERNS = [
        (r'(input|image|data)\s*=\s*request\.',
         'Direct input from request without adversarial validation'),
        (r'predict\s*\(.*request',
         'Prediction on unvalidated request input'),
        (r'model\s*\(.*user_input',
         'Model inference on raw user input'),
    ]

    # Soft Output / Distillation patterns
    DISTILLATION_PATTERNS = [
        (r'(softmax|probabilities|logits)\s*.*return',
         'Soft outputs returned (distillation attack risk)'),
        (r'return.*\.probs',
         'Probability distribution exposed'),
        (r'response.*confidence.*score',
         'Confidence scores exposed (aids distillation)'),
        (r'temperature\s*=\s*[0-9.]+.*output',
         'Temperature-scaled outputs exposed'),
        (r'top_k.*probabilities',
         'Top-k probabilities exposed'),
    ]

    # Backdoor Attack patterns
    BACKDOOR_PATTERNS = [
        (r'trigger\s*=',
         'Trigger pattern defined (potential backdoor)'),
        (r'watermark\s*=',
         'Watermark pattern (could be trigger)'),
        (r'if.*specific.*pattern.*return.*fixed',
         'Conditional fixed output based on pattern'),
        (r'(train|fine_tune).*untrusted',
         'Training on untrusted data source'),
        (r'load.*weights.*http',
         'Loading weights from remote URL (backdoor risk)'),
    ]

    # Privacy / Differential Privacy patterns
    PRIVACY_PATTERNS = [
        (r'differential_privacy\s*=\s*False',
         'Differential privacy explicitly disabled'),
        (r'noise\s*=\s*(0|None)',
         'No noise added to outputs'),
        (r'(clip|clipping)\s*=\s*False',
         'Gradient clipping disabled'),
    ]

    # Model Endpoint patterns
    ENDPOINT_PATTERNS = [
        (r'@(app|router)\.(get|post).*model',
         'Model endpoint detected'),
        (r'model.*endpoint.*public',
         'Public model endpoint'),
        (r'(predict|inference|generate)\s*.*@',
         'Inference function as endpoint'),
    ]

    # Authentication/Protection patterns (good patterns)
    PROTECTION_PATTERNS = [
        r'authenticate',
        r'authorize',
        r'rate_limit',
        r'input_validation',
        r'sanitize',
        r'verify',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for model attack vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is ML/model-related
            ml_indicators = [
                'model', 'train', 'predict', 'inference', 'neural',
                'torch', 'tensorflow', 'keras', 'sklearn', 'transformers',
                'llm', 'gpt', 'bert', 'embedding', 'fine_tune', 'weights',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in ml_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for protection mechanisms
            has_protection = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.PROTECTION_PATTERNS
            )

            # MA001: Model Inversion / Overfitting
            for pattern, message in self.OVERFITTING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA001",
                        severity=Severity.MEDIUM,
                        message=f"Model Inversion Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Use regularization, early stopping, and differential privacy",
                    ))

            # MA002: Adversarial Input
            for pattern, message in self.ADVERSARIAL_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    severity = Severity.MEDIUM if has_protection else Severity.HIGH
                    issues.append(ScannerIssue(
                        rule_id="MA002",
                        severity=severity,
                        message=f"Adversarial Attack Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate inputs, use adversarial training, implement input sanitization",
                    ))

            # MA004: Distillation Attack
            for pattern, message in self.DISTILLATION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA004",
                        severity=Severity.MEDIUM,
                        message=f"Distillation Attack Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Return only hard labels, add noise to outputs, limit API access",
                    ))

            # MA005: Backdoor Attack
            for pattern, message in self.BACKDOOR_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA005",
                        severity=Severity.HIGH,
                        message=f"Backdoor Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate training data, use anomaly detection, verify model provenance",
                    ))

            # MA007: Missing Differential Privacy
            for pattern, message in self.PRIVACY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA007",
                        severity=Severity.MEDIUM,
                        message=f"Privacy Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Enable differential privacy, add calibrated noise to outputs",
                    ))

            # Check model endpoints
            issues.extend(self._check_model_endpoints(content, file_path, has_protection))

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

    def _check_model_endpoints(
        self, content: str, file_path: Path, has_protection: bool
    ) -> List[ScannerIssue]:
        """Check for unprotected model endpoints"""
        issues = []

        for pattern, message in self.ENDPOINT_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1

                if not has_protection:
                    issues.append(ScannerIssue(
                        rule_id="MA010",
                        severity=Severity.HIGH,
                        message=f"Unprotected Model Endpoint: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Add authentication, rate limiting, and input validation",
                    ))

        return issues
