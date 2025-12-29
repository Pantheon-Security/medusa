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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class ModelAttackScanner(RuleBasedScanner):
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

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['MODEL-ATK-', 'MODEL-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['model_attack', 'adversarial', 'model_poisoning']

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

    # CVE-2019-20634: Model Extraction / "Proof Pudding" patterns
    # Training data exposure that enables model extraction
    MODEL_EXTRACTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Training data exposure
        (r'training_data.*(?:public|exposed|return|response)',
         'CVE-2019-20634: Training data potentially exposed', Severity.HIGH),
        (r'dataset.*(?:exposed|public|api|endpoint)',
         'CVE-2019-20634: Dataset exposed via API', Severity.HIGH),
        (r'model\.train\s*\(.*user_data',
         'CVE-2019-20634: Training on user data (extraction risk)', Severity.MEDIUM),
        # Model query logging exposure
        (r'log.*(?:query|input|prompt).*model',
         'Query logging may leak information for model extraction', Severity.MEDIUM),
        (r'(?:cache|store).*(?:query|response).*model',
         'Caching model queries (extraction via cache timing)', Severity.MEDIUM),
        # Direct model access
        (r'model\.(?:weights|parameters|state_dict).*return',
         'Model weights/parameters returned directly', Severity.CRITICAL),
        (r'(?:export|save).*model.*(?:public|shared)',
         'Model exported to public location', Severity.HIGH),
        # Membership inference enablers
        (r'(?:loss|confidence|perplexity).*return.*(?:api|response)',
         'Loss/confidence returned (membership inference risk)', Severity.MEDIUM),
        (r'training.*sample.*(?:id|index).*(?:return|expose)',
         'Training sample identifiers exposed', Severity.HIGH),
    ]

    # CVE-2023-4969: GPU Memory Leakage (LeftOvers) patterns
    GPU_MEMORY_LEAKAGE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'del\s+model(?!\s*[\r\n]*.*(?:gc\.collect|empty_cache))',
         'CVE-2023-4969: Model deleted without GPU memory clear', Severity.MEDIUM),
        (r'\.to\s*\(\s*["\']cuda["\'].*(?:del|None)',
         'GPU tensor not properly cleared after use', Severity.LOW),
        (r'cuda.*(?:tensor|model).*(?!.*empty_cache)',
         'CUDA operations without explicit memory management', Severity.LOW),
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
                # Still scan with YAML rules even if no ML indicators
                lines = content.split('\n')
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=yaml_issues,
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
                        message=f"Model Inversion Risk: {message} - use regularization, differential privacy",
                        line=line,
                        column=1,
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
                        message=f"Adversarial Attack Risk: {message} - validate inputs, use adversarial training",
                        line=line,
                        column=1,
                    ))

            # MA004: Distillation Attack
            for pattern, message in self.DISTILLATION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA004",
                        severity=Severity.MEDIUM,
                        message=f"Distillation Attack Risk: {message} - return hard labels only, add noise",
                        line=line,
                        column=1,
                    ))

            # MA005: Backdoor Attack
            for pattern, message in self.BACKDOOR_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA005",
                        severity=Severity.HIGH,
                        message=f"Backdoor Risk: {message} - validate training data, use anomaly detection, verify model provenance",
                        line=line,
                        column=1,
                    ))

            # MA007: Missing Differential Privacy
            for pattern, message in self.PRIVACY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA007",
                        severity=Severity.MEDIUM,
                        message=f"Privacy Risk: {message} - enable differential privacy, add calibrated noise to outputs",
                        line=line,
                        column=1,
                    ))

            # Check model endpoints
            issues.extend(self._check_model_endpoints(content, has_protection))

            # MA011: Model Extraction (CVE-2019-20634)
            for pattern, message, severity in self.MODEL_EXTRACTION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA011",
                        severity=severity,
                        message=f"Model Extraction Risk: {message}",
                        line=line,
                        column=1,
                    ))

            # MA012: GPU Memory Leakage (CVE-2023-4969)
            for pattern, message, severity in self.GPU_MEMORY_LEAKAGE_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="MA012",
                        severity=severity,
                        message=f"GPU Memory Leakage: {message} - call torch.cuda.empty_cache() or gc.collect()",
                        line=line,
                        column=1,
                    ))

            # Scan with YAML rules
            lines = content.split('\n')
            issues.extend(self._scan_with_rules(lines, file_path))

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _check_model_endpoints(
        self, content: str, has_protection: bool
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
                        message=f"Unprotected Model Endpoint: {message} - add authentication, rate limiting, and input validation",
                        line=line,
                        column=1,
                    ))

        return issues
