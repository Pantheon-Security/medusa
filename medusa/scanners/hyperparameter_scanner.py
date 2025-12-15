#!/usr/bin/env python3
"""
MEDUSA Hyperparameter Tampering Scanner
Detects ML training sabotage and suspicious hyperparameter configurations

Based on:
- "Generative AI Security: Theories and Practices" - Hyperparameter Tampering
- ML security best practices
- Training data poisoning research

Detects:
- Suspiciously high/low learning rates
- Batch sizes that cause gradient issues
- Disabled regularization with high epochs
- Training configs from untrusted sources
- Missing validation/early stopping
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class HyperparameterScanner(BaseScanner):
    """
    Hyperparameter Tampering Detection Scanner

    Scans for:
    - HPT001: Suspiciously high learning rate
    - HPT002: Suspiciously low learning rate (slow poisoning)
    - HPT003: Extreme batch sizes
    - HPT004: Disabled regularization with high epochs
    - HPT005: Training config from untrusted source
    - HPT006: Missing validation split
    - HPT007: Disabled early stopping
    - HPT008: Suspicious weight initialization
    - HPT009: Gradient clipping disabled
    - HPT010: Untrusted pretrained weights
    """

    # HPT001: High learning rate (causes instability/divergence)
    HIGH_LR_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'learning_rate\s*[=:]\s*(?:1\.0|1(?:\.0)?|[2-9]|[1-9]\d+)',
         'Extremely high learning rate (>=1.0) - training sabotage risk', Severity.HIGH),
        (r'lr\s*[=:]\s*(?:0\.[5-9]|1\.)',
         'High learning rate (>=0.5) - may cause instability', Severity.MEDIUM),
        (r'(?:learning_rate|lr)\s*[=:]\s*0\.1(?!\d)',
         'Learning rate of 0.1 - unusually high for most models', Severity.LOW),
    ]

    # HPT002: Extremely low learning rate (slow training, hard to detect poisoning)
    LOW_LR_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'learning_rate\s*[=:]\s*(?:0\.0{6,}|1e-[7-9]|1e-[1-9]\d)',
         'Extremely low learning rate - potential slow poisoning attack', Severity.MEDIUM),
        (r'lr\s*[=:]\s*0\.0{5,}',
         'Very low learning rate (<1e-5) - training may be ineffective', Severity.LOW),
    ]

    # HPT003: Extreme batch sizes
    BATCH_SIZE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'batch_size\s*[=:]\s*(?:[1-9]\d{4,}|[5-9]\d{3})',
         'Extremely large batch size (>5000) - gradient issues risk', Severity.MEDIUM),
        (r'batch_size\s*[=:]\s*1(?!\d)',
         'Batch size of 1 - stochastic, unstable training', Severity.LOW),
        (r'batch_size\s*[=:]\s*(?:2|3|4)(?!\d)',
         'Very small batch size (<5) - noisy gradients', Severity.LOW),
    ]

    # HPT004: Disabled regularization
    REGULARIZATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'dropout\s*[=:]\s*(?:0(?:\.0)?|None|False)',
         'Dropout disabled - overfitting/memorization risk', Severity.MEDIUM),
        (r'weight_decay\s*[=:]\s*(?:0(?:\.0)?|None)',
         'Weight decay disabled - overfitting risk', Severity.LOW),
        (r'regularization\s*[=:]\s*(?:0|None|False)',
         'Regularization disabled - model may memorize training data', Severity.MEDIUM),
        (r'l2_penalty\s*[=:]\s*(?:0|None)',
         'L2 penalty disabled - overfitting risk', Severity.LOW),
    ]

    # HPT005: Training config from untrusted source
    UNTRUSTED_CONFIG_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:load|read).*config.*(?:http|url|remote)',
         'Training config loaded from remote source', Severity.HIGH),
        (r'yaml\.(?:safe_)?load\s*\(.*(?:url|http|request)',
         'YAML config from remote URL (tampering risk)', Severity.HIGH),
        (r'json\.load\s*\(.*(?:url|http|request)',
         'JSON config from remote URL', Severity.MEDIUM),
        (r'(?:wget|curl|requests\.get).*(?:config|hyperparameter|hparam)',
         'Downloading training configuration', Severity.MEDIUM),
        (r'eval\s*\(.*(?:config|param)',
         'eval() on config values (code injection)', Severity.CRITICAL),
    ]

    # HPT006: Missing validation
    VALIDATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'validation_split\s*[=:]\s*(?:0(?:\.0)?|None)',
         'No validation split - cannot detect overfitting', Severity.MEDIUM),
        (r'val_size\s*[=:]\s*(?:0(?:\.0)?|None)',
         'Validation size is zero - no validation monitoring', Severity.MEDIUM),
        (r'(?:train|fit)\s*\([^)]*\)(?!.*valid)',
         'Training without validation data parameter', Severity.LOW),
    ]

    # HPT007: Disabled early stopping
    EARLY_STOPPING_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'early_stopping\s*[=:]\s*(?:False|None|0)',
         'Early stopping disabled - overfitting risk', Severity.MEDIUM),
        (r'patience\s*[=:]\s*(?:None|0|-1)',
         'Early stopping patience disabled', Severity.LOW),
        (r'epochs\s*[=:]\s*(?:[5-9]\d{2,}|\d{4,})',
         'Extremely high epoch count (>=500) without early stopping check', Severity.MEDIUM),
    ]

    # HPT008: Suspicious weight initialization
    WEIGHT_INIT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:weights|kernel)_initializer\s*[=:]\s*["\']?zeros',
         'Zero weight initialization (dead neurons)', Severity.MEDIUM),
        (r'init\.constant_\s*\([^,]+,\s*0\)',
         'Constant zero initialization', Severity.MEDIUM),
        (r'(?:bias|weight).*fill_\s*\(\s*0\s*\)',
         'Filling weights with zeros', Severity.LOW),
        (r'nn\.init\.(?:zeros_|constant_.*0)',
         'PyTorch zero initialization', Severity.MEDIUM),
    ]

    # HPT009: Gradient clipping disabled
    GRADIENT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:clip_grad|gradient_clip)\s*[=:]\s*(?:None|False|0)',
         'Gradient clipping disabled - exploding gradients risk', Severity.LOW),
        (r'max_grad_norm\s*[=:]\s*(?:None|0|inf)',
         'Max gradient norm disabled or infinite', Severity.LOW),
    ]

    # HPT010: Untrusted pretrained weights
    PRETRAINED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'load_state_dict\s*\(.*(?:http|url|download)',
         'Loading model weights from URL (backdoor risk)', Severity.HIGH),
        (r'(?:torch|tf)\.load\s*\(.*(?:http|url)',
         'Loading model from URL', Severity.HIGH),
        (r'from_pretrained\s*\(["\'][^"\']*(?:http|://)',
         'Loading pretrained model from URL', Severity.MEDIUM),
        (r'(?:wget|curl).*(?:\.pt|\.pth|\.h5|\.ckpt|\.safetensors)',
         'Downloading model weights', Severity.MEDIUM),
        (r'load.*weights.*(?:untrusted|external|third.?party)',
         'Loading weights from untrusted source', Severity.HIGH),
    ]

    # Good patterns (security measures)
    SECURITY_PATTERNS = [
        r'validate.*checksum|checksum.*validate',
        r'verify.*signature|signature.*verify',
        r'hash.*weights|weights.*hash',
        r'trusted.*source|source.*trusted',
        r'early_stopping\s*[=:]\s*True',
        r'validation_split\s*[=:]\s*0\.[1-3]',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"]

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for hyperparameter tampering vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is ML/training related
            ml_indicators = [
                'train', 'model', 'epoch', 'batch', 'learning_rate', 'lr',
                'optimizer', 'loss', 'fit', 'keras', 'torch', 'tensorflow',
                'sklearn', 'xgboost', 'lightgbm', 'hyperparameter', 'config',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in ml_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for security patterns
            has_security = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.SECURITY_PATTERNS
            )

            lines = content.split('\n')

            # Check all pattern categories
            all_patterns = [
                (self.HIGH_LR_PATTERNS, "HPT001"),
                (self.LOW_LR_PATTERNS, "HPT002"),
                (self.BATCH_SIZE_PATTERNS, "HPT003"),
                (self.REGULARIZATION_PATTERNS, "HPT004"),
                (self.UNTRUSTED_CONFIG_PATTERNS, "HPT005"),
                (self.VALIDATION_PATTERNS, "HPT006"),
                (self.EARLY_STOPPING_PATTERNS, "HPT007"),
                (self.WEIGHT_INIT_PATTERNS, "HPT008"),
                (self.GRADIENT_PATTERNS, "HPT009"),
                (self.PRETRAINED_PATTERNS, "HPT010"),
            ]

            for patterns, rule_id in all_patterns:
                issues.extend(self._check_patterns(content, lines, patterns, rule_id))

            # Reduce severity if security measures present
            if has_security:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.MEDIUM:
                        issue.severity = Severity.LOW

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

    def _check_patterns(
        self,
        content: str,
        lines: List[str],
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        """Check content against patterns"""
        issues = []
        seen = set()

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        if message not in seen:
                            issues.append(ScannerIssue(
                                rule_id=rule_id,
                                severity=severity,
                                message=f"{message} - verify training configuration integrity",
                                line=i,
                                column=1,
                            ))
                            seen.add(message)
                            break
                except re.error:
                    continue

        return issues
