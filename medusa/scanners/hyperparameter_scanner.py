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
from medusa.scanners._ml_context import has_ml_context


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
    HIGH_LR_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'learning_rate\s*[=:]\s*(?:1\.0|1(?:\.0)?|[2-9]|[1-9]\d+)', re.IGNORECASE),
         'Extremely high learning rate (>=1.0) - training sabotage risk', Severity.HIGH),
        (re.compile(r'lr\s*[=:]\s*(?:0\.[5-9]|1\.)', re.IGNORECASE),
         'High learning rate (>=0.5) - may cause instability', Severity.MEDIUM),
        (re.compile(r'(?:learning_rate|lr)\s*[=:]\s*0\.1(?!\d)', re.IGNORECASE),
         'Learning rate of 0.1 - unusually high for most models', Severity.LOW),
    ]

    # HPT002: Extremely low learning rate (slow training, hard to detect poisoning)
    LOW_LR_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'learning_rate\s*[=:]\s*(?:0\.0{6,}|1e-[7-9]|1e-[1-9]\d)', re.IGNORECASE),
         'Extremely low learning rate - potential slow poisoning attack', Severity.MEDIUM),
        (re.compile(r'lr\s*[=:]\s*0\.0{5,}', re.IGNORECASE),
         'Very low learning rate (<1e-5) - training may be ineffective', Severity.LOW),
    ]

    # HPT003: Extreme batch sizes
    BATCH_SIZE_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'batch_size\s*[=:]\s*(?:[1-9]\d{4,}|[5-9]\d{3})', re.IGNORECASE),
         'Extremely large batch size (>5000) - gradient issues risk', Severity.MEDIUM),
        (re.compile(r'batch_size\s*[=:]\s*1(?!\d)', re.IGNORECASE),
         'Batch size of 1 - stochastic, unstable training', Severity.LOW),
        (re.compile(r'batch_size\s*[=:]\s*(?:2|3|4)(?!\d)', re.IGNORECASE),
         'Very small batch size (<5) - noisy gradients', Severity.LOW),
    ]

    # HPT004: Disabled regularization
    REGULARIZATION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'dropout\s*[=:]\s*(?:0(?:\.0)?|None|False)', re.IGNORECASE),
         'Dropout disabled - overfitting/memorization risk', Severity.MEDIUM),
        (re.compile(r'weight_decay\s*[=:]\s*(?:0(?:\.0)?|None)', re.IGNORECASE),
         'Weight decay disabled - overfitting risk', Severity.LOW),
        (re.compile(r'regularization\s*[=:]\s*(?:0|None|False)', re.IGNORECASE),
         'Regularization disabled - model may memorize training data', Severity.MEDIUM),
        (re.compile(r'l2_penalty\s*[=:]\s*(?:0|None)', re.IGNORECASE),
         'L2 penalty disabled - overfitting risk', Severity.LOW),
    ]

    # HPT005: Training config from untrusted source
    UNTRUSTED_CONFIG_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:load|read).*config.*(?:http|url|remote)', re.IGNORECASE),
         'Training config loaded from remote source', Severity.HIGH),
        (re.compile(r'yaml\.(?:safe_)?load\s*\(.*(?:url|http|request)', re.IGNORECASE),
         'YAML config from remote URL (tampering risk)', Severity.HIGH),
        (re.compile(r'json\.load\s*\(.*(?:url|http|request)', re.IGNORECASE),
         'JSON config from remote URL', Severity.MEDIUM),
        (re.compile(r'(?:wget|curl|requests\.get).*(?:config|hyperparameter|hparam)', re.IGNORECASE),
         'Downloading training configuration', Severity.MEDIUM),
        (re.compile(r'eval\s*\(.*(?:config|param)', re.IGNORECASE),
         'eval() on config values (code injection)', Severity.CRITICAL),
    ]

    # HPT006: Missing validation
    VALIDATION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'validation_split\s*[=:]\s*(?:0(?:\.0)?|None)', re.IGNORECASE),
         'No validation split - cannot detect overfitting', Severity.MEDIUM),
        (re.compile(r'val_size\s*[=:]\s*(?:0(?:\.0)?|None)', re.IGNORECASE),
         'Validation size is zero - no validation monitoring', Severity.MEDIUM),
        (re.compile(r'(?:train|fit)\s*\([^)]*\)(?!.*valid)', re.IGNORECASE),
         'Training without validation data parameter', Severity.LOW),
    ]

    # HPT007: Disabled early stopping
    EARLY_STOPPING_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'early_stopping\s*[=:]\s*(?:False|None|0)', re.IGNORECASE),
         'Early stopping disabled - overfitting risk', Severity.MEDIUM),
        (re.compile(r'patience\s*[=:]\s*(?:None|0|-1)', re.IGNORECASE),
         'Early stopping patience disabled', Severity.LOW),
        (re.compile(r'epochs\s*[=:]\s*(?:[5-9]\d{2,}|\d{4,})', re.IGNORECASE),
         'Extremely high epoch count (>=500) without early stopping check', Severity.MEDIUM),
    ]

    # HPT008: Suspicious weight initialization
    WEIGHT_INIT_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:weights|kernel)_initializer\s*[=:]\s*["\']?zeros', re.IGNORECASE),
         'Zero weight initialization (dead neurons)', Severity.MEDIUM),
        (re.compile(r'init\.constant_\s*\([^,]+,\s*0\)', re.IGNORECASE),
         'Constant zero initialization', Severity.MEDIUM),
        (re.compile(r'(?:bias|weight).*fill_\s*\(\s*0\s*\)', re.IGNORECASE),
         'Filling weights with zeros', Severity.LOW),
        (re.compile(r'nn\.init\.(?:zeros_|constant_.*0)', re.IGNORECASE),
         'PyTorch zero initialization', Severity.MEDIUM),
    ]

    # HPT009: Gradient clipping disabled
    GRADIENT_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:clip_grad|gradient_clip)\s*[=:]\s*(?:None|False|0)', re.IGNORECASE),
         'Gradient clipping disabled - exploding gradients risk', Severity.LOW),
        (re.compile(r'max_grad_norm\s*[=:]\s*(?:None|0|inf)', re.IGNORECASE),
         'Max gradient norm disabled or infinite', Severity.LOW),
    ]

    # HPT010: Untrusted pretrained weights
    PRETRAINED_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'load_state_dict\s*\(.*(?:http|url|download)', re.IGNORECASE),
         'Loading model weights from URL (backdoor risk)', Severity.HIGH),
        (re.compile(r'(?:torch|tf)\.load\s*\(.*(?:http|url)', re.IGNORECASE),
         'Loading model from URL', Severity.HIGH),
        (re.compile(r'from_pretrained\s*\(["\'][^"\']*(?:http|://)', re.IGNORECASE),
         'Loading pretrained model from URL', Severity.MEDIUM),
        (re.compile(r'(?:wget|curl).*(?:\.pt|\.pth|\.h5|\.ckpt|\.safetensors)', re.IGNORECASE),
         'Downloading model weights', Severity.MEDIUM),
        (re.compile(r'load.*weights.*(?:untrusted|external|third.?party)', re.IGNORECASE),
         'Loading weights from untrusted source', Severity.HIGH),
    ]

    # Good patterns (security measures)
    SECURITY_PATTERNS: List[re.Pattern] = [
        re.compile(r'validate.*checksum|checksum.*validate', re.IGNORECASE),
        re.compile(r'verify.*signature|signature.*verify', re.IGNORECASE),
        re.compile(r'hash.*weights|weights.*hash', re.IGNORECASE),
        re.compile(r'trusted.*source|source.*trusted', re.IGNORECASE),
        re.compile(r'early_stopping\s*[=:]\s*True', re.IGNORECASE),
        re.compile(r'validation_split\s*[=:]\s*0\.[1-3]', re.IGNORECASE),
    ]

    # JSON filenames that are plausibly ML training configs.
    # Generic data files (enterprise-attack.json, cve-db.json, etc.) are excluded.
    ML_JSON_NAMES: frozenset = frozenset([
        "config.json", "training_args.json", "train_config.json",
        "model_config.json", "hyperparameters.json", "hyperparameter.json",
        "hparams.json", "hp_config.json", "run_config.json",
        "experiment_config.json", "trainer_config.json", "finetune_config.json",
    ])

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"]

    def is_available(self) -> bool:
        return True

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return 0 for generic JSON data files — only scan known ML config filenames."""
        if file_path.suffix == ".json":
            if file_path.name.lower() in self.ML_JSON_NAMES:
                return 30
            return 0
        if file_path.suffix in (".py", ".yaml", ".yml", ".toml", ".cfg", ".ini"):
            return 20
        return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    # Maximum file size for hyperparameter scanning (2 MB).
    # Large JSON/YAML data files are datasets, not training configs.
    MAX_CONTENT_SCAN_SIZE = 2 * 1024 * 1024

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for hyperparameter tampering vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            # Skip large data files -- training configs are always small
            if content is None:
                try:
                    if file_path.stat().st_size > self.MAX_CONTENT_SCAN_SIZE:
                        return ScannerResult(
                            scanner_name=self.name,
                            file_path=str(file_path),
                            issues=[],
                            scan_time=time.time() - start_time,
                            success=True,
                        )
                except OSError:
                    pass
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is ML/training related.
            #
            # APPLICABILITY GATE: this scanner is ML-specific by definition (it
            # only flags training-hyperparameter issues). The legacy `ml_indicators`
            # list below admits generic substrings ('config', 'lr', 'fit', 'loss',
            # 'batch') that appear in benign non-ML code (e.g. rich/jinja2), causing
            # every HPT* heuristic AND the YAML corpus to fire on unrelated files.
            # Require genuine ML context (shared detector, which also ignores
            # quoted-name->emoji-glyph data lines) before doing ANY work here. A
            # real hyperparameter issue in ML code still carries that context, so it
            # still fires; coverage is preserved and no rule is removed.
            ml_indicators = [
                'train', 'model', 'epoch', 'batch', 'learning_rate', 'lr',
                'optimizer', 'loss', 'fit', 'keras', 'torch', 'tensorflow',
                'sklearn', 'xgboost', 'lightgbm', 'hyperparameter', 'config',
            ]
            content_lower = content.lower()

            if not has_ml_context(content) or not any(
                ind in content_lower for ind in ml_indicators
            ):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for security patterns
            has_security = any(
                p.search(content)
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
        patterns: List[Tuple[re.Pattern, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        """Check content against patterns"""
        issues = []
        seen = set()

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
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

        return issues
