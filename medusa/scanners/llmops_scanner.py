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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class LLMOpsScanner(RuleBasedScanner):
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
    - LO011: Ray framework vulnerability
    - LO012: Shadow Ray attack pattern
    - LO013: Vulnerable ML dependency
    - LO014: Unsigned LoRA adapter
    - LO015: Untrusted adapter source
    - LO016: Adapter integrity check missing
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['LLMOPS-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['llmops', 'model_deployment', 'inference_security']

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

    # LO011-012: Ray Framework / Shadow Ray vulnerability patterns
    RAY_VULNERABILITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Ray framework imports (check for vulnerable versions)
        (r'from\s+ray\s+import',
         'LO011: Ray framework detected - check version for vulnerabilities', Severity.MEDIUM),
        (r'import\s+ray',
         'LO011: Ray framework detected - check version for vulnerabilities', Severity.MEDIUM),
        (r'ray\.init\s*\(',
         'LO011: Ray cluster initialization - ensure dashboard is secured', Severity.MEDIUM),

        # Shadow Ray attack patterns (CVE-2023-48022 related)
        (r'ray\.dashboard\.modules',
         'LO012: Ray dashboard module access - potential Shadow Ray attack vector', Severity.HIGH),
        (r'ray[_-]?client.*connect.*(?!localhost)',
         'LO012: Remote Ray client connection - verify authorization', Severity.HIGH),
        (r'ray\.job_submission',
         'LO012: Ray job submission API - ensure proper authentication', Severity.HIGH),

        # Exposed Ray dashboard
        (r'dashboard[_-]?host\s*=\s*["\']0\.0\.0\.0["\']',
         'LO012: Ray dashboard exposed to all interfaces (Shadow Ray risk)', Severity.CRITICAL),
        (r'dashboard[_-]?port.*[0-9]+.*host.*0\.0\.0\.0',
         'LO012: Ray dashboard publicly accessible', Severity.CRITICAL),
    ]

    # LO013: Vulnerable ML dependencies
    VULNERABLE_ML_DEPS: List[Tuple[str, str, Severity]] = [
        # Known vulnerable packages/patterns
        (r'tensorflow\s*[<>=!]+\s*[12]\.[0-9]+\.[0-9]+',
         'LO013: TensorFlow version specified - check for known vulnerabilities', Severity.LOW),
        (r'torch\s*[<>=!]+\s*[12]\.[0-9]+',
         'LO013: PyTorch version specified - check for known vulnerabilities', Severity.LOW),
        (r'transformers\s*[<>=!]+\s*[34]\.[0-9]+',
         'LO013: Transformers version specified - verify security updates', Severity.LOW),

        # Insecure serialization
        (r'pickle\.loads?\s*\([^)]*(?:url|http|request)',
         'LO013: Pickle deserialization from remote source (RCE risk)', Severity.CRITICAL),
        (r'torch\.load\s*\([^)]*http',
         'LO013: PyTorch model loaded from URL without verification', Severity.HIGH),
    ]

    # LO014-016: LoRA Adapter Security patterns
    LORA_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Loading unsigned adapters
        (r'load_adapter\s*\((?!.*(?:verify|signature|checksum))',
         'LO014: LoRA adapter loaded without signature verification', Severity.HIGH),
        (r'PeftModel\.from_pretrained\s*\((?!.*(?:verify|trust))',
         'LO014: PEFT model loaded - consider verifying adapter source', Severity.MEDIUM),
        (r'LoraConfig\s*\((?!.*signature)',
         'LO014: LoRA config without signature parameter', Severity.LOW),

        # Untrusted adapter sources
        (r'load_adapter\s*\(["\'][^"\']*(?!huggingface\.co/[a-zA-Z0-9_-]+/)',
         'LO015: LoRA adapter from potentially untrusted source', Severity.MEDIUM),
        (r'from_pretrained\s*\(["\'](?!.*(?:huggingface|openai|anthropic))',
         'LO015: Adapter from non-standard source - verify authenticity', Severity.MEDIUM),
        (r'adapter_path\s*=\s*["\']http',
         'LO015: LoRA adapter loaded from HTTP URL', Severity.HIGH),

        # Missing adapter integrity checks
        (r'merge_adapter\s*\((?!.*(?:checksum|verify|validate))',
         'LO016: Adapter merge without integrity verification', Severity.HIGH),
        (r'set_adapter\s*\([^)]*\)(?!.*verify)',
         'LO016: Adapter set without verification', Severity.MEDIUM),
        (r'add_adapter\s*\([^)]*(?:url|http)',
         'LO016: Adapter added from URL without integrity check', Severity.HIGH),
    ]

    # GPU Memory vulnerability patterns (CVE-2023-4969 - LeftOvers)
    GPU_MEMORY_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'torch\.cuda\.empty_cache\(\)',
         'GPU memory clearing present (good practice)', Severity.LOW),  # Actually good
        (r'del\s+model\s*(?!.*(?:gc\.collect|empty_cache))',
         'Model deleted but GPU memory not explicitly cleared', Severity.MEDIUM),
        (r'\.to\s*\(\s*["\']cuda',
         'Model moved to GPU - ensure proper cleanup after inference', Severity.LOW),
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
                # Still scan with YAML rules
                lines = content.split('\n')
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=yaml_issues,
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
                        message=f"Insecure Model Loading: {message} - use safetensors, verify model hashes",
                        line=line,
                        column=1,
                    ))

            # LO002: Missing Model Versioning
            if 'model' in content_lower and 'save' in content_lower and not has_versioning:
                issues.append(ScannerIssue(
                    rule_id="LO002",
                    severity=Severity.LOW,
                    message="Model operations without versioning - use MLflow, DVC, or W&B for tracking",
                    line=1,
                    column=1,
                ))

            # LO003: Unmonitored Deployment
            if 'deploy' in content_lower and not has_monitoring:
                issues.append(ScannerIssue(
                    rule_id="LO003",
                    severity=Severity.MEDIUM,
                    message="Model deployment without monitoring - add Prometheus, Arize, or WhyLabs",
                    line=1,
                    column=1,
                ))

            # LO004: Insecure Fine-tuning
            for pattern, message in self.FINETUNING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO004",
                        severity=Severity.HIGH,
                        message=f"Insecure Fine-tuning: {message} - validate data and sanitize inputs",
                        line=line,
                        column=1,
                    ))

            # LO005: Missing Drift Detection
            if 'deploy' in content_lower and not has_drift_detection:
                issues.append(ScannerIssue(
                    rule_id="LO005",
                    severity=Severity.LOW,
                    message="No drift detection for deployed model - use Evidently or Alibi Detect",
                    line=1,
                    column=1,
                ))

            # LO006: Exposed Feedback Channels
            for pattern, message in self.FEEDBACK_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO006",
                        severity=Severity.HIGH,
                        message=f"Feedback Vulnerability: {message} - validate and sanitize feedback",
                        line=line,
                        column=1,
                    ))

            # LO007: Insecure Checkpoint Storage
            for pattern, message in self.CHECKPOINT_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO007",
                        severity=Severity.HIGH,
                        message=f"Checkpoint Security: {message} - use private encrypted storage",
                        line=line,
                        column=1,
                    ))

            # LO009: Unencrypted Model Transfer
            for pattern, message in self.TRANSFER_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO009",
                        severity=Severity.HIGH,
                        message=f"Insecure Transfer: {message} - use HTTPS and verify checksums",
                        line=line,
                        column=1,
                    ))

            # LO010: Missing Audit Logging
            if ('train' in content_lower or 'deploy' in content_lower) and not has_audit:
                issues.append(ScannerIssue(
                    rule_id="LO010",
                    severity=Severity.MEDIUM,
                    message="Model operations without audit logging - log all training and deployment ops",
                    line=1,
                    column=1,
                ))

            # LO011-012: Ray Framework / Shadow Ray vulnerabilities
            for pattern, message, severity in self.RAY_VULNERABILITY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    rule_id = message.split(':')[0] if ':' in message else "LO011"
                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=f"{message} - secure dashboard, use auth, update version",
                        line=line,
                        column=1,
                    ))

            # LO013: Vulnerable ML Dependencies
            for pattern, message, severity in self.VULNERABLE_ML_DEPS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO013",
                        severity=severity,
                        message=f"{message} - use pip-audit or safety for scanning",
                        line=line,
                        column=1,
                    ))

            # LO014-016: LoRA Adapter Security
            for pattern, message, severity in self.LORA_SECURITY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    rule_id = message.split(':')[0] if ':' in message else "LO014"
                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=f"{message} - verify signatures and checksums",
                        line=line,
                        column=1,
                    ))

            # GPU Memory patterns (informational - CVE-2023-4969 related)
            for pattern, message, severity in self.GPU_MEMORY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match and severity != Severity.LOW:  # Skip informational patterns
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LO013",  # Associated with vulnerability detection
                        severity=severity,
                        message=f"CVE-2023-4969 related: {message} - use empty_cache() and gc.collect()",
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
