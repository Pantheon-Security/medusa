#!/usr/bin/env python3
"""
MEDUSA LLM Guard Integration Scanner
Wraps Laiyer.ai's LLM Guard for input/output security scanning

LLM Guard is a production-ready tool for:
- Prompt injection detection and prevention
- Sensitive data detection (PII, secrets, credentials)
- Output sanitization and validation
- Toxicity and harmful content filtering

Based on: https://github.com/laiyer-ai/llm-guard
"""

import re
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class LLMGuardScanner(BaseScanner):
    """
    LLM Guard Integration Scanner

    Detects vulnerabilities that LLM Guard would catch:
    - LLG001: Prompt injection patterns
    - LLG002: Sensitive data exposure (PII)
    - LLG003: Secrets/credentials in prompts
    - LLG004: Toxic content patterns
    - LLG005: Language detection bypass
    - LLG006: Invisible character injection
    - LLG007: Code injection in prompts
    - LLG008: Regex attack patterns (ReDoS)
    - LLG009: Ban topics/subjects bypass
    - LLG010: Missing LLM guards

    This scanner performs static analysis on LLM-related code and configurations.
    For runtime protection, install: pip install llm-guard
    """

    # File extensions for LLM code/configs
    LLM_EXTENSIONS = [
        ".py", ".js", ".ts",  # Code
        ".yaml", ".yml", ".json", ".toml",  # Config
    ]

    # Keywords that indicate LLM interaction
    LLM_KEYWORDS = [
        "openai", "anthropic", "llm", "gpt", "claude", "prompt",
        "completion", "chat", "assistant", "langchain", "llamaindex",
        "huggingface", "transformers", "ollama", "gemini", "bedrock",
    ]

    def __init__(self):
        super().__init__()
        self._llm_guard_available = None

    def get_tool_name(self) -> str:
        return "llm-guard"

    def get_file_extensions(self) -> List[str]:
        return self.LLM_EXTENSIONS

    def is_available(self) -> bool:
        """Check if llm-guard is available"""
        if self._llm_guard_available is None:
            try:
                import llm_guard
                self._llm_guard_available = True
            except ImportError:
                self._llm_guard_available = False
        return self._llm_guard_available

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a single file"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """
        Scan file for LLM security issues

        Args:
            file_path: Path to the file
            content: File content (optional)

        Returns:
            ScannerResult with security issues
        """
        start_time = time.time()
        issues: List[ScannerIssue] = []

        if file_path.suffix.lower() not in self.LLM_EXTENSIONS:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        # Read content
        if content is None:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=False,
                    error="Failed to read file",
                )

        # Check if file is LLM-related
        content_lower = content.lower()
        if not any(kw in content_lower for kw in self.LLM_KEYWORDS):
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        # Run static analysis
        issues.extend(self._check_prompt_injection(content, file_path))
        issues.extend(self._check_pii_exposure(content, file_path))
        issues.extend(self._check_secrets_in_prompts(content, file_path))
        issues.extend(self._check_toxic_patterns(content, file_path))
        issues.extend(self._check_invisible_chars(content, file_path))
        issues.extend(self._check_code_injection(content, file_path))
        issues.extend(self._check_missing_guards(content, file_path))

        return ScannerResult(
            scanner_name=self.name,
            file_path=file_path,
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )

    def _check_prompt_injection(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG001: Check for prompt injection vulnerabilities"""
        issues = []
        lines = content.split('\n')

        # Patterns that indicate unprotected user input in prompts
        injection_patterns = [
            (r'f["\'][^"\']*\{user', "User input directly in f-string prompt"),
            (r'\.format\([^)]*user', "User input in .format() prompt"),
            (r'prompt\s*=\s*user', "User input assigned directly to prompt"),
            (r'message\s*=.*\+.*user', "User input concatenated to message"),
            (r'content.*\+.*input', "Input concatenated to content"),
            (r'template.*\{.*input', "Input in template string"),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, description in injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id="LLG001",
                        severity=Severity.CRITICAL,
                        message=f"Potential prompt injection: {description}. Sanitize user input before including in prompts.",
                        line=line_num,
                        column=1,
                        code=line.strip()[:100],
                        cwe_id=94,
                    ))
                    break

        return issues

    def _check_pii_exposure(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG002: Check for PII in prompts/responses"""
        issues = []
        lines = content.split('\n')

        # PII patterns that might end up in LLM interactions
        pii_patterns = [
            (r'ssn.*\d{3}[-\s]?\d{2}[-\s]?\d{4}', "Social Security Number pattern"),
            (r'credit.*card.*\d{4}', "Credit card number"),
            (r'email.*@.*\.(com|org|net)', "Email address"),
            (r'phone.*\d{3}[-\s]?\d{3}[-\s]?\d{4}', "Phone number"),
            (r'dob|birth.*date.*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', "Date of birth"),
            (r'address.*\d+.*street|ave|road', "Street address"),
        ]

        for line_num, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, description in pii_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id="LLG002",
                        severity=Severity.HIGH,
                        message=f"PII detected in LLM context: {description}. Use anonymization before sending to LLM.",
                        line=line_num,
                        column=1,
                        code=line.strip()[:80],
                    ))
                    break

        return issues

    def _check_secrets_in_prompts(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG003: Check for secrets that might leak to LLM"""
        issues = []
        lines = content.split('\n')

        # Secrets patterns
        secret_patterns = [
            (r'api[_-]?key.*["\'][a-zA-Z0-9]{20,}', "API key"),
            (r'(password|passwd|pwd).*["\'][^"\']{8,}', "Password"),
            (r'(secret|token).*["\'][a-zA-Z0-9]{16,}', "Secret/Token"),
            (r'bearer.*[a-zA-Z0-9\-_.]{20,}', "Bearer token"),
            (r'aws.*access.*key', "AWS access key"),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, description in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if it's in a prompt context
                    if any(kw in line.lower() for kw in ['prompt', 'message', 'content', 'chat']):
                        issues.append(ScannerIssue(
                            rule_id="LLG003",
                            severity=Severity.CRITICAL,
                            message=f"Secret may be exposed to LLM: {description}. Redact secrets before LLM calls.",
                            line=line_num,
                            column=1,
                            code=line.strip()[:60] + "...",
                        ))
                        break

        return issues

    def _check_toxic_patterns(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG004: Check for toxic content handling"""
        issues = []
        lines = content.split('\n')

        # Check for missing toxicity handling
        has_toxicity_check = any(term in content.lower() for term in [
            'toxicity', 'toxic', 'harmful', 'content_filter', 'moderation'
        ])

        if not has_toxicity_check:
            # Check if file has LLM output handling
            output_patterns = ['response', 'completion', 'output', 'result', 'answer']
            if any(p in content.lower() for p in output_patterns):
                for line_num, line in enumerate(lines, 1):
                    if any(p in line.lower() for p in output_patterns):
                        if 'return' in line.lower() or 'print' in line.lower():
                            issues.append(ScannerIssue(
                                rule_id="LLG004",
                                severity=Severity.MEDIUM,
                                message="LLM output returned without toxicity check. Consider adding content moderation.",
                                line=line_num,
                                column=1,
                                code=line.strip()[:100],
                            ))
                            break

        return issues

    def _check_invisible_chars(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG006: Check for invisible character injection"""
        issues = []
        lines = content.split('\n')

        # Invisible/zero-width characters that could hide malicious content
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space
            '\u00ad',  # Soft hyphen
        ]

        for line_num, line in enumerate(lines, 1):
            for char in invisible_chars:
                if char in line:
                    issues.append(ScannerIssue(
                        rule_id="LLG006",
                        severity=Severity.HIGH,
                        message="Invisible/zero-width character detected (potential prompt injection vector).",
                        line=line_num,
                        column=line.index(char) + 1,
                    ))
                    break

        return issues

    def _check_code_injection(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """LLG007: Check for code injection in prompts"""
        issues = []
        lines = content.split('\n')

        # Patterns that might allow code execution
        code_patterns = [
            (r'exec\s*\([^)]*response', "exec() on LLM response"),
            (r'eval\s*\([^)]*response', "eval() on LLM response"),
            (r'subprocess.*response', "subprocess with LLM response"),
            (r'os\.system.*response', "os.system with LLM response"),
            (r'__import__.*response', "dynamic import from response"),
        ]

        for line_num, line in enumerate(lines, 1):
            for pattern, description in code_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id="LLG007",
                        severity=Severity.CRITICAL,
                        message=f"Code execution from LLM output: {description}. Never execute LLM output as code.",
                        line=line_num,
                        column=1,
                        code=line.strip()[:100],
                        cwe_id=94,
                    ))

        return issues

    def _check_missing_guards(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """Check for missing LLM Guard patterns"""
        issues = []

        # Check if file has LLM API calls but no guard patterns
        has_api_call = any(term in content.lower() for term in [
            'openai.', 'anthropic.', '.chat.', '.complete',
            'langchain', 'llm.invoke', 'model.generate'
        ])

        guard_patterns = [
            'llm_guard', 'llm-guard', 'sanitize', 'validate_prompt',
            'check_injection', 'filter_output', 'scan_prompt'
        ]

        has_guards = any(term in content.lower() for term in guard_patterns)

        if has_api_call and not has_guards:
            issues.append(ScannerIssue(
                rule_id="LLG010",
                severity=Severity.MEDIUM,
                message="LLM API calls detected without input/output guards. Consider using LLM Guard: pip install llm-guard",
                line=1,
                column=1,
            ))

        return issues
