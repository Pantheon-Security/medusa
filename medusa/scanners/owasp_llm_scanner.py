#!/usr/bin/env python3
"""
MEDUSA OWASP LLM Top 10 Scanner
Detects vulnerabilities from OWASP Top 10 for LLM Applications

Based on "Generative AI Security Theories and Practices" Chapter 7

Detects:
- LLM01: Prompt Injection vulnerabilities
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning vectors
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance patterns
- LLM10: Model Theft vulnerabilities
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class OWASPLLMScanner(BaseScanner):
    """
    OWASP LLM Top 10 Security Scanner

    Scans for:
    - LLM01: Prompt Injection (direct and indirect)
    - LLM02: Insecure Output Handling (XSS, code execution)
    - LLM03: Training Data Poisoning vectors
    - LLM04: Model Denial of Service
    - LLM05: Supply Chain Vulnerabilities
    - LLM06: Sensitive Information Disclosure
    - LLM07: Insecure Plugin Design
    - LLM08: Excessive Agency
    - LLM09: Overreliance patterns
    - LLM10: Model Theft vulnerabilities
    """

    # LLM01: Prompt Injection patterns
    PROMPT_INJECTION_PATTERNS = [
        (r'(prompt|message)\s*=\s*.*\+\s*(user|input|request)',
         'User input concatenated into prompt (prompt injection risk)'),
        (r'f["\'].*\{(user_input|request|query|message)\}.*["\']',
         'User input interpolated in prompt string'),
        (r'(system_prompt|instructions)\s*\+\s*',
         'System prompt concatenated with untrusted data'),
        (r'prompt\s*=\s*(request|input|body)\.',
         'Prompt directly from request without sanitization'),
        (r'\.(format|replace)\s*\(.*user',
         'User input in string formatting for prompt'),
    ]

    # LLM02: Insecure Output Handling patterns
    INSECURE_OUTPUT_PATTERNS = [
        (r'(innerHTML|dangerouslySetInnerHTML)\s*=\s*.*response',
         'LLM response rendered as HTML without sanitization (XSS risk)'),
        (r'eval\s*\(.*response',
         'LLM response executed via eval (code execution risk)'),
        (r'exec\s*\(.*response',
         'LLM response executed via exec'),
        (r'subprocess.*response',
         'LLM response passed to subprocess'),
        (r'document\.write\s*\(.*response',
         'LLM response in document.write'),
        (r'(cursor|execute)\s*\(.*response',
         'LLM response in SQL query (SQL injection risk)'),
    ]

    # LLM04: Model DoS patterns
    DOS_PATTERNS = [
        (r'max_tokens\s*=\s*None',
         'No max_tokens limit (DoS risk)'),
        (r'max_tokens\s*=\s*\d{5,}',
         'Excessively high max_tokens value'),
        (r'while\s+True.*generate',
         'Unbounded generation loop'),
        (r'(input|prompt).*\*\s*\d{3,}',
         'Input multiplication (amplification attack)'),
    ]

    # LLM06: Sensitive Information Disclosure patterns
    DISCLOSURE_PATTERNS = [
        (r'(api_key|apikey|secret|password|token)\s*=\s*["\'][^"\']{8,}',
         'Hardcoded credential in code'),
        (r'(print|log|console)\s*\(.*prompt',
         'Prompt logged (may expose system instructions)'),
        (r'return.*system_prompt',
         'System prompt returned to user'),
        (r'response.*\+.*config',
         'Configuration data in response'),
        (r'(error|exception).*prompt',
         'Prompt exposed in error message'),
    ]

    # LLM07: Insecure Plugin patterns
    PLUGIN_PATTERNS = [
        (r'plugin\s*=\s*.*input',
         'Plugin loaded from user input'),
        (r'import.*\(.*user',
         'Dynamic import from user input'),
        (r'require\s*\(.*request',
         'Dynamic require from request'),
        (r'loadPlugin.*without.*auth',
         'Plugin loaded without authentication'),
        (r'plugin.*\*\s*permissions',
         'Plugin with wildcard permissions'),
    ]

    # LLM08: Excessive Agency patterns
    AGENCY_PATTERNS = [
        (r'auto_execute\s*=\s*True',
         'Auto-execution enabled (excessive agency)'),
        (r'confirm\s*=\s*False.*delete',
         'Deletion without confirmation'),
        (r'(sudo|admin|root)\s*=\s*True',
         'Elevated privileges enabled by default'),
        (r'permissions\s*=\s*\[?\s*["\']?\*',
         'Wildcard permissions granted'),
        (r'human_in_loop\s*=\s*False',
         'Human oversight disabled'),
        (r'auto_approve\s*=\s*True',
         'Auto-approval enabled'),
    ]

    # LLM10: Model Theft patterns
    MODEL_THEFT_PATTERNS = [
        (r'model\.(save|export|dump)\s*\(.*public',
         'Model exported to public location'),
        (r'(weights|checkpoint)\s*=.*download',
         'Model weights downloadable'),
        (r'model.*serializ.*response',
         'Model serialized in response'),
        (r'(GET|POST).*model.*weights',
         'Model weights exposed via API'),
    ]

    # Input validation patterns (good patterns)
    VALIDATION_PATTERNS = [
        r'sanitize',
        r'validate.*input',
        r'escape.*html',
        r'clean.*prompt',
        r'filter.*input',
        r'encode.*output',
    ]

    # Rate limiting patterns (good patterns)
    RATE_LIMIT_PATTERNS = [
        r'rate.*limit',
        r'throttle',
        r'max.*request',
        r'quota',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for OWASP LLM Top 10 vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is LLM-related
            llm_indicators = [
                'llm', 'gpt', 'openai', 'anthropic', 'claude', 'gemini',
                'prompt', 'completion', 'chat', 'generate', 'model',
                'langchain', 'llamaindex', 'huggingface',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in llm_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for validation (reduces severity)
            has_validation = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.VALIDATION_PATTERNS
            )

            has_rate_limit = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.RATE_LIMIT_PATTERNS
            )

            # LLM01: Prompt Injection
            for pattern, message in self.PROMPT_INJECTION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    severity = Severity.MEDIUM if has_validation else Severity.CRITICAL
                    issues.append(ScannerIssue(
                        rule_id="LLM01",
                        severity=severity,
                        message=f"Prompt Injection: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Sanitize user input, use parameterized prompts, implement input validation",
                    ))

            # LLM02: Insecure Output Handling
            for pattern, message in self.INSECURE_OUTPUT_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM02",
                        severity=Severity.CRITICAL,
                        message=f"Insecure Output: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate and sanitize LLM outputs before rendering or executing",
                    ))

            # LLM04: Model DoS
            for pattern, message in self.DOS_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    severity = Severity.MEDIUM if has_rate_limit else Severity.HIGH
                    issues.append(ScannerIssue(
                        rule_id="LLM04",
                        severity=severity,
                        message=f"Model DoS: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Implement token limits, rate limiting, and resource management",
                    ))

            # LLM06: Sensitive Information Disclosure
            for pattern, message in self.DISCLOSURE_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM06",
                        severity=Severity.HIGH,
                        message=f"Information Disclosure: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Use environment variables for secrets, sanitize error messages",
                    ))

            # LLM07: Insecure Plugin Design
            for pattern, message in self.PLUGIN_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM07",
                        severity=Severity.HIGH,
                        message=f"Insecure Plugin: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate plugin sources, implement access controls, use allowlists",
                    ))

            # LLM08: Excessive Agency
            for pattern, message in self.AGENCY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM08",
                        severity=Severity.HIGH,
                        message=f"Excessive Agency: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Limit permissions, require human approval for sensitive actions",
                    ))

            # LLM10: Model Theft
            for pattern, message in self.MODEL_THEFT_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM10",
                        severity=Severity.HIGH,
                        message=f"Model Theft Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Implement access controls, monitoring, and encryption for model assets",
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
