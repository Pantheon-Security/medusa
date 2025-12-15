#!/usr/bin/env python3
"""
MEDUSA Plugin Security Scanner (Cross-Plugin Request Forgery)
Detects LLM plugin vulnerabilities and CPRF attack vectors

Based on:
- OWASP Top 10 for LLM Applications - Insecure Plugin Design
- "Generative AI Security" - Plugin Security
- Cross-Plugin Request Forgery (CPRF) research

Detects:
- Insecure plugin input validation
- Cross-plugin request forgery patterns
- Missing access control in plugins
- Plugin chain exploitation risks
- Chat history exfiltration vectors
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PluginSecurityScanner(BaseScanner):
    """
    LLM Plugin Security Scanner (CPRF Detection)

    Scans for:
    - PLG001: Plugin without input validation
    - PLG002: Cross-plugin data access
    - PLG003: Missing plugin authentication
    - PLG004: Chat history exposure
    - PLG005: Plugin chain without sanitization
    - PLG006: Unrestricted plugin capabilities
    - PLG007: Plugin-to-plugin trust assumptions
    - PLG008: Sensitive data in plugin responses
    - PLG009: Plugin command injection
    - PLG010: Missing plugin rate limiting
    """

    # PLG001: Plugin without input validation
    INPUT_VALIDATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'@(?:plugin|tool|function)\s*\n.*def\s+\w+\([^)]*\)(?!.*(?:validate|sanitize|check))',
         'Plugin function without input validation', Severity.HIGH),
        (r'def\s+(?:execute|run|call)_plugin\s*\([^)]*\)(?!.*valid)',
         'Plugin execution without validation', Severity.HIGH),
        (r'plugin.*input.*(?:=|:).*(?:request|user)',
         'Plugin receiving raw user input', Severity.MEDIUM),
        (r'tool_input\s*=\s*(?:args|params|request)',
         'Tool input from unvalidated source', Severity.MEDIUM),
    ]

    # PLG002: Cross-plugin data access
    CPRF_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:get|access|read)_plugin_data\s*\(\s*["\'][^"\']+["\']',
         'Cross-plugin data access (CPRF risk)', Severity.HIGH),
        (r'plugins\[["\'][^"\']+["\']\]\.(?:data|state|context)',
         'Direct plugin state access', Severity.HIGH),
        (r'(?:share|pass).*(?:between|across).*plugin',
         'Data sharing between plugins', Severity.MEDIUM),
        (r'plugin_context\[.*\]\s*=',
         'Writing to shared plugin context', Severity.MEDIUM),
        (r'other_plugin\.(?:invoke|call|execute)',
         'Plugin invoking another plugin', Severity.MEDIUM),
    ]

    # PLG003: Missing plugin authentication
    AUTH_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'@(?:plugin|tool).*\n(?!.*(?:auth|permission|token|verify))',
         'Plugin without authentication check', Severity.MEDIUM),
        (r'plugin.*(?:public|open|unrestricted)',
         'Plugin marked as public/unrestricted', Severity.HIGH),
        (r'skip.*(?:auth|authentication).*plugin',
         'Authentication skipped for plugin', Severity.HIGH),
        (r'allow_anonymous.*(?:True|true)',
         'Plugin allows anonymous access', Severity.HIGH),
    ]

    # PLG004: Chat history exposure
    CHAT_HISTORY_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:chat|conversation)_history.*(?:return|response|expose)',
         'Chat history exposed in plugin response', Severity.HIGH),
        (r'(?:get|read|access)_(?:chat|conversation)_history',
         'Plugin accessing chat history', Severity.MEDIUM),
        (r'messages\[.*\].*(?:plugin|tool)',
         'Message history accessible to plugin', Severity.MEDIUM),
        (r'(?:export|dump|serialize).*(?:chat|conversation)',
         'Chat history export functionality', Severity.MEDIUM),
        (r'previous_messages|message_history|chat_log',
         'Chat log variable in plugin context', Severity.LOW),
    ]

    # PLG005: Plugin chain without sanitization
    CHAIN_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'plugin.*chain|chain.*plugin',
         'Plugin chaining detected (validate between steps)', Severity.MEDIUM),
        (r'(?:pipe|forward|pass).*(?:to|through).*plugin',
         'Data piped between plugins', Severity.MEDIUM),
        (r'plugin_result.*(?:input|param).*next_plugin',
         'Plugin output used as next plugin input', Severity.HIGH),
        (r'(?:sequential|series).*plugin.*(?:execute|run)',
         'Sequential plugin execution', Severity.LOW),
    ]

    # PLG006: Unrestricted plugin capabilities
    CAPABILITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'plugin.*(?:file|filesystem|disk).*(?:read|write|delete)',
         'Plugin with filesystem access', Severity.HIGH),
        (r'plugin.*(?:network|http|request).*(?:send|fetch|get)',
         'Plugin with network access', Severity.MEDIUM),
        (r'plugin.*(?:execute|run|shell|subprocess)',
         'Plugin with code execution capability', Severity.CRITICAL),
        (r'plugin.*(?:database|sql|query)',
         'Plugin with database access', Severity.HIGH),
        (r'(?:os\.|subprocess\.|exec\().*plugin',
         'OS/subprocess in plugin code', Severity.CRITICAL),
    ]

    # PLG007: Plugin-to-plugin trust
    TRUST_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'trust.*plugin|plugin.*trust',
         'Plugin trust relationship', Severity.LOW),
        (r'(?:skip|bypass).*validation.*plugin',
         'Validation bypassed for trusted plugin', Severity.HIGH),
        (r'internal_plugin.*(?:unrestricted|full_access)',
         'Internal plugin with full access', Severity.MEDIUM),
        (r'(?:whitelist|allowlist).*plugin',
         'Plugin whitelist (verify entries)', Severity.LOW),
    ]

    # PLG008: Sensitive data in plugin responses
    SENSITIVE_DATA_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'return.*(?:password|secret|key|token|credential)',
         'Sensitive data in plugin return', Severity.CRITICAL),
        (r'plugin.*response.*(?:api_key|secret|password)',
         'Sensitive data in plugin response', Severity.CRITICAL),
        (r'(?:include|expose).*(?:env|environment).*plugin',
         'Environment variables exposed to plugin', Severity.HIGH),
        (r'plugin.*(?:log|print).*(?:secret|password|token)',
         'Plugin logging sensitive data', Severity.HIGH),
    ]

    # PLG009: Plugin command injection
    INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:exec|eval|system)\s*\(.*plugin.*input',
         'Command injection via plugin input', Severity.CRITICAL),
        (r'(?:os\.system|subprocess).*(?:plugin|tool).*(?:param|arg)',
         'OS command with plugin parameters', Severity.CRITICAL),
        (r'sql.*(?:format|%|f["\']).*plugin',
         'SQL formatting with plugin input', Severity.CRITICAL),
        (r'(?:shell|bash|cmd).*plugin.*(?:input|param)',
         'Shell command with plugin input', Severity.CRITICAL),
    ]

    # PLG010: Missing rate limiting
    RATE_LIMIT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'@(?:plugin|tool)(?!.*(?:rate_limit|throttle|limit))',
         'Plugin without rate limiting', Severity.LOW),
        (r'plugin.*(?:unlimited|no_limit)',
         'Plugin with unlimited access', Severity.MEDIUM),
        (r'(?:disable|skip).*rate.*limit.*plugin',
         'Rate limiting disabled for plugin', Severity.MEDIUM),
    ]

    # Good patterns
    SECURITY_PATTERNS = [
        r'validate.*input|input.*validate',
        r'sanitize|escape|clean',
        r'rate_limit|throttle',
        r'authenticate|authorize|permission',
        r'access_control',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx"]

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for plugin security vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is plugin/tool related
            plugin_indicators = [
                'plugin', 'tool', 'function_call', 'action', 'capability',
                'langchain', 'llama_index', 'openai.function', 'anthropic.tool',
                'chatgpt', 'assistant', 'agent',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in plugin_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            has_security = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.SECURITY_PATTERNS
            )

            lines = content.split('\n')

            all_patterns = [
                (self.INPUT_VALIDATION_PATTERNS, "PLG001"),
                (self.CPRF_PATTERNS, "PLG002"),
                (self.AUTH_PATTERNS, "PLG003"),
                (self.CHAT_HISTORY_PATTERNS, "PLG004"),
                (self.CHAIN_PATTERNS, "PLG005"),
                (self.CAPABILITY_PATTERNS, "PLG006"),
                (self.TRUST_PATTERNS, "PLG007"),
                (self.SENSITIVE_DATA_PATTERNS, "PLG008"),
                (self.INJECTION_PATTERNS, "PLG009"),
                (self.RATE_LIMIT_PATTERNS, "PLG010"),
            ]

            for patterns, rule_id in all_patterns:
                issues.extend(self._check_patterns(content, lines, patterns, rule_id))

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
                                message=f"{message} - implement proper plugin security controls",
                                line=i,
                                column=1,
                            ))
                            seen.add(message)
                            break
                except re.error:
                    continue

        return issues
