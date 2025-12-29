#!/usr/bin/env python3
"""
MEDUSA Prompt Leakage Scanner
Detects potential system prompt and instruction leakage in agent code

Based on "Agentic Design Patterns" Chapter 18 - Guardrails/Safety Patterns

Detects:
- System prompts exposed in responses
- Tool definitions leaked to users
- Internal instructions in output
- Debug information exposure
- Sensitive configuration in logs
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class PromptLeakageScanner(RuleBasedScanner):
    """
    Prompt Leakage Detection Scanner

    Scans for:
    - PL001: System prompt concatenated with user output
    - PL002: Tool definitions in response strings
    - PL003: Internal instructions exposed
    - PL004: Debug mode exposing internals
    - PL005: Logging system prompts
    - PL006: Error messages exposing prompts
    - PL007: Direct prompt echo in response
    - PL008: Tool schema in user-facing output
    - PL009: Configuration dump in responses
    - PL010: Missing output sanitization
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['PROMPT-LK-', 'PROMPT-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['prompt_leakage', 'system_prompt']

    # Patterns indicating prompt leakage risks
    PROMPT_LEAKAGE_PATTERNS: List[Tuple[str, str, Severity, str]] = [
        # Direct prompt inclusion in responses
        (
            r'(response|output|result|answer)\s*[+=]\s*(system_prompt|SYSTEM_PROMPT|systemPrompt)',
            'System prompt directly included in response',
            Severity.CRITICAL,
            'PL001',
        ),
        (
            r'(response|output|result)\s*[+=].{0,50}\+\s*(prompt|instruction)',
            'Prompt concatenated with response',
            Severity.HIGH,
            'PL001',
        ),
        (
            r'f["\'].*\{(system_prompt|instructions|PROMPT)\}',
            'System prompt interpolated in f-string response',
            Severity.CRITICAL,
            'PL001',
        ),
        (
            r'\$\{(systemPrompt|system_prompt|instructions)\}',
            'System prompt in template literal',
            Severity.CRITICAL,
            'PL001',
        ),

        # Tool definitions leaked
        (
            r'(return|response|output).{0,50}tool(s|_definition|Schema|_schema)',
            'Tool definitions included in response',
            Severity.HIGH,
            'PL002',
        ),
        (
            r'JSON\.stringify\s*\(\s*(tools|toolDefinitions)',
            'Tool definitions serialized in response',
            Severity.HIGH,
            'PL002',
        ),

        # Internal instructions
        (
            r'(response|return).{0,50}internal.{0,30}instruction',
            'Internal instructions in output',
            Severity.HIGH,
            'PL003',
        ),
        (
            r'\.append\s*\(\s*(system|internal).*prompt',
            'System/internal prompt appended to output',
            Severity.CRITICAL,
            'PL003',
        ),

        # Debug mode risks
        (
            r'if\s*\(?\s*(debug|DEBUG|verbose)',
            'Debug mode check - ensure prompts not leaked in debug',
            Severity.MEDIUM,
            'PL004',
        ),
        (
            r'debug.{0,20}=.{0,10}[Tt]rue.{0,50}print.{0,30}(prompt|instruction|system)',
            'Debug mode printing prompts',
            Severity.HIGH,
            'PL004',
        ),
        (
            r'console\.(log|debug|info)\s*\(\s*(system|prompt|instruction)',
            'Console logging system prompts',
            Severity.HIGH,
            'PL004',
        ),

        # Logging prompts
        (
            r'(log|logger)\.(info|debug|warning|error)\s*\(.{0,50}system.{0,30}prompt',
            'Logging system prompts (may appear in user-visible logs)',
            Severity.MEDIUM,
            'PL005',
        ),
        (
            r'(log|print|console)\s*\(.{0,50}PROMPT',
            'Logging prompt constants',
            Severity.MEDIUM,
            'PL005',
        ),

        # Error messages exposing prompts
        (
            r'(raise|throw|Error)\s*\(.{0,50}prompt',
            'Error message may expose prompt',
            Severity.MEDIUM,
            'PL006',
        ),
        (
            r'except.{0,20}:.{0,50}return.{0,30}(prompt|instruction)',
            'Exception handler returns prompt content',
            Severity.HIGH,
            'PL006',
        ),
        (
            r'catch.{0,50}return.{0,30}(prompt|instruction|system)',
            'Catch block returns prompt content',
            Severity.HIGH,
            'PL006',
        ),

        # Direct echo
        (
            r'echo\s+(prompt|instruction|system)',
            'Direct echo of prompt variables',
            Severity.HIGH,
            'PL007',
        ),
        (
            r'return\s+(prompt|system_prompt|instructions)\s*$',
            'Directly returning prompt variable',
            Severity.CRITICAL,
            'PL007',
        ),

        # Tool schema exposure
        (
            r'(response|output).{0,50}schema',
            'Schema included in response',
            Severity.MEDIUM,
            'PL008',
        ),
        (
            r'return.{0,50}function.{0,30}definition',
            'Function definition in return value',
            Severity.MEDIUM,
            'PL008',
        ),

        # Config dumps
        (
            r'(response|return).{0,50}config(uration)?',
            'Configuration in response',
            Severity.MEDIUM,
            'PL009',
        ),
        (
            r'JSON\.stringify\s*\(\s*config',
            'Config serialized in output',
            Severity.MEDIUM,
            'PL009',
        ),
    ]

    # Patterns for missing output sanitization
    MISSING_SANITIZATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (
            r'return\s+raw',
            'Returning raw response without sanitization',
            Severity.MEDIUM,
        ),
        (
            r'response\s*=\s*llm\.',
            'LLM response used without output filtering',
            Severity.LOW,
        ),
        (
            r'(await|async).*generate.*return',
            'Generated content returned without filtering',
            Severity.LOW,
        ),
    ]

    # Patterns that indicate good sanitization (reduce false positives)
    SANITIZATION_PATTERNS = [
        r'sanitize',
        r'filter.*output',
        r'validate.*response',
        r'clean.*response',
        r'strip.*prompt',
        r'remove.*system',
        r'redact',
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
        """Scan for prompt leakage vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Skip if file seems to have good sanitization
            content_lower = content.lower()
            has_sanitization = any(
                re.search(pattern, content_lower)
                for pattern in self.SANITIZATION_PATTERNS
            )

            # Check prompt leakage patterns
            for pattern, message, severity, rule_id in self.PROMPT_LEAKAGE_PATTERNS:
                matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
                for match in matches:
                    line = content[:match.start()].count('\n') + 1
                    # Reduce severity if sanitization exists
                    effective_severity = severity
                    if has_sanitization and severity != Severity.CRITICAL:
                        effective_severity = Severity(max(1, severity.value - 1))

                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=effective_severity,
                        message=message,
                        file_path=file_path,
                        line=line,
                        column=match.start() - content.rfind('\n', 0, match.start()),
                        context=self._get_context(content, match.start()),
                        suggestion=self._get_suggestion(rule_id),
                    ))

            # Check for missing sanitization (only if no sanitization found)
            if not has_sanitization:
                for pattern, message, severity in self.MISSING_SANITIZATION_PATTERNS:
                    matches = list(re.finditer(pattern, content, re.IGNORECASE))
                    for match in matches:
                        line = content[:match.start()].count('\n') + 1
                        issues.append(ScannerIssue(
                            rule_id="PL010",
                            severity=severity,
                            message=message,
                            file_path=file_path,
                            line=line,
                            column=1,
                            suggestion="Add output filtering/sanitization before returning LLM responses",
                        ))

            # Scan with YAML rules
            lines = content.split('\n')
            issues.extend(self._scan_with_rules(lines, file_path))

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
                error_message=str(e),
            )

    def _get_context(self, content: str, pos: int, context_lines: int = 2) -> str:
        """Get code context around a match"""
        lines = content.split('\n')
        line_num = content[:pos].count('\n')
        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)
        return '\n'.join(lines[start:end])

    def _get_suggestion(self, rule_id: str) -> str:
        """Get remediation suggestion for rule"""
        suggestions = {
            "PL001": "Never include system prompts in user-visible responses. Use output filtering.",
            "PL002": "Tool definitions should only be sent to the LLM, not included in user responses.",
            "PL003": "Internal instructions must be stripped from any user-facing output.",
            "PL004": "Ensure debug mode doesn't expose prompts. Use separate debug logging.",
            "PL005": "Use structured logging that masks/redacts prompt content.",
            "PL006": "Sanitize error messages to remove any prompt or instruction content.",
            "PL007": "Add output filtering layer between LLM response and user output.",
            "PL008": "Tool schemas are internal - filter them from responses.",
            "PL009": "Configuration should not appear in user responses.",
            "PL010": "Implement output sanitization to filter LLM responses before returning.",
        }
        return suggestions.get(rule_id, "Review code for potential prompt leakage.")
