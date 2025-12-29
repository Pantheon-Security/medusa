#!/usr/bin/env python3
"""
MEDUSA Agent Reflection Security Scanner
Detects security issues in reflection/self-correction patterns

Based on "Agentic Design Patterns" Chapter 4 - Reflection

Detects:
- Unbounded reflection loops (resource exhaustion)
- Missing iteration limits
- Context window overflow risks
- Self-critique without validation
- Producer-Critic separation issues
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class AgentReflectionScanner(BaseScanner):
    """
    Agent Reflection Security Scanner

    Scans for:
    - RF001: Reflection loop without iteration limit
    - RF002: Self-critique without external validation
    - RF003: Context accumulation without truncation
    - RF004: Missing stopping condition in refinement
    - RF005: Producer-Critic in same context (cognitive bias)
    - RF006: Reflection without cost/latency controls
    - RF007: Unbounded retry in self-correction
    - RF008: Missing error handling in reflection loop
    - RF009: Reflection output not sanitized
    - RF010: Self-modification without guardrails
    """

    # Patterns indicating reflection/self-correction loops
    REFLECTION_PATTERNS = [
        r'self[_-]?correct',
        r'self[_-]?refine',
        r'self[_-]?improve',
        r'reflect(ion)?[_-]?(loop|cycle)?',
        r'refine[_-]?(output|response|result)',
        r'critique[_-]?(self|own|output)',
        r'review[_-]?(self|own|output)',
        r'iterative[_-]?refine',
        r'feedback[_-]?loop',
        r'producer[_-]?critic',
        r'critic[_-]?agent',
        r'evaluator[_-]?agent',
    ]

    # Patterns indicating iteration/loop control
    ITERATION_CONTROL_PATTERNS = [
        r'max[_-]?(iter|iteration|retry|attempt|loop)',
        r'maxIter',
        r'MAX_ITER',
        r'iteration[_-]?limit',
        r'retry[_-]?limit',
        r'attempt[_-]?limit',
        r'loop[_-]?(count|limit|max)',
        r'for\s+\w+\s+in\s+range\s*\(\s*\d+',  # Python for i in range(N)
        r'for\s*\(\s*\w+\s*=\s*\d+\s*;\s*\w+\s*<\s*\d+',  # JS/TS for loop
        r'\.slice\s*\(\s*0\s*,\s*\d+\s*\)',  # Context truncation
    ]

    # Patterns indicating cost/resource controls
    RESOURCE_CONTROL_PATTERNS = [
        r'max[_-]?tokens',
        r'token[_-]?limit',
        r'cost[_-]?(limit|budget|max)',
        r'timeout',
        r'deadline',
        r'time[_-]?limit',
        r'budget[_-]?(check|limit|remaining)',
        r'rate[_-]?limit',
    ]

    # Patterns indicating stopping conditions
    STOPPING_CONDITION_PATTERNS = [
        r'(if|while).*satisf(y|ied|actory)',
        r'(if|while).*good[_-]?enough',
        r'(if|while).*converge',
        r'(if|while).*threshold',
        r'(if|while).*quality[_-]?score',
        r'break\s*(if|when)',
        r'return\s+.*final',
        r'is[_-]?complete',
        r'should[_-]?stop',
        r'early[_-]?exit',
    ]

    # Patterns indicating sanitization
    SANITIZATION_PATTERNS = [
        r'sanitize',
        r'validate[_-]?(output|result|response)',
        r'filter[_-]?(output|result|response)',
        r'clean[_-]?(output|result|response)',
        r'check[_-]?(output|result|response)',
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
        """Scan for reflection pattern security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            content_lower = content.lower()

            # Check if file contains reflection patterns
            has_reflection = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.REFLECTION_PATTERNS
            )

            if not has_reflection:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for iteration limits
            has_iteration_limit = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.ITERATION_CONTROL_PATTERNS
            )

            # Check for resource controls
            has_resource_control = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.RESOURCE_CONTROL_PATTERNS
            )

            # Check for stopping conditions
            has_stopping_condition = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.STOPPING_CONDITION_PATTERNS
            )

            # Check for output sanitization
            has_sanitization = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.SANITIZATION_PATTERNS
            )

            # RF001: Missing iteration limit
            if not has_iteration_limit:
                for pattern in self.REFLECTION_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        line = content[:match.start()].count('\n') + 1
                        issues.append(ScannerIssue(
                            rule_id="RF001",
                            severity=Severity.HIGH,
                            message="Reflection loop without iteration limit (resource exhaustion risk)",
                            file_path=file_path,
                            line=line,
                            column=1,
                            suggestion="Add max_iterations or retry_limit to prevent infinite loops",
                        ))
                        break

            # RF004: Missing stopping condition
            if not has_stopping_condition:
                issues.append(ScannerIssue(
                    rule_id="RF004",
                    severity=Severity.MEDIUM,
                    message="Reflection pattern without clear stopping condition",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Add quality threshold or convergence check to stop refinement",
                ))

            # RF006: Missing resource controls
            if not has_resource_control:
                issues.append(ScannerIssue(
                    rule_id="RF006",
                    severity=Severity.MEDIUM,
                    message="Reflection without cost/latency controls",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Add token limits, timeout, or cost budget for reflection loops",
                ))

            # RF009: Missing output sanitization
            if not has_sanitization:
                issues.append(ScannerIssue(
                    rule_id="RF009",
                    severity=Severity.MEDIUM,
                    message="Reflection output not validated/sanitized",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Validate and sanitize refined output before returning",
                ))

            # Check for specific anti-patterns
            issues.extend(self._check_cognitive_bias(content, file_path))
            issues.extend(self._check_context_accumulation(content, file_path))
            issues.extend(self._check_error_handling(content, file_path))
            issues.extend(self._check_self_modification(content, file_path))

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

    def _check_cognitive_bias(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for Producer-Critic in same context (cognitive bias)"""
        issues = []

        # Pattern: Same function/class doing both produce and critique
        patterns = [
            (r'def\s+\w*(produce|generate)\w*.*\n(?:.*\n)*?.*\w*(critique|review|evaluate)',
             'Producer and Critic in same function'),
            (r'(generate|create).*\n.*\n.*\n.*(critique|review|validate).*same',
             'Self-critique without separation'),
        ]

        for pattern, message in patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="RF005",
                    severity=Severity.MEDIUM,
                    message=message,
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Separate Producer and Critic into distinct agents/contexts",
                ))

        return issues

    def _check_context_accumulation(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for context window overflow risks"""
        issues = []

        # Patterns indicating context accumulation without management
        accumulation_patterns = [
            (r'messages\.(append|push)\s*\(', 'Messages accumulated without truncation'),
            (r'history\.(append|push|extend)', 'History accumulated without limit'),
            (r'context\s*\+=', 'Context concatenated without size check'),
            (r'conversation\.(append|push)', 'Conversation grows unbounded'),
        ]

        # Check if there's truncation nearby
        has_truncation = any(
            re.search(p, content, re.IGNORECASE)
            for p in [r'truncate', r'slice', r'limit', r'max.*length', r'pop\s*\(']
        )

        if not has_truncation:
            for pattern, message in accumulation_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="RF003",
                        severity=Severity.MEDIUM,
                        message=f"{message} (context window overflow risk)",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Add context truncation or sliding window",
                    ))

        return issues

    def _check_error_handling(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for error handling in reflection loops"""
        issues = []

        # Check for reflection with while/for but no try/except
        loop_patterns = [
            r'while.*refine',
            r'for.*iteration.*refine',
            r'while.*reflect',
            r'for.*attempt.*critique',
        ]

        has_loop = any(re.search(p, content, re.IGNORECASE) for p in loop_patterns)
        has_error_handling = re.search(r'try\s*:|catch\s*\(', content, re.IGNORECASE)

        if has_loop and not has_error_handling:
            issues.append(ScannerIssue(
                rule_id="RF008",
                severity=Severity.MEDIUM,
                message="Reflection loop without error handling",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Add try/catch to handle LLM failures in reflection loop",
            ))

        return issues

    def _check_self_modification(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for self-modification without guardrails"""
        issues = []

        # Dangerous self-modification patterns
        modification_patterns = [
            (r'self\.(prompt|instruction|system)\s*=', 'Agent modifying own prompt'),
            (r'(update|modify|change).*system.*prompt', 'System prompt modification'),
            (r'exec\s*\(.*self', 'Self-executing generated code'),
            (r'eval\s*\(.*refine', 'Evaluating refined code'),
        ]

        for pattern, message in modification_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="RF010",
                    severity=Severity.CRITICAL,
                    message=f"{message} without guardrails",
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Add guardrails to prevent unsafe self-modification",
                ))

        return issues
