#!/usr/bin/env python3
"""
MEDUSA Tool Callback Security Scanner
Audits agent code for proper before_tool_callback implementation

Based on "Agentic Design Patterns" Chapter 18 - Guardrails/Safety Patterns

Detects:
- Missing pre-execution validation (before_tool_callback)
- Missing post-execution validation
- Insufficient permission checks
- Missing argument validation
- Unprotected destructive operations
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple, Set

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class ToolCallbackScanner(RuleBasedScanner):
    """
    Tool Callback Security Audit Scanner

    Scans for:
    - TC001: Missing before_tool_callback pattern
    - TC002: Tool execution without permission check
    - TC003: Missing argument validation before tool use
    - TC004: Destructive operation without confirmation
    - TC005: Missing after_tool_callback (output validation)
    - TC006: Tool call without rate limiting
    - TC007: Missing audit logging for tool execution
    - TC008: Hardcoded permissions (no dynamic check)
    - TC009: Missing error handling in tool callback
    - TC010: Tool execution without session context
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['TOOL-CB-', 'TOOL-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['tool_callback', 'tool_security']

    # Patterns indicating tool execution
    TOOL_EXECUTION_PATTERNS = [
        # Python patterns
        r'def\s+\w*tool\w*\s*\(',
        r'@tool\s*(\(|$)',
        r'execute_tool\s*\(',
        r'run_tool\s*\(',
        r'call_tool\s*\(',
        r'tool\.(run|execute|call)',
        r'tools\[.*\]\s*\(',
        r'invoke_tool\s*\(',

        # TypeScript/JavaScript patterns
        r'async\s+\w*[Tt]ool\w*\s*\(',
        r'handleTool\s*\(',
        r'executeTool\s*\(',
        r'runTool\s*\(',
        r'tool\.execute\s*\(',
        r'toolHandler\s*\(',
        r'server\.setRequestHandler.*Tool',
        r'CallToolRequestSchema',
    ]

    # Patterns indicating proper validation (good patterns)
    VALIDATION_PATTERNS = [
        r'before_tool',
        r'beforeTool',
        r'pre_execute',
        r'preExecute',
        r'validate.*arg',
        r'validateArg',
        r'check.*permission',
        r'checkPermission',
        r'has_permission',
        r'hasPermission',
        r'authorize',
        r'isAuthorized',
        r'canExecute',
        r'allowedTools',
        r'permittedTools',
    ]

    # Patterns for after-execution validation
    AFTER_VALIDATION_PATTERNS = [
        r'after_tool',
        r'afterTool',
        r'post_execute',
        r'postExecute',
        r'validate.*result',
        r'validateResult',
        r'sanitize.*output',
        r'sanitizeOutput',
        r'filter.*response',
        r'filterResponse',
    ]

    # Patterns indicating destructive operations
    DESTRUCTIVE_PATTERNS = [
        (r'delete|remove|drop|truncate|destroy', 'Destructive operation'),
        (r'rm\s+-rf|rmdir|unlink', 'File deletion'),
        (r'exec|eval|spawn|system', 'Code execution'),
        (r'write.{0,30}file|writeFile|fs\.write', 'File write'),
        (r'update|modify|alter', 'Data modification'),
        (r'send.{0,20}email|sendEmail|smtp', 'Email sending'),
        (r'(post|put|patch).{0,30}http|fetch.{0,30}method.{0,10}POST', 'External API call'),
        (r'subprocess|child_process|exec', 'Process execution'),
    ]

    # Audit logging patterns
    AUDIT_PATTERNS = [
        r'audit',
        r'log.*tool',
        r'logTool',
        r'track.*execution',
        r'record.*action',
        r'emit.*event.*tool',
    ]

    # Rate limiting patterns
    RATE_LIMIT_PATTERNS = [
        r'rate.*limit',
        r'rateLimit',
        r'throttle',
        r'cooldown',
        r'quota',
        r'maxRequests',
        r'requestLimit',
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
        """Scan for tool callback security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            content_lower = content.lower()

            # Check if file contains tool execution patterns
            has_tool_execution = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.TOOL_EXECUTION_PATTERNS
            )

            if not has_tool_execution:
                # Still scan with YAML rules even if no tool execution patterns
                lines = content.split('\n')
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=yaml_issues,
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for validation patterns
            has_before_validation = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.VALIDATION_PATTERNS
            )

            has_after_validation = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.AFTER_VALIDATION_PATTERNS
            )

            has_audit = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.AUDIT_PATTERNS
            )

            has_rate_limit = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.RATE_LIMIT_PATTERNS
            )

            # TC001: Missing before_tool_callback
            if not has_before_validation:
                # Find tool execution locations
                for pattern in self.TOOL_EXECUTION_PATTERNS:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line = content[:match.start()].count('\n') + 1
                        issues.append(ScannerIssue(
                            rule_id="TC001",
                            severity=Severity.HIGH,
                            message="Tool execution without before_tool_callback validation",
                            line=line,
                            column=1,
                        ))
                        break  # One issue per pattern is enough

            # TC005: Missing after_tool_callback
            if not has_after_validation and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC005",
                    severity=Severity.MEDIUM,
                    message="No after_tool_callback for output validation detected",
                    line=1,
                    column=1,
                ))

            # TC007: Missing audit logging
            if not has_audit and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC007",
                    severity=Severity.MEDIUM,
                    message="Tool execution without audit logging",
                    line=1,
                    column=1,
                ))

            # TC006: Missing rate limiting
            if not has_rate_limit and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC006",
                    severity=Severity.LOW,
                    message="No rate limiting detected for tool execution",
                    line=1,
                    column=1,
                ))

            # Check destructive operations
            issues.extend(self._check_destructive_operations(content, file_path, has_before_validation))

            # Check for hardcoded permissions
            issues.extend(self._check_hardcoded_permissions(content, file_path))

            # Check for session context usage
            issues.extend(self._check_session_context(content, file_path))

            # Check error handling
            issues.extend(self._check_error_handling(content, file_path))

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

    def _check_destructive_operations(
        self, content: str, file_path: Path, has_validation: bool
    ) -> List[ScannerIssue]:
        """Check destructive operations have proper guards"""
        issues = []

        for pattern, description in self.DESTRUCTIVE_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for match in matches:
                line = content[:match.start()].count('\n') + 1

                # Check if there's a confirmation/validation nearby
                context_start = max(0, match.start() - 500)
                context_end = min(len(content), match.end() + 100)
                context = content[context_start:context_end].lower()

                has_confirm = any(word in context for word in [
                    'confirm', 'verify', 'approve', 'authorized',
                    'permission', 'allowed', 'check', 'validate'
                ])

                if not has_confirm and not has_validation:
                    issues.append(ScannerIssue(
                        rule_id="TC004",
                        severity=Severity.HIGH,
                        message=f"{description} without validation/confirmation",
                        line=line,
                        column=1,
                        suggestion="Add confirmation or validation before destructive operations",
                    ))

        return issues

    def _check_hardcoded_permissions(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for hardcoded permission values"""
        issues = []

        # Patterns indicating hardcoded permissions
        hardcoded_patterns = [
            (r'allowed_tools\s*=\s*\[', 'Hardcoded allowed tools list'),
            (r'permissions\s*=\s*\[', 'Hardcoded permissions list'),
            (r'can_execute\s*=\s*True', 'Hardcoded execution permission'),
            (r'isAdmin\s*=\s*true', 'Hardcoded admin flag'),
            (r'role\s*[=:]\s*["\']admin["\']', 'Hardcoded admin role'),
        ]

        for pattern, description in hardcoded_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="TC008",
                    severity=Severity.MEDIUM,
                    message=description,
                    line=line,
                    column=1,
                    suggestion="Use dynamic permission checks based on session context",
                ))

        return issues

    def _check_session_context(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for session context usage in tool execution"""
        issues = []

        # Check if file has tool execution but no session context
        has_tool_exec = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        session_patterns = [
            r'session',
            r'context',
            r'user_id',
            r'userId',
            r'request\.user',
            r'ctx\.',
            r'state\.',
        ]

        has_session = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in session_patterns
        )

        if has_tool_exec and not has_session:
            issues.append(ScannerIssue(
                rule_id="TC010",
                severity=Severity.MEDIUM,
                message="Tool execution without session/context tracking",
                line=1,
                column=1,
                suggestion="Include session context for user/permission tracking",
            ))

        return issues

    def _check_error_handling(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for proper error handling in tool callbacks"""
        issues = []

        # Check for tool execution in try blocks
        try_patterns = [
            r'try\s*:.{0,200}tool',
            r'try\s*\{.{0,200}tool',
        ]

        catch_patterns = [
            r'except.*:',
            r'catch\s*\(',
        ]

        has_try = any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in try_patterns)
        has_catch = any(re.search(p, content, re.IGNORECASE) for p in catch_patterns)

        # Check if there's tool execution without error handling
        has_tool_exec = any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        if has_tool_exec and not (has_try or has_catch):
            issues.append(ScannerIssue(
                rule_id="TC009",
                severity=Severity.LOW,
                message="Tool execution without explicit error handling",
                line=1,
                column=1,
                suggestion="Add try/catch or error handling for tool execution failures",
            ))

        return issues
