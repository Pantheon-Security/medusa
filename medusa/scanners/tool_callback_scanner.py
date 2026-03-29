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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number, filter_contextual_fps


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
    RULE_ID_PREFIXES = ['TOOL-CB-', 'TOOL-', 'MEDUSA-TUA-']

    # Categories to load from YAML
    RULE_CATEGORIES = [
        'tool_callback', 'tool_security', 'tool_use_attacks',
        # Orphaned rule directories wired here
        'sandbox_execution_boundaries',
    ]

    # Patterns indicating tool execution
    TOOL_EXECUTION_PATTERNS = [
        # Python patterns
        re.compile(r'def\s+\w*tool\w*\s*\(', re.IGNORECASE),
        re.compile(r'@tool\s*(\(|$)', re.IGNORECASE),
        re.compile(r'execute_tool\s*\(', re.IGNORECASE),
        re.compile(r'run_tool\s*\(', re.IGNORECASE),
        re.compile(r'call_tool\s*\(', re.IGNORECASE),
        re.compile(r'tool\.(run|execute|call)', re.IGNORECASE),
        re.compile(r'tools\[.*\]\s*\(', re.IGNORECASE),
        re.compile(r'invoke_tool\s*\(', re.IGNORECASE),

        # TypeScript/JavaScript patterns
        re.compile(r'async\s+\w*[Tt]ool\w*\s*\(', re.IGNORECASE),
        re.compile(r'handleTool\s*\(', re.IGNORECASE),
        re.compile(r'executeTool\s*\(', re.IGNORECASE),
        re.compile(r'runTool\s*\(', re.IGNORECASE),
        re.compile(r'tool\.execute\s*\(', re.IGNORECASE),
        re.compile(r'toolHandler\s*\(', re.IGNORECASE),
        re.compile(r'server\.setRequestHandler.*Tool', re.IGNORECASE),
        re.compile(r'CallToolRequestSchema', re.IGNORECASE),
    ]

    # Patterns indicating proper validation (good patterns)
    VALIDATION_PATTERNS = [
        re.compile(r'before_tool', re.IGNORECASE),
        re.compile(r'beforeTool', re.IGNORECASE),
        re.compile(r'pre_execute', re.IGNORECASE),
        re.compile(r'preExecute', re.IGNORECASE),
        re.compile(r'validate.*arg', re.IGNORECASE),
        re.compile(r'validateArg', re.IGNORECASE),
        re.compile(r'check.*permission', re.IGNORECASE),
        re.compile(r'checkPermission', re.IGNORECASE),
        re.compile(r'has_permission', re.IGNORECASE),
        re.compile(r'hasPermission', re.IGNORECASE),
        re.compile(r'authorize', re.IGNORECASE),
        re.compile(r'isAuthorized', re.IGNORECASE),
        re.compile(r'canExecute', re.IGNORECASE),
        re.compile(r'allowedTools', re.IGNORECASE),
        re.compile(r'permittedTools', re.IGNORECASE),
    ]

    # Patterns for after-execution validation
    AFTER_VALIDATION_PATTERNS = [
        re.compile(r'after_tool', re.IGNORECASE),
        re.compile(r'afterTool', re.IGNORECASE),
        re.compile(r'post_execute', re.IGNORECASE),
        re.compile(r'postExecute', re.IGNORECASE),
        re.compile(r'validate.*result', re.IGNORECASE),
        re.compile(r'validateResult', re.IGNORECASE),
        re.compile(r'sanitize.*output', re.IGNORECASE),
        re.compile(r'sanitizeOutput', re.IGNORECASE),
        re.compile(r'filter.*response', re.IGNORECASE),
        re.compile(r'filterResponse', re.IGNORECASE),
    ]

    # Patterns indicating destructive operations
    DESTRUCTIVE_PATTERNS = [
        (re.compile(r'delete|remove|drop|truncate|destroy', re.IGNORECASE), 'Destructive operation'),
        (re.compile(r'rm\s+-rf|rmdir|unlink', re.IGNORECASE), 'File deletion'),
        (re.compile(r'exec|eval|spawn|system', re.IGNORECASE), 'Code execution'),
        (re.compile(r'write.{0,30}file|writeFile|fs\.write', re.IGNORECASE), 'File write'),
        (re.compile(r'update|modify|alter', re.IGNORECASE), 'Data modification'),
        (re.compile(r'send.{0,20}email|sendEmail|smtp', re.IGNORECASE), 'Email sending'),
        (re.compile(r'(post|put|patch).{0,30}http|fetch.{0,30}method.{0,10}POST', re.IGNORECASE), 'External API call'),
        (re.compile(r'subprocess|child_process|exec', re.IGNORECASE), 'Process execution'),
    ]

    # Audit logging patterns
    AUDIT_PATTERNS = [
        re.compile(r'audit', re.IGNORECASE),
        re.compile(r'log.*tool', re.IGNORECASE),
        re.compile(r'logTool', re.IGNORECASE),
        re.compile(r'track.*execution', re.IGNORECASE),
        re.compile(r'record.*action', re.IGNORECASE),
        re.compile(r'emit.*event.*tool', re.IGNORECASE),
    ]

    # Rate limiting patterns
    RATE_LIMIT_PATTERNS = [
        re.compile(r'rate.*limit', re.IGNORECASE),
        re.compile(r'rateLimit', re.IGNORECASE),
        re.compile(r'throttle', re.IGNORECASE),
        re.compile(r'cooldown', re.IGNORECASE),
        re.compile(r'quota', re.IGNORECASE),
        re.compile(r'maxRequests', re.IGNORECASE),
        re.compile(r'requestLimit', re.IGNORECASE),
    ]

    # Indicators that a file is related to AI agent tool execution.
    # Without these, the scanner produces massive false positives on
    # standard web apps (every CRUD operation matches destructive patterns).
    AGENT_TOOL_INDICATORS = [
        # MCP / Agent framework imports
        'mcp', 'langchain', 'llama_index', 'llamaindex',
        'autogen', 'crewai', 'semantic_kernel',
        'tool_registry', 'tool_handler', 'tool_executor',
        # MCP-specific patterns
        'CallToolRequestSchema', 'ListToolsRequestSchema',
        'setRequestHandler', 'MCPServer', 'mcp_server',
        # Agent tool decorators and methods
        '@tool', 'execute_tool', 'run_tool', 'call_tool',
        'invoke_tool', 'tool.execute', 'tool.run',
        'AgentExecutor', 'agent_executor',
        # Tool callback patterns (the actual target of this scanner)
        'before_tool', 'after_tool', 'tool_callback',
        'beforeTool', 'afterTool', 'toolCallback',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]

    def can_scan(self, file_path: Path) -> bool:
        """Only scan files that contain AI agent tool execution indicators.

        Without this gate, every Python/JS file gets scanned and patterns
        like 'delete|remove' and 'exec|eval' match standard CRUD code.
        """
        if file_path.suffix not in self.get_file_extensions():
            return False

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(8192)  # First 8KB
            head_lower = head.lower()
            return any(ind.lower() in head_lower for ind in self.AGENT_TOOL_INDICATORS)
        except OSError:
            return False

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

            _offsets = _build_line_offsets(content)

            content_lower = content.lower()

            # Check if file contains tool execution patterns
            has_tool_execution = any(
                pattern.search(content)
                for pattern in self.TOOL_EXECUTION_PATTERNS
            )

            if not has_tool_execution:
                # No tool execution patterns found - skip entirely.
                # The can_scan() gate already confirmed this file has agent
                # indicators, but without actual tool execution, there's
                # nothing actionable to report.
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for validation patterns
            has_before_validation = any(
                pattern.search(content)
                for pattern in self.VALIDATION_PATTERNS
            )

            has_after_validation = any(
                pattern.search(content)
                for pattern in self.AFTER_VALIDATION_PATTERNS
            )

            has_audit = any(
                pattern.search(content)
                for pattern in self.AUDIT_PATTERNS
            )

            has_rate_limit = any(
                pattern.search(content)
                for pattern in self.RATE_LIMIT_PATTERNS
            )

            # TC001: Missing before_tool_callback
            if not has_before_validation:
                # Find tool execution locations
                for pattern in self.TOOL_EXECUTION_PATTERNS:
                    matches = pattern.finditer(content)
                    for match in matches:
                        line = _get_line_number(_offsets, match.start())
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
            issues.extend(self._check_destructive_operations(content, file_path, has_before_validation, _offsets))

            # Check for hardcoded permissions
            issues.extend(self._check_hardcoded_permissions(content, file_path, _offsets))

            # Check for session context usage
            issues.extend(self._check_session_context(content, file_path))

            # Check error handling
            issues.extend(self._check_error_handling(content, file_path))

            # NOTE: We deliberately do NOT call _scan_with_rules() here.
            # The YAML rules (TOOL-CB-*) duplicate our hardcoded patterns
            # but lack the context awareness of _check_destructive_operations()
            # which checks for nearby validation/confirmation. Running both
            # would double-count findings and add noise.

            # Context-aware FP filtering for defensive security / compliance / auth files
            issues = filter_contextual_fps(issues, file_path, content)

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
        self, content: str, file_path: Path, has_validation: bool, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """Check destructive operations have proper guards"""
        issues = []

        for pattern, description in self.DESTRUCTIVE_PATTERNS:
            matches = list(pattern.finditer(content))
            for match in matches:
                line = _get_line_number(_offsets, match.start())

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
                        code="Add confirmation or validation before destructive operations",
                    ))

        return issues

    def _check_hardcoded_permissions(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """Check for hardcoded permission values"""
        issues = []

        # Patterns indicating hardcoded permissions
        hardcoded_patterns = [
            (re.compile(r'allowed_tools\s*=\s*\[', re.IGNORECASE), 'Hardcoded allowed tools list'),
            (re.compile(r'permissions\s*=\s*\[', re.IGNORECASE), 'Hardcoded permissions list'),
            (re.compile(r'can_execute\s*=\s*True', re.IGNORECASE), 'Hardcoded execution permission'),
            (re.compile(r'isAdmin\s*=\s*true', re.IGNORECASE), 'Hardcoded admin flag'),
            (re.compile(r'role\s*[=:]\s*["\']admin["\']', re.IGNORECASE), 'Hardcoded admin role'),
        ]

        for pattern, description in hardcoded_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                line = _get_line_number(_offsets, match.start())
                issues.append(ScannerIssue(
                    rule_id="TC008",
                    severity=Severity.MEDIUM,
                    message=description,
                    line=line,
                    column=1,
                    code="Use dynamic permission checks based on session context",
                ))

        return issues

    def _check_session_context(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for session context usage in tool execution"""
        issues = []

        # Check if file has tool execution but no session context
        has_tool_exec = any(
            pattern.search(content)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        session_patterns = [
            re.compile(r'session', re.IGNORECASE),
            re.compile(r'context', re.IGNORECASE),
            re.compile(r'user_id', re.IGNORECASE),
            re.compile(r'userId', re.IGNORECASE),
            re.compile(r'request\.user', re.IGNORECASE),
            re.compile(r'ctx\.', re.IGNORECASE),
            re.compile(r'state\.', re.IGNORECASE),
        ]

        has_session = any(
            pattern.search(content)
            for pattern in session_patterns
        )

        if has_tool_exec and not has_session:
            issues.append(ScannerIssue(
                rule_id="TC010",
                severity=Severity.MEDIUM,
                message="Tool execution without session/context tracking",
                line=1,
                column=1,
                code="Include session context for user/permission tracking",
            ))

        return issues

    def _check_error_handling(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for proper error handling in tool callbacks"""
        issues = []

        # Check for tool execution in try blocks
        try_patterns = [
            re.compile(r'try\s*:.{0,200}tool', re.IGNORECASE | re.DOTALL),
            re.compile(r'try\s*\{.{0,200}tool', re.IGNORECASE | re.DOTALL),
        ]

        catch_patterns = [
            re.compile(r'except.*:', re.IGNORECASE),
            re.compile(r'catch\s*\(', re.IGNORECASE),
        ]

        has_try = any(p.search(content) for p in try_patterns)
        has_catch = any(p.search(content) for p in catch_patterns)

        # Check if there's tool execution without error handling
        has_tool_exec = any(
            pattern.search(content)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        if has_tool_exec and not (has_try or has_catch):
            issues.append(ScannerIssue(
                rule_id="TC009",
                severity=Severity.LOW,
                message="Tool execution without explicit error handling",
                line=1,
                column=1,
                code="Add try/catch or error handling for tool execution failures",
            ))

        return issues
