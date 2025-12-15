#!/usr/bin/env python3
"""
MEDUSA Excessive Agency Scanner
Detects over-permissioned AI agents and missing safety controls

Based on:
- OWASP Top 10 for LLM Applications - Excessive Agency
- "Agentic Design Patterns" - Guardrails/Safety Patterns
- "Generative AI Security" - Agent Security

Detects:
- Agents with excessive permissions
- Missing before_tool_callback validation
- Unbounded action loops
- Missing human-in-the-loop controls
- Over-permissioned tool access
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class ExcessiveAgencyScanner(BaseScanner):
    """
    Excessive Agency Detection Scanner

    Scans for:
    - EXA001: Agent with unrestricted tool access
    - EXA002: Missing before_tool_callback validation
    - EXA003: Unbounded action loops (no max iterations)
    - EXA004: Missing human approval for critical actions
    - EXA005: Agent with write/delete permissions
    - EXA006: Agent with network/external access
    - EXA007: Missing action logging/audit
    - EXA008: Auto-execution without confirmation
    - EXA009: Recursive agent calls without depth limit
    - EXA010: Agent with credential/secret access
    """

    # EXA001: Unrestricted tool access
    UNRESTRICTED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'tools\s*[=:]\s*(?:all|"\*"|\'?\*\'?|\[.*\*.*\])',
         'Agent with unrestricted tool access', Severity.HIGH),
        (r'allow_all_tools|all_tools_enabled',
         'All tools enabled for agent', Severity.HIGH),
        (r'tool_permissions\s*[=:]\s*(?:None|null|unrestricted)',
         'No tool permission restrictions', Severity.HIGH),
        (r'(?:disable|skip).*tool.*(?:filter|restriction)',
         'Tool restrictions disabled', Severity.HIGH),
    ]

    # EXA002: Missing before_tool_callback
    CALLBACK_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:Agent|Runner)\s*\([^)]*\)(?!.*before_tool_callback)',
         'Agent without before_tool_callback validation', Severity.MEDIUM),
        (r'tool_executor(?!.*(?:validate|callback|check))',
         'Tool executor without validation hook', Severity.MEDIUM),
        (r'execute_tool\s*\([^)]*\)(?!.*(?:valid|check|verify))',
         'Tool execution without validation', Severity.MEDIUM),
        (r'before_tool_callback\s*[=:]\s*(?:None|null)',
         'before_tool_callback explicitly disabled', Severity.HIGH),
    ]

    # EXA003: Unbounded loops
    UNBOUNDED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'while\s+True.*(?:agent|action|tool)',
         'Unbounded while loop with agent/tool', Severity.HIGH),
        (r'max_iterations\s*[=:]\s*(?:None|null|0|-1|inf)',
         'No maximum iteration limit', Severity.HIGH),
        (r'(?:agent|loop).*(?:forever|infinite|unlimited)',
         'Infinite agent loop', Severity.HIGH),
        (r'for\s+_\s+in\s+(?:iter|count)\s*\(\)',
         'Unbounded iteration', Severity.MEDIUM),
        (r'recursion_limit\s*[=:]\s*(?:None|null|0|-1)',
         'No recursion limit', Severity.HIGH),
    ]

    # EXA004: Missing human approval
    HUMAN_APPROVAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:auto|automatic).*(?:execute|run|action)(?!.*(?:confirm|approve|human))',
         'Auto-execution without human approval', Severity.MEDIUM),
        (r'(?:skip|bypass).*(?:confirm|approval|human)',
         'Human approval bypassed', Severity.HIGH),
        (r'require_confirmation\s*[=:]\s*(?:False|false)',
         'Confirmation requirement disabled', Severity.HIGH),
        (r'human_in_the_loop\s*[=:]\s*(?:False|false)',
         'Human-in-the-loop disabled', Severity.HIGH),
        (r'auto_approve\s*[=:]\s*(?:True|true)',
         'Auto-approval enabled', Severity.HIGH),
    ]

    # EXA005: Write/delete permissions
    WRITE_DELETE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:agent|tool).*(?:write|delete|remove|modify).*(?:file|disk|storage)',
         'Agent with filesystem write/delete access', Severity.HIGH),
        (r'allow_(?:write|delete|modify)\s*[=:]\s*(?:True|true)',
         'Write/delete permissions enabled', Severity.HIGH),
        (r'(?:os\.remove|os\.unlink|shutil\.rmtree).*(?:agent|tool)',
         'File deletion in agent context', Severity.CRITICAL),
        (r'(?:truncate|overwrite).*(?:agent|tool)',
         'Destructive file operation', Severity.HIGH),
    ]

    # EXA006: Network/external access
    NETWORK_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:agent|tool).*(?:http|request|fetch|api)',
         'Agent with network access', Severity.MEDIUM),
        (r'allow_(?:network|external|internet)',
         'External network access enabled', Severity.MEDIUM),
        (r'(?:socket|websocket).*(?:agent|tool)',
         'Socket access in agent', Severity.HIGH),
        (r'(?:agent|tool).*(?:download|upload)',
         'Agent with download/upload capability', Severity.MEDIUM),
    ]

    # EXA007: Missing logging/audit
    AUDIT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:agent|tool).*(?:execute|action)(?!.*(?:log|audit|record))',
         'Agent action without logging', Severity.LOW),
        (r'(?:disable|skip).*(?:log|audit)',
         'Logging/audit disabled', Severity.MEDIUM),
        (r'audit\s*[=:]\s*(?:False|false|None)',
         'Audit explicitly disabled', Severity.MEDIUM),
    ]

    # EXA008: Auto-execution
    AUTO_EXEC_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'auto_execute\s*[=:]\s*(?:True|true)',
         'Auto-execution enabled without confirmation', Severity.HIGH),
        (r'execute_immediately|run_without_confirm',
         'Immediate execution pattern', Severity.HIGH),
        (r'(?:agent|action).*(?:auto|immediate).*(?:run|execute)',
         'Automatic agent execution', Severity.MEDIUM),
    ]

    # EXA009: Recursive agent calls
    RECURSIVE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'agent.*(?:call|invoke).*agent(?!.*(?:depth|limit|max))',
         'Recursive agent calls without depth limit', Severity.HIGH),
        (r'(?:spawn|create)_agent.*(?:within|inside).*agent',
         'Nested agent spawning', Severity.MEDIUM),
        (r'sub_agent|child_agent|nested_agent',
         'Sub-agent pattern (verify depth limits)', Severity.LOW),
        (r'max_depth\s*[=:]\s*(?:None|null|0|-1)',
         'No maximum depth for agent recursion', Severity.HIGH),
    ]

    # EXA010: Credential/secret access
    CREDENTIAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:agent|tool).*(?:credential|password|secret|api_key)',
         'Agent with credential access', Severity.CRITICAL),
        (r'(?:read|get|access).*(?:env|environment).*(?:agent|tool)',
         'Agent accessing environment variables', Severity.HIGH),
        (r'(?:agent|tool).*(?:vault|keyring|secrets_manager)',
         'Agent with secrets manager access', Severity.CRITICAL),
        (r'pass.*(?:credential|secret|key).*(?:to|agent)',
         'Credentials passed to agent', Severity.HIGH),
    ]

    # Good patterns (safety measures)
    SAFETY_PATTERNS = [
        r'before_tool_callback',
        r'human_in_the_loop\s*[=:]\s*True',
        r'require_confirmation\s*[=:]\s*True',
        r'max_iterations\s*[=:]\s*\d+',
        r'action_whitelist|allowed_actions',
        r'permission_check|validate_permission',
        r'audit_log|log_action',
        r'rate_limit|throttle',
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
        """Scan for excessive agency vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file is agent-related
            agent_indicators = [
                'agent', 'langchain', 'llama_index', 'autogen', 'crewai',
                'tool', 'action', 'execute', 'openai', 'anthropic',
                'assistant', 'function_call', 'capability',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in agent_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            has_safety = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.SAFETY_PATTERNS
            )

            lines = content.split('\n')

            all_patterns = [
                (self.UNRESTRICTED_PATTERNS, "EXA001"),
                (self.CALLBACK_PATTERNS, "EXA002"),
                (self.UNBOUNDED_PATTERNS, "EXA003"),
                (self.HUMAN_APPROVAL_PATTERNS, "EXA004"),
                (self.WRITE_DELETE_PATTERNS, "EXA005"),
                (self.NETWORK_PATTERNS, "EXA006"),
                (self.AUDIT_PATTERNS, "EXA007"),
                (self.AUTO_EXEC_PATTERNS, "EXA008"),
                (self.RECURSIVE_PATTERNS, "EXA009"),
                (self.CREDENTIAL_PATTERNS, "EXA010"),
            ]

            for patterns, rule_id in all_patterns:
                issues.extend(self._check_patterns(content, lines, patterns, rule_id))

            if has_safety:
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
                                message=f"{message} - implement proper agent safety controls",
                                line=i,
                                column=1,
                            ))
                            seen.add(message)
                            break
                except re.error:
                    continue

        return issues
