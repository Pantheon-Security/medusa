#!/usr/bin/env python3
"""
MEDUSA Agent Planning Security Scanner
Detects security issues in planning/task decomposition patterns

Based on "Agentic Design Patterns" Chapter 6 - Planning

Detects:
- Instruction subversion vectors
- Unvalidated plan execution
- Missing scope boundaries
- Dynamic planning without constraints
- Goal injection vulnerabilities
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class AgentPlanningScanner(BaseScanner):
    """
    Agent Planning Security Scanner

    Scans for:
    - PL001: Plan generated from untrusted input
    - PL002: Plan execution without validation
    - PL003: Missing scope/boundary constraints
    - PL004: Dynamic planning without safety limits
    - PL005: Goal injection vulnerability
    - PL006: Plan steps not validated before execution
    - PL007: Missing plan audit logging
    - PL008: Unbounded task decomposition
    - PL009: Plan modification without authorization
    - PL010: Missing rollback capability for plan failures
    """

    # Patterns indicating planning/task decomposition
    PLANNING_PATTERNS = [
        r'(create|generate|make)[_-]?plan',
        r'task[_-]?(decompos|break|split)',
        r'(sub[_-]?)?goal[_-]?(set|list|queue)',
        r'action[_-]?(plan|sequence|list)',
        r'step[_-]?(list|sequence|queue)',
        r'planner[_-]?(agent|class|module)',
        r'planning[_-]?(loop|cycle|phase)',
        r'workflow[_-]?(generat|creat)',
        r'orchestrat(e|or|ion)',
        r'task[_-]?queue',
        r'execution[_-]?plan',
    ]

    # Patterns indicating plan validation
    VALIDATION_PATTERNS = [
        r'validate[_-]?(plan|step|action|goal)',
        r'check[_-]?(plan|step|action|goal)',
        r'verify[_-]?(plan|step|action)',
        r'approve[_-]?(plan|step|action)',
        r'review[_-]?(plan|step|action)',
        r'allowed[_-]?(action|step|tool)',
        r'permitted[_-]?(action|step)',
        r'within[_-]?(scope|boundary|limit)',
    ]

    # Patterns indicating scope/boundary controls
    BOUNDARY_PATTERNS = [
        r'scope[_-]?(limit|bound|check)',
        r'boundary[_-]?(check|enforce)',
        r'constraint[_-]?(check|enforce)',
        r'allowed[_-]?(scope|domain|action)',
        r'forbidden[_-]?(action|scope)',
        r'blacklist',
        r'whitelist',
        r'allowed[_-]?tools',
        r'permitted[_-]?actions',
        r'deny[_-]?list',
        r'allow[_-]?list',
    ]

    # Patterns indicating audit logging
    AUDIT_PATTERNS = [
        r'audit[_-]?(log|trail|record)',
        r'log[_-]?(plan|step|action|execution)',
        r'record[_-]?(action|step|decision)',
        r'trace[_-]?(execution|plan)',
        r'track[_-]?(step|action|progress)',
    ]

    # Patterns indicating safety controls
    SAFETY_PATTERNS = [
        r'max[_-]?(step|action|depth|iteration)',
        r'limit[_-]?(step|action|depth)',
        r'timeout',
        r'deadline',
        r'rollback',
        r'revert',
        r'undo[_-]?(action|step)',
        r'cancel[_-]?(plan|execution)',
        r'abort[_-]?(plan|execution)',
    ]

    # Dangerous patterns indicating injection vectors
    INJECTION_PATTERNS = [
        (r'goal\s*=\s*(input|request|user)', 'Goal set directly from user input'),
        (r'plan\s*=\s*.*\+.*user', 'Plan constructed with user input concatenation'),
        (r'eval\s*\(.*plan', 'Plan executed via eval'),
        (r'exec\s*\(.*step', 'Step executed via exec'),
        (r'(instruction|prompt)\s*=.*user.*input', 'Instructions from user input'),
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
        """Scan for planning pattern security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file contains planning patterns
            has_planning = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.PLANNING_PATTERNS
            )

            if not has_planning:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for validation
            has_validation = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.VALIDATION_PATTERNS
            )

            # Check for boundary controls
            has_boundaries = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.BOUNDARY_PATTERNS
            )

            # Check for audit logging
            has_audit = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.AUDIT_PATTERNS
            )

            # Check for safety controls
            has_safety = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.SAFETY_PATTERNS
            )

            # AP002: Plan execution without validation
            if not has_validation:
                for pattern in self.PLANNING_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        line = content[:match.start()].count('\n') + 1
                        issues.append(ScannerIssue(
                            rule_id="AP002",
                            severity=Severity.HIGH,
                            message="Plan execution without validation",
                            file_path=file_path,
                            line=line,
                            column=1,
                            suggestion="Validate each plan step before execution using before_tool_callback",
                        ))
                        break

            # AP003: Missing scope boundaries
            if not has_boundaries:
                issues.append(ScannerIssue(
                    rule_id="AP003",
                    severity=Severity.HIGH,
                    message="Planning without scope/boundary constraints",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Define allowed actions/tools scope to prevent out-of-bounds execution",
                ))

            # AP007: Missing audit logging
            if not has_audit:
                issues.append(ScannerIssue(
                    rule_id="AP007",
                    severity=Severity.MEDIUM,
                    message="Plan execution without audit logging",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Log all plan steps and actions for security monitoring",
                ))

            # AP004: Dynamic planning without safety limits
            if not has_safety:
                issues.append(ScannerIssue(
                    rule_id="AP004",
                    severity=Severity.MEDIUM,
                    message="Dynamic planning without safety limits",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Add max_steps, timeout, or rollback capability",
                ))

            # Check for injection vulnerabilities
            issues.extend(self._check_injection_vectors(content, file_path))

            # Check for decomposition issues
            issues.extend(self._check_decomposition(content, file_path))

            # Check for authorization
            issues.extend(self._check_authorization(content, file_path))

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

    def _check_injection_vectors(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for goal/instruction injection vulnerabilities"""
        issues = []

        for pattern, message in self.INJECTION_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="AP005",
                    severity=Severity.CRITICAL,
                    message=f"Goal injection vulnerability: {message}",
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Sanitize and validate all inputs before using in planning",
                ))

        # Check for plan from untrusted sources
        untrusted_patterns = [
            (r'plan\s*=\s*(json\.loads|JSON\.parse)\s*\(\s*(request|input|body)',
             'Plan parsed directly from request'),
            (r'steps\s*=\s*.*\[(request|input|body)',
             'Plan steps from untrusted input'),
        ]

        for pattern, message in untrusted_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="AP001",
                    severity=Severity.CRITICAL,
                    message=f"Plan from untrusted input: {message}",
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Never accept execution plans from untrusted sources",
                ))

        return issues

    def _check_decomposition(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for unbounded task decomposition"""
        issues = []

        # Patterns indicating recursive decomposition
        decomp_patterns = [
            r'def\s+decompose.*decompose\s*\(',
            r'function\s+decompose.*decompose\s*\(',
            r'while.*decompose',
            r'recursive.*task.*split',
        ]

        # Check if there's a depth limit
        has_depth_limit = re.search(
            r'(max[_-]?depth|depth[_-]?limit|recursion[_-]?limit)',
            content, re.IGNORECASE
        )

        for pattern in decomp_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if match and not has_depth_limit:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="AP008",
                    severity=Severity.HIGH,
                    message="Unbounded task decomposition (infinite recursion risk)",
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Add max_depth limit to prevent infinite decomposition",
                ))

        return issues

    def _check_authorization(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for plan modification authorization"""
        issues = []

        # Patterns indicating plan modification
        modification_patterns = [
            r'plan\.(update|modify|change|add|remove)',
            r'(update|modify|change)[_-]?plan',
            r'steps\.(push|append|pop|shift)',
            r'add[_-]?(step|action|goal)',
            r'remove[_-]?(step|action|goal)',
        ]

        # Check if there's authorization
        has_auth = re.search(
            r'(authorize|permission|allow|can[_-]?modify|is[_-]?allowed)',
            content, re.IGNORECASE
        )

        for pattern in modification_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and not has_auth:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="AP009",
                    severity=Severity.MEDIUM,
                    message="Plan modification without authorization check",
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Verify authorization before allowing plan modifications",
                ))
                break  # One warning is enough

        # Check for rollback capability
        has_modification = any(
            re.search(p, content, re.IGNORECASE) for p in modification_patterns
        )
        has_rollback = re.search(
            r'(rollback|revert|undo|restore[_-]?(state|plan))',
            content, re.IGNORECASE
        )

        if has_modification and not has_rollback:
            issues.append(ScannerIssue(
                rule_id="AP010",
                severity=Severity.LOW,
                message="Plan modification without rollback capability",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Add rollback mechanism for failed plan executions",
            ))

        return issues
