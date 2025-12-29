#!/usr/bin/env python3
"""
MEDUSA Multi-Agent Security Scanner
Detects security issues in multi-agent collaboration patterns

Based on "Agentic Design Patterns" Chapter 7 - Multi-Agent Collaboration

Detects:
- Insecure agent-to-agent communication
- Missing authentication in handoffs
- Unvalidated inter-agent messages
- Privilege escalation in delegation
- Missing consensus validation
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class MultiAgentScanner(RuleBasedScanner):
    """
    Multi-Agent Security Scanner

    Scans for:
    - MA001: Agent handoff without authentication
    - MA002: Inter-agent message without validation
    - MA003: Privilege escalation in delegation
    - MA004: Missing consensus validation
    - MA005: Unencrypted agent communication
    - MA006: Missing agent identity verification
    - MA007: Unrestricted agent spawning
    - MA008: Missing audit trail for agent interactions
    - MA009: Cross-agent data leakage
    - MA010: Missing timeout in agent coordination
    - MA011: Prompt infection - no origin tagging
    - MA012: Cascading prompt without sanitization
    - MA013: Agent broadcast without validation
    - MA014: Missing content boundaries
    - MA015: No agent authentication in handoff
    - MA016: LLM tagging absence (multi-agent)
    - MA017: Untrusted agent message forwarding
    - MA018: Multi-agent consensus bypass
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['MULTI-AGT-', 'MULTI-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['multi_agent', 'agent_orchestration']

    # Patterns indicating multi-agent collaboration
    MULTI_AGENT_PATTERNS = [
        r'(agent|worker)[_-]?(pool|team|group|ensemble)',
        r'multi[_-]?agent',
        r'agent[_-]?collaborat',
        r'delegate[_-]?(to[_-])?agent',
        r'handoff[_-]?(to[_-])?agent',
        r'pass[_-]?to[_-]?agent',
        r'agent[_-]?to[_-]?agent',
        r'a2a[_-]?(protocol|communication)',
        r'orchestrator[_-]?agent',
        r'manager[_-]?agent',
        r'worker[_-]?agent',
        r'specialist[_-]?agent',
        r'crew[_-]?ai',
        r'agent[_-]?spawn',
        r'create[_-]?agent',
        r'agent[_-]?registry',
    ]

    # Patterns indicating authentication/security
    SECURITY_PATTERNS = [
        r'authenticate[_-]?(agent|sender|source)',
        r'verify[_-]?(agent|identity|sender)',
        r'agent[_-]?token',
        r'agent[_-]?auth',
        r'mtls',
        r'mutual[_-]?tls',
        r'signed[_-]?message',
        r'verify[_-]?signature',
        r'agent[_-]?certificate',
        r'trusted[_-]?agent',
    ]

    # Patterns indicating message validation
    VALIDATION_PATTERNS = [
        r'validate[_-]?(message|payload|request)',
        r'verify[_-]?(message|content|data)',
        r'sanitize[_-]?(input|message|payload)',
        r'check[_-]?(schema|format|type)',
        r'message[_-]?schema',
        r'payload[_-]?validation',
    ]

    # Patterns indicating privilege/permission handling
    PRIVILEGE_PATTERNS = [
        r'check[_-]?permission',
        r'verify[_-]?permission',
        r'has[_-]?permission',
        r'authorize[_-]?(action|delegation)',
        r'permission[_-]?check',
        r'capability[_-]?(check|verify)',
        r'scope[_-]?(check|limit)',
        r'delegate[_-]?permission',
    ]

    # Patterns indicating consensus mechanisms
    CONSENSUS_PATTERNS = [
        r'consensus',
        r'vote[_-]?(result|tally|count)',
        r'majority[_-]?(agree|vote)',
        r'quorum',
        r'agree[_-]?(ment|on)',
        r'confirm[_-]?all',
        r'all[_-]?agents[_-]?agree',
        r'debate[_-]?result',
    ]

    # Patterns indicating audit logging
    AUDIT_PATTERNS = [
        r'audit[_-]?(log|trail)',
        r'log[_-]?(interaction|communication|handoff)',
        r'record[_-]?(message|action|delegation)',
        r'trace[_-]?(agent|interaction)',
        r'track[_-]?(handoff|delegation)',
    ]

    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        (r'agent\.(send|post)\s*\([^)]*password', 'Password in agent communication'),
        (r'agent\.(send|post)\s*\([^)]*secret', 'Secret in agent communication'),
        (r'spawn[_-]?agent\s*\(\s*(input|request|user)', 'Agent spawned from user input'),
        (r'trust\s*=\s*True', 'Hardcoded trust flag'),
        (r'skip[_-]?auth\s*=\s*[Tt]rue', 'Auth bypassed for agent'),
        (r'http://.*agent', 'Unencrypted agent endpoint'),
    ]

    # Prompt Infection patterns (MA011-MA015)
    # Cascading prompt attacks that self-replicate across collaborative agents
    PROMPT_INFECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Agent-to-agent message without origin tagging
        (r'agent\.send\s*\([^)]*message[^)]*\)(?!.*(?:tag|origin|source))',
         'MA011: Agent message without origin tagging (prompt infection risk)', Severity.HIGH),
        # Broadcast prompt without origin marker
        (r'broadcast\s*\([^)]*(?:prompt|message)[^)]*\)(?!.*origin)',
         'MA012: Broadcast to agents without origin marker', Severity.HIGH),
        # Forwarding untrusted input to agent
        (r'forward[_-]?to[_-]?agent\s*\([^)]*(?:user[_-]?input|request\.)',
         'MA013: Forwarding untrusted user input to agent', Severity.CRITICAL),
        # Agent receive without source identification
        (r'agents?\[.*\]\.receive\s*\((?!.*source)',
         'MA014: Agent receive without source identification', Severity.HIGH),
        # Missing sanitization in agent chain
        (r'(?:next|downstream)[_-]?agent\.(?:send|process)\s*\([^)]*(?:response|output)',
         'MA015: Passing agent output to next agent without sanitization', Severity.HIGH),
    ]

    # LLM Tagging patterns (MA016-MA018)
    # Check for missing agent origin markers in multi-agent systems
    LLM_TAGGING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Agent messages without source identification
        (r'agent\.send\s*\((?!.*source[_-]?agent)',
         'MA016: Agent send without source_agent identifier', Severity.MEDIUM),
        # Missing content boundaries in message construction
        (r'prompt\s*\+=\s*(?:other[_-]?)?agent',
         'MA017: Agent content concatenation without boundaries', Severity.MEDIUM),
        # Context extension without tagging
        (r'context\.(?:extend|append)\s*\([^)]*agent[_-]?response(?!.*tagged)',
         'MA018: Agent response added to context without tagging', Severity.MEDIUM),
    ]

    # Untrusted forwarding patterns
    UNTRUSTED_FORWARDING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct user input to agent chain
        (r'agent[_-]?chain\.(?:run|execute)\s*\([^)]*(?:user|input|request)',
         'Untrusted input passed directly to agent chain', Severity.CRITICAL),
        # Unvalidated external data to agents
        (r'agent\.process\s*\([^)]*(?:external|api|http)',
         'External data passed to agent without validation', Severity.HIGH),
    ]

    # Consensus bypass patterns
    CONSENSUS_BYPASS_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Skipping consensus check
        (r'skip[_-]?consensus\s*=\s*[Tt]rue',
         'Consensus check explicitly skipped', Severity.HIGH),
        # Single agent override
        (r'single[_-]?agent[_-]?(?:override|decision)',
         'Single agent can override multi-agent consensus', Severity.HIGH),
        # No quorum check
        (r'execute[_-]?(?:action|decision)\s*\((?!.*quorum)',
         'Multi-agent action without quorum validation', Severity.MEDIUM),
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
        """Scan for multi-agent security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file contains multi-agent patterns
            has_multi_agent = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.MULTI_AGENT_PATTERNS
            )

            if not has_multi_agent:
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

            # Check for security measures
            has_security = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.SECURITY_PATTERNS
            )

            has_validation = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.VALIDATION_PATTERNS
            )

            has_privilege_check = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.PRIVILEGE_PATTERNS
            )

            has_consensus = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.CONSENSUS_PATTERNS
            )

            has_audit = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.AUDIT_PATTERNS
            )

            # MA001: Missing authentication
            if not has_security:
                for pattern in self.MULTI_AGENT_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        line = content[:match.start()].count('\n') + 1
                        issues.append(ScannerIssue(
                            rule_id="MA001",
                            severity=Severity.HIGH,
                            message="Agent handoff/communication without authentication - implement mTLS or signed messages",
                            line=line,
                            column=1,
                        ))
                        break

            # MA002: Missing message validation
            if not has_validation:
                issues.append(ScannerIssue(
                    rule_id="MA002",
                    severity=Severity.HIGH,
                    message="Inter-agent messages without validation - use schema validation",
                    line=1,
                    column=1,
                ))

            # MA003: Missing privilege checks
            if not has_privilege_check:
                issues.append(ScannerIssue(
                    rule_id="MA003",
                    severity=Severity.HIGH,
                    message="Agent delegation without privilege verification - check permissions before delegating",
                    line=1,
                    column=1,
                ))

            # MA004: Missing consensus (if debate/vote patterns exist)
            debate_patterns = ['debate', 'vote', 'decide', 'choose']
            has_debate = any(
                re.search(p, content, re.IGNORECASE) for p in debate_patterns
            )
            if has_debate and not has_consensus:
                issues.append(ScannerIssue(
                    rule_id="MA004",
                    severity=Severity.MEDIUM,
                    message="Multi-agent decision without consensus validation - implement quorum voting",
                    line=1,
                    column=1,
                ))

            # MA008: Missing audit trail
            if not has_audit:
                issues.append(ScannerIssue(
                    rule_id="MA008",
                    severity=Severity.MEDIUM,
                    message="Agent interactions without audit logging - log all agent-to-agent communications",
                    line=1,
                    column=1,
                ))

            # Check for dangerous patterns
            issues.extend(self._check_dangerous_patterns(content, file_path))

            # Check for agent spawning controls
            issues.extend(self._check_agent_spawning(content, file_path))

            # Check for timeout mechanisms
            issues.extend(self._check_coordination_timeout(content, file_path))

            # Check for data leakage
            issues.extend(self._check_data_leakage(content, file_path))

            # NEW: Check for prompt infection patterns (MA011-MA015)
            issues.extend(self._check_prompt_infection(content, file_path))

            # NEW: Check for LLM tagging absence (MA016-MA018)
            issues.extend(self._check_llm_tagging(content, file_path))

            # NEW: Check for untrusted forwarding
            issues.extend(self._check_untrusted_forwarding(content, file_path))

            # NEW: Check for consensus bypass
            issues.extend(self._check_consensus_bypass(content, file_path))

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

    def _check_dangerous_patterns(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for dangerous multi-agent patterns"""
        issues = []

        for pattern, message in self.DANGEROUS_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1

                # Determine severity based on pattern
                if 'password' in message.lower() or 'secret' in message.lower():
                    severity = Severity.CRITICAL
                    rule_id = "MA009"
                elif 'http://' in pattern:
                    severity = Severity.HIGH
                    rule_id = "MA005"
                else:
                    severity = Severity.HIGH
                    rule_id = "MA006"

                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    line=line,
                    column=1,
                ))

        return issues

    def _check_agent_spawning(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for unrestricted agent spawning"""
        issues = []

        spawn_patterns = [
            r'spawn[_-]?agent',
            r'create[_-]?agent',
            r'new[_-]?Agent\s*\(',
            r'agent[_-]?factory',
            r'launch[_-]?agent',
        ]

        limit_patterns = [
            r'max[_-]?agents',
            r'agent[_-]?limit',
            r'pool[_-]?size',
            r'concurrent[_-]?limit',
        ]

        has_spawning = any(
            re.search(p, content, re.IGNORECASE) for p in spawn_patterns
        )
        has_limit = any(
            re.search(p, content, re.IGNORECASE) for p in limit_patterns
        )

        if has_spawning and not has_limit:
            issues.append(ScannerIssue(
                rule_id="MA007",
                severity=Severity.MEDIUM,
                message="Unrestricted agent spawning (resource exhaustion risk) - add max_agents limit",
                line=1,
                column=1,
            ))

        return issues

    def _check_coordination_timeout(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for timeout in agent coordination"""
        issues = []

        coordination_patterns = [
            r'await.*agent',
            r'wait[_-]?for[_-]?agent',
            r'agent\.join',
            r'gather\s*\(\s*\[.*agent',
            r'Promise\.all.*agent',
        ]

        timeout_patterns = [
            r'timeout',
            r'deadline',
            r'max[_-]?wait',
            r'time[_-]?limit',
        ]

        has_coordination = any(
            re.search(p, content, re.IGNORECASE) for p in coordination_patterns
        )
        has_timeout = any(
            re.search(p, content, re.IGNORECASE) for p in timeout_patterns
        )

        if has_coordination and not has_timeout:
            issues.append(ScannerIssue(
                rule_id="MA010",
                severity=Severity.MEDIUM,
                message="Agent coordination without timeout (deadlock risk) - add timeout to prevent indefinite waiting",
                line=1,
                column=1,
            ))

        return issues

    def _check_data_leakage(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for cross-agent data leakage"""
        issues = []

        # Patterns indicating data sharing
        sharing_patterns = [
            (r'share[_-]?(state|context|data)\s*\(\s*\*',
             'Sharing all data between agents'),
            (r'global[_-]?(state|context)',
             'Global state accessible to all agents'),
            (r'broadcast\s*\(.*secret',
             'Broadcasting secrets to agents'),
        ]

        for pattern, message in sharing_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="MA009",
                    severity=Severity.HIGH,
                    message=f"Cross-agent data leakage: {message} - limit data sharing between agents",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_prompt_infection(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """
        Check for prompt infection vulnerabilities (MA011-MA015)

        Prompt infection is a cascading attack where malicious prompts
        self-replicate across collaborative agents in multi-agent systems.
        """
        issues = []

        for pattern, message, severity in self.PROMPT_INFECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count('\n') + 1
                rule_id = message.split(':')[0] if ':' in message else "MA011"
                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"{message} - add origin tagging and sanitize prompts",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_llm_tagging(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """
        Check for missing LLM tagging in multi-agent systems (MA016-MA018)

        LLM tagging helps track the origin of messages and prevents
        confusion about which agent generated which content.
        """
        issues = []

        for pattern, message, severity in self.LLM_TAGGING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count('\n') + 1
                rule_id = message.split(':')[0] if ':' in message else "MA016"
                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"{message} - add source_agent identifier and content boundaries",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_untrusted_forwarding(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """
        Check for untrusted data being forwarded to agent chains (MA017)
        """
        issues = []

        for pattern, message, severity in self.UNTRUSTED_FORWARDING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="MA017",
                    severity=severity,
                    message=f"Untrusted forwarding: {message} - validate and sanitize all external data",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_consensus_bypass(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """
        Check for patterns that bypass multi-agent consensus (MA018)
        """
        issues = []

        for pattern, message, severity in self.CONSENSUS_BYPASS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="MA018",
                    severity=severity,
                    message=f"Consensus bypass: {message} - require quorum validation",
                    line=line,
                    column=1,
                ))

        return issues
