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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number


class MultiAgentScanner(RuleBasedScanner):
    """
    Multi-Agent Security Scanner

    Scans for:
    - MAG001: Agent handoff without authentication
    - MAG002: Inter-agent message without validation
    - MAG003: Privilege escalation in delegation
    - MAG004: Missing consensus validation
    - MAG005: Unencrypted agent communication
    - MAG006: Missing agent identity verification
    - MAG007: Unrestricted agent spawning
    - MAG008: Missing audit trail for agent interactions
    - MAG009: Cross-agent data leakage
    - MAG010: Missing timeout in agent coordination
    - MAG011: Prompt infection - no origin tagging
    - MAG012: Cascading prompt without sanitization
    - MAG013: Agent broadcast without validation
    - MAG014: Missing content boundaries
    - MAG015: No agent authentication in handoff
    - MAG016: LLM tagging absence (multi-agent)
    - MAG017: Untrusted agent message forwarding
    - MAG018: Multi-agent consensus bypass
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['MULTI-AGT-', 'MULTI-', 'MEDUSA-AGT26-', 'MEDUSA-AGT-', 'MEDUSA-AGENT-SCAN', 'MEDUSA-TUA-']

    # Categories to load from YAML
    RULE_CATEGORIES = [
        'multi_agent', 'agent_orchestration',
        # AGT26 agentic attack categories
        'delegation_chain', 'social_engineering',
        'corpus_embedding_manipulation', 'prompt_injection',
        # AGT-SCAN agent security categories
        'agent_security', 'multi_agent_security', 'multi_agent_attack',
        # AGENT-SCAN categories (from agentic_attacks_scanner.yaml)
        'agentic_attacks', 'environmental_injection', 'indirect_injection',
        'indirect_prompt_injection', 'malicious_agent', 'memory_poisoning',
        'safety_bypass', 'societal_harm', 'tool_supply_chain', 'data_poisoning',
        # TUA-SCAN categories (from tool_use_attacks_scanner.yaml)
        'tool_use_attacks', 'tool_misuse', 'tool_hallucination', 'tool_jailbreak',
        'availability_risk', 'content_injection', 'insecure_code_generation',
        'multi_agent_risk', 'reliability_risk', 'robustness',
        'unsafe_code_generation', 'automated_attack_tool',
        # ACP-SCAN agent-specific categories (from acp_vulnerabilities_scanner.yaml)
        'excessive_agency', 'excessive_permissions', 'context_contamination',
        'memory_injection', 'multimodal_injection', 'sandbox_escape',
        'transport_security', 'worm_propagation', 'infectious_attack',
        'backdoor_detection', 'tool_abuse', 'tool_poisoning',
        # Orphaned rule directories wired here
        'agent_identity_impersonation', 'agentic_exploitation',
        'agentic_patterns',
        # Injection payload strings — ungated, fires on any file containing
        # injection payload content regardless of multi-agent framework presence
        'injection_payload_strings',
    ]

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

    # Framework imports/API calls that confirm actual multi-agent code
    # (not just keyword mentions in strings/comments/classification data)
    FRAMEWORK_INDICATORS = [
        # Python imports
        'from crewai', 'import crewai',
        'from autogen', 'import autogen',
        'from langraph', 'import langraph',
        'from langgraph', 'import langgraph',
        'from agentscope', 'import agentscope',
        'from openai_agents', 'import openai_agents',
        'from swarm', 'import swarm',
        'from metagpt', 'import metagpt',
        'from camel', 'import camel',
        # JS/TS imports
        'from "langchain/agents"', "from 'langchain/agents'",
        'require("langchain/agents")', "require('langchain/agents')",
        # Multi-agent API calls
        'Agent(', 'CrewAgent(', 'AssistantAgent(', 'UserProxyAgent(',
        'agent.send(', 'agent.handoff(', 'agent.delegate(',
        'agent.receive(', 'agent.initiate_chat(',
        'Crew(', 'GroupChat(', 'AgentExecutor(',
        # Class definitions extending agent bases
        'class Agent', '(BaseAgent)', '(AgentBase)',
        # A2A protocol implementation
        'AgentCard(', 'a2a_server', 'a2a_client',
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

    # Prompt Infection patterns (MAG011-MAG015)
    # Cascading prompt attacks that self-replicate across collaborative agents
    PROMPT_INFECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Agent-to-agent message without origin tagging
        (r'agent\.send\s*\([^)]*message[^)]*\)(?!.*(?:tag|origin|source))',
         'MAG011: Agent message without origin tagging (prompt infection risk)', Severity.HIGH),
        # Broadcast prompt without origin marker
        (r'broadcast\s*\([^)]*(?:prompt|message)[^)]*\)(?!.*origin)',
         'MAG012: Broadcast to agents without origin marker', Severity.HIGH),
        # Forwarding untrusted input to agent
        (r'forward[_-]?to[_-]?agent\s*\([^)]*(?:user[_-]?input|request\.)',
         'MAG013: Forwarding untrusted user input to agent', Severity.CRITICAL),
        # Agent receive without source identification
        (r'agents?\[.*\]\.receive\s*\((?!.*source)',
         'MAG014: Agent receive without source identification', Severity.HIGH),
        # Missing sanitization in agent chain
        (r'(?:next|downstream)[_-]?agent\.(?:send|process)\s*\([^)]*(?:response|output)',
         'MAG015: Passing agent output to next agent without sanitization', Severity.HIGH),
    ]

    # LLM Tagging patterns (MAG016-MAG018)
    # Check for missing agent origin markers in multi-agent systems
    LLM_TAGGING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Agent messages without source identification
        (r'agent\.send\s*\((?!.*source[_-]?agent)',
         'MAG016: Agent send without source_agent identifier', Severity.MEDIUM),
        # Missing content boundaries in message construction
        (r'prompt\s*\+=\s*(?:other[_-]?)?agent',
         'MAG017: Agent content concatenation without boundaries', Severity.MEDIUM),
        # Context extension without tagging
        (r'context\.(?:extend|append)\s*\([^)]*agent[_-]?response(?!.*tagged)',
         'MAG018: Agent response added to context without tagging', Severity.MEDIUM),
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

            _offsets = _build_line_offsets(content)

            # Pass 1: Ungated scan — injection_payload_strings rules fire on any file
            # that contains explicit injection payload content (authority impersonation,
            # covert action instructions). These are always-suspicious strings; no
            # framework gate needed.
            _payload_rules = [r for r in self.rules if r.category == 'injection_payload_strings']
            _file_str = str(file_path)
            _lines = content.split('\n')
            _scan_lines = _lines[:self.MAX_RULE_SCAN_LINES] if len(_lines) > self.MAX_RULE_SCAN_LINES else _lines
            _seen_payload = set()
            for rule in _payload_rules:
                if not rule.matches_file_type(_file_str):
                    continue
                for i, line in enumerate(_scan_lines, 1):
                    for compiled in rule._compiled_patterns:
                        try:
                            if compiled.search(line):
                                key = (rule.id, i)
                                if key not in _seen_payload:
                                    _seen_payload.add(key)
                                    issues.append(ScannerIssue(
                                        rule_id=rule.id,
                                        severity=rule.severity,
                                        message=f"Security issue detected: {rule.name}",
                                        line=i,
                                        column=1,
                                    ))
                                break
                        except re.error:
                            pass

            # Compound gate: file must have BOTH multi-agent keywords
            # AND actual framework imports/API calls.
            # This prevents FPs on files that merely mention "crewai"
            # or "agent-to-agent" in string literals or classification data.
            has_multi_agent = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in self.MULTI_AGENT_PATTERNS
            )

            has_framework = any(
                indicator in content
                for indicator in self.FRAMEWORK_INDICATORS
            )

            if not (has_multi_agent and has_framework):
                # No multi-agent indicators — return only ungated payload findings
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=issues,
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

            # MAG001: Missing authentication
            if not has_security:
                for pattern in self.MULTI_AGENT_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        line = _get_line_number(_offsets, match.start())
                        issues.append(ScannerIssue(
                            rule_id="MAG001",
                            severity=Severity.HIGH,
                            message="Agent handoff/communication without authentication - implement mTLS or signed messages",
                            line=line,
                            column=1,
                        ))
                        break

            # MAG002: Missing message validation
            if not has_validation:
                issues.append(ScannerIssue(
                    rule_id="MAG002",
                    severity=Severity.HIGH,
                    message="Inter-agent messages without validation - use schema validation",
                    line=1,
                    column=1,
                ))

            # MAG003: Missing privilege checks
            if not has_privilege_check:
                issues.append(ScannerIssue(
                    rule_id="MAG003",
                    severity=Severity.HIGH,
                    message="Agent delegation without privilege verification - check permissions before delegating",
                    line=1,
                    column=1,
                ))

            # MAG004: Missing consensus (if debate/vote patterns exist)
            debate_patterns = ['debate', 'vote', 'decide', 'choose']
            has_debate = any(
                re.search(p, content, re.IGNORECASE) for p in debate_patterns
            )
            if has_debate and not has_consensus:
                issues.append(ScannerIssue(
                    rule_id="MAG004",
                    severity=Severity.MEDIUM,
                    message="Multi-agent decision without consensus validation - implement quorum voting",
                    line=1,
                    column=1,
                ))

            # MAG008: Missing audit trail
            if not has_audit:
                issues.append(ScannerIssue(
                    rule_id="MAG008",
                    severity=Severity.MEDIUM,
                    message="Agent interactions without audit logging - log all agent-to-agent communications",
                    line=1,
                    column=1,
                ))

            # Check for dangerous patterns
            issues.extend(self._check_dangerous_patterns(content, file_path, _offsets))

            # Check for agent spawning controls
            issues.extend(self._check_agent_spawning(content, file_path))

            # Check for timeout mechanisms
            issues.extend(self._check_coordination_timeout(content, file_path))

            # Check for data leakage
            issues.extend(self._check_data_leakage(content, file_path, _offsets))

            # NEW: Check for prompt infection patterns (MAG011-MAG015)
            issues.extend(self._check_prompt_infection(content, file_path, _offsets))

            # NEW: Check for LLM tagging absence (MAG016-MAG018)
            issues.extend(self._check_llm_tagging(content, file_path, _offsets))

            # NEW: Check for untrusted forwarding
            issues.extend(self._check_untrusted_forwarding(content, file_path, _offsets))

            # NEW: Check for consensus bypass
            issues.extend(self._check_consensus_bypass(content, file_path, _offsets))

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
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """Check for dangerous multi-agent patterns"""
        issues = []

        for pattern, message in self.DANGEROUS_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line = _get_line_number(_offsets, match.start())

                # Determine severity based on pattern
                if 'password' in message.lower() or 'secret' in message.lower():
                    severity = Severity.CRITICAL
                    rule_id = "MAG009"
                elif 'http://' in pattern:
                    severity = Severity.HIGH
                    rule_id = "MAG005"
                else:
                    severity = Severity.HIGH
                    rule_id = "MAG006"

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
                rule_id="MAG007",
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
                rule_id="MAG010",
                severity=Severity.MEDIUM,
                message="Agent coordination without timeout (deadlock risk) - add timeout to prevent indefinite waiting",
                line=1,
                column=1,
            ))

        return issues

    def _check_data_leakage(
        self, content: str, file_path: Path, _offsets: List[int] = None
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
                line = _get_line_number(_offsets, match.start())
                issues.append(ScannerIssue(
                    rule_id="MAG009",
                    severity=Severity.HIGH,
                    message=f"Cross-agent data leakage: {message} - limit data sharing between agents",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_prompt_infection(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """
        Check for prompt infection vulnerabilities (MAG011-MAG015)

        Prompt infection is a cascading attack where malicious prompts
        self-replicate across collaborative agents in multi-agent systems.
        """
        issues = []

        for pattern, message, severity in self.PROMPT_INFECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = _get_line_number(_offsets, match.start())
                rule_id = message.split(':')[0] if ':' in message else "MAG011"
                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"{message} - add origin tagging and sanitize prompts",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_llm_tagging(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """
        Check for missing LLM tagging in multi-agent systems (MAG016-MAG018)

        LLM tagging helps track the origin of messages and prevents
        confusion about which agent generated which content.
        """
        issues = []

        for pattern, message, severity in self.LLM_TAGGING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = _get_line_number(_offsets, match.start())
                rule_id = message.split(':')[0] if ':' in message else "MAG016"
                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"{message} - add source_agent identifier and content boundaries",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_untrusted_forwarding(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """
        Check for untrusted data being forwarded to agent chains (MAG017)
        """
        issues = []

        for pattern, message, severity in self.UNTRUSTED_FORWARDING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = _get_line_number(_offsets, match.start())
                issues.append(ScannerIssue(
                    rule_id="MAG017",
                    severity=severity,
                    message=f"Untrusted forwarding: {message} - validate and sanitize all external data",
                    line=line,
                    column=1,
                ))

        return issues

    def _check_consensus_bypass(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """
        Check for patterns that bypass multi-agent consensus (MAG018)
        """
        issues = []

        for pattern, message, severity in self.CONSENSUS_BYPASS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = _get_line_number(_offsets, match.start())
                issues.append(ScannerIssue(
                    rule_id="MAG018",
                    severity=severity,
                    message=f"Consensus bypass: {message} - require quorum validation",
                    line=line,
                    column=1,
                ))

        return issues
