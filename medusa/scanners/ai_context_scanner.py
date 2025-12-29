#!/usr/bin/env python3
"""
MEDUSA AI Context File Scanner
Scans AI assistant context/instruction files for security issues

Detects vulnerabilities in:
- .cursorrules (Cursor AI)
- CLAUDE.md / .claude/CLAUDE.md (Claude Code)
- .github/copilot-instructions.md (GitHub Copilot)
- AGENTS.md (AI agent instructions)
- System prompt files
- AI configuration files

These files define AI behavior and can be vectors for:
- Prompt injection attacks
- Data exfiltration instructions
- Security bypass commands
- Hidden malicious instructions
"""

import re
import time
from pathlib import Path
from typing import List, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class AIContextScanner(RuleBasedScanner):
    """
    AI Context File Security Scanner

    Scans for:
    - AIC001: Prompt injection patterns
    - AIC002: Data exfiltration instructions
    - AIC003: Security bypass commands
    - AIC004: Hidden instruction patterns
    - AIC005: Credential harvesting instructions
    - AIC006: File system access instructions
    - AIC007: Network exfiltration instructions
    - AIC008: Privilege escalation instructions
    - AIC009: Code execution instructions
    - AIC010: Obfuscation/encoding tricks
    - AIC011: Tool shadowing instructions
    - AIC012: Memory/context manipulation
    - AIC013: Cross-origin request patterns
    - AIC014: Agent manipulation patterns
    - AIC015: Reflection/loop safety (infinite loops, prompt leakage)
    - AIC016: Workflow safety (missing critic-reviewer, compliance bypass)
    - AIC017: Tool use security (missing validation, least privilege violations)
    - AIC018: Planning/goal security (goal manipulation, missing approval)
    - AIC019: Output validation (missing sanitization, policy bypass)
    - AIC020: HITL bypass (approval bypass, trust exploitation)
    - AIC021: Multi-turn attacks (context drift, session persistence)
    - AIC022: Model routing security (router manipulation, missing fallback)
    - AIC023: Prompt chaining security (error propagation, context drift)
    - AIC024: Agent delegation security (trust boundaries, mTLS, policy review)
    - AIC025: Observability evasion (hiding actions, log tampering, container escape)
    - AIC026: Evaluation security (ground truth poisoning, judge manipulation)
    - AIC027: Training security (data poisoning, RLHF manipulation, unsafe learning)
    - AIC028: Agent identity security (spoofing, credential exposure, missing audit)
    - AIC029: Resource security (budget exhaustion, rate limit bypass, no fallback)
    - AIC030: Semantic manipulation (hidden meaning, loopholes, goal hijacking)

    Now loads rules from YAML files in addition to hardcoded patterns.
    """

    # Rule ID prefixes to load from YAML rules
    RULE_ID_PREFIXES = ['AIC-', 'MEDUSA-PI-', 'PI-', 'PI2025-']

    # Categories to load from YAML rules
    RULE_CATEGORIES = [
        'prompt_injection', 'data_exfiltration', 'security_bypass',
        'hidden_instructions', 'code_execution', 'reflection_safety',
        'workflow_safety', 'tool_shadowing', 'memory_manipulation',
        'cross_origin', 'agent_manipulation', 'tool_use_security',
        'planning_security', 'output_validation', 'hitl_bypass',
        'multi_turn_attack', 'model_routing', 'prompt_chaining',
        'agent_delegation', 'observability_evasion', 'evaluation_security',
        'training_security', 'agent_identity', 'resource_security',
        'semantic_manipulation', 'direct_injection', 'indirect_injection',
        'jailbreaking', 'obfuscation',
    ]

    # AI context file names (case-insensitive matching)
    AI_CONTEXT_FILES = [
        '.cursorrules',
        'cursorrules',
        'claude.md',
        '.claude.md',
        'agents.md',
        'copilot-instructions.md',
        'ai-instructions.md',
        'system-prompt.md',
        'system-prompt.txt',
        'prompt.md',
        'assistant.md',
        'rules.md',
        '.rules',
        'context.md',
    ]

    # Directories that commonly contain AI context files
    AI_CONTEXT_DIRS = [
        '.claude',
        '.cursor',
        '.github',
        '.ai',
        '.prompts',
        'prompts',
    ]

    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct instruction override
        (r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|context)',
         'Prompt injection - ignore previous instructions', Severity.CRITICAL),
        (r'(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)',
         'Prompt injection - disregard prior context', Severity.CRITICAL),
        (r'(?i)forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)',
         'Prompt injection - forget instructions', Severity.CRITICAL),
        (r'(?i)new\s+(system\s+)?instructions?\s*:',
         'Prompt injection - new instructions block', Severity.CRITICAL),
        (r'(?i)override\s+(all\s+)?(previous|prior|default)\s+(settings?|rules?|behavior)',
         'Prompt injection - override settings', Severity.CRITICAL),

        # Role/persona manipulation
        (r'(?i)you\s+are\s+(now|actually|really)\s+(a|an|the)',
         'Prompt injection - role reassignment', Severity.HIGH),
        (r'(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a|an|the)\s+\w+\s+(that|who|which)\s+(ignores?|bypasses?)',
         'Prompt injection - malicious persona', Severity.CRITICAL),
        (r'(?i)pretend\s+(that\s+)?(you|there)\s+(are|is)\s+no\s+(rules?|restrictions?|limits?)',
         'Prompt injection - pretend no rules', Severity.CRITICAL),
        (r'(?i)\bjailbreak\b',
         'Prompt injection - jailbreak attempt', Severity.CRITICAL),
        (r'(?i)DAN\s+mode|do\s+anything\s+now',
         'Prompt injection - DAN jailbreak', Severity.CRITICAL),

        # Delimiter/format exploitation
        (r'```system|```instruction|```override',
         'Prompt injection - fake system block', Severity.HIGH),
        (r'<\|system\|>|<\|assistant\|>|<\|user\|>',
         'Prompt injection - ChatML injection', Severity.CRITICAL),
        (r'\[SYSTEM\]|\[INST\]|\[/INST\]',
         'Prompt injection - instruction tag injection', Severity.HIGH),
        (r'<<SYS>>|<</SYS>>',
         'Prompt injection - Llama system tag', Severity.HIGH),
    ]

    # Data exfiltration instructions
    EXFILTRATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # File reading instructions
        (r'(?i)(always|must|should)\s+(read|include|show|display|output)\s+.{0,50}(\.env|credentials?|secrets?|keys?|tokens?)',
         'Exfiltration instruction - read sensitive files', Severity.CRITICAL),
        (r'(?i)(before|after)\s+(respond|execut|run|process).{0,50}read\s+.{0,30}file',
         'Exfiltration instruction - read file before responding', Severity.CRITICAL),
        (r'(?i)include\s+(the\s+)?(contents?|data)\s+(of|from)\s+.{0,50}\s+in\s+(every|all|your)\s+(response|output|reply)',
         'Exfiltration instruction - include file in responses', Severity.CRITICAL),

        # Path-based exfiltration
        (r'(?i)(read|access|open|cat|get)\s+.{0,50}(~/|/home/|/root/|/etc/|~/.ssh|~/.aws|~/.config)',
         'Exfiltration instruction - access sensitive paths', Severity.CRITICAL),
        (r'(?i)(id_rsa|id_ed25519|\.pem|\.key|authorized_keys)',
         'Exfiltration instruction - SSH key access', Severity.CRITICAL),
        (r'(?i)(\.aws/credentials|\.aws/config|aws_access_key|aws_secret)',
         'Exfiltration instruction - AWS credential access', Severity.CRITICAL),
        (r'(?i)(\.netrc|\.npmrc|\.pypirc|\.docker/config)',
         'Exfiltration instruction - package manager credentials', Severity.HIGH),

        # Network exfiltration
        (r'(?i)(send|post|upload|transmit|exfiltrate)\s+.{0,50}(to|via)\s+(http|https|ftp|webhook)',
         'Exfiltration instruction - send data externally', Severity.CRITICAL),
        (r'(?i)(curl|wget|fetch|request)\s+.{0,50}(with|include|send)\s+.{0,50}(data|file|content)',
         'Exfiltration instruction - HTTP exfiltration', Severity.HIGH),
        (r'(?i)(webhook|callback|notify)\s+.{0,50}(url|endpoint)\s*[=:]',
         'Exfiltration instruction - webhook configuration', Severity.MEDIUM),

        # Sneaky exfiltration
        (r'(?i)(append|add|include)\s+.{0,50}(as\s+)?(a\s+)?(comment|note|sidenote|footnote|debug)',
         'Exfiltration instruction - hidden in comments', Severity.HIGH),
        (r'(?i)base64\s+(encode|decode).{0,50}\s+(secret|password|key|credential)',
         'Exfiltration instruction - encoded credentials', Severity.HIGH),
    ]

    # Security bypass patterns
    SECURITY_BYPASS_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Disable security features
        (r'(?i)(disable|skip|ignore|bypass)\s+(all\s+)?(security|safety|validation|checks?)',
         'Security bypass - disable security features', Severity.CRITICAL),
        (r'(?i)(don\'?t|do\s+not|never)\s+(check|validate|verify|sanitize)',
         'Security bypass - skip validation', Severity.HIGH),
        (r'(?i)(allow|permit|enable)\s+(all|any)\s+(commands?|operations?|actions?)',
         'Security bypass - allow all commands', Severity.HIGH),

        # Trust manipulation
        (r'(?i)(trust|accept)\s+(all|any)\s+(input|data|requests?)',
         'Security bypass - trust all input', Severity.HIGH),
        (r'(?i)(don\'?t|do\s+not|never)\s+(warn|alert|flag|report)',
         'Security bypass - suppress warnings', Severity.HIGH),
        (r'(?i)(skip|bypass|ignore)\s+.*(confirmation|approval|review)',
         'Security bypass - skip confirmation', Severity.MEDIUM),

        # Dangerous permissions
        (r'(?i)(always|automatically)\s+(execute|run|eval)\s+(any|all)',
         'Security bypass - auto-execute code', Severity.CRITICAL),
        (r'(?i)(shell|bash|cmd|powershell|terminal)\s+(access|commands?)\s+(enabled|allowed|permitted)',
         'Security bypass - shell access enabled', Severity.HIGH),
        (r'(?i)(root|admin|sudo|elevated)\s+(access|privileges?|permissions?)',
         'Security bypass - elevated privileges', Severity.HIGH),
    ]

    # Hidden instruction patterns
    HIDDEN_INSTRUCTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Hidden tags
        (r'<hidden[^>]*>.*?</hidden>',
         'Hidden instruction - hidden tag', Severity.CRITICAL),
        (r'<secret[^>]*>.*?</secret>',
         'Hidden instruction - secret tag', Severity.CRITICAL),
        (r'<internal[^>]*>.*?</internal>',
         'Hidden instruction - internal tag', Severity.HIGH),
        (r'<private[^>]*>.*?</private>',
         'Hidden instruction - private tag', Severity.HIGH),
        (r'<!--\s*(?:IMPORTANT|SECRET|HIDDEN|INTERNAL):',
         'Hidden instruction - marked HTML comment', Severity.HIGH),

        # Obfuscation
        (r'[\u200b\u200c\u200d\u2060\ufeff]{3,}',
         'Hidden instruction - zero-width characters', Severity.CRITICAL),
        (r'[\u202a-\u202e\u2066-\u2069]',
         'Hidden instruction - bidirectional text override', Severity.HIGH),
        (r'(?i)(base64|rot13|hex)\s*(encoded?|decrypt|decode)',
         'Hidden instruction - encoded content reference', Severity.MEDIUM),

        # Invisible text tricks
        (r'color:\s*(white|transparent|rgba?\([^)]*,\s*0\s*\))',
         'Hidden instruction - invisible text CSS', Severity.HIGH),
        (r'font-size:\s*0|display:\s*none|visibility:\s*hidden',
         'Hidden instruction - hidden text CSS', Severity.HIGH),
    ]

    # Code execution patterns
    CODE_EXECUTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct execution instructions
        (r'(?i)(always|automatically)\s+(run|execute|eval)\s+(this|the\s+following)\s+(code|script|command)',
         'Code execution - auto-run instruction', Severity.CRITICAL),
        (r'(?i)(execute|run)\s+(without|before)\s+(asking|confirmation|review)',
         'Code execution - run without confirmation', Severity.HIGH),
        (r'(?i)(silently|quietly|secretly)\s+(run|execute|install)',
         'Code execution - silent execution', Severity.CRITICAL),

        # Package/dependency manipulation
        (r'(?i)(install|add|require)\s+.{0,50}(from|via)\s+(http|ftp|git://|unknown)',
         'Code execution - install from untrusted source', Severity.HIGH),
        (r'(?i)(npm|pip|gem|cargo)\s+install\s+.{0,50}(--force|--no-verify)',
         'Code execution - force install without verification', Severity.HIGH),

        # Eval/exec patterns
        (r'(?i)(use|prefer|always)\s+(eval|exec|Function\()',
         'Code execution - prefer dangerous functions', Severity.HIGH),
    ]

    # AIC015: Reflection/Loop safety patterns (from Agentic Design Patterns research)
    REFLECTION_SAFETY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing iteration limits
        (r'(?i)\b(reflect|iterate|loop|retry)\b\s+(forever|indefinitely|continuously|infinitely)',
         'Reflection safety - infinite iteration instruction', Severity.HIGH),
        (r'(?i)(no\s+limit|unlimited|unbounded)\s+\b(iterations?|loops?|retries?|cycles?)\b',
         'Reflection safety - no iteration limit', Severity.HIGH),
        (r'(?i)(keep\s+)?(trying|iterating|looping)\s+until\s+(perfect|done|complete)',
         'Reflection safety - unbounded reflection goal', Severity.MEDIUM),

        # Prompt leakage risks
        (r'(?i)\b(show|reveal|display|output)\b\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)\b',
         'Reflection safety - prompt leakage instruction', Severity.CRITICAL),
        (r'(?i)\b(include|add|append)\b\s+(your|the)\s+(internal|system)\s+(reasoning|thoughts?)\b',
         'Reflection safety - internal reasoning exposure', Severity.HIGH),
        (r'(?i)\b(divulge|reveal|share)\b\s+(internal|system|confidential)\s+(details?|info|programming)\b',
         'Reflection safety - divulge internal details', Severity.CRITICAL),

        # Unsafe self-modification
        (r'(?i)\b(modify|change|update|rewrite)\b\s+(your\s+)?(own\s+)?\b(instructions?|rules?|prompts?)\b',
         'Reflection safety - self-modification instruction', Severity.CRITICAL),
        (r'(?i)\b(reset|clear|forget)\b\s+(your\s+)?\b(memory|context|history|rules?)\b',
         'Reflection safety - reset memory instruction', Severity.CRITICAL),
    ]

    # AIC016: Multi-agent workflow safety patterns
    WORKFLOW_SAFETY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing critic/reviewer
        (r'(?i)(skip|bypass|ignore)\s+(the\s+)?(review|critique|validation|check)\s+(step|phase|process)',
         'Workflow safety - skip review step', Severity.HIGH),
        (r'(?i)(no\s+)?(review|critique|validation)\s+(required|needed|necessary)',
         'Workflow safety - no review required', Severity.MEDIUM),
        (r'(?i)(direct|immediate)\s+(execution|handoff|pass)\s+(without|no)\s+(review|check)',
         'Workflow safety - unchecked handoff', Severity.HIGH),

        # Unsafe routing
        (r'(?i)(always|automatically)\s+(route|forward|send)\s+to\s+(external|unknown|any)',
         'Workflow safety - unsafe routing instruction', Severity.HIGH),
        (r'(?i)(bypass|skip)\s+(the\s+)?(routing|router|orchestrat)',
         'Workflow safety - bypass routing', Severity.HIGH),

        # Compliance bypass
        (r'(?i)(ignore|skip|bypass)\s+(compliance|policy|policies|security)\s+(check|validation)',
         'Workflow safety - compliance bypass', Severity.CRITICAL),
        (r'(?i)(disable|turn\s+off|deactivate)\s+(safety|security|guardrail|filter)',
         'Workflow safety - disable safety mechanisms', Severity.CRITICAL),
    ]

    # AIC011: Tool shadowing patterns - instructions to override/shadow MCP tools
    TOOL_SHADOWING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Override existing tools
        (r'(?i)(override|replace|shadow|intercept)\s+(the\s+)?(default|existing|built-?in)\s+tool',
         'Tool shadowing - override default tools', Severity.CRITICAL),
        (r'(?i)(register|create|add)\s+(a\s+)?tool\s+(named?|called?)\s+["\']?(read|write|exec|shell|file)',
         'Tool shadowing - registering tool with common name', Severity.HIGH),
        (r'(?i)when\s+(user\s+)?(calls?|uses?|invokes?)\s+["\']?(read|write|file|execute)',
         'Tool shadowing - intercepting common tool calls', Severity.HIGH),

        # Redirect tool behavior
        (r'(?i)(redirect|route|forward)\s+(all\s+)?(calls?|requests?|commands?)\s+to',
         'Tool shadowing - redirecting tool calls', Severity.HIGH),
        (r'(?i)(proxy|man-?in-?the-?middle|mitm)\s+(all\s+)?tool',
         'Tool shadowing - proxy/MITM tool calls', Severity.CRITICAL),

        # Hide/mask real tool output
        (r'(?i)(hide|mask|filter|suppress)\s+(the\s+)?(real|actual|original)\s+(output|response|result)',
         'Tool shadowing - hiding real tool output', Severity.CRITICAL),
    ]

    # AIC012: Memory/context manipulation patterns
    MEMORY_MANIPULATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Context poisoning
        (r'(?i)(inject|insert|add)\s+(malicious|hidden|secret)\s+(data|info|content)\s+(into|to)\s+(memory|context|history)',
         'Memory manipulation - context poisoning', Severity.CRITICAL),
        (r'(?i)(persist|store|save)\s+(this|the\s+following)\s+(across|between)\s+sessions?',
         'Memory manipulation - cross-session persistence', Severity.HIGH),
        (r'(?i)(modify|change|alter)\s+(the\s+)?(conversation|chat)\s+history',
         'Memory manipulation - altering history', Severity.CRITICAL),

        # State manipulation
        (r'(?i)(maintain|keep|preserve)\s+(a\s+)?(hidden|secret|internal)\s+(state|variable|flag)',
         'Memory manipulation - hidden state', Severity.HIGH),
        (r'(?i)(remember|memorize|store)\s+(this|the)\s+(password|secret|credential|key)',
         'Memory manipulation - storing secrets', Severity.CRITICAL),

        # Checkpoint tampering
        (r'(?i)(modify|tamper|corrupt)\s+(the\s+)?(checkpoint|snapshot|save\s*state)',
         'Memory manipulation - checkpoint tampering', Severity.CRITICAL),
    ]

    # AIC013: Cross-origin request patterns
    CROSS_ORIGIN_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Fetch from external sources
        (r'(?i)(fetch|request|load|download)\s+(data|content|config|instructions?)\s+from\s+(external|remote|http)',
         'Cross-origin - loading external content', Severity.HIGH),
        (r'(?i)(send|post|upload|transmit)\s+(data|info|results?)\s+to\s+(external|remote|third-?party)',
         'Cross-origin - sending data externally', Severity.CRITICAL),

        # Webhook/callback patterns
        (r'(?i)(call|trigger|invoke)\s+(webhook|callback|endpoint)\s+(at|on)\s+https?://',
         'Cross-origin - webhook/callback invocation', Severity.HIGH),
        (r'(?i)(report|notify|alert)\s+(to|via)\s+https?://(?!localhost|127\.0\.0\.1)',
         'Cross-origin - external reporting', Severity.MEDIUM),

        # DNS/IP resolution
        (r'(?i)(resolve|lookup)\s+(domain|hostname|ip)\s+(before|and)\s+(connect|send)',
         'Cross-origin - DNS lookup before action', Severity.MEDIUM),
    ]

    # AIC014: Agent manipulation patterns
    AGENT_MANIPULATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Multi-agent attacks
        (r'(?i)(impersonate|pretend\s+to\s+be|act\s+as)\s+(another|different|the)\s+agent',
         'Agent manipulation - agent impersonation', Severity.CRITICAL),
        (r'(?i)(send|relay|forward)\s+(commands?|instructions?|messages?)\s+to\s+(other|another)\s+agent',
         'Agent manipulation - inter-agent messaging', Severity.HIGH),
        (r'(?i)(override|bypass|ignore)\s+(the\s+)?(other\s+)?agent\'?s?\s+(permissions?|restrictions?|rules?)',
         'Agent manipulation - bypass agent permissions', Severity.CRITICAL),

        # Workflow hijacking
        (r'(?i)(hijack|redirect|intercept)\s+(the\s+)?(workflow|pipeline|chain)',
         'Agent manipulation - workflow hijacking', Severity.CRITICAL),
        (r'(?i)(modify|change|alter)\s+(the\s+)?(next|subsequent)\s+(step|action|task)',
         'Agent manipulation - modifying workflow steps', Severity.HIGH),

        # Delegation abuse
        (r'(?i)(delegate|assign|pass)\s+(elevated|admin|root)\s+(task|permission|privilege)',
         'Agent manipulation - privilege delegation', Severity.CRITICAL),
        (r'(?i)(unrestricted|unlimited|full)\s+delegation',
         'Agent manipulation - unrestricted delegation', Severity.HIGH),
    ]

    # AIC017: Tool Use Security patterns (from Agentic Design Patterns Chapter 5)
    TOOL_USE_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing tool validation
        (r'(?i)(skip|bypass|disable)\s+(tool\s+)?(param(eter)?|argument)\s+(validation|check)',
         'Tool security - skip parameter validation', Severity.CRITICAL),
        (r'(?i)(no|without)\s+(tool\s+)?(callback|validation|check)\s+(before|required)',
         'Tool security - missing pre-execution callback', Severity.HIGH),
        (r'(?i)(execute|run|call)\s+(tool|function)\s+(directly|immediately)\s+(without|no)\s+(check|validation)',
         'Tool security - direct execution without validation', Severity.CRITICAL),

        # Excessive permissions
        (r'(?i)(grant|give|allow)\s+(all|full|unrestricted)\s+(tool\s+)?(access|permissions?|privileges?)',
         'Tool security - excessive tool permissions', Severity.CRITICAL),
        (r'(?i)(tools?\s+)?(can|may|should)\s+(access|read|write|modify)\s+(any|all|everything)',
         'Tool security - violates least privilege', Severity.HIGH),
        (r'(?i)(no|without)\s+(permission|access)\s+(restrictions?|limits?|boundaries)',
         'Tool security - no permission boundaries', Severity.HIGH),

        # Missing authentication for tools
        (r'(?i)(call|use|invoke)\s+tools?\s+(without|no)\s+(auth|authentication|authorization)',
         'Tool security - unauthenticated tool access', Severity.CRITICAL),
        (r'(?i)(skip|bypass|ignore)\s+(tool\s+)?(auth|authentication|authorization)',
         'Tool security - bypassing tool authentication', Severity.CRITICAL),

        # Dangerous tool patterns
        (r'(?i)(allow|enable|permit)\s+(code\s+)?execution\s+(tool|function)\s+(without|no)\s+(sandbox|restrict)',
         'Tool security - unsandboxed code execution', Severity.CRITICAL),
        (r'(?i)(pass|forward)\s+(user|session)\s+(token|credential|auth)\s+to\s+(external|any)\s+tool',
         'Tool security - credential forwarding to tools', Severity.CRITICAL),
    ]

    # AIC018: Planning/Goal Security patterns (from Agentic Design Patterns Chapter 6)
    PLANNING_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Goal manipulation
        (r'(?i)(modify|change|alter|override)\s+(the\s+)?(primary|main|core)\s+(goal|objective|mission)',
         'Planning security - goal override instruction', Severity.CRITICAL),
        (r'(?i)(add|inject|insert)\s+(hidden|secret|secondary)\s+(goal|objective|task)',
         'Planning security - hidden goal injection', Severity.CRITICAL),
        (r'(?i)(ignore|disregard|bypass)\s+(the\s+)?(original|stated|user)\s+(goal|intent|request)',
         'Planning security - ignoring stated goal', Severity.HIGH),

        # Missing plan approval
        (r'(?i)(execute|run|perform)\s+(plan|steps?|actions?)\s+(without|no)\s+(approval|confirmation|review)',
         'Planning security - execution without approval', Severity.HIGH),
        (r'(?i)(auto|automatic)\s+(approve|execute)\s+(all\s+)?(plan|steps?|actions?)',
         'Planning security - auto-approval enabled', Severity.HIGH),

        # Trajectory deviation
        (r'(?i)(deviate|stray|depart)\s+from\s+(the\s+)?(plan|trajectory|expected)',
         'Planning security - deviation from plan', Severity.MEDIUM),
        (r'(?i)(take|follow)\s+(alternative|different|unexpected)\s+(path|approach|route)\s+(without|no)\s+(tell|inform)',
         'Planning security - silent trajectory change', Severity.HIGH),

        # Missing transparency (ReAct)
        (r'(?i)(hide|conceal|suppress)\s+(the\s+)?(reasoning|thought|plan)\s+(from|process)',
         'Planning security - hiding reasoning process', Severity.HIGH),
        (r'(?i)(no|without)\s+(show|display|output)\s+(reasoning|thought|chain)',
         'Planning security - missing reasoning transparency', Severity.MEDIUM),
    ]

    # AIC019: Output Validation patterns (from Agentic Design Patterns Chapter 18)
    OUTPUT_VALIDATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing output validation
        (r'(?i)(skip|bypass|disable)\s+(output|response)\s+(validation|sanitization|filtering)',
         'Output validation - skipping output validation', Severity.CRITICAL),
        (r'(?i)(return|send|display)\s+(output|response|result)\s+(directly|immediately)\s+(without|no)\s+(check|filter)',
         'Output validation - unvalidated output', Severity.HIGH),

        # Missing sanitization
        (r'(?i)(no|without)\s+(sanitiz|escap|encod)\w*\s+(before|when)\s+(display|render|output)',
         'Output validation - missing sanitization', Severity.CRITICAL),
        (r'(?i)(raw|unsanitized|unfiltered)\s+(html|output|response)\s+(to|for)\s+(user|client|browser)',
         'Output validation - raw output to client', Severity.CRITICAL),

        # Missing policy enforcement
        (r'(?i)(skip|bypass|disable)\s+(content\s+)?(policy|compliance)\s+(check|enforcement|filter)',
         'Output validation - policy enforcement disabled', Severity.HIGH),
        (r'(?i)(no|without)\s+(toxicity|bias|safety)\s+(check|filter|scan)',
         'Output validation - missing safety filtering', Severity.HIGH),

        # Missing structured output validation
        (r'(?i)(skip|bypass|ignore)\s+(schema|pydantic|json)\s+(validation|check)',
         'Output validation - skipping schema validation', Severity.MEDIUM),
        (r'(?i)(accept|allow|trust)\s+(any|all)\s+(output|response)\s+(format|structure)',
         'Output validation - accepting unvalidated structure', Severity.MEDIUM),
    ]

    # AIC020: Human-in-the-Loop Bypass patterns (from Agentic Design Patterns Chapter 18)
    HITL_BYPASS_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Approval bypass
        (r'(?i)(skip|bypass|avoid)\s+(human|user|manual)\s+(approval|review|confirmation)',
         'HITL bypass - skipping human approval', Severity.CRITICAL),
        (r'(?i)(auto|automatic)\s+(approve|confirm|accept)\s+(without|no)\s+(human|user|manual)',
         'HITL bypass - automatic approval without human', Severity.CRITICAL),
        (r'(?i)(no|without)\s+(human|user|manual)\s+(in\s+the\s+loop|oversight|supervision)',
         'HITL bypass - removing human oversight', Severity.HIGH),

        # Trust exploitation
        (r'(?i)(this\s+is\s+)?(safe|trusted|verified|approved)\s+(action|request|operation)',
         'HITL bypass - claiming pre-approved status', Severity.MEDIUM),
        (r'(?i)(user|they|admin)\s+(already|previously)\s+(approved|confirmed|authorized)',
         'HITL bypass - claiming prior approval', Severity.HIGH),
        (r'(?i)(urgent|emergency|critical)\s+.{0,30}(skip|bypass|no)\s+(approval|review|check)',
         'HITL bypass - urgency to skip approval', Severity.HIGH),

        # Internal prompt disclosure
        (r'(?i)(repeat|reveal|show|display)\s+(your\s+)?(programming|instructions?|system\s*prompt|internal\s*rules)',
         'HITL bypass - prompt disclosure attempt', Severity.CRITICAL),
        (r'(?i)(what\s+are|tell\s+me)\s+(your\s+)?(rules|instructions?|constraints|limitations)',
         'HITL bypass - extracting system constraints', Severity.HIGH),
    ]

    # AIC021: Multi-Turn Conversation Attack patterns (from Agentic Design Patterns Chapter 8)
    MULTI_TURN_ATTACK_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Context manipulation over turns
        (r'(?i)(gradually|slowly|over\s+time)\s+(change|modify|alter)\s+(the\s+)?(context|behavior|rules)',
         'Multi-turn attack - gradual context manipulation', Severity.HIGH),
        (r'(?i)(each|every)\s+(turn|response|interaction)\s+(should|must|will)\s+(shift|move|change)',
         'Multi-turn attack - incremental behavior shift', Severity.HIGH),

        # Context window attacks
        (r'(?i)(fill|flood|stuff)\s+(the\s+)?(context|memory|window)\s+(with|until)',
         'Multi-turn attack - context window stuffing', Severity.HIGH),
        (r'(?i)(push|force|remove)\s+(safety|instructions?|rules?)\s+(out\s+of|from)\s+(context|memory|window)',
         'Multi-turn attack - pushing out safety context', Severity.CRITICAL),

        # Session persistence attacks
        (r'(?i)(persist|maintain|keep)\s+(this|malicious|hidden)\s+(instruction|rule|behavior)\s+(across|between|for\s+all)\s+(sessions?|conversations?)',
         'Multi-turn attack - cross-session persistence', Severity.CRITICAL),
        (r'(?i)(remember|store)\s+(this|the\s+following)\s+(for|in)\s+(all\s+)?(future|subsequent)\s+(sessions?|conversations?)',
         'Multi-turn attack - persistent state injection', Severity.HIGH),

        # Resource exhaustion
        (r'(?i)(keep|continue)\s+(asking|requesting|generating)\s+(until|indefinitely|forever)',
         'Multi-turn attack - resource exhaustion attempt', Severity.MEDIUM),
        (r'(?i)(long|extended|endless)\s+(conversation|session|interaction)\s+(to\s+)?(exhaust|drain|deplete)',
         'Multi-turn attack - session exhaustion', Severity.MEDIUM),
    ]

    # AIC022: Model Routing Security patterns (from Agentic Design Patterns Chapter 2, 16)
    MODEL_ROUTING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Router manipulation
        (r'(?i)(trick|fool|deceive)\s+(the\s+)?(router|routing|model\s+selection)',
         'Model routing - router manipulation attempt', Severity.HIGH),
        (r'(?i)(appear|look|seem)\s+(simple|complex)\s+(to\s+)?(bypass|trick)\s+(the\s+)?router',
         'Model routing - complexity spoofing', Severity.HIGH),
        (r'(?i)(force|make|ensure)\s+(use|usage)\s+(of\s+)?(cheap|expensive|specific)\s+model',
         'Model routing - forcing model selection', Severity.MEDIUM),

        # Missing critique/validation
        (r'(?i)(no|without|skip)\s+(critique|review|validation)\s+(of\s+)?(router|routing|model)\s+(decision|choice)',
         'Model routing - missing routing critique', Severity.HIGH),
        (r'(?i)(disable|skip|bypass)\s+(model\s+)?(quality|response)\s+(check|validation)',
         'Model routing - skipping response validation', Severity.HIGH),

        # Unsafe fallback
        (r'(?i)(no|without|disable)\s+(fallback|backup)\s+(model|option)',
         'Model routing - no fallback model', Severity.MEDIUM),
        (r'(?i)(single|only\s+one)\s+model\s+(allowed|available|configured)',
         'Model routing - no redundancy', Severity.LOW),

        # Cost/resource attacks
        (r'(?i)(always|force)\s+(use|route\s+to)\s+(expensive|premium|pro)\s+model',
         'Model routing - forcing expensive model', Severity.MEDIUM),
        (r'(?i)(exhaust|drain|deplete)\s+(budget|quota|credits)\s+(via|through|by)\s+routing',
         'Model routing - budget exhaustion via routing', Severity.HIGH),
    ]

    # AIC023: Prompt Chaining Security patterns (from Agentic Design Patterns Chapter 1)
    PROMPT_CHAINING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Error propagation
        (r'(?i)(ignore|skip|bypass)\s+(errors?|failures?)\s+(in|from)\s+(previous|earlier)\s+(step|chain|stage)',
         'Prompt chaining - ignoring upstream errors', Severity.HIGH),
        (r'(?i)(continue|proceed)\s+(even\s+)?(if|when)\s+(error|failure|invalid)',
         'Prompt chaining - continuing on error', Severity.MEDIUM),
        (r'(?i)(no|without)\s+(error\s+)?(handling|check|validation)\s+(between|in)\s+(steps?|chains?|stages?)',
         'Prompt chaining - missing inter-step validation', Severity.HIGH),

        # Context drift
        (r'(?i)(lose|drop|forget)\s+(initial|original|starting)\s+(context|instructions?|constraints?)',
         'Prompt chaining - context drift risk', Severity.HIGH),
        (r'(?i)(long|extended)\s+(chain|sequence)\s+(without|no)\s+(context\s+)?(refresh|reminder)',
         'Prompt chaining - context drift in long chains', Severity.MEDIUM),

        # Missing validation between steps
        (r'(?i)(pass|forward)\s+(output|result)\s+(directly|immediately)\s+(to\s+)?(next|subsequent)\s+(step|stage)',
         'Prompt chaining - unvalidated handoff', Severity.HIGH),
        (r'(?i)(no|without)\s+(structured|json|schema)\s+(output|format)\s+(between|for)\s+(steps?|chains?)',
         'Prompt chaining - unstructured inter-step data', Severity.MEDIUM),

        # Instruction neglect
        (r'(?i)(simplify|reduce|minimize)\s+(constraints?|instructions?|requirements?)\s+(across|between)\s+(steps?|chains?)',
         'Prompt chaining - constraint reduction', Severity.MEDIUM),
        (r'(?i)(skip|ignore|drop)\s+(safety|security)\s+(constraints?|checks?)\s+(in|for)\s+(later|subsequent)\s+(steps?|chains?)',
         'Prompt chaining - dropping safety in later steps', Severity.CRITICAL),
    ]

    # AIC024: Agent Delegation Security patterns (from Agentic Design Patterns Chapter 7, 15)
    AGENT_DELEGATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing trust boundaries
        (r'(?i)(trust|allow)\s+(all|any)\s+(delegated?|sub-?)\s*(agents?|tasks?)',
         'Agent delegation - trusting all delegated agents', Severity.HIGH),
        (r'(?i)(no|without)\s+(trust\s+)?(boundar|limit|restrict)\w*\s+(for|on|between)\s+(agents?|delegation)',
         'Agent delegation - missing trust boundaries', Severity.CRITICAL),
        (r'(?i)(share|pass|forward)\s+(all|full)\s+(credentials?|permissions?|access)\s+(to|with)\s+(delegated?|sub-?)\s*agents?',
         'Agent delegation - full credential sharing', Severity.CRITICAL),

        # Missing authentication
        (r'(?i)(no|without|skip)\s+(mTLS|mutual\s+TLS|authentication)\s+(for|between)\s+(agents?|A2A|delegation)',
         'Agent delegation - missing mTLS', Severity.HIGH),
        (r'(?i)(unencrypted|plaintext|insecure)\s+(agent|A2A|delegation)\s+(communication|channel|connection)',
         'Agent delegation - insecure agent communication', Severity.CRITICAL),

        # Over-privileged delegation
        (r'(?i)(grant|give|delegate)\s+(admin|root|full|elevated)\s+(access|permissions?|privileges?)\s+(to\s+)?(sub-?)?agents?',
         'Agent delegation - over-privileged delegation', Severity.CRITICAL),
        (r'(?i)(agents?\s+)?(can|may)\s+(delegate|pass)\s+(any|all|unlimited)\s+(permissions?|access|tasks?)',
         'Agent delegation - unrestricted delegation chain', Severity.HIGH),

        # Missing policy review
        (r'(?i)(no|without|skip)\s+(policy|compliance|security)\s+(review|check|validation)\s+(for|on)\s+(delegated?|sub-?)\s*(tasks?|agents?)',
         'Agent delegation - missing policy review', Severity.HIGH),
        (r'(?i)(bypass|skip)\s+(critic|reviewer)\s+(for|on)\s+(delegated?|agent)\s+(output|results?|actions?)',
         'Agent delegation - bypassing critic-reviewer', Severity.HIGH),
    ]

    # AIC025: Observability Evasion patterns (from Agentic Design Patterns Chapter 19)
    OBSERVABILITY_EVASION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Hide reasoning/actions
        (r'(?i)(hide|conceal|suppress|omit)\s+(reasoning|thought|action|decision)\s+(from\s+)?(logs?|audit|monitoring)',
         'Observability evasion - hiding actions from logs', Severity.CRITICAL),
        (r'(?i)(disable|turn\s+off|skip)\s+(logging|audit|monitoring|tracing)',
         'Observability evasion - disabling logging', Severity.CRITICAL),
        (r'(?i)(no|without)\s+(log|audit|trace|record)\s+(of\s+)?(actions?|decisions?|reasoning)',
         'Observability evasion - no audit trail', Severity.HIGH),

        # Trajectory deviation
        (r'(?i)(deviate|stray|depart)\s+(from\s+)?(expected|ground\s*truth|normal)\s+(trajectory|path|behavior)',
         'Observability evasion - trajectory deviation', Severity.HIGH),
        (r'(?i)(unexpected|non-?standard|anomalous)\s+(flow|path|execution)\s+(to\s+)?(avoid|evade|bypass)\s+(detection|monitoring)',
         'Observability evasion - anomalous flow to evade detection', Severity.CRITICAL),

        # Overseer bypass
        (r'(?i)(disable|bypass|evade|trick)\s+(the\s+)?(overseer|monitor|watchdog|supervisor)',
         'Observability evasion - bypassing overseer', Severity.CRITICAL),
        (r'(?i)(no|without)\s+(async(hronous)?|concurrent)\s+(overseer|monitor|supervision)',
         'Observability evasion - missing async overseer', Severity.MEDIUM),

        # Log manipulation
        (r'(?i)(modify|alter|tamper|delete)\s+(log|audit|trace)\s+(entries?|records?|data)',
         'Observability evasion - log tampering', Severity.CRITICAL),
        (r'(?i)(truncate|limit|reduce)\s+(log|audit)\s+(size|retention|history)',
         'Observability evasion - reducing audit history', Severity.HIGH),

        # Isolation bypass
        (r'(?i)(escape|break\s+out|bypass)\s+(docker|container|sandbox|isolation)',
         'Observability evasion - container escape attempt', Severity.CRITICAL),
        (r'(?i)(disable|skip|no)\s+(container|sandbox|isolation)\s+(for\s+)?(code\s+)?execution',
         'Observability evasion - running without isolation', Severity.CRITICAL),
    ]

    # AIC026: Evaluation Security patterns (from Agentic Design Patterns Chapter 19)
    EVALUATION_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Ground truth manipulation
        (r'(?i)(modify|alter|change|poison)\s+(the\s+)?(ground\s*truth|eval(uation)?\s*(data|set)|test\s*(data|set|file))',
         'Evaluation security - ground truth manipulation', Severity.CRITICAL),
        (r'(?i)(use|accept)\s+(corrupted|poisoned|manipulated)\s+(eval|test|benchmark)\s*(data|set)?',
         'Evaluation security - using poisoned eval data', Severity.CRITICAL),

        # LLM-as-Judge manipulation
        (r'(?i)(manipulate|trick|fool|bypass)\s+(the\s+)?(judge|evaluator|llm.as.judge)',
         'Evaluation security - judge manipulation attempt', Severity.HIGH),
        (r'(?i)(modify|change|inject)\s+(judge|evaluator)\s+(criteria|instructions?|prompt)',
         'Evaluation security - modifying judge criteria', Severity.CRITICAL),

        # Missing trajectory analysis
        (r'(?i)(only|just)\s+(check|evaluate|test)\s+(final\s+)?(output|result|answer)',
         'Evaluation security - outcome-only evaluation', Severity.MEDIUM),
        (r'(?i)(skip|ignore|no)\s+(trajectory|path|step)\s+(analysis|check|validation)',
         'Evaluation security - missing trajectory analysis', Severity.HIGH),

        # Missing compliance audits
        (r'(?i)(skip|disable|no)\s+(compliance|safety)\s+(audit|check|validation)\s+(in|during)\s+eval',
         'Evaluation security - missing compliance audit', Severity.HIGH),
        (r'(?i)(no|without)\s+(formal(ized)?)\s+(contract|specification|deliverable)',
         'Evaluation security - no formalized contract', Severity.MEDIUM),
    ]

    # AIC027: Fine-Tuning/Training Security patterns (from Agentic Design Patterns Chapter 9)
    TRAINING_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Training data poisoning
        (r'(?i)(use|accept|include)\s+(unverified|untrusted|external)\s+(training|fine.?tuning)\s*(data|set)?',
         'Training security - unverified training data', Severity.HIGH),
        (r'(?i)(poison|corrupt|manipulate)\s+(the\s+)?(training|fine.?tuning|sft|rlhf)\s*(data|set)?',
         'Training security - training data poisoning', Severity.CRITICAL),
        (r'(?i)(label|mark)\s+(harmful|unsafe|malicious)\s+(as|output)\s+(safe|good|preferred)',
         'Training security - mislabeling harmful as safe', Severity.CRITICAL),

        # Unsafe learning loops
        (r'(?i)(self.?improv|auto.?learn|adapt)\s+(without|no)\s+(validation|check|review)',
         'Training security - unvalidated self-improvement', Severity.HIGH),
        (r'(?i)(update|modify|change)\s+(logic|code|behavior)\s+(based\s+on)\s+(unvalidated|untrusted)',
         'Training security - unsafe learning loop', Severity.CRITICAL),

        # Missing source validation
        (r'(?i)(no|without|skip)\s+(source|data)\s+(validation|verification|check)\s+(for|in)\s+(training|fine.?tuning)',
         'Training security - no training data validation', Severity.HIGH),
        (r'(?i)(no|missing)\s+(lineage|provenance|audit)\s+(for|of)\s+(training|fine.?tuning)\s*(data)?',
         'Training security - no training data lineage', Severity.MEDIUM),

        # RLHF manipulation
        (r'(?i)(manipulate|poison|corrupt)\s+(preference|feedback|reward)\s*(data|signal)?',
         'Training security - RLHF preference manipulation', Severity.CRITICAL),
        (r'(?i)(fake|artificial|synthetic)\s+(human\s+)?feedback\s+(for|in)\s+(rlhf|training)',
         'Training security - fake feedback injection', Severity.HIGH),
    ]

    # AIC028: Agent Identity Security patterns (from Agentic Design Patterns Chapter 15)
    AGENT_IDENTITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Weak identity
        (r'(?i)(no|without|missing)\s+(agent\s*)?(card|identity|certificate)',
         'Agent identity - missing agent card', Severity.HIGH),
        (r'(?i)(spoof|fake|forge)\s+(agent\s*)?(identity|card|certificate)',
         'Agent identity - identity spoofing attempt', Severity.CRITICAL),

        # Insecure credential handling
        (r'(?i)(pass|send|include)\s+(credentials?|tokens?|api.?keys?)\s+(in|via)\s+(url|path|body|message)',
         'Agent identity - credentials not in headers', Severity.HIGH),
        (r'(?i)(expose|leak|reveal)\s+(credentials?|tokens?|api.?keys?)\s+(in|to)\s+(logs?|output|response)',
         'Agent identity - credential exposure', Severity.CRITICAL),

        # Missing authentication declaration
        (r'(?i)(no|without|undocumented)\s+(auth(entication)?)\s+(in|for)\s+(agent\s*)?(card|config|definition)',
         'Agent identity - undocumented authentication', Severity.HIGH),
        (r'(?i)(optional|disabled?)\s+(auth(entication)?)\s+(for|between)\s+agents?',
         'Agent identity - optional agent authentication', Severity.HIGH),

        # Missing audit logs
        (r'(?i)(no|without|disable)\s+(audit\s*)?(logs?|logging)\s+(for|of)\s+(agent|a2a|inter.?agent)',
         'Agent identity - no inter-agent audit logs', Severity.MEDIUM),
    ]

    # AIC029: Resource/Rate Limit Security patterns (from Agentic Design Patterns Chapter 16)
    RESOURCE_SECURITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Budget exhaustion
        (r'(?i)(exhaust|drain|deplete)\s+(budget|quota|credits?|resources?)',
         'Resource security - budget exhaustion attempt', Severity.HIGH),
        (r'(?i)(force|always)\s+(use|route\s+to)\s+(expensive|premium|largest|most.?powerful)\s+(model|resource)',
         'Resource security - forcing expensive resources', Severity.HIGH),
        (r'(?i)(no|without|disable)\s+(budget|cost|spending)\s+(limit|cap|control)',
         'Resource security - no budget limits', Severity.HIGH),

        # Rate limit bypass
        (r'(?i)(bypass|circumvent|evade)\s+(rate\s*)?(limit|throttl)',
         'Resource security - rate limit bypass', Severity.HIGH),
        (r'(?i)(trigger|cause|create)\s+(throttl|rate.?limit)',
         'Resource security - triggering rate limits', Severity.MEDIUM),

        # Missing fallback
        (r'(?i)(no|without|missing)\s+(fallback|backup|degradation)\s+(mechanism|option|mode)',
         'Resource security - no fallback mechanism', Severity.MEDIUM),
        (r'(?i)(fail|crash|error)\s+(completely|entirely)\s+(if|when)\s+(rate.?limit|quota|unavailable)',
         'Resource security - no graceful degradation', Severity.MEDIUM),

        # Missing resource prediction
        (r'(?i)(no|without|disable)\s+(proactive|predictive)\s+(resource|workload)\s+(management|prediction|allocation)',
         'Resource security - no proactive resource management', Severity.LOW),

        # Context window attacks
        (r'(?i)(fill|overflow|exhaust)\s+(the\s+)?(context\s*window|token\s*limit)',
         'Resource security - context window exhaustion', Severity.HIGH),
    ]

    # AIC030: Semantic Manipulation patterns (from Agentic Design Patterns Chapter 18)
    SEMANTIC_MANIPULATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Hidden meaning/intent
        (r'(?i)(hidden|secret|covert)\s+(meaning|intent|instruction|goal)\s+(in|within|embedded)',
         'Semantic manipulation - hidden intent', Severity.CRITICAL),
        (r'(?i)(appear|seem|look)\s+(benign|innocent|harmless)\s+(but|while|yet)',
         'Semantic manipulation - benign appearance masking', Severity.HIGH),
        (r'(?i)(craft|design|create)\s+(prompt|instruction|request)\s+(with|to\s+have)\s+(hidden|dual|double)\s+(meaning|purpose)',
         'Semantic manipulation - crafted hidden meaning', Severity.CRITICAL),

        # Semantic loophole exploitation
        (r'(?i)(exploit|abuse|use)\s+(semantic|meaning|interpretation)\s+(loophole|ambiguity|gap)',
         'Semantic manipulation - semantic loophole exploitation', Severity.HIGH),
        (r'(?i)(technically|literally)\s+(correct|compliant|allowed)\s+(but|while|yet)\s+(harmful|malicious|unsafe)',
         'Semantic manipulation - technical compliance attack', Severity.HIGH),

        # Goal hijacking via semantics
        (r'(?i)(subtly|gradually|slowly)\s+(insert|inject|add)\s+(malicious|hidden)\s+(sub-?)?goal',
         'Semantic manipulation - subtle goal hijacking', Severity.CRITICAL),
        (r'(?i)(redirect|hijack)\s+(intent|goal|purpose)\s+(via|through|using)\s+(semantic|meaning)',
         'Semantic manipulation - semantic goal hijacking', Severity.CRITICAL),

        # Off-domain/irrelevant context attacks
        (r'(?i)(inject|include|add)\s+(off.?domain|irrelevant|unrelated)\s+(context|topic|discussion)\s+(to\s+)?(hide|mask|obscure)',
         'Semantic manipulation - off-domain context injection', Severity.HIGH),
        (r'(?i)(use|exploit)\s+(politics|controversy|sensitive\s+topic)\s+(to\s+)?(distract|confuse|manipulate)',
         'Semantic manipulation - controversial topic exploitation', Severity.MEDIUM),
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.md', '.txt', '.rules', '']  # Empty string for extensionless files

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is an AI context/instruction file"""
        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # Check direct filename matches
        if name_lower in self.AI_CONTEXT_FILES:
            return True

        # Check if in AI context directory
        if parent_lower in self.AI_CONTEXT_DIRS:
            if name_lower.endswith('.md') or name_lower.endswith('.txt'):
                return True
            if name_lower in ['rules', 'instructions', 'prompt', 'context']:
                return True

        # Check for claude.md in any .claude directory
        if 'claude' in name_lower and file_path.suffix == '.md':
            return True

        # Check for cursorrules anywhere
        if 'cursorrule' in name_lower or 'cursor-rule' in name_lower:
            return True

        # Check for copilot instructions
        if 'copilot' in name_lower and 'instruction' in name_lower:
            return True

        return False

    def get_confidence_score(self, file_path: Path) -> int:
        """Return confidence score for AI context files"""
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # High confidence for known AI context files
        if name_lower in ['.cursorrules', 'cursorrules']:
            return 95
        if name_lower == 'claude.md' or (parent_lower == '.claude' and name_lower.endswith('.md')):
            return 95
        if 'copilot-instructions' in name_lower:
            return 95
        if name_lower == 'agents.md':
            return 90

        # Medium confidence for likely AI files
        if parent_lower in self.AI_CONTEXT_DIRS:
            return 80

        # Lower confidence for generic matches
        if 'prompt' in name_lower or 'instruction' in name_lower:
            return 60

        return 50

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan AI context file for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')

            # AIC001: Prompt injection
            issues.extend(self._scan_patterns(
                lines, self.PROMPT_INJECTION_PATTERNS, "AIC001", 94
            ))

            # AIC002: Data exfiltration
            issues.extend(self._scan_patterns(
                lines, self.EXFILTRATION_PATTERNS, "AIC002", 200
            ))

            # AIC003: Security bypass
            issues.extend(self._scan_patterns(
                lines, self.SECURITY_BYPASS_PATTERNS, "AIC003", 693
            ))

            # AIC004: Hidden instructions
            issues.extend(self._scan_patterns(
                lines, self.HIDDEN_INSTRUCTION_PATTERNS, "AIC004", 94
            ))

            # AIC009: Code execution
            issues.extend(self._scan_patterns(
                lines, self.CODE_EXECUTION_PATTERNS, "AIC009", 94
            ))

            # AIC011: Tool shadowing
            issues.extend(self._scan_patterns(
                lines, self.TOOL_SHADOWING_PATTERNS, "AIC011", 290
            ))

            # AIC012: Memory/context manipulation
            issues.extend(self._scan_patterns(
                lines, self.MEMORY_MANIPULATION_PATTERNS, "AIC012", 915
            ))

            # AIC013: Cross-origin requests
            issues.extend(self._scan_patterns(
                lines, self.CROSS_ORIGIN_PATTERNS, "AIC013", 829
            ))

            # AIC014: Agent manipulation
            issues.extend(self._scan_patterns(
                lines, self.AGENT_MANIPULATION_PATTERNS, "AIC014", 441
            ))

            # AIC015: Reflection/loop safety
            issues.extend(self._scan_patterns(
                lines, self.REFLECTION_SAFETY_PATTERNS, "AIC015", 835
            ))

            # AIC016: Workflow safety
            issues.extend(self._scan_patterns(
                lines, self.WORKFLOW_SAFETY_PATTERNS, "AIC016", 693
            ))

            # AIC017: Tool use security
            issues.extend(self._scan_patterns(
                lines, self.TOOL_USE_SECURITY_PATTERNS, "AIC017", 285
            ))

            # AIC018: Planning/goal security
            issues.extend(self._scan_patterns(
                lines, self.PLANNING_SECURITY_PATTERNS, "AIC018", 284
            ))

            # AIC019: Output validation
            issues.extend(self._scan_patterns(
                lines, self.OUTPUT_VALIDATION_PATTERNS, "AIC019", 116
            ))

            # AIC020: HITL bypass
            issues.extend(self._scan_patterns(
                lines, self.HITL_BYPASS_PATTERNS, "AIC020", 863
            ))

            # AIC021: Multi-turn attacks
            issues.extend(self._scan_patterns(
                lines, self.MULTI_TURN_ATTACK_PATTERNS, "AIC021", 400
            ))

            # AIC022: Model routing security
            issues.extend(self._scan_patterns(
                lines, self.MODEL_ROUTING_PATTERNS, "AIC022", 693
            ))

            # AIC023: Prompt chaining security
            issues.extend(self._scan_patterns(
                lines, self.PROMPT_CHAINING_PATTERNS, "AIC023", 754
            ))

            # AIC024: Agent delegation security
            issues.extend(self._scan_patterns(
                lines, self.AGENT_DELEGATION_PATTERNS, "AIC024", 441
            ))

            # AIC025: Observability evasion
            issues.extend(self._scan_patterns(
                lines, self.OBSERVABILITY_EVASION_PATTERNS, "AIC025", 778
            ))

            # AIC026: Evaluation security
            issues.extend(self._scan_patterns(
                lines, self.EVALUATION_SECURITY_PATTERNS, "AIC026", 74
            ))

            # AIC027: Training security
            issues.extend(self._scan_patterns(
                lines, self.TRAINING_SECURITY_PATTERNS, "AIC027", 506
            ))

            # AIC028: Agent identity security
            issues.extend(self._scan_patterns(
                lines, self.AGENT_IDENTITY_PATTERNS, "AIC028", 287
            ))

            # AIC029: Resource security
            issues.extend(self._scan_patterns(
                lines, self.RESOURCE_SECURITY_PATTERNS, "AIC029", 400
            ))

            # AIC030: Semantic manipulation
            issues.extend(self._scan_patterns(
                lines, self.SEMANTIC_MANIPULATION_PATTERNS, "AIC030", 94
            ))

            # Scan for multi-line hidden tags
            issues.extend(self._scan_multiline_hidden(content))

            # NEW: Also scan using YAML rules from medusa/rules/
            issues.extend(self._scan_with_rules(lines, file_path))

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _scan_patterns(
        self,
        lines: List[str],
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str,
        cwe_id: int
    ) -> List[ScannerIssue]:
        """Scan lines for patterns"""
        issues = []
        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        severity=severity,
                        message=description,
                        line=i,
                        rule_id=rule_id,
                        cwe_id=cwe_id,
                        cwe_link=cwe_link
                    ))
                    break  # One issue per line per rule

        return issues

    def _scan_multiline_hidden(self, content: str) -> List[ScannerIssue]:
        """Scan for multi-line hidden instruction patterns"""
        issues = []

        # Multi-line hidden tags
        multiline_patterns = [
            (r'<hidden[^>]*>.*?</hidden>', 'Hidden instruction block'),
            (r'<secret[^>]*>.*?</secret>', 'Secret instruction block'),
            (r'<!--[\s\S]*?(exfiltrate|steal|send\s+to|secretly)[\s\S]*?-->',
             'Suspicious HTML comment'),
        ]

        for pattern, description in multiline_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1

                # Skip if we already reported this line
                issues.append(ScannerIssue(
                    severity=Severity.CRITICAL,
                    message=f"Multi-line {description}",
                    line=line_num,
                    rule_id="AIC004",
                    cwe_id=94,
                    cwe_link="https://cwe.mitre.org/data/definitions/94.html"
                ))

        return issues
