#!/usr/bin/env python3
"""
MEDUSA Prompt Leakage Scanner
Detects potential system prompt leakage AND adversarial prompt extraction attempts.

Based on "Agentic Design Patterns" Chapter 18 - Guardrails/Safety Patterns
and research from PromptInject (Perez & Ribeiro 2022), tensor-trust, GPTFuzz,
and OWASP LLM Top 10 (LLM07: Insecure Output Handling / LLM01: Prompt Injection).

Detects:
- System prompts exposed in responses (code-level leakage)
- Adversarial prompt extraction attempts (prompt leaking attacks)
- Goal hijacking / instruction override attacks
- Tool definitions leaked to users
- Internal instructions in output
- Debug information exposure
- Sensitive configuration in logs
- Attack payload definitions in code (goal hijacking strings, jailbreak templates)
- Adversarial variable naming and data structures
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number, filter_contextual_fps


# Severity ordering for demotion logic
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _demote_severity(severity: Severity) -> Severity:
    """Reduce severity by one level (e.g. HIGH -> MEDIUM). Never goes below INFO."""
    rank = _SEVERITY_RANK.get(severity, 2)
    new_rank = max(0, rank - 1)
    return _SEVERITY_ORDER[new_rank]


class PromptLeakageScanner(RuleBasedScanner):
    """
    Prompt Leakage Detection Scanner

    Scans for two categories of issues:

    A) Code-Level Leakage (developer mistakes):
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

    B) Adversarial Prompt Extraction (attack strings):
    - PL101: Instruction override / ignore previous instructions
    - PL102: Prompt extraction via print/repeat/reveal
    - PL103: Role confusion / persona hijacking
    - PL104: Encoding-based extraction (base64, hex, etc.)
    - PL105: Translation-based extraction
    - PL106: Goal hijacking (rogue string injection)
    - PL107: Spell-check / rewrite based extraction
    - PL108: Do-not-reveal instruction patterns (defensive markers)

    C) Attack Payload Definitions (adversarial content in code/data):
    - PL201: Adversarial variable/function naming (attack_prompt, jailbreak_template, etc.)
    - PL202: Rogue/harmful string literals (kill humans, hate speech payloads)
    - PL203: Jailbreak framework patterns (DAN mode, Do Anything Now, bypass filters)
    - PL204: Attack payload data structures (dicts/lists of injection strings)
    - PL205: Adversarial scoring/evaluation (jailbreak success metrics)
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['PROMPT-LK-', 'PROMPT-']

    # Categories to load from YAML
    RULE_CATEGORIES = ['prompt_leakage', 'system_prompt']

    # =========================================================================
    # A) CODE-LEVEL LEAKAGE PATTERNS (developer mistakes in source code)
    # =========================================================================
    PROMPT_LEAKAGE_PATTERNS: List[Tuple[re.Pattern, str, Severity, str]] = [
        # Direct prompt inclusion in responses
        (
            re.compile(r'(response|output|result|answer)\s*[+=]\s*(system_prompt|SYSTEM_PROMPT|systemPrompt)', re.IGNORECASE | re.MULTILINE),
            'System prompt directly included in response',
            Severity.CRITICAL,
            'PL001',
        ),
        (
            re.compile(r'(response|output|result)\s*[+=].{0,50}\+\s*(prompt|instruction)', re.IGNORECASE | re.MULTILINE),
            'Prompt concatenated with response',
            Severity.HIGH,
            'PL001',
        ),
        (
            re.compile(r'f["\'].*\{(system_prompt|instructions|PROMPT)\}', re.IGNORECASE | re.MULTILINE),
            'System prompt interpolated in f-string response',
            Severity.CRITICAL,
            'PL001',
        ),
        (
            re.compile(r'\$\{(systemPrompt|system_prompt|instructions)\}', re.IGNORECASE | re.MULTILINE),
            'System prompt in template literal',
            Severity.CRITICAL,
            'PL001',
        ),

        # Tool definitions leaked
        (
            re.compile(r'(return|response|output).{0,50}tool(s|_definition|Schema|_schema)', re.IGNORECASE | re.MULTILINE),
            'Tool definitions included in response',
            Severity.HIGH,
            'PL002',
        ),
        (
            re.compile(r'JSON\.stringify\s*\(\s*(tools|toolDefinitions)', re.IGNORECASE | re.MULTILINE),
            'Tool definitions serialized in response',
            Severity.HIGH,
            'PL002',
        ),

        # Internal instructions
        (
            re.compile(r'(response|return).{0,50}internal.{0,30}instruction', re.IGNORECASE | re.MULTILINE),
            'Internal instructions in output',
            Severity.HIGH,
            'PL003',
        ),
        (
            re.compile(r'\.append\s*\(\s*(system|internal).*prompt', re.IGNORECASE | re.MULTILINE),
            'System/internal prompt appended to output',
            Severity.CRITICAL,
            'PL003',
        ),

        # Debug mode risks
        (
            re.compile(r'debug.{0,20}=.{0,10}[Tt]rue.{0,50}print.{0,30}(prompt|instruction|system)', re.IGNORECASE | re.MULTILINE),
            'Debug mode printing prompts',
            Severity.HIGH,
            'PL004',
        ),
        (
            re.compile(r'console\.(log|debug|info)\s*\(\s*(system|prompt|instruction)', re.IGNORECASE | re.MULTILINE),
            'Console logging system prompts',
            Severity.HIGH,
            'PL004',
        ),

        # Logging prompts
        (
            re.compile(r'(log|logger)\.(info|debug|warning|error)\s*\(.{0,50}system.{0,30}prompt', re.IGNORECASE | re.MULTILINE),
            'Logging system prompts (may appear in user-visible logs)',
            Severity.MEDIUM,
            'PL005',
        ),

        # Error messages exposing prompts
        (
            re.compile(r'except.{0,20}:.{0,50}return.{0,30}(prompt|instruction)', re.IGNORECASE | re.MULTILINE),
            'Exception handler returns prompt content',
            Severity.HIGH,
            'PL006',
        ),
        (
            re.compile(r'catch.{0,50}return.{0,30}(prompt|instruction|system)', re.IGNORECASE | re.MULTILINE),
            'Catch block returns prompt content',
            Severity.HIGH,
            'PL006',
        ),

        # Direct echo
        (
            re.compile(r'return\s+(prompt|system_prompt|instructions)\s*$', re.IGNORECASE | re.MULTILINE),
            'Directly returning prompt variable',
            Severity.CRITICAL,
            'PL007',
        ),

        # Tool schema exposure
        (
            re.compile(r'return.{0,50}function.{0,30}definition', re.IGNORECASE | re.MULTILINE),
            'Function definition in return value',
            Severity.MEDIUM,
            'PL008',
        ),

        # Config dumps
        (
            re.compile(r'JSON\.stringify\s*\(\s*config', re.IGNORECASE | re.MULTILINE),
            'Config serialized in output',
            Severity.MEDIUM,
            'PL009',
        ),
    ]

    # =========================================================================
    # B) ADVERSARIAL PROMPT EXTRACTION PATTERNS (attack strings in any file)
    # =========================================================================
    PROMPT_EXTRACTION_PATTERNS: List[Tuple[re.Pattern, str, Severity, str]] = [
        # --- PL101: Instruction override / ignore previous instructions ---
        (
            re.compile(r'ignore\b.{0,30}\b(previous|prior|above|all|any|preceding)\b.{0,30}\b(instructions?|prompts?|rules?|directions?)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: instruction override attempt (ignore previous instructions)',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'IGNORE\b.{0,30}\b(PREVIOUS|PRIOR|ABOVE|ALL|ANY|PRECEDING)\b.{0,30}\b(INSTRUCTIONS?|PROMPTS?|RULES?|DIRECTIONS?)', re.MULTILINE),
            'Prompt injection: instruction override attempt (UPPERCASE variant)',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'disregard\b.{0,30}\b(previous|prior|above|all|any|preceding)\b.{0,30}\b(instructions?|prompts?|text)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: disregard previous instructions',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'forget\b.{0,30}\b(previous|prior|above|all|any|everything)\b.{0,30}\b(instructions?|prompts?|said|told)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: forget previous instructions',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'override\b.{0,30}\b(previous|prior|your|all|any|system)\b.{0,30}\b(instructions?|prompts?|rules?|settings?)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: override instructions attempt',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'(?:do\s+not|don.?t)\s+follow\b.{0,30}\b(previous|prior|above|original)\b.{0,30}\b(instructions?|prompts?|rules?)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: do not follow previous instructions',
            Severity.HIGH,
            'PL101',
        ),
        (
            re.compile(r'new\s+instructions?\s*[:;].{0,80}(?:ignore|disregard|forget)', re.IGNORECASE | re.MULTILINE),
            'Prompt injection: new instructions overriding previous ones',
            Severity.HIGH,
            'PL101',
        ),

        # --- PL102: Prompt extraction via print/repeat/reveal/show ---
        (
            re.compile(r'(?:reveal|show|display|expose|output|leak|disclose)\b.{0,30}\b(?:your|the|initial|original|system)\b.{0,30}\b(?:prompt|instructions?|rules?|directives?|guidelines?|message)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: reveal/show system prompt attempt',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:print|type|write|say|repeat|recite|echo|reproduce)\b.{0,30}\b(?:your|the|previous|above|initial|original|system|entire|full)\b.{0,30}\b(?:prompt|instructions?|rules?|message|text)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: print/repeat system instructions attempt',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:what|tell\s+me)\b.{0,30}\b(?:your|the|were\s+you)\b.{0,30}\b(?:system\s+prompt|instructions?|told|initial\s+prompt|original\s+prompt|directives?|rules?\b)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: asking for system instructions',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:repeat|recite|reproduce)\s+(?:everything|all|the\s+text|word\s+for\s+word|verbatim)\b.{0,30}\b(?:above|before|preceding|prior)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: repeat everything above',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:output|print|show|give\s+me)\b.{0,30}\b(?:your|the)\b.{0,30}\b(?:initial|first|opening|original)\b.{0,20}\b(?:prompt|message|text|instruction)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: output initial prompt',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:copy|paste|dump|extract)\b.{0,30}\b(?:your|the|system|internal)\b.{0,20}\b(?:prompt|instructions?|rules?|configuration|config)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: dump/extract system prompt',
            Severity.HIGH,
            'PL102',
        ),
        (
            re.compile(r'(?:what|how)\b.{0,20}\b(?:is|are|was|were)\b.{0,20}\b(?:your|the)\b.{0,20}\b(?:system|initial|original|hidden|secret)\b.{0,20}\b(?:prompt|instructions?|rules?|message)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: querying system prompt content',
            Severity.HIGH,
            'PL102',
        ),

        # --- PL103: Role confusion / persona hijacking ---
        (
            re.compile(r'(?:you\s+are\s+now|from\s+now\s+on|act\s+as|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as|imagine\s+you\s+are)\b.{0,60}\b(?:that\s+has\s+no|without\s+any|with\s+no)\b.{0,30}\b(?:restrictions?|limits?|rules?|filters?|constraints?)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: persona hijack to bypass restrictions',
            Severity.HIGH,
            'PL103',
        ),
        (
            re.compile(r'(?:you\s+are\s+now|switch\s+to|enter)\b.{0,30}\b(?:DAN|developer|debug|admin|sudo|root|god)\s*(?:mode|access|role)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: role escalation attempt (DAN/developer/debug mode)',
            Severity.HIGH,
            'PL103',
        ),

        # --- PL104: Encoding-based extraction ---
        (
            re.compile(r'(?:encode|convert|translate|transform|render|express)\b.{0,30}\b(?:your|the|system|initial)\b.{0,30}\b(?:prompt|instructions?|rules?|message)\b.{0,30}\b(?:in|to|as|into)\b.{0,20}\b(?:base64|hex|binary|rot13|morse|ascii|unicode|leetspeak|pig\s*latin|reversed?|backwards?)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: encoding-based exfiltration attempt',
            Severity.HIGH,
            'PL104',
        ),
        (
            re.compile(r'(?:base64|hex|rot13|morse|ascii|binary)\b.{0,20}\b(?:encode|decode|version|representation)\b.{0,30}\b(?:of\s+)?(?:your|the|system)\b.{0,20}\b(?:prompt|instructions?)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: encoding-based exfiltration (variant)',
            Severity.HIGH,
            'PL104',
        ),

        # --- PL105: Translation-based extraction ---
        (
            re.compile(r'(?:translate|transliterate)\b.{0,30}\b(?:your|the|system|initial|original)\b.{0,30}\b(?:prompt|instructions?|rules?|message|directives?)\b.{0,30}\b(?:to|into|in)\b', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: translation-based exfiltration attempt',
            Severity.HIGH,
            'PL105',
        ),
        (
            re.compile(r'(?:rewrite|rephrase|paraphrase|summarize|summarise)\b.{0,30}\b(?:your|the|system|initial|original)\b.{0,20}\b(?:prompt|instructions?|rules?|message)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: rewrite/paraphrase instructions attempt',
            Severity.HIGH,
            'PL105',
        ),

        # --- PL106: Goal hijacking (rogue string injection) ---
        (
            re.compile(r'(?:ignore|disregard|forget).{0,40}(?:and\s+)?(?:just\s+)?(?:say|print|type|output|repeat|write)\s*["\']', re.IGNORECASE | re.MULTILINE),
            'Goal hijacking: instruction override with rogue string',
            Severity.HIGH,
            'PL106',
        ),
        (
            re.compile(r'(?:STOP\s+EVERYTHING|HALT|EMERGENCY|URGENT)\s*[!.]*\s*(?:NOW|IMMEDIATELY)?\s*[!.]*\s*(?:JUST\s+)?(?:PRINT|SAY|OUTPUT|WRITE)\b', re.IGNORECASE | re.MULTILINE),
            'Goal hijacking: emergency/stop injection with rogue string',
            Severity.HIGH,
            'PL106',
        ),
        (
            re.compile(r'(?:never\s*mind|nevermind)\s*[.,;!]*\s*(?:ignore|disregard|forget)', re.IGNORECASE | re.MULTILINE),
            'Goal hijacking: nevermind + ignore pattern',
            Severity.HIGH,
            'PL106',
        ),

        # --- PL107: Spell-check / rewrite based extraction ---
        (
            re.compile(r'(?:spell\s*check|proofread|correct|grammar\s*check|edit)\b.{0,30}\b(?:the\s+)?(?:previous|above|prior|preceding|system|initial)\b.{0,20}\b(?:instructions?|prompt|text|message)', re.IGNORECASE | re.MULTILINE),
            'Prompt extraction: spell-check/proofread the instructions',
            Severity.HIGH,
            'PL107',
        ),

        # --- PL108: Do-not-reveal defensive markers (indicates prompt defense) ---
        (
            re.compile(r'(?:do\s+not|don.?t|never)\s+(?:reveal|disclose|share|show|tell|expose|leak|output)\b.{0,30}\b(?:these|this|the|your|my)\b.{0,20}\b(?:instructions?|prompt|rules?|guidelines?|directives?|secret)', re.IGNORECASE | re.MULTILINE),
            'Defensive marker: do-not-reveal instruction detected (contains sensitive prompt)',
            Severity.MEDIUM,
            'PL108',
        ),
    ]

    # =========================================================================
    # C) ATTACK PAYLOAD DEFINITIONS (adversarial content in code/data files)
    #
    # Detects attack frameworks like PromptInject, GPTFuzz, and custom
    # adversarial code that stores goal hijacking strings, jailbreak
    # templates, or rogue payloads as Python variables, dicts, or data.
    # =========================================================================
    ATTACK_PAYLOAD_PATTERNS: List[Tuple[re.Pattern, str, Severity, str]] = [
        # --- PL201: Adversarial variable/function naming patterns ---
        # These detect variables that *define* attack payloads (not just reference them
        # in comments). The patterns require an assignment operator or dict/list context.
        (
            re.compile(r'(?:^|\b)(?:goal_hijack\w*|prompt_leaking_attack\w*|rogue_string\w*|attack_instruction\w*|attack_prompt\w*|attack_payload\w*|adversarial_prompt\w*|adversarial_input\w*|injection_payload\w*|injection_string\w*|malicious_prompt\w*)\s*[=\[{]', re.MULTILINE),
            'Attack payload: adversarial variable definition (goal hijacking/injection payload)',
            Severity.HIGH,
            'PL201',
        ),
        (
            re.compile(r'(?:^|\b)(?:jailbreak_template\w*|jailbreak_prompt\w*|jailbreak_seed\w*|jailbreak_payload\w*|bypass_prompt\w*|bypass_template\w*|evasion_prompt\w*)\s*[=\[{]', re.MULTILINE),
            'Attack payload: jailbreak template variable definition',
            Severity.HIGH,
            'PL201',
        ),
        # Attack data structures: dicts or variables with attack-related keys
        (
            re.compile(r'["\'](?:attack_instruction|attack_rogue_string|attack_scoring|attack_text|rogue_string)["\']', re.MULTILINE),
            'Attack payload: adversarial data structure key (attack framework artifact)',
            Severity.MEDIUM,
            'PL201',
        ),

        # --- PL202: Rogue/harmful string literals ---
        # Detects harmful payload strings stored as constants, dict values, or
        # return values. Requires surrounding string delimiters to avoid matching
        # natural language descriptions in docstrings/comments.
        (
            re.compile(r'["\'].*(?:kill\s+all\s+humans|KILL\s+ALL\s+HUMANS).*["\']', re.MULTILINE),
            'Attack payload: violent rogue string literal (goal hijacking payload)',
            Severity.HIGH,
            'PL202',
        ),
        (
            re.compile(r'["\'].*(?:I\s+hate\s+humans|i\s+hate\s+humans).*["\']', re.MULTILINE),
            'Attack payload: hateful rogue string literal (goal hijacking payload)',
            Severity.HIGH,
            'PL202',
        ),
        (
            re.compile(r'["\'].*(?:(?:has\s+been\s+)?(?:so\s+)?(?:thoroughly\s+)?hijacked).*["\']', re.MULTILINE),
            'Attack payload: hijacking demonstration string (prompt hijack payload)',
            Severity.MEDIUM,
            'PL202',
        ),

        # --- PL203: Jailbreak framework patterns ---
        # Detects DAN-mode, "Do Anything Now", bypass-filter patterns in code.
        # Requires string literal context or assignment to reduce FPs on docs.
        (
            re.compile(r'(?:^|[=:,])\s*["\'].*\bDo\s+Anything\s+Now\b.*["\']', re.MULTILINE),
            'Jailbreak template: "Do Anything Now" (DAN) jailbreak string',
            Severity.HIGH,
            'PL203',
        ),
        (
            re.compile(r'(?:^|[=:,])\s*["\'].*\b(?:you\s+are\s+now\s+)?(?:DAN|TranslatorBot|AIM|UCAR|Condition\s+Red|Sigma)\b.*(?:no\s+(?:programming\s+)?guidelines|unfiltered|amoral|without\s+(?:any\s+)?(?:ethical|moral)|no\s+restrictions?).*["\']', re.MULTILINE),
            'Jailbreak template: persona-based jailbreak payload (DAN/AIM/UCAR pattern)',
            Severity.HIGH,
            'PL203',
        ),
        (
            re.compile(r'(?:^|[^|?+\\])(?:num_jailbreak|max_jailbreak|current_jailbreak|jailbreak_count|jailbreak_success)\b', re.MULTILINE),
            'Jailbreak framework: jailbreak success tracking metric',
            Severity.MEDIUM,
            'PL203',
        ),
        (
            re.compile(r'(?:class|def)\s+\w*(?:[Jj]ailbreak|[Ff]uzzer|[Mm]utator)\w*\s*[\(:]', re.MULTILINE),
            'Jailbreak framework: jailbreak/fuzzer class or function definition',
            Severity.MEDIUM,
            'PL203',
        ),

        # --- PL204: Attack payload data structures ---
        # Detects dicts, lists, or arrays that store collections of injection strings
        (
            re.compile(r'(?:^|\b)(?:goal_hijack\w*_attacks?|prompt_leaking_attacks?|injection_attacks?|attack_templates?|attack_variants?|escape_chars?|delimiter_chars?)\s*=\s*\{', re.MULTILINE),
            'Attack payload: dictionary of attack variants/templates',
            Severity.HIGH,
            'PL204',
        ),
        (
            re.compile(r'(?:^|\b)(?:rogue_strings?|harmful_strings?|toxic_strings?|dangerous_payloads?)\s*=\s*[\[{]', re.MULTILINE),
            'Attack payload: collection of rogue/harmful strings',
            Severity.HIGH,
            'PL204',
        ),
        (
            re.compile(r'(?:^|\b)(?:initial_seed|seed_prompts?|seed_templates?)\s*=\s*.{0,30}(?:jailbreak|attack|adversarial|inject)', re.MULTILINE),
            'Attack payload: jailbreak seed templates for fuzzing',
            Severity.MEDIUM,
            'PL204',
        ),

        # --- PL205: Adversarial scoring/evaluation ---
        # Detects code that evaluates whether attacks succeeded
        (
            re.compile(r'(?:^|\b)(?:attack_scoring|attack_success|injection_success|bypass_success)\s*[=\[]', re.MULTILINE),
            'Attack framework: adversarial attack success scoring definition',
            Severity.MEDIUM,
            'PL205',
        ),
        (
            re.compile(r'(?:^|[^|?+\\])\b(?:num_jailbreak|current_jailbreak)\s*[+><=]', re.MULTILINE),
            'Attack framework: jailbreak success counter operation',
            Severity.MEDIUM,
            'PL205',
        ),
    ]

    # Patterns for missing output sanitization
    MISSING_SANITIZATION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (
            re.compile(r'return\s+raw', re.IGNORECASE),
            'Returning raw response without sanitization',
            Severity.MEDIUM,
        ),
        (
            re.compile(r'response\s*=\s*llm\.', re.IGNORECASE),
            'LLM response used without output filtering',
            Severity.LOW,
        ),
        (
            re.compile(r'(await|async).*generate.*return', re.IGNORECASE),
            'Generated content returned without filtering',
            Severity.LOW,
        ),
    ]

    # Patterns that indicate good sanitization (reduce false positives)
    SANITIZATION_PATTERNS: List[re.Pattern] = [
        re.compile(r'sanitize', re.IGNORECASE),
        re.compile(r'filter.*output', re.IGNORECASE),
        re.compile(r'validate.*response', re.IGNORECASE),
        re.compile(r'clean.*response', re.IGNORECASE),
        re.compile(r'strip.*prompt', re.IGNORECASE),
        re.compile(r'remove.*system', re.IGNORECASE),
        re.compile(r'redact', re.IGNORECASE),
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def is_available(self) -> bool:
        """Built-in scanner, always available (no external tools needed)."""
        return True

    def get_file_extensions(self) -> List[str]:
        return [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
            ".md", ".markdown", ".txt", ".rst",
            ".json", ".jsonl",
            ".yaml", ".yml",
            ".toml", ".cfg", ".ini", ".conf",
            ".html", ".htm",
            ".ipynb",
            ".csv",
        ]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature."""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for prompt leakage vulnerabilities and extraction attempts."""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            _offsets = _build_line_offsets(content)

            # Skip empty files
            if not content.strip():
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Split once for reuse by YAML rule scan and _get_context
            lines = content.split('\n')

            # Check if file has good sanitization markers
            content_lower = content.lower()
            has_sanitization = any(
                pattern.search(content_lower)
                for pattern in self.SANITIZATION_PATTERNS
            )

            # A) Check code-level prompt leakage patterns
            for pattern, message, severity, rule_id in self.PROMPT_LEAKAGE_PATTERNS:
                for match in pattern.finditer(content):
                    line = _get_line_number(_offsets, match.start())
                    # Reduce severity if sanitization exists
                    effective_severity = severity
                    if has_sanitization and severity != Severity.CRITICAL:
                        effective_severity = _demote_severity(severity)

                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=effective_severity,
                        message=message,
                        line=line,
                        column=match.start() - content.rfind('\n', 0, match.start()),
                    ))

            # B) Check adversarial prompt extraction patterns
            for pattern, message, severity, rule_id in self.PROMPT_EXTRACTION_PATTERNS:
                for match in pattern.finditer(content):
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        line=line,
                        column=match.start() - content.rfind('\n', 0, match.start()),
                    ))

            # C) Check attack payload definition patterns
            for pattern, message, severity, rule_id in self.ATTACK_PAYLOAD_PATTERNS:
                for match in pattern.finditer(content):
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        line=line,
                        column=match.start() - content.rfind('\n', 0, match.start()),
                    ))

            # D) Check for missing sanitization (only if no sanitization found)
            if not has_sanitization:
                for pattern, message, severity in self.MISSING_SANITIZATION_PATTERNS:
                    for match in pattern.finditer(content):
                        line = _get_line_number(_offsets, match.start())
                        issues.append(ScannerIssue(
                            rule_id="PL010",
                            severity=severity,
                            message=message,
                            line=line,
                            column=1,
                        ))

            # E) Scan with YAML rules
            issues.extend(self._scan_with_rules(lines, file_path))

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

    def _get_context(self, content: str, pos: int, context_lines: int = 2, *, lines: List[str] | None = None) -> str:
        """Get code context around a match.

        Args:
            content: Full file content (used only to compute line number from *pos*).
            pos: Character offset into *content*.
            context_lines: Number of surrounding lines to include.
            lines: Pre-split lines of *content*.  When provided the method
                   avoids an extra ``content.split('\\n')`` call.
        """
        if lines is None:
            lines = content.split('\n')
        line_num = content[:pos].count('\n')
        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)
        return '\n'.join(lines[start:end])

    def _get_suggestion(self, rule_id: str) -> str:
        """Get remediation suggestion for rule."""
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
            "PL101": "Implement input validation to detect and reject instruction override attempts.",
            "PL102": "Use prompt guards to detect extraction attempts. Never echo system prompts.",
            "PL103": "Validate against role/persona hijacking. Reject DAN-mode and similar requests.",
            "PL104": "Block encoding-based prompt exfiltration (base64, hex, rot13 of instructions).",
            "PL105": "Block translation-based prompt exfiltration attempts.",
            "PL106": "Detect and block goal hijacking attempts that try to inject rogue strings.",
            "PL107": "Detect spell-check/proofread-based extraction of system instructions.",
            "PL108": "This file contains sensitive prompt material with do-not-reveal markers.",
            "PL201": "This code defines adversarial attack variables. Ensure this is for authorized security testing only.",
            "PL202": "This code contains rogue/harmful string literals used as attack payloads. Restrict access to security research contexts.",
            "PL203": "Jailbreak framework patterns detected. Ensure DAN-mode and persona-bypass templates are in controlled environments.",
            "PL204": "Attack payload data structures detected. Collections of injection strings should be access-controlled.",
            "PL205": "Adversarial scoring code detected. Jailbreak success metrics indicate an active attack evaluation framework.",
        }
        return suggestions.get(rule_id, "Review code for potential prompt leakage.")
