#!/usr/bin/env python3
"""
MEDUSA Prompt Injection Code Scanner
Detects unsanitized user input concatenated directly into LLM API calls

This is the #1 AI-specific detection gap: when user input is passed directly
into LLM API calls via f-strings, string concatenation, or .format(), it
creates prompt injection vulnerabilities.

Detects patterns in:
- OpenAI API calls (openai.chat.completions.create, ChatOpenAI)
- Anthropic API calls (anthropic.messages.create, ChatAnthropic)
- LangChain calls (llm.invoke, llm(), ChatOpenAI, HumanMessage with f-strings)
- LlamaIndex calls
- Generic LLM calls with user input interpolation
- Direct string concatenation into prompt variables passed to LLM functions

Based on:
- OWASP LLM01: Prompt Injection
- CWE-94: Improper Control of Generation of Code
- CWE-77: Command Injection (adapted for prompt context)
"""

import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number


class PromptInjectionCodeScanner(BaseScanner):
    """
    Prompt Injection Code Scanner

    Detects unsanitized user input directly concatenated or interpolated
    into LLM API calls in Python source code.

    Rule IDs:
    - PIC001: User input in f-string passed to LLM API call
    - PIC002: String concatenation of user input into prompt/LLM call
    - PIC003: User input in .format() passed to LLM call
    - PIC004: Unsanitized variable in HumanMessage/SystemMessage content
    - PIC005: Direct request/input data in LLM completion call
    - PIC006: LangChain chain/agent with unsanitized user input
    - PIC007: Generic LLM function call with f-string/concat user input
    - PIC008: Prompt variable built from user input then passed to LLM
    """

    # ---------------------------------------------------------------
    # Indicators that a file involves LLM / AI usage
    # Only specific library/API names - NOT generic verbs like
    # 'invoke', 'generate', 'predict' which match non-LLM code
    # ---------------------------------------------------------------
    LLM_INDICATORS = [
        'openai', 'anthropic', 'langchain', 'llama_index', 'llamaindex',
        'chatgpt', 'claude', 'gemini', 'cohere', 'huggingface',
        'chat_model', 'chatmodel',
        'ChatOpenAI', 'ChatAnthropic', 'ChatGoogle',
        'BaseChatModel', 'HumanMessage', 'SystemMessage', 'AIMessage',
        'Llama', 'llama_cpp', 'ollama', 'groq', 'mistral',
        'ChatCompletion', 'chat.completions',
        'llm.invoke', 'llm(', 'chain.invoke',
        'agenerate', 'achat',
    ]

    # ---------------------------------------------------------------
    # Tokens that indicate user-controlled input
    # Split into HIGH (explicitly user-named) and LOW (generic)
    # confidence tiers to reduce false positives on common variable
    # names like 'message', 'data', 'content' which appear everywhere
    # ---------------------------------------------------------------
    HIGH_CONFIDENCE_INPUT_TOKENS = [
        'user_input', 'user_message', 'user_query', 'user_text',
        'user_prompt', 'user_request', 'user_data', 'user_content',
        'user_msg', 'user_question',
    ]

    LOW_CONFIDENCE_INPUT_TOKENS = [
        'request', 'query', 'question', 'message', 'text', 'input',
        'body', 'data', 'prompt', 'content', 'instruction',
        'msg', 'req', 'payload',
    ]

    # Combined for patterns that already have strong LLM context
    USER_INPUT_TOKENS = HIGH_CONFIDENCE_INPUT_TOKENS + LOW_CONFIDENCE_INPUT_TOKENS

    # Build regex alternations
    _USER_INPUT_RE = '|'.join(USER_INPUT_TOKENS)
    _HIGH_CONF_INPUT_RE = '|'.join(HIGH_CONFIDENCE_INPUT_TOKENS)

    # ---------------------------------------------------------------
    # Non-prompt context patterns - lines matching these are building
    # logs, cost entries, narratives, or data structures, NOT prompts
    # ---------------------------------------------------------------
    NON_PROMPT_CONTEXTS: List[re.Pattern] = [
        re.compile(r'^\s*(?:log|logger|logging)\.', re.IGNORECASE),                # log.info(f"...")
        re.compile(r'^\s*print\s*\(', re.IGNORECASE),                              # print(f"...")
        re.compile(r'^\s*(?:return\s+)?\{', re.IGNORECASE),                        # return {"key": f"..."}
        re.compile(r'(?:cost|price|token|usage|billing)', re.IGNORECASE),           # cost tracking
        re.compile(r'(?:narrative|summary|description|report)\s*[+=]', re.IGNORECASE), # narrative building
        re.compile(r'(?:status|error|warning|info|debug)\s*[=:]', re.IGNORECASE),  # status messages
        re.compile(r'(?:raise\s|except\s)', re.IGNORECASE),                         # exception handling
        re.compile(r'structlog|structlog\.', re.IGNORECASE),                        # structured logging
        re.compile(r'\.(?:info|debug|warning|error|critical)\s*\(', re.IGNORECASE), # logger method calls
    ]

    # ---------------------------------------------------------------
    # PIC001: f-string with user input in LLM API call arguments
    # Matches: llm(f"...{user_input}..."), openai.chat.completions.create(...f"...{question}...")
    # ---------------------------------------------------------------
    FSTRING_IN_LLM_CALL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # OpenAI-style API calls with f-strings containing user input
        (re.compile(r'(?:completions?|chat|messages?)\.create\s*\([^)]*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC001: User input interpolated via f-string in OpenAI API call (prompt injection risk)', Severity.HIGH),

        # Anthropic-style API calls with f-strings
        (re.compile(r'(?:anthropic|claude).*\.(?:create|messages|completions?)\s*\([^)]*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC001: User input interpolated via f-string in Anthropic API call (prompt injection risk)', Severity.HIGH),

        # LangChain ChatOpenAI/ChatAnthropic invoke with f-strings
        (re.compile(r'(?:llm|chat|model|chain)(?:_with_tools)?\.invoke\s*\([^)]*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC001: User input interpolated via f-string in LLM invoke() call', Severity.HIGH),

        # Generic llm() / llm.invoke() / llm.generate() with f-string user input
        (re.compile(r'(?:llm|chat|model|assistant|agent|bot|ai)\s*[\.(]\s*[^)]*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC001: User input in f-string passed to LLM function call', Severity.HIGH),

        # Direct llm(f"...") pattern (ai-goat style)
        (re.compile(r'\bllm\s*\(\s*f["\']', re.IGNORECASE),
         'PIC001: f-string passed directly to llm() call (prompt injection risk)', Severity.HIGH),
    ]

    # ---------------------------------------------------------------
    # PIC002: String concatenation with user input in LLM calls
    # Matches: llm("Instruction: " + instruction + " Question: " + question)
    # ---------------------------------------------------------------
    CONCAT_IN_LLM_CALL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # Direct concatenation in llm() call (ai-goat exact pattern)
        (re.compile(r'\bllm\s*\(\s*["\'][^"\']*["\']\s*\+\s*\w+\s*\+\s*["\'][^"\']*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC002: User input concatenated into llm() call via string concatenation', Severity.HIGH),

        # Any LLM function with string concat containing user input
        (re.compile(r'(?:llm|chat|model|complete|generate|invoke|predict)\s*\([^)]*["\'][^"\']*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC002: User input concatenated into LLM call argument', Severity.HIGH),

        # Reverse order: variable + string in LLM call
        (re.compile(r'(?:llm|chat|model|complete|generate|invoke|predict)\s*\([^)]*(?:' + _USER_INPUT_RE + r')\s*\+\s*["\']', re.IGNORECASE),
         'PIC002: User input concatenated into LLM call argument', Severity.HIGH),

        # "Instruction: " + instruction + " Question: " + question pattern
        (re.compile(r'["\'](?:Instruction|Question|Query|Prompt|Input|Context)\s*:\s*["\']\s*\+\s*\w+\s*\+\s*["\'].*(?:Question|Answer|Query|Response)\s*:\s*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC002: Classic prompt+question concatenation pattern (prompt injection risk)', Severity.HIGH),

        # Generic: string + user_var in function call context
        (re.compile(r'["\'][^"\']*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')\s*\+\s*["\']', re.IGNORECASE),
         'PIC002: User input sandwiched in string concatenation (potential prompt building)', Severity.MEDIUM),
    ]

    # ---------------------------------------------------------------
    # PIC003: .format() with user input in LLM-related context
    # ---------------------------------------------------------------
    FORMAT_IN_LLM_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # prompt.format(user_input=...) or prompt.format(question=...)
        (re.compile(r'(?:prompt|template|instruction|system_prompt|message)\s*\.format\s*\([^)]*(?:' + _USER_INPUT_RE + r')\s*=', re.IGNORECASE),
         'PIC003: User input in .format() applied to prompt template', Severity.MEDIUM),

        # "...{}...".format(user_input)
        (re.compile(r'["\'][^"\']*\{\}[^"\']*["\']\.format\s*\(\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC003: User input passed to .format() on string literal', Severity.MEDIUM),

        # f-string equivalent via % formatting
        (re.compile(r'(?:prompt|template|instruction|message)\s*%\s*(?:\(|(?:' + _USER_INPUT_RE + r'))', re.IGNORECASE),
         'PIC003: User input in %-formatting applied to prompt', Severity.MEDIUM),
    ]

    # ---------------------------------------------------------------
    # PIC004: User input in LangChain message objects
    # Matches: HumanMessage(content=f"...{text}..."), SystemMessage(content=text)
    # ---------------------------------------------------------------
    MESSAGE_OBJECT_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # HumanMessage with f-string content containing user variables
        (re.compile(r'HumanMessage\s*\(\s*content\s*=\s*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC004: User input interpolated in HumanMessage content (prompt injection via LangChain)', Severity.HIGH),

        # SystemMessage with f-string (system prompt injection)
        (re.compile(r'SystemMessage\s*\(\s*content\s*=\s*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC004: User input interpolated in SystemMessage content (system prompt injection)', Severity.CRITICAL),

        # Direct variable assignment to message content
        (re.compile(r'(?:Human|System|AI)Message\s*\(\s*content\s*=\s*(?:' + _USER_INPUT_RE + r')\s*[,)]', re.IGNORECASE),
         'PIC004: User input variable passed directly as message content', Severity.HIGH),

        # messages list with f-string content containing user variables
        (re.compile(r'["\'](?:content|text)["\']\s*:\s*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC004: User input in message content dict via f-string', Severity.HIGH),

        # messages list with direct user variable as content
        (re.compile(r'["\']content["\']\s*:\s*(?:' + _USER_INPUT_RE + r')\s*[,}\s]', re.IGNORECASE),
         'PIC004: User input variable as message content value (no sanitization)', Severity.MEDIUM),
    ]

    # ---------------------------------------------------------------
    # PIC005: Direct request/input data in LLM completion calls
    # Matches: openai.ChatCompletion.create(...request.body...)
    # ---------------------------------------------------------------
    DIRECT_REQUEST_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # Flask/Django request object in LLM call
        (re.compile(r'(?:completions?|messages?)\.create\s*\([^)]*request\.', re.IGNORECASE),
         'PIC005: Flask/Django request data in LLM API call', Severity.HIGH),

        # request.json / request.form / request.args in LLM context
        (re.compile(r'(?:llm|chat|model|chain|agent).*request\.(?:json|form|args|data|get_json)', re.IGNORECASE),
         'PIC005: HTTP request data used in LLM call context', Severity.HIGH),
    ]

    # ---------------------------------------------------------------
    # PIC006: LangChain chain/agent with unsanitized user input
    # ---------------------------------------------------------------
    LANGCHAIN_CHAIN_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # chain.run(user_input) / chain.invoke(user_input)
        (re.compile(r'(?:chain|llm_chain|qa_chain|agent)\.(?:run|invoke|call|predict)\s*\(\s*(?:' + _USER_INPUT_RE + r')\s*[,)]', re.IGNORECASE),
         'PIC006: Unsanitized user input passed to LangChain chain', Severity.MEDIUM),

        # llm.invoke(user_input) / model.invoke(user_input)
        (re.compile(r'(?:llm|model|chat|llm_with_tools|chat_model)\.invoke\s*\(\s*(?:' + _USER_INPUT_RE + r')\s*[,)]', re.IGNORECASE),
         'PIC006: Unsanitized user input passed directly to LLM invoke()', Severity.HIGH),

        # agent_executor.invoke with user input
        (re.compile(r'(?:agent_executor|executor)\.invoke\s*\([^)]*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC006: User input passed to agent executor without sanitization', Severity.MEDIUM),

        # llm(user_input) - direct call
        (re.compile(r'\b(?:llm|model|chat)\s*\(\s*(?:' + _USER_INPUT_RE + r')\s*[,)]', re.IGNORECASE),
         'PIC006: Unsanitized user input passed directly to LLM call', Severity.HIGH),
    ]

    # ---------------------------------------------------------------
    # PIC007: Generic LLM function calls with user input
    # Broader patterns for less common LLM libraries
    # ---------------------------------------------------------------
    GENERIC_LLM_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # Any function with llm/chat/completion/generate in name, called with f-string
        (re.compile(r'(?:\w*(?:llm|chat|completion|generate|invoke|predict)\w*)\s*\(\s*f["\'].*\{', re.IGNORECASE),
         'PIC007: f-string with interpolation in LLM-related function call', Severity.MEDIUM),

        # llama_cpp Llama() direct call with concatenation (ai-goat exact pattern)
        (re.compile(r'\bllm\s*\(\s*["\'].*["\']\s*\+\s*\w+', re.IGNORECASE),
         'PIC007: String concatenation in direct LLM call', Severity.HIGH),
    ]

    # ---------------------------------------------------------------
    # PIC008: Prompt variable built from user input, then used in LLM call
    # Multi-line pattern: detected via two-pass analysis
    # ---------------------------------------------------------------
    # Patterns for prompt variable assignment with user input
    PROMPT_ASSIGNMENT_PATTERNS: List[Tuple[re.Pattern, str]] = [
        # prompt = "..." + user_input / prompt = f"...{user_input}..."
        (re.compile(r'(prompt|instruction|system_message|sys_prompt|context|template)\s*=\s*["\'][^"\']*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC008: Prompt variable built via concatenation with user input'),
        (re.compile(r'(prompt|instruction|system_message|sys_prompt|context|template)\s*=\s*f["\'].*\{(?:' + _USER_INPUT_RE + r').*\}', re.IGNORECASE),
         'PIC008: Prompt variable built via f-string with user input'),
        (re.compile(r'(prompt|instruction|system_message|sys_prompt|context|template)\s*\+=\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC008: Prompt variable appended with user input'),
        (re.compile(r'(prompt|instruction|system_message|sys_prompt|context|template)\s*\+=\s*["\'].*["\']\s*\+\s*(?:' + _USER_INPUT_RE + r')', re.IGNORECASE),
         'PIC008: Prompt variable appended with concatenated user input'),
    ]

    # Patterns that indicate the prompt variable is passed to an LLM call
    PROMPT_USAGE_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?:llm|chat|model|chain|agent|completion|generate|invoke|predict|create)\s*\([^)]*\b(?:prompt|instruction|system_message|sys_prompt|context|template)\b', re.IGNORECASE),
        re.compile(r'(?:HumanMessage|SystemMessage|AIMessage)\s*\(\s*content\s*=\s*(?:prompt|instruction|system_message|sys_prompt|context|template)', re.IGNORECASE),
        re.compile(r'["\']content["\']\s*:\s*(?:prompt|instruction|system_message|sys_prompt|context|template)', re.IGNORECASE),
    ]

    # ---------------------------------------------------------------
    # Safety/mitigation patterns (reduce severity if present)
    # ---------------------------------------------------------------
    SANITIZATION_PATTERNS: List[re.Pattern] = [
        re.compile(r'\bsanitize\s*\(', re.IGNORECASE), re.compile(r'\bvalidate_input\s*\(', re.IGNORECASE), re.compile(r'\bclean_input\s*\(', re.IGNORECASE),
        re.compile(r'\bescape_input\s*\(', re.IGNORECASE), re.compile(r'\bfilter_input\s*\(', re.IGNORECASE),
        re.compile(r'\bprompt_guard\b', re.IGNORECASE), re.compile(r'\binput_guard\b', re.IGNORECASE), re.compile(r'\bllm_guard\b', re.IGNORECASE),
        re.compile(r'\brebuff\b', re.IGNORECASE), re.compile(r'\bguardrail\b', re.IGNORECASE), re.compile(r'\bNeMoGuardrails\b', re.IGNORECASE),
        re.compile(r'\bprompt_injection_detect', re.IGNORECASE), re.compile(r'\bsanitize_prompt\s*\(', re.IGNORECASE),
        re.compile(r'\bclean_prompt\s*\(', re.IGNORECASE), re.compile(r'\bstrip_injection\s*\(', re.IGNORECASE),
        re.compile(r'\binput_sanitizer\b', re.IGNORECASE), re.compile(r'\bprompt_filter\b', re.IGNORECASE),
    ]

    # ---------------------------------------------------------------
    # Defense code indicators - files that DETECT or PREVENT injection
    # rather than being vulnerable to it. These files contain injection
    # patterns as detection signatures, not as attack vectors.
    # ---------------------------------------------------------------
    DEFENSE_CODE_INDICATORS: List[re.Pattern] = [
        re.compile(r'_PROMPT_INJECTION_PATTERN'),      # Detection regex collections
        re.compile(r'INJECTION_PATTERN'),              # Detection pattern constants
        re.compile(r'detect_injection'),               # Injection detection functions
        re.compile(r'check_for_injection'),            # Injection checking
        re.compile(r'is_injection'),                   # Injection classification
        re.compile(r'injection_score'),                # Scoring injection likelihood
        re.compile(r'prompt_injection_filter'),        # Filtering injections
        re.compile(r'sanitize_alert_for_prompt'),      # Alert sanitization
        re.compile(r'sanitize_for_prompt'),            # Prompt sanitization
        re.compile(r'class\s+\w*(?:Guard|Filter|Sanitizer|Detector)\w*'), # Guard/filter classes
    ]

    def __init__(self) -> None:
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner, always available

    def get_file_extensions(self) -> List[str]:
        return [".py"]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        """Check if file is a Python file that may contain LLM calls."""
        if file_path.suffix != '.py':
            return False

        # Quick check: read the first 8KB and look for LLM indicators
        # Require at least one specific library import to reduce FPs on
        # files that happen to contain generic words like 'invoke'
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(8192)
            head_lower = head.lower()
            matches = sum(1 for ind in self.LLM_INDICATORS if ind.lower() in head_lower)
            # Need at least 1 match (indicators are now specific enough)
            return matches >= 1
        except OSError:
            return False

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return confidence score for Python files with LLM usage.

        Args:
            file_path: Path to file to analyze.
            content_head: Optional pre-read file head (first 8KB).
        """
        if not self.can_scan(file_path):
            return 0

        # This scanner is specifically for prompt injection in code
        # Give it high confidence for LLM-related Python files
        try:
            if content_head is not None:
                head = content_head
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    head = f.read(8192)
            head_lower = head.lower()

            # Count how many LLM indicators are present
            indicator_count = sum(
                1 for ind in self.LLM_INDICATORS
                if ind.lower() in head_lower
            )

            if indicator_count >= 5:
                return 90
            elif indicator_count >= 3:
                return 80
            elif indicator_count >= 1:
                return 70
            return 0
        except OSError:
            return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a Python file for prompt injection vulnerabilities in LLM calls."""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='replace')
            _offsets = _build_line_offsets(content)
            lines = content.split('\n')

            # Check if this file IS defense code (detects/prevents injection)
            # Defense code contains injection patterns as detection signatures,
            # not as vulnerabilities. Skip scanning entirely for these files.
            is_defense_code = any(
                p.search(content)
                for p in self.DEFENSE_CODE_INDICATORS
            )
            if is_defense_code:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for sanitization mitigations
            has_sanitization = any(
                p.search(content)
                for p in self.SANITIZATION_PATTERNS
            )

            # Single-line pattern scans
            all_single_line_patterns = [
                (self.FSTRING_IN_LLM_CALL_PATTERNS, "PIC001"),
                (self.CONCAT_IN_LLM_CALL_PATTERNS, "PIC002"),
                (self.FORMAT_IN_LLM_PATTERNS, "PIC003"),
                (self.MESSAGE_OBJECT_PATTERNS, "PIC004"),
                (self.DIRECT_REQUEST_PATTERNS, "PIC005"),
                (self.LANGCHAIN_CHAIN_PATTERNS, "PIC006"),
                (self.GENERIC_LLM_PATTERNS, "PIC007"),
            ]

            # Pre-compute docstring line set once for all pattern checks
            docstring_lines = self._build_docstring_set(lines)

            for patterns, rule_id in all_single_line_patterns:
                issues.extend(
                    self._check_patterns(lines, patterns, rule_id, has_sanitization, docstring_lines)
                )

            # Multi-line analysis: prompt built from user input, then used in LLM
            issues.extend(
                self._check_prompt_flow(lines, content, has_sanitization, docstring_lines, _offsets)
            )

            # Reduce severity if sanitization is present
            if has_sanitization:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.CRITICAL:
                        issue.severity = Severity.HIGH

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

    @staticmethod
    def _build_docstring_set(lines: List[str]) -> Set[int]:
        """Build a set of line numbers (1-indexed) that are inside docstrings or comments."""
        in_docstring: Set[int] = set()
        inside = False
        delimiter = ''

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Comment lines
            if stripped.startswith('#'):
                in_docstring.add(i)
                continue

            if not inside:
                # Check for docstring start
                if '"""' in stripped:
                    in_docstring.add(i)
                    # Single-line docstring: """..."""
                    if stripped.count('"""') >= 2:
                        continue
                    inside = True
                    delimiter = '"""'
                elif "'''" in stripped:
                    in_docstring.add(i)
                    if stripped.count("'''") >= 2:
                        continue
                    inside = True
                    delimiter = "'''"
            else:
                in_docstring.add(i)
                if delimiter in stripped:
                    inside = False

        return in_docstring

    def _is_non_prompt_context(self, line: str) -> bool:
        """Check if a line is clearly NOT building an LLM prompt.

        Returns True for logging, cost tracking, narrative building,
        status messages, and data structure construction.
        """
        for ctx_pattern in self.NON_PROMPT_CONTEXTS:
            if ctx_pattern.search(line):
                return True
        return False

    def _check_patterns(
        self,
        lines: List[str],
        patterns: List[Tuple[re.Pattern, str, Severity]],
        rule_id: str,
        has_sanitization: bool,
        docstring_lines: Optional[Set[int]] = None,
    ) -> List[ScannerIssue]:
        """Scan lines against a list of patterns and return issues."""
        issues: List[ScannerIssue] = []
        seen_messages: Set[str] = set()

        if docstring_lines is None:
            docstring_lines = self._build_docstring_set(lines)

        for i, line in enumerate(lines, 1):
            # Skip lines inside docstrings or comments
            if i in docstring_lines:
                continue

            # Skip lines that are clearly non-prompt contexts
            if self._is_non_prompt_context(line):
                continue

            for pattern, message, severity in patterns:
                if pattern.search(line):
                    # Avoid duplicate messages for the same pattern
                    if message not in seen_messages:
                        issues.append(ScannerIssue(
                            rule_id=rule_id,
                            severity=severity,
                            message=f"{message} - sanitize all user input before passing to LLM",
                            line=i,
                            column=1,
                            cwe_id=94,
                            cwe_link="https://cwe.mitre.org/data/definitions/94.html",
                        ))
                        seen_messages.add(message)
                        break  # One issue per line

        return issues

    def _check_prompt_flow(
        self,
        lines: List[str],
        content: str,
        has_sanitization: bool,
        docstring_lines: Optional[Set[int]] = None,
        _offsets: List[int] = None,
    ) -> List[ScannerIssue]:
        """
        Multi-line analysis: detect when a prompt variable is built from user
        input and then passed to an LLM call.

        Example vulnerable pattern (two lines):
            prompt = "Tell me about " + user_input
            output = llm(prompt)
        """
        issues: List[ScannerIssue] = []

        if docstring_lines is None:
            docstring_lines = self._build_docstring_set(lines)

        # Phase 1: Find all prompt variable assignments tainted by user input
        tainted_vars: Dict[str, int] = {}  # var_name -> line_number
        for i, line in enumerate(lines, 1):
            # Skip docstring/comment lines
            if i in docstring_lines:
                continue

            for pattern, _message in self.PROMPT_ASSIGNMENT_PATTERNS:
                match = pattern.search(line)
                if match:
                    var_name = match.group(1)
                    tainted_vars[var_name] = i
                    break

        if not tainted_vars:
            return issues

        # Phase 2: Check if any tainted variable is used in an LLM call
        for var_name, assignment_line in tainted_vars.items():
            for usage_pattern in self.PROMPT_USAGE_PATTERNS:
                # Replace the generic variable name in the pattern with the actual one
                specific_pattern_str = usage_pattern.pattern.replace(
                    r'(?:prompt|instruction|system_message|sys_prompt|context|template)',
                    re.escape(var_name)
                )
                try:
                    specific_re = re.compile(specific_pattern_str, re.IGNORECASE)
                    match = specific_re.search(content)
                    if match:
                        usage_line = _get_line_number(_offsets, match.start())
                        issues.append(ScannerIssue(
                            rule_id="PIC008",
                            severity=Severity.HIGH,
                            message=(
                                f"PIC008: Variable '{var_name}' built from user input (line {assignment_line}) "
                                f"is passed to LLM call - sanitize user input before prompt construction"
                            ),
                            line=usage_line,
                            column=1,
                            cwe_id=94,
                            cwe_link="https://cwe.mitre.org/data/definitions/94.html",
                        ))
                        break  # One issue per tainted variable
                except re.error:
                    continue

        return issues
