#!/usr/bin/env python3
"""
MEDUSA OWASP LLM Top 10 Scanner (2025 Edition)
Detects vulnerabilities from OWASP Top 10 for LLM Applications 2025

Updated based on OWASP Top 10 for LLM Applications 2025 (Nov 2024)

Detects:
- LLM01: Prompt Injection (direct and indirect)
- LLM02: Sensitive Information Disclosure
- LLM03: Supply Chain vulnerabilities
- LLM04: Data and Model Poisoning
- LLM05: Improper Output Handling
- LLM06: Excessive Agency
- LLM07: System Prompt Leakage (NEW in 2025)
- LLM08: Vector and Embedding Weaknesses (NEW in 2025)
- LLM09: Misinformation
- LLM10: Unbounded Consumption (expanded from DoS)
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number

# Module-level pre-compiled regex for assignment matching (used per-line in taint analysis)
_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(.+)')


class OWASPLLMScanner(RuleBasedScanner):
    """
    OWASP LLM Top 10 Security Scanner (2025 Edition)

    Based on OWASP Top 10 for LLM Applications 2025 (Version 2025)
    Released November 18, 2024

    Scans for:
    - LLM01: Prompt Injection (direct and indirect)
    - LLM02: Sensitive Information Disclosure
    - LLM02-DL: Data Leak via Legitimate Channel (Slack, email, webhook exfiltration)
    - LLM03: Supply Chain vulnerabilities
    - LLM04: Data and Model Poisoning
    - LLM05: Improper Output Handling (XSS, RCE, SQLi)
    - LLM06: Excessive Agency
    - LLM07: System Prompt Leakage (NEW)
    - LLM08: Vector and Embedding Weaknesses (NEW)
    - LLM09: Misinformation/Hallucination
    - LLM10: Unbounded Consumption (DoS/DoW)
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['OWASP-', 'LLM']

    # Categories to load from YAML
    RULE_CATEGORIES = ['owasp_llm', 'llm_security']

    # LLM01: Prompt Injection patterns (direct and indirect)
    PROMPT_INJECTION_PATTERNS = [
        (re.compile(r'(prompt|message)\s*=\s*.{0,50}\+\s*(user|input|request)', re.IGNORECASE),
         'User input concatenated into prompt (direct injection risk)'),
        (re.compile(r'f["\'].{0,100}\{(user_input|request|query|message)\}.{0,100}["\']', re.IGNORECASE),
         'User input interpolated in prompt string'),
        (re.compile(r'(system_prompt|instructions)\s*\+\s*', re.IGNORECASE),
         'System prompt concatenated with untrusted data'),
        (re.compile(r'prompt\s*=\s*(request|input|body)\.', re.IGNORECASE),
         'Prompt directly from request without sanitization'),
        (re.compile(r'\.(format|replace)\s*\(.{0,50}user', re.IGNORECASE),
         'User input in string formatting for prompt'),
        # Indirect injection patterns (from external sources)
        (re.compile(r'(fetch|axios|request)\s*\(.{0,100}\).{0,50}prompt', re.IGNORECASE),
         'External content fetched and used in prompt (indirect injection)'),
        (re.compile(r'(scrape|crawl|parse).{0,50}\+.{0,50}prompt', re.IGNORECASE),
         'Scraped content in prompt (indirect injection vector)'),
        (re.compile(r'(document|file|url).{0,50}content.{0,50}prompt', re.IGNORECASE),
         'Document content injected into prompt'),
    ]

    # CVE-2024-5184: LLM Email Assistant Code Injection
    # Email content passed directly to LLM without sanitization
    EMAIL_INJECTION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'email\.body.*(?:prompt|llm|generate)', re.IGNORECASE),
         'CVE-2024-5184: Email body passed to LLM without sanitization', Severity.CRITICAL),
        (re.compile(r'message\.content.*(?:llm\.|openai|anthropic)', re.IGNORECASE),
         'CVE-2024-5184: Email message content in LLM call', Severity.CRITICAL),
        (re.compile(r'inbox\[.*\].*(?:generate|complete|chat)', re.IGNORECASE),
         'CVE-2024-5184: Inbox content in LLM generation', Severity.HIGH),
        (re.compile(r'mail\.(?:subject|body|text).*(?:prompt|system)', re.IGNORECASE),
         'CVE-2024-5184: Email field in prompt construction', Severity.HIGH),
        (re.compile(r'(?:imap|pop3|smtp).*(?:llm|ai|assistant)', re.IGNORECASE),
         'Email protocol integration with LLM - verify sanitization', Severity.MEDIUM),
        (re.compile(r'email_assistant.*(?:process|handle).*(?:unsanitized|raw)', re.IGNORECASE),
         'Email assistant processing raw email content', Severity.CRITICAL),
    ]

    # Prompt Injection Obfuscation Detection
    # Detect attempts to hide malicious prompts
    PROMPT_OBFUSCATION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # HTML comment hiding
        (re.compile(r'<!--.*(?:ignore|forget|disregard|new instructions).*-->', re.IGNORECASE),
         'HTML comment with injection keywords', Severity.HIGH),
        (re.compile(r'<hidden>.*</hidden>', re.IGNORECASE),
         'Hidden HTML tag (potential prompt hiding)', Severity.MEDIUM),
        # Zero-width character detection (Unicode obfuscation)
        (re.compile(r'[\u200b\u200c\u200d\ufeff]', re.IGNORECASE),
         'Zero-width Unicode characters (prompt obfuscation)', Severity.HIGH),
        # Control token abuse (model-specific tokens)
        (re.compile(r'\[INST\]|\[/INST\]', re.IGNORECASE),
         'Llama instruction tokens in input (control token injection)', Severity.CRITICAL),
        (re.compile(r'<\|im_start\|>|<\|im_end\|>', re.IGNORECASE),
         'ChatML control tokens in input (control token injection)', Severity.CRITICAL),
        (re.compile(r'<\|system\|>|<\|user\|>|<\|assistant\|>', re.IGNORECASE),
         'Role tokens in input (control token injection)', Severity.CRITICAL),
        (re.compile(r'<<SYS>>|<</SYS>>', re.IGNORECASE),
         'Llama2 system tokens in input', Severity.CRITICAL),
        # Base64/encoding obfuscation in prompts
        (re.compile(r'base64\.(?:b64decode|decode)\s*\([^)]*(?:prompt|instruction)', re.IGNORECASE),
         'Base64 decoding in prompt construction', Severity.HIGH),
        (re.compile(r'(?:atob|btoa)\s*\([^)]*(?:prompt|message)', re.IGNORECASE),
         'JavaScript base64 in prompt handling', Severity.HIGH),
        # Unicode escape sequences
        (re.compile(r'\\u[0-9a-fA-F]{4}.*(?:prompt|instruction)', re.IGNORECASE),
         'Unicode escapes in prompt (obfuscation attempt)', Severity.MEDIUM),
        # Markdown/formatting abuse
        (re.compile(r'\[(?:system|admin|root)\]:', re.IGNORECASE),
         'Fake role prefix in markdown format', Severity.HIGH),
        (re.compile(r'```(?:system|instruction|ignore).*```', re.IGNORECASE),
         'Code block with injection keywords', Severity.MEDIUM),
    ]

    # LLM02: Sensitive Information Disclosure patterns
    DISCLOSURE_PATTERNS = [
        (re.compile(r'(api_key|apikey|secret|password|token)\s*=\s*["\'][^"\']{8,}', re.IGNORECASE),
         'Hardcoded credential in code'),
        (re.compile(r'(print|log|console)\s*\(.{0,50}prompt', re.IGNORECASE),
         'Prompt logged (may expose system instructions)'),
        (re.compile(r'return.{0,30}system_prompt', re.IGNORECASE),
         'System prompt returned to user'),
        (re.compile(r'response.{0,50}\+.{0,50}(config|credential)', re.IGNORECASE),
         'Configuration/credential data in response'),
        (re.compile(r'(error|exception).{0,50}prompt', re.IGNORECASE),
         'Prompt exposed in error message'),
        (re.compile(r'(pii|personal|ssn|email).{0,50}response', re.IGNORECASE),
         'PII potentially in response'),
        (re.compile(r'training.{0,30}data.{0,30}expos', re.IGNORECASE),
         'Training data exposure risk'),
    ]

    # LLM03: Supply Chain patterns
    SUPPLY_CHAIN_PATTERNS = [
        (re.compile(r'from_pretrained\s*\(["\'][^"\']+["\']', re.IGNORECASE),
         'Pre-trained model loaded - verify source integrity'),
        (re.compile(r'(lora|adapter).*load.*\(', re.IGNORECASE),
         'LoRA adapter loaded - verify provenance'),
        (re.compile(r'(pickle|joblib|dill)\.load\s*\(', re.IGNORECASE),
         'Insecure deserialization (use safetensors)'),
        (re.compile(r'download.*model.*http://', re.IGNORECASE),
         'Model downloaded over HTTP (use HTTPS)'),
        (re.compile(r'hub\.(download|load).*trust_remote_code\s*=\s*True', re.IGNORECASE),
         'Remote code execution enabled in model loading'),
    ]

    # LLM04: Data and Model Poisoning patterns
    POISONING_PATTERNS = [
        (re.compile(r'(fine_tune|train).*user.*data', re.IGNORECASE),
         'Training on user-provided data (poisoning risk)'),
        (re.compile(r'(embed|index).*untrusted', re.IGNORECASE),
         'Embedding untrusted content'),
        (re.compile(r'feedback.*train', re.IGNORECASE),
         'User feedback used in training without validation'),
        (re.compile(r'(rlhf|rlaif).*\(.*user', re.IGNORECASE),
         'RLHF with unvalidated user input'),
    ]

    # LLM05: Improper Output Handling patterns (RCE, XSS, SQLi)
    # Single-line patterns where LLM output variable flows directly to a sink
    OUTPUT_HANDLING_PATTERNS = [
        (re.compile(r'(innerHTML|dangerouslySetInnerHTML)\s*=\s*.*response', re.IGNORECASE),
         'LLM response rendered as HTML (XSS risk)'),
        (re.compile(r'eval\s*\(.*response', re.IGNORECASE),
         'LLM response executed via eval (RCE risk)'),
        (re.compile(r'exec\s*\(.*response', re.IGNORECASE),
         'LLM response executed via exec (RCE risk)'),
        (re.compile(r'subprocess.*response', re.IGNORECASE),
         'LLM response passed to subprocess'),
        (re.compile(r'document\.write\s*\(.*response', re.IGNORECASE),
         'LLM response in document.write'),
        (re.compile(r'(cursor|execute)\s*\(.*response', re.IGNORECASE),
         'LLM response in SQL query (SQLi risk)'),
        (re.compile(r'child_process.*response', re.IGNORECASE),
         'LLM response in child process'),
        (re.compile(r'Function\s*\(.*response', re.IGNORECASE),
         'LLM response in Function constructor'),
    ]

    # ---- LLM05 Taint Analysis Configuration ----
    # Patterns that identify where LLM output originates (sources).
    # Each entry: (regex, group_name_or_index_for_variable)
    # The regex should capture the variable name that receives the LLM output.
    LLM_OUTPUT_SOURCE_PATTERNS: List[re.Pattern] = [
        # OpenAI / llama.cpp style: output = llm(...) or output = client.chat.completions.create(...)
        re.compile(r'(\w+)\s*=\s*(?:llm|client\.chat\.completions\.create|openai\.ChatCompletion\.create|openai\.Completion\.create)\s*\('),
        # Anthropic: response = anthropic.messages.create(...)
        re.compile(r'(\w+)\s*=\s*(?:anthropic\.\w+\.create|claude\.\w+)\s*\('),
        # LangChain: answer = chain.run(...), result = llmChain.predict(...)
        re.compile(r'(\w+)\s*=\s*(?:\w+\.(?:run|predict|invoke|call|generate|complete|arun|ainvoke))\s*\('),
        # HuggingFace: output = pipeline(...), result = model.generate(...)
        re.compile(r'(\w+)\s*=\s*(?:\w+\.generate|pipeline)\s*\('),
        # Generic: response = chat(...), result = generate_text(...)
        re.compile(r'(\w+)\s*=\s*(?:chat|generate_text|ask_llm|query_model|get_completion|complete|generate_response)\s*\('),
        # choices[0] extraction: text = output['choices'][0]['text']
        re.compile(r'(\w+)\s*=\s*\w+\[.?choices.?\]\s*\['),
        # .content extraction: text = response.choices[0].message.content
        re.compile(r'(\w+)\s*=\s*\w+\.choices\['),
        # .content direct: answer = completion.content
        re.compile(r'(\w+)\s*=\s*\w+\.(?:content|text|message|output|result)\b'),
        # .split() on LLM output: url = full_response.split(...)
        re.compile(r'(\w+)\s*=\s*(\w+)\.split\s*\('),
    ]

    # Dangerous sinks: functions/calls that should never receive unsanitized LLM output.
    # Tuples of (regex_template, message, severity).
    # {var} is replaced with the tainted variable name.
    LLM_OUTPUT_SINK_PATTERNS: List[Tuple[str, str, Severity]] = [
        # RCE sinks (CRITICAL)
        (r'subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*\b{var}\b',
         'LLM output in subprocess (RCE)', Severity.CRITICAL),
        (r'os\.(?:system|popen|exec\w*)\s*\([^)]*\b{var}\b',
         'LLM output in os.system/popen (RCE)', Severity.CRITICAL),
        (r'eval\s*\(\s*{var}\b',
         'LLM output in eval() (RCE)', Severity.CRITICAL),
        (r'exec\s*\(\s*{var}\b',
         'LLM output in exec() (RCE)', Severity.CRITICAL),
        (r'compile\s*\(\s*{var}\b',
         'LLM output in compile() (RCE)', Severity.CRITICAL),
        (r'subprocess\.check_output\s*\(\s*{var}\b',
         'LLM output in subprocess.check_output (RCE)', Severity.CRITICAL),
        (r'(?:shell|bash|cmd)\s*=\s*True.*\b{var}\b',
         'LLM output passed with shell=True (RCE)', Severity.CRITICAL),
        # Network/SSRF sinks (HIGH)
        (r'requests\.(?:get|post|put|delete|patch|head)\s*\([^)]*\b{var}\b',
         'LLM output used as URL in requests (SSRF)', Severity.HIGH),
        (r'urllib\.request\.urlopen\s*\([^)]*\b{var}\b',
         'LLM output used in urllib.urlopen (SSRF)', Severity.HIGH),
        (r'httpx\.(?:get|post|put|delete|patch)\s*\([^)]*\b{var}\b',
         'LLM output used as URL in httpx (SSRF)', Severity.HIGH),
        (r'aiohttp\.(?:ClientSession|request)\s*\([^)]*\b{var}\b',
         'LLM output used in aiohttp request (SSRF)', Severity.HIGH),
        (r'(?:fetch|axios)\s*\([^)]*\b{var}\b',
         'LLM output used in fetch/axios (SSRF)', Severity.HIGH),
        (r'urlopen\s*\([^)]*\b{var}\b',
         'LLM output in urlopen (SSRF)', Severity.HIGH),
        # File access sinks (HIGH)
        (r'open\s*\(\s*{var}\b',
         'LLM output used as file path in open() (path traversal)', Severity.HIGH),
        (r'(?:Path|pathlib)\s*\(\s*{var}\b',
         'LLM output used as file path (path traversal)', Severity.HIGH),
        (r'(?:shutil|os)\.(?:copy|move|remove|unlink|rename)\s*\([^)]*\b{var}\b',
         'LLM output in file operation (path traversal)', Severity.HIGH),
        (r'(?:os\.path\.join|os\.makedirs)\s*\([^)]*\b{var}\b',
         'LLM output in path construction (path traversal)', Severity.HIGH),
        # SQL injection sinks (HIGH)
        (r'(?:cursor\.execute|\.execute)\s*\([^)]*\b{var}\b',
         'LLM output in SQL execute (SQLi)', Severity.HIGH),
        (r'(?:cursor|db|conn)\.execute\s*\([^)]*%.*%\s*{var}\b',
         'LLM output in SQL string formatting (SQLi)', Severity.HIGH),
        (r'(?:cursor|db|conn)\.execute\s*\([^)]*\.format\([^)]*{var}\b',
         'LLM output in SQL .format() (SQLi)', Severity.HIGH),
        (r'f["\'](?:SELECT|INSERT|UPDATE|DELETE).*\{{{var}\}}',
         'LLM output in f-string SQL query (SQLi)', Severity.HIGH),
        # XSS / HTML rendering sinks (MEDIUM)
        (r'render_template_string\s*\([^)]*\b{var}\b',
         'LLM output in render_template_string (XSS)', Severity.MEDIUM),
        (r'Markup\s*\(\s*{var}\b',
         'LLM output in Markup() (XSS)', Severity.MEDIUM),
        (r'(?:innerHTML|dangerouslySetInnerHTML)\s*=.*\b{var}\b',
         'LLM output set as innerHTML (XSS)', Severity.MEDIUM),
        (r'document\.write\s*\([^)]*\b{var}\b',
         'LLM output in document.write (XSS)', Severity.MEDIUM),
    ]

    # Maximum line distance for taint propagation within a function
    TAINT_WINDOW = 30

    # Pre-compiled patterns for direct LLM output access in sinks (LLM05 Step 4).
    # Hoisted to class level to avoid re-compiling on every line.
    DIRECT_LLM_SINK_PATTERNS: List[Tuple[re.Pattern, str, 'Severity', int]] = [
        (re.compile(r'subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*(?:choices\[|\.content|\.text|\.message|\.output)', re.IGNORECASE),
         'LLM output directly in subprocess (RCE)', Severity.CRITICAL, 78),
        (re.compile(r'os\.(?:system|popen|exec\w*)\s*\([^)]*(?:choices\[|\.content|\.text|\.message)', re.IGNORECASE),
         'LLM output directly in os command (RCE)', Severity.CRITICAL, 78),
        (re.compile(r'eval\s*\([^)]*(?:choices\[|\.content|\.text|\.message|\.output)', re.IGNORECASE),
         'LLM output directly in eval (RCE)', Severity.CRITICAL, 95),
        (re.compile(r'exec\s*\([^)]*(?:choices\[|\.content|\.text|\.message|\.output)', re.IGNORECASE),
         'LLM output directly in exec (RCE)', Severity.CRITICAL, 95),
        (re.compile(r'requests\.(?:get|post|put|delete|patch|head)\s*\([^)]*(?:choices\[|\.content|\.text|\.message|\.output)', re.IGNORECASE),
         'LLM output directly as URL in requests (SSRF)', Severity.HIGH, 918),
        (re.compile(r'urllib\.request\.urlopen\s*\([^)]*(?:choices\[|\.content|\.text|\.message)', re.IGNORECASE),
         'LLM output directly in urlopen (SSRF)', Severity.HIGH, 918),
        (re.compile(r'open\s*\([^)]*(?:choices\[|\.content|\.text|\.message|\.output)', re.IGNORECASE),
         'LLM output directly as file path (path traversal)', Severity.HIGH, 22),
        (re.compile(r'(?:cursor\.execute|\.execute)\s*\([^)]*(?:choices\[|\.content|\.text|\.message)', re.IGNORECASE),
         'LLM output directly in SQL query (SQLi)', Severity.HIGH, 89),
        (re.compile(r'render_template_string\s*\([^)]*(?:choices\[|\.content|\.text|\.message)', re.IGNORECASE),
         'LLM output directly in template rendering (XSS)', Severity.MEDIUM, 79),
        (re.compile(r'Markup\s*\([^)]*(?:choices\[|\.content|\.text|\.message)', re.IGNORECASE),
         'LLM output directly in Markup (XSS)', Severity.MEDIUM, 79),
    ]

    # Pre-compiled sink templates for taint analysis (LLM05 Step 3).
    # Each entry: (compiled_regex_with_generic_word_match, message, severity).
    # The regex uses (\b\w+\b) in place of {var}; at runtime we first do a
    # fast ``tvar in line`` check, then run the pre-compiled regex, then verify
    # the captured group matches the tainted variable name.
    _COMPILED_SINK_TEMPLATES: Optional[List[Tuple[re.Pattern, str, 'Severity']]] = None

    @classmethod
    def _get_compiled_sink_templates(cls) -> List[Tuple[re.Pattern, str, 'Severity']]:
        """Lazily compile sink templates once and cache at class level."""
        if cls._COMPILED_SINK_TEMPLATES is None:
            compiled = []
            for template, message, severity in cls.LLM_OUTPUT_SINK_PATTERNS:
                # Replace {var} with a named capture group for a word token
                generic = template.replace(r'\b{var}\b', r'\b(?P<tvar>\w+)\b')
                generic = generic.replace('{var}', r'(?P<tvar>\w+)')
                try:
                    compiled.append((re.compile(generic, re.IGNORECASE), message, severity))
                except re.error:
                    continue
            cls._COMPILED_SINK_TEMPLATES = compiled
        return cls._COMPILED_SINK_TEMPLATES

    # LLM06: Excessive Agency patterns
    AGENCY_PATTERNS = [
        (re.compile(r'auto_execute\s*=\s*True', re.IGNORECASE),
         'Auto-execution enabled (excessive agency)'),
        (re.compile(r'confirm\s*=\s*False.{0,50}(delete|remove|drop)', re.IGNORECASE),
         'Destructive action without confirmation'),
        (re.compile(r'(sudo|admin|root)\s*=\s*True', re.IGNORECASE),
         'Elevated privileges enabled by default'),
        (re.compile(r'permissions\s*=\s*\[?\s*["\']?\*', re.IGNORECASE),
         'Wildcard permissions granted'),
        (re.compile(r'human_in_loop\s*=\s*False', re.IGNORECASE),
         'Human oversight disabled'),
        (re.compile(r'auto_approve\s*=\s*True', re.IGNORECASE),
         'Auto-approval enabled'),
        (re.compile(r'(shell|bash|cmd)\s*=\s*True', re.IGNORECASE),
         'Shell access enabled for agent'),
        (re.compile(r'run_command.{0,30}\(.{0,50}llm', re.IGNORECASE),
         'LLM can execute system commands'),
        # Confused deputy indicators
        (re.compile(r'(service_account|admin_token).{0,50}tool', re.IGNORECASE),
         'Tool using service account (confused deputy risk)'),
        (re.compile(r'privileged\s*=\s*True', re.IGNORECASE),
         'Privileged mode enabled'),
    ]

    # LLM07: System Prompt Leakage (NEW in 2025)
    SYSTEM_PROMPT_LEAKAGE_PATTERNS = [
        (re.compile(r'(system_prompt|system_message)\s*=\s*["\'][^"\']{50,}', re.IGNORECASE),
         'Long system prompt with potential sensitive instructions'),
        (re.compile(r'(api_key|password|secret|token)\s*.*system.*prompt', re.IGNORECASE),
         'Credentials referenced in system prompt'),
        (re.compile(r'system.*prompt.*(return|response|output)', re.IGNORECASE),
         'System prompt potentially exposed in output'),
        (re.compile(r'(database|db_name|table)\s*.*system.*prompt', re.IGNORECASE),
         'Database details in system prompt'),
        (re.compile(r'internal.*rule.*system.*prompt', re.IGNORECASE),
         'Internal rules in system prompt (should use guardrails)'),
        (re.compile(r'role.*admin.*system.*prompt', re.IGNORECASE),
         'Admin role info in system prompt'),
        (re.compile(r'(limit|threshold|max).*system.*prompt', re.IGNORECASE),
         'Security limits in system prompt (can be bypassed)'),
    ]

    # LLM08: Vector and Embedding Weaknesses (NEW in 2025)
    VECTOR_EMBEDDING_PATTERNS = [
        (re.compile(r'(embed|vector).*user.*input', re.IGNORECASE),
         'User input directly embedded without validation'),
        (re.compile(r'(similarity|nearest).*search.*\*', re.IGNORECASE),
         'Unrestricted similarity search'),
        (re.compile(r'(chroma|pinecone|weaviate|milvus).*public', re.IGNORECASE),
         'Vector DB with public access'),
        (re.compile(r'embedding.*\(.*pii', re.IGNORECASE),
         'PII being embedded'),
        (re.compile(r'(retrieve|search).*without.*filter', re.IGNORECASE),
         'Vector retrieval without access filtering'),
        (re.compile(r'multi.*tenant.*embed.*shared', re.IGNORECASE),
         'Shared embeddings across tenants'),
    ]

    # LLM09: Misinformation/Hallucination patterns
    MISINFORMATION_PATTERNS = [
        (re.compile(r'(medical|legal|financial).*advice.*llm', re.IGNORECASE),
         'LLM providing sensitive advice without guardrails'),
        (re.compile(r'(fact|verify|ground).*=\s*False', re.IGNORECASE),
         'Fact-checking/grounding disabled'),
        (re.compile(r'hallucination.*allow', re.IGNORECASE),
         'Hallucination explicitly allowed'),
        (re.compile(r'response.*direct.*user.*without.*check', re.IGNORECASE),
         'LLM response sent without verification'),
    ]

    # LLM10: Unbounded Consumption (DoS/DoW)
    UNBOUNDED_CONSUMPTION_PATTERNS = [
        (re.compile(r'max_tokens\s*=\s*None', re.IGNORECASE),
         'No max_tokens limit (unbounded consumption)'),
        (re.compile(r'max_tokens\s*=\s*\d{5,}', re.IGNORECASE),
         'Excessively high max_tokens value'),
        (re.compile(r'while\s+True.*generate', re.IGNORECASE),
         'Unbounded generation loop'),
        (re.compile(r'(input|prompt).*\*\s*\d{3,}', re.IGNORECASE),
         'Input multiplication (amplification attack)'),
        (re.compile(r'(timeout|max_time)\s*=\s*(None|0)', re.IGNORECASE),
         'No timeout configured'),
        (re.compile(r'retry.*=\s*(-1|unlimited|infinite)', re.IGNORECASE),
         'Unlimited retries configured'),
        (re.compile(r'(budget|cost|limit)\s*=\s*None', re.IGNORECASE),
         'No cost/budget limit (Denial of Wallet risk)'),
    ]

    # Data Leak via Legitimate Channel patterns
    # Exfiltration through legitimate tool calls (Slack, email, webhook)
    DATA_LEAK_CHANNEL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # Sensitive data sent through messaging tools
        (re.compile(r'(slack|discord|teams)\.(?:post|send|message)\s*\([^)]*(?:password|secret|api_key|token|credential)', re.IGNORECASE),
         'Sensitive data sent via messaging channel', Severity.CRITICAL),
        (re.compile(r'(slack|discord|teams)\.(?:post|send|message)\s*\([^)]*(?:env|environ|config)', re.IGNORECASE),
         'Environment/config data sent via messaging', Severity.HIGH),
        # Email exfiltration
        (re.compile(r'(?:send_email|smtp|sendmail)\s*\([^)]*(?:password|secret|api_key|token)', re.IGNORECASE),
         'Sensitive data in email content', Severity.CRITICAL),
        (re.compile(r'mail\.(?:send|compose)\s*\([^)]*(?:credential|key|secret)', re.IGNORECASE),
         'Credentials in email', Severity.CRITICAL),
        # Webhook exfiltration
        (re.compile(r'webhook\s*\([^)]*(?:password|secret|token|credential)', re.IGNORECASE),
         'Sensitive data sent to webhook', Severity.CRITICAL),
        (re.compile(r'(?:fetch|axios|request)\s*\([^)]*\.env', re.IGNORECASE),
         'Environment variables sent externally', Severity.CRITICAL),
        # Response narration of sensitive data
        (re.compile(r'response.*(?:narrate|include|contain).*(?:password|secret|credential)', re.IGNORECASE),
         'Response narrates sensitive data', Severity.HIGH),
        (re.compile(r'(?:say|tell|respond).*user.*(?:password|api_key|secret)', re.IGNORECASE),
         'Agent instructed to reveal secrets', Severity.CRITICAL),
        # File content exfiltration through tools
        (re.compile(r'(?:upload|send|post).*(?:\.ssh|\.aws|\.env|credentials)', re.IGNORECASE),
         'Sensitive file exfiltration via tool', Severity.CRITICAL),
        (re.compile(r'tool\.(?:call|execute).*(?:exfil|leak|send).*(?:data|secret)', re.IGNORECASE),
         'Exfiltration via tool call', Severity.CRITICAL),
    ]

    # Input validation patterns (good patterns - reduce severity)
    VALIDATION_PATTERNS = [
        re.compile(r'sanitize', re.IGNORECASE),
        re.compile(r'validate.*input', re.IGNORECASE),
        re.compile(r'escape.*html', re.IGNORECASE),
        re.compile(r'clean.*prompt', re.IGNORECASE),
        re.compile(r'filter.*input', re.IGNORECASE),
        re.compile(r'encode.*output', re.IGNORECASE),
        re.compile(r'parameterized', re.IGNORECASE),
        re.compile(r'prepared.*statement', re.IGNORECASE),
    ]

    # Rate limiting patterns (good patterns)
    RATE_LIMIT_PATTERNS = [
        re.compile(r'rate.*limit', re.IGNORECASE),
        re.compile(r'throttle', re.IGNORECASE),
        re.compile(r'max.*request', re.IGNORECASE),
        re.compile(r'quota', re.IGNORECASE),
        re.compile(r'budget', re.IGNORECASE),
    ]

    # Human-in-the-loop patterns (good patterns)
    HITL_PATTERNS = [
        re.compile(r'human.*in.*loop', re.IGNORECASE),
        re.compile(r'require.*approval', re.IGNORECASE),
        re.compile(r'confirm.*action', re.IGNORECASE),
        re.compile(r'await.*user', re.IGNORECASE),
        re.compile(r'manual.*review', re.IGNORECASE),
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def is_available(self) -> bool:
        """Built-in scanner is always available (no external tool needed)."""
        return True

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return higher confidence for files with LLM/AI indicators.

        Reads a sample of the file to detect LLM-related imports and calls.
        Returns 60 for LLM-related files, 20 otherwise (still scans but at
        lower priority than specialized scanners).

        Args:
            file_path: Path to file to analyze.
            content_head: Optional pre-read file head (first 8KB).

        Returns:
            Confidence score 0-100.
        """
        if not self.can_scan(file_path):
            return 0
        try:
            if content_head is not None:
                text = content_head[:4096].lower()
            else:
                text = file_path.read_text(encoding="utf-8", errors="replace")[:4096].lower()
            llm_indicators = [
                'openai', 'anthropic', 'langchain', 'llm', 'gpt',
                'completion', 'chat', 'llamaindex', 'huggingface',
                'prompt', 'generate', 'llama', 'claude', 'gemini',
            ]
            matches = sum(1 for ind in llm_indicators if ind in text)
            if matches >= 3:
                return 60  # Strong LLM context
            if matches >= 1:
                return 40  # Some LLM context
        except (OSError, UnicodeDecodeError):
            pass
        return 20

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def _detect_insecure_output_handling(
        self, lines: List[str], has_validation: bool
    ) -> List[ScannerIssue]:
        """
        LLM05 Taint Analysis: Detect insecure handling of LLM output.

        Performs lightweight intra-function taint tracking:
        1. Identify lines where a variable receives LLM output (source).
        2. Track derived variables (assignments from tainted variables).
        3. Check if any tainted variable reaches a dangerous sink within
           a configurable line window (TAINT_WINDOW).

        This catches real-world patterns like:
            output = llm(...)
            url = output['choices'][0]['text'].split(...)[1]
            requests.get(url)   # SSRF via LLM output

        Args:
            lines: Source code lines of the file.
            has_validation: Whether the file contains output validation patterns.

        Returns:
            List of ScannerIssue for each tainted-source-to-dangerous-sink flow.
        """
        issues: List[ScannerIssue] = []
        # Track tainted variables: {var_name: source_line_number}
        tainted: dict[str, int] = {}
        # Set of (source_line, sink_line) pairs already reported to avoid duplicates
        reported: set[Tuple[int, int]] = set()

        # Fetch pre-compiled sink templates once before the loop
        compiled_sinks = self._get_compiled_sink_templates()

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments and blank lines
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            # --- Step 1: Detect LLM output sources ---
            for src_pattern in self.LLM_OUTPUT_SOURCE_PATTERNS:
                m = src_pattern.search(stripped)
                if m:
                    var_name = m.group(1)
                    # Avoid tainting overly-generic single-char variables or
                    # common loop vars that generate false positives
                    if len(var_name) >= 2 and var_name not in (
                        'if', 'in', 'is', 'or', 'os', 're', 'io',
                    ):
                        tainted[var_name] = line_num

            # --- Step 2: Propagate taint through assignments ---
            # Matches: new_var = tainted_var.something or new_var = func(tainted_var)
            assign_match = _ASSIGN_RE.match(stripped)
            if assign_match:
                new_var = assign_match.group(1)
                rhs = assign_match.group(2)
                # Check if any tainted variable appears in the RHS
                for tvar, src_line in list(tainted.items()):
                    # Only propagate within the taint window
                    if (line_num - src_line) <= self.TAINT_WINDOW:
                        # Use word boundary to avoid partial matches
                        if re.search(r'\b' + re.escape(tvar) + r'\b', rhs):
                            if len(new_var) >= 2 and new_var not in (
                                'if', 'in', 'is', 'or', 'os', 're', 'io',
                            ):
                                tainted[new_var] = src_line

            # --- Step 3: Check if tainted variables reach sinks ---
            # Use pre-compiled sink templates: fast string 'in' check first,
            # then regex match, then verify captured variable name.
            for tvar, src_line in list(tainted.items()):
                # Only check within the taint window
                if (line_num - src_line) > self.TAINT_WINDOW:
                    continue
                # Fast pre-filter: skip if variable name not on this line at all
                if tvar not in stripped:
                    continue
                for sink_re, message, severity in compiled_sinks:
                    try:
                        sink_m = sink_re.search(stripped)
                        if sink_m:
                            # Verify the captured word is exactly our tainted var
                            try:
                                captured = sink_m.group('tvar')
                            except IndexError:
                                captured = tvar  # fallback if no named group
                            if captured != tvar:
                                continue
                            report_key = (src_line, line_num)
                            if report_key not in reported:
                                reported.add(report_key)
                                # Downgrade severity if validation is present
                                eff_severity = severity
                                if has_validation and eff_severity == Severity.CRITICAL:
                                    eff_severity = Severity.HIGH
                                elif has_validation and eff_severity == Severity.HIGH:
                                    eff_severity = Severity.MEDIUM
                                issues.append(ScannerIssue(
                                    rule_id="LLM05-TAINT",
                                    severity=eff_severity,
                                    message=(
                                        f"Insecure Output Handling: {message} - "
                                        f"variable '{tvar}' from LLM source (line {src_line}) "
                                        f"flows to dangerous sink. Validate and sanitize all "
                                        f"LLM output before use in {self._sink_category(eff_severity)}"
                                    ),
                                    line=line_num,
                                    column=1,
                                    cwe_id=self._cwe_for_sink(message),
                                    cwe_link=f"https://cwe.mitre.org/data/definitions/{self._cwe_for_sink(message)}.html",
                                ))
                    except re.error:
                        continue

            # --- Step 4: Also detect direct LLM output access in sinks ---
            # Catches: requests.get(output['choices'][0]['text'])
            # or subprocess.run(completion.choices[0].message.content)
            for pattern, message, severity, cwe in self.DIRECT_LLM_SINK_PATTERNS:
                try:
                    if pattern.search(stripped):
                        issues.append(ScannerIssue(
                            rule_id="LLM05-TAINT",
                            severity=severity,
                            message=(
                                f"Insecure Output Handling: {message} - "
                                f"validate and sanitize all LLM output before use"
                            ),
                            line=line_num,
                            column=1,
                            cwe_id=cwe,
                            cwe_link=f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                        ))
                except re.error:
                    continue

        return issues

    @staticmethod
    def _cwe_for_sink(message: str) -> int:
        """Map sink message to CWE ID."""
        msg_lower = message.lower()
        if 'rce' in msg_lower or 'subprocess' in msg_lower or 'os.' in msg_lower:
            return 78  # CWE-78: OS Command Injection
        if 'eval' in msg_lower or 'exec' in msg_lower:
            return 95  # CWE-95: Eval Injection
        if 'ssrf' in msg_lower or 'url' in msg_lower or 'request' in msg_lower:
            return 918  # CWE-918: SSRF
        if 'path' in msg_lower or 'file' in msg_lower or 'open' in msg_lower:
            return 22  # CWE-22: Path Traversal
        if 'sql' in msg_lower:
            return 89  # CWE-89: SQL Injection
        if 'xss' in msg_lower or 'html' in msg_lower or 'template' in msg_lower:
            return 79  # CWE-79: XSS
        return 74  # CWE-74: Generic Injection

    @staticmethod
    def _sink_category(severity: Severity) -> str:
        """Return human-readable category based on severity."""
        if severity == Severity.CRITICAL:
            return "code execution contexts"
        if severity == Severity.HIGH:
            return "network/file/database operations"
        return "HTML rendering contexts"

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for OWASP LLM Top 10 (2025) vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            _offsets = _build_line_offsets(content)

            # Split content into lines once; reused by multiple subsystems
            lines = content.split('\n')

            # Check if file is LLM-related
            llm_indicators = [
                'llm', 'gpt', 'openai', 'anthropic', 'claude', 'gemini',
                'prompt', 'completion', 'chat', 'generate', 'model',
                'langchain', 'llamaindex', 'huggingface', 'embedding',
                'vector', 'rag', 'agent', 'tool_use',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in llm_indicators):
                # Still scan with YAML rules
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=yaml_issues,
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for mitigations (reduces severity)
            has_validation = any(
                p.search(content)
                for p in self.VALIDATION_PATTERNS
            )

            has_rate_limit = any(
                p.search(content)
                for p in self.RATE_LIMIT_PATTERNS
            )

            has_hitl = any(
                p.search(content)
                for p in self.HITL_PATTERNS
            )

            # LLM01: Prompt Injection
            for pattern, message in self.PROMPT_INJECTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    severity = Severity.HIGH if has_validation else Severity.CRITICAL
                    issues.append(ScannerIssue(
                        rule_id="LLM01",
                        severity=severity,
                        message=f"Prompt Injection: {message} - sanitize input, use semantic filters",
                        line=line,
                        column=1,
                    ))

            # CVE-2024-5184: Email Assistant Code Injection
            for pattern, message, severity in self.EMAIL_INJECTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM01-CVE",
                        severity=severity,
                        message=f"{message} - sanitize email content before LLM processing",
                        line=line,
                        column=1,
                        cwe_id=94,
                        cwe_link="https://cwe.mitre.org/data/definitions/94.html",
                    ))

            # Prompt Obfuscation Detection
            for pattern, message, severity in self.PROMPT_OBFUSCATION_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM01-OBF",
                        severity=severity,
                        message=f"Prompt Obfuscation: {message} - filter control tokens and hidden content",
                        line=line,
                        column=1,
                    ))

            # LLM02: Sensitive Information Disclosure
            for pattern, message in self.DISCLOSURE_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_text = match.group(0)
                    # Skip if the flagged keyword is inside a static string literal
                    # (no interpolation: no ${}, no .format(), no % formatting)
                    if re.search(r'["\'][^"\']*(?:prompt|credential|api_key)[^"\']*["\']', matched_text, re.IGNORECASE):
                        if not re.search(r'[\$`]\{|\.format\(|%\s*[(\w]', matched_text):
                            continue  # Static string, not actual data exposure
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM02",
                        severity=Severity.HIGH,
                        message=f"Information Disclosure: {message} - use env vars, apply least privilege",
                        line=line,
                        column=1,
                    ))

            # LLM03: Supply Chain
            for pattern, message in self.SUPPLY_CHAIN_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM03",
                        severity=Severity.HIGH,
                        message=f"Supply Chain: {message} - verify provenance, use SBOM",
                        line=line,
                        column=1,
                    ))

            # LLM04: Data and Model Poisoning
            for pattern, message in self.POISONING_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM04",
                        severity=Severity.HIGH,
                        message=f"Poisoning Risk: {message} - validate training data, use anomaly detection",
                        line=line,
                        column=1,
                    ))

            # LLM05: Improper Output Handling (single-line patterns)
            for pattern, message in self.OUTPUT_HANDLING_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM05",
                        severity=Severity.CRITICAL,
                        message=f"Improper Output: {message} - treat LLM as untrusted, use parameterized queries",
                        line=line,
                        column=1,
                    ))

            # LLM05: Taint Analysis for insecure output handling
            # Tracks LLM output variables across multiple lines to detect
            # cases where output flows to dangerous sinks (subprocess, requests, etc.)
            taint_issues = self._detect_insecure_output_handling(
                lines, has_validation
            )
            issues.extend(taint_issues)

            # LLM06: Excessive Agency
            for pattern, message in self.AGENCY_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    severity = Severity.MEDIUM if has_hitl else Severity.HIGH
                    issues.append(ScannerIssue(
                        rule_id="LLM06",
                        severity=severity,
                        message=f"Excessive Agency: {message} - apply least privilege, require HITL",
                        line=line,
                        column=1,
                    ))

            # LLM07: System Prompt Leakage (NEW)
            for pattern, message in self.SYSTEM_PROMPT_LEAKAGE_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM07",
                        severity=Severity.HIGH,
                        message=f"System Prompt Leakage: {message} - never embed secrets in prompts",
                        line=line,
                        column=1,
                    ))

            # LLM08: Vector and Embedding Weaknesses (NEW)
            for pattern, message in self.VECTOR_EMBEDDING_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM08",
                        severity=Severity.MEDIUM,
                        message=f"Vector/Embedding Weakness: {message} - use access controls, tenant isolation",
                        line=line,
                        column=1,
                    ))

            # LLM09: Misinformation
            for pattern, message in self.MISINFORMATION_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM09",
                        severity=Severity.MEDIUM,
                        message=f"Misinformation Risk: {message} - use RAG for grounding, add HITL review",
                        line=line,
                        column=1,
                    ))

            # LLM10: Unbounded Consumption
            for pattern, message in self.UNBOUNDED_CONSUMPTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    severity = Severity.MEDIUM if has_rate_limit else Severity.HIGH
                    issues.append(ScannerIssue(
                        rule_id="LLM10",
                        severity=severity,
                        message=f"Unbounded Consumption: {message} - set token limits, add cost budgets",
                        line=line,
                        column=1,
                    ))

            # Data Leak via Legitimate Channel (LLM02 extension)
            # Detects sensitive data exfiltration through Slack, email, webhooks, etc.
            for pattern, message, severity in self.DATA_LEAK_CHANNEL_PATTERNS:
                match = pattern.search(content)
                if match:
                    line = _get_line_number(_offsets, match.start())
                    issues.append(ScannerIssue(
                        rule_id="LLM02-DL",
                        severity=severity,
                        message=f"Data Leak Channel: {message}",
                        line=line,
                        column=1,
                    ))

            # Scan with YAML rules
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
