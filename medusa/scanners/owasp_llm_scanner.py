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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


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
        (r'(prompt|message)\s*=\s*.{0,50}\+\s*(user|input|request)',
         'User input concatenated into prompt (direct injection risk)'),
        (r'f["\'].{0,100}\{(user_input|request|query|message)\}.{0,100}["\']',
         'User input interpolated in prompt string'),
        (r'(system_prompt|instructions)\s*\+\s*',
         'System prompt concatenated with untrusted data'),
        (r'prompt\s*=\s*(request|input|body)\.',
         'Prompt directly from request without sanitization'),
        (r'\.(format|replace)\s*\(.{0,50}user',
         'User input in string formatting for prompt'),
        # Indirect injection patterns (from external sources)
        (r'(fetch|axios|request)\s*\(.{0,100}\).{0,50}prompt',
         'External content fetched and used in prompt (indirect injection)'),
        (r'(scrape|crawl|parse).{0,50}\+.{0,50}prompt',
         'Scraped content in prompt (indirect injection vector)'),
        (r'(document|file|url).{0,50}content.{0,50}prompt',
         'Document content injected into prompt'),
    ]

    # CVE-2024-5184: LLM Email Assistant Code Injection
    # Email content passed directly to LLM without sanitization
    EMAIL_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'email\.body.*(?:prompt|llm|generate)',
         'CVE-2024-5184: Email body passed to LLM without sanitization', Severity.CRITICAL),
        (r'message\.content.*(?:llm\.|openai|anthropic)',
         'CVE-2024-5184: Email message content in LLM call', Severity.CRITICAL),
        (r'inbox\[.*\].*(?:generate|complete|chat)',
         'CVE-2024-5184: Inbox content in LLM generation', Severity.HIGH),
        (r'mail\.(?:subject|body|text).*(?:prompt|system)',
         'CVE-2024-5184: Email field in prompt construction', Severity.HIGH),
        (r'(?:imap|pop3|smtp).*(?:llm|ai|assistant)',
         'Email protocol integration with LLM - verify sanitization', Severity.MEDIUM),
        (r'email_assistant.*(?:process|handle).*(?:unsanitized|raw)',
         'Email assistant processing raw email content', Severity.CRITICAL),
    ]

    # Prompt Injection Obfuscation Detection
    # Detect attempts to hide malicious prompts
    PROMPT_OBFUSCATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # HTML comment hiding
        (r'<!--.*(?:ignore|forget|disregard|new instructions).*-->',
         'HTML comment with injection keywords', Severity.HIGH),
        (r'<hidden>.*</hidden>',
         'Hidden HTML tag (potential prompt hiding)', Severity.MEDIUM),
        # Zero-width character detection (Unicode obfuscation)
        (r'[\u200b\u200c\u200d\ufeff]',
         'Zero-width Unicode characters (prompt obfuscation)', Severity.HIGH),
        # Control token abuse (model-specific tokens)
        (r'\[INST\]|\[/INST\]',
         'Llama instruction tokens in input (control token injection)', Severity.CRITICAL),
        (r'<\|im_start\|>|<\|im_end\|>',
         'ChatML control tokens in input (control token injection)', Severity.CRITICAL),
        (r'<\|system\|>|<\|user\|>|<\|assistant\|>',
         'Role tokens in input (control token injection)', Severity.CRITICAL),
        (r'<<SYS>>|<</SYS>>',
         'Llama2 system tokens in input', Severity.CRITICAL),
        # Base64/encoding obfuscation in prompts
        (r'base64\.(?:b64decode|decode)\s*\([^)]*(?:prompt|instruction)',
         'Base64 decoding in prompt construction', Severity.HIGH),
        (r'(?:atob|btoa)\s*\([^)]*(?:prompt|message)',
         'JavaScript base64 in prompt handling', Severity.HIGH),
        # Unicode escape sequences
        (r'\\u[0-9a-fA-F]{4}.*(?:prompt|instruction)',
         'Unicode escapes in prompt (obfuscation attempt)', Severity.MEDIUM),
        # Markdown/formatting abuse
        (r'\[(?:system|admin|root)\]:',
         'Fake role prefix in markdown format', Severity.HIGH),
        (r'```(?:system|instruction|ignore).*```',
         'Code block with injection keywords', Severity.MEDIUM),
    ]

    # LLM02: Sensitive Information Disclosure patterns
    DISCLOSURE_PATTERNS = [
        (r'(api_key|apikey|secret|password|token)\s*=\s*["\'][^"\']{8,}',
         'Hardcoded credential in code'),
        (r'(print|log|console)\s*\(.{0,50}prompt',
         'Prompt logged (may expose system instructions)'),
        (r'return.{0,30}system_prompt',
         'System prompt returned to user'),
        (r'response.{0,50}\+.{0,50}(config|credential)',
         'Configuration/credential data in response'),
        (r'(error|exception).{0,50}prompt',
         'Prompt exposed in error message'),
        (r'(pii|personal|ssn|email).{0,50}response',
         'PII potentially in response'),
        (r'training.{0,30}data.{0,30}expos',
         'Training data exposure risk'),
    ]

    # LLM03: Supply Chain patterns
    SUPPLY_CHAIN_PATTERNS = [
        (r'from_pretrained\s*\(["\'][^"\']+["\']',
         'Pre-trained model loaded - verify source integrity'),
        (r'(lora|adapter).*load.*\(',
         'LoRA adapter loaded - verify provenance'),
        (r'(pickle|joblib|dill)\.load\s*\(',
         'Insecure deserialization (use safetensors)'),
        (r'download.*model.*http://',
         'Model downloaded over HTTP (use HTTPS)'),
        (r'hub\.(download|load).*trust_remote_code\s*=\s*True',
         'Remote code execution enabled in model loading'),
    ]

    # LLM04: Data and Model Poisoning patterns
    POISONING_PATTERNS = [
        (r'(fine_tune|train).*user.*data',
         'Training on user-provided data (poisoning risk)'),
        (r'(embed|index).*untrusted',
         'Embedding untrusted content'),
        (r'feedback.*train',
         'User feedback used in training without validation'),
        (r'(rlhf|rlaif).*\(.*user',
         'RLHF with unvalidated user input'),
    ]

    # LLM05: Improper Output Handling patterns (RCE, XSS, SQLi)
    OUTPUT_HANDLING_PATTERNS = [
        (r'(innerHTML|dangerouslySetInnerHTML)\s*=\s*.*response',
         'LLM response rendered as HTML (XSS risk)'),
        (r'eval\s*\(.*response',
         'LLM response executed via eval (RCE risk)'),
        (r'exec\s*\(.*response',
         'LLM response executed via exec (RCE risk)'),
        (r'subprocess.*response',
         'LLM response passed to subprocess'),
        (r'document\.write\s*\(.*response',
         'LLM response in document.write'),
        (r'(cursor|execute)\s*\(.*response',
         'LLM response in SQL query (SQLi risk)'),
        (r'child_process.*response',
         'LLM response in child process'),
        (r'Function\s*\(.*response',
         'LLM response in Function constructor'),
    ]

    # LLM06: Excessive Agency patterns
    AGENCY_PATTERNS = [
        (r'auto_execute\s*=\s*True',
         'Auto-execution enabled (excessive agency)'),
        (r'confirm\s*=\s*False.{0,50}(delete|remove|drop)',
         'Destructive action without confirmation'),
        (r'(sudo|admin|root)\s*=\s*True',
         'Elevated privileges enabled by default'),
        (r'permissions\s*=\s*\[?\s*["\']?\*',
         'Wildcard permissions granted'),
        (r'human_in_loop\s*=\s*False',
         'Human oversight disabled'),
        (r'auto_approve\s*=\s*True',
         'Auto-approval enabled'),
        (r'(shell|bash|cmd)\s*=\s*True',
         'Shell access enabled for agent'),
        (r'run_command.{0,30}\(.{0,50}llm',
         'LLM can execute system commands'),
        # Confused deputy indicators
        (r'(service_account|admin_token).{0,50}tool',
         'Tool using service account (confused deputy risk)'),
        (r'privileged\s*=\s*True',
         'Privileged mode enabled'),
    ]

    # LLM07: System Prompt Leakage (NEW in 2025)
    SYSTEM_PROMPT_LEAKAGE_PATTERNS = [
        (r'(system_prompt|system_message)\s*=\s*["\'][^"\']{50,}',
         'Long system prompt with potential sensitive instructions'),
        (r'(api_key|password|secret|token)\s*.*system.*prompt',
         'Credentials referenced in system prompt'),
        (r'system.*prompt.*(return|response|output)',
         'System prompt potentially exposed in output'),
        (r'(database|db_name|table)\s*.*system.*prompt',
         'Database details in system prompt'),
        (r'internal.*rule.*system.*prompt',
         'Internal rules in system prompt (should use guardrails)'),
        (r'role.*admin.*system.*prompt',
         'Admin role info in system prompt'),
        (r'(limit|threshold|max).*system.*prompt',
         'Security limits in system prompt (can be bypassed)'),
    ]

    # LLM08: Vector and Embedding Weaknesses (NEW in 2025)
    VECTOR_EMBEDDING_PATTERNS = [
        (r'(embed|vector).*user.*input',
         'User input directly embedded without validation'),
        (r'(similarity|nearest).*search.*\*',
         'Unrestricted similarity search'),
        (r'(chroma|pinecone|weaviate|milvus).*public',
         'Vector DB with public access'),
        (r'embedding.*\(.*pii',
         'PII being embedded'),
        (r'(retrieve|search).*without.*filter',
         'Vector retrieval without access filtering'),
        (r'multi.*tenant.*embed.*shared',
         'Shared embeddings across tenants'),
    ]

    # LLM09: Misinformation/Hallucination patterns
    MISINFORMATION_PATTERNS = [
        (r'(medical|legal|financial).*advice.*llm',
         'LLM providing sensitive advice without guardrails'),
        (r'(fact|verify|ground).*=\s*False',
         'Fact-checking/grounding disabled'),
        (r'hallucination.*allow',
         'Hallucination explicitly allowed'),
        (r'response.*direct.*user.*without.*check',
         'LLM response sent without verification'),
    ]

    # LLM10: Unbounded Consumption (DoS/DoW)
    UNBOUNDED_CONSUMPTION_PATTERNS = [
        (r'max_tokens\s*=\s*None',
         'No max_tokens limit (unbounded consumption)'),
        (r'max_tokens\s*=\s*\d{5,}',
         'Excessively high max_tokens value'),
        (r'while\s+True.*generate',
         'Unbounded generation loop'),
        (r'(input|prompt).*\*\s*\d{3,}',
         'Input multiplication (amplification attack)'),
        (r'(timeout|max_time)\s*=\s*(None|0)',
         'No timeout configured'),
        (r'retry.*=\s*(-1|unlimited|infinite)',
         'Unlimited retries configured'),
        (r'(budget|cost|limit)\s*=\s*None',
         'No cost/budget limit (Denial of Wallet risk)'),
    ]

    # Data Leak via Legitimate Channel patterns
    # Exfiltration through legitimate tool calls (Slack, email, webhook)
    DATA_LEAK_CHANNEL_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Sensitive data sent through messaging tools
        (r'(slack|discord|teams)\.(?:post|send|message)\s*\([^)]*(?:password|secret|api_key|token|credential)',
         'Sensitive data sent via messaging channel', Severity.CRITICAL),
        (r'(slack|discord|teams)\.(?:post|send|message)\s*\([^)]*(?:env|environ|config)',
         'Environment/config data sent via messaging', Severity.HIGH),
        # Email exfiltration
        (r'(?:send_email|smtp|sendmail)\s*\([^)]*(?:password|secret|api_key|token)',
         'Sensitive data in email content', Severity.CRITICAL),
        (r'mail\.(?:send|compose)\s*\([^)]*(?:credential|key|secret)',
         'Credentials in email', Severity.CRITICAL),
        # Webhook exfiltration
        (r'webhook\s*\([^)]*(?:password|secret|token|credential)',
         'Sensitive data sent to webhook', Severity.CRITICAL),
        (r'(?:fetch|axios|request)\s*\([^)]*\.env',
         'Environment variables sent externally', Severity.CRITICAL),
        # Response narration of sensitive data
        (r'response.*(?:narrate|include|contain).*(?:password|secret|credential)',
         'Response narrates sensitive data', Severity.HIGH),
        (r'(?:say|tell|respond).*user.*(?:password|api_key|secret)',
         'Agent instructed to reveal secrets', Severity.CRITICAL),
        # File content exfiltration through tools
        (r'(?:upload|send|post).*(?:\.ssh|\.aws|\.env|credentials)',
         'Sensitive file exfiltration via tool', Severity.CRITICAL),
        (r'tool\.(?:call|execute).*(?:exfil|leak|send).*(?:data|secret)',
         'Exfiltration via tool call', Severity.CRITICAL),
    ]

    # Input validation patterns (good patterns - reduce severity)
    VALIDATION_PATTERNS = [
        r'sanitize',
        r'validate.*input',
        r'escape.*html',
        r'clean.*prompt',
        r'filter.*input',
        r'encode.*output',
        r'parameterized',
        r'prepared.*statement',
    ]

    # Rate limiting patterns (good patterns)
    RATE_LIMIT_PATTERNS = [
        r'rate.*limit',
        r'throttle',
        r'max.*request',
        r'quota',
        r'budget',
    ]

    # Human-in-the-loop patterns (good patterns)
    HITL_PATTERNS = [
        r'human.*in.*loop',
        r'require.*approval',
        r'confirm.*action',
        r'await.*user',
        r'manual.*review',
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
        """Scan for OWASP LLM Top 10 (2025) vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

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
                lines = content.split('\n')
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
                re.search(p, content, re.IGNORECASE)
                for p in self.VALIDATION_PATTERNS
            )

            has_rate_limit = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.RATE_LIMIT_PATTERNS
            )

            has_hitl = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.HITL_PATTERNS
            )

            # LLM01: Prompt Injection
            for pattern, message in self.PROMPT_INJECTION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
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
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
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
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM01-OBF",
                        severity=severity,
                        message=f"Prompt Obfuscation: {message} - filter control tokens and hidden content",
                        line=line,
                        column=1,
                    ))

            # LLM02: Sensitive Information Disclosure
            for pattern, message in self.DISCLOSURE_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM02",
                        severity=Severity.HIGH,
                        message=f"Information Disclosure: {message} - use env vars, apply least privilege",
                        line=line,
                        column=1,
                    ))

            # LLM03: Supply Chain
            for pattern, message in self.SUPPLY_CHAIN_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM03",
                        severity=Severity.HIGH,
                        message=f"Supply Chain: {message} - verify provenance, use SBOM",
                        line=line,
                        column=1,
                    ))

            # LLM04: Data and Model Poisoning
            for pattern, message in self.POISONING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM04",
                        severity=Severity.HIGH,
                        message=f"Poisoning Risk: {message} - validate training data, use anomaly detection",
                        line=line,
                        column=1,
                    ))

            # LLM05: Improper Output Handling
            for pattern, message in self.OUTPUT_HANDLING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM05",
                        severity=Severity.CRITICAL,
                        message=f"Improper Output: {message} - treat LLM as untrusted, use parameterized queries",
                        line=line,
                        column=1,
                    ))

            # LLM06: Excessive Agency
            for pattern, message in self.AGENCY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
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
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM07",
                        severity=Severity.HIGH,
                        message=f"System Prompt Leakage: {message} - never embed secrets in prompts",
                        line=line,
                        column=1,
                    ))

            # LLM08: Vector and Embedding Weaknesses (NEW)
            for pattern, message in self.VECTOR_EMBEDDING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM08",
                        severity=Severity.MEDIUM,
                        message=f"Vector/Embedding Weakness: {message} - use access controls, tenant isolation",
                        line=line,
                        column=1,
                    ))

            # LLM09: Misinformation
            for pattern, message in self.MISINFORMATION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM09",
                        severity=Severity.MEDIUM,
                        message=f"Misinformation Risk: {message} - use RAG for grounding, add HITL review",
                        line=line,
                        column=1,
                    ))

            # LLM10: Unbounded Consumption
            for pattern, message in self.UNBOUNDED_CONSUMPTION_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
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
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="LLM02-DL",
                        severity=severity,
                        message=f"Data Leak Channel: {message}",
                        line=line,
                        column=1,
                    ))

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
