#!/usr/bin/env python3
"""
MEDUSA Excessive Agency Scanner
Detects over-permissioned AI agents and missing safety controls

Based on:
- OWASP Top 10 for LLM Applications - Excessive Agency
- "Agentic Design Patterns" - Guardrails/Safety Patterns
- "Generative AI Security" - Agent Security
- Document-to-RCE chain attacks via LLM agents

Detects:
- Agents with excessive permissions
- Missing before_tool_callback validation
- Unbounded action loops
- Missing human-in-the-loop controls
- Over-permissioned tool access
- Unsandboxed code execution tools (PythonREPL, ShellTool)
- Document parsers feeding LLM agent chains
- Agent executors with dangerous tool combinations
- Dynamic tool loading with code execution capabilities
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity, filter_contextual_fps
from medusa.scanners._ml_context import has_ml_context


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
    - EXA011: Unsandboxed code execution tools (PythonREPL, ShellTool, BashProcess)
    - EXA012: Document loaders feeding LLM agent chains (document-to-RCE risk)
    - EXA013: Agent executor with dangerous tool combinations
    - EXA014: Dynamic tool loading with code execution capabilities
    - EXA015: Direct exec/eval/subprocess in agent tool definitions
    """

    # EXA001: Unrestricted tool access
    UNRESTRICTED_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'tools\s*[=:]\s*(?:all|"\*"|\'?\*\'?|\[.*\*.*\])', re.IGNORECASE),
         'Agent with unrestricted tool access', Severity.HIGH),
        (re.compile(r'allow_all_tools|all_tools_enabled', re.IGNORECASE),
         'All tools enabled for agent', Severity.HIGH),
        (re.compile(r'tool_permissions\s*[=:]\s*(?:None|null|unrestricted)', re.IGNORECASE),
         'No tool permission restrictions', Severity.HIGH),
        (re.compile(r'(?:disable|skip).*tool.*(?:filter|restriction)', re.IGNORECASE),
         'Tool restrictions disabled', Severity.HIGH),
    ]

    # EXA002: Missing before_tool_callback
    CALLBACK_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:Agent|Runner)\s*\([^)]*\)(?!.*before_tool_callback)', re.IGNORECASE),
         'Agent without before_tool_callback validation', Severity.MEDIUM),
        (re.compile(r'tool_executor(?!.*(?:validate|callback|check))', re.IGNORECASE),
         'Tool executor without validation hook', Severity.MEDIUM),
        (re.compile(r'execute_tool\s*\([^)]*\)(?!.*(?:valid|check|verify))', re.IGNORECASE),
         'Tool execution without validation', Severity.MEDIUM),
        (re.compile(r'before_tool_callback\s*[=:]\s*(?:None|null)', re.IGNORECASE),
         'before_tool_callback explicitly disabled', Severity.HIGH),
    ]

    # EXA003: Unbounded loops
    UNBOUNDED_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'while\s+True.*(?:agent|action|tool)', re.IGNORECASE),
         'Unbounded while loop with agent/tool', Severity.HIGH),
        (re.compile(r'max_iterations\s*[=:]\s*(?:None|null|0|-1|inf)', re.IGNORECASE),
         'No maximum iteration limit', Severity.HIGH),
        (re.compile(r'(?:agent|loop).*(?:forever|infinite|unlimited)', re.IGNORECASE),
         'Infinite agent loop', Severity.HIGH),
        (re.compile(r'for\s+_\s+in\s+(?:iter|count)\s*\(\)', re.IGNORECASE),
         'Unbounded iteration', Severity.MEDIUM),
        (re.compile(r'recursion_limit\s*[=:]\s*(?:None|null|0|-1)', re.IGNORECASE),
         'No recursion limit', Severity.HIGH),
    ]

    # EXA004: Missing human approval
    HUMAN_APPROVAL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:auto|automatic).*(?:execute|run|action)(?!.*(?:confirm|approve|human))', re.IGNORECASE),
         'Auto-execution without human approval', Severity.MEDIUM),
        (re.compile(r'(?:skip|bypass).*(?:confirm|approval|human)', re.IGNORECASE),
         'Human approval bypassed', Severity.HIGH),
        (re.compile(r'require_confirmation\s*[=:]\s*(?:False|false)', re.IGNORECASE),
         'Confirmation requirement disabled', Severity.HIGH),
        (re.compile(r'human_in_the_loop\s*[=:]\s*(?:False|false)', re.IGNORECASE),
         'Human-in-the-loop disabled', Severity.HIGH),
        (re.compile(r'auto_approve\s*[=:]\s*(?:True|true)', re.IGNORECASE),
         'Auto-approval enabled', Severity.HIGH),
    ]

    # EXA005: Write/delete permissions
    WRITE_DELETE_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:agent|tool).*(?:write|delete|remove|modify).*(?:file|disk|storage)', re.IGNORECASE),
         'Agent with filesystem write/delete access', Severity.HIGH),
        (re.compile(r'allow_(?:write|delete|modify)\s*[=:]\s*(?:True|true)', re.IGNORECASE),
         'Write/delete permissions enabled', Severity.HIGH),
        (re.compile(r'(?:os\.remove|os\.unlink|shutil\.rmtree).*(?:agent|tool)', re.IGNORECASE),
         'File deletion in agent context', Severity.CRITICAL),
        (re.compile(r'(?:truncate|overwrite).*(?:agent|tool)', re.IGNORECASE),
         'Destructive file operation', Severity.HIGH),
    ]

    # EXA006: Network/external access
    NETWORK_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:agent|tool).*(?:http|request|fetch|api)', re.IGNORECASE),
         'Agent with network access', Severity.MEDIUM),
        (re.compile(r'allow_(?:network|external|internet)', re.IGNORECASE),
         'External network access enabled', Severity.MEDIUM),
        (re.compile(r'(?:socket|websocket).*(?:agent|tool)', re.IGNORECASE),
         'Socket access in agent', Severity.HIGH),
        (re.compile(r'(?:agent|tool).*(?:download|upload)', re.IGNORECASE),
         'Agent with download/upload capability', Severity.MEDIUM),
    ]

    # EXA007: Missing logging/audit
    AUDIT_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:agent|tool).*(?:execute|action)(?!.*(?:log|audit|record))', re.IGNORECASE),
         'Agent action without logging', Severity.LOW),
        (re.compile(r'(?:disable|skip).*(?:log|audit)', re.IGNORECASE),
         'Logging/audit disabled', Severity.MEDIUM),
        (re.compile(r'audit\s*[=:]\s*(?:False|false|None)', re.IGNORECASE),
         'Audit explicitly disabled', Severity.MEDIUM),
    ]

    # EXA008: Auto-execution
    AUTO_EXEC_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'auto_execute\s*[=:]\s*(?:True|true)', re.IGNORECASE),
         'Auto-execution enabled without confirmation', Severity.HIGH),
        (re.compile(r'execute_immediately|run_without_confirm', re.IGNORECASE),
         'Immediate execution pattern', Severity.HIGH),
        (re.compile(r'(?:agent|action).*(?:auto|immediate).*(?:run|execute)', re.IGNORECASE),
         'Automatic agent execution', Severity.MEDIUM),
    ]

    # EXA009: Recursive agent calls
    RECURSIVE_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'agent.*(?:call|invoke).*agent(?!.*(?:depth|limit|max))', re.IGNORECASE),
         'Recursive agent calls without depth limit', Severity.HIGH),
        (re.compile(r'(?:spawn|create)_agent.*(?:within|inside).*agent', re.IGNORECASE),
         'Nested agent spawning', Severity.MEDIUM),
        (re.compile(r'sub_agent|child_agent|nested_agent', re.IGNORECASE),
         'Sub-agent pattern (verify depth limits)', Severity.LOW),
        (re.compile(r'max_depth\s*[=:]\s*(?:None|null|0|-1)', re.IGNORECASE),
         'No maximum depth for agent recursion', Severity.HIGH),
    ]

    # EXA010: Credential/secret access
    CREDENTIAL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(?:agent|tool).*(?:credential|password|secret|api_key)', re.IGNORECASE),
         'Agent with credential access', Severity.CRITICAL),
        (re.compile(r'(?:read|get|access).*(?:env|environment).*(?:agent|tool)', re.IGNORECASE),
         'Agent accessing environment variables', Severity.HIGH),
        (re.compile(r'(?:agent|tool).*(?:vault|keyring|secrets_manager)', re.IGNORECASE),
         'Agent with secrets manager access', Severity.CRITICAL),
        (re.compile(r'pass.*(?:credential|secret|key).*(?:to|agent)', re.IGNORECASE),
         'Credentials passed to agent', Severity.HIGH),
    ]

    # EXA011: Unsandboxed code execution tools
    CODE_EXEC_TOOL_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # LangChain PythonREPL variants - the primary RCE vector
        (re.compile(r'PythonREPL\s*\(', re.IGNORECASE),
         'Unsandboxed PythonREPL tool - enables arbitrary code execution via LLM', Severity.CRITICAL),
        (re.compile(r'PythonREPLTool\s*\(', re.IGNORECASE),
         'PythonREPLTool without sandboxing - enables RCE through LLM agent', Severity.CRITICAL),
        (re.compile(r'PythonAstREPLTool\s*\(', re.IGNORECASE),
         'PythonAstREPLTool without sandboxing - enables code execution via LLM', Severity.CRITICAL),
        # Import detection for PythonREPL utilities
        (re.compile(r'from\s+langchain_experimental\.utilities\s+import\s+PythonREPL', re.IGNORECASE),
         'Import of unsandboxed PythonREPL utility - RCE risk when used with agents', Severity.CRITICAL),
        (re.compile(r'from\s+langchain(?:_experimental)?\.tools(?:\.python)?.*import.*Python(?:REPL|Ast)', re.IGNORECASE),
         'Import of unsandboxed Python execution tool - RCE risk with agents', Severity.CRITICAL),
        # LangChain ShellTool / BashProcess
        (re.compile(r'ShellTool\s*\(', re.IGNORECASE),
         'ShellTool grants shell access to LLM agent - command injection risk', Severity.CRITICAL),
        (re.compile(r'BashProcess\s*\(', re.IGNORECASE),
         'BashProcess grants bash execution to LLM agent - RCE risk', Severity.CRITICAL),
        (re.compile(r'from\s+langchain(?:_community)?\.(?:tools|utilities).*import.*(?:ShellTool|BashProcess)', re.IGNORECASE),
         'Import of shell/bash execution tool for LLM agent', Severity.CRITICAL),
        # Generic REPL tool naming patterns
        (re.compile(r'(?:name|tool_name)\s*[=:]\s*["\']python_repl["\']', re.IGNORECASE),
         'Tool named python_repl - unsandboxed code execution via agent', Severity.CRITICAL),
        (re.compile(r'(?:name|tool_name)\s*[=:]\s*["\'](?:bash|shell|terminal)["\']', re.IGNORECASE),
         'Tool named bash/shell/terminal - command execution via agent', Severity.CRITICAL),
    ]

    # EXA012: Document loaders feeding LLM agent chains
    DOC_LOADER_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # Word document loaders
        (re.compile(r'Docx2txtLoader\s*\(', re.IGNORECASE),
         'Word document loader in agent chain - document content may trigger code execution', Severity.HIGH),
        (re.compile(r'UnstructuredWordDocumentLoader\s*\(', re.IGNORECASE),
         'Word document loader in agent chain - document-to-RCE risk', Severity.HIGH),
        (re.compile(r'from\s+langchain.*import.*Docx2txtLoader', re.IGNORECASE),
         'Import of Word document loader - verify no code execution tools in chain', Severity.HIGH),
        # PDF loaders
        (re.compile(r'(?:PyPDFLoader|PDFPlumberLoader|PyMuPDFLoader|UnstructuredPDFLoader)\s*\(', re.IGNORECASE),
         'PDF loader in agent chain - document content may trigger code execution', Severity.HIGH),
        (re.compile(r'from\s+langchain.*import.*(?:PyPDF|PDFPlumber|PyMuPDF|UnstructuredPDF)Loader', re.IGNORECASE),
         'Import of PDF document loader - verify no code execution tools in chain', Severity.HIGH),
        # Spreadsheet / CSV loaders
        (re.compile(r'(?:UnstructuredExcelLoader|CSVLoader)\s*\(', re.IGNORECASE),
         'Spreadsheet/CSV loader in agent chain - data may trigger code execution', Severity.HIGH),
        # Generic document loaders with user-uploaded content
        (re.compile(r'(?:DirectoryLoader|UnstructuredFileLoader|S3FileLoader)\s*\(', re.IGNORECASE),
         'Generic file loader in agent chain - untrusted content may reach exec tools', Severity.MEDIUM),
        # python-docx direct usage
        (re.compile(r'(?:docx|docx2txt|python-docx).*(?:open|load|read)', re.IGNORECASE),
         'Direct document parsing - verify output is not passed to code execution', Severity.MEDIUM),
        # openpyxl / pdfplumber direct usage
        (re.compile(r'(?:openpyxl|pdfplumber|PyPDF2|fitz)\.(?:open|load)', re.IGNORECASE),
         'Document parser library - verify output is not passed to exec/eval', Severity.MEDIUM),
    ]

    # EXA013: Agent executor with dangerous tool combinations
    AGENT_EXEC_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # LangChain AgentExecutor with tools
        (re.compile(r'AgentExecutor\s*\(', re.IGNORECASE),
         'AgentExecutor instantiation - verify tools do not include code execution', Severity.HIGH),
        # create_*_agent patterns
        (re.compile(r'create_(?:openai_functions|react|structured_chat|openai_tools|tool_calling)_agent\s*\(', re.IGNORECASE),
         'LLM agent creation - verify attached tools are sandboxed', Severity.HIGH),
        # initialize_agent (older LangChain API)
        (re.compile(r'initialize_agent\s*\(', re.IGNORECASE),
         'Agent initialization - verify tools list does not include code execution', Severity.HIGH),
        # CrewAI agents with tools
        (re.compile(r'(?:Agent|Task)\s*\([^)]*tools\s*=', re.IGNORECASE),
         'Agent/Task with tools - verify no unsandboxed execution tools', Severity.MEDIUM),
        # AutoGen agents
        (re.compile(r'(?:AssistantAgent|UserProxyAgent)\s*\([^)]*code_execution', re.IGNORECASE),
         'AutoGen agent with code execution config - RCE risk', Severity.CRITICAL),
        # LlamaIndex agent
        (re.compile(r'(?:ReActAgent|OpenAIAgent|FunctionCallingAgent)\.from_tools\s*\(', re.IGNORECASE),
         'LlamaIndex agent with tools - verify no code execution tools', Severity.MEDIUM),
    ]

    # EXA014: Dynamic tool loading with code execution capabilities
    TOOL_LOADING_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # load_tools with python_repl
        (re.compile(r'load_tools\s*\(\s*\[.*["\']python_repl["\']', re.IGNORECASE),
         'Loading python_repl tool - unsandboxed code execution via agent', Severity.CRITICAL),
        (re.compile(r'load_tools\s*\(\s*\[.*["\']terminal["\']', re.IGNORECASE),
         'Loading terminal tool - shell execution via agent', Severity.CRITICAL),
        (re.compile(r'load_tools\s*\(\s*\[.*["\']bash["\']', re.IGNORECASE),
         'Loading bash tool - shell execution via agent', Severity.CRITICAL),
        # Tool function wrapping exec/eval
        (re.compile(r'Tool\s*\([^)]*func\s*=\s*.*\.run', re.IGNORECASE),
         'Tool wrapping .run method - verify target is not a code executor', Severity.MEDIUM),
        # StructuredTool with exec capabilities
        (re.compile(r'StructuredTool\.from_function\s*\([^)]*(?:exec|eval|subprocess|shell)', re.IGNORECASE),
         'StructuredTool wrapping code execution function', Severity.CRITICAL),
    ]

    # EXA015: Direct exec/eval/subprocess in agent tool functions
    AGENT_CODE_EXEC_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        # exec/eval in code that also has agent/tool indicators
        (re.compile(r'python_repl\.run\s*\(', re.IGNORECASE),
         'PythonREPL.run() called - executes arbitrary Python code', Severity.CRITICAL),
        (re.compile(r'repl_tool\s*=\s*Tool\s*\(', re.IGNORECASE),
         'REPL wrapped as agent tool - document content may reach code execution', Severity.CRITICAL),
        # func=python_repl.run or similar binding
        (re.compile(r'func\s*=\s*python_repl\.run', re.IGNORECASE),
         'python_repl.run bound as tool function - arbitrary code execution', Severity.CRITICAL),
        (re.compile(r'func\s*=\s*.*(?:PythonREPL|BashProcess|ShellTool).*\.run', re.IGNORECASE),
         'Code execution tool bound as agent function', Severity.CRITICAL),
        # Gradio/Streamlit with agent + upload (attack surface)
        (re.compile(r'gr\.(?:UploadButton|File|Image)\s*\(', re.IGNORECASE),
         'File upload UI component - uploaded content may reach agent code execution tools', Severity.HIGH),
        (re.compile(r'(?:gradio|streamlit).*(?:upload|file).*(?:agent|llm|chain)', re.IGNORECASE),
         'File upload feeding LLM agent - document-to-RCE attack vector', Severity.HIGH),
    ]

    # Good patterns (safety measures)
    SAFETY_PATTERNS: List[re.Pattern] = [
        re.compile(r'before_tool_callback', re.IGNORECASE),
        re.compile(r'human_in_the_loop\s*[=:]\s*True', re.IGNORECASE),
        re.compile(r'require_confirmation\s*[=:]\s*True', re.IGNORECASE),
        re.compile(r'max_iterations\s*[=:]\s*\d+', re.IGNORECASE),
        re.compile(r'action_whitelist|allowed_actions', re.IGNORECASE),
        re.compile(r'permission_check|validate_permission', re.IGNORECASE),
        re.compile(r'audit_log|log_action', re.IGNORECASE),
        re.compile(r'rate_limit|throttle', re.IGNORECASE),
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

            # Check if file is agent-related.
            #
            # APPLICABILITY GATE: this scanner is LLM-agent-specific (OWASP LLM08).
            # The generic substrings in `agent_indicators` ('tool', 'action',
            # 'execute', 'capability') appear in benign non-AI code (requests,
            # urllib3), causing EXA* heuristics + the YAML corpus to fire on
            # unrelated files. Require EITHER genuine ML/LLM context (shared
            # detector) OR a STRONG, unambiguous agent-framework construct
            # (AgentExecutor, create_react_agent, PythonREPL, load_tools, ...).
            # This preserves coverage for agent code that uses no LLM-SDK token
            # while dropping the generic-substring false positives.
            content_lower = content.lower()

            # Strong agent-framework constructs — specific enough not to collide
            # with general-purpose code.
            strong_agent_indicators = [
                'langchain', 'llama_index', 'autogen', 'crewai',
                'pythonrepl', 'python_repl', 'shelltool', 'bashprocess',
                'agentexecutor', 'create_react_agent', 'create_openai',
                'load_tools', 'function_call', 'document_loader',
            ]
            has_agent_context = (
                has_ml_context(content)
                or any(ind in content_lower for ind in strong_agent_indicators)
            )

            if not has_agent_context:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            has_safety = any(
                p.search(content)
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
                (self.CODE_EXEC_TOOL_PATTERNS, "EXA011"),
                (self.DOC_LOADER_PATTERNS, "EXA012"),
                (self.AGENT_EXEC_PATTERNS, "EXA013"),
                (self.TOOL_LOADING_PATTERNS, "EXA014"),
                (self.AGENT_CODE_EXEC_PATTERNS, "EXA015"),
            ]

            for patterns, rule_id in all_patterns:
                issues.extend(self._check_patterns(content, lines, patterns, rule_id))

            if has_safety:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.MEDIUM:
                        issue.severity = Severity.LOW

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

    def _check_patterns(
        self,
        content: str,
        lines: List[str],
        patterns: List[Tuple[re.Pattern, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        issues = []
        seen = set()

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
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

        return issues
