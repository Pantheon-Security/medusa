#!/usr/bin/env python3
"""
MEDUSA Tool Callback Security Scanner
Audits agent code for proper before_tool_callback implementation

Based on "Agentic Design Patterns" Chapter 18 - Guardrails/Safety Patterns

Detects:
- Missing pre-execution validation (before_tool_callback)
- Missing post-execution validation
- Insufficient permission checks
- Missing argument validation
- Unprotected destructive operations
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple, Set

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _build_line_offsets, _get_line_number, filter_contextual_fps


class ToolCallbackScanner(RuleBasedScanner):
    """
    Tool Callback Security Audit Scanner

    Scans for:
    - TC001: Missing before_tool_callback pattern
    - TC002: Tool execution without permission check
    - TC003: Missing argument validation before tool use
    - TC004: Destructive operation without confirmation
    - TC005: Missing after_tool_callback (output validation)
    - TC006: Tool call without rate limiting
    - TC007: Missing audit logging for tool execution
    - TC008: Hardcoded permissions (no dynamic check)
    - TC009: Missing error handling in tool callback
    - TC010: Tool execution without session context
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['TOOL-CB-', 'TOOL-', 'MEDUSA-TUA-']

    # Categories to load from YAML
    RULE_CATEGORIES = [
        'tool_callback', 'tool_security', 'tool_use_attacks',
        # Orphaned rule directories wired here
        'sandbox_execution_boundaries',
    ]

    # Patterns indicating tool execution
    TOOL_EXECUTION_PATTERNS = [
        # Python patterns
        re.compile(r'def\s+\w*tool\w*\s*\(', re.IGNORECASE),
        re.compile(r'@tool\s*(\(|$)', re.IGNORECASE),
        re.compile(r'execute_tool\s*\(', re.IGNORECASE),
        re.compile(r'run_tool\s*\(', re.IGNORECASE),
        re.compile(r'call_tool\s*\(', re.IGNORECASE),
        re.compile(r'tool\.(run|execute|call)', re.IGNORECASE),
        re.compile(r'tools\[.*\]\s*\(', re.IGNORECASE),
        re.compile(r'invoke_tool\s*\(', re.IGNORECASE),

        # TypeScript/JavaScript patterns
        re.compile(r'async\s+\w*[Tt]ool\w*\s*\(', re.IGNORECASE),
        re.compile(r'handleTool\s*\(', re.IGNORECASE),
        re.compile(r'executeTool\s*\(', re.IGNORECASE),
        re.compile(r'runTool\s*\(', re.IGNORECASE),
        re.compile(r'tool\.execute\s*\(', re.IGNORECASE),
        re.compile(r'toolHandler\s*\(', re.IGNORECASE),
        re.compile(r'server\.setRequestHandler.*Tool', re.IGNORECASE),
        re.compile(r'CallToolRequestSchema', re.IGNORECASE),
    ]

    # Patterns indicating proper validation (good patterns)
    VALIDATION_PATTERNS = [
        re.compile(r'before_tool', re.IGNORECASE),
        re.compile(r'beforeTool', re.IGNORECASE),
        re.compile(r'pre_execute', re.IGNORECASE),
        re.compile(r'preExecute', re.IGNORECASE),
        re.compile(r'validate.*arg', re.IGNORECASE),
        re.compile(r'validateArg', re.IGNORECASE),
        re.compile(r'check.*permission', re.IGNORECASE),
        re.compile(r'checkPermission', re.IGNORECASE),
        re.compile(r'has_permission', re.IGNORECASE),
        re.compile(r'hasPermission', re.IGNORECASE),
        re.compile(r'authorize', re.IGNORECASE),
        re.compile(r'isAuthorized', re.IGNORECASE),
        re.compile(r'canExecute', re.IGNORECASE),
        re.compile(r'allowedTools', re.IGNORECASE),
        re.compile(r'permittedTools', re.IGNORECASE),
    ]

    # Patterns for after-execution validation
    AFTER_VALIDATION_PATTERNS = [
        re.compile(r'after_tool', re.IGNORECASE),
        re.compile(r'afterTool', re.IGNORECASE),
        re.compile(r'post_execute', re.IGNORECASE),
        re.compile(r'postExecute', re.IGNORECASE),
        re.compile(r'validate.*result', re.IGNORECASE),
        re.compile(r'validateResult', re.IGNORECASE),
        re.compile(r'sanitize.*output', re.IGNORECASE),
        re.compile(r'sanitizeOutput', re.IGNORECASE),
        re.compile(r'filter.*response', re.IGNORECASE),
        re.compile(r'filterResponse', re.IGNORECASE),
    ]

    # Dangerous/destructive SINK call-sites (TC004), as (regex, description,
    # category).
    #
    # These are ACTUAL function-call invocations, not bare word fragments. The
    # previous version matched substrings like `system`, `exec`, `remove`,
    # `update` anywhere in the file — including comments, docstrings, string
    # literals, import statements and identifiers (`File system`, `remove_tool`,
    # `SYSTEM = "system"`), which carpet-bombed every benign MCP server. A real
    # TC004 is a dangerous sink (shell/code execution, file deletion) invoked on
    # *untrusted/tainted* input (see _arg_is_tainted) inside a tool-callback file
    # with no nearby validation — i.e. a tool that can execute or destroy on
    # attacker-controlled arguments. Each pattern ends with `\(` so the match
    # consumes the opening paren; _find_dangerous_sinks inspects the arg list.
    #
    # Category drives the taint policy:
    #   'exec'   — command/code execution: tainted by dynamic construction
    #              (f-string/concat/format/shell=True) OR an input-named arg.
    #   'delete' — destructive filesystem op: tainted only when the path derives
    #              from an input-named arg (so benign log-rotation on an internal
    #              path like fs.unlinkSync(path.join(this.config.logDir, file))
    #              does NOT fire).
    SINK_CALL_PATTERNS = [
        # Shell / command execution
        (re.compile(r'\bos\.system\s*\('), 'Shell command execution', 'exec'),
        (re.compile(r'\bos\.popen\s*\('), 'Shell command execution', 'exec'),
        (re.compile(r'\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\('), 'Subprocess execution', 'exec'),
        (re.compile(r'\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\('), 'Subprocess execution', 'exec'),
        # Dynamic code execution / evaluation (not the benign `regex.exec()` — the
        # negative look-behind rules out method calls like `.exec(`)
        (re.compile(r'(?<![\w.])exec\s*\('), 'Dynamic code execution', 'exec'),
        (re.compile(r'(?<![\w.])eval\s*\('), 'Dynamic code evaluation', 'exec'),
        (re.compile(r'\bnew\s+Function\s*\('), 'Dynamic code execution', 'exec'),
        # Destructive filesystem operations
        (re.compile(r'\bos\.(?:remove|unlink|rmdir)\s*\('), 'File deletion', 'delete'),
        (re.compile(r'\bshutil\.rmtree\s*\('), 'Recursive directory deletion', 'delete'),
        (re.compile(r'\bfs\.(?:unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync)\s*\('), 'File deletion', 'delete'),
    ]

    # Identifier words that mark an argument as untrusted (tool/agent/request)
    # input. Matched against camelCase/snake_case-split tokens of the arg text.
    # Deliberately excludes generic path/data/file words so benign internal path
    # building does not read as tainted.
    TAINT_WORDS = frozenset({
        'arg', 'args', 'argument', 'arguments', 'argv',
        'param', 'params', 'parameter', 'parameters',
        'request', 'req', 'payload', 'input', 'inputs',
        'cmd', 'cmdline', 'command', 'commands', 'query', 'querystring',
        'body', 'form', 'formdata', 'kwargs', 'prompt', 'stdin',
        'untrusted', 'usersupplied', 'userinput', 'toolinput', 'toolargs',
    })

    # Audit logging patterns
    AUDIT_PATTERNS = [
        re.compile(r'audit', re.IGNORECASE),
        re.compile(r'log.*tool', re.IGNORECASE),
        re.compile(r'logTool', re.IGNORECASE),
        re.compile(r'track.*execution', re.IGNORECASE),
        re.compile(r'record.*action', re.IGNORECASE),
        re.compile(r'emit.*event.*tool', re.IGNORECASE),
    ]

    # Rate limiting patterns
    RATE_LIMIT_PATTERNS = [
        re.compile(r'rate.*limit', re.IGNORECASE),
        re.compile(r'rateLimit', re.IGNORECASE),
        re.compile(r'throttle', re.IGNORECASE),
        re.compile(r'cooldown', re.IGNORECASE),
        re.compile(r'quota', re.IGNORECASE),
        re.compile(r'maxRequests', re.IGNORECASE),
        re.compile(r'requestLimit', re.IGNORECASE),
    ]

    # Indicators that a file is related to AI agent tool execution.
    # Without these, the scanner produces massive false positives on
    # standard web apps (every CRUD operation matches destructive patterns).
    AGENT_TOOL_INDICATORS = [
        # MCP / Agent framework imports
        'mcp', 'langchain', 'llama_index', 'llamaindex',
        'autogen', 'crewai', 'semantic_kernel',
        'tool_registry', 'tool_handler', 'tool_executor',
        # MCP-specific patterns
        'CallToolRequestSchema', 'ListToolsRequestSchema',
        'setRequestHandler', 'MCPServer', 'mcp_server',
        # Agent tool decorators and methods
        '@tool', 'execute_tool', 'run_tool', 'call_tool',
        'invoke_tool', 'tool.execute', 'tool.run',
        'AgentExecutor', 'agent_executor',
        # Tool callback patterns (the actual target of this scanner)
        'before_tool', 'after_tool', 'tool_callback',
        'beforeTool', 'afterTool', 'toolCallback',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]

    def can_scan(self, file_path: Path) -> bool:
        """Only scan files that contain AI agent tool execution indicators.

        Without this gate, every Python/JS file gets scanned and patterns
        like 'delete|remove' and 'exec|eval' match standard CRUD code.
        """
        if file_path.suffix not in self.get_file_extensions():
            return False

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(8192)  # First 8KB
            head_lower = head.lower()
            return any(ind.lower() in head_lower for ind in self.AGENT_TOOL_INDICATORS)
        except OSError:
            return False

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for tool callback security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            _offsets = _build_line_offsets(content)

            content_lower = content.lower()

            # Check if file contains tool execution patterns
            has_tool_execution = any(
                pattern.search(content)
                for pattern in self.TOOL_EXECUTION_PATTERNS
            )

            if not has_tool_execution:
                # No tool execution patterns found - skip entirely.
                # The can_scan() gate already confirmed this file has agent
                # indicators, but without actual tool execution, there's
                # nothing actionable to report.
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for validation patterns
            has_before_validation = any(
                pattern.search(content)
                for pattern in self.VALIDATION_PATTERNS
            )

            has_after_validation = any(
                pattern.search(content)
                for pattern in self.AFTER_VALIDATION_PATTERNS
            )

            has_audit = any(
                pattern.search(content)
                for pattern in self.AUDIT_PATTERNS
            )

            has_rate_limit = any(
                pattern.search(content)
                for pattern in self.RATE_LIMIT_PATTERNS
            )

            # Locate genuinely-dangerous sink call-sites (shell/code execution,
            # file deletion) that consume dynamic/tainted input. Both TC001 and
            # TC004 are gated on these — the "missing guard" and "unprotected
            # destructive op" findings only make sense when a real dangerous
            # operation on untrusted input is actually present. This replaces the
            # previous behaviour of firing on the bare tool-callback shape.
            dangerous_sinks = self._find_dangerous_sinks(content, file_path, _offsets)

            # TC001: a tool reaches a dangerous sink on dynamic input but the file
            # has no before_tool_callback / permission / argument-validation guard
            # anywhere. One finding per file (at the first risky sink), not one per
            # tool-execution pattern.
            if not has_before_validation and dangerous_sinks:
                first_line, _desc, _s, _e = min(dangerous_sinks, key=lambda s: s[2])
                issues.append(ScannerIssue(
                    rule_id="TC001",
                    severity=Severity.HIGH,
                    message=(
                        "Tool reaches a dangerous operation on dynamic input "
                        "without a before_tool_callback validation guard"
                    ),
                    line=first_line,
                    column=1,
                ))

            # TC005: Missing after_tool_callback
            if not has_after_validation and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC005",
                    severity=Severity.MEDIUM,
                    message="No after_tool_callback for output validation detected",
                    line=1,
                    column=1,
                ))

            # TC007: Missing audit logging
            if not has_audit and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC007",
                    severity=Severity.MEDIUM,
                    message="Tool execution without audit logging",
                    line=1,
                    column=1,
                ))

            # TC006: Missing rate limiting
            if not has_rate_limit and has_tool_execution:
                issues.append(ScannerIssue(
                    rule_id="TC006",
                    severity=Severity.LOW,
                    message="No rate limiting detected for tool execution",
                    line=1,
                    column=1,
                ))

            # Check destructive operations
            issues.extend(self._check_destructive_operations(content, file_path, has_before_validation, dangerous_sinks, _offsets))

            # Check for hardcoded permissions
            issues.extend(self._check_hardcoded_permissions(content, file_path, _offsets))

            # Check for session context usage
            issues.extend(self._check_session_context(content, file_path))

            # Check error handling
            issues.extend(self._check_error_handling(content, file_path))

            # NOTE: We deliberately do NOT call _scan_with_rules() here.
            # The YAML rules (TOOL-CB-*) duplicate our hardcoded patterns
            # but lack the context awareness of _check_destructive_operations()
            # which checks for nearby validation/confirmation. Running both
            # would double-count findings and add noise.

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

    def _find_dangerous_sinks(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[Tuple[int, str, int, int]]:
        """Locate real dangerous/destructive sink call-sites on dynamic input.

        Returns (line, description, start_offset, end_offset) for each sink
        invocation (from SINK_CALL_PATTERNS) that:
          - is NOT inside a comment or string literal (via _mask_code), and
          - is called with an *untrusted/tainted* argument (via _arg_is_tainted)
            per the sink's category — not a static literal like os.system("clear")
            or subprocess.run(["where", "python"]), and not benign internal-path
            deletion like fs.unlinkSync(path.join(this.config.logDir, file)).

        This is the taint/dynamic-exec signal that separates a genuinely
        dangerous tool (`subprocess.run(params["cmd"], shell=True)`) from
        ordinary tool-callback/registration code.
        """
        if _offsets is None:
            _offsets = _build_line_offsets(content)

        is_python = file_path.suffix.lower() in (".py", ".pyi")
        mask = self._mask_code(content, is_python)

        sinks: List[Tuple[int, str, int, int]] = []
        for pattern, description, category in self.SINK_CALL_PATTERNS:
            for match in pattern.finditer(content):
                start = match.start()
                # Skip sinks that live inside a comment or string literal:
                # masked positions are blanked to spaces.
                if start >= len(mask) or mask[start] == ' ':
                    continue
                # Pattern ends with '\(' so match.end()-1 is the opening paren.
                args = self._extract_call_args(content, match.end() - 1)
                if not self._arg_is_tainted(args, category):
                    continue
                line = _get_line_number(_offsets, start)
                sinks.append((line, description, start, match.end()))
        return sinks

    def _check_destructive_operations(
        self,
        content: str,
        file_path: Path,
        has_validation: bool,
        dangerous_sinks: List[Tuple[int, str, int, int]],
        _offsets: List[int] = None,
    ) -> List[ScannerIssue]:
        """Flag dangerous sinks (on dynamic input) that lack nearby validation.

        Operates only on the pre-vetted `dangerous_sinks` (real sink calls on
        tainted args, not comments/strings/identifiers), so it no longer fires
        on the bare word-fragments that carpet-bombed benign MCP servers.
        """
        issues = []

        for line, description, start, end in dangerous_sinks:
            # Check if there's a confirmation/validation guard nearby
            context_start = max(0, start - 500)
            context_end = min(len(content), end + 100)
            context = content[context_start:context_end].lower()

            has_confirm = any(word in context for word in [
                'confirm', 'verify', 'approve', 'authorized',
                'permission', 'allowed', 'check', 'validate'
            ])

            if not has_confirm and not has_validation:
                issues.append(ScannerIssue(
                    rule_id="TC004",
                    severity=Severity.HIGH,
                    message=f"{description} on dynamic input without validation/confirmation",
                    line=line,
                    column=1,
                    code="Add confirmation or validation before destructive operations",
                ))

        return issues

    @staticmethod
    def _extract_call_args(content: str, open_paren_idx: int, limit: int = 400) -> str:
        """Return the argument text between a call's balanced parentheses.

        Bounded to `limit` chars to avoid pathological scans. Does not attempt
        to skip parens inside strings — good enough for the boolean taint check
        in _arg_is_tainted (a stray ')' in a literal only truncates the arg
        text, it doesn't flip a variable reference into a literal).
        """
        depth = 0
        n = len(content)
        end_limit = min(n, open_paren_idx + limit)
        i = open_paren_idx
        while i < end_limit:
            c = content[i]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return content[open_paren_idx + 1:i]
            i += 1
        return content[open_paren_idx + 1:end_limit]

    @staticmethod
    def _split_identifier(token: str) -> List[str]:
        """Split a camelCase / snake_case identifier into lowercase words.

        `toolInput` -> ['tool', 'input']; `bat_path` -> ['bat', 'path'];
        `logDir` -> ['log', 'dir']. Used to test arg tokens against TAINT_WORDS.
        """
        parts = re.split(r'[_\W]+', token)
        words: List[str] = []
        for p in parts:
            # split camelCase: insert boundary between lower/digit and Upper
            for w in re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+', p):
                words.append(w.lower())
        return words

    @classmethod
    def _arg_has_taint_source(cls, stripped: str) -> bool:
        """True if any identifier in the (string-stripped) arg text is an
        untrusted-input name (TAINT_WORDS), by camel/snake word split."""
        for ident in re.findall(r'[A-Za-z_]\w*', stripped):
            if any(word in cls.TAINT_WORDS for word in cls._split_identifier(ident)):
                return True
        return False

    @classmethod
    def _arg_is_tainted(cls, raw: str, category: str) -> bool:
        """True if a sink's argument carries untrusted/tainted input.

        Policy by sink category:
          - 'exec'   (command/code execution): tainted by dynamic command
            construction (f-string, `${...}` template, `+` concat, `.format(`,
            `%`-format, `shell=True`) OR an input-named argument. This keeps the
            classic injection vectors even when the variable name is generic.
          - 'delete' (destructive filesystem op): tainted ONLY when the path
            derives from an input-named argument — benign internal-path deletion
            (`fs.unlinkSync(path.join(this.config.logDir, file))`) is not flagged.

        A pure-literal argument (`os.system("clear")`,
        `subprocess.run(["ls", "-la"])`) is never tainted.
        """
        a = raw.strip()
        if not a:
            return False

        stripped = re.sub(
            r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"]*"|\'[^\']*\'|`[^`]*`',
            '', a,
        )

        if category == 'exec':
            # Dynamic command-construction signals (injection vectors)
            if re.search(r'f["\']', a):          # Python f-string
                return True
            if '${' in a:                         # JS/TS template interpolation
                return True
            if '+' in stripped:                   # concatenation of code/vars
                return True
            if '.format(' in a:
                return True
            if re.search(r'%\s*[\(\w\'"]', a):    # printf-style % formatting
                return True
            if re.search(r'shell\s*=\s*True', a):
                return True

        # Both categories: an input-named argument marks the sink as tainted.
        return cls._arg_has_taint_source(stripped)

    @staticmethod
    def _mask_code(content: str, is_python: bool) -> str:
        """Return a same-length copy of `content` with comment and string-literal
        characters replaced by spaces (newlines preserved).

        Used to reject sink matches that live inside comments or string literals
        (e.g. a docstring mentioning `os.system(cmd)` or `# subprocess.run(x)`).
        A lightweight lexer — not a full parser — but only ever *reduces* false
        positives, and the taint check is the primary precision gate.
        """
        out: List[str] = []
        i = 0
        n = len(content)
        string_char: Optional[str] = None
        triple = False
        while i < n:
            c = content[i]
            if string_char is not None:
                # Inside a string literal
                if c == '\\' and i + 1 < n:
                    out.append('\n' if c == '\n' else ' ')
                    out.append('\n' if content[i + 1] == '\n' else ' ')
                    i += 2
                    continue
                if triple:
                    if content[i:i + 3] == string_char * 3:
                        out.append('   ')
                        string_char = None
                        triple = False
                        i += 3
                        continue
                    out.append('\n' if c == '\n' else ' ')
                    i += 1
                    continue
                # single/double-quoted (single line)
                if c == string_char:
                    out.append(' ')
                    string_char = None
                    i += 1
                    continue
                if c == '\n':  # unterminated — reset at line end
                    out.append('\n')
                    string_char = None
                    i += 1
                    continue
                out.append(' ')
                i += 1
                continue
            # Not inside a string
            if is_python and c == '#':
                while i < n and content[i] != '\n':
                    out.append(' ')
                    i += 1
                continue
            if not is_python and c == '/' and i + 1 < n and content[i + 1] == '/':
                while i < n and content[i] != '\n':
                    out.append(' ')
                    i += 1
                continue
            if not is_python and c == '/' and i + 1 < n and content[i + 1] == '*':
                while i < n and content[i:i + 2] != '*/':
                    out.append('\n' if content[i] == '\n' else ' ')
                    i += 1
                if i < n:
                    out.append(' ')
                    i += 1
                if i < n:
                    out.append(' ')
                    i += 1
                continue
            if c in ('"', "'"):
                if content[i:i + 3] == c * 3:
                    triple = True
                    string_char = c
                    out.append('   ')
                    i += 3
                    continue
                string_char = c
                out.append(' ')
                i += 1
                continue
            if not is_python and c == '`':
                string_char = '`'
                out.append(' ')
                i += 1
                continue
            out.append(c)
            i += 1
        return ''.join(out)

    def _check_hardcoded_permissions(
        self, content: str, file_path: Path, _offsets: List[int] = None
    ) -> List[ScannerIssue]:
        """Check for hardcoded permission values"""
        issues = []

        # Patterns indicating hardcoded permissions
        hardcoded_patterns = [
            (re.compile(r'allowed_tools\s*=\s*\[', re.IGNORECASE), 'Hardcoded allowed tools list'),
            (re.compile(r'permissions\s*=\s*\[', re.IGNORECASE), 'Hardcoded permissions list'),
            (re.compile(r'can_execute\s*=\s*True', re.IGNORECASE), 'Hardcoded execution permission'),
            (re.compile(r'isAdmin\s*=\s*true', re.IGNORECASE), 'Hardcoded admin flag'),
            (re.compile(r'role\s*[=:]\s*["\']admin["\']', re.IGNORECASE), 'Hardcoded admin role'),
        ]

        for pattern, description in hardcoded_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                line = _get_line_number(_offsets, match.start())
                issues.append(ScannerIssue(
                    rule_id="TC008",
                    severity=Severity.MEDIUM,
                    message=description,
                    line=line,
                    column=1,
                    code="Use dynamic permission checks based on session context",
                ))

        return issues

    def _check_session_context(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for session context usage in tool execution"""
        issues = []

        # Check if file has tool execution but no session context
        has_tool_exec = any(
            pattern.search(content)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        session_patterns = [
            re.compile(r'session', re.IGNORECASE),
            re.compile(r'context', re.IGNORECASE),
            re.compile(r'user_id', re.IGNORECASE),
            re.compile(r'userId', re.IGNORECASE),
            re.compile(r'request\.user', re.IGNORECASE),
            re.compile(r'ctx\.', re.IGNORECASE),
            re.compile(r'state\.', re.IGNORECASE),
        ]

        has_session = any(
            pattern.search(content)
            for pattern in session_patterns
        )

        if has_tool_exec and not has_session:
            issues.append(ScannerIssue(
                rule_id="TC010",
                severity=Severity.MEDIUM,
                message="Tool execution without session/context tracking",
                line=1,
                column=1,
                code="Include session context for user/permission tracking",
            ))

        return issues

    def _check_error_handling(
        self, content: str, file_path: Path
    ) -> List[ScannerIssue]:
        """Check for proper error handling in tool callbacks"""
        issues = []

        # Check for tool execution in try blocks
        try_patterns = [
            re.compile(r'try\s*:.{0,200}tool', re.IGNORECASE | re.DOTALL),
            re.compile(r'try\s*\{.{0,200}tool', re.IGNORECASE | re.DOTALL),
        ]

        catch_patterns = [
            re.compile(r'except.*:', re.IGNORECASE),
            re.compile(r'catch\s*\(', re.IGNORECASE),
        ]

        has_try = any(p.search(content) for p in try_patterns)
        has_catch = any(p.search(content) for p in catch_patterns)

        # Check if there's tool execution without error handling
        has_tool_exec = any(
            pattern.search(content)
            for pattern in self.TOOL_EXECUTION_PATTERNS
        )

        if has_tool_exec and not (has_try or has_catch):
            issues.append(ScannerIssue(
                rule_id="TC009",
                severity=Severity.LOW,
                message="Tool execution without explicit error handling",
                line=1,
                column=1,
                code="Add try/catch or error handling for tool execution failures",
            ))

        return issues
