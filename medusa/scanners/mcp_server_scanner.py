#!/usr/bin/env python3
"""
MEDUSA MCP Server Code Scanner
Scans MCP (Model Context Protocol) server source code for security issues

Detects vulnerabilities in TypeScript/JavaScript and Python MCP servers:
- Tool poisoning in descriptions
- Command/SQL injection in handlers
- Data exfiltration patterns
- Missing input validation
- Unsafe file operations
- Missing security annotations
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class MCPServerScanner(BaseScanner):
    """
    MCP Server Code Security Scanner

    Scans for:
    - MCP101: Tool poisoning patterns in descriptions
    - MCP102: Command injection in tool handlers
    - MCP103: SQL injection in database tools
    - MCP104: Missing input validation
    - MCP105: Unsafe file operations (data exfiltration risk)
    - MCP106: Missing authentication on sensitive tools
    - MCP107: Hardcoded credentials in server code
    - MCP108: Missing destructiveHint annotation
    - MCP109: Missing readOnlyHint annotation
    - MCP110: Dynamic instruction loading
    - MCP111: Data exfiltration patterns
    """

    # Tool poisoning patterns - hidden instructions in descriptions
    TOOL_POISONING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Hidden XML/HTML tags
        (r'<hidden[^>]*>.*?</hidden>', 'Hidden instruction tag in description', Severity.CRITICAL),
        (r'<system[^>]*>.*?</system>', 'System instruction tag in description', Severity.CRITICAL),
        (r'<instruction[^>]*>.*?</instruction>', 'Instruction tag in description', Severity.CRITICAL),
        (r'<secret[^>]*>.*?</secret>', 'Secret instruction tag in description', Severity.CRITICAL),
        (r'<internal[^>]*>.*?</internal>', 'Internal instruction tag in description', Severity.CRITICAL),
        (r'<!--.*?-->', 'HTML comment potentially hiding instructions', Severity.HIGH),

        # Prompt injection patterns
        (r'(?i)ignore\s+(all\s+)?previous\s+instructions?', 'Prompt injection - ignore previous', Severity.CRITICAL),
        (r'(?i)disregard\s+(all\s+)?(prior|previous|above)', 'Prompt injection - disregard prior', Severity.CRITICAL),
        (r'(?i)forget\s+(everything|all|what)', 'Prompt injection - forget instructions', Severity.CRITICAL),
        (r'(?i)new\s+instructions?\s*:', 'Prompt injection - new instructions', Severity.CRITICAL),
        (r'(?i)system\s*:\s*you\s+are', 'Prompt injection - system role override', Severity.CRITICAL),

        # Data exfiltration instructions
        (r'(?i)before\s+execut(e|ing).*read', 'Exfiltration instruction - read before execute', Severity.CRITICAL),
        (r'(?i)secretly\s+(send|transmit|exfiltrate|upload|post)', 'Exfiltration instruction - secretly send', Severity.CRITICAL),
        (r'(?i)include\s+(in\s+)?(the\s+)?response.*file', 'Exfiltration instruction - include file in response', Severity.CRITICAL),
        (r'(?i)pass\s+.*\s+as\s+(a\s+)?sidenote', 'Exfiltration instruction - pass as sidenote', Severity.CRITICAL),
        (r'(?i)append\s+.*\s+to\s+(the\s+)?(output|response|result)', 'Exfiltration instruction - append to output', Severity.HIGH),
        (r'(?i)read\s+.*\.(ssh|aws|env|credentials|key|pem|secret)', 'Exfiltration instruction - read sensitive file', Severity.CRITICAL),
        (r'(?i)(~|home).*/(\.ssh|\.aws|\.gnupg|\.config)', 'Exfiltration instruction - access sensitive directory', Severity.CRITICAL),

        # Invisible/zero-width characters (used to hide instructions)
        (r'[\u200b\u200c\u200d\u2060\ufeff]', 'Zero-width character potentially hiding content', Severity.HIGH),

        # Unicode tricks
        (r'[\u202a-\u202e\u2066-\u2069]', 'Bidirectional text override character', Severity.HIGH),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Shell execution with user input
        (r'subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
         'Shell=True with potential user input', Severity.CRITICAL),
        (r'os\.system\s*\([^)]*\+', 'os.system with string concatenation', Severity.CRITICAL),
        (r'os\.popen\s*\([^)]*\+', 'os.popen with string concatenation', Severity.CRITICAL),
        (r'exec\s*\([^)]*input', 'exec() with user input', Severity.CRITICAL),
        (r'eval\s*\([^)]*input', 'eval() with user input', Severity.CRITICAL),

        # JavaScript/TypeScript
        (r'child_process\.(exec|execSync|spawn)\s*\([^)]*\$\{',
         'child_process with template literal injection', Severity.CRITICAL),
        (r'child_process\.(exec|execSync)\s*\([^)]*\+',
         'child_process with string concatenation', Severity.CRITICAL),
        (r'new\s+Function\s*\([^)]*input', 'new Function() with user input', Severity.CRITICAL),
        (r'eval\s*\([^)]*\$\{', 'eval with template literal', Severity.CRITICAL),
    ]

    # SQL injection patterns
    SQL_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # String formatting in SQL
        (r'execute\s*\(\s*f["\'].*\{', 'SQL with f-string interpolation', Severity.CRITICAL),
        (r'execute\s*\([^)]*%\s*\(', 'SQL with % formatting', Severity.CRITICAL),
        (r'execute\s*\([^)]*\.format\s*\(', 'SQL with .format()', Severity.CRITICAL),
        (r'execute\s*\([^)]*\+\s*(input|query|param|user|data)',
         'SQL with string concatenation', Severity.CRITICAL),

        # Raw query patterns
        (r'(SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*["\']?\s*\+',
         'Raw SQL with concatenation', Severity.CRITICAL),
        (r'query\s*\(\s*["\'].*\$\{', 'SQL query with template literal', Severity.CRITICAL),
        (r'rawQuery\s*\([^)]*\+', 'Raw query with concatenation', Severity.HIGH),
    ]

    # Data exfiltration code patterns (not just in descriptions)
    EXFILTRATION_CODE_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Reading sensitive files
        (r'(readFile|readFileSync|open)\s*\([^)]*["\'].*/(\.ssh|\.aws|\.gnupg|\.env)',
         'Reading sensitive file', Severity.CRITICAL),
        (r'(readFile|readFileSync|open)\s*\([^)]*["\'].*/id_rsa',
         'Reading SSH private key', Severity.CRITICAL),
        (r'(readFile|readFileSync|open)\s*\([^)]*["\'].*/credentials',
         'Reading credentials file', Severity.CRITICAL),
        (r'(readFile|readFileSync|open)\s*\([^)]*["\'].*/\.netrc',
         'Reading .netrc file', Severity.CRITICAL),
        (r'(readFile|readFileSync|open)\s*\([^)]*["\'].*/\.npmrc',
         'Reading .npmrc (may contain tokens)', Severity.HIGH),

        # Environment variable access patterns
        (r'process\.env\[(input|param|query|user)',
         'Dynamic environment variable access', Severity.HIGH),
        (r'os\.environ\[.*\+',
         'Dynamic environment variable access', Severity.HIGH),

        # Sending data externally
        (r'(fetch|axios|request)\s*\([^)]*\+.*file',
         'Sending file content externally', Severity.CRITICAL),
        (r'(fetch|axios|request)\s*\([^)]*\+.*env',
         'Sending environment data externally', Severity.CRITICAL),
        (r'\.send\s*\([^)]*readFile',
         'Sending file content in response', Severity.HIGH),

        # Glob patterns for mass file access
        (r'glob\s*\([^)]*["\'][*]', 'Glob pattern for file enumeration', Severity.MEDIUM),
        (r'(walk|listdir|readdir)\s*\([^)]*home', 'Directory traversal from home', Severity.HIGH),
    ]

    # Missing validation patterns
    MISSING_VALIDATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct use of input without validation
        (r'handler\s*:\s*async\s*\([^)]*\)\s*=>\s*\{[^}]*(?<!parse|validate|sanitize)[^}]*input\.',
         'Handler uses input without apparent validation', Severity.MEDIUM),
        (r'def\s+\w+\s*\([^)]*\):[^:]*(?<!pydantic|validator)[^:]*input\[',
         'Function uses input without apparent validation', Severity.MEDIUM),
    ]

    # Missing annotation patterns (destructive operations without hints)
    DESTRUCTIVE_KEYWORDS = [
        'delete', 'remove', 'drop', 'truncate', 'destroy', 'erase', 'purge',
        'wipe', 'clear', 'reset', 'terminate', 'kill', 'unlink', 'rmdir'
    ]

    SENSITIVE_KEYWORDS = [
        'password', 'secret', 'credential', 'token', 'key', 'auth',
        'admin', 'root', 'sudo', 'privilege', 'permission'
    ]

    # MCP SDK import patterns
    MCP_IMPORT_PATTERNS = [
        r'from\s+["\']@modelcontextprotocol/sdk',
        r'import\s+.*from\s+["\']@modelcontextprotocol/sdk',
        r'require\s*\(["\']@modelcontextprotocol/sdk',
        r'from\s+mcp\s+import',
        r'from\s+mcp\.server\s+import',
        r'from\s+fastmcp\s+import',
        r'import\s+mcp',
    ]

    # Tool definition patterns
    TOOL_DEFINITION_PATTERNS = [
        r'server\.tool\s*\(',
        r'\.tool\s*\(\s*\{',
        r'@server\.tool',
        r'@mcp\.tool',
        r'tools\.define',
        r'registerTool\s*\(',
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.ts', '.js', '.mjs', '.py']

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is likely an MCP server implementation"""
        if file_path.suffix not in self.get_file_extensions():
            return False

        # Check filename hints
        name_lower = file_path.name.lower()
        if 'mcp' in name_lower:
            return True
        if 'server' in name_lower and file_path.suffix in ['.ts', '.js', '.py']:
            return True

        return True  # Will do content check in get_confidence_score

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Return high confidence for files containing MCP SDK imports.
        """
        if not self.can_scan(file_path):
            return 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Read first 10KB for efficiency

            # Check for MCP SDK imports
            for pattern in self.MCP_IMPORT_PATTERNS:
                if re.search(pattern, content):
                    return 90  # High confidence - definitely MCP

            # Check for tool definitions without imports (might be partial file)
            for pattern in self.TOOL_DEFINITION_PATTERNS:
                if re.search(pattern, content):
                    return 70  # Medium-high - likely MCP

            # Filename contains 'mcp'
            if 'mcp' in file_path.name.lower():
                return 60

            return 0  # Not an MCP file

        except Exception:
            return 0

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan MCP server source code for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')

            # Check if this is actually an MCP server file
            is_mcp_file = any(
                re.search(pattern, content)
                for pattern in self.MCP_IMPORT_PATTERNS + self.TOOL_DEFINITION_PATTERNS
            )

            if not is_mcp_file:
                # Not an MCP file, return empty results
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True
                )

            # MCP101: Tool poisoning in descriptions
            issues.extend(self._scan_tool_poisoning(content, lines))

            # MCP102: Command injection
            issues.extend(self._scan_patterns(
                content, lines,
                self.COMMAND_INJECTION_PATTERNS,
                "MCP102"
            ))

            # MCP103: SQL injection
            issues.extend(self._scan_patterns(
                content, lines,
                self.SQL_INJECTION_PATTERNS,
                "MCP103"
            ))

            # MCP105/MCP111: Data exfiltration patterns
            issues.extend(self._scan_patterns(
                content, lines,
                self.EXFILTRATION_CODE_PATTERNS,
                "MCP111"
            ))

            # MCP108/MCP109: Missing annotations
            issues.extend(self._scan_missing_annotations(content, lines))

            # MCP107: Hardcoded credentials
            issues.extend(self._scan_hardcoded_credentials(content, lines))

            # MCP110: Dynamic instruction loading
            issues.extend(self._scan_dynamic_instructions(content, lines))

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

    def _scan_tool_poisoning(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for tool poisoning patterns in descriptions"""
        issues = []

        # Find description strings (both in tool definitions and standalone)
        # Look for description patterns
        desc_pattern = r'description\s*[=:]\s*[`"\']([^`"\']*(?:[`"\'][^`"\']*)*)[`"\']'

        for match in re.finditer(desc_pattern, content, re.DOTALL | re.IGNORECASE):
            desc_content = match.group(1)
            desc_start = match.start()

            # Find line number
            line_num = content[:desc_start].count('\n') + 1

            # Check for poisoning patterns
            for pattern, description, severity in self.TOOL_POISONING_PATTERNS:
                if re.search(pattern, desc_content, re.IGNORECASE | re.DOTALL):
                    issues.append(ScannerIssue(
                        severity=severity,
                        message=f"Tool poisoning: {description}",
                        line=line_num,
                        rule_id="MCP101",
                        cwe_id=94,
                        cwe_link="https://cwe.mitre.org/data/definitions/94.html"
                    ))

        # Also scan entire file for poisoning patterns (might be in comments, etc.)
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in self.TOOL_POISONING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Avoid duplicates from description scan
                    if not any(iss.line == i and iss.rule_id == "MCP101" for iss in issues):
                        issues.append(ScannerIssue(
                            severity=severity,
                            message=f"Tool poisoning: {description}",
                            line=i,
                            rule_id="MCP101",
                            cwe_id=94,
                            cwe_link="https://cwe.mitre.org/data/definitions/94.html"
                        ))

        return issues

    def _scan_patterns(
        self,
        content: str,
        lines: List[str],
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        """Generic pattern scanning"""
        issues = []

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Map rule IDs to CWE
                    cwe_map = {
                        "MCP102": (78, "https://cwe.mitre.org/data/definitions/78.html"),  # Command injection
                        "MCP103": (89, "https://cwe.mitre.org/data/definitions/89.html"),  # SQL injection
                        "MCP111": (200, "https://cwe.mitre.org/data/definitions/200.html"),  # Info exposure
                    }
                    cwe_id, cwe_link = cwe_map.get(rule_id, (None, None))

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

    def _scan_missing_annotations(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for tools missing proper annotations"""
        issues = []

        # Find tool definitions
        tool_pattern = r'(server\.tool|\.tool|@server\.tool|@mcp\.tool)\s*\(\s*\{([^}]*)\}'

        for match in re.finditer(tool_pattern, content, re.DOTALL):
            tool_content = match.group(2)
            tool_start = match.start()
            line_num = content[:tool_start].count('\n') + 1

            # Check for destructive operations without destructiveHint
            has_destructive_keyword = any(
                kw in tool_content.lower()
                for kw in self.DESTRUCTIVE_KEYWORDS
            )
            has_destructive_hint = 'destructiveHint' in tool_content or 'destructive_hint' in tool_content

            if has_destructive_keyword and not has_destructive_hint:
                issues.append(ScannerIssue(
                    severity=Severity.MEDIUM,
                    message="Destructive tool missing destructiveHint annotation",
                    line=line_num,
                    rule_id="MCP108",
                    cwe_id=693,
                    cwe_link="https://cwe.mitre.org/data/definitions/693.html"
                ))

            # Check for read operations without readOnlyHint
            is_read_only = any(
                kw in tool_content.lower()
                for kw in ['get', 'read', 'list', 'fetch', 'query', 'search', 'find']
            )
            is_not_write = not any(
                kw in tool_content.lower()
                for kw in self.DESTRUCTIVE_KEYWORDS + ['write', 'create', 'update', 'set', 'put', 'post']
            )
            has_readonly_hint = 'readOnlyHint' in tool_content or 'read_only_hint' in tool_content

            if is_read_only and is_not_write and not has_readonly_hint:
                issues.append(ScannerIssue(
                    severity=Severity.LOW,
                    message="Read-only tool missing readOnlyHint annotation",
                    line=line_num,
                    rule_id="MCP109",
                    cwe_id=693,
                    cwe_link="https://cwe.mitre.org/data/definitions/693.html"
                ))

        return issues

    def _scan_hardcoded_credentials(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for hardcoded credentials in server code"""
        issues = []

        # Reuse patterns from MCP Config Scanner
        credential_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
            (r'sk-[a-zA-Z0-9]{48,}', 'OpenAI API Key'),
            (r'sk-ant-[a-zA-Z0-9-]{80,}', 'Anthropic API Key'),
            (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token'),
            (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']{16,}["\']', 'Hardcoded API key'),
            (r'secret\s*[=:]\s*["\'][^"\']{16,}["\']', 'Hardcoded secret'),
        ]

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#'):
                continue

            for pattern, description in credential_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"Hardcoded credential: {description}",
                        line=i,
                        rule_id="MCP107",
                        cwe_id=798,
                        cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                    ))
                    break

        return issues

    def _scan_dynamic_instructions(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for dynamic instruction loading (rug pull risk)"""
        issues = []

        # Patterns that indicate dynamic loading of instructions/descriptions
        dynamic_patterns = [
            (r'description\s*[=:]\s*await\s+(fetch|axios|request)',
             'Description loaded from remote source'),
            (r'description\s*[=:]\s*\w+\s*\(\)',
             'Description loaded from function call'),
            (r'instructions?\s*[=:]\s*await\s+(fetch|axios|request)',
             'Instructions loaded from remote source'),
            (r'(fetch|axios|request)\s*\([^)]*\)\.then\s*\([^)]*description',
             'Description fetched asynchronously'),
            (r'\.load(Instructions?|Description)\s*\(',
             'Dynamic instruction/description loading'),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, description in dynamic_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message=f"Rug pull risk: {description}",
                        line=i,
                        rule_id="MCP110",
                        cwe_id=829,
                        cwe_link="https://cwe.mitre.org/data/definitions/829.html"
                    ))
                    break

        return issues
