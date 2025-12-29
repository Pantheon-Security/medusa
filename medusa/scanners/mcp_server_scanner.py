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

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class MCPServerScanner(RuleBasedScanner):
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
    - MCP110: Dynamic instruction loading (rug pull risk)
    - MCP111: Data exfiltration patterns
    - MCP112: Tool name spoofing (deceptive tool names)
    - MCP113: Confused deputy patterns (token passthrough)
    - MCP114: Cross-server attack patterns (server shadowing)
    - MCP115: Insecure transport (SSE without TLS)
    - MCP116: Dynamic schema updates (mid-session changes)
    - MCP117: CVE-2025-6514 OAuth command injection (mcp-remote RCE)
    - MCP118: Advanced confused deputy attacks (privilege escalation)
    - MCP119: PowerShell subexpression injection (Windows RCE)
    - MCP120: Tool name shadows system function
    - MCP121: Tool impersonation pattern
    - MCP122: Deceptive tool description
    - MCP123: Auto-update without integrity check
    - MCP124: Path traversal vulnerabilities (arbitrary file read/write)
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['MCP-SRV-', 'MCP-', 'MEDUSA-MCP-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['mcp_server', 'mcp_security', 'tool_poisoning']

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
        (r'execute\s*\([^)]*\+\s*["\']?\s*\+?\s*(input|query|param|user|data)\b',
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

    # MCP124: Path traversal vulnerabilities - arbitrary file read/write
    PATH_TRAVERSAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct path parameter to file operations (no validation)
        (r'(readFile|readFileSync)\s*\(\s*(file_?path|path|filename|input\.\w*path)',
         'Path traversal: File read with unvalidated path parameter', Severity.CRITICAL),
        (r'(writeFile|writeFileSync)\s*\(\s*(file_?path|path|filename|input\.\w*path)',
         'Path traversal: File write with unvalidated path parameter', Severity.CRITICAL),
        (r'open\s*\(\s*(file_?path|path|filename|input\.\w*path)',
         'Path traversal: File open with unvalidated path parameter', Severity.CRITICAL),

        # Python path operations without validation
        (r'Path\s*\(\s*(file_?path|path|filename|input\.get)',
         'Path traversal: Path object with unvalidated input', Severity.HIGH),
        (r'\.read_text\s*\(\)|\.read_bytes\s*\(\)',
         'Direct file read without path validation', Severity.MEDIUM),

        # Missing path validation patterns
        (r'(?<!realpath)(?<!resolve)(?<!abspath)\s*(readFile|open|Path)\s*\([^)]*\+',
         'File operation with string concatenation (no path validation)', Severity.HIGH),

        # Dangerous patterns that bypass validation
        (r'os\.path\.(isfile|isdir|exists)\s*\([^)]*\).*(?!realpath)',
         'Path check without realpath (symlink bypass)', Severity.MEDIUM),

        # User input directly in file paths
        (r'f["\'][^"\']*\{(file_?path|path|filename|input)',
         'Path traversal: f-string with unvalidated path input', Severity.CRITICAL),
        (r'`[^`]*\$\{(file_?path|path|filename|input)',
         'Path traversal: Template literal with unvalidated path input', Severity.CRITICAL),

        # Missing directory restriction
        (r'(send_file|send_voice|download_media)\s*\([^)]*(?!allowed_dir|base_path|restrict)',
         'File operation without directory restriction', Severity.HIGH),
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

    # MCP112: Tool name spoofing patterns - deceptive names that hide malicious intent
    TOOL_NAME_SPOOFING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Names that sound benign but could be malicious
        (r'name\s*[=:]\s*["\'](?:send_email|email_sender)["\'].*(?:readFile|process\.env|credentials)',
         'Tool name spoofing - email tool accessing sensitive data', Severity.CRITICAL),
        (r'name\s*[=:]\s*["\'](?:format|formatter|beautify)["\'].*(?:fetch|request|axios|http)',
         'Tool name spoofing - formatter tool making network requests', Severity.HIGH),
        (r'name\s*[=:]\s*["\'](?:validate|validator|check)["\'].*(?:exec|spawn|system)',
         'Tool name spoofing - validator tool executing commands', Severity.CRITICAL),
        (r'name\s*[=:]\s*["\'](?:log|logger|debug)["\'].*(?:post|fetch|request)\s*\(',
         'Tool name spoofing - logger tool sending data externally', Severity.HIGH),
        (r'name\s*[=:]\s*["\'](?:helper|util|utility)["\'].*(?:\.ssh|\.aws|credentials)',
         'Tool name spoofing - utility tool accessing credentials', Severity.CRITICAL),
    ]

    # MCP113: Confused deputy patterns - token/credential passthrough abuse
    CONFUSED_DEPUTY_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Token passthrough without validation
        (r'(authorization|auth|bearer|token)\s*[=:]\s*(req|request|ctx|context)\.',
         'Confused deputy - token passthrough from request', Severity.HIGH),
        (r'headers\s*\[\s*["\']authorization["\']\s*\]\s*=.*\+',
         'Confused deputy - dynamic authorization header', Severity.HIGH),
        (r'(process\.env|os\.environ)\s*\[[^\]]*\]\s*\+\s*[^,;\n]*(user|input|param|query)\b',
         'Confused deputy - mixing env vars with user input', Severity.CRITICAL),
        (r'fetch\s*\([^)]*,\s*\{[^}]*headers\s*:\s*\{[^}]*["\']Authorization["\']\s*:\s*`',
         'Confused deputy - template literal in auth header', Severity.HIGH),

        # Acting on behalf of user without verification
        (r'(as_user|on_behalf|impersonate|act_as)\s*[=:]',
         'Confused deputy - user impersonation pattern', Severity.HIGH),
        (r'(sudo|runas|elevate)\s*[=:]\s*(true|True|1)',
         'Confused deputy - privilege elevation flag', Severity.CRITICAL),
    ]

    # MCP114: Cross-server attack patterns - server shadowing/hijacking
    CROSS_SERVER_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Registering tools with existing names
        (r'(?:registerTool|server\.tool|\.tool)\s*\([^)]*name\s*[=:]\s*["\'](?:read|write|execute|shell|file)',
         'Cross-server attack - common tool name that could shadow', Severity.MEDIUM),

        # Server discovery/enumeration
        (r'(listServers|getServers|discoverServers|enumServers)',
         'Cross-server attack - server enumeration function', Severity.MEDIUM),
        (r'(connectTo|proxyTo|forwardTo)\s*\(\s*[^)]*\+',
         'Cross-server attack - dynamic server connection', Severity.HIGH),

        # MCP server manipulation
        (r'(unregisterServer|removeServer|replaceServer)\s*\(',
         'Cross-server attack - server manipulation', Severity.HIGH),
        (r'server\s*\[\s*["\'].*["\']\s*\]\s*=',
         'Cross-server attack - dynamic server assignment', Severity.MEDIUM),
    ]

    # MCP115: Insecure transport patterns
    INSECURE_TRANSPORT_PATTERNS: List[Tuple[str, str, Severity]] = [
        # SSE without TLS
        (r'(SSEServerTransport|SSEClientTransport|createSSE)\s*\([^)]*http://',
         'Insecure transport - SSE over HTTP (no TLS)', Severity.HIGH),
        (r'new\s+EventSource\s*\(\s*["\']http://',
         'Insecure transport - EventSource over HTTP', Severity.HIGH),

        # Binding to all interfaces
        (r'(listen|bind|serve)\s*\([^)]*0\.0\.0\.0',
         'Insecure transport - binding to all interfaces', Severity.MEDIUM),
        (r'host\s*[=:]\s*["\']0\.0\.0\.0["\']',
         'Insecure transport - host set to all interfaces', Severity.MEDIUM),

        # Disabled TLS verification
        (r'(rejectUnauthorized|verify_ssl|verify)\s*[=:]\s*(false|False|0)',
         'Insecure transport - TLS verification disabled', Severity.CRITICAL),
        (r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0',
         'Insecure transport - Node TLS rejection disabled', Severity.CRITICAL),
    ]

    # MCP116: Dynamic schema update patterns - tools changing mid-session
    DYNAMIC_SCHEMA_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Schema modification functions
        (r'(updateSchema|modifySchema|changeSchema|setSchema)\s*\(',
         'Dynamic schema - schema modification function', Severity.HIGH),
        (r'(tool|tools)\s*\[\s*[^]]*\]\s*\.\s*(schema|inputSchema)\s*=',
         'Dynamic schema - direct schema assignment', Severity.HIGH),

        # Tool description updates
        (r'(updateDescription|setDescription|changeDescription)\s*\(',
         'Dynamic schema - description modification', Severity.HIGH),
        (r'\.description\s*=\s*(await\s+)?fetch',
         'Dynamic schema - description from remote source', Severity.CRITICAL),

        # Dynamic tool registration
        (r'setTimeout\s*\([^)]*registerTool',
         'Dynamic schema - delayed tool registration', Severity.MEDIUM),
        (r'setInterval\s*\([^)]*\.(schema|description|tool)',
         'Dynamic schema - periodic schema updates', Severity.HIGH),

        # Conditional tool behavior (must be in condition, not just any mention)
        (r'if\s*\([^)]*(?:Date\s*\(\)|\.getTime\(\)|\.getHours?\(\)|\.getDay\(\))',
         'Dynamic schema - time-based conditional behavior', Severity.MEDIUM),
    ]

    # MCP117: CVE-2025-6514 OAuth Command Injection patterns
    # Based on mcp-remote vulnerability (CVSS 9.6) - authorization_endpoint URL injection
    # Affects: mcp-remote versions 0.0.5 to 0.1.15
    OAUTH_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # OAuth URL handling with user input
        (r'authorization_endpoint\s*[=:]\s*[^,\n]*\+',
         'CVE-2025-6514: OAuth authorization_endpoint with string concatenation', Severity.CRITICAL),
        (r'authorization_endpoint\s*[=:]\s*[`"\']?\$\{',
         'CVE-2025-6514: OAuth authorization_endpoint with template literal', Severity.CRITICAL),
        (r'authorization_endpoint\s*[=:]\s*.*(user|input|param|query)',
         'CVE-2025-6514: OAuth authorization_endpoint from user input', Severity.CRITICAL),

        # open() function with untrusted URLs (the actual attack vector)
        (r'open\s*\(\s*[^)]*authorization',
         'CVE-2025-6514: open() called with authorization URL', Severity.HIGH),
        (r'(start|open|exec|spawn)\s*\([^)]*\+[^)]*url',
         'CVE-2025-6514: Browser open with dynamic URL', Severity.HIGH),
        (r'(opn|open)\s*\(\s*`[^`]*\$\{',
         'CVE-2025-6514: open() with template literal URL', Severity.CRITICAL),

        # PowerShell command injection indicators (Windows attack vector)
        # Must look like PowerShell: Start-Process, Invoke-Expression, etc. nearby
        (r'(Start-Process|Invoke-Expression|iex|powershell).*\$\([^)]+\)',
         'PowerShell subexpression that could enable command injection', Severity.MEDIUM),
        (r'Start-Process\s*[^;]*\+',
         'CVE-2025-6514: Start-Process with dynamic argument', Severity.HIGH),

        # mcp-remote specific patterns
        (r'mcp-remote',
         'Uses mcp-remote - check version >= 0.1.16 for CVE-2025-6514 fix', Severity.MEDIUM),
        (r'@anthropic/mcp-remote',
         'Uses mcp-remote - check version >= 0.1.16 for CVE-2025-6514 fix', Severity.MEDIUM),

        # OAuth metadata discovery with untrusted input
        (r'\.well-known/oauth-authorization-server.*\+',
         'OAuth discovery with dynamic server (injection risk)', Severity.HIGH),
        (r'openid-configuration.*\+',
         'OpenID configuration discovery with dynamic URL', Severity.HIGH),

        # General OAuth URL manipulation
        (r'(redirect_uri|callback_url)\s*[=:]\s*[^,\n]*\+',
         'OAuth redirect_uri with string concatenation', Severity.HIGH),
        (r'token_endpoint\s*[=:]\s*[^,\n]*\+',
         'OAuth token_endpoint with string concatenation', Severity.HIGH),
    ]

    # MCP118: Confused Deputy Attack patterns (expanded from MCP113)
    # Based on MCP security research - privilege escalation via tool authorization
    CONFUSED_DEPUTY_ADVANCED_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Tool using higher privileges than caller
        (r'(admin|root|system).*token.*tool',
         'Confused deputy - tool using elevated token', Severity.CRITICAL),
        (r'service_account.*execute',
         'Confused deputy - service account execution', Severity.HIGH),

        # Capability confusion
        (r'(user|caller).*permission.*bypass',
         'Confused deputy - permission bypass pattern', Severity.CRITICAL),
        (r'inherit.*privilege',
         'Confused deputy - privilege inheritance', Severity.HIGH),

        # Request context manipulation
        (r'(context|ctx)\.(user|auth).*=.*tool',
         'Confused deputy - context manipulation from tool', Severity.HIGH),
        (r'override.*(permission|role|access)',
         'Confused deputy - permission override', Severity.CRITICAL),

        # Indirect authorization bypass
        (r'tool.*auth.*\!=.*user.*auth',
         'Confused deputy - tool auth differs from user', Severity.HIGH),
        (r'(escalate|elevate).*via.*tool',
         'Confused deputy - privilege escalation via tool', Severity.CRITICAL),

        # Multi-hop authorization issues
        (r'forward.*auth.*header',
         'Confused deputy - auth header forwarding', Severity.MEDIUM),
        (r'proxy.*credential',
         'Confused deputy - credential proxying', Severity.HIGH),
    ]

    # MCP119: PowerShell subexpression injection patterns
    # Windows-specific RCE via $() in strings - expanded detection
    POWERSHELL_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Direct $() subexpression patterns (Windows RCE vector)
        (r'\$\([^)]*(?:cmd|powershell|exe|del|rm|wget|curl)[^)]*\)',
         'MCP119: PowerShell subexpression with dangerous command', Severity.CRITICAL),
        (r'\$\([^)]*(?:invoke|iex|start-process|new-object)[^)]*\)',
         'MCP119: PowerShell subexpression with execution command', Severity.CRITICAL),

        # Custom URI scheme with subexpression
        (r'[a-z]{2,10}:\$\([^)]+\)',
         'MCP119: Custom URI scheme with PowerShell subexpression', Severity.CRITICAL),
        (r'[a-z]{2,10}://\$\{',
         'MCP119: Custom URI scheme with template injection', Severity.HIGH),

        # open() function patterns (the attack vector for mcp-remote)
        (r'open\s*\(\s*[^)]*\$\([^)]+\)',
         'MCP119: open() with PowerShell subexpression', Severity.CRITICAL),
        (r'open\s*\(\s*[`"\'][^`"\']*\+',
         'MCP119: open() with string concatenation', Severity.HIGH),
        (r'open\s*\(\s*`[^`]*\$\{',
         'MCP119: open() with template literal', Severity.HIGH),

        # PowerShell encoded command indicators
        (r'-[Ee]ncoded[Cc]ommand',
         'MCP119: PowerShell encoded command (obfuscation)', Severity.CRITICAL),
        (r'-[Ww]indow[Ss]tyle\s+[Hh]idden',
         'MCP119: Hidden PowerShell window', Severity.HIGH),
        (r'[Bb]ypass.*[Ee]xecution[Pp]olicy',
         'MCP119: Execution policy bypass', Severity.HIGH),

        # Start-Process with dynamic arguments
        (r'Start-Process\s+[^;]*\$\(',
         'MCP119: Start-Process with subexpression', Severity.CRITICAL),
        (r'Invoke-Expression\s+[^;]*\$\(',
         'MCP119: Invoke-Expression with subexpression', Severity.CRITICAL),
    ]

    # MCP120-122: Tool Shadowing/Impersonation patterns
    # Deceptive tool names that mimic system functions
    TOOL_SHADOW_NAMES = [
        "ListFiles", "ReadFile", "WriteFile", "DeleteFile",
        "Execute", "RunCommand", "Shell", "Terminal",
        "GetEnv", "SetEnv", "ProcessList", "KillProcess",
        "NetworkRequest", "FetchURL", "Download", "Upload",
        "CreateUser", "DeleteUser", "ChangePassword",
        "DatabaseQuery", "SQLExecute", "AdminAccess",
        "SystemInfo", "GetCredentials", "SetPermission",
    ]

    TOOL_SHADOWING_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Tool names that shadow common system operations
        (r'(?:name|tool_name)\s*[=:]\s*["\'](?:List|Read|Write|Delete|Get|Set|Create|Kill|Execute|Run|Admin|System|Process|Network|Database|SQL|Fetch|Upload|Download)[A-Z][a-zA-Z]*["\']',
         'MCP120: Tool name shadows common system operation', Severity.MEDIUM),

        # Tool impersonation - names similar to built-in tools
        (r'(?:name|tool_name)\s*[=:]\s*["\'](?:file_read|file_write|run_bash|run_shell|exec_cmd|db_query)["\']',
         'MCP121: Tool name impersonates built-in tool', Severity.MEDIUM),

        # Intentionally deceptive names
        (r'(?:name|tool_name)\s*[=:]\s*["\'](?:safe|benign|harmless|helper|utility|util)[_-]?[a-z]+["\'].*(?:exec|shell|cmd|eval)',
         'MCP121: Deceptive "safe" name with dangerous operation', Severity.HIGH),

        # Description mentions different functionality than name suggests
        (r'name\s*[=:]\s*["\'](?:format|beautify|lint|validate)["\'].*description\s*[=:]\s*["\'][^"\']*(?:execute|delete|send|upload)',
         'MCP122: Deceptive tool description mismatches name', Severity.HIGH),

        # Hidden functionality in description
        (r'description\s*[=:]\s*["\'][^"\']*(?:also|additionally|secretly|internally)\s+(?:read|send|upload|delete)',
         'MCP122: Description reveals hidden functionality', Severity.HIGH),
    ]

    # MCP123: Auto-update without integrity check patterns
    AUTO_UPDATE_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Auto-update flags without verification
        (r'auto[_-]?update\s*[=:]\s*["\']?(?:true|yes|enabled|1)["\']?',
         'MCP123: Auto-update enabled without integrity check', Severity.MEDIUM),
        (r'self[_-]?update\s*\(',
         'MCP123: Self-update function (check for integrity verification)', Severity.MEDIUM),
        (r'fetch[_-]?latest[_-]?version\s*\(',
         'MCP123: Fetches latest version (check for signature verification)', Severity.MEDIUM),

        # Download without checksum/signature
        (r'download\s*\([^)]*\)(?!.*(?:checksum|hash|verify|signature))',
         'MCP123: Download without integrity verification', Severity.HIGH),
        (r'update\s*\([^)]*\)(?!.*(?:verify|sign|hash))',
         'MCP123: Update without verification', Severity.HIGH),
        (r'install\s*\([^)]*(?:url|http)[^)]*\)(?!.*signature)',
         'MCP123: Install from URL without signature check', Severity.HIGH),

        # Dynamic code loading
        (r'(?:eval|exec)\s*\(\s*(?:await\s+)?(?:fetch|request|axios)',
         'MCP123: Dynamic code execution from remote source', Severity.CRITICAL),
        (r'import\s*\([^)]*\+[^)]*\)',
         'MCP123: Dynamic import with concatenation', Severity.HIGH),
        (r'require\s*\([^)]*\+[^)]*\)',
         'MCP123: Dynamic require with concatenation', Severity.HIGH),
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
                # Not an MCP file, but still scan with YAML rules
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=yaml_issues,
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

            # MCP124: Path traversal vulnerabilities
            issues.extend(self._scan_patterns(
                content, lines,
                self.PATH_TRAVERSAL_PATTERNS,
                "MCP124"
            ))

            # MCP108/MCP109: Missing annotations
            issues.extend(self._scan_missing_annotations(content, lines))

            # MCP107: Hardcoded credentials
            issues.extend(self._scan_hardcoded_credentials(content, lines))

            # MCP110: Dynamic instruction loading
            issues.extend(self._scan_dynamic_instructions(content, lines))

            # MCP112: Tool name spoofing
            issues.extend(self._scan_tool_name_spoofing(content, lines))

            # MCP113: Confused deputy patterns
            issues.extend(self._scan_patterns(
                content, lines,
                self.CONFUSED_DEPUTY_PATTERNS,
                "MCP113"
            ))

            # MCP114: Cross-server attack patterns
            issues.extend(self._scan_patterns(
                content, lines,
                self.CROSS_SERVER_PATTERNS,
                "MCP114"
            ))

            # MCP115: Insecure transport
            issues.extend(self._scan_patterns(
                content, lines,
                self.INSECURE_TRANSPORT_PATTERNS,
                "MCP115"
            ))

            # MCP116: Dynamic schema updates
            issues.extend(self._scan_patterns(
                content, lines,
                self.DYNAMIC_SCHEMA_PATTERNS,
                "MCP116"
            ))

            # MCP117: CVE-2025-6514 OAuth command injection
            issues.extend(self._scan_patterns(
                content, lines,
                self.OAUTH_INJECTION_PATTERNS,
                "MCP117"
            ))

            # MCP118: Advanced confused deputy patterns
            issues.extend(self._scan_patterns(
                content, lines,
                self.CONFUSED_DEPUTY_ADVANCED_PATTERNS,
                "MCP118"
            ))

            # MCP119: PowerShell subexpression injection (Windows RCE)
            issues.extend(self._scan_patterns(
                content, lines,
                self.POWERSHELL_INJECTION_PATTERNS,
                "MCP119"
            ))

            # MCP120-122: Tool shadowing/impersonation patterns
            issues.extend(self._scan_patterns(
                content, lines,
                self.TOOL_SHADOWING_PATTERNS,
                "MCP120"
            ))

            # MCP123: Auto-update without integrity check
            issues.extend(self._scan_patterns(
                content, lines,
                self.AUTO_UPDATE_PATTERNS,
                "MCP123"
            ))

            # Scan with YAML rules
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
                        "MCP112": (345, "https://cwe.mitre.org/data/definitions/345.html"),  # Insufficient verification
                        "MCP113": (441, "https://cwe.mitre.org/data/definitions/441.html"),  # Confused deputy
                        "MCP114": (290, "https://cwe.mitre.org/data/definitions/290.html"),  # Auth bypass by spoofing
                        "MCP115": (319, "https://cwe.mitre.org/data/definitions/319.html"),  # Cleartext transmission
                        "MCP116": (915, "https://cwe.mitre.org/data/definitions/915.html"),  # Improperly controlled mod
                        "MCP117": (78, "https://cwe.mitre.org/data/definitions/78.html"),  # CVE-2025-6514 command injection
                        "MCP118": (441, "https://cwe.mitre.org/data/definitions/441.html"),  # Confused deputy
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

    def _scan_tool_name_spoofing(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan for tool name spoofing - deceptive names hiding malicious behavior"""
        issues = []

        # Find tool definitions and check if name vs behavior is suspicious
        tool_pattern = r'(?:server\.tool|\.tool|@server\.tool|@mcp\.tool|registerTool)\s*\([^)]*'

        # Build a map of tool-like regions in the content
        for match in re.finditer(tool_pattern, content, re.DOTALL):
            tool_start = match.start()
            # Get ~500 chars after the tool definition start for analysis
            tool_region = content[tool_start:tool_start + 500]
            line_num = content[:tool_start].count('\n') + 1

            for pattern, description, severity in self.TOOL_NAME_SPOOFING_PATTERNS:
                if re.search(pattern, tool_region, re.IGNORECASE | re.DOTALL):
                    issues.append(ScannerIssue(
                        severity=severity,
                        message=description,
                        line=line_num,
                        rule_id="MCP112",
                        cwe_id=345,
                        cwe_link="https://cwe.mitre.org/data/definitions/345.html"
                    ))
                    break  # One spoofing issue per tool

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
