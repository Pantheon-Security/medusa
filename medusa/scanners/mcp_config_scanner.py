#!/usr/bin/env python3
"""
MEDUSA MCP Configuration Scanner
Scans MCP (Model Context Protocol) configuration files for security issues

Detects vulnerabilities in:
- Claude Desktop configs (~/.config/Claude/claude_desktop_config.json)
- Cursor configs (.cursor/mcp.json)
- Generic MCP configs (mcp.json, mcp-config.json)
- VS Code MCP configs (.vscode/mcp.json)
"""

import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class MCPConfigScanner(RuleBasedScanner):
    """
    MCP Configuration Security Scanner

    Scans for:
    - MCP001: Hardcoded secrets in env blocks
    - MCP002: Hardcoded secrets in args
    - MCP003: Root filesystem access exposure
    - MCP004: Home directory access without restriction
    - MCP005: HTTP transport (no TLS)
    - MCP006: Missing authentication for remote servers
    - MCP007: Overly broad directory permissions
    - MCP008: Missing version pinning (rug pull risk)
    - MCP009: SSE transport without TLS (insecure)
    - MCP010: Non-localhost binding for local servers
    - MCP011: Wildcard path patterns (excessive access)
    - MCP012: Untrusted server sources
    - MCP013: Missing TLS certificate validation
    - MCP014: Server as OAuth provider (anti-pattern)
    - MCP015: Missing HTTPS for OAuth
    - MCP016: Stateful token management warning
    - MCP017: CVE-2025-6514 - mcp-remote RCE vulnerability (CVSS 9.6)
    - MCP018: mcp-remote over HTTP (MITM attack vector)
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['MCP-CFG-', 'MCP-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['mcp_config', 'mcp_security']

    # Known secret patterns (reused from EnvScanner with additions)
    SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', Severity.CRITICAL),
        (r'(?<![A-Za-z0-9])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9])', 'AWS Secret Access Key', Severity.HIGH),

        # GitHub
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', Severity.CRITICAL),
        (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token', Severity.CRITICAL),
        (r'github_pat_[0-9a-zA-Z_]{22,}', 'GitHub Fine-grained PAT', Severity.CRITICAL),

        # OpenAI / Anthropic
        (r'sk-[a-zA-Z0-9]{48,}', 'OpenAI API Key', Severity.CRITICAL),
        (r'sk-ant-[a-zA-Z0-9-]{80,}', 'Anthropic API Key', Severity.CRITICAL),
        (r'sk-proj-[a-zA-Z0-9]{48,}', 'OpenAI Project Key', Severity.CRITICAL),

        # Stripe
        (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Secret Key', Severity.CRITICAL),
        (r'sk_test_[0-9a-zA-Z]{24,}', 'Stripe Test Secret Key', Severity.MEDIUM),

        # Google
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', Severity.HIGH),

        # Slack
        (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', 'Slack Token', Severity.CRITICAL),

        # Database URLs with credentials
        (r'(postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@', 'Database URL with credentials', Severity.CRITICAL),

        # Generic patterns
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key', Severity.CRITICAL),
        (r'password\s*[=:]\s*["\'][^"\']{8,}["\']', 'Hardcoded Password', Severity.CRITICAL),
    ]

    # Sensitive environment variable patterns
    SENSITIVE_ENV_VARS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'api-key', 'access_key', 'access_token', 'auth_token', 'private_key',
        'client_secret', 'app_secret', 'encryption_key', 'signing_key',
        'database_url', 'db_password', 'redis_password', 'mongo_password',
        'credentials', 'bearer', 'jwt', 'session_secret',
    ]

    # Dangerous filesystem paths
    DANGEROUS_PATHS = {
        # Root access - CRITICAL
        '/': ('Root filesystem access', Severity.CRITICAL),
        'C:\\': ('Root filesystem access (Windows)', Severity.CRITICAL),
        'C:/': ('Root filesystem access (Windows)', Severity.CRITICAL),

        # Home directory without restriction - HIGH
        '~': ('Home directory access', Severity.HIGH),
        '$HOME': ('Home directory access', Severity.HIGH),
        '%USERPROFILE%': ('Home directory access (Windows)', Severity.HIGH),

        # Sensitive directories - HIGH
        '~/.ssh': ('SSH directory access', Severity.CRITICAL),
        '~/.aws': ('AWS credentials access', Severity.CRITICAL),
        '~/.config': ('Config directory access', Severity.HIGH),
        '~/.gnupg': ('GPG keys access', Severity.CRITICAL),
        '/etc': ('System config access', Severity.HIGH),
        '/etc/passwd': ('Password file access', Severity.CRITICAL),
        '/etc/shadow': ('Shadow file access', Severity.CRITICAL),
        '/var': ('System var access', Severity.MEDIUM),
        '/tmp': ('Temp directory access', Severity.MEDIUM),
    }

    # Placeholder values to ignore
    PLACEHOLDER_VALUES = [
        '', '""', "''", 'null', 'NULL', 'none', 'None', 'NONE',
        'your-key-here', 'your_key_here', 'your-secret-here',
        'xxx', 'XXX', 'xxxxxxxx', 'changeme', 'CHANGEME',
        'replace-me', 'replace_me', 'REPLACE_ME',
        'todo', 'TODO', 'fixme', 'FIXME',
        'example', 'EXAMPLE', 'sample', 'SAMPLE',
        'placeholder', 'PLACEHOLDER',
        '<your-key>', '<YOUR_KEY>', '<secret>',
        '<password>', '<api-key>', '<token>',
    ]

    # MCP011: Wildcard path patterns - excessive filesystem access
    WILDCARD_PATTERNS = [
        ('**', 'Double-star wildcard (recursive access)', Severity.HIGH),
        ('/*', 'Root wildcard pattern', Severity.CRITICAL),
        ('*.*', 'All files wildcard', Severity.HIGH),
        ('../', 'Path traversal pattern', Severity.CRITICAL),
        ('%SYSTEMROOT%', 'Windows system root access', Severity.CRITICAL),
        ('%PROGRAMFILES%', 'Windows program files access', Severity.HIGH),
    ]

    # MCP012: Untrusted server sources
    UNTRUSTED_SOURCES = [
        (r'git\+https?://github\.com/[^/]+/[^/]+(?!\.git)', 'GitHub repo without .git suffix', Severity.MEDIUM),
        (r'http://[^/]+', 'HTTP server (no TLS)', Severity.HIGH),
        (r'https?://\d+\.\d+\.\d+\.\d+', 'IP address instead of hostname', Severity.MEDIUM),
        (r'localhost:\d+', 'Localhost development server', Severity.LOW),
        (r'\.onion/', 'Tor hidden service', Severity.CRITICAL),
        (r'ngrok\.io|localtunnel\.me|serveo\.net', 'Tunnel service', Severity.HIGH),
    ]

    # MCP013: Insecure TLS settings
    INSECURE_TLS_SETTINGS = [
        'rejectUnauthorized',
        'NODE_TLS_REJECT_UNAUTHORIZED',
        'verify_ssl',
        'ssl_verify',
        'insecure',
        'skip_ssl',
        'no_verify',
    ]

    # CVE-2025-6514: mcp-remote RCE vulnerability
    # Vulnerable versions: 0.0.5 to 0.1.15
    # Fixed in: 0.1.16
    MCP_REMOTE_VULNERABLE_VERSIONS = [
        '0.0.5', '0.0.6', '0.0.7', '0.0.8', '0.0.9',
        '0.1.0', '0.1.1', '0.1.2', '0.1.3', '0.1.4', '0.1.5',
        '0.1.6', '0.1.7', '0.1.8', '0.1.9', '0.1.10', '0.1.11',
        '0.1.12', '0.1.13', '0.1.14', '0.1.15',
    ]

    # MCP014-016: OAuth Authorization Specification Warnings
    # Based on MCP security research - problematic OAuth patterns
    MCP_OAUTH_WARNINGS: List[Tuple[str, str, str, Severity]] = [
        # MCP014: Server acting as both resource + auth server (anti-pattern)
        (r'authorization_endpoint.*localhost',
         'MCP014',
         'MCP server implements its own OAuth - consider using external IdP',
         Severity.MEDIUM),
        (r'token_endpoint.*localhost',
         'MCP014',
         'Local token endpoint - MCP servers should use external OAuth providers',
         Severity.MEDIUM),

        # MCP015: Missing HTTPS for OAuth (critical)
        (r'authorization_endpoint.*http://(?!localhost)',
         'MCP015',
         'OAuth authorization_endpoint must use HTTPS',
         Severity.HIGH),
        (r'token_endpoint.*http://(?!localhost)',
         'MCP015',
         'OAuth token_endpoint must use HTTPS',
         Severity.HIGH),
        (r'redirect_uri.*http://(?!localhost)',
         'MCP015',
         'OAuth redirect_uri should use HTTPS',
         Severity.MEDIUM),

        # MCP016: Stateful token management (scaling concern)
        (r'token_store|token_cache|session_store',
         'MCP016',
         'Stateful MCP server detected - may have scaling issues',
         Severity.LOW),
        (r'in_memory.*token|token.*in_memory',
         'MCP016',
         'In-memory token storage - tokens lost on restart',
         Severity.LOW),
    ]

    # OAuth-related keys to check in config
    OAUTH_CONFIG_KEYS = [
        'authorization_endpoint',
        'token_endpoint',
        'redirect_uri',
        'client_id',
        'client_secret',
        'scope',
        'oauth',
        'auth',
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.json']

    def get_file_patterns(self) -> List[str]:
        """Match MCP config files"""
        return [
            'mcp.json',
            'mcp-config.json',
            'mcp_config.json',
            'claude_desktop_config.json',
            '.mcp.json',
        ]

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is an MCP config"""
        name = file_path.name.lower()
        parent = file_path.parent.name.lower()

        # Direct MCP config files
        mcp_names = [
            'mcp.json', 'mcp-config.json', 'mcp_config.json',
            'claude_desktop_config.json', '.mcp.json'
        ]
        if name in mcp_names:
            return True

        # MCP configs in specific directories
        if name == 'mcp.json' and parent in ['.cursor', '.vscode', 'claude']:
            return True

        return False

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Return high confidence for MCP config files.
        This ensures MCP scanner takes priority over generic JSON scanner.
        """
        if not self.can_scan(file_path):
            return 0

        # Check content for MCP-specific patterns
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Very high confidence if mcpServers or servers key present
                if '"mcpServers"' in content or '"servers"' in content:
                    return 95
                # Medium confidence for MCP-named files
                return 80
        except Exception:
            # File named like MCP config but can't read
            return 70

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan MCP configuration file for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Try to parse JSON
            try:
                config = json.loads(content)
            except json.JSONDecodeError as e:
                # Return JSON parse error without YAML rules (no valid content)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[ScannerIssue(
                        severity=Severity.LOW,
                        message=f"Invalid JSON in MCP config: {e}",
                        line=1,
                        rule_id="MCP000"
                    )],
                    scan_time=time.time() - start_time,
                    success=True
                )

            # Find line numbers for reporting
            lines = content.split('\n')

            # Scan for MCP servers
            mcp_servers = config.get('mcpServers', config.get('servers', {}))
            if isinstance(mcp_servers, dict):
                for server_name, server_config in mcp_servers.items():
                    if isinstance(server_config, dict):
                        server_issues = self._scan_server_config(
                            server_name, server_config, content, lines
                        )
                        issues.extend(server_issues)

            # Also scan raw content for secrets (in case of unusual structure)
            raw_issues = self._scan_raw_content(content, lines)
            # Only add raw issues that don't duplicate existing findings
            existing_lines = {i.line for i in issues}
            for issue in raw_issues:
                if issue.line not in existing_lines:
                    issues.append(issue)

            # Scan with YAML rules (lines already defined)
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

    def _scan_server_config(
        self,
        server_name: str,
        config: Dict[str, Any],
        full_content: str,
        lines: List[str]
    ) -> List[ScannerIssue]:
        """Scan a single MCP server configuration"""
        issues: List[ScannerIssue] = []

        # MCP001: Check env block for hardcoded secrets
        env_block = config.get('env', {})
        if isinstance(env_block, dict):
            for key, value in env_block.items():
                if not isinstance(value, str):
                    continue

                # Skip placeholders and environment variable references
                if self._is_placeholder(value):
                    continue

                line_num = self._find_line_number(lines, key, value)

                # Check for known secret patterns
                for pattern, description, severity in self.SECRET_PATTERNS:
                    if re.search(pattern, value):
                        issues.append(ScannerIssue(
                            severity=severity,
                            message=f"MCP server '{server_name}': Hardcoded {description} in env.{key}",
                            line=line_num,
                            rule_id="MCP001",
                            cwe_id=798,
                            cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                        ))
                        break
                else:
                    # Check for sensitive variable names with values
                    key_lower = key.lower()
                    for sensitive in self.SENSITIVE_ENV_VARS:
                        if sensitive in key_lower:
                            # Check if value looks like a real secret (not placeholder)
                            if len(value) >= 8 and not self._is_placeholder(value):
                                issues.append(ScannerIssue(
                                    severity=Severity.HIGH,
                                    message=f"MCP server '{server_name}': Sensitive variable '{key}' has hardcoded value in env block",
                                    line=line_num,
                                    rule_id="MCP001",
                                    cwe_id=798,
                            cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                                ))
                            break

        # MCP002: Check args for hardcoded secrets
        args = config.get('args', [])
        if isinstance(args, list):
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    continue

                line_num = self._find_line_number(lines, arg)

                for pattern, description, severity in self.SECRET_PATTERNS:
                    if re.search(pattern, arg):
                        issues.append(ScannerIssue(
                            severity=severity,
                            message=f"MCP server '{server_name}': Hardcoded {description} in args",
                            line=line_num,
                            rule_id="MCP002",
                            cwe_id=798,
                            cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                        ))
                        break

        # MCP003/004/007: Check for dangerous filesystem paths in args
        if isinstance(args, list):
            args_str = ' '.join(str(a) for a in args)

            # Skip placeholder paths (e.g., "/PATH-TO/", "/path/to/your/")
            placeholder_path_patterns = [
                r'/PATH[-_]TO/', r'/path[-_]to/', r'/your[-_]', r'/YOUR[-_]',
                r'/example/', r'/EXAMPLE/', r'/placeholder/', r'/PLACEHOLDER/',
                r'/replace[-_]me/', r'/REPLACE[-_]ME/',
            ]
            is_placeholder = any(re.search(p, args_str, re.IGNORECASE) for p in placeholder_path_patterns)
            if is_placeholder:
                pass  # Skip dangerous path checks for placeholder paths
            else:
                for dangerous_path, (description, severity) in self.DANGEROUS_PATHS.items():
                    # Check if path is used with directory flags
                    # For root path (/), require exact match or end-of-string/quote
                    if dangerous_path == '/':
                        path_patterns = [
                            r'--allowed-directories\s+"?\s*/"?\s*(?:$|"|\s)',  # --allowed-directories "/"
                            r'--directory\s+"?\s*/"?\s*(?:$|"|\s)',
                            r'--path\s+"?\s*/"?\s*(?:$|"|\s)',
                            r'--root\s+"?\s*/"?\s*(?:$|"|\s)',
                            r'-d\s+"?\s*/"?\s*(?:$|"|\s)',
                            r'(?:^|\s)"/"(?:\s|$)',  # Standalone "/" in args
                            r'(?:^|\s)/(?:\s|$)',    # Standalone / (not part of path)
                        ]
                    else:
                        path_patterns = [
                            f'--allowed-directories.*{re.escape(dangerous_path)}',
                            f'--directory.*{re.escape(dangerous_path)}',
                            f'--path.*{re.escape(dangerous_path)}',
                            f'--root.*{re.escape(dangerous_path)}',
                            f'-d.*{re.escape(dangerous_path)}',
                            f'"?{re.escape(dangerous_path)}"?',  # Direct path in args
                        ]

                    for pattern in path_patterns:
                        if re.search(pattern, args_str, re.IGNORECASE):
                            line_num = self._find_line_number(lines, dangerous_path)

                            # Determine rule ID based on path type
                            if dangerous_path in ['/', 'C:\\', 'C:/']:
                                rule_id = "MCP003"
                            elif dangerous_path in ['~', '$HOME', '%USERPROFILE%']:
                                rule_id = "MCP004"
                            else:
                                rule_id = "MCP007"

                            issues.append(ScannerIssue(
                                severity=severity,
                                message=f"MCP server '{server_name}': {description} - path '{dangerous_path}' is exposed",
                                line=line_num,
                                rule_id=rule_id,
                                cwe_id=552,
                                cwe_link="https://cwe.mitre.org/data/definitions/552.html"
                            ))
                            break

        # MCP005: Check for HTTP (non-TLS) transport
        url = config.get('url', '')
        if isinstance(url, str) and url.startswith('http://'):
            # Exception for localhost
            if not any(local in url for local in ['localhost', '127.0.0.1', '[::1]']):
                line_num = self._find_line_number(lines, url)
                issues.append(ScannerIssue(
                    severity=Severity.HIGH,
                    message=f"MCP server '{server_name}': HTTP transport without TLS - use HTTPS instead",
                    line=line_num,
                    rule_id="MCP005",
                    cwe_id=319,
                    cwe_link="https://cwe.mitre.org/data/definitions/319.html"
                ))

        # MCP006: Check for missing authentication on remote servers
        if isinstance(url, str) and url.startswith(('http://', 'https://')):
            auth = config.get('auth', config.get('authentication', config.get('oauth', None)))
            headers = config.get('headers', {})
            has_auth_header = any(
                'auth' in k.lower() or 'bearer' in k.lower() or 'api-key' in k.lower()
                for k in headers.keys()
            ) if isinstance(headers, dict) else False

            if not auth and not has_auth_header:
                line_num = self._find_line_number(lines, url)
                issues.append(ScannerIssue(
                    severity=Severity.HIGH,
                    message=f"MCP server '{server_name}': Remote server has no authentication configured",
                    line=line_num,
                    rule_id="MCP006",
                    cwe_id=306,
                    cwe_link="https://cwe.mitre.org/data/definitions/306.html"
                ))

        # MCP008: Check for missing version pinning (npm packages)
        command = config.get('command', '')
        if isinstance(command, str) and command in ['npx', 'npm']:
            # Check if args contain version specifier
            if isinstance(args, list):
                package_args = [a for a in args if isinstance(a, str) and not a.startswith('-')]
                for pkg in package_args:
                    if pkg and '@' not in pkg and not pkg.startswith('.'):
                        line_num = self._find_line_number(lines, pkg)
                        issues.append(ScannerIssue(
                            severity=Severity.MEDIUM,
                            message=f"MCP server '{server_name}': Package '{pkg}' has no version pinning - vulnerable to rug pull attacks",
                            line=line_num,
                            rule_id="MCP008",
                            cwe_id=1104,
                            cwe_link="https://cwe.mitre.org/data/definitions/1104.html"
                        ))

        # MCP017: CVE-2025-6514 - mcp-remote RCE vulnerability (CVSS 9.6)
        # Affects mcp-remote 0.0.5 to 0.1.15, fixed in 0.1.16
        if isinstance(command, str) and command in ['npx', 'npm']:
            if isinstance(args, list):
                for pkg in args:
                    if not isinstance(pkg, str):
                        continue
                    # Check for mcp-remote package
                    if 'mcp-remote' in pkg:
                        line_num = self._find_line_number(lines, 'mcp-remote')
                        # Check if version is specified
                        if '@' in pkg:
                            # Extract version: mcp-remote@0.1.15 or @anthropic/mcp-remote@0.1.15
                            version_match = re.search(r'mcp-remote@(\d+\.\d+\.\d+)', pkg)
                            if version_match:
                                version = version_match.group(1)
                                if version in self.MCP_REMOTE_VULNERABLE_VERSIONS:
                                    issues.append(ScannerIssue(
                                        severity=Severity.CRITICAL,
                                        message=f"MCP server '{server_name}': CVE-2025-6514 - mcp-remote@{version} is vulnerable to RCE via OAuth URL injection. Update to >=0.1.16",
                                        line=line_num,
                                        rule_id="MCP017",
                                        cwe_id=78,
                                        cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                                    ))
                        else:
                            # No version pinned - warn about potential vulnerability
                            issues.append(ScannerIssue(
                                severity=Severity.HIGH,
                                message=f"MCP server '{server_name}': CVE-2025-6514 risk - mcp-remote without version pin may use vulnerable version (<0.1.16). Pin to @0.1.16 or later",
                                line=line_num,
                                rule_id="MCP017",
                                cwe_id=78,
                                cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                            ))

        # MCP018: mcp-remote with HTTP URL (MITM attack vector for CVE-2025-6514)
        if isinstance(args, list):
            has_mcp_remote = any('mcp-remote' in str(a) for a in args)
            if has_mcp_remote:
                for arg in args:
                    if isinstance(arg, str) and arg.startswith('http://'):
                        if 'localhost' not in arg and '127.0.0.1' not in arg:
                            line_num = self._find_line_number(lines, arg)
                            issues.append(ScannerIssue(
                                severity=Severity.CRITICAL,
                                message=f"MCP server '{server_name}': mcp-remote over HTTP is vulnerable to MITM attacks (CVE-2025-6514 Scenario 2). Use HTTPS",
                                line=line_num,
                                rule_id="MCP018",
                                cwe_id=319,
                                cwe_link="https://cwe.mitre.org/data/definitions/319.html"
                            ))

        # MCP010: Check for non-localhost binding
        if isinstance(args, list):
            args_str = ' '.join(str(a) for a in args)
            # Check for binding to 0.0.0.0 or all interfaces
            if re.search(r'(--host|--bind|--listen)\s*[=\s]*0\.0\.0\.0', args_str):
                line_num = self._find_line_number(lines, '0.0.0.0')
                issues.append(ScannerIssue(
                    severity=Severity.MEDIUM,
                    message=f"MCP server '{server_name}': Binding to all interfaces (0.0.0.0) - should use localhost for local servers",
                    line=line_num,
                    rule_id="MCP010",
                    cwe_id=668,
                    cwe_link="https://cwe.mitre.org/data/definitions/668.html"
                ))

        # MCP011: Check for wildcard path patterns
        if isinstance(args, list):
            args_str = ' '.join(str(a) for a in args)
            for pattern, description, severity in self.WILDCARD_PATTERNS:
                if pattern in args_str:
                    line_num = self._find_line_number(lines, pattern)
                    issues.append(ScannerIssue(
                        severity=severity,
                        message=f"MCP server '{server_name}': {description} - excessive filesystem access risk",
                        line=line_num,
                        rule_id="MCP011",
                        cwe_id=552,
                        cwe_link="https://cwe.mitre.org/data/definitions/552.html"
                    ))

        # MCP012: Check for untrusted server sources
        source = config.get('url', '') or config.get('command', '') or ''
        if isinstance(args, list):
            source += ' ' + ' '.join(str(a) for a in args if isinstance(a, str))

        for pattern, description, severity in self.UNTRUSTED_SOURCES:
            if re.search(pattern, source, re.IGNORECASE):
                line_num = self._find_line_number(lines, pattern.replace(r'\.', '.').replace(r'\d+', ''))
                # Exception for localhost in development
                if 'localhost' in description.lower() and os.environ.get('MEDUSA_ALLOW_LOCALHOST'):
                    continue
                issues.append(ScannerIssue(
                    severity=severity,
                    message=f"MCP server '{server_name}': {description} detected",
                    line=line_num if line_num > 1 else 1,
                    rule_id="MCP012",
                    cwe_id=829,
                    cwe_link="https://cwe.mitre.org/data/definitions/829.html"
                ))

        # MCP013: Check for insecure TLS settings
        config_str = str(config)
        for setting in self.INSECURE_TLS_SETTINGS:
            if setting.lower() in config_str.lower():
                # Check if it's set to false/0 (disabling verification)
                setting_pattern = rf'{setting}\s*[=:]\s*["\']?(false|False|0|no)["\']?'
                if re.search(setting_pattern, config_str, re.IGNORECASE):
                    line_num = self._find_line_number(lines, setting)
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"MCP server '{server_name}': TLS certificate validation disabled ({setting})",
                        line=line_num,
                        rule_id="MCP013",
                        cwe_id=295,
                        cwe_link="https://cwe.mitre.org/data/definitions/295.html"
                    ))

        # MCP009: Check for SSE transport without TLS
        transport = config.get('transport', '')
        if isinstance(transport, str) and transport.lower() == 'sse':
            url = config.get('url', '')
            if isinstance(url, str) and url.startswith('http://') and 'localhost' not in url and '127.0.0.1' not in url:
                line_num = self._find_line_number(lines, 'sse', 'SSE')
                issues.append(ScannerIssue(
                    severity=Severity.HIGH,
                    message=f"MCP server '{server_name}': SSE transport over HTTP (no TLS) - vulnerable to eavesdropping",
                    line=line_num,
                    rule_id="MCP009",
                    cwe_id=319,
                    cwe_link="https://cwe.mitre.org/data/definitions/319.html"
                ))

        # MCP014-016: OAuth Authorization Spec Warnings
        config_str = json.dumps(config) if isinstance(config, dict) else str(config)
        for pattern, rule_id, message, severity in self.MCP_OAUTH_WARNINGS:
            if re.search(pattern, config_str, re.IGNORECASE):
                line_num = self._find_line_number(lines, pattern.split('.*')[0].replace('\\', ''))
                issues.append(ScannerIssue(
                    severity=severity,
                    message=f"MCP server '{server_name}': {message}",
                    line=line_num if line_num > 1 else 1,
                    rule_id=rule_id,
                    cwe_id=287 if rule_id == 'MCP015' else 1188,
                    cwe_link="https://cwe.mitre.org/data/definitions/287.html" if rule_id == 'MCP015' else "https://cwe.mitre.org/data/definitions/1188.html"
                ))

        return issues

    def _scan_raw_content(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Scan raw content for secrets that might be in unusual locations"""
        issues: List[ScannerIssue] = []

        for i, line in enumerate(lines, 1):
            # Skip if line looks like a comment or empty
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            for pattern, description, severity in self.SECRET_PATTERNS:
                if re.search(pattern, line):
                    issues.append(ScannerIssue(
                        severity=severity,
                        message=f"Potential {description} found in config",
                        line=i,
                        rule_id="MCP001",
                        cwe_id=798,
                        cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                    ))
                    break  # One issue per line max

        return issues

    def _is_placeholder(self, value: str) -> bool:
        """Check if a value is a placeholder, not a real secret"""
        if not value:
            return True

        value_lower = value.lower().strip()

        # Check against known placeholders
        if value_lower in [p.lower() for p in self.PLACEHOLDER_VALUES]:
            return True

        # Check for environment variable references
        if value.startswith('${') or value.startswith('$(') or value.startswith('$'):
            return True

        # Check for template syntax
        if value.startswith('<') and value.endswith('>'):
            return True
        if '{{' in value and '}}' in value:
            return True

        return False

    def _find_line_number(self, lines: List[str], *search_strings: str) -> int:
        """Find the line number containing any of the search strings"""
        for i, line in enumerate(lines, 1):
            for search in search_strings:
                if search and search in line:
                    return i
        return 1  # Default to line 1 if not found

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0.0

        freq: Dict[str, int] = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1

        length = len(string)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def get_install_instructions(self) -> str:
        return "MCP configuration scanning is built-in (no installation required)"
