#!/usr/bin/env python3
"""
MEDUSA MCP-Remote RCE Scanner (CVE-2025-6514)

Detects vulnerable mcp-remote package versions affected by the critical
OS command injection vulnerability (CVSS 9.6).

The vulnerability allows remote code execution when connecting to untrusted
MCP servers via crafted authorization_endpoint URLs that bypass URL validation
and execute PowerShell commands on Windows.

References:
- https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
- https://github.com/advisories/GHSA-6xpm-ggf7-wc3p
- https://nvd.nist.gov/vuln/detail/CVE-2025-6514
"""

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class MCPRemoteRCEScanner(BaseScanner):
    """
    Scanner for CVE-2025-6514 - Critical RCE in mcp-remote

    This vulnerability allows OS command injection via crafted
    authorization_endpoint URLs when using mcp-remote to connect
    to untrusted MCP servers.

    Checks:
    - package.json for vulnerable mcp-remote versions
    - package-lock.json, yarn.lock, pnpm-lock.yaml for locked versions
    - Claude Desktop config for mcp-remote usage
    - Source files for vulnerable patterns (open() with authorization URLs)
    """

    # Vulnerable version range
    # Affected: >= 0.0.5, < 0.1.16
    VULNERABLE_MIN = (0, 0, 5)
    VULNERABLE_MAX = (0, 1, 15)  # inclusive
    FIXED_VERSION = "0.1.16"

    # Package names to check
    MCP_REMOTE_PACKAGES = [
        "mcp-remote",
        "@anthropic/mcp-remote",
        "@modelcontextprotocol/mcp-remote",
    ]

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return ['.json', '.lock', '.yaml', '.ts', '.js', '.mjs']

    def get_target_files(self) -> List[str]:
        return [
            'package.json',
            'package-lock.json',
            'yarn.lock',
            'pnpm-lock.yaml',
            'claude_desktop_config.json',
        ]

    def is_available(self) -> bool:
        return True

    def get_confidence_score(self, file_path: Path) -> int:
        """Return high confidence for package manifest files."""
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()

        # High confidence for package manifest files
        if name_lower == 'package.json':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if any(pkg in content for pkg in self.MCP_REMOTE_PACKAGES):
                        return 95  # Very high - this is what we're looking for
                    if 'mcp' in content.lower():
                        return 60  # Medium - MCP related but not mcp-remote
            except (OSError, IOError, UnicodeDecodeError):
                pass
            return 20  # Low - it's a package.json but no MCP

        # High confidence for lockfiles
        if name_lower in ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']:
            return 85

        # High confidence for Claude Desktop config
        if name_lower == 'claude_desktop_config.json':
            return 90

        # TypeScript/JavaScript - check for mcp-remote usage
        if file_path.suffix in ['.ts', '.js', '.mjs']:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(5000)
                    if 'mcp-remote' in content or 'authorization_endpoint' in content:
                        return 80
            except (OSError, IOError, UnicodeDecodeError):
                pass
            return 0

        return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan for CVE-2025-6514 (mcp-remote RCE)"""
        start_time = time.time()
        issues = []

        try:
            filename = file_path.name.lower()

            if filename == 'package.json':
                issues.extend(self._scan_package_json(file_path))
            elif filename == 'package-lock.json':
                issues.extend(self._scan_package_lock(file_path))
            elif filename == 'yarn.lock':
                issues.extend(self._scan_yarn_lock(file_path))
            elif filename == 'pnpm-lock.yaml':
                issues.extend(self._scan_pnpm_lock(file_path))
            elif filename == 'claude_desktop_config.json':
                issues.extend(self._scan_claude_config(file_path))
            elif file_path.suffix in ['.ts', '.js', '.mjs']:
                issues.extend(self._scan_source_file(file_path))

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

    def _scan_package_json(self, file_path: Path) -> List[ScannerIssue]:
        """Scan package.json for vulnerable mcp-remote dependency"""
        issues = []

        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return issues

        # Check all dependency sections
        dep_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

        for section in dep_sections:
            deps = data.get(section, {})

            for pkg in self.MCP_REMOTE_PACKAGES:
                if pkg in deps:
                    version = self._extract_version(deps[pkg])
                    if version and self._is_vulnerable(version):
                        issues.append(ScannerIssue(
                            severity=Severity.CRITICAL,
                            message=f"CVE-2025-6514: {pkg}@{version} is vulnerable to RCE via OS command injection. "
                                    f"A malicious MCP server can execute arbitrary commands on your machine. "
                                    f"Upgrade to {self.FIXED_VERSION}. "
                                    f"See: https://github.com/advisories/GHSA-6xpm-ggf7-wc3p",
                            line=None,
                            rule_id="mcp-remote-rce",
                            cwe_id=78,
                            cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                        ))

        return issues

    def _scan_package_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan package-lock.json for vulnerable transitive dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return issues

        # Handle both lockfile v2/v3 format
        packages = data.get('packages', {})
        if not packages:
            # Fallback to v1 format
            packages = data.get('dependencies', {})

        for pkg_path, pkg_info in packages.items():
            pkg_name = pkg_path.split('node_modules/')[-1] if 'node_modules/' in pkg_path else pkg_path
            version = pkg_info.get('version', '')

            for target_pkg in self.MCP_REMOTE_PACKAGES:
                if pkg_name == target_pkg or pkg_name.endswith(f'/{target_pkg}'):
                    if self._is_vulnerable(version):
                        issues.append(ScannerIssue(
                            severity=Severity.CRITICAL,
                            message=f"CVE-2025-6514: Locked {target_pkg}@{version} is vulnerable to RCE. "
                                    f"Run 'npm update {target_pkg}' to upgrade to {self.FIXED_VERSION}",
                            line=None,
                            rule_id="mcp-remote-rce-lock",
                            cwe_id=78,
                            cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                        ))

        return issues

    def _scan_yarn_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan yarn.lock for vulnerable dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            content = f.read()

        for pkg in self.MCP_REMOTE_PACKAGES:
            # Yarn.lock format: mcp-remote@^0.1.0:
            #   version "0.1.10"
            pkg_escaped = re.escape(pkg)
            pattern = rf'{pkg_escaped}@[^:]+:\s*\n\s*version\s+"([^"]+)"'

            for match in re.finditer(pattern, content):
                version = match.group(1)
                if self._is_vulnerable(version):
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-6514: Locked {pkg}@{version} is vulnerable to RCE. "
                                f"Run 'yarn upgrade {pkg}' to upgrade to {self.FIXED_VERSION}",
                        line=None,
                        rule_id="mcp-remote-rce-yarn",
                        cwe_id=78,
                        cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                    ))

        return issues

    def _scan_pnpm_lock(self, file_path: Path) -> List[ScannerIssue]:
        """Scan pnpm-lock.yaml for vulnerable dependencies"""
        issues = []

        with open(file_path, 'r') as f:
            content = f.read()

        for pkg in self.MCP_REMOTE_PACKAGES:
            # pnpm format: /mcp-remote@0.1.10 or mcp-remote@0.1.10
            pkg_escaped = re.escape(pkg)
            pattern = rf'[/"]?{pkg_escaped}@(\d+\.\d+\.\d+(?:-[a-z0-9.]+)?)'

            for match in re.finditer(pattern, content):
                version = match.group(1)
                if self._is_vulnerable(version):
                    issues.append(ScannerIssue(
                        severity=Severity.CRITICAL,
                        message=f"CVE-2025-6514: Locked {pkg}@{version} is vulnerable to RCE. "
                                f"Run 'pnpm update {pkg}' to upgrade to {self.FIXED_VERSION}",
                        line=None,
                        rule_id="mcp-remote-rce-pnpm",
                        cwe_id=78,
                        cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                    ))

        return issues

    def _scan_claude_config(self, file_path: Path) -> List[ScannerIssue]:
        """Scan Claude Desktop config for mcp-remote usage"""
        issues = []

        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return issues

        # Check mcpServers section for mcp-remote usage
        mcp_servers = data.get('mcpServers', {})

        for server_name, server_config in mcp_servers.items():
            command = server_config.get('command', '')
            args = server_config.get('args', [])

            # Check if using npx mcp-remote or direct mcp-remote
            all_args = ' '.join(str(a) for a in args) if isinstance(args, list) else str(args)
            full_command = f"{command} {all_args}"

            if 'mcp-remote' in full_command:
                # Check for insecure URL schemes
                if 'http://' in full_command:
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message=f"MCP server '{server_name}' uses mcp-remote with HTTP (insecure). "
                                f"Use HTTPS for remote MCP connections. "
                                f"Also ensure mcp-remote >= {self.FIXED_VERSION} for CVE-2025-6514 fix.",
                        line=None,
                        rule_id="mcp-remote-insecure-transport",
                        cwe_id=319,
                        cwe_link="https://cwe.mitre.org/data/definitions/319.html"
                    ))
                else:
                    # General warning about mcp-remote usage
                    issues.append(ScannerIssue(
                        severity=Severity.MEDIUM,
                        message=f"MCP server '{server_name}' uses mcp-remote. "
                                f"Ensure mcp-remote >= {self.FIXED_VERSION} to avoid CVE-2025-6514 RCE. "
                                f"Only connect to trusted MCP servers.",
                        line=None,
                        rule_id="mcp-remote-usage",
                        cwe_id=78,
                        cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                    ))

        return issues

    def _scan_source_file(self, file_path: Path) -> List[ScannerIssue]:
        """Scan TypeScript/JavaScript source for vulnerable patterns"""
        issues = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        # Patterns that indicate vulnerable mcp-remote usage or similar vulnerabilities
        vulnerable_patterns = [
            # Direct open() with authorization URL (the attack vector)
            (r'open\s*\(\s*[^)]*authorization_endpoint',
             'Vulnerable pattern: open() called with authorization_endpoint URL (CVE-2025-6514 attack vector)'),

            # Using open npm package with dynamic URLs
            (r'import\s+.*open.*from\s+["\']open["\'].*\n.*open\s*\(\s*[^)]*\+',
             'Potential CVE-2025-6514: open() with dynamic URL concatenation'),

            # authorization_endpoint from untrusted source
            (r'authorization_endpoint\s*=\s*[^;]*metadata',
             'Potential CVE-2025-6514: authorization_endpoint from metadata (validate before use)'),

            # PowerShell subexpression in URLs (Windows RCE)
            (r'\$\([^)]*\)',
             'PowerShell subexpression detected - potential command injection on Windows'),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, description in vulnerable_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message=description,
                        line=i,
                        rule_id="mcp-remote-rce-pattern",
                        cwe_id=78,
                        cwe_link="https://cwe.mitre.org/data/definitions/78.html"
                    ))
                    break  # One issue per line

        return issues

    def _extract_version(self, version_spec: str) -> Optional[str]:
        """Extract concrete version from npm version specifier"""
        if not version_spec:
            return None

        # Remove common prefixes
        version = version_spec.strip()
        for prefix in ['^', '~', '>=', '>', '<=', '<', '=', 'v']:
            if version.startswith(prefix):
                version = version[len(prefix):]

        # Handle ranges - take the first version
        if ' ' in version:
            version = version.split()[0]

        # Validate it looks like a version
        if re.match(r'^\d+\.\d+\.\d+', version):
            return version

        return None

    def _is_vulnerable(self, version: str) -> bool:
        """Check if version is in vulnerable range (0.0.5 to 0.1.15)"""
        if not version:
            return False

        try:
            parsed = self._parse_version(version)
            return self.VULNERABLE_MIN <= parsed <= self.VULNERABLE_MAX
        except (ValueError, TypeError):
            return False

    def _parse_version(self, version: str) -> Tuple[int, int, int]:
        """Parse version string into tuple for comparison"""
        # Handle prerelease versions: 0.1.16-beta.1
        if '-' in version:
            version = version.split('-')[0]

        parts = version.split('.')
        if len(parts) < 3:
            parts.extend(['0'] * (3 - len(parts)))

        return (int(parts[0]), int(parts[1]), int(parts[2]))

    def get_install_instructions(self) -> str:
        return "MCP-Remote RCE scanning is built-in (no additional tools required)"
