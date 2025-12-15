#!/usr/bin/env python3
"""
MEDUSA Docker MCP Security Scanner
Scans Dockerfiles and docker-compose files for container security issues
with special focus on AI/ML and MCP server deployments

Based on:
- OWASP Docker Security Cheat Sheet
- CIS Docker Benchmarks
- AI/ML container security best practices
- MCP server container security research
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class DockerMCPScanner(BaseScanner):
    """
    Docker MCP Security Scanner

    Scans for:
    - DKR001: Running as root user
    - DKR002: Privileged container mode
    - DKR003: Exposed sensitive ports
    - DKR004: Hardcoded secrets in environment
    - DKR005: Latest tag usage (unpinned images)
    - DKR006: Excessive capabilities
    - DKR007: Volume mounts to sensitive directories
    - DKR008: Host network mode
    - DKR009: Missing health checks for MCP servers
    - DKR010: Writable root filesystem
    - DKR011: Missing resource limits (DoS risk)
    - DKR012: AI model volume exposure
    - DKR013: GPU passthrough without security
    - DKR014: MCP socket exposure
    - DKR015: Insecure base images
    """

    # DKR001: Root user patterns
    ROOT_USER_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'^USER\s+root\s*$', 'Container runs as root user', Severity.HIGH),
        (r'user:\s*["\']?root["\']?', 'Service configured to run as root', Severity.HIGH),
        (r'user:\s*["\']?0["\']?', 'Service runs as UID 0 (root)', Severity.HIGH),
    ]

    # DKR002: Privileged mode patterns
    PRIVILEGED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'privileged:\s*true', 'Container runs in privileged mode', Severity.CRITICAL),
        (r'--privileged', 'Privileged flag in run command', Severity.CRITICAL),
    ]

    # DKR003: Sensitive port patterns
    SENSITIVE_PORTS: List[Tuple[str, str, Severity]] = [
        (r'(22|2222):', 'SSH port exposed', Severity.MEDIUM),
        (r'(3306|5432|27017|6379):', 'Database port exposed', Severity.HIGH),
        (r'(2375|2376):', 'Docker daemon port exposed', Severity.CRITICAL),
        (r'(10250|10255|10256):', 'Kubernetes kubelet port exposed', Severity.CRITICAL),
        (r'(6443|8443):', 'Kubernetes API port exposed', Severity.HIGH),
        (r'(2379|2380):', 'etcd port exposed', Severity.CRITICAL),
        (r'9090:', 'Prometheus port exposed (may leak metrics)', Severity.MEDIUM),
    ]

    # DKR004: Hardcoded secrets patterns (in ENV/environment)
    SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
        # API Keys
        (r'OPENAI_API_KEY\s*[=:]\s*["\']?sk-[a-zA-Z0-9]{48,}',
         'Hardcoded OpenAI API key', Severity.CRITICAL),
        (r'ANTHROPIC_API_KEY\s*[=:]\s*["\']?sk-ant-[a-zA-Z0-9-]{80,}',
         'Hardcoded Anthropic API key', Severity.CRITICAL),
        (r'(API_KEY|APIKEY)\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}',
         'Hardcoded API key', Severity.HIGH),

        # AWS
        (r'AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?AKIA[0-9A-Z]{16}',
         'Hardcoded AWS Access Key', Severity.CRITICAL),
        (r'AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?[a-zA-Z0-9/+=]{40}',
         'Hardcoded AWS Secret Key', Severity.CRITICAL),

        # Database passwords
        (r'(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_PASSWORD)\s*[=:]\s*["\']?[^"\'\s]{8,}',
         'Hardcoded database password', Severity.CRITICAL),

        # Generic secrets
        (r'(PASSWORD|SECRET|TOKEN)\s*[=:]\s*["\']?[^"\'\s$]{8,}',
         'Hardcoded credential', Severity.HIGH),

        # Private keys
        (r'PRIVATE_KEY\s*[=:]', 'Private key in environment', Severity.CRITICAL),
    ]

    # DKR005: Unpinned image patterns
    UNPINNED_IMAGE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'^FROM\s+\S+:latest\s*$', 'Using :latest tag (unpinned)', Severity.MEDIUM),
        (r'^FROM\s+[^\s:@]+\s*$', 'Image without version tag', Severity.MEDIUM),
        (r'image:\s*["\']?\S+:latest["\']?', 'Using :latest tag in compose', Severity.MEDIUM),
        (r'image:\s*["\']?[^\s:@"\']+["\']?\s*$', 'Compose image without tag', Severity.LOW),
    ]

    # DKR006: Excessive capabilities
    CAPABILITY_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'cap_add:\s*\n\s*-\s*SYS_ADMIN', 'SYS_ADMIN capability (near root)', Severity.CRITICAL),
        (r'cap_add:\s*\n\s*-\s*ALL', 'All capabilities granted', Severity.CRITICAL),
        (r'cap_add:\s*\n\s*-\s*NET_ADMIN', 'NET_ADMIN capability', Severity.HIGH),
        (r'cap_add:\s*\n\s*-\s*SYS_PTRACE', 'SYS_PTRACE capability (debug)', Severity.HIGH),
        (r'--cap-add\s*=?\s*SYS_ADMIN', 'SYS_ADMIN capability added', Severity.CRITICAL),
        (r'--cap-add\s*=?\s*ALL', 'All capabilities added', Severity.CRITICAL),
    ]

    # DKR007: Sensitive volume mounts
    SENSITIVE_VOLUME_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'/var/run/docker\.sock', 'Docker socket mounted (container escape)', Severity.CRITICAL),
        (r'/etc/passwd', 'Password file mounted', Severity.CRITICAL),
        (r'/etc/shadow', 'Shadow file mounted', Severity.CRITICAL),
        (r'~?/\.ssh', 'SSH directory mounted', Severity.CRITICAL),
        (r'~?/\.aws', 'AWS credentials mounted', Severity.CRITICAL),
        (r'~?/\.gnupg', 'GPG keys mounted', Severity.CRITICAL),
        (r'~?/\.config', 'User config directory mounted', Severity.HIGH),
        (r'/root', 'Root home directory mounted', Severity.HIGH),
        (r'/proc', '/proc filesystem mounted', Severity.HIGH),
        (r'/sys', '/sys filesystem mounted', Severity.HIGH),
    ]

    # DKR008: Network mode patterns
    NETWORK_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'network_mode:\s*["\']?host["\']?', 'Host network mode (no isolation)', Severity.HIGH),
        (r'--network\s*=?\s*host', 'Host network mode', Severity.HIGH),
        (r'--pid\s*=?\s*host', 'Host PID namespace', Severity.HIGH),
        (r'pid:\s*["\']?host["\']?', 'Host PID namespace', Severity.HIGH),
    ]

    # DKR011: Missing resource limits
    RESOURCE_LIMIT_KEYWORDS = [
        'mem_limit', 'memory', 'cpus', 'cpu_quota',
        'deploy', 'resources', 'limits',
    ]

    # DKR012: AI Model volume exposure patterns
    AI_MODEL_VOLUME_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'volumes:.*(?:models?|weights?|checkpoints?|\.safetensors|\.gguf|\.bin).*:rw',
         'AI model directory mounted read-write', Severity.HIGH),
        (r'/models?:/.*:rw', 'Model volume writable from container', Severity.MEDIUM),
        (r'huggingface.*cache.*:rw', 'HuggingFace cache writable', Severity.MEDIUM),
    ]

    # DKR013: GPU passthrough patterns
    GPU_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'--gpus\s+all', 'All GPUs exposed to container', Severity.MEDIUM),
        (r'runtime:\s*nvidia', 'NVIDIA runtime (GPU access)', Severity.LOW),
        (r'NVIDIA_VISIBLE_DEVICES\s*[=:]\s*all', 'All NVIDIA devices visible', Severity.MEDIUM),
    ]

    # DKR014: MCP socket/port patterns
    MCP_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(/tmp/mcp|mcp\.sock)', 'MCP socket exposed', Severity.HIGH),
        (r'MCP_.*PORT\s*[=:]', 'MCP port configuration', Severity.LOW),
        (r'(3000|8080|9000):.*mcp', 'MCP service port exposed', Severity.MEDIUM),
    ]

    # DKR015: Insecure base images
    INSECURE_BASE_IMAGES: List[Tuple[str, str, Severity]] = [
        (r'^FROM\s+ubuntu\s*$', 'Using unversioned Ubuntu base', Severity.MEDIUM),
        (r'^FROM\s+debian\s*$', 'Using unversioned Debian base', Severity.MEDIUM),
        (r'^FROM\s+python\s*$', 'Using unversioned Python base', Severity.MEDIUM),
        (r'^FROM\s+node\s*$', 'Using unversioned Node base', Severity.MEDIUM),
        (r'^FROM\s+alpine\s*$', 'Using unversioned Alpine base', Severity.LOW),
    ]

    # Good security patterns (reduce severity)
    SECURITY_PATTERNS = [
        r'USER\s+\d+',  # Non-root user by UID
        r'USER\s+(?!root)[a-z]+',  # Named non-root user
        r'--read-only',  # Read-only root filesystem
        r'read_only:\s*true',
        r'security_opt:',
        r'no-new-privileges',
        r'cap_drop:',
        r'healthcheck:',
        r'HEALTHCHECK',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return []  # We use patterns instead

    def get_file_patterns(self) -> List[str]:
        return [
            'Dockerfile',
            'Dockerfile.*',
            '*.dockerfile',
            'docker-compose.yml',
            'docker-compose.yaml',
            'docker-compose*.yml',
            'docker-compose*.yaml',
            'compose.yml',
            'compose.yaml',
        ]

    def can_scan(self, file_path: Path) -> bool:
        """Check if this is a Docker-related file"""
        name = file_path.name.lower()

        # Dockerfiles
        if name == 'dockerfile' or name.startswith('dockerfile.'):
            return True
        if name.endswith('.dockerfile'):
            return True

        # Docker Compose files
        if 'docker-compose' in name or 'compose' in name:
            if name.endswith(('.yml', '.yaml')):
                return True

        return False

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan Docker file for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            lines = content.split('\n')
            is_dockerfile = 'dockerfile' in file_path.name.lower()
            is_compose = 'compose' in file_path.name.lower() or file_path.suffix in ['.yml', '.yaml']

            # Check for good security patterns
            has_security = any(
                re.search(p, content, re.IGNORECASE | re.MULTILINE)
                for p in self.SECURITY_PATTERNS
            )

            # DKR001: Root user check
            issues.extend(self._check_patterns(
                content, lines, self.ROOT_USER_PATTERNS, "DKR001"
            ))

            # DKR002: Privileged mode
            issues.extend(self._check_patterns(
                content, lines, self.PRIVILEGED_PATTERNS, "DKR002"
            ))

            # DKR003: Sensitive ports
            issues.extend(self._check_patterns(
                content, lines, self.SENSITIVE_PORTS, "DKR003"
            ))

            # DKR004: Hardcoded secrets
            issues.extend(self._check_patterns(
                content, lines, self.SECRET_PATTERNS, "DKR004"
            ))

            # DKR005: Unpinned images
            issues.extend(self._check_patterns(
                content, lines, self.UNPINNED_IMAGE_PATTERNS, "DKR005"
            ))

            # DKR006: Excessive capabilities
            issues.extend(self._check_patterns(
                content, lines, self.CAPABILITY_PATTERNS, "DKR006"
            ))

            # DKR007: Sensitive volumes
            issues.extend(self._check_patterns(
                content, lines, self.SENSITIVE_VOLUME_PATTERNS, "DKR007"
            ))

            # DKR008: Network mode
            issues.extend(self._check_patterns(
                content, lines, self.NETWORK_PATTERNS, "DKR008"
            ))

            # DKR009: Missing healthcheck for MCP services
            if self._looks_like_mcp_service(content):
                if not re.search(r'healthcheck|HEALTHCHECK', content, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id="DKR009",
                        severity=Severity.MEDIUM,
                        message="MCP service without health check - service failures may go undetected",
                        line=1,
                        column=1,
                    ))

            # DKR010: Writable root filesystem (compose files)
            if is_compose and not re.search(r'read_only:\s*true', content):
                # Only flag if there are services defined
                if 'services:' in content:
                    issues.append(ScannerIssue(
                        rule_id="DKR010",
                        severity=Severity.LOW,
                        message="Container root filesystem is writable - consider read_only: true",
                        line=1,
                        column=1,
                    ))

            # DKR011: Missing resource limits
            if is_compose and 'services:' in content:
                if not any(kw in content.lower() for kw in self.RESOURCE_LIMIT_KEYWORDS):
                    issues.append(ScannerIssue(
                        rule_id="DKR011",
                        severity=Severity.MEDIUM,
                        message="No resource limits defined - vulnerable to DoS via resource exhaustion",
                        line=1,
                        column=1,
                    ))

            # DKR012: AI Model volume exposure
            issues.extend(self._check_patterns(
                content, lines, self.AI_MODEL_VOLUME_PATTERNS, "DKR012"
            ))

            # DKR013: GPU passthrough
            issues.extend(self._check_patterns(
                content, lines, self.GPU_PATTERNS, "DKR013"
            ))

            # DKR014: MCP socket/port exposure
            issues.extend(self._check_patterns(
                content, lines, self.MCP_PATTERNS, "DKR014"
            ))

            # DKR015: Insecure base images
            if is_dockerfile:
                issues.extend(self._check_patterns(
                    content, lines, self.INSECURE_BASE_IMAGES, "DKR015"
                ))

            # Reduce severity if security patterns are present
            if has_security:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.MEDIUM:
                        issue.severity = Severity.LOW

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
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        """Check content against a list of patterns"""
        issues = []

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        line=i,
                        column=1,
                    ))
                    break  # One issue per pattern

        return issues

    def _looks_like_mcp_service(self, content: str) -> bool:
        """Check if content looks like an MCP service"""
        mcp_indicators = [
            'mcp', 'model-context', 'claude', 'anthropic',
            'openai', 'llm', 'langchain', 'autogen',
        ]
        content_lower = content.lower()
        return any(ind in content_lower for ind in mcp_indicators)
