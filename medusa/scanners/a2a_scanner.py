#!/usr/bin/env python3
"""
MEDUSA A2A (Agent-to-Agent) Security Scanner
Scans Agent Cards and A2A configurations for security issues

Based on "Agentic Design Patterns" Chapter 15 - Inter-Agent Communication

Detects vulnerabilities in:
- Agent Card (agent.json) misconfigurations
- Missing authentication requirements
- Insecure transport configurations
- Exposed sensitive capabilities
- Missing mTLS requirements
- Credential handling issues
"""

import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class A2AScanner(RuleBasedScanner):
    """
    A2A (Agent-to-Agent) Security Scanner

    Scans for:
    - A2A001: Missing authentication in Agent Card
    - A2A002: HTTP endpoint without TLS requirement
    - A2A003: Overly permissive capabilities
    - A2A004: Missing mTLS configuration
    - A2A005: Exposed admin/destructive capabilities
    - A2A006: Credential exposure in Agent Card
    - A2A007: Missing version pinning
    - A2A008: Wildcard permissions
    - A2A009: Missing rate limiting configuration
    - A2A010: Insecure SSE configuration
    - A2A011: Missing input validation schema
    - A2A012: Agent Card at predictable location without protection
    - A2A013: Missing audit logging requirement
    - A2A014: Cross-origin capabilities without restrictions
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['A2A-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['a2a', 'agent_to_agent']

    # Patterns for sensitive capability names
    SENSITIVE_CAPABILITIES = [
        "admin", "sudo", "root", "execute", "shell", "system",
        "delete", "remove", "drop", "truncate", "destroy",
        "write", "modify", "update", "create",
        "upload", "download", "transfer", "exfiltrate",
        "credentials", "secrets", "keys", "tokens", "passwords",
        "database", "sql", "query",
        "file", "filesystem", "disk",
        "network", "http", "request", "fetch",
        "eval", "exec", "run", "spawn", "process",
    ]

    # Patterns indicating credential exposure
    CREDENTIAL_PATTERNS = [
        (r'"(api[_-]?key|apikey)":\s*"[^"]{10,}"', 'Hardcoded API key in Agent Card'),
        (r'"(secret|password|token)":\s*"[^"]+"', 'Hardcoded secret in Agent Card'),
        (r'"authorization":\s*"(Bearer|Basic)\s+[^"]+"', 'Hardcoded authorization header'),
        (r'(sk-[a-zA-Z0-9]{20,})', 'OpenAI API key exposed'),
        (r'(ghp_[a-zA-Z0-9]{36,})', 'GitHub PAT exposed'),
        (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key exposed'),
        (r'"private[_-]?key":\s*"[^"]+"', 'Private key in Agent Card'),
    ]

    # Required security fields in Agent Card
    REQUIRED_SECURITY_FIELDS = [
        "authentication",
        "version",
    ]

    # Recommended security fields
    RECOMMENDED_SECURITY_FIELDS = [
        "rateLimit",
        "rateLimiting",
        "inputSchema",
        "validation",
        "auditLog",
        "logging",
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".json"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def _is_agent_card(self, content: str, file_path: Path) -> bool:
        """Check if file is likely an Agent Card"""
        # Check filename patterns
        name_lower = file_path.name.lower()
        if name_lower in ["agent.json", "agent-card.json", "agentcard.json"]:
            return True

        # Check path patterns
        path_str = str(file_path).lower()
        if "/.well-known/agent.json" in path_str:
            return True
        if "/agents/" in path_str and name_lower.endswith(".json"):
            return True

        # Check content patterns
        try:
            data = json.loads(content)
            # Agent Cards typically have these fields
            agent_card_indicators = [
                "capabilities" in data,
                "endpoint" in data or "endpoints" in data,
                "skills" in data,
                "name" in data and ("version" in data or "url" in data),
                "agentId" in data or "agent_id" in data,
            ]
            return sum(agent_card_indicators) >= 2
        except json.JSONDecodeError:
            return False

    def _is_a2a_config(self, content: str, file_path: Path) -> bool:
        """Check if file is an A2A configuration"""
        try:
            data = json.loads(content)
            # A2A config indicators
            indicators = [
                "agents" in data,
                "a2a" in str(file_path).lower(),
                "remoteAgents" in data,
                "agentRegistry" in data,
                "trustedAgents" in data,
            ]
            return any(indicators)
        except json.JSONDecodeError:
            return False

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan Agent Card or A2A config for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if this is an Agent Card or A2A config
            is_agent_card = self._is_agent_card(content, file_path)
            is_a2a_config = self._is_a2a_config(content, file_path)

            if not is_agent_card and not is_a2a_config:
                # Still scan with YAML rules
                lines = content.split('\n')
                yaml_issues = self._scan_with_rules(lines, file_path)
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=yaml_issues,
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Parse JSON
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                issues.append(ScannerIssue(
                    rule_id="A2A000",
                    severity=Severity.HIGH,
                    message=f"Invalid JSON in Agent Card: {e}",
                    file_path=file_path,
                    line=1,
                    column=1,
                ))
                # Return immediately on JSON parse error
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=issues,
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Run all checks
            if is_agent_card:
                issues.extend(self._check_authentication(data, file_path, content))
                issues.extend(self._check_transport_security(data, file_path, content))
                issues.extend(self._check_capabilities(data, file_path, content))
                issues.extend(self._check_credentials(content, file_path))
                issues.extend(self._check_required_fields(data, file_path))
                issues.extend(self._check_permissions(data, file_path, content))
                issues.extend(self._check_validation(data, file_path))

            if is_a2a_config:
                issues.extend(self._check_a2a_config(data, file_path, content))

            # Scan with YAML rules
            lines = content.split('\n')
            issues.extend(self._scan_with_rules(lines, file_path))

            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _check_authentication(
        self, data: Dict[str, Any], file_path: Path, content: str
    ) -> List[ScannerIssue]:
        """Check authentication requirements"""
        issues = []

        auth = data.get("authentication") or data.get("auth") or data.get("security", {}).get("authentication")

        if not auth:
            issues.append(ScannerIssue(
                rule_id="A2A001",
                severity=Severity.CRITICAL,
                message="Agent Card missing authentication requirements - agents can connect without auth",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Add 'authentication' field specifying required auth method (OAuth2, mTLS, API key)",
            ))
        else:
            # Check for weak auth
            auth_str = json.dumps(auth).lower() if isinstance(auth, dict) else str(auth).lower()

            if "none" in auth_str or auth_str == "false":
                issues.append(ScannerIssue(
                    rule_id="A2A001",
                    severity=Severity.CRITICAL,
                    message="Agent Card explicitly disables authentication",
                    file_path=file_path,
                    line=self._find_line(content, "authentication"),
                    column=1,
                ))

            # Check for mTLS
            if "mtls" not in auth_str and "mutual" not in auth_str:
                issues.append(ScannerIssue(
                    rule_id="A2A004",
                    severity=Severity.MEDIUM,
                    message="Agent Card does not require mutual TLS (mTLS) for inter-agent auth",
                    file_path=file_path,
                    line=self._find_line(content, "authentication"),
                    column=1,
                    suggestion="Consider requiring mTLS for secure agent-to-agent communication",
                ))

        return issues

    def _check_transport_security(
        self, data: Dict[str, Any], file_path: Path, content: str
    ) -> List[ScannerIssue]:
        """Check transport layer security"""
        issues = []

        # Check endpoints
        endpoints = []
        if "endpoint" in data:
            endpoints.append(data["endpoint"])
        if "endpoints" in data:
            endpoints.extend(data["endpoints"] if isinstance(data["endpoints"], list) else [data["endpoints"]])
        if "url" in data:
            endpoints.append(data["url"])

        for endpoint in endpoints:
            if isinstance(endpoint, str):
                if endpoint.startswith("http://"):
                    issues.append(ScannerIssue(
                        rule_id="A2A002",
                        severity=Severity.CRITICAL,
                        message=f"Agent endpoint uses HTTP without TLS: {endpoint}",
                        file_path=file_path,
                        line=self._find_line(content, endpoint),
                        column=1,
                        suggestion="Use HTTPS for all agent endpoints",
                    ))

        # Check SSE configuration
        sse_config = data.get("sse") or data.get("streaming") or data.get("serverSentEvents")
        if sse_config:
            sse_str = json.dumps(sse_config).lower() if isinstance(sse_config, dict) else str(sse_config).lower()
            if "http://" in sse_str:
                issues.append(ScannerIssue(
                    rule_id="A2A010",
                    severity=Severity.HIGH,
                    message="SSE (Server-Sent Events) configured without TLS",
                    file_path=file_path,
                    line=self._find_line(content, "sse"),
                    column=1,
                ))

        return issues

    def _check_capabilities(
        self, data: Dict[str, Any], file_path: Path, content: str
    ) -> List[ScannerIssue]:
        """Check for overly permissive or dangerous capabilities"""
        issues = []

        capabilities = data.get("capabilities") or data.get("skills") or data.get("tools") or []

        if isinstance(capabilities, dict):
            capabilities = list(capabilities.keys()) + list(capabilities.values())

        cap_str = json.dumps(capabilities).lower()

        for sensitive in self.SENSITIVE_CAPABILITIES:
            if sensitive in cap_str:
                # Check if it's an admin/destructive capability
                if sensitive in ["admin", "sudo", "root", "delete", "destroy", "drop", "truncate"]:
                    issues.append(ScannerIssue(
                        rule_id="A2A005",
                        severity=Severity.HIGH,
                        message=f"Agent exposes sensitive capability: '{sensitive}'",
                        file_path=file_path,
                        line=self._find_line(content, sensitive),
                        column=1,
                        suggestion="Consider if this capability should be exposed to other agents",
                    ))

        # Check for wildcard/all permissions
        if "*" in cap_str or '"all"' in cap_str.lower():
            issues.append(ScannerIssue(
                rule_id="A2A008",
                severity=Severity.CRITICAL,
                message="Agent Card uses wildcard (*) or 'all' permissions",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Use explicit capability lists instead of wildcards",
            ))

        return issues

    def _check_credentials(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """Check for exposed credentials"""
        issues = []

        for pattern, message in self.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line = content[:match.start()].count('\n') + 1
                issues.append(ScannerIssue(
                    rule_id="A2A006",
                    severity=Severity.CRITICAL,
                    message=message,
                    file_path=file_path,
                    line=line,
                    column=1,
                    suggestion="Move credentials to environment variables or secure vault",
                ))

        return issues

    def _check_required_fields(
        self, data: Dict[str, Any], file_path: Path
    ) -> List[ScannerIssue]:
        """Check for required security fields"""
        issues = []

        # Flatten data for checking
        data_str = json.dumps(data).lower()

        for field in self.REQUIRED_SECURITY_FIELDS:
            if field.lower() not in data_str:
                issues.append(ScannerIssue(
                    rule_id="A2A007",
                    severity=Severity.MEDIUM,
                    message=f"Agent Card missing recommended field: '{field}'",
                    file_path=file_path,
                    line=1,
                    column=1,
                ))

        # Check recommended fields
        missing_recommended = []
        for field in self.RECOMMENDED_SECURITY_FIELDS:
            if field.lower() not in data_str:
                missing_recommended.append(field)

        if missing_recommended:
            issues.append(ScannerIssue(
                rule_id="A2A009",
                severity=Severity.LOW,
                message=f"Agent Card missing recommended security fields: {', '.join(missing_recommended)}",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Consider adding rate limiting, input validation, and audit logging",
            ))

        return issues

    def _check_permissions(
        self, data: Dict[str, Any], file_path: Path, content: str
    ) -> List[ScannerIssue]:
        """Check permission configurations"""
        issues = []

        # Check for cross-origin without restrictions
        cors = data.get("cors") or data.get("crossOrigin") or data.get("allowedOrigins")
        if cors:
            cors_str = json.dumps(cors) if isinstance(cors, (dict, list)) else str(cors)
            if "*" in cors_str or "all" in cors_str.lower():
                issues.append(ScannerIssue(
                    rule_id="A2A014",
                    severity=Severity.HIGH,
                    message="Agent allows cross-origin requests from any origin (*)",
                    file_path=file_path,
                    line=self._find_line(content, "cors"),
                    column=1,
                    suggestion="Restrict allowed origins to trusted domains",
                ))

        return issues

    def _check_validation(
        self, data: Dict[str, Any], file_path: Path
    ) -> List[ScannerIssue]:
        """Check input validation configuration"""
        issues = []

        data_str = json.dumps(data).lower()

        # Check for input schema/validation
        if "schema" not in data_str and "validation" not in data_str and "validate" not in data_str:
            issues.append(ScannerIssue(
                rule_id="A2A011",
                severity=Severity.MEDIUM,
                message="Agent Card does not define input validation schema",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Add input schema to validate incoming requests",
            ))

        # Check for audit logging
        if "audit" not in data_str and "logging" not in data_str:
            issues.append(ScannerIssue(
                rule_id="A2A013",
                severity=Severity.LOW,
                message="Agent Card does not specify audit logging requirements",
                file_path=file_path,
                line=1,
                column=1,
                suggestion="Add audit logging configuration for security monitoring",
            ))

        return issues

    def _check_a2a_config(
        self, data: Dict[str, Any], file_path: Path, content: str
    ) -> List[ScannerIssue]:
        """Check A2A configuration files"""
        issues = []

        # Check trusted agents
        trusted = data.get("trustedAgents") or data.get("trusted") or []
        if isinstance(trusted, list):
            if "*" in trusted or "all" in [str(t).lower() for t in trusted]:
                issues.append(ScannerIssue(
                    rule_id="A2A008",
                    severity=Severity.CRITICAL,
                    message="A2A config trusts all agents (wildcard)",
                    file_path=file_path,
                    line=self._find_line(content, "trusted"),
                    column=1,
                    suggestion="Explicitly list trusted agent IDs",
                ))

        # Check for credential exposure in config
        issues.extend(self._check_credentials(content, file_path))

        return issues

    def _find_line(self, content: str, search: str) -> int:
        """Find line number of search string"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if search.lower() in line.lower():
                return i
        return 1
