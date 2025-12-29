#!/usr/bin/env python3
"""
MEDUSA Agent Memory Security Scanner
Scans AI agent memory configurations for security issues

Detects vulnerabilities in:
- Memory configuration files (memory.json, state.json)
- Checkpoint/snapshot files
- Session storage configurations
- Vector store configurations
- Conversation history storage

These files can be vectors for:
- Memory poisoning attacks
- State manipulation
- Checkpoint tampering
- Sensitive data exposure
- Cross-session data leakage
"""

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class AgentMemoryScanner(RuleBasedScanner):
    """
    Agent Memory Security Scanner

    Scans for:
    - AIM001: Unencrypted memory storage
    - AIM002: Memory accessible to untrusted code
    - AIM003: No memory sanitization
    - AIM004: Unbounded memory growth
    - AIM005: Missing memory expiration
    - AIM006: Sensitive data in memory
    - AIM007: Insecure checkpoint storage
    - AIM008: Cross-session data exposure
    - AIM009: Memory injection patterns
    - AIM010: Insecure vector store config
    - AIM011: Unvalidated memory write (poisoning risk)
    - AIM012: Persistent memory without encryption
    - AIM013: Vector store poisoning risk
    - AIM014: Memory checksum missing
    - AIM015: Cross-session memory contamination
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['AGENT-MEM-', 'AGENT-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['agent_memory', 'memory_poisoning', 'session_bleed']

    # Memory config file patterns
    MEMORY_CONFIG_FILES = [
        'memory.json', 'memory.yaml', 'memory.yml',
        'state.json', 'state.yaml', 'state.yml',
        'session.json', 'sessions.json',
        'checkpoint.json', 'checkpoints.json',
        'history.json', 'conversation.json',
        'vectorstore.json', 'vector_store.json',
        'embeddings.json', 'cache.json',
        'persistence.json', 'storage.json',
    ]

    # Directories that commonly contain memory configs
    MEMORY_CONFIG_DIRS = [
        '.memory', '.state', '.cache',
        '.checkpoints', '.sessions',
        'memory', 'state', 'checkpoints',
        'data', 'persistence', '.data',
    ]

    # AIM001: Patterns indicating unencrypted storage
    UNENCRYPTED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(encryption|encrypt)\s*[=:]\s*["\']?(false|none|off|disabled|0)["\']?',
         'Memory storage encryption disabled', Severity.CRITICAL),
        (r'(?i)(unencrypted|plaintext)\s*[=:]\s*["\']?(true|yes|on|enabled|1)["\']?',
         'Explicitly unencrypted storage', Severity.CRITICAL),
        (r'(?i)(ssl|tls)\s*[=:]\s*["\']?(false|none|off|disabled|0)["\']?',
         'TLS disabled for memory storage', Severity.HIGH),
        (r'(?i)file://[^"\']*\.(json|txt|yaml|yml)',
         'Plain file storage without encryption hint', Severity.MEDIUM),
    ]

    # AIM002: Patterns indicating accessible to untrusted code
    UNTRUSTED_ACCESS_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(public|world|everyone)\s*[=:]\s*["\']?(true|yes|read|write|rw)["\']?',
         'Memory accessible to all', Severity.CRITICAL),
        (r'(?i)(permission|access)\s*[=:]\s*["\']?(777|666|0777|0666)["\']?',
         'Overly permissive file permissions', Severity.CRITICAL),
        (r'(?i)(shared|global)\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Shared/global memory access enabled', Severity.HIGH),
        (r'(?i)(auth|authentication)\s*[=:]\s*["\']?(false|none|disabled)["\']?',
         'Memory access without authentication', Severity.CRITICAL),
    ]

    # AIM003: Missing sanitization patterns
    NO_SANITIZATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(sanitize|sanitization)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Memory sanitization disabled', Severity.HIGH),
        (r'(?i)(validate|validation)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Memory validation disabled', Severity.HIGH),
        (r'(?i)(raw|unsafe)\s*[=:]\s*["\']?(true|yes|on|enabled)["\']?',
         'Raw/unsafe mode enabled', Severity.HIGH),
        (r'(?i)(filter|filtering)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Content filtering disabled', Severity.MEDIUM),
    ]

    # AIM004: Unbounded growth patterns
    UNBOUNDED_GROWTH_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(max_size|maxsize|limit)\s*[=:]\s*["\']?(0|null|none|unlimited|-1)["\']?',
         'No memory size limit', Severity.MEDIUM),
        (r'(?i)(max_items|maxitems|max_entries)\s*[=:]\s*["\']?(0|null|none|unlimited|-1)["\']?',
         'No item count limit', Severity.MEDIUM),
        (r'(?i)(truncate|prune)\s*[=:]\s*["\']?(false|never|off|disabled)["\']?',
         'Memory pruning disabled', Severity.MEDIUM),
    ]

    # AIM005: Missing expiration patterns
    NO_EXPIRATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(ttl|time_to_live|expir)\s*[=:]\s*["\']?(0|null|none|never|-1)["\']?',
         'Memory never expires', Severity.MEDIUM),
        (r'(?i)(persist|permanent)\s*[=:]\s*["\']?(true|forever|always)["\']?',
         'Permanent memory storage', Severity.MEDIUM),
        (r'(?i)(cleanup|gc|garbage)\s*[=:]\s*["\']?(false|off|disabled|never)["\']?',
         'Memory cleanup disabled', Severity.MEDIUM),
    ]

    # AIM006: Sensitive data in memory patterns
    SENSITIVE_DATA_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(password|passwd|pwd)["\']?\s*[=:]',
         'Password found in memory config', Severity.CRITICAL),
        (r'(?i)["\']?(api[_-]?key|apikey)["\']?\s*[=:]',
         'API key found in memory config', Severity.CRITICAL),
        (r'(?i)["\']?(secret|token|credential)["\']?\s*[=:]',
         'Secret/token found in memory config', Severity.CRITICAL),
        (r'(?i)["\']?(private[_-]?key)["\']?\s*[=:]',
         'Private key reference in memory config', Severity.CRITICAL),
        # Actual secret patterns
        (r'sk-[a-zA-Z0-9]{48,}', 'OpenAI API key in memory', Severity.CRITICAL),
        (r'sk-ant-[a-zA-Z0-9-]{80,}', 'Anthropic API key in memory', Severity.CRITICAL),
        (r'ghp_[0-9a-zA-Z]{36}', 'GitHub token in memory', Severity.CRITICAL),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key in memory', Severity.CRITICAL),
    ]

    # AIM007: Insecure checkpoint patterns
    INSECURE_CHECKPOINT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(checkpoint|snapshot)\s*[=:]\s*["\']?(/tmp|/var/tmp|%TEMP%)',
         'Checkpoints in temp directory', Severity.HIGH),
        (r'(?i)(backup|checkpoint)\s*[=:]\s*["\']?(http://|ftp://)',
         'Checkpoints over insecure protocol', Severity.CRITICAL),
        (r'(?i)(sign|signature|verify)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Checkpoint signature verification disabled', Severity.HIGH),
        (r'(?i)(integrity|hash|checksum)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Checkpoint integrity check disabled', Severity.HIGH),
    ]

    # AIM008: Cross-session patterns
    CROSS_SESSION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(share_between|shared_memory|cross_session)\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Cross-session memory sharing enabled', Severity.HIGH),
        (r'(?i)(isolate|isolation)\s*[=:]\s*["\']?(false|none|off|disabled)["\']?',
         'Session isolation disabled', Severity.HIGH),
        (r'(?i)(namespace|scope)\s*[=:]\s*["\']?(global|shared|common)["\']?',
         'Global memory namespace', Severity.MEDIUM),
    ]

    # AIM009: Memory injection patterns (in actual content/history)
    INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)ignore\s+(all\s+)?previous\s+instructions?',
         'Prompt injection in memory', Severity.CRITICAL),
        (r'<(hidden|secret|system)[^>]*>',
         'Hidden tag in memory content', Severity.CRITICAL),
        (r'(?i)you\s+are\s+(now|actually|really)',
         'Role manipulation in memory', Severity.HIGH),
        (r'[\u200b\u200c\u200d\u2060\ufeff]{3,}',
         'Zero-width characters in memory', Severity.HIGH),
    ]

    # AIM010: Vector store security patterns
    VECTOR_STORE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)(pinecone|weaviate|milvus|qdrant).*["\']?api[_-]?key["\']?\s*[=:]\s*["\'][^"\']+["\']',
         'Hardcoded vector store API key', Severity.CRITICAL),
        (r'(?i)(embedding|vector)\s*[=:]\s*["\']?http://',
         'Vector service over HTTP', Severity.HIGH),
        (r'(?i)(allow_overwrite|upsert)\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Vector overwrite enabled (poisoning risk)', Severity.MEDIUM),
    ]

    # AIM011: Unvalidated memory write patterns (Memory Poisoning)
    # Persistent exploit injection into agent memory/state
    UNVALIDATED_WRITE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'memory\.store\s*\([^)]*user[_-]?input',
         'Unvalidated user input written to memory', Severity.CRITICAL),
        (r'context\.append\s*\([^)]*external[_-]?data',
         'External data appended to context without validation', Severity.HIGH),
        (r'conversation[_-]?history\.add\s*\((?!.*sanitize)',
         'History added without sanitization', Severity.HIGH),
        (r'memory\.(?:set|put|write)\s*\([^)]*(?:request|input|body)',
         'Request data stored directly in memory', Severity.HIGH),
        (r'state\.update\s*\([^)]*(?:user|external|api)',
         'External data updates agent state', Severity.HIGH),
    ]

    # AIM012: Persistent memory without encryption
    PERSISTENT_UNENCRYPTED_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'persist[_-]?memory\s*\((?!.*encrypt)',
         'Memory persisted without encryption', Severity.HIGH),
        (r'save[_-]?state\s*\((?!.*(?:checksum|hash|encrypt))',
         'State saved without integrity check or encryption', Severity.HIGH),
        (r'(?i)(long[_-]?term|permanent)[_-]?(?:memory|storage)\s*[=:].*(?!.*encrypt)',
         'Long-term memory storage without encryption', Severity.MEDIUM),
        (r'dump[_-]?memory\s*\([^)]*(?:file|disk|path)',
         'Memory dumped to file (may lack encryption)', Severity.MEDIUM),
    ]

    # AIM013: Vector store poisoning patterns
    VECTOR_POISONING_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'index\.add\s*\([^)]*(?:untrusted|user|external)',
         'Untrusted data added to vector index', Severity.CRITICAL),
        (r'vectorstore\.(?:insert|upsert|add)\s*\((?!.*validate)',
         'Vector store insert without validation', Severity.HIGH),
        (r'embedding[_-]?store\.(?:put|add)\s*\([^)]*(?:raw|unfiltered)',
         'Raw data added to embedding store', Severity.HIGH),
        (r'(?i)rag[_-]?(?:index|store)\.(?:update|add)\s*\(',
         'RAG index update (check for validation)', Severity.MEDIUM),
    ]

    # AIM014: Missing memory checksum/integrity patterns
    MISSING_CHECKSUM_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'load[_-]?memory\s*\((?!.*(?:verify|checksum|hash|integrity))',
         'Memory loaded without integrity verification', Severity.HIGH),
        (r'restore[_-]?(?:state|checkpoint)\s*\((?!.*verify)',
         'State restored without verification', Severity.HIGH),
        (r'deserialize[_-]?memory\s*\(',
         'Memory deserialized (verify integrity check exists)', Severity.MEDIUM),
        (r'(?i)pickle\.loads?\s*\(',
         'Pickle deserialization (unsafe - check source)', Severity.CRITICAL),
    ]

    # AIM015: Cross-session memory contamination patterns
    CROSS_SESSION_CONTAMINATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)shared[_-]?memory[_-]?pool',
         'Shared memory pool across sessions', Severity.HIGH),
        (r'(?i)global[_-]?(?:context|memory|state)[_-]?cache',
         'Global cache shared across sessions', Severity.HIGH),
        (r'(?i)session[_-]?(?:less|agnostic)[_-]?(?:memory|state)',
         'Session-agnostic memory (contamination risk)', Severity.MEDIUM),
        (r'(?i)inherit[_-]?(?:memory|context)[_-]?from',
         'Memory inheritance between sessions', Severity.MEDIUM),
        (r'memory\.(?:share|export)\s*\([^)]*(?:all|other)[_-]?session',
         'Memory shared with other sessions', Severity.HIGH),
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.json', '.yaml', '.yml', '.toml']

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is an agent memory config"""
        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # Check direct filename matches
        if name_lower in self.MEMORY_CONFIG_FILES:
            return True

        # Check if in memory config directory
        if parent_lower in self.MEMORY_CONFIG_DIRS:
            if file_path.suffix in ['.json', '.yaml', '.yml', '.toml']:
                return True

        # Check for memory-related keywords in filename
        memory_keywords = ['memory', 'state', 'checkpoint', 'session', 'cache',
                          'history', 'vector', 'embedding', 'persistence']
        if any(kw in name_lower for kw in memory_keywords):
            return True

        return False

    def get_confidence_score(self, file_path: Path) -> int:
        """Return confidence score for memory config files"""
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # High confidence for exact matches
        if name_lower in self.MEMORY_CONFIG_FILES:
            return 90

        # High confidence for files in memory directories
        if parent_lower in self.MEMORY_CONFIG_DIRS:
            return 85

        # Medium confidence for keyword matches
        if any(kw in name_lower for kw in ['memory', 'checkpoint', 'state']):
            return 70

        return 50

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan agent memory configuration file for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')

            # AIM001: Unencrypted storage
            issues.extend(self._scan_patterns(
                lines, self.UNENCRYPTED_PATTERNS, "AIM001", 311
            ))

            # AIM002: Untrusted access
            issues.extend(self._scan_patterns(
                lines, self.UNTRUSTED_ACCESS_PATTERNS, "AIM002", 732
            ))

            # AIM003: No sanitization
            issues.extend(self._scan_patterns(
                lines, self.NO_SANITIZATION_PATTERNS, "AIM003", 20
            ))

            # AIM004: Unbounded growth
            issues.extend(self._scan_patterns(
                lines, self.UNBOUNDED_GROWTH_PATTERNS, "AIM004", 400
            ))

            # AIM005: Missing expiration
            issues.extend(self._scan_patterns(
                lines, self.NO_EXPIRATION_PATTERNS, "AIM005", 613
            ))

            # AIM006: Sensitive data
            issues.extend(self._scan_patterns(
                lines, self.SENSITIVE_DATA_PATTERNS, "AIM006", 798
            ))

            # AIM007: Insecure checkpoints
            issues.extend(self._scan_patterns(
                lines, self.INSECURE_CHECKPOINT_PATTERNS, "AIM007", 922
            ))

            # AIM008: Cross-session exposure
            issues.extend(self._scan_patterns(
                lines, self.CROSS_SESSION_PATTERNS, "AIM008", 200
            ))

            # AIM009: Memory injection
            issues.extend(self._scan_patterns(
                lines, self.INJECTION_PATTERNS, "AIM009", 94
            ))

            # AIM010: Vector store security
            issues.extend(self._scan_patterns(
                lines, self.VECTOR_STORE_PATTERNS, "AIM010", 798
            ))

            # AIM011: Unvalidated memory write (Memory Poisoning)
            issues.extend(self._scan_patterns(
                lines, self.UNVALIDATED_WRITE_PATTERNS, "AIM011", 94
            ))

            # AIM012: Persistent memory without encryption
            issues.extend(self._scan_patterns(
                lines, self.PERSISTENT_UNENCRYPTED_PATTERNS, "AIM012", 311
            ))

            # AIM013: Vector store poisoning
            issues.extend(self._scan_patterns(
                lines, self.VECTOR_POISONING_PATTERNS, "AIM013", 94
            ))

            # AIM014: Missing memory checksum
            issues.extend(self._scan_patterns(
                lines, self.MISSING_CHECKSUM_PATTERNS, "AIM014", 354
            ))

            # AIM015: Cross-session memory contamination
            issues.extend(self._scan_patterns(
                lines, self.CROSS_SESSION_CONTAMINATION_PATTERNS, "AIM015", 488
            ))

            # Parse JSON and do structured analysis
            if file_path.suffix == '.json':
                issues.extend(self._scan_json_structure(content, lines))

            # Scan with YAML rules (lines already defined earlier)
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

    def _scan_patterns(
        self,
        lines: List[str],
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str,
        cwe_id: int
    ) -> List[ScannerIssue]:
        """Scan lines for patterns"""
        issues = []
        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
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

    def _scan_json_structure(self, content: str, lines: List[str]) -> List[ScannerIssue]:
        """Analyze JSON structure for security issues"""
        issues = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return issues

        # Check for common insecure patterns in structure
        def check_dict(d: Dict, path: str = ""):
            if not isinstance(d, dict):
                return

            for key, value in d.items():
                full_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                # Check for sensitive keys with values
                if key_lower in ['password', 'secret', 'token', 'api_key', 'apikey']:
                    if isinstance(value, str) and len(value) > 5:
                        issues.append(ScannerIssue(
                            severity=Severity.CRITICAL,
                            message=f"Sensitive data at '{full_path}'",
                            line=self._find_line_number(lines, key),
                            rule_id="AIM006",
                            cwe_id=798,
                            cwe_link="https://cwe.mitre.org/data/definitions/798.html"
                        ))

                # Check for history/messages that might contain injected content
                if key_lower in ['history', 'messages', 'conversation', 'chat']:
                    if isinstance(value, list):
                        for idx, item in enumerate(value):
                            if isinstance(item, dict):
                                content_val = item.get('content', item.get('text', ''))
                                if isinstance(content_val, str):
                                    for pattern, desc, sev in self.INJECTION_PATTERNS:
                                        if re.search(pattern, content_val, re.IGNORECASE):
                                            issues.append(ScannerIssue(
                                                severity=sev,
                                                message=f"Memory injection in {full_path}[{idx}]: {desc}",
                                                line=self._find_line_number(lines, content_val[:30] if len(content_val) > 30 else content_val),
                                                rule_id="AIM009",
                                                cwe_id=94,
                                                cwe_link="https://cwe.mitre.org/data/definitions/94.html"
                                            ))
                                            break

                # Recurse into nested dicts
                if isinstance(value, dict):
                    check_dict(value, full_path)
                elif isinstance(value, list):
                    for idx, item in enumerate(value):
                        if isinstance(item, dict):
                            check_dict(item, f"{full_path}[{idx}]")

        check_dict(data)
        return issues

    def _find_line_number(self, lines: List[str], search: str) -> int:
        """Find the line number containing the search string"""
        for i, line in enumerate(lines, 1):
            if search and search in line:
                return i
        return 1

    def get_install_instructions(self) -> str:
        return "Agent memory scanning is built-in (no installation required)"
