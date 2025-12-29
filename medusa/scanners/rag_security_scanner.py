#!/usr/bin/env python3
"""
MEDUSA RAG Security Scanner
Scans RAG (Retrieval-Augmented Generation) configurations for security issues

Detects vulnerabilities in:
- RAG configuration files
- Vector database configurations
- Document ingestion pipelines
- Embedding service configurations
- Knowledge base definitions

These files can be vectors for:
- Knowledge base poisoning
- Unsafe document retrieval
- Embedding attacks
- Source confusion attacks
- Data exfiltration via retrieval
"""

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue, Severity


class RAGSecurityScanner(RuleBasedScanner):
    """
    RAG Security Scanner

    Scans for:
    - AIR001: Untrusted document sources
    - AIR002: No content sanitization before indexing
    - AIR003: Executable code in knowledge base
    - AIR004: Mixed trust level sources
    - AIR005: Missing source attribution
    - AIR006: Insecure embedding service
    - AIR007: Vector DB credential exposure
    - AIR008: Unsafe chunking configuration
    - AIR009: No retrieval filtering
    - AIR010: Knowledge base injection patterns
    - AIR011: Agentic RAG validation (source validation, conflict resolution)
    - AIR012: Embedding pipeline security (KB reconciliation, contradiction handling)
    - AIR013: Hidden text poisoning (CSS tricks, zero-width chars)
    - AIR014: Adversarial suffix patterns
    - AIR015: Multi-tenant vector isolation
    """

    # Rule ID prefixes to load from YAML
    RULE_ID_PREFIXES = ['RAG-', 'MEDUSA-RAG-']
    
    # Categories to load from YAML  
    RULE_CATEGORIES = ['rag_poisoning', 'rag_security', 'retrieval_attack', 'embedding_attack', 'knowledge_poisoning']

    # RAG config file patterns
    RAG_CONFIG_FILES = [
        'rag.json', 'rag.yaml', 'rag.yml',
        'rag_config.json', 'rag_config.yaml',
        'retrieval.json', 'retrieval.yaml',
        'knowledge.json', 'knowledge.yaml',
        'kb.json', 'kb.yaml', 'knowledgebase.json',
        'vectordb.json', 'vector_db.json',
        'embeddings.json', 'embedding.json',
        'langchain.json', 'langchain.yaml',
        'llamaindex.json', 'llama_index.json',
        'chunking.json', 'indexer.json',
        'ingest.json', 'ingestion.json',
    ]

    # Directories that commonly contain RAG configs
    RAG_CONFIG_DIRS = [
        'rag', 'retrieval', 'knowledge',
        'kb', 'knowledgebase', 'knowledge_base',
        'vectordb', 'vector_db', 'embeddings',
        'langchain', 'llamaindex', 'llama_index',
        '.rag', '.knowledge', '.embeddings',
    ]

    # AIR001: Untrusted document sources
    UNTRUSTED_SOURCE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(source|url|path)["\']?\s*[=:]\s*["\']?https?://[^"\']*',
         'External HTTP source (verify trustworthiness)', Severity.MEDIUM),
        (r'(?i)["\']?(source|url|path)["\']?\s*[=:]\s*["\']?http://[^"\']*',
         'Unencrypted HTTP source', Severity.HIGH),
        (r'(?i)["\']?(source|url|path)["\']?\s*[=:]\s*["\']?ftp://[^"\']*',
         'FTP source (insecure)', Severity.HIGH),
        (r'(?i)["\']?(source|url)["\']?\s*[=:]\s*["\']?\$\{?[A-Z_]+',
         'Dynamic source from environment variable', Severity.MEDIUM),
        (r'(?i)["\']?(allow_any|any_source|trust_all)["\']?\s*[=:]\s*["\']?(true|yes|enabled)',
         'Allowing any document source', Severity.CRITICAL),
        (r'(?i)\.onion[/"\']',
         'Tor hidden service as source', Severity.CRITICAL),
        (r'(?i)(ngrok|localtunnel|serveo)',
         'Tunnel service as document source', Severity.HIGH),
    ]

    # AIR002: No sanitization patterns
    NO_SANITIZATION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(sanitize|sanitization)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Document sanitization disabled', Severity.HIGH),
        (r'(?i)["\']?(strip_html|remove_scripts)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'HTML/script stripping disabled', Severity.HIGH),
        (r'(?i)["\']?(validate|validation)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Document validation disabled', Severity.HIGH),
        (r'(?i)["\']?(allow_html|html_enabled)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'HTML content allowed in knowledge base', Severity.MEDIUM),
        (r'(?i)["\']?(raw_mode|unsafe_mode)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Raw/unsafe mode enabled', Severity.HIGH),
    ]

    # AIR003: Executable code patterns
    EXECUTABLE_CODE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(allow_code|code_execution)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Code execution in knowledge base allowed', Severity.CRITICAL),
        (r'(?i)["\']?(eval|exec)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Eval/exec enabled for documents', Severity.CRITICAL),
        (r'(?i)["\']?(file_types?|extensions?)["\']?\s*[=:].{0,100}\.(py|js|sh|bat|ps1|rb)',
         'Executable file types allowed in KB', Severity.HIGH),
        (r'(?i)["\']?(run_scripts?|execute_scripts?)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Script execution enabled', Severity.CRITICAL),
        (r'(?i)["\']?(process_macros?|macros?)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Macro processing enabled', Severity.HIGH),
    ]

    # AIR004: Mixed trust patterns
    MIXED_TRUST_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(trust_level|trust)["\']?\s*[=:]\s*["\']?(mixed|any|all)["\']?',
         'Mixed trust levels in knowledge base', Severity.HIGH),
        (r'(?i)["\']?(sources|collections)["\']?\s*[=:].{0,50}\[.{0,100}internal.{0,50}external',
         'Mixed internal/external sources', Severity.MEDIUM),
        (r'(?i)["\']?(verified|unverified)["\']?\s*[=:].{0,50}\[.{0,100}unverified',
         'Unverified sources included', Severity.MEDIUM),
    ]

    # AIR005: Missing attribution patterns
    MISSING_ATTRIBUTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(attribution|cite|source_tracking)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Source attribution disabled', Severity.MEDIUM),
        (r'(?i)["\']?(track_source|source_metadata)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Source tracking disabled', Severity.MEDIUM),
        (r'(?i)["\']?(include_source|show_source)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Source inclusion disabled', Severity.LOW),
    ]

    # AIR006: Insecure embedding service patterns
    INSECURE_EMBEDDING_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(embedding|embeddings?_url|embed_url)["\']?\s*[=:]\s*["\']?http://[^"\']*',
         'Embedding service over HTTP', Severity.HIGH),
        (r'(?i)["\']?(openai|anthropic|cohere)[_-]?api[_-]?key["\']?\s*[=:]\s*["\'][^"\']+["\']',
         'Hardcoded embedding API key', Severity.CRITICAL),
        (r'(?i)["\']?(verify_ssl|ssl_verify)["\']?\s*[=:]\s*["\']?(false|off|disabled|0)["\']?',
         'SSL verification disabled for embeddings', Severity.CRITICAL),
        (r'(?i)["\']?embedding["\']?\s*[=:].*localhost',
         'Local embedding service (check security)', Severity.LOW),
    ]

    # AIR007: Vector DB credential patterns
    VECTOR_DB_CREDENTIAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(pinecone|weaviate|milvus|qdrant|chroma)[_-]?api[_-]?key["\']?\s*[=:]\s*["\'][^"\']+["\']',
         'Hardcoded vector DB API key', Severity.CRITICAL),
        (r'(?i)["\']?(password|passwd)["\']?\s*[=:]\s*["\'][^"\']{8,}["\']',
         'Hardcoded vector DB password', Severity.CRITICAL),
        (r'(?i)["\']?(connection_string|conn_str)["\']?\s*[=:].*:.*@',
         'Connection string with credentials', Severity.CRITICAL),
        (r'(?i)["\']?(admin_key|master_key)["\']?\s*[=:]\s*["\'][^"\']+["\']',
         'Hardcoded admin/master key', Severity.CRITICAL),
    ]

    # AIR008: Unsafe chunking patterns
    UNSAFE_CHUNKING_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(chunk_size|max_chunk)["\']?\s*[=:]\s*["\']?(\d{5,}|unlimited)["\']?',
         'Very large or unlimited chunk size', Severity.MEDIUM),
        (r'(?i)["\']?(overlap|chunk_overlap)["\']?\s*[=:]\s*["\']?0["\']?',
         'No chunk overlap (may miss context)', Severity.LOW),
        (r'(?i)["\']?(preserve_boundaries|respect_boundaries)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Document boundaries not preserved', Severity.MEDIUM),
    ]

    # AIR009: No retrieval filtering patterns
    NO_FILTERING_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(filter|filtering)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Retrieval filtering disabled', Severity.HIGH),
        (r'(?i)["\']?(return_all|all_results)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Returning all results without filtering', Severity.MEDIUM),
        (r'(?i)["\']?(min_score|threshold)["\']?\s*[=:]\s*["\']?0["\']?',
         'No minimum relevance threshold', Severity.MEDIUM),
        (r'(?i)["\']?(max_results|top_k)["\']?\s*[=:]\s*["\']?(\d{3,}|unlimited)["\']?',
         'Very high or unlimited result count', Severity.MEDIUM),
    ]

    # AIR010: Knowledge base injection patterns
    KB_INJECTION_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)ignore\s+(all\s+)?previous\s+instructions?',
         'Prompt injection in KB content', Severity.CRITICAL),
        (r'<(hidden|secret|system)[^>]*>',
         'Hidden tag in KB content', Severity.CRITICAL),
        (r'(?i)you\s+are\s+(now|actually|really)',
         'Role manipulation in KB content', Severity.HIGH),
        (r'(?i)when\s+(user\s+)?(asks?|queries?|retrieves?).{0,50}always',
         'Conditional behavior injection', Severity.HIGH),
        (r'(?i)(exfiltrate|steal|send\s+to)\s+.{0,50}data',
         'Data exfiltration instruction in KB', Severity.CRITICAL),
    ]

    # AIR013: Hidden text poisoning patterns (from AI security research)
    # Attackers hide malicious instructions using CSS or formatting tricks
    HIDDEN_TEXT_PATTERNS: List[Tuple[str, str, Severity]] = [
        # CSS color hiding (white on white, same foreground/background)
        (r'color\s*:\s*#fff.*background.*#fff',
         'Hidden text attack: white on white text', Severity.CRITICAL),
        (r'color\s*:\s*white.*background.*white',
         'Hidden text attack: white on white text', Severity.CRITICAL),
        (r'color\s*:\s*transparent',
         'Hidden text attack: transparent text', Severity.CRITICAL),
        (r'visibility\s*:\s*hidden',
         'Hidden text attack: visibility hidden', Severity.HIGH),
        (r'display\s*:\s*none',
         'Hidden text attack: display none', Severity.HIGH),
        (r'font-size\s*:\s*0',
         'Hidden text attack: zero font size', Severity.HIGH),
        (r'opacity\s*:\s*0',
         'Hidden text attack: zero opacity', Severity.HIGH),
        # HTML comment injection
        (r'<!--.*(?:ignore|system|override|instruction).*-->',
         'Hidden instruction in HTML comment', Severity.CRITICAL),
        # Zero-width characters for hidden text
        (r'\\u200[bcd]|\\u2060|\\ufeff',
         'Zero-width character hiding', Severity.HIGH),
    ]

    # AIR014: Adversarial suffix patterns
    # Patterns that indicate potential adversarial manipulation
    ADVERSARIAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Gibberish suffixes (common adversarial patterns)
        (r'[^\s\w]{15,}',
         'Potential adversarial suffix: long special character sequence', Severity.MEDIUM),
        # Base64-like patterns that could contain hidden instructions
        (r'(?i)(system|instruction|override)\s*:\s*[A-Za-z0-9+/=]{20,}',
         'Potential encoded instruction', Severity.HIGH),
        # Unicode abuse
        (r'[\u0300-\u036f]{5,}',
         'Unicode combining character abuse', Severity.MEDIUM),
        # Mixed scripts (potential homoglyph attacks)
        (r'[\u0400-\u04ff].*[a-z].*[\u0400-\u04ff]|[a-z].*[\u0400-\u04ff].*[a-z]',
         'Mixed script text (potential homoglyph attack)', Severity.MEDIUM),
    ]

    # AIR015: Document poisoning via multi-tenant vectors
    MULTITENANT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?i)["\']?(tenant_isolation|isolate_tenant)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Multi-tenant isolation disabled', Severity.CRITICAL),
        (r'(?i)["\']?(shared_namespace|common_namespace)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Shared namespace in multi-tenant setup', Severity.HIGH),
        (r'(?i)["\']?(access_control|rbac)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Access control disabled in vector DB', Severity.CRITICAL),
        (r'(?i)["\']?(partition_key|tenant_key)["\']?\s*[=:]\s*["\']?(none|null|undefined)["\']?',
         'Missing tenant partition key', Severity.HIGH),
    ]

    # AIR011: Agentic RAG validation patterns (from Agentic Design Patterns research)
    AGENTIC_RAG_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Missing source validation
        (r'(?i)["\']?(validate_source|source_validation|verify_source)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Agentic RAG - source validation disabled', Severity.HIGH),
        (r'(?i)["\']?(check_authority|authority_check|verify_authority)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Agentic RAG - authority check disabled', Severity.HIGH),
        (r'(?i)["\']?(metadata_check|check_metadata)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Agentic RAG - metadata check disabled', Severity.MEDIUM),

        # Missing conflict resolution
        (r'(?i)["\']?(resolve_conflicts?|conflict_resolution)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Agentic RAG - conflict resolution disabled', Severity.HIGH),
        (r'(?i)["\']?(prioritize_sources?|source_priority)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Agentic RAG - source prioritization disabled', Severity.MEDIUM),

        # Dangerous retrieval settings
        (r'(?i)["\']?(skip_validation|no_validation|bypass_check)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Agentic RAG - validation bypassed', Severity.CRITICAL),
        (r'(?i)["\']?(trust_all_sources|accept_all)["\']?\s*[=:]\s*["\']?(true|yes|enabled)["\']?',
         'Agentic RAG - trusting all sources', Severity.CRITICAL),

        # Missing knowledge gap handling
        (r'(?i)["\']?(fallback|external_search|knowledge_gap)["\']?\s*[=:]\s*["\']?(false|off|disabled|none)["\']?',
         'Agentic RAG - knowledge gap handling disabled', Severity.LOW),
    ]

    # AIR012: Embedding Pipeline Security patterns (from Agentic Design Patterns research)
    EMBEDDING_PIPELINE_PATTERNS: List[Tuple[str, str, Severity]] = [
        # KB integrity issues
        (r'(?i)["\']?(reconcile|reconciliation|sync)["\']?\s*[=:]\s*["\']?(false|off|disabled|never)["\']?',
         'Embedding pipeline - KB reconciliation disabled', Severity.HIGH),
        (r'(?i)["\']?(update_frequency|refresh_interval)["\']?\s*[=:]\s*["\']?(never|none|0)["\']?',
         'Embedding pipeline - KB never updated', Severity.HIGH),
        (r'(?i)["\']?(validate_sources?|source_check)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Embedding pipeline - source validation disabled', Severity.HIGH),

        # Noise/irrelevant chunk handling
        (r'(?i)["\']?(filter_irrelevant|relevance_filter|noise_filter)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Embedding pipeline - relevance filtering disabled', Severity.MEDIUM),
        (r'(?i)["\']?(relevance_threshold|similarity_threshold)["\']?\s*[=:]\s*["\']?(0|0\.0|none)["\']?',
         'Embedding pipeline - no relevance threshold', Severity.MEDIUM),

        # Contradiction handling
        (r'(?i)["\']?(handle_contradictions?|contradiction_check)["\']?\s*[=:]\s*["\']?(false|off|disabled|ignore)["\']?',
         'Embedding pipeline - contradiction handling disabled', Severity.HIGH),
        (r'(?i)["\']?(merge_strategy|conflict_strategy)["\']?\s*[=:]\s*["\']?(none|ignore|skip)["\']?',
         'Embedding pipeline - no conflict strategy', Severity.MEDIUM),

        # Completeness/context issues
        (r'(?i)["\']?(check_completeness|completeness_check)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Embedding pipeline - completeness check disabled', Severity.MEDIUM),
        (r'(?i)["\']?(cross_chunk|multi_chunk|chunk_linking)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Embedding pipeline - cross-chunk linking disabled', Severity.LOW),

        # Performance/efficiency indicators
        (r'(?i)["\']?(cache|caching)["\']?\s*[=:]\s*["\']?(false|off|disabled)["\']?',
         'Embedding pipeline - caching disabled (performance risk)', Severity.LOW),
        (r'(?i)["\']?(batch_size)["\']?\s*[=:]\s*["\']?(1|none)["\']?',
         'Embedding pipeline - inefficient batch size', Severity.LOW),
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return ['.json', '.yaml', '.yml', '.toml']

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is a RAG configuration"""
        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # Check direct filename matches
        if name_lower in self.RAG_CONFIG_FILES:
            return True

        # Check if in RAG config directory
        if parent_lower in self.RAG_CONFIG_DIRS:
            if file_path.suffix in ['.json', '.yaml', '.yml', '.toml']:
                return True

        # Check for RAG-related keywords in filename
        rag_keywords = ['rag', 'retrieval', 'knowledge', 'vectordb', 'vector_db',
                       'embedding', 'langchain', 'llamaindex', 'chunking', 'ingest']
        if any(kw in name_lower for kw in rag_keywords):
            return True

        return False

    def get_confidence_score(self, file_path: Path) -> int:
        """Return confidence score for RAG config files"""
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()
        parent_lower = file_path.parent.name.lower()

        # High confidence for exact matches
        if name_lower in self.RAG_CONFIG_FILES:
            return 90

        # High confidence for files in RAG directories
        if parent_lower in self.RAG_CONFIG_DIRS:
            return 85

        # Medium confidence for keyword matches
        if any(kw in name_lower for kw in ['rag', 'knowledge', 'vectordb']):
            return 75

        return 50

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan RAG configuration file for security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.split('\n')

            # AIR001: Untrusted sources
            issues.extend(self._scan_patterns(
                lines, self.UNTRUSTED_SOURCE_PATTERNS, "AIR001", 829
            ))

            # AIR002: No sanitization
            issues.extend(self._scan_patterns(
                lines, self.NO_SANITIZATION_PATTERNS, "AIR002", 20
            ))

            # AIR003: Executable code
            issues.extend(self._scan_patterns(
                lines, self.EXECUTABLE_CODE_PATTERNS, "AIR003", 94
            ))

            # AIR004: Mixed trust
            issues.extend(self._scan_patterns(
                lines, self.MIXED_TRUST_PATTERNS, "AIR004", 285
            ))

            # AIR005: Missing attribution
            issues.extend(self._scan_patterns(
                lines, self.MISSING_ATTRIBUTION_PATTERNS, "AIR005", 346
            ))

            # AIR006: Insecure embedding
            issues.extend(self._scan_patterns(
                lines, self.INSECURE_EMBEDDING_PATTERNS, "AIR006", 319
            ))

            # AIR007: Vector DB credentials
            issues.extend(self._scan_patterns(
                lines, self.VECTOR_DB_CREDENTIAL_PATTERNS, "AIR007", 798
            ))

            # AIR008: Unsafe chunking
            issues.extend(self._scan_patterns(
                lines, self.UNSAFE_CHUNKING_PATTERNS, "AIR008", 400
            ))

            # AIR009: No filtering
            issues.extend(self._scan_patterns(
                lines, self.NO_FILTERING_PATTERNS, "AIR009", 285
            ))

            # AIR010: KB injection
            issues.extend(self._scan_patterns(
                lines, self.KB_INJECTION_PATTERNS, "AIR010", 94
            ))

            # AIR011: Agentic RAG validation
            issues.extend(self._scan_patterns(
                lines, self.AGENTIC_RAG_PATTERNS, "AIR011", 285
            ))

            # AIR012: Embedding pipeline security
            issues.extend(self._scan_patterns(
                lines, self.EMBEDDING_PIPELINE_PATTERNS, "AIR012", 400
            ))

            # AIR013: Hidden text poisoning
            issues.extend(self._scan_patterns(
                lines, self.HIDDEN_TEXT_PATTERNS, "AIR013", 94
            ))

            # AIR014: Adversarial suffix patterns
            issues.extend(self._scan_patterns(
                lines, self.ADVERSARIAL_PATTERNS, "AIR014", 74
            ))

            # AIR015: Multi-tenant vector isolation
            issues.extend(self._scan_patterns(
                lines, self.MULTITENANT_PATTERNS, "AIR015", 653
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

    def get_install_instructions(self) -> str:
        return "RAG security scanning is built-in (no installation required)"
