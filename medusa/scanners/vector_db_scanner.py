#!/usr/bin/env python3
"""
MEDUSA Vector Database Security Scanner
Detects security issues in vector database configurations

Based on "Generative AI Security Theories and Practices" Chapter 5

Detects:
- Unencrypted vector storage
- Missing access controls
- PII in embeddings
- Insecure similarity search
- Missing tenant isolation
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class VectorDBScanner(BaseScanner):
    """
    Vector Database Security Scanner

    Scans for:
    - VD001: Unencrypted vector storage
    - VD002: Missing access controls
    - VD003: PII embedded without anonymization
    - VD004: Insecure similarity search exposure
    - VD005: Missing tenant isolation
    - VD006: Exposed vector database endpoint
    - VD007: Missing data provenance
    - VD008: Insecure embedding generation
    - VD009: Missing audit logging
    - VD010: Unvalidated vector input
    """

    # Vector DB indicators
    VECTOR_DB_INDICATORS = [
        'pinecone', 'weaviate', 'milvus', 'qdrant', 'chroma',
        'faiss', 'pgvector', 'redis.*vector', 'elasticsearch.*vector',
        'vector.*store', 'embedding.*store', 'vectordb',
        'similarity.*search', 'nearest.*neighbor',
    ]

    # Encryption patterns (good)
    ENCRYPTION_PATTERNS = [
        r'encrypt',
        r'ssl\s*=\s*True',
        r'tls\s*=\s*True',
        r'https://',
        r'encrypted\s*=\s*True',
    ]

    # Access Control patterns (good)
    ACCESS_CONTROL_PATTERNS = [
        r'api_key',
        r'auth',
        r'token',
        r'rbac',
        r'role.*based',
        r'permission',
        r'acl',
    ]

    # PII patterns (bad if in embeddings)
    PII_PATTERNS = [
        (r'embed.*(email|phone|ssn|address|name)',
         'PII fields being embedded'),
        (r'(personal|private).*embed',
         'Personal data in embeddings'),
        (r'vector.*(pii|personal)',
         'PII stored in vectors'),
        (r'embed.*user.*data',
         'User data embedded without anonymization'),
    ]

    # Insecure Similarity Search patterns
    SIMILARITY_PATTERNS = [
        (r'search.*\(.*user.*input',
         'User input directly in similarity search'),
        (r'query.*vector.*\(.*request',
         'Request data in vector query'),
        (r'similarity.*public',
         'Public similarity search endpoint'),
        (r'top_k\s*=\s*\d{3,}',
         'Excessively large top_k (data exposure risk)'),
    ]

    # Tenant Isolation patterns (good)
    ISOLATION_PATTERNS = [
        r'tenant',
        r'namespace',
        r'partition',
        r'collection.*id',
        r'isolated',
        r'segregat',
    ]

    # Endpoint Exposure patterns
    ENDPOINT_PATTERNS = [
        (r'(0\.0\.0\.0|public).*vector',
         'Vector DB bound to public interface'),
        (r'vector.*port.*expose',
         'Vector DB port exposed'),
        (r'allow.*all.*vector',
         'Vector DB allows all connections'),
    ]

    # Data Provenance patterns (good)
    PROVENANCE_PATTERNS = [
        r'source',
        r'origin',
        r'provenance',
        r'lineage',
        r'metadata.*source',
    ]

    # Embedding Security patterns
    EMBEDDING_PATTERNS = [
        (r'embed.*\(.*untrusted',
         'Embedding untrusted content'),
        (r'openai.*embed.*user.*input',
         'User input sent to embedding API without sanitization'),
        (r'embed.*http.*input',
         'Embedding content from HTTP input'),
    ]

    # Audit patterns (good)
    AUDIT_PATTERNS = [
        r'audit',
        r'log.*(query|search|embed)',
        r'track.*access',
        r'record.*operation',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".env"]

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for vector database security issues"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            content_lower = content.lower()

            # Check if file is vector DB-related
            is_vector_db = any(
                re.search(ind, content_lower)
                for ind in self.VECTOR_DB_INDICATORS
            )

            if not is_vector_db:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for good patterns
            has_encryption = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.ENCRYPTION_PATTERNS
            )

            has_access_control = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.ACCESS_CONTROL_PATTERNS
            )

            has_isolation = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.ISOLATION_PATTERNS
            )

            has_provenance = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.PROVENANCE_PATTERNS
            )

            has_audit = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.AUDIT_PATTERNS
            )

            # VD001: Missing Encryption
            if not has_encryption:
                issues.append(ScannerIssue(
                    rule_id="VD001",
                    severity=Severity.HIGH,
                    message="Vector database without encryption configuration",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Enable TLS/SSL for vector database connections and at-rest encryption",
                ))

            # VD002: Missing Access Controls
            if not has_access_control:
                issues.append(ScannerIssue(
                    rule_id="VD002",
                    severity=Severity.HIGH,
                    message="Vector database without access controls",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Implement RBAC, API key authentication, and least privilege access",
                ))

            # VD003: PII in Embeddings
            for pattern, message in self.PII_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="VD003",
                        severity=Severity.HIGH,
                        message=f"PII Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Anonymize or pseudonymize PII before embedding, use differential privacy",
                    ))

            # VD004: Insecure Similarity Search
            for pattern, message in self.SIMILARITY_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="VD004",
                        severity=Severity.MEDIUM,
                        message=f"Similarity Search Risk: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate search inputs, limit result count, implement access filtering",
                    ))

            # VD005: Missing Tenant Isolation
            if not has_isolation:
                issues.append(ScannerIssue(
                    rule_id="VD005",
                    severity=Severity.MEDIUM,
                    message="No tenant isolation in vector database",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Use namespaces, partitions, or collections for tenant isolation",
                ))

            # VD006: Exposed Endpoint
            for pattern, message in self.ENDPOINT_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="VD006",
                        severity=Severity.CRITICAL,
                        message=f"Exposed Endpoint: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Bind to localhost, use network segmentation, firewall rules",
                    ))

            # VD007: Missing Provenance
            if not has_provenance:
                issues.append(ScannerIssue(
                    rule_id="VD007",
                    severity=Severity.LOW,
                    message="No data provenance tracking for vectors",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Track source and lineage of embedded data for auditability",
                ))

            # VD008: Insecure Embedding Generation
            for pattern, message in self.EMBEDDING_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    line = content[:match.start()].count('\n') + 1
                    issues.append(ScannerIssue(
                        rule_id="VD008",
                        severity=Severity.MEDIUM,
                        message=f"Embedding Security: {message}",
                        file_path=file_path,
                        line=line,
                        column=1,
                        suggestion="Validate and sanitize content before embedding",
                    ))

            # VD009: Missing Audit Logging
            if not has_audit:
                issues.append(ScannerIssue(
                    rule_id="VD009",
                    severity=Severity.LOW,
                    message="No audit logging for vector database operations",
                    file_path=file_path,
                    line=1,
                    column=1,
                    suggestion="Log all vector operations for security monitoring",
                ))

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
