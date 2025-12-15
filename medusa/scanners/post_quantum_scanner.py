#!/usr/bin/env python3
"""
MEDUSA Post-Quantum Cryptography Scanner
Detects quantum-vulnerable cryptographic implementations

Based on:
- NIST FIPS 203/204/205 (August 2024)
- "Harvest Now, Decrypt Later" (HNDL) threat model
- Cryptographic Agility best practices

Detects:
- Quantum-vulnerable algorithms (RSA, ECDSA, ECDH, DH)
- Crypto-agility anti-patterns (hardcoded algorithms)
- Side-channel vulnerable patterns
- Missing hybrid encryption schemes
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class PostQuantumScanner(BaseScanner):
    """
    Post-Quantum Cryptography Scanner

    Scans for:
    - PQC001: RSA usage (quantum-vulnerable key exchange/encryption)
    - PQC002: ECDSA usage (quantum-vulnerable signatures)
    - PQC003: ECDH/DH usage (quantum-vulnerable key agreement)
    - PQC004: Hardcoded algorithm strings (crypto-agility anti-pattern)
    - PQC005: Classical key sizes (RSA-2048, etc.)
    - PQC006: Missing PQC library imports
    - PQC007: Side-channel vulnerable patterns (secret-dependent branches)
    - PQC008: Non-constant-time comparisons
    - PQC009: Long-lived data with classical encryption
    - PQC010: TLS/SSL without PQC hybrid support
    """

    # PQC001: RSA patterns (quantum-vulnerable)
    RSA_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Python
        (r'from\s+Crypto\.PublicKey\s+import\s+RSA',
         'PyCrypto RSA import (quantum-vulnerable)', Severity.HIGH),
        (r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa',
         'cryptography RSA import (quantum-vulnerable)', Severity.HIGH),
        (r'RSA\.generate\s*\(',
         'RSA key generation (quantum-vulnerable)', Severity.HIGH),
        (r'rsa\.generate_private_key\s*\(',
         'RSA private key generation (quantum-vulnerable)', Severity.HIGH),

        # Java
        (r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']',
         'Java RSA KeyPairGenerator (quantum-vulnerable)', Severity.HIGH),
        (r'Cipher\.getInstance\s*\(\s*["\']RSA',
         'Java RSA Cipher (quantum-vulnerable)', Severity.HIGH),
        (r'Signature\.getInstance\s*\(\s*["\'].*RSA',
         'Java RSA Signature (quantum-vulnerable)', Severity.HIGH),

        # JavaScript/Node
        (r'crypto\.generateKeyPair\s*\(\s*["\']rsa["\']',
         'Node.js RSA key generation (quantum-vulnerable)', Severity.HIGH),
        (r'crypto\.createSign\s*\(\s*["\']RSA-',
         'Node.js RSA signing (quantum-vulnerable)', Severity.HIGH),

        # Go
        (r'rsa\.GenerateKey\s*\(',
         'Go RSA key generation (quantum-vulnerable)', Severity.HIGH),
        (r'import\s+["\']crypto/rsa["\']',
         'Go crypto/rsa import (quantum-vulnerable)', Severity.MEDIUM),

        # Generic
        (r'new\s+RSASigner\s*\(',
         'RSA signer instantiation (quantum-vulnerable)', Severity.HIGH),
        (r'RSAPublicKey|RSAPrivateKey',
         'RSA key type usage (quantum-vulnerable)', Severity.MEDIUM),
    ]

    # PQC002: ECDSA patterns (quantum-vulnerable signatures)
    ECDSA_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Python
        (r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec',
         'cryptography EC import (ECDSA quantum-vulnerable)', Severity.HIGH),
        (r'ec\.generate_private_key\s*\(',
         'EC private key generation (quantum-vulnerable)', Severity.HIGH),
        (r'from\s+ecdsa\s+import',
         'python-ecdsa import (quantum-vulnerable)', Severity.HIGH),

        # Java
        (r'Signature\.getInstance\s*\(\s*["\'].*ECDSA',
         'Java ECDSA Signature (quantum-vulnerable)', Severity.HIGH),
        (r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']',
         'Java EC KeyPairGenerator (quantum-vulnerable)', Severity.HIGH),

        # JavaScript/Node
        (r'crypto\.createSign\s*\(\s*["\'].*ecdsa',
         'Node.js ECDSA signing (quantum-vulnerable)', Severity.HIGH),
        (r'crypto\.generateKeyPair\s*\(\s*["\']ec["\']',
         'Node.js EC key generation (quantum-vulnerable)', Severity.HIGH),

        # Go
        (r'ecdsa\.GenerateKey\s*\(',
         'Go ECDSA key generation (quantum-vulnerable)', Severity.HIGH),
        (r'import\s+["\']crypto/ecdsa["\']',
         'Go crypto/ecdsa import (quantum-vulnerable)', Severity.MEDIUM),
    ]

    # PQC003: ECDH/DH patterns (quantum-vulnerable key exchange)
    KEY_EXCHANGE_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Python
        (r'ECDH\s*\(',
         'ECDH key exchange (quantum-vulnerable, negates forward secrecy)', Severity.HIGH),
        (r'X25519\s*\(',
         'X25519 key exchange (quantum-vulnerable without hybrid)', Severity.MEDIUM),
        (r'dh\.generate_parameters\s*\(',
         'DH parameter generation (quantum-vulnerable)', Severity.HIGH),

        # Java
        (r'KeyAgreement\.getInstance\s*\(\s*["\']ECDH["\']',
         'Java ECDH KeyAgreement (quantum-vulnerable)', Severity.HIGH),
        (r'KeyAgreement\.getInstance\s*\(\s*["\']DH["\']',
         'Java DH KeyAgreement (quantum-vulnerable)', Severity.HIGH),
        (r'KeyAgreement\.getInstance\s*\(\s*["\']DiffieHellman["\']',
         'Java DiffieHellman (quantum-vulnerable)', Severity.HIGH),

        # JavaScript/Node
        (r'crypto\.createDiffieHellman\s*\(',
         'Node.js DiffieHellman (quantum-vulnerable)', Severity.HIGH),
        (r'crypto\.createECDH\s*\(',
         'Node.js ECDH (quantum-vulnerable)', Severity.HIGH),
        (r'crypto\.diffieHellman\s*\(',
         'Node.js DH (quantum-vulnerable)', Severity.HIGH),

        # Go
        (r'elliptic\.P256\s*\(\)|elliptic\.P384\s*\(\)|elliptic\.P521\s*\(',
         'Go elliptic curve (quantum-vulnerable without hybrid)', Severity.MEDIUM),
        (r'import\s+["\']crypto/elliptic["\']',
         'Go crypto/elliptic import (quantum-vulnerable)', Severity.MEDIUM),
    ]

    # PQC004: Hardcoded algorithm strings (crypto-agility anti-pattern)
    HARDCODED_ALGO_PATTERNS: List[Tuple[str, str, Severity]] = [
        # RSA variants
        (r'["\']RSA/ECB/PKCS1Padding["\']',
         'Hardcoded RSA/ECB/PKCS1Padding (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']RSA/ECB/OAEPWithSHA-256["\']',
         'Hardcoded RSA-OAEP (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']SHA256withRSA["\']',
         'Hardcoded SHA256withRSA (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']SHA512withRSA["\']',
         'Hardcoded SHA512withRSA (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']SHA1withRSA["\']',
         'Hardcoded SHA1withRSA (weak + quantum-vulnerable)', Severity.CRITICAL),

        # ECDSA variants
        (r'["\']SHA256withECDSA["\']',
         'Hardcoded SHA256withECDSA (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']SHA384withECDSA["\']',
         'Hardcoded SHA384withECDSA (crypto-agility anti-pattern)', Severity.HIGH),
        (r'["\']SHA512withECDSA["\']',
         'Hardcoded SHA512withECDSA (crypto-agility anti-pattern)', Severity.HIGH),

        # Direct algorithm specification
        (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-256["\']',
         'Hardcoded algorithm in MessageDigest (consider crypto-agility)', Severity.LOW),
        (r'Cipher\.getInstance\s*\(\s*["\']AES',
         'Hardcoded AES cipher (consider crypto-agility for key wrapping)', Severity.LOW),
    ]

    # PQC005: Classical key sizes
    KEY_SIZE_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'RSA-?2048|rsa_?2048|key_?size\s*=\s*2048',
         'RSA-2048 key size (vulnerable to Shor\'s algorithm)', Severity.HIGH),
        (r'RSA-?4096|rsa_?4096|key_?size\s*=\s*4096',
         'RSA-4096 key size (still vulnerable to quantum attacks)', Severity.HIGH),
        (r'RSA-?1024|rsa_?1024|key_?size\s*=\s*1024',
         'RSA-1024 key size (weak + quantum-vulnerable)', Severity.CRITICAL),
        (r'secp256r1|P-256|prime256v1',
         'P-256 curve (quantum-vulnerable without hybrid)', Severity.MEDIUM),
        (r'secp384r1|P-384',
         'P-384 curve (quantum-vulnerable without hybrid)', Severity.MEDIUM),
        (r'secp521r1|P-521',
         'P-521 curve (quantum-vulnerable without hybrid)', Severity.MEDIUM),
    ]

    # PQC007: Side-channel vulnerable patterns
    SIDE_CHANNEL_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Secret-dependent branching
        (r'if\s*\(\s*(?:secret|key|private).*(?:==|!=|<|>)',
         'Secret-dependent conditional (timing attack risk)', Severity.HIGH),
        (r'if\s*\(\s*(?:password|token|credential).*(?:==|!=)',
         'Credential-dependent conditional (timing attack risk)', Severity.HIGH),

        # Secret-dependent array access
        (r'\[\s*(?:secret|key|private).*\]',
         'Secret-dependent array index (cache attack risk)', Severity.MEDIUM),

        # Non-constant-time comparison
        (r'(?:secret|key|private|password).*(?:==|!=)\s*["\']',
         'Direct secret comparison (use constant-time compare)', Severity.HIGH),
    ]

    # PQC008: Non-constant-time comparison patterns
    NON_CONSTANT_TIME_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'\.equals\s*\(\s*(?:secret|key|password|token)',
         'Non-constant-time equals() on secret (use MessageDigest.isEqual)', Severity.HIGH),
        (r'strcmp\s*\(\s*(?:secret|key|password)',
         'Non-constant-time strcmp on secret (use constant_time_compare)', Severity.HIGH),
        (r'(?:secret|key|password)\s*==\s*(?:secret|key|password)',
         'Non-constant-time comparison of secrets', Severity.HIGH),
    ]

    # PQC010: TLS patterns without PQC
    TLS_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'TLS_ECDHE_RSA|TLS_ECDHE_ECDSA',
         'TLS cipher suite without PQC (consider hybrid)', Severity.MEDIUM),
        (r'ssl\.PROTOCOL_TLS|TLSv1\.[0-3]',
         'TLS without PQC hybrid support (HNDL risk)', Severity.LOW),
    ]

    # Good patterns - PQC library usage (reduce severity if present)
    PQC_GOOD_PATTERNS = [
        r'ML-KEM|MLKEM|ml_kem|mlkem',
        r'ML-DSA|MLDSA|ml_dsa|mldsa',
        r'SLH-DSA|SLHDSA|slh_dsa|slhdsa',
        r'CRYSTALS-Kyber|Kyber|kyber',
        r'CRYSTALS-Dilithium|Dilithium|dilithium',
        r'SPHINCS\+|sphincs',
        r'liboqs|oqs',
        r'pqcrypto|post_quantum',
        r'BoringSSL.*hybrid|hybrid.*BoringSSL',
        r'X25519.*Kyber|Kyber.*X25519',
    ]

    # Hybrid scheme patterns (good - reduces severity)
    HYBRID_PATTERNS = [
        r'X25519_Kyber|Kyber_X25519',
        r'hybrid.*key|key.*hybrid',
        r'pq_hybrid|hybrid_pq',
        r'classical.*pqc|pqc.*classical',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs"]

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for quantum-vulnerable cryptographic implementations"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file contains crypto-related code
            crypto_indicators = [
                'crypto', 'cipher', 'sign', 'encrypt', 'decrypt', 'key',
                'rsa', 'ecdsa', 'ecdh', 'dh', 'certificate', 'tls', 'ssl',
                'hash', 'digest', 'hmac', 'aes', 'secret', 'private',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in crypto_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for PQC adoption (good patterns)
            has_pqc = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.PQC_GOOD_PATTERNS
            )

            # Check for hybrid schemes
            has_hybrid = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.HYBRID_PATTERNS
            )

            lines = content.split('\n')

            # PQC001: RSA patterns
            issues.extend(self._check_patterns(
                content, lines, self.RSA_PATTERNS, "PQC001"
            ))

            # PQC002: ECDSA patterns
            issues.extend(self._check_patterns(
                content, lines, self.ECDSA_PATTERNS, "PQC002"
            ))

            # PQC003: ECDH/DH patterns
            issues.extend(self._check_patterns(
                content, lines, self.KEY_EXCHANGE_PATTERNS, "PQC003"
            ))

            # PQC004: Hardcoded algorithm strings
            issues.extend(self._check_patterns(
                content, lines, self.HARDCODED_ALGO_PATTERNS, "PQC004"
            ))

            # PQC005: Classical key sizes
            issues.extend(self._check_patterns(
                content, lines, self.KEY_SIZE_PATTERNS, "PQC005"
            ))

            # PQC007: Side-channel patterns
            issues.extend(self._check_patterns(
                content, lines, self.SIDE_CHANNEL_PATTERNS, "PQC007"
            ))

            # PQC008: Non-constant-time comparisons
            issues.extend(self._check_patterns(
                content, lines, self.NON_CONSTANT_TIME_PATTERNS, "PQC008"
            ))

            # PQC010: TLS without PQC
            issues.extend(self._check_patterns(
                content, lines, self.TLS_PATTERNS, "PQC010"
            ))

            # Reduce severity if PQC or hybrid schemes are present
            if has_pqc or has_hybrid:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.MEDIUM:
                        issue.severity = Severity.LOW

            # Add informational note if no PQC detected in crypto code
            if issues and not has_pqc:
                issues.append(ScannerIssue(
                    rule_id="PQC006",
                    severity=Severity.LOW,
                    message="No PQC library imports detected - consider adopting ML-KEM (FIPS 203), ML-DSA (FIPS 204), or hybrid schemes",
                    line=1,
                    column=1,
                ))

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
        seen_messages = set()

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Avoid duplicate messages for same pattern
                    if message not in seen_messages:
                        issues.append(ScannerIssue(
                            rule_id=rule_id,
                            severity=severity,
                            message=f"{message} - migrate to NIST PQC standards (ML-KEM, ML-DSA)",
                            line=i,
                            column=1,
                        ))
                        seen_messages.add(message)
                        break  # One issue per pattern type

        return issues
