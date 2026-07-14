#!/usr/bin/env python3
"""
MEDUSA Credential File Scanner

Detects committed credential files that the native pipeline otherwise never flags
(GitLeaks would, but it is an optional external tool — not present on many hosts).
A repo/skill you are vetting has no business shipping a private key, an npm auth
token, cloud credentials, or a PyPI/git password — it is either a leaked secret or
a plant. Covers the file classes the adversarial PC001 pass found invisible:

  - private keys:      id_rsa/id_dsa/id_ecdsa/id_ed25519, *.pem, *.key  (PEM/OpenSSH)
  - npm:               .npmrc  (_authToken / _password)
  - cloud:             .aws/credentials, files named `credentials`  (aws_secret_access_key)
  - packaging / vcs:   .pypirc (password), .git-credentials (user:pass@ URL)
  - web auth:          .htpasswd

Emits MEDUSA-CRED-001 (HIGH) — a vet SIGNAL, FP-exempt (these files exist to hold
secrets, so a match is a true positive).
"""

import re
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity

_NAMES = frozenset({
    ".npmrc", ".pypirc", ".git-credentials", "credentials", ".htpasswd",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
_SUFFIXES = (".pem", ".key")

# (compiled pattern, human description). can_scan already restricts us to
# credential-bearing files, so these are deliberately simple / high-signal.
_PATTERNS = [
    # `-{5}` (not a literal `-----BEGIN … KEY-----`) so this detection pattern is
    # not itself flagged as a committed key by the pre-commit secret scan.
    (re.compile(r"-{5}BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-{5}"),
     "private key material"),
    (re.compile(r"(?i)_auth(?:Token)?\s*=\s*\S{8,}"), "npm auth token (.npmrc)"),
    (re.compile(r"(?i)aws_secret_access_key\s*=\s*\S{16,}"), "AWS secret access key"),
    (re.compile(r"(?i)\b_password\s*=\s*\S{6,}"), "npm password"),
    (re.compile(r"https?://[^/\s:@]+:[^/\s:@]{3,}@"), "credentials embedded in a URL"),
    (re.compile(r"(?i)^\s*password\s*[:=]\s*\S{6,}", re.MULTILINE), "plaintext password"),
]

_MAX_BYTES = 1 * 1024 * 1024  # credential files are tiny; cap defensively


class CredentialFileScanner(BaseScanner):
    """Flags committed credential files (private keys, tokens, cloud creds)."""

    display_name = "Credential File"
    description = ("Detects committed credential files — private keys, npm/aws/pypi "
                   "credentials, .git-credentials — that a vetted repo should not carry.")

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return list(_SUFFIXES)

    def can_scan(self, file_path: Path) -> bool:
        n = file_path.name.lower()
        return n in _NAMES or n.endswith(_SUFFIXES)

    def get_confidence_score(self, file_path: Path,
                             content_head: Optional[str] = None) -> int:
        return 90 if self.can_scan(file_path) else 0

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]
        except (OSError, IOError) as e:
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))

        issues: List[ScannerIssue] = []
        seen = set()
        for pat, desc in _PATTERNS:
            m = pat.search(content)
            if m and desc not in seen:
                seen.add(desc)
                issues.append(ScannerIssue(
                    severity=Severity.HIGH,
                    message=(f"Committed credential file '{file_path.name}': {desc} — a repo/skill "
                             "you install should not ship credentials (leaked secret or plant)"),
                    line=content[:m.start()].count("\n") + 1,
                    rule_id="MEDUSA-CRED-001",
                    cwe_id=798,
                ))
        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)
