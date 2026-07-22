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
    ".netrc", ".dockercfg", ".pgpass", ".s3cfg",
})
_SUFFIXES = (".pem", ".key")

# Test-fixture credential material — test TLS certs/keys, sample .npmrc — is a
# standard, expected part of a repo's test suite: every HTTP/TLS library ships
# `tests/certs/*.key`. Flagging it as a "committed credential" is a ~100%-FP that
# hard-blocks legitimate repos (this is exactly why `requests` vetted
# DO_NOT_INSTALL — 4 test certs under tests/certs/). A real leaked secret in a
# test dir is vanishingly rare, and live-payload malice (droppers, hijack skills)
# is caught by the other scanners that still descend test dirs. So skip credential
# scanning under obvious test-fixture paths.
_TEST_FIXTURE_DIRS = frozenset({
    "test", "tests", "testing", "testdata", "test_data", "__tests__",
    "fixtures", "fixture", "__fixtures__", "testfixtures",
    "mocks", "mock", "examples", "example", "spec", "specs", "e2e",
})


def _is_test_fixture_path(file_path: Path) -> bool:
    """True if any parent directory marks this as test-fixture material."""
    return any(part.lower() in _TEST_FIXTURE_DIRS for part in file_path.parts[:-1])

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
    # .netrc: `machine host login user password SECRET` (space-separated).
    (re.compile(r"(?i)\bpassword\s+\S{4,}"), "netrc/plaintext password"),
    # .dockercfg / .docker/config.json: base64 registry auth token.
    (re.compile(r'(?i)"auth"\s*:\s*"[A-Za-z0-9+/]{8,}={0,2}"'), "docker registry auth token"),
    # .s3cfg: cloud access/secret key assignments.
    (re.compile(r"(?i)\b(?:secret_key|access_key)\s*=\s*\S{8,}"), "cloud access/secret key"),
    # .pgpass: host:port:db:user:PASSWORD line.
    (re.compile(r"(?m)^(?:[^:\n]*:){4}[^:\n]{3,}$"), "pgpass credential line"),
]

_MAX_BYTES = 1 * 1024 * 1024  # credential files are tiny; cap defensively

# A committed PRIVATE KEY is a CRITICAL exposure — it hard-blocks the install
# verdict on its own (aligns with GitLeaks, which maps private-key -> CRITICAL, and
# with scan_api's "leaked live secrets still hard-block" intent). A committed TOKEN
# file (npm/aws/docker/netrc/s3cfg/pgpass) stays HIGH: serious, but the private key
# is the higher-severity plant. Keyed on the pattern description above.
_CRITICAL_DESCS = frozenset({"private key material"})


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
        is_cred = (
            n in _NAMES
            or n.endswith(_SUFFIXES)
            # docker config lives at .docker/config.json — only credential-bearing
            # under a .docker/ dir (a bare config.json elsewhere is not a cred file)
            or (n == "config.json" and file_path.parent.name.lower() == ".docker")
        )
        if not is_cred:
            return False
        # test certs/keys are expected fixtures, not leaked secrets (see above)
        return not _is_test_fixture_path(file_path)

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
                    severity=Severity.CRITICAL if desc in _CRITICAL_DESCS else Severity.HIGH,
                    message=(f"Committed credential file '{file_path.name}': {desc} — a repo/skill "
                             "you install should not ship credentials (leaked secret or plant)"),
                    line=content[:m.start()].count("\n") + 1,
                    rule_id="MEDUSA-CRED-001",
                    cwe_id=798,
                ))
        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)
