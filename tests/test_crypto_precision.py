"""Two-sided precision gate for weak-hash (MD5/SHA1) crypto rules.

Context (2026-07, p1-trust-safety): the corpus gate on Ross's real projects
found a 52.9% false-block rate, with weak-crypto rules a top-3 driver — ~20
blocking HIGH false positives on ONE repo alone (graphify-super) where MD5/SHA1
is used for HTML node IDs, cache keys, and content hashing (NON-security).

The rules involved:
  * WEB-CRYPTO-001         (python_web_security.yaml)  — bare MD5/SHA1
  * SAST-CRYPTO-001/002    (traditional_sast.yaml)     — MD5/SHA1 password/sec
  * bandit B324/B303       (python_scanner.py mapping)  — hashlib weak hash

The fix tiers weak-hash by *purpose*:
  * NON-security MD5/SHA1 (cache key, ETag, dedup, checksum of non-secret data)
    -> MEDIUM, below the fail-on:high blocking gate (informative, not blocking).
  * SECURITY-context MD5/SHA1 (password/token/secret/sign/HMAC) -> HIGH, still
    a real, blocking finding.

Both sides are asserted here. If a genuine security-context weak-hash ever stops
firing HIGH, side (b) fails; if a benign cache/ETag hash ever drives a blocking
HIGH again, side (a) fails. This runs on the REAL production scan path
(MedusaParallelScanner + standardize_issue — the same path parallel.py uses to
build the findings list), not on to_dict()/source-grep, so it can't false-green.
"""
import re
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures — two tiny files, one benign (non-security) and one security-context.
# ---------------------------------------------------------------------------

# NON-security weak hashing: cache keys, ETags, HTML node IDs, content dedup.
# None of this is a vulnerability; none of it should drive a blocking verdict.
NON_SECURITY_SRC = '''\
import hashlib


def cache_key(url: str) -> str:
    # cache key for a memoized fetch — not security
    return hashlib.md5(url.encode()).hexdigest()


def etag(body: bytes) -> str:
    # HTTP ETag for content addressing — not security
    return hashlib.sha1(body).hexdigest()


def node_id(raw: str) -> str:
    # short stable id for an HTML anchor — not security
    return hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]


def content_dedup(chunk: bytes) -> str:
    return hashlib.md5(chunk).hexdigest()
'''

# SECURITY-context weak hashing: password hashing and token signing. This is a
# genuine, exploitable weakness and MUST remain a blocking HIGH finding.
SECURITY_SRC = '''\
import hashlib


def hash_password(password: str) -> str:
    # storing a password digest with MD5 — broken, must stay HIGH
    return hashlib.md5(password.encode()).hexdigest()


def sign_token(token: str) -> str:
    # deriving a token signature with SHA1 — broken, must stay HIGH
    token_signature = hashlib.sha1(token.encode()).hexdigest()
    return token_signature
'''

# rule_ids / message signature that identify a weak-hash finding regardless of
# which scanner (native regex rules or bandit) produced it.
_CRYPTO_RULE_IDS = {
    "WEB-CRYPTO-001", "SAST-CRYPTO-001", "SAST-CRYPTO-002",
    "SAST-CRYPTO-003", "B324", "B303",
}
_CRYPTO_MSG = re.compile(r"(?i)\b(?:md5|sha1|weak hash)\b")
_BLOCKING = {"HIGH", "CRITICAL"}


def _crypto_findings(findings):
    out = []
    for f in findings:
        rid = str(f.get("rule_id") or "")
        msg = str(f.get("issue") or "")
        if rid in _CRYPTO_RULE_IDS or _CRYPTO_MSG.search(msg):
            out.append(f)
    return out


def _scan_dir(path: Path):
    """Scan ``path`` on the real production path and return standardized
    findings — identical to how parallel.py builds its pre-filter list."""
    from medusa.core.finding_schema import standardize_issue
    from medusa.core.parallel import MedusaParallelScanner

    scanner = MedusaParallelScanner(
        project_root=path,
        workers=2,
        use_cache=False,
    )
    files = scanner.find_scannable_files()
    results = scanner.scan_parallel(files)
    return [
        standardize_issue(issue, result)
        for result in results
        for issue in result.issues
    ]


@pytest.fixture(scope="module")
def scans():
    """Scan the non-security and security fixtures once for the module."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        ns = base / "non_security"
        sec = base / "security"
        ns.mkdir()
        sec.mkdir()
        (ns / "cache_util.py").write_text(NON_SECURITY_SRC)
        (sec / "auth_util.py").write_text(SECURITY_SRC)
        yield {
            "non_security": _crypto_findings(_scan_dir(ns)),
            "security": _crypto_findings(_scan_dir(sec)),
        }


# ---------------------------------------------------------------------------
# Side (a): non-security weak hashing must NOT drive a blocking (HIGH+) finding.
# ---------------------------------------------------------------------------

def test_non_security_weak_hash_is_not_blocking(scans):
    blocking = [
        f for f in scans["non_security"]
        if str(f.get("severity", "")).upper() in _BLOCKING
    ]
    assert not blocking, (
        "Non-security MD5/SHA1 (cache key / ETag / node id / dedup) produced a "
        "BLOCKING HIGH+ finding — this is the false positive the fix removes:\n"
        + "\n".join(
            f"  [{f.get('severity')}] {f.get('rule_id')} L{f.get('line')}: {f.get('issue')}"
            for f in blocking
        )
    )


def test_non_security_weak_hash_still_detected_below_gate(scans):
    """The weakness is not *ignored* — it is still reported, just below the
    blocking gate (MEDIUM/LOW). This proves the fix is a demotion, not a
    deletion of coverage."""
    assert scans["non_security"], (
        "Non-security weak hash produced no finding at all — the fix should "
        "DEMOTE these to MEDIUM, not silence detection entirely."
    )


# ---------------------------------------------------------------------------
# Side (b): security-context weak hashing MUST still fire a blocking HIGH.
# ---------------------------------------------------------------------------

def test_security_context_weak_hash_still_high(scans):
    blocking = [
        f for f in scans["security"]
        if str(f.get("severity", "")).upper() in _BLOCKING
    ]
    assert blocking, (
        "Security-context MD5/SHA1 (password hashing / token signing) produced "
        "NO blocking HIGH+ finding — the fix has over-demoted and lost a real "
        "detection. All crypto findings on the security fixture:\n"
        + "\n".join(
            f"  [{f.get('severity')}] {f.get('rule_id')} L{f.get('line')}: {f.get('issue')}"
            for f in scans["security"]
        )
    )
