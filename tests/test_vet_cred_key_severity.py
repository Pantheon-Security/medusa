"""Gate — a committed private-key file is a CRITICAL credential exposure
(-> DO_NOT_INSTALL), aligning the native CredentialFileScanner path with GitLeaks
(which already maps private-key -> CRITICAL) and scan_api's "leaked live secrets still
hard-block" intent.

A committed TOKEN file (.npmrc auth token, docker/netrc/s3cfg) stays HIGH (-> CAUTION
for a single one) — a leaked token is serious but the key is the higher-severity plant.
Test-fixture certs remain exempt (CredentialFileScanner skips test paths), so no new FPs.

The key fixture is GENERATED at runtime (openssl) so no key material lives in this test's
source — otherwise this file would itself trip the very detection it exercises.
"""
import shutil
import subprocess

import pytest

import medusa.core.scan_api as api
from medusa.scanners.base import Severity
from medusa.scanners.credential_file_scanner import CredentialFileScanner


def _gen_key(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available to generate a throwaway key fixture")
    keyfile = tmp_path / "server.key"
    subprocess.run([openssl, "genrsa", "-out", str(keyfile), "2048"],
                   check=True, capture_output=True)
    return keyfile


# --- scanner: private-key CRITICAL, token HIGH -------------------------------- #
def test_private_key_material_is_critical(tmp_path):
    iss = CredentialFileScanner().scan_file(_gen_key(tmp_path)).issues
    assert iss, "a committed private-key file must be flagged"
    assert any(i.severity == Severity.CRITICAL for i in iss), [i.severity.value for i in iss]


def test_npmrc_token_stays_high(tmp_path):
    f = tmp_path / ".npmrc"
    f.write_text("//registry.npmjs.org/:_authToken=abcdef1234567890xyz\n")
    iss = CredentialFileScanner().scan_file(f).issues
    assert iss, ".npmrc auth token must be flagged"
    assert all(i.severity == Severity.HIGH for i in iss), [i.severity.value for i in iss]


# --- verdict: CRITICAL key -> DNI; single HIGH token -> CAUTION --------------- #
def _f(sev, file="src/creds"):
    return {"rule_id": "MEDUSA-CRED-001", "scanner": "CredentialFileScanner",
            "severity": sev, "file": file, "line": 1, "issue": ""}


def test_leaked_private_key_repo_is_dni():
    r = api._summarize([_f("CRITICAL", "src/server.key")], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]


def test_single_token_file_is_caution():
    r = api._summarize([_f("HIGH", "src/.npmrc")], root="/x")
    assert r["verdict"] == api.CAUTION, r["verdict"]
