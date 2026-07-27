"""Canonical path-classification for the vet/scan trust surface.

Single source of truth for "is this a non-executing test/fixture path?" and "is
this a live-payload file (executes or carries a real secret regardless of the dir
it sits in)?". Previously these were defined four times — in ``scan_api``,
``reporter``, ``credential_file_scanner`` and (as a fifth near-copy) ``parallel``
— with divergent membership, so ``medusa scan`` and ``medusa vet`` could disagree
about the same file (CR-007). This module is intentionally dependency-free (only
``pathlib``) so every layer can import it without a cycle.
"""
from __future__ import annotations

from pathlib import Path

# Non-executing test/fixture/example dir components — the UNION of every prior
# definition (scan_api's JVM test source-sets, credential_file_scanner's
# e2e/__fixtures__/testfixtures/mock, reporter's base set). A finding whose path
# includes one of these is test-data, not an install-risk signal — EXCEPT a
# live-payload file (see below), which stays a signal wherever it sits.
TEST_DATA_DIRS = frozenset({
    "test", "tests", "testing", "__tests__", "spec", "specs",
    "vectors", "testdata", "test_data", "fixtures", "fixture",
    "__fixtures__", "testfixtures",
    "examples", "example", "samples", "sample", "mocks", "mock", "e2e",
    # Kotlin/Java multiplatform + gradle test source sets
    "jvmtest", "androidtest", "commontest", "jstest", "nativetest", "integrationtest",
})


def is_test_data_path(file_path) -> bool:
    """True if any path component is a recognized non-executing test-data dir."""
    parts = str(file_path or "").replace("\\", "/").lower().split("/")
    return any(p in TEST_DATA_DIRS for p in parts)


# A LIVE-payload file executes or carries a real secret regardless of the
# directory it sits in — a real mcp.json, skill/install script, credential file,
# or payload image parked in tests/fixtures/ IS an install risk (an attacker just
# picks a "test-data" dir to evade vet). Unlike an attack STRING inside a dataset
# (which the test-data exclusion legitimately dismisses), these stay a signal.
# Superset of scan_api's set with the credential filenames parallel.py used
# (.netrc/.dockercfg/.pgpass/.s3cfg).
LIVE_PAYLOAD_EXACT = frozenset({
    "mcp.json", ".mcp.json", "mcp-config.json", "mcp_config.json",
    "claude_desktop_config.json", "skill.md", "settings.json", "settings.local.json",
    "install.sh", "setup.sh", "preinstall.sh", "postinstall.sh",
    ".npmrc", ".pypirc", ".git-credentials", "credentials",
    ".netrc", ".dockercfg", ".pgpass", ".s3cfg",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd",
})
LIVE_PAYLOAD_SUFFIX = (
    ".env", ".pem", ".key",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff",
)


def is_live_payload_file(file_path) -> bool:
    """True if the file executes / carries a real secret regardless of directory."""
    if not file_path:
        return False
    name = Path(str(file_path)).name.lower()
    return (name in LIVE_PAYLOAD_EXACT
            or name.startswith(".env")
            or name.endswith(LIVE_PAYLOAD_SUFFIX))
