"""Shared hardened git-clone helper.

The security-critical clone hardening (absolute git binary so a PATH shim can't
intercept the clone, shallow / single-branch / blob-size cap, an env that never
prompts for credentials and skips LFS smudging, a wall-clock timeout, atexit
temp cleanup, and credential redaction of any stderr) lived in two places —
:func:`medusa.core.scan_api._clone_repo` and ``cli._scan_git_repo`` — and would
drift. This is the single source of truth (CR-020).

The caller is responsible for URL validation / host allow-listing BEFORE calling
this; this helper only performs the hardened clone of an already-vetted URL.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import subprocess
import tempfile

# Default wall-clock budget for a clone. A private/nonexistent repo would
# otherwise hang for a long time even with prompts disabled.
CLONE_TIMEOUT = 120


def clone_hardened(url: str, prefix: str = "medusa-vet-", timeout: int = CLONE_TIMEOUT) -> str:
    """Shallow, hardened clone of ``url`` into a fresh temp dir; return its path.

    Raises :class:`RuntimeError` on any failure (missing git, timeout, or a
    non-zero clone) with credentials stripped from the message. The temp dir is
    registered for atexit cleanup and also removed eagerly on failure.
    """
    git_bin = shutil.which("git")
    if not git_bin:
        raise RuntimeError("git not found on PATH — cannot clone repository")

    tmp_dir = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, tmp_dir, True)

    # Never prompt for credentials on the TTY, disable any askpass helper, and
    # skip LFS smudging (we only need the tree to scan, not large binaries).
    git_env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }

    try:
        result = subprocess.run(
            [git_bin, "clone", "--depth", "1", "--single-branch",
             "--filter=blob:limit=5m", url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"git clone timed out after {timeout}s")

    if result.returncode != 0:
        # Strip auth tokens from error output (https://token@host -> https://host).
        stderr = re.sub(r"https?://[^@\s]+@", "https://", (result.stderr or "").strip())
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {stderr or 'unknown error'}")

    return tmp_dir
