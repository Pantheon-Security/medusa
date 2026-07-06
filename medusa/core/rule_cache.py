"""Process- and disk-level cache of parsed+compiled MEDUSA rules (PR-004).

Materializing the rule corpus (~42k rules / ~108k regex patterns) is expensive:
a full YAML parse plus regex compilation plus the pre-load integrity scan costs
~70s cold. ``medusa vet`` — the command wired into the Claude Code PreToolUse
install gate — forces ``use_cache=False`` so every vet re-scans the *target*
fresh. That flag must NOT also force a fresh *rule parse*: the rule corpus is
byte-identical between vets, so re-parsing it on every invocation is pure waste
(a ~75s hang before a git clone that agents route around).

This module caches the parsed corpus independently of the per-file scan-result
cache, keyed on a stat fingerprint of the rule files:

  * an in-process, module-level dict (:data:`_MEM`) — shared across every scanner
    instance and across repeated vets in one long-lived process (e.g. the MCP
    gatekeeper), and inherited for free by ``fork()`` Pool workers via COW;
  * an HMAC-verified pickle on disk (``~/.medusa/cache/rules/``) — so a *fresh*
    ``medusa vet`` CLI/hook process skips the parse AND the integrity scan.

Security: the on-disk blob is deserialized with ``pickle``, so an attacker who
could plant a file in the cache dir would get code execution at load time. We
defend exactly as the result cache does — an HMAC-SHA256 over the blob with a
machine-local 0600 key, verified BEFORE the blob is ever unpickled. A missing
key, fingerprint mismatch, HMAC mismatch, or any load error silently discards
the cache and falls back to a fresh parse (fail-safe: never fail-open, and a
tampered cache can never inject a rule or suppress a finding).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import secrets
from pathlib import Path
from typing import Dict, List, Optional

# In-process cache: fingerprint -> parsed rule list. Module scope so every
# scanner instance in the process (and fork-inherited Pool workers) share one
# parsed copy, and repeated vets in a persistent process pay the parse once.
_MEM: Dict[str, list] = {}

# Cache lives beside the result cache so one 0700 dir holds all machine-local
# MEDUSA state and shares the same HMAC key.
_CACHE_DIR = Path.home() / ".medusa" / "cache"
_RULES_DIR = _CACHE_DIR / "rules"
_HMAC_KEY_FILE = _CACHE_DIR / ".hmac_key"

# Bump when the on-disk pickle layout or the Rule class shape changes so an old
# blob is treated as a miss rather than unpickled into an incompatible object.
_FORMAT = "v1"


def _rule_files(rules_dir: Path) -> list:
    """Return the rule files that ``RuleLoader.load_all_rules`` actually loads.

    Mirrors the loader's traversal: one level of subdirectories under
    ``rules_dir`` (``<subdir>/*.yaml``), excluding the non-loaded ``archive`` and
    ``runtime`` dirs and any ``*_runtime.yaml`` (paid-tier proxy rules). Kept in
    sync with :meth:`RuleLoader.load_all_rules` so the fingerprint tracks exactly
    the corpus that was parsed.
    """
    out = []
    # Resolve so a relative and an absolute caller for the same dir share one
    # fingerprint (the fingerprint mixes in each file's path).
    rules_dir = Path(rules_dir).resolve()
    for yf in sorted(rules_dir.glob("*/*.yaml")):
        parts = yf.parts
        if "archive" in parts or "runtime" in parts:
            continue
        if yf.name.endswith("_runtime.yaml"):
            continue
        out.append(yf)
    return out


def corpus_fingerprint(rules_dir: Path) -> str:
    """Stat-based fingerprint (path + size + mtime) of the loaded rule corpus.

    Stat-based rather than content-based to stay cheap (no ~48MB read on every
    scan init) — the same trade-off the result cache makes. Any edit that changes
    a rule's behaviour changes its size or mtime and so busts the cache.
    """
    hasher = hashlib.sha256()
    hasher.update(f"{_FORMAT}|".encode())
    files = _rule_files(rules_dir)
    hasher.update(str(len(files)).encode())
    for yf in files:
        try:
            st = yf.stat()
            hasher.update(f"{yf}:{st.st_size}:{st.st_mtime_ns}".encode())
        except OSError:
            # A vanished/unreadable file changes the fingerprint (fewer entries),
            # which is the correct invalidation.
            pass
    return hasher.hexdigest()[:32]


def _hmac_key() -> Optional[bytes]:
    """Load (or create) the machine-local HMAC key shared with the result cache.

    Returns None only if the key can neither be read nor created — in which case
    the caller declines to trust/write any on-disk blob (fail-safe).
    """
    try:
        if _HMAC_KEY_FILE.exists():
            key = _HMAC_KEY_FILE.read_bytes().strip()
            if len(key) >= 32:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32).encode()
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(_HMAC_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except OSError:
        return None


def _blob_path(fingerprint: str) -> Path:
    return _RULES_DIR / f"rules-{fingerprint}.pkl"


def load(rules_dir: Path) -> Optional[list]:
    """Return the cached parsed rule list for ``rules_dir``, or None on any miss.

    Checks the in-process cache first, then an HMAC-verified on-disk pickle. A
    None return means the caller must parse from source (and should then call
    :func:`store`). The HMAC is verified before the blob is unpickled, so a
    planted/corrupt cache can never execute code or inject rules.
    """
    fp = corpus_fingerprint(rules_dir)
    cached = _MEM.get(fp)
    if cached is not None:
        return cached

    path = _blob_path(fp)
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    key = _hmac_key()
    if key is None:
        return None
    # Envelope: <64-hex-char HMAC><newline><pickle bytes>. Split and verify the
    # MAC over the pickle bytes BEFORE unpickling anything.
    sep = raw.find(b"\n")
    if sep != 64:
        return None
    stored_mac = raw[:sep]
    blob = raw[sep + 1:]
    expected = hmac.new(key, blob, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(stored_mac, expected):
        return None
    try:
        rules = pickle.loads(blob)
    except Exception:
        return None
    if not isinstance(rules, list):
        return None
    _MEM[fp] = rules
    return rules


def store(rules_dir: Path, rules: list, persist: bool = True) -> None:
    """Cache ``rules`` for ``rules_dir`` in-process and (optionally) on disk.

    The in-process cache is always populated. The disk pickle is written only
    when ``persist`` is True — callers pass ``persist=False`` when the corpus was
    loaded WITHOUT the integrity scan, so an unvetted parse can never be promoted
    to a disk blob that later loads skip integrity against. Disk write failures
    are swallowed: the cache is an optimization, never required for correctness.
    """
    fp = corpus_fingerprint(rules_dir)
    _MEM[fp] = rules
    if not persist:
        return
    key = _hmac_key()
    if key is None:
        return
    try:
        blob = pickle.dumps(rules, protocol=pickle.HIGHEST_PROTOCOL)
        mac = hmac.new(key, blob, hashlib.sha256).hexdigest().encode()
        _RULES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = _blob_path(fp)
        tmp = path.with_suffix(".pkl.tmp")
        with open(tmp, "wb") as f:
            f.write(mac)
            f.write(b"\n")
            f.write(blob)
        os.replace(tmp, path)
        _prune_stale(keep=fp)
    except Exception:
        pass


def _prune_stale(keep: str) -> None:
    """Delete disk blobs for other fingerprints so a rule update doesn't leave an
    unbounded pile of stale caches. Best-effort."""
    try:
        for f in _RULES_DIR.glob("rules-*.pkl"):
            if f.name != f"rules-{keep}.pkl":
                f.unlink(missing_ok=True)
    except OSError:
        pass
