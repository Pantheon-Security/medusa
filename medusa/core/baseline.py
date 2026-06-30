"""Fingerprint baseline / suppression support.

A *baseline* is a saved set of finding fingerprints representing the known,
accepted state of a project. On a later scan, findings whose fingerprint is in
the baseline are suppressed so that only NEW findings surface — the standard
"ratchet" workflow for adopting a scanner on an existing codebase without
drowning in pre-existing noise.

The fingerprint formula here is intentionally IDENTICAL to the one the SARIF
reporter emits (``medusa/core/reporter.py``):

    sha256("{rule_id}:{file}:{line}:{issue}")

so that a fingerprint written by ``--write-baseline`` matches the
``fingerprints["medusa/v1"]`` value in a SARIF report for the same finding.
Keep the two in lock-step; if the reporter formula changes, change it here too.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def _finding_field(finding: Any, *names: str, default: str = "") -> Any:
    """Read the first present field from a finding (dict or object).

    Scan results reach the CLI either as plain dicts (cache hits, most
    scanners) or as ``ScannerIssue``-style objects. The reporter normalizes
    both into a finding dict with keys ``rule_id`` / ``file`` / ``line`` /
    ``issue`` before fingerprinting; we accept the raw forms too and map the
    common aliases so the resulting fingerprint matches regardless of source.
    """
    for name in names:
        if isinstance(finding, dict):
            if name in finding and finding[name] is not None:
                return finding[name]
        else:
            value = getattr(finding, name, None)
            if value is not None:
                return value
    return default


def finding_fingerprint(finding: Any) -> str:
    """Return the stable SHA-256 fingerprint for a single finding.

    Mirrors the reporter's formula exactly:
        sha256("{rule_id}:{file}:{line}:{issue}")

    ``finding`` may be the reporter's normalized finding dict, a raw scanner
    issue dict, or a ``ScannerIssue`` object; the relevant fields are resolved
    via their common aliases so all three produce the same digest for the same
    underlying finding.
    """
    rule_id = _finding_field(finding, "rule_id", default="")
    file = _finding_field(finding, "file", "file_path", default="")
    line = _finding_field(finding, "line", "line_number", default="")
    issue = _finding_field(finding, "issue", "issue_text", "message", default="")

    fingerprint_input = f"{rule_id}:{file}:{line}:{issue}"
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()


def load_baseline(path: str | Path) -> Set[str]:
    """Load a baseline file into a set of fingerprint strings.

    Accepts either of the two shapes ``write_baseline`` may have produced
    across versions:
      * a bare JSON list of fingerprint strings, or
      * a JSON object with a ``"fingerprints"`` list (plus metadata).

    A missing file, unreadable file, or malformed content yields an empty set
    rather than raising — a baseline is an optimization, never a hard
    dependency, so a broken baseline must not abort a scan.
    """
    p = Path(path)
    if not p.exists():
        return set()

    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return set()

    if isinstance(data, list):
        return {str(fp) for fp in data if fp}
    if isinstance(data, dict):
        fingerprints = data.get("fingerprints")
        if isinstance(fingerprints, list):
            return {str(fp) for fp in fingerprints if fp}
    return set()


def write_baseline(findings: List[Any], path: str | Path) -> int:
    """Write the fingerprints of ``findings`` to ``path`` as JSON.

    The on-disk shape is an object with metadata and a sorted, de-duplicated
    ``fingerprints`` list so the file is stable across runs (diff-friendly,
    no spurious churn from ordering). Returns the number of unique
    fingerprints written.
    """
    from medusa import __version__

    fingerprints = sorted({finding_fingerprint(f) for f in findings})

    document = {
        "version": __version__,
        "tool": "medusa",
        "count": len(fingerprints),
        "fingerprints": fingerprints,
    }

    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
        f.write("\n")

    return len(fingerprints)


def apply_baseline(
    findings: List[Any], baseline_set: Set[str]
) -> Tuple[List[Any], List[Any]]:
    """Split ``findings`` into (kept, suppressed) by baseline membership.

    A finding is *suppressed* when its fingerprint is present in
    ``baseline_set``; everything else is *kept* and surfaces as a NEW finding.
    An empty baseline keeps everything (no-op).
    """
    if not baseline_set:
        return list(findings), []

    kept: List[Any] = []
    suppressed: List[Any] = []
    for finding in findings:
        if finding_fingerprint(finding) in baseline_set:
            suppressed.append(finding)
        else:
            kept.append(finding)
    return kept, suppressed
