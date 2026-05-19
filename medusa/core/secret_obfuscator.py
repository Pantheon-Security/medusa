"""Masking and report I/O for `medusa secrets`.

Two concerns kept together because they're the bridge between the
scanner (which emits raw secrets) and everything that later sees them:
the human-facing CLI output and the on-disk report consumed by the
purger.

Masking policy
--------------
* Default: render `<prefix>***...***` where prefix length comes from the
  canonical `SecretPattern.mask_prefix` for the matching rule.
* Asterisks are a fixed count, not `len(secret)` — secret length is
  itself an oracle in some contexts.
* `--reveal` bypasses masking entirely. The CLI requires a typed
  confirmation before passing `reveal=True` to anything in this module.

Report I/O
----------
* Reports land in `~/.medusa/secrets-scan/`. They are never written to
  the project tree (no `.medusa/reports/` like the project scanner).
* Reports always store raw secrets — they're useless for the purger
  otherwise. The directory is created with 0o700 so other users on the
  host can't read it.
* Each scan produces one report file: `secrets-YYYYMMDD-HHMMSS.json`.
  Most-recent symlinked as `latest.json` for convenience.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from medusa.core.secret_patterns import SECRET_PATTERNS_BY_ID
from medusa.scanners.ai_chat_history_scanner import FileScanResult, SecretFinding


def mask_secret(secret: str, prefix_chars: int) -> str:
    """Render a credential with `prefix_chars` leading chars revealed.

    >>> mask_secret("pypi-AgEIcHl...", 10)
    'pypi-AgEIc***...***'
    """
    if not secret:
        return ""
    prefix = secret[:prefix_chars] if len(secret) > prefix_chars else secret
    return f"{prefix}***...***"


def mask_finding(finding: SecretFinding) -> str:
    pattern = SECRET_PATTERNS_BY_ID.get(finding.rule_id)
    prefix = pattern.mask_prefix if pattern else 6
    return mask_secret(finding.secret, prefix)


# ---------------------------------------------------------------------------
# Report I/O
# ---------------------------------------------------------------------------

def reports_dir() -> Path:
    """Return the directory where scan reports are stored.

    Created on demand with 0o700 (owner-only). The path is fixed at
    `~/.medusa/secrets-scan/` — deliberately outside any project tree
    so reports can't be checked in by accident.
    """
    base = Path.home() / ".medusa" / "secrets-scan"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    # If the directory pre-existed with looser permissions, tighten it.
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


@dataclass
class ReportEntry:
    """One finding as serialized in the on-disk report."""
    rule_id: str
    name: str
    issuer: str
    kind: str
    severity: str
    file_path: str
    source_label: str
    line: int
    column: int
    byte_start: int
    byte_end: int
    secret: str  # raw — see module docstring


def _finding_to_entry(f: SecretFinding) -> ReportEntry:
    severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return ReportEntry(
        rule_id=f.rule_id,
        name=f.name,
        issuer=f.issuer,
        kind=f.kind,
        severity=severity,
        file_path=str(f.file_path),
        source_label=f.source_label,
        line=f.line,
        column=f.column,
        byte_start=f.byte_start,
        byte_end=f.byte_end,
        secret=f.secret,
    )


def write_report(results: Iterable[FileScanResult], scan_id: Optional[str] = None) -> Path:
    """Persist a scan as JSON. Returns the path to the report file.

    `scan_id` overrides the default timestamp-based identifier; tests
    use this for deterministic filenames.
    """
    if scan_id is None:
        scan_id = datetime.now().strftime("%Y%m%d-%H%M%S")

    entries: List[ReportEntry] = []
    files_scanned = 0
    files_with_findings = 0
    for r in results:
        files_scanned += 1
        if r.findings:
            files_with_findings += 1
        for f in r.findings:
            entries.append(_finding_to_entry(f))

    report = {
        "scan_id": scan_id,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "files_scanned": files_scanned,
            "files_with_findings": files_with_findings,
            "total_findings": len(entries),
        },
        "findings": [asdict(e) for e in entries],
    }

    out_dir = reports_dir()
    out_path = out_dir / f"secrets-{scan_id}.json"
    tmp_path = out_path.with_suffix(".json.tmp")
    # Write 0o600 from the outset — never let raw secrets land at 0o644.
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    tmp_path.replace(out_path)

    # Maintain a `latest.json` symlink for the purger and convenience.
    latest = out_dir / "latest.json"
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(out_path.name)
    except OSError:
        # On filesystems where symlinks aren't permitted (e.g. some
        # Windows configs), silently skip — the purger can still locate
        # the most-recent file by mtime.
        pass

    return out_path


def load_latest_report() -> Optional[dict]:
    """Load the most recent report, or None if there isn't one."""
    out_dir = reports_dir()
    latest = out_dir / "latest.json"
    if latest.exists():
        with open(latest, "r", encoding="utf-8") as f:
            return json.load(f)
    # Fallback: scan the directory by mtime.
    candidates = sorted(
        out_dir.glob("secrets-*.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    if not candidates:
        return None
    with open(candidates[0], "r", encoding="utf-8") as f:
        return json.load(f)


def load_report(scan_id: str) -> Optional[dict]:
    """Load a named scan report. Returns None if missing."""
    path = reports_dir() / f"secrets-{scan_id}.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
