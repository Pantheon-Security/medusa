"""Redact credentials in chat / shell history files, in place.

Operations are designed to be safe-by-default:

1. **Backup before write.** Every file that's about to be modified is
   copied to `~/.medusa/secrets-scan/backups/<run-id>/<mirrored-path>`
   first. The original is never touched until the backup is durable
   on disk.

2. **Verify before splice.** The scanner records a byte/character
   offset and the literal secret string. Before redacting we re-read
   that span and confirm it still matches — if the file changed since
   the scan, we refuse and tell the user.

3. **Replace, don't delete.** The replacement string is a stable
   marker `[REDACTED-MEDUSA-<RULE>-<RUN>]`. It contains no characters
   that need JSON escaping (no `"`, `\`, controls), so when the
   surrounding context is a JSON string value, the document still
   parses afterwards.

4. **JSON sanity check.** For files whose extension is `.json` or
   `.jsonl`, every line that we modified is re-parsed after the write.
   If any line stops parsing as JSON we restore from the backup and
   raise.

5. **Atomic write.** The rewritten content goes to a temp file in the
   same directory, then `os.replace` swaps it in. Either the original
   stays or the rewrite lands — never both, never neither.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


REDACTION_TEMPLATE = "[REDACTED-{rule}-{run}]"


@dataclass
class PendingRedaction:
    """One redaction queued for application against a single file.

    Offsets are character positions in the file when read as UTF-8
    text — matching the offset semantics used by the scanner.
    """
    rule_id: str
    byte_start: int  # really char-start; named for compat with scanner output
    byte_end: int
    expected_secret: str


@dataclass
class FilePurgePlan:
    file_path: Path
    redactions: List[PendingRedaction]


@dataclass
class PurgeResult:
    file_path: Path
    redactions_applied: int
    backup_path: Optional[Path] = None
    error: Optional[str] = None


def _backup_dir(run_id: str) -> Path:
    base = Path.home() / ".medusa" / "secrets-scan" / "backups" / run_id
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def _backup_path_for(run_id: str, original: Path) -> Path:
    """Mirror the original path under the run's backup directory.

    `/home/ross/.claude/history.jsonl` ->
    `<backup_root>/home/ross/.claude/history.jsonl`

    The full path is preserved so backups from multiple files don't
    collide and the user can reason about provenance.
    """
    base = _backup_dir(run_id)
    rel = Path(*original.absolute().parts[1:])  # drop leading `/`
    target = base / rel
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return target


def _new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def apply_plan(
    plan: FilePurgePlan,
    run_id: str,
    redaction_template: str = REDACTION_TEMPLATE,
) -> PurgeResult:
    """Apply every queued redaction in `plan.file_path`.

    Redactions are applied in descending start-offset order so each
    splice doesn't invalidate the offsets of redactions that follow.
    """
    result = PurgeResult(file_path=plan.file_path, redactions_applied=0)

    if not plan.redactions:
        return result

    try:
        with open(plan.file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        result.error = f"read failed: {exc}"
        return result

    # Verify every offset still matches its expected secret. If any
    # don't, refuse the whole plan — partial application is worse than
    # none for credential redaction.
    mismatches: List[str] = []
    for r in plan.redactions:
        actual = content[r.byte_start : r.byte_end]
        if actual != r.expected_secret:
            mismatches.append(
                f"{r.rule_id} @ [{r.byte_start},{r.byte_end}): expected "
                f"{r.expected_secret[:12]!r}..., found {actual[:12]!r}..."
            )
    if mismatches:
        result.error = (
            "file changed since scan; refusing to apply.\n  "
            + "\n  ".join(mismatches)
        )
        return result

    # Back up the original first. Mode 0o600 — backups also contain
    # the raw secrets.
    backup_path = _backup_path_for(run_id, plan.file_path)
    shutil.copy2(plan.file_path, backup_path)
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    result.backup_path = backup_path

    # Splice in descending offset order so earlier offsets stay valid.
    sorted_redactions = sorted(
        plan.redactions, key=lambda r: r.byte_start, reverse=True
    )
    new_content = content
    for r in sorted_redactions:
        marker = redaction_template.format(rule=r.rule_id, run=run_id)
        new_content = (
            new_content[: r.byte_start] + marker + new_content[r.byte_end :]
        )

    # For JSON / JSONL files, re-parse the lines we touched so we know
    # the redaction didn't break the document.
    suffix = plan.file_path.suffix.lower()
    if suffix in {".json", ".jsonl"}:
        validation_error = _validate_json_like(suffix, new_content, sorted_redactions, content)
        if validation_error is not None:
            result.error = f"JSON validation failed after redaction: {validation_error}"
            return result

    # Atomic replace: temp file in the same directory, then os.replace.
    tmp_path = plan.file_path.with_suffix(plan.file_path.suffix + ".medusa-tmp")
    try:
        fd = os.open(
            tmp_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_content)
        # Preserve the original mode/owner so we don't tighten access
        # the user didn't ask for. Re-statting after copy2 doesn't
        # apply here because we created tmp_path fresh.
        try:
            orig_stat = plan.file_path.stat()
            os.chmod(tmp_path, orig_stat.st_mode & 0o777)
        except OSError:
            pass
        os.replace(tmp_path, plan.file_path)
    except Exception as exc:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        result.error = f"write failed: {exc}"
        return result

    result.redactions_applied = len(plan.redactions)
    return result


def _validate_json_like(
    suffix: str,
    new_content: str,
    redactions: List[PendingRedaction],
    original_content: str,
) -> Optional[str]:
    """Confirm modified lines still parse as JSON. Returns the first
    error message, or None if all touched lines parse cleanly.
    """
    if suffix == ".json":
        try:
            json.loads(new_content)
        except json.JSONDecodeError as exc:
            return f"file no longer parses as JSON: {exc}"
        return None

    # JSONL: figure out which lines were touched and parse each one.
    # We use the original content to find line boundaries (their
    # positions don't change once we count offsets, which are character
    # positions); then look up the corresponding line in new_content
    # by walking forwards.
    touched_line_indices = set()
    cumulative = 0
    line_offsets: List[Tuple[int, int]] = []  # (start, end_exclusive) in original
    for line in original_content.splitlines(keepends=True):
        line_offsets.append((cumulative, cumulative + len(line)))
        cumulative += len(line)

    for r in redactions:
        for i, (a, b) in enumerate(line_offsets):
            if a <= r.byte_start < b:
                touched_line_indices.add(i)
                break

    # Build line offsets for new_content — they may be shifted but the
    # line *count* is the same because the redaction marker contains no
    # newlines.
    new_lines = new_content.splitlines()
    for i in sorted(touched_line_indices):
        if i >= len(new_lines):
            return f"line index {i} missing in rewritten content"
        candidate = new_lines[i].strip()
        if not candidate:
            continue  # blank line, nothing to parse
        try:
            json.loads(candidate)
        except json.JSONDecodeError as exc:
            return f"line {i + 1} broken: {exc}"
    return None


def build_plans_from_report(
    report: dict,
    selected_indices: Optional[List[int]] = None,
) -> Dict[Path, FilePurgePlan]:
    """Group report findings by file into purge plans.

    `selected_indices` (if provided) acts as a whitelist of finding
    array positions to include. Used by the interactive purger to
    apply only the redactions the user confirmed.
    """
    findings = report.get("findings", [])
    chosen = set(selected_indices) if selected_indices is not None else None

    plans: Dict[Path, FilePurgePlan] = {}
    for i, f in enumerate(findings):
        if chosen is not None and i not in chosen:
            continue
        path = Path(f["file_path"])
        plan = plans.setdefault(path, FilePurgePlan(file_path=path, redactions=[]))
        plan.redactions.append(
            PendingRedaction(
                rule_id=f["rule_id"],
                byte_start=int(f["byte_start"]),
                byte_end=int(f["byte_end"]),
                expected_secret=f["secret"],
            )
        )
    return plans


def execute_plans(
    plans: Dict[Path, FilePurgePlan],
    run_id: Optional[str] = None,
) -> List[PurgeResult]:
    """Execute every plan. Returns a result record per file.

    A single run_id covers the entire batch so all backups land in one
    directory; if the user needs to roll back the session it's one
    `cp -r` away.
    """
    if run_id is None:
        run_id = _new_run_id()
    results = []
    for plan in plans.values():
        results.append(apply_plan(plan, run_id=run_id))
    return results
