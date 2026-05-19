"""Scan host-side conversation/history files for leaked credentials.

Distinct from the project-scoped scanners in this directory: this one is
invoked only via `medusa secrets scan` (host scope, ~/) and never via
`medusa scan` (project scope, cwd). It does not register with the global
scanner_registry — that keeps host-only patterns out of normal project
scans and the cache pipeline.

The scanner produces `SecretFinding` records (defined here, not the
project-scoped `ScannerIssue`) which carry byte-precise offsets so the
companion purger can redact the credential in place without disturbing
the rest of the file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from medusa.core.secret_patterns import (
    SECRET_PATTERNS,
    SecretPattern,
)
from medusa.scanners.base import Severity


@dataclass
class SecretFinding:
    """One credential occurrence located by the scanner.

    `byte_start` / `byte_end` are offsets into the file as read with UTF-8
    decoding — the purger uses these to perform precise replacement.
    `secret` holds the raw matched value; callers must mask before display.
    """
    rule_id: str
    name: str
    issuer: str
    kind: str
    severity: Severity
    file_path: Path
    line: int
    column: int
    byte_start: int
    byte_end: int
    secret: str
    source_label: str = ""  # populated by the discovery layer ("claude-code", "bash", ...)


@dataclass
class FileScanResult:
    file_path: Path
    findings: List[SecretFinding] = field(default_factory=list)
    error: Optional[str] = None
    bytes_scanned: int = 0


# Files larger than this are skipped to keep scans interactive. Chat
# histories that get this big almost certainly have older copies the
# user would rather look at separately.
_MAX_FILE_BYTES = 32 * 1024 * 1024  # 32 MB


def scan_file(
    file_path: Path,
    patterns: Optional[Iterable[SecretPattern]] = None,
    source_label: str = "",
) -> FileScanResult:
    """Scan a single file for any of the configured secret patterns.

    The file is read once as UTF-8 (with replacement for invalid bytes,
    so binary stretches don't abort the scan) and each pattern is applied
    over the whole text. Matching uses `re.finditer` so we get exact
    offsets for redaction.
    """
    patterns = list(patterns) if patterns is not None else SECRET_PATTERNS
    result = FileScanResult(file_path=file_path)

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        result.error = f"stat failed: {exc}"
        return result

    if size > _MAX_FILE_BYTES:
        result.error = f"skipped: {size} bytes exceeds {_MAX_FILE_BYTES}"
        return result

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as exc:
        result.error = f"read failed: {exc}"
        return result

    result.bytes_scanned = len(text)

    # Build a line-offset index once so we can convert byte offsets to
    # (line, column) cheaply for every match.
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def offset_to_line_col(offset: int) -> tuple[int, int]:
        # Binary search would be tidier but the list is small in practice
        # (line count of a chat-history file). Linear from the end is fine.
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - line_starts[lo] + 1

    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            secret = match.group(0)
            line, column = offset_to_line_col(match.start())
            result.findings.append(
                SecretFinding(
                    rule_id=pattern.rule_id,
                    name=pattern.name,
                    issuer=pattern.issuer,
                    kind=pattern.kind,
                    severity=pattern.severity,
                    file_path=file_path,
                    line=line,
                    column=column,
                    byte_start=match.start(),
                    byte_end=match.end(),
                    secret=secret,
                    source_label=source_label,
                )
            )

    return result


def scan_paths(
    paths: Iterable[Path],
    source_label_for: Optional[dict] = None,
) -> List[FileScanResult]:
    """Scan a collection of paths. Caller-provided source labels keep the
    UI grouping (Claude Code / Cursor / bash / ...) sensible.
    """
    source_label_for = source_label_for or {}
    results: List[FileScanResult] = []
    for path in paths:
        label = source_label_for.get(path, "")
        results.append(scan_file(path, source_label=label))
    return results
