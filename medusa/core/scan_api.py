"""Programmatic MEDUSA scan API.

A thin, import-safe wrapper over the existing scan internals so non-CLI
callers (the MCP gatekeeper server, native hooks) can vet a path, repo,
or skill and get a structured verdict back — without going through Click,
``sys.exit``, report-file generation, or terminal output.

Nothing here reimplements detection. It drives:
  - ``MedusaParallelScanner`` (medusa/core/parallel.py) for code/config scans
  - the FP filter (medusa/core/fp_filter.py) so verdicts match what the CLI
    would show a user (post-screening)
  - the secrets engine (ai_chat_history_scanner.scan_file + chat_history
    discovery) for credential scans

Verdict thresholds follow the SkillSpector model:
    any CRITICAL, or >= 3 HIGH                  -> DO_NOT_INSTALL
    any HIGH, or >= 3 MEDIUM                    -> CAUTION
    otherwise                                  -> SAFE

IMPORTANT: the underlying scanner prints a banner/progress to stdout. When
this API is driven by an MCP stdio server, stdout is the JSON-RPC channel,
so every scan runs with stdout redirected to devnull (see ``_quiet``).
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import sys
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Verdict labels (stable strings — the MCP tools and hooks key off these).
SAFE = "SAFE"
CAUTION = "CAUTION"
DO_NOT_INSTALL = "DO_NOT_INSTALL"

# Severity weights for the numeric score (higher = worse).
_SEVERITY_WEIGHT = {
    "CRITICAL": 100,
    "HIGH": 25,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}

# Number of top findings to surface in a verdict.
_TOP_FINDINGS = 8

# Serializes the global sys.stdout swap in _quiet. FastMCP runs tool handlers in
# a thread pool, so two concurrent scans could otherwise interleave their swaps
# and one call would close a devnull fd another call still owns
# ("I/O operation on closed file"). The lock makes the swap+scan+restore atomic
# per process (CR-018).
_QUIET_LOCK = threading.Lock()


@contextlib.contextmanager
def _quiet():
    """Redirect stdout to devnull for the duration of a scan.

    The parallel scanner prints a banner and progress to stdout. That would
    corrupt an MCP stdio session (stdout carries JSON-RPC), so we swallow it.
    stderr is left alone so genuine errors can still surface in logs.

    Guarded by a module-level lock so concurrent handlers (FastMCP thread pool)
    cannot clobber each other's stdout swap or close a shared fd.
    """
    with _QUIET_LOCK:
        devnull = open(os.devnull, "w")
        saved = sys.stdout
        try:
            sys.stdout = devnull
            with contextlib.redirect_stdout(devnull):
                yield
        finally:
            sys.stdout = saved
            devnull.close()


def _normalize_severity(value) -> str:
    sev = str(getattr(value, "value", value) or "MEDIUM").upper()
    return sev if sev in _SEVERITY_WEIGHT else "MEDIUM"


def _verdict_from_counts(counts: dict) -> str:
    """Map severity counts to a verdict label (SkillSpector thresholds)."""
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    med = counts.get("MEDIUM", 0)
    if crit >= 1 or high >= 3:
        return DO_NOT_INSTALL
    if high >= 1 or med >= 3:
        return CAUTION
    return SAFE


def _score_from_counts(counts: dict) -> int:
    """Numeric risk score (0 = clean, unbounded above)."""
    return sum(_SEVERITY_WEIGHT.get(sev, 0) * n for sev, n in counts.items())


def _extract_findings(scanner, results) -> list:
    """Turn raw ScanResults into standardized finding dicts + FP filtering.

    Mirrors the standardization block inside MedusaParallelScanner.generate_report
    (parallel.py) but WITHOUT generating any report files. We then apply the same
    FalsePositiveFilter the CLI applies so a programmatic verdict matches what a
    user would see post-screening.
    """
    from medusa.core.finding_schema import standardize_issue

    findings = []
    for result in results:
        for issue in result.issues:
            # Shared field-name fallbacks (CR-019); scan_api additionally
            # validates the severity string against the known weight table.
            f = standardize_issue(issue, result)
            f["severity"] = _normalize_severity(f["severity"])
            findings.append(f)

    # Apply the same FP filter the CLI uses (screening on, like a default scan).
    try:
        from medusa.core.fp_filter import FalsePositiveFilter
        fp_filter = FalsePositiveFilter(scanner.project_root, screening=True)
        findings, _likely_fps = fp_filter.filter_findings(findings)
    except Exception:
        # If the FP filter is unavailable, fall back to raw findings rather
        # than failing the whole vet — a verdict from raw findings is still
        # conservative (it can only be more cautious, never less).
        pass

    return findings


def _relativize(file_path, root) -> str:
    """Return ``file_path`` relative to ``root`` (best effort).

    Falls back to the bare basename when the path is outside ``root`` or not
    resolvable — either way the absolute path is not leaked. Used only on the
    redacted (MCP) path so an external agent never learns host filesystem
    layout.
    """
    if not file_path:
        return file_path
    try:
        p = Path(str(file_path)).resolve()
        if root is not None:
            return str(p.relative_to(Path(root).resolve()))
    except (ValueError, OSError):
        pass
    return Path(str(file_path)).name


def _summarize(findings: list, redact_snippets: bool = False, root=None) -> dict:
    """Build a verdict dict from standardized findings.

    ``redact_snippets`` (the MCP path) drops the matched-source ``issue`` body
    from ``top_findings`` and relativizes the file path, leaving only
    rule_id + severity + relative file:line. The CLI path (default False) is
    unchanged.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        counts[sev] = counts.get(sev, 0) + 1

    # Sort findings worst-first for the top list.
    ordered = sorted(
        findings,
        key=lambda f: -_SEVERITY_WEIGHT.get(f.get("severity", "MEDIUM"), 0),
    )
    top = []
    for f in ordered[:_TOP_FINDINGS]:
        entry = {
            "severity": f.get("severity"),
            "scanner": f.get("scanner"),
            "rule_id": f.get("rule_id"),
            "file": _relativize(f.get("file"), root) if redact_snippets else f.get("file"),
            "line": f.get("line"),
        }
        if not redact_snippets:
            entry["issue"] = (f.get("issue") or "")[:200]
        top.append(entry)

    return {
        "verdict": _verdict_from_counts(counts),
        "score": _score_from_counts(counts),
        "counts_by_severity": counts,
        "total_findings": len(findings),
        "top_findings": top,
    }


def vet_path(path, redact_snippets: bool = False) -> dict:
    """Scan a local directory or file and return a structured verdict.

    Returns a dict: {verdict, score, counts_by_severity, total_findings,
    top_findings, target, error?}. Never raises for an ordinary scan
    failure — a failed scan returns an ``error`` field and a CAUTION verdict
    so callers fail safe rather than fail open.

    ``redact_snippets`` (set by the MCP layer) drops matched-source bodies and
    relativizes file paths in ``top_findings``; the CLI path leaves them intact.
    """
    target = Path(path)
    if not target.exists():
        return {
            "verdict": CAUTION,
            "score": 0,
            "counts_by_severity": {},
            "total_findings": 0,
            "top_findings": [],
            "target": str(target),
            "error": f"path does not exist: {target}",
        }

    try:
        from medusa.core.parallel import MedusaParallelScanner
        with _quiet():
            scanner = MedusaParallelScanner(
                project_root=target if target.is_dir() else target.parent,
                use_cache=False,
                quick_mode=False,
            )
            if target.is_dir():
                files = scanner.find_scannable_files()
            else:
                files = [target]
            scan_root = target if target.is_dir() else target.parent
            if not files:
                summary = _summarize([], redact_snippets=redact_snippets, root=scan_root)
                summary["target"] = str(target)
                return summary
            results = scanner.scan_parallel(files)
            findings = _extract_findings(scanner, results)
    except Exception as exc:
        return {
            "verdict": CAUTION,
            "score": 0,
            "counts_by_severity": {},
            "total_findings": 0,
            "top_findings": [],
            "target": str(target),
            "error": f"scan failed: {exc}",
        }

    summary = _summarize(findings, redact_snippets=redact_snippets, root=scan_root)
    summary["target"] = str(target)
    return summary


def _looks_like_url(value: str) -> bool:
    """True if the string is a remote git URL rather than a local path."""
    if value.startswith(("git@", "ssh://")):
        return True
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https", "git") and bool(parsed.netloc)


def _clone_repo(url: str) -> str:
    """Hardened shallow clone of a remote repo into a fresh temp dir.

    Thin wrapper over the shared :func:`medusa.core.git_clone.clone_hardened`
    (CR-020) — the single source of truth for clone hardening, also used by
    ``cli._scan_git_repo``. Returns the clone directory path; raises
    RuntimeError on any failure (caller maps it to a safe verdict).
    """
    from medusa.core.git_clone import clone_hardened

    return clone_hardened(url)


def vet_repo(url_or_path, redact_snippets: bool = False) -> dict:
    """Vet a repository given a local path OR a remote git URL.

    Local existing path -> delegate to ``vet_path``.
    Remote URL          -> hardened shallow clone into a temp dir, vet it,
                           then clean up.

    A clone failure returns a CAUTION verdict with an ``error`` field (fail
    safe) rather than raising.

    ``redact_snippets`` is forwarded to ``vet_path`` (MCP path).
    """
    value = str(url_or_path)

    # An existing local path always wins over URL heuristics.
    if Path(value).exists():
        result = vet_path(value, redact_snippets=redact_snippets)
        result["target"] = value
        return result

    if not _looks_like_url(value):
        return {
            "verdict": CAUTION,
            "score": 0,
            "counts_by_severity": {},
            "total_findings": 0,
            "top_findings": [],
            "target": value,
            "error": f"not a local path or recognized git URL: {value}",
        }

    try:
        clone_dir = _clone_repo(value)
    except RuntimeError as exc:
        return {
            "verdict": CAUTION,
            "score": 0,
            "counts_by_severity": {},
            "total_findings": 0,
            "top_findings": [],
            "target": value,
            "error": str(exc),
        }

    try:
        result = vet_path(clone_dir, redact_snippets=redact_snippets)
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)

    result["target"] = value
    return result


def vet_skill(path, redact_snippets: bool = False) -> dict:
    """Vet a skill directory or SKILL.md file.

    For now this is a content scan of the skill (vet_path on the dir/file).
    Deep SKILL.md manifest vetting is deferred (see the feature plan).

    ``redact_snippets`` is forwarded to ``vet_path`` (MCP path).
    """
    target = Path(path)
    # If pointed at a SKILL.md, scan its whole directory so adjacent scripts
    # (the actual risk surface of a skill) are included.
    if target.is_file() and target.name.upper() == "SKILL.MD":
        result = vet_path(target.parent, redact_snippets=redact_snippets)
    else:
        result = vet_path(target, redact_snippets=redact_snippets)
    result["target"] = str(target)
    return result


def secrets_scan(path: Optional[str] = None) -> dict:
    """Scan for leaked credentials using the existing secrets engine.

    path is None -> discover host AI-chat / shell history targets and scan
                    them all (same discovery the `medusa secrets scan` CLI uses).
    path given   -> scan that one file (or every file under a directory).

    Returns {count, files_with_findings, findings_summary:[...], target}.
    Secret VALUES are never returned — only masked descriptions — so this is
    safe to surface to an LLM context.
    """
    from medusa.scanners.ai_chat_history_scanner import scan_file

    targets: list[tuple[Path, str]] = []
    error = None

    if path is None:
        try:
            from medusa.core.chat_history_discovery import list_targets
            discovered = list_targets(None)
            targets = [(t.path, t.source) for t in discovered]
        except Exception as exc:
            error = f"discovery failed: {exc}"
    else:
        p = Path(path)
        if not p.exists():
            error = f"path does not exist: {p}"
        elif p.is_dir():
            targets = [(f, "explicit") for f in p.rglob("*") if f.is_file()]
        else:
            targets = [(p, "explicit")]

    if error is not None:
        return {
            "count": 0,
            "files_with_findings": 0,
            "findings_summary": [],
            "target": str(path) if path is not None else "host-discovery",
            "error": error,
        }

    count = 0
    files_with_findings = 0
    summary = []
    for file_path, label in targets:
        try:
            res = scan_file(file_path, source_label=label)
        except Exception:
            continue
        if res.findings:
            files_with_findings += 1
            count += len(res.findings)
            for finding in res.findings:
                # Mask: never echo the raw secret into an LLM context.
                summary.append({
                    "name": finding.name,
                    "issuer": finding.issuer,
                    "severity": _normalize_severity(finding.severity),
                    "file": str(finding.file_path),
                    "line": finding.line,
                })

    # Cap the summary so a huge host scan can't blow up the response.
    summary = summary[:50]

    return {
        "count": count,
        "files_with_findings": files_with_findings,
        "findings_summary": summary,
        "target": str(path) if path is not None else "host-discovery",
    }
