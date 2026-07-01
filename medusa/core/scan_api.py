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

# --- Vet verdict scoping (P1-trust-safety) ---------------------------------
# The install verdict (SAFE / CAUTION / DO_NOT_INSTALL) must reflect *malice and
# supply-chain* signals — a poisoned Claude Code hook, an anti-refusal SKILL.md,
# injected MCP metadata, a taint exfil path, a known-vulnerable pinned
# dependency, a known attack signature — NOT the full 40k-pattern generic SAST
# sweep. Summing every generic finding into the verdict made 8 of 9
# universally-trusted libraries (requests, flask, click, six, ...) read as
# DO_NOT_INSTALL. Generic findings are still scanned, still counted
# (``total_findings``), and still visible via ``medusa scan``; they simply do
# not gate installation. See tests/test_vet_scoping.py.
#
# Scanners whose findings drive the install verdict.
_VET_SIGNAL_SCANNERS = frozenset({
    "ClaudeCodeScanner",         # poisoned .claude hooks / settings
    "MCPServerScanner",          # MCP metadata poisoning
    "MCPConfigScanner",          # mcp.json injected directives
    "MCPRemoteRCEScanner",       # remote MCP RCE
    "DockerMCPScanner",          # containerised MCP escape
    "SkillManifestScanner",      # SKILL.md anti-refusal / hidden instructions
    "TaintScanner",              # secret -> network exfil dataflow
    "DependencyCVEScanner",      # OSV known-vuln pinned deps (MEDUSA-OSV-001)
    "CriticalCVEScanner",        # curated critical CVEs
    "PromptInjectionCodeScanner",
    "DatasetInjectionScanner",
    "AIAttackSignatureScanner",  # known malware/attack signatures
    "GitLeaksScanner",           # committed live credentials
    "EnvScanner",                # leaked secrets in env files
    "ModelScanScanner",          # malicious serialized models
    "PluginSecurityScanner",     # malicious plugin behaviour
})

# Rule-ID prefixes that drive the verdict regardless of scanner attribution.
# Defence in depth: a finding is a signal if EITHER its scanner OR its rule_id
# says so, so a future attribution change can't silently drop malice signals.
_VET_SIGNAL_RULE_PREFIXES = (
    "CC-",                       # Claude Code hook/config abuse
    "MEDUSA-MCP-POISON-",        # MCP metadata poisoning
    "MEDUSA-SKILL-",             # skill manifest abuse
    "MEDUSA-TAINT-",             # taint exfil
    "MEDUSA-OSV-001",            # OSV known-vuln dependency (NOT -INCOMPLETE)
    "CVE-",                      # curated CVE hits
    "MEDUSA-ATKSIG-",            # attack signatures
)

# Informational rule IDs that must NEVER drive the verdict even though they are
# emitted by a signal scanner. MEDUSA-OSV-INCOMPLETE is a "couldn't reach the
# OSV network" notice, not a vulnerability — it comes from DependencyCVEScanner
# (a signal scanner) so the scanner-based rule alone would wrongly block on it.
_VET_NONSIGNAL_RULE_IDS = frozenset({
    "MEDUSA-OSV-INCOMPLETE",
})


# Directory components whose contents do NOT execute at install/import time.
# A finding buried in test vectors / fixtures / examples is not an install-risk
# signal (e.g. pyca/cryptography ships 300+ high-entropy test vectors that trip
# the generic secret detector). Such findings are still scanned and counted in
# `medusa scan`, but they do not gate the install verdict. Genuine install-path
# malice (poisoned .claude/, install scripts, package code) lives outside these.
_VET_TEST_DATA_DIRS = frozenset({
    "test", "tests", "testing", "__tests__", "spec", "specs",
    "vectors", "testdata", "test_data", "fixtures", "fixture",
    "examples", "example", "samples", "sample", "mocks",
})


def _is_test_data_path(file_path) -> bool:
    """True if any path component is a recognized non-executing test-data dir."""
    parts = str(file_path or "").replace("\\", "/").lower().split("/")
    return any(p in _VET_TEST_DATA_DIRS for p in parts)


def _is_vet_signal(finding: dict) -> bool:
    """True if a finding should drive the install verdict (malice / supply-chain).

    A finding is a signal when its owning scanner is a malice/supply-chain
    scanner OR its ``rule_id`` carries a signal prefix — with an explicit
    informational denylist (OSV network-incomplete) subtracted first, and
    findings inside non-executing test-data dirs excluded (they are not an
    install risk). Everything else (generic SAST: WEB-*, PythonScanner B1xx,
    dual-use AST behaviour, style/quality) is scanned and counted but does NOT
    gate installation.
    """
    rule_id = finding.get("rule_id") or ""
    if rule_id in _VET_NONSIGNAL_RULE_IDS:
        return False
    if _is_test_data_path(finding.get("file")):
        return False
    scanner = finding.get("scanner") or ""
    if scanner in _VET_SIGNAL_SCANNERS:
        return True
    return rule_id.startswith(_VET_SIGNAL_RULE_PREFIXES)


# --- Dependency-vulnerability sub-tier (softer than malice) ----------------
# A known-vulnerable *dependency* (a CVE / OSV hit on a manifest) is a genuine
# supply-chain signal, but it is NOT the same as active malice: nearly every
# real-world repo pins or ranges some dependency that has a published CVE, so
# hard-blocking install on that basis reproduces the very cry-wolf failure this
# work fixes (requests / flask were DO_NOT_INSTALL purely from CVEs on their own
# dependency metadata). So dependency-CVE signals can raise the verdict to
# CAUTION ("known-vulnerable deps — review / update") but NEVER to
# DO_NOT_INSTALL on their own. True-malice signals (poisoned hook, anti-refusal
# skill, MCP poisoning, taint exfil, attack signature, prompt/dataset injection,
# leaked live secrets, malicious model/plugin) still hard-block. See
# tests/test_vet_scoping.py.
_VET_DEP_VULN_SCANNERS = frozenset({
    "CriticalCVEScanner",
    "DependencyCVEScanner",
})
_VET_DEP_VULN_RULE_PREFIXES = (
    "CVE-",
    "cve-",          # CriticalCVEScanner emits lowercase ``cve-cve-...`` ids
    "MEDUSA-OSV-001",
)


def _is_dependency_vuln_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a known-vulnerable-DEPENDENCY hit.

    These are the softer supply-chain tier: they can escalate the verdict to
    CAUTION but never to DO_NOT_INSTALL by themselves. Assumes the finding has
    already passed :func:`_is_vet_signal` (so MEDUSA-OSV-INCOMPLETE, an INFO
    network notice, is already excluded).
    """
    scanner = finding.get("scanner") or ""
    if scanner in _VET_DEP_VULN_SCANNERS:
        return True
    return (finding.get("rule_id") or "").startswith(_VET_DEP_VULN_RULE_PREFIXES)


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

    Verdict scoping (P1-trust-safety): the verdict, score, and
    ``counts_by_severity`` are computed from ONLY the malice/supply-chain SIGNAL
    subset (see :func:`_is_vet_signal`); generic SAST findings are counted in
    ``total_findings`` and ``other_findings`` but never gate the install
    decision. ``top_findings`` is drawn from the SIGNAL set so the user sees WHY
    a repo is flagged. This does NOT touch ``medusa scan`` output.

    Two-tier verdict: within the signal set, known-vulnerable-DEPENDENCY findings
    (CVE / OSV — see :func:`_is_dependency_vuln_signal`) are a *softer* tier that
    can raise the verdict to CAUTION but never to DO_NOT_INSTALL on their own.
    Only true-malice signals (poisoned hook, anti-refusal skill, MCP poisoning,
    taint exfil, attack signature, injection, leaked secret, malicious model/
    plugin) can drive DO_NOT_INSTALL. Nearly every real repo has a dependency
    with a published CVE, so hard-blocking on that alone is cry-wolf.
    """
    # Partition into what drives the verdict (malice/supply-chain) vs. the rest
    # (generic SAST — informational for an install decision).
    signal = [f for f in findings if _is_vet_signal(f)]

    # Within the signal set, separate the hard-blocking malice tier from the
    # softer known-vulnerable-dependency tier (CVE/OSV).
    dep_vuln = [f for f in signal if _is_dependency_vuln_signal(f)]
    malice = [f for f in signal if not _is_dependency_vuln_signal(f)]

    # Severity counts (for display) come from the whole SIGNAL subset.
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in signal:
        sev = f.get("severity", "MEDIUM")
        counts[sev] = counts.get(sev, 0) + 1

    # The DO_NOT_INSTALL / CAUTION escalation is driven ONLY by the malice tier.
    malice_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in malice:
        sev = f.get("severity", "MEDIUM")
        malice_counts[sev] = malice_counts.get(sev, 0) + 1
    verdict = _verdict_from_counts(malice_counts)
    # A known-vulnerable dependency (with no malice) warrants CAUTION, never a
    # hard block — cap the dependency tier at CAUTION.
    if verdict == SAFE and dep_vuln:
        verdict = CAUTION

    # Sort SIGNAL findings worst-first for the top list — the user sees the
    # findings that actually drove the verdict, not generic SAST noise.
    ordered = sorted(
        signal,
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
        "verdict": verdict,
        "score": _score_from_counts(counts),
        "counts_by_severity": counts,
        "total_findings": len(findings),        # ALL findings (unchanged meaning)
        "blocking_findings": len(signal),       # malice + dependency-vuln signals
        "other_findings": len(findings) - len(signal),  # non-blocking SAST
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

    SKILL.md manifest vetting is active: the scan of the skill dir/file (via
    vet_path) runs the SkillManifestScanner (registered in scanners/__init__.py)
    over the manifest plus adjacent scripts — the actual risk surface of a skill.

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
