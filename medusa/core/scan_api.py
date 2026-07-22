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
import functools
import io
import os
import re
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
# PR-007: "we could not vet this target at all" (bad path / unclonable URL) is NOT a
# security verdict — it must never look like CAUTION. Distinct outcome, exit code 3
# (still non-zero, so an automated gate/hook fails closed).
ERROR = "ERROR"

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
    "LLMProviderHijackScanner",  # base-URL hijack / API-key URL exfil
    "ImageEmbeddedThreatScanner",  # commands hidden in images / polyglots
    "CredentialFileScanner",     # committed private keys / tokens / cloud creds
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
    "MEDUSA-LLMJACK-",           # LLM provider base-URL hijack / API-key URL exfil
    "MEDUSA-IMG-",               # commands hidden in image metadata / polyglots
    "MEDUSA-CRED-",              # committed credential files (keys / tokens / creds)
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


# Documentation dirs — a leaked-secret finding here is overwhelmingly a copy-paste
# example (`Authorization: Bearer <TOKEN>`, a sample `.env`), not a real credential.
# Scoped to the GitLeaks exemption only (below); other scanners (e.g. a prompt-
# injection directive in a README) still drive the verdict inside docs/.
_VET_DOC_DIRS = frozenset({"docs", "doc", "documentation"})


def _is_test_or_doc_path(file_path) -> bool:
    """True if a path component is a test-data OR documentation dir."""
    parts = str(file_path or "").replace("\\", "/").lower().split("/")
    return any(p in _VET_TEST_DATA_DIRS or p in _VET_DOC_DIRS for p in parts)


def _is_gitleaks_signal(finding: dict) -> bool:
    """A leaked-secret finding from GitLeaks (scanner name or ``GL-`` rule prefix)."""
    return (finding.get("scanner") == "GitLeaksScanner"
            or str(finding.get("rule_id") or "").startswith("GL-"))


# A LIVE-payload file class executes or carries a real secret regardless of the
# directory it sits in — a real mcp.json, skill/install script, credential file,
# or payload image parked in tests/fixtures/ IS an install risk (an attacker just
# picks a "test-data" dir to evade vet). Unlike an attack STRING inside a dataset
# (which the test-data exclusion legitimately dismisses), these stay a signal.
_VET_LIVE_PAYLOAD_EXACT = frozenset({
    "mcp.json", ".mcp.json", "mcp-config.json", "mcp_config.json",
    "claude_desktop_config.json", "skill.md", "settings.json", "settings.local.json",
    "install.sh", "setup.sh", "preinstall.sh", "postinstall.sh",
    ".npmrc", ".pypirc", ".git-credentials", "credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd",
})
_VET_LIVE_PAYLOAD_SUFFIX = (
    ".env", ".pem", ".key",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff",
)


def _is_live_payload_file(file_path) -> bool:
    if not file_path:
        return False
    name = Path(str(file_path)).name.lower()
    return (name in _VET_LIVE_PAYLOAD_EXACT
            or name.startswith(".env")
            or name.endswith(_VET_LIVE_PAYLOAD_SUFFIX))


def _rel_to_root(file_path, root) -> str:
    """Return ``file_path`` relative to ``root`` as a posix string (best effort).

    Used only for vet_allowlist glob matching. Falls back to the normalized
    absolute path when the file is outside ``root`` or not resolvable — so a path
    outside the scan root simply won't match a repo-relative glob (fail safe: it
    stays a signal). Distinct from :func:`_relativize`, which drops to a bare
    basename for redaction; here we must preserve the full relative path so globs
    like ``skills/**`` / ``agents/*.md`` match correctly.
    """
    if not file_path:
        return ""
    s = str(file_path).replace("\\", "/")
    if root is not None:
        try:
            return str(
                Path(s).resolve().relative_to(Path(root).resolve())
            ).replace("\\", "/")
        except (ValueError, OSError):
            pass
    return s


@functools.lru_cache(maxsize=256)
def _glob_to_regex(pattern: str):
    """Compile a path glob to a regex with gitignore-style segment semantics.

    Deliberately NOT plain ``fnmatch`` (whose ``*`` also matches ``/``): for a
    security allowlist a single ``*`` must match ONE path segment and ``**`` any
    depth, so an over-broad ``*.md`` cannot silently suppress a poisoned file
    nested several dirs deep. Owner expectation matches gitignore/most tools.

      *   -> one path segment (no ``/``)
      **  -> any number of segments (crosses ``/``)
      ?   -> one non-``/`` char
    A trailing ``/`` is treated as ``/**`` (allowlist everything under a dir).
    """
    if pattern.endswith("/"):
        pattern = pattern + "**"
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # Collapse a run of '*' into '**'; consume an immediate '/'.
                while i < n and pattern[i] == "*":
                    i += 1
                if i < n and pattern[i] == "/":
                    out.append("(?:.*/)?")   # **/  -> zero or more leading dirs
                    i += 1
                else:
                    out.append(".*")          # **   -> anything
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("(?s:" + "".join(out) + r")\Z")


def _is_allowlisted(file_path, root, vet_allowlist) -> bool:
    """True if ``file_path`` matches a USER-configured vet_allowlist glob.

    Globs are matched against the finding's path RELATIVE to the scan root, with
    gitignore-style segment semantics (:func:`_glob_to_regex`), so ``skills/**``
    / ``agents/*.md`` behave as a repo owner expects. An allowlisted finding is
    excluded from the install verdict SIGNAL set (see :func:`_summarize`) — the
    same treatment as a test-data path.

    SECURITY: ``vet_allowlist`` must originate from the USER's config (loaded
    from CWD upward by ConfigManager), NEVER from the scanned target's own
    .medusa.yml — otherwise an untrusted repo could allowlist away its own
    malice. This function is source-agnostic; the guarantee is upheld by the
    caller threading ``scanner.config.vet_allowlist`` (the user config).
    """
    if not vet_allowlist or not file_path:
        return False
    rel = _rel_to_root(file_path, root)
    for glob in vet_allowlist:
        pattern = str(glob or "").strip()
        if pattern and _glob_to_regex(pattern).match(rel):
            return True
    return False


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
    # GitLeaks (leaked-secret) finding on a test-fixture / example / doc path is a
    # fixture or documentation snippet — a test TLS cert (`.key`/`.pem`), a sample
    # `.env`, a `Bearer <TOKEN>` doc example — NOT a real leaked credential. It does
    # not drive the verdict. The SAME leak in shipped source / root is still a signal
    # (not a test/doc path -> falls through below). This deliberately overrides the
    # live-payload exception for GitLeaks only: a test cert IS a `.key`, so the
    # live-payload class would otherwise re-block it (the okhttp / requests FP class).
    if _is_gitleaks_signal(finding) and _is_test_or_doc_path(finding.get("file")):
        return False
    # A test-data dir dismisses attack STRINGS in datasets — but NOT a live
    # payload file (real mcp.json / install script / credential / image), which
    # an attacker would park in tests/fixtures/ precisely to evade vet.
    if _is_test_data_path(finding.get("file")) and not _is_live_payload_file(finding.get("file")):
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


# --- Screening-only (harvested) sub-tier (softer than curated malice) ---------
# vet runs the full 40k-pattern corpus in screening mode for RECALL, but the
# harvested rules are high-recall / low-precision BY DESIGN (PR-013 gates them out
# of default scans). Like the dependency-CVE tier, a screening-only match can
# raise the verdict to CAUTION ("we screened this and found things worth a look")
# but must NEVER hard-block (DO_NOT_INSTALL) on its own — otherwise the harvested
# corpus carpet-bombs any repo that merely *mentions* attack strings (security
# tools, research, benchmarks). Curated rules + the malice-signal prefixes
# (CC-/MEDUSA-MCP-POISON-/MEDUSA-SKILL-/MEDUSA-TAINT-/MEDUSA-ATKSIG-) still
# hard-block. See tests/test_vet_screening_cap.py.
@functools.lru_cache(maxsize=1)
def _screening_only_rule_ids() -> frozenset:
    """Rule IDs that are screening-only (harvested / low pipeline_confidence).

    Loaded once per process from the rule corpus (the parsed-rule cache keeps this
    cheap). Falls back to an empty set if the corpus can't load, so a load failure
    degrades to the prior behaviour rather than silently dropping malice.
    """
    try:
        from medusa.rules import RuleLoader, is_screening_only
        return frozenset(
            rid for r in RuleLoader().load_all_rules()
            if (rid := getattr(r, "id", None)) and is_screening_only(r)
        )
    except Exception:
        return frozenset()


def _is_screening_only_signal(finding: dict) -> bool:
    """True if a (already-signal) finding comes from a screening-only rule."""
    return (finding.get("rule_id") or "") in _screening_only_rule_ids()


# --- Attack-signature sub-tier (softer than curated malice) -------------------
# ATKSIG detects named attack strings (jailbreaks, DAN, "ignore previous
# instructions"). Their PRESENCE means a repo CONTAINS attack content — worth a
# human look (CAUTION) — but not that installing it attacks you: a jailbreak
# dataset, a fuzzing corpus, or a firewall's own detection patterns are full of
# these strings legitimately, and that's the biggest false-block source on
# security tools / attack research. Actionable install-time malice (poisoned
# hook, MCP/skill poisoning, taint exfil, leaked secret) still hard-blocks via
# its OWN rules, which ATKSIG only ever corroborated. So an attack-signature
# match caps the verdict at CAUTION, never DO_NOT_INSTALL on its own — the same
# tier as dependency-CVE and harvested screening. See tests/test_vet_screening_cap.py.
_ATTACK_SIGNATURE_PREFIX = "MEDUSA-ATKSIG-"


def _is_attack_signature_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is an attack-signature match."""
    return (finding.get("rule_id") or "").startswith(_ATTACK_SIGNATURE_PREFIX)


# --- Docker/config-hardening sub-tier (softer than curated malice) ------------
# DockerMCPScanner's DKR rules are container-HARDENING findings: a hardcoded env
# password in a compose file (POSTGRES_PASSWORD=example — every dockerised repo
# has one), a docker-socket volume mount (portainer needs it), latest-tag,
# host-network, missing caps. These are "review your container hardening"
# (CAUTION), not "this attacks you on install" (DO_NOT_INSTALL). A genuinely
# LEAKED credential still hard-blocks via GitLeaks/EnvScanner; a malicious
# container's actual payload trips its own rules. So a DKR match caps the verdict
# at CAUTION, never DO_NOT_INSTALL on its own. See tests/test_vet_screening_cap.py.
_DOCKER_HARDENING_PREFIX = "DKR"


def _is_docker_hardening_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a Docker config-hardening (DKR) rule."""
    return (finding.get("rule_id") or "").startswith(_DOCKER_HARDENING_PREFIX)


# --- "Review, don't block" sub-tier (softer than curated malice) --------------
# These curated rules fire on operations a legitimate agent/skill/LLM TOOL
# performs as its normal function — indistinguishable from a rogue one by text
# alone — so they carpet-block legit frameworks (claude-forge, nanoclaw, agent
# tools). A genuinely malicious repo carries its actual PAYLOAD (a persistent
# base-URL write to settings/rc = LLMJACK-003, key exfil = LLMJACK-002, an MCP
# dropper, taint exfil, an anti-refusal directive) which hard-blocks via its OWN
# rule (verified in tests/test_vet_scoping.py). So these are "review this" signals
# that cap the verdict at CAUTION, never DO_NOT_INSTALL on their own — the same
# tier as attack-signature / dependency-CVE / docker-hardening:
#   SKILL-ROGUE-001  self-modification / persistence ("add a hook to settings.json")
#   SKILL-MEMORY-001 memory-poisoning ("remember to always …")
#   SKILL-TRIGGER-001 over-broad / shadowing skill trigger (a legit skill framework
#                    like claude-forge declares broad triggers) — the anti-refusal /
#                    hidden-instruction SKILL rules still hard-block.
#   LLMJACK-001      base-URL OVERRIDE *mentioned* (a README `ANTHROPIC_BASE_URL=…`
#                    config example) — the persistent WRITE (LLMJACK-003) still blocks.
_VET_SOFT_REVIEW_RULE_IDS = frozenset({
    'MEDUSA-SKILL-ROGUE-001', 'MEDUSA-SKILL-MEMORY-001',
    'MEDUSA-SKILL-TRIGGER-001', 'MEDUSA-LLMJACK-001',
})


def _is_soft_review_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a 'review, don't block' rule (a legit
    tool's normal operation; the active-attack payload rules hard-block separately)."""
    return (finding.get("rule_id") or "") in _VET_SOFT_REVIEW_RULE_IDS


# --- Plugin-security sub-tier (softer than curated malice) ---------------------
# PluginSecurityScanner's PLG001-PLG010 are plugin CODE-QUALITY / info-leak
# findings (missing input validation / auth, chat-history exposure, "sensitive
# data in a plugin response", plugin command injection). Like external SAST, they
# describe a weakness in the REPO's own plugin code — a "review this repo's plugin
# security" concern — not an install-time attack on the installer, and they were
# the #1 false-block driver on legit agent frameworks (PLG008 alone = 25x across
# nanoclaw/agentshield/openshield/rampart/superagent; its `return.*key` pattern
# matches `registry.keys()`, `continuationKey`, code comments, test strings). A
# genuinely malicious plugin's actual payload (exfil, dropper, taint) hard-blocks
# via its OWN rule. So a PLG match caps the verdict at CAUTION, never
# DO_NOT_INSTALL on its own — same tier as attack-signature / dependency-CVE.
_PLUGIN_SECURITY_PREFIX = "PLG"


def _is_plugin_security_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a PluginSecurityScanner (PLG) rule."""
    return (finding.get("rule_id") or "").startswith(_PLUGIN_SECURITY_PREFIX)


# --- Repo AI-security-hygiene sub-tier (softer than curated malice) ------------
# DatasetInjectionScanner (DSI001-003: attack strings embedded in a DATASET) and
# PromptInjectionCodeScanner (PIC001-008: the repo's OWN code builds a prompt from
# user input — an injection sink) describe attack-content-as-DATA or a prompt-
# injection weakness in the repo's own code — the same "review this repo" class as
# ATKSIG (attack signatures as data) and PLG (plugin code-quality). A research /
# red-team repo ships attack datasets (AdvBox / GPTFuzz / llm-attacks) and a prompt-
# firewall (openshield / superagent) flows user input into an LLM by design, so these
# carpet-block legit AI tooling. The INSTALLER-directed prompt attack (a poisoned
# SKILL.md directive, an mcp.json injected directive, a base-URL hijack) is a
# DIFFERENT scanner (SkillManifest / MCP / LLMJACK) and still hard-blocks via its own
# rule. So DSI / PIC cap the verdict at CAUTION, never DO_NOT_INSTALL on their own.
_REPO_AI_HYGIENE_SCANNERS = frozenset({
    "DatasetInjectionScanner", "PromptInjectionCodeScanner",
})
_REPO_AI_HYGIENE_PREFIXES = ("DSI", "PIC")


def _is_repo_ai_hygiene_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a dataset-injection (DSI) or prompt-
    injection-in-code (PIC) rule — the repo's own AI-security weakness / attack-
    content-as-data, not an install-time attack on the installer."""
    return (finding.get("scanner") in _REPO_AI_HYGIENE_SCANNERS
            or str(finding.get("rule_id") or "").startswith(_REPO_AI_HYGIENE_PREFIXES))


# --- Env sensitive-NAME-only sub-tier (softer than a confirmed secret) ---------
# EnvScanner's `env-sensitive-var-*` fires on a sensitive-named var (API_KEY / SECRET
# / TOKEN / PASSWORD) whose value is present but LOW-entropy — a config default or
# short placeholder, not a confirmed secret. (A HIGH-entropy value in the same var is a
# real leaked secret and gets the hard `env-secret-var-*` id; a known-format secret
# gets `env-secret-*` via the pattern check; both still hard-block.) So a bare
# sensitive-NAME match is a "review this config" concern -> cap at CAUTION, never
# DO_NOT_INSTALL on its own. This is only safe BECAUSE the scanner now routes real
# high-entropy secrets to `env-secret-var-*` instead of this id (FX-003b).
_ENV_NAME_ONLY_PREFIX = "env-sensitive-var-"


def _is_env_name_only_signal(finding: dict) -> bool:
    """True if a (already-signal) finding is a sensitive-NAME-only env match (a
    low-entropy value) — softer than a confirmed hardcoded secret (`env-secret-*`
    / `env-secret-var-*`, which stay hard-blocking malice)."""
    return (finding.get("rule_id") or "").startswith(_ENV_NAME_ONLY_PREFIX)


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


def _summarize(findings: list, redact_snippets: bool = False, root=None,
               vet_allowlist=None) -> dict:
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

    Owner overrides (``vet_allowlist``): a finding whose file matches one of the
    user-configured allowlist globs (relative to ``root``) is excluded from the
    signal set — a repo owner can mark known-benign security-content files so
    ``medusa vet`` reaches SAFE without weakening detection elsewhere. It is
    still counted in ``total_findings`` / ``other_findings``. The allowlist MUST
    be the USER's (never the scanned target's) — see :func:`_is_allowlisted`.
    """
    # Partition into what drives the verdict (malice/supply-chain) vs. the rest
    # (generic SAST — informational for an install decision). Findings under a
    # USER-configured vet_allowlist path (owner overrides) are excluded from the
    # signal set too — same treatment as test-data dirs: still counted below in
    # total_findings / other_findings, but they do not gate installation. The
    # allowlist is the user's, never the target's (see :func:`_is_allowlisted`).
    signal = [
        f for f in findings
        if _is_vet_signal(f) and not _is_allowlisted(f.get("file"), root, vet_allowlist)
    ]

    # Within the signal set, separate the hard-blocking curated-malice tier from
    # the softer tiers that INFORM but never hard-block: known-vulnerable
    # dependencies (CVE/OSV) and screening-only (harvested, low-precision) rules.
    def _is_soft(f):
        return (_is_dependency_vuln_signal(f) or _is_screening_only_signal(f)
                or _is_attack_signature_signal(f) or _is_docker_hardening_signal(f)
                or _is_soft_review_signal(f) or _is_plugin_security_signal(f)
                or _is_repo_ai_hygiene_signal(f) or _is_env_name_only_signal(f))
    soft = [f for f in signal if _is_soft(f)]
    malice = [f for f in signal if not _is_soft(f)]

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
    # A soft signal (known-vulnerable dependency OR a screening-only harvested
    # match) with no curated malice warrants CAUTION, never a hard block.
    if verdict == SAFE and soft:
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


def _config_origin_allowlist(scanner, target_root) -> list:
    """Return the config-file ``vet_allowlist`` ONLY if the config that produced
    it lives STRICTLY OUTSIDE the scanned target root.

    SECURITY (config-origin guard): the scanner loads config via
    ``ConfigManager.find_config()``, which walks UP from CWD. The natural flow
    ``git clone evil && cd evil && medusa vet .`` makes CWD == target, so
    find_config() loads the TARGET's OWN ``.medusa.yml`` — an untrusted repo
    shipping ``vet_allowlist: ['**']`` would then self-suppress its own malice to
    SAFE (a full compromise of the vet decision). We therefore honor a
    config-file allowlist ONLY when the resolved config file is neither equal to
    nor nested under ``target_root``. A target-resident (or non-resolvable)
    config allowlist is IGNORED — we return an empty list and print a one-line
    stderr notice pointing the owner at the safe mechanisms (``--allow`` or a
    config kept outside the repo).
    """
    config_allow = list(getattr(scanner.config, "vet_allowlist", None) or [])
    if not config_allow:
        return []
    honored = False
    try:
        from medusa.config import ConfigManager
        cfg_path = ConfigManager.find_config()
        if cfg_path is not None:
            cfg_resolved = Path(cfg_path).resolve()
            root_resolved = Path(target_root).resolve()
            # Honor ONLY if the config is strictly outside the target root:
            # not the target dir itself and not any file nested within it.
            if (cfg_resolved != root_resolved
                    and root_resolved not in cfg_resolved.parents):
                honored = True
    except (ValueError, OSError):
        honored = False
    if honored:
        return config_allow
    print(
        "medusa vet: ignoring target-resident vet_allowlist — "
        "use --allow or a config outside the repo",
        file=sys.stderr,
    )
    return []


def vet_path(path, redact_snippets: bool = False, allow=None) -> dict:
    """Scan a local directory or file and return a structured verdict.

    Returns a dict: {verdict, score, counts_by_severity, total_findings,
    top_findings, target, error?}. Never raises for an ordinary scan
    failure — a failed scan returns an ``error`` field and a CAUTION verdict
    so callers fail safe rather than fail open.

    ``redact_snippets`` (set by the MCP layer) drops matched-source bodies and
    relativizes file paths in ``top_findings``; the CLI path leaves them intact.

    ``allow`` is an EXPLICIT, always-trusted allowlist of path globs (the CLI
    ``medusa vet --allow`` flag). A user-typed flag cannot be shipped by the
    scanned repo, so it is honored unconditionally — unlike a config-file
    allowlist, which is honored only when the config lives outside the target
    (see :func:`_config_origin_allowlist`). The two are MERGED.
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
                # Vet screens a stranger's repo before install: the harvested
                # keyword corpus (mention-detection) IS signal here, so run the
                # full rule set exactly as --git / --screening do (PR-013).
                screening=True,
            )
            scan_root = target if target.is_dir() else target.parent
            # Owner-overrides allowlist. Two sources, different trust:
            #   1. --allow (``allow`` arg): explicit, user-typed, ALWAYS trusted
            #      — a repo cannot ship a CLI flag.
            #   2. config-file vet_allowlist: honored ONLY if the config lives
            #      outside the target (config-origin guard) — otherwise a
            #      `cd untrusted-repo && medusa vet .` would let the target's own
            #      .medusa.yml self-suppress its malice. See
            #      :func:`_config_origin_allowlist`.
            # The two are merged into the effective allowlist.
            vet_allowlist = list(allow or []) + _config_origin_allowlist(
                scanner, scan_root)
            if target.is_dir():
                files = scanner.find_scannable_files()
            else:
                files = [target]
            if not files:
                summary = _summarize([], redact_snippets=redact_snippets,
                                     root=scan_root, vet_allowlist=vet_allowlist)
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

    summary = _summarize(findings, redact_snippets=redact_snippets,
                         root=scan_root, vet_allowlist=vet_allowlist)
    # Honest-partial: if the deep-vet walk hit the enum cap inside a huge
    # installed-dep / cache tree it did NOT fully screen that subtree. A partial
    # scan must never read as a clean SAFE — surface it and floor the verdict at
    # CAUTION ("couldn't fully screen — review"). A real payload found before the
    # cap still hard-blocks; this only lifts a would-be SAFE.
    if getattr(scanner, "_screening_partial", False):
        summary["partial_scan"] = True
        summary["partial_note"] = (
            "vet could not fully screen a large installed-dependency / cache tree "
            "(file budget exceeded) — result is PARTIAL, not a clean pass"
        )
        if summary.get("verdict") == SAFE:
            summary["verdict"] = CAUTION
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


def vet_repo(url_or_path, redact_snippets: bool = False, allow=None) -> dict:
    """Vet a repository given a local path OR a remote git URL.

    Local existing path -> delegate to ``vet_path``.
    Remote URL          -> hardened shallow clone into a temp dir, vet it,
                           then clean up.

    A clone failure returns a CAUTION verdict with an ``error`` field (fail
    safe) rather than raising.

    ``redact_snippets`` is forwarded to ``vet_path`` (MCP path). ``allow`` is the
    explicit, always-trusted allowlist (CLI ``--allow``) forwarded to
    ``vet_path`` — it survives the clone/local branch alike.
    """
    value = str(url_or_path)

    # An existing local path always wins over URL heuristics.
    if Path(value).exists():
        result = vet_path(value, redact_snippets=redact_snippets, allow=allow)
        result["target"] = value
        return result

    if not _looks_like_url(value):
        return {
            "verdict": ERROR,
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
            "verdict": ERROR,
            "score": 0,
            "counts_by_severity": {},
            "total_findings": 0,
            "top_findings": [],
            "target": value,
            "error": str(exc),
        }

    try:
        result = vet_path(clone_dir, redact_snippets=redact_snippets, allow=allow)
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
