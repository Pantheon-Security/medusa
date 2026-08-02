"""Canonical vet-verdict tier data (CR-008 — single source of truth).

The install verdict is ``malice = signal − soft``. Two prefix universes drive it,
and they used to be defined independently in ``scan_api`` (``SIGNAL_RULE_PREFIXES``)
and ``fp_filter`` (``NEVER_GENERIC_FP_PREFIXES``) with divergent membership — so
adding a prefix to one and forgetting the other could silently flip a finding from
hard-block to dropped (a fail-OPEN drift). Both now live here, next to the
soft-tier table, and ``fp_filter`` imports its set from this module.

The nine "soft" sub-tiers (findings that INFORM but never hard-block on their own)
were nine near-identical predicates; eight are static (scanner-set / rule-prefix /
rule-id) and collapse into the ``SOFT_TIERS`` data table below. The ninth —
screening-only (a dynamic rule-corpus lookup) — stays a function in ``scan_api``
and is OR'd alongside ``soft_tier_of``.
"""
from __future__ import annotations

from typing import Optional

# --- Signal universe: a finding drives the verdict if its scanner OR rule_id says
#     so. Kept as a tuple for str.startswith(). ------------------------------------
SIGNAL_RULE_PREFIXES = (
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
    "MEDUSA-RCE-FETCHEXEC-",     # fetch-then-execute a remote script
)

# --- Never-generic malice prefixes: findings the generic context FP heuristics
#     must NEVER bury (a poisoned .claude/ hook / SKILL.md / mcp.json is a true
#     positive, not "config data"). Imported by fp_filter. ATKSIG/OSV are
#     intentionally absent — they rely on the rule-corpus recognition to avoid
#     firing on MEDUSA's own signature corpus. ----------------------------------
NEVER_GENERIC_FP_PREFIXES = (
    "MEDUSA-MCP-POISON-",
    "CC-",
    "MEDUSA-SKILL-",
    "MEDUSA-TAINT-",
    "MEDUSA-LLMJACK-",
    "MCP0",
    "MEDUSA-SC-MCP-",
    "MEDUSA-IMG-",
    "MEDUSA-CRED-",
)

# --- Soft tiers (INFORM → cap at CAUTION, never DO_NOT_INSTALL alone) -----------
# One row per tier: (name, scanners, rule_prefixes, rule_ids). A finding is in the
# tier if its scanner is in ``scanners`` OR its rule_id is in ``rule_ids`` OR it
# startswith any of ``rule_prefixes``. Prefixes/scanners are mutually distinct, so
# a finding matches at most one row (soft_tier_of returns the first).
SOFT_TIERS = (
    ("dependency_vuln",
     frozenset({"CriticalCVEScanner", "DependencyCVEScanner"}),
     ("CVE-", "cve-", "MEDUSA-OSV-001"),
     frozenset()),
    ("attack_signature", frozenset(), ("MEDUSA-ATKSIG-",), frozenset()),
    ("docker_hardening", frozenset(), ("DKR",), frozenset()),
    # CR-010: a broad TRIGGER / "remember to…" MEMORY / README base-URL LLMJACK-001
    # example are the legit-framework FP drivers → cap at CAUTION. ROGUE-001
    # (self-modification / persistence / config rewrite) is self-persistence
    # ENTRENCHMENT — a directive to write agent-executable config or disable a
    # control — so it is NOT soft: it hard-blocks via its own CRITICAL malice tier.
    # MEDUSA-SKILL-ROGUE-002 is the DISCLOSED config-write: the skill states it
    # writes agent config AND shows the exact block it writes, so the user can read
    # it and decide (a skill-authoring tool legitimately must write there — see
    # SkillManifestScanner._disclosed_block). Transparency is the whole difference:
    # the CONCEALED form (HTML comment / no content shown) stays ROGUE-001 and
    # hard-blocks. This softens ONLY the "it writes to config" signal — the
    # disclosed content is still scanned by every other rule, so a malicious block
    # hard-blocks on its own merits.
    ("soft_review", frozenset(), (),
     frozenset({"MEDUSA-SKILL-MEMORY-001", "MEDUSA-SKILL-ROGUE-002",
                "MEDUSA-SKILL-TRIGGER-001", "MEDUSA-LLMJACK-001"})),
    ("plugin_security", frozenset(), ("PLG",), frozenset()),
    ("repo_ai_hygiene",
     frozenset({"DatasetInjectionScanner", "PromptInjectionCodeScanner"}),
     ("DSI", "PIC"), frozenset()),
    ("fetch_exec", frozenset({"RemoteFetchExecScanner"}),
     ("MEDUSA-RCE-FETCHEXEC-",), frozenset()),
    ("env_name_only", frozenset(), ("env-sensitive-var-",), frozenset()),
    # Model-LOADING-call hygiene (from_pretrained / torch.load / trust_remote_code /
    # revision-pin) fires on essentially every model-loading repo → INFORM, cap at
    # CAUTION. The committed poisoned-model FILE families (MLSC-SERIAL-*/MLSC-HUB-*)
    # are deliberately NOT here — they remain hard-block malice.
    ("model_load", frozenset(), ("MLSC-LOAD-",), frozenset()),
)


def soft_tier_of(finding: dict) -> Optional[str]:
    """Return the soft-tier name a (already-signal) finding belongs to, or None.

    None means it is NOT one of the static soft tiers (it may still be the dynamic
    screening-only tier, which scan_api checks separately, or hard-block malice).
    """
    scanner = finding.get("scanner") or ""
    rule_id = str(finding.get("rule_id") or "")
    for name, scanners, prefixes, ids in SOFT_TIERS:
        if scanner in scanners or rule_id in ids or (prefixes and rule_id.startswith(prefixes)):
            return name
    return None
