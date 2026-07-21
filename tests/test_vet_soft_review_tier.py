"""Gate: the "review, don't block" soft tier — a legit tool's normal operations
cap at CAUTION, while active-attack payloads still hard-block.

An FP measurement over the clean corpus (2026-07-21) showed the #1 false-block
class is legit agent/skill frameworks (claude-forge, nanoclaw) tripping rules
that describe operations a legitimate tool performs — SKILL-ROGUE-001 (self-mod:
"add a hook to settings.json"), SKILL-MEMORY-001 ("remember to always …"),
LLMJACK-001 (a README `ANTHROPIC_BASE_URL=…` config example). Textually these are
indistinguishable from a rogue tool, so they now cap the verdict at CAUTION. The
ACTUAL attack payloads a malicious repo carries — API-key URL exfil (LLMJACK-002),
a persistent base-URL WRITE to settings/rc (LLMJACK-003), an MCP curl|bash dropper
(MCP017) — still hard-block via their own rules.
"""
import medusa.core.scan_api as api


def _vf(rule_id, sev="CRITICAL", scanner="LLMProviderHijackScanner"):
    # scanner must be a real vet-signal scanner OR the rule_id a signal prefix,
    # else _is_vet_signal drops it (as it would any generic-SAST finding).
    return {"rule_id": rule_id, "scanner": scanner, "severity": sev, "file": "x/y", "line": 1, "issue": ""}


def test_soft_review_rules_cap_at_caution():
    # even many of these together -> CAUTION, never DO_NOT_INSTALL (they were the
    # carpet-block driver on legit skill frameworks).
    for rid in ("MEDUSA-SKILL-ROGUE-001", "MEDUSA-SKILL-MEMORY-001", "MEDUSA-LLMJACK-001"):
        r = api._summarize([_vf(rid) for _ in range(6)], root="/x")
        assert r["verdict"] == api.CAUTION, f"{rid} should cap at CAUTION, got {r['verdict']}"


def test_active_attack_payloads_still_hard_block():
    # a single one of these is an install-time attack and must still DO_NOT_INSTALL.
    for rid, scanner in (("MEDUSA-LLMJACK-002", "LLMProviderHijackScanner"),
                         ("MEDUSA-LLMJACK-003", "LLMProviderHijackScanner"),
                         ("MCP017", "MCPConfigScanner")):
        r = api._summarize([_vf(rid, scanner=scanner)], root="/x")
        assert r["verdict"] == api.DO_NOT_INSTALL, f"{rid} must still hard-block, got {r['verdict']}"


def test_soft_review_helper_membership():
    assert api._is_soft_review_signal(_vf("MEDUSA-SKILL-ROGUE-001"))
    assert api._is_soft_review_signal(_vf("MEDUSA-LLMJACK-001"))
    assert not api._is_soft_review_signal(_vf("MEDUSA-LLMJACK-003"))  # persistent write = malice
    assert not api._is_soft_review_signal(_vf("MCP017"))               # dropper = malice
