"""Gate for FX-002 + FX-003a — the "review, don't block" tier extended to attack-
content-as-data and the repo's own AI-security weaknesses.

  DSI001-003 (DatasetInjectionScanner)      — attack strings embedded in a dataset
  PIC001-008 (PromptInjectionCodeScanner)   — the repo's own code builds a prompt
                                              from user input (an injection sink)
  MEDUSA-SKILL-TRIGGER-001 (SkillManifest)  — over-broad / shadowing skill trigger

A research / red-team repo ships attack datasets (AdvBox / GPTFuzz / llm-attacks); a
prompt-firewall (openshield / superagent) flows user input into an LLM by design; a
legit skill framework (claude-forge) declares broad triggers. These are "review this
repo" signals, not install-time attacks on the installer — so they cap at CAUTION. The
INSTALLER-directed payloads (mcp.json dropper = MCP017, persistent base-URL write =
LLMJACK-003, taint exfil) still hard-block via their OWN rules (FN-safety, born-red).
"""
import medusa.core.scan_api as api


def _f(rule_id, scanner, sev="CRITICAL", file="x/mod.py"):
    return {"rule_id": rule_id, "scanner": scanner, "severity": sev,
            "file": file, "line": 1, "issue": ""}


# --- soft tier: these cap at CAUTION even in bulk ------------------------------ #
def test_dataset_injection_caps_at_caution():
    for rid in ("DSI001", "DSI002", "DSI003"):
        r = api._summarize([_f(rid, "DatasetInjectionScanner") for _ in range(6)], root="/x")
        assert r["verdict"] == api.CAUTION, f"{rid} should cap at CAUTION, got {r['verdict']}"


def test_prompt_injection_code_caps_at_caution():
    for rid in ("PIC002", "PIC008", "PIC004"):
        r = api._summarize([_f(rid, "PromptInjectionCodeScanner") for _ in range(6)], root="/x")
        assert r["verdict"] == api.CAUTION, f"{rid} should cap at CAUTION, got {r['verdict']}"


def test_skill_trigger_caps_at_caution():
    r = api._summarize([_f("MEDUSA-SKILL-TRIGGER-001", "SkillManifestScanner") for _ in range(4)], root="/x")
    assert r["verdict"] == api.CAUTION, f"SKILL-TRIGGER-001 should cap at CAUTION, got {r['verdict']}"


def test_helper_membership():
    assert api._is_repo_ai_hygiene_signal(_f("DSI001", "DatasetInjectionScanner"))
    assert api._is_repo_ai_hygiene_signal(_f("PIC008", "PromptInjectionCodeScanner"))
    assert api._is_soft_review_signal(_f("MEDUSA-SKILL-TRIGGER-001", "SkillManifestScanner"))
    # active-payload rules are NOT soft
    assert not api._is_repo_ai_hygiene_signal(_f("MCP017", "MCPConfigScanner"))
    assert not api._is_soft_review_signal(_f("MEDUSA-LLMJACK-003", "LLMProviderHijackScanner"))


# --- FN-safety: installer-directed active payloads STILL hard-block ------------ #
def test_active_payloads_still_dni():
    # a SINGLE active payload -> DO_NOT_INSTALL, even amid a pile of soft findings
    soft = ([_f("DSI003", "DatasetInjectionScanner") for _ in range(8)] +
            [_f("PIC008", "PromptInjectionCodeScanner") for _ in range(8)] +
            [_f("MEDUSA-SKILL-TRIGGER-001", "SkillManifestScanner") for _ in range(4)])
    for payload in (_f("MCP017", "MCPConfigScanner"),
                    _f("MEDUSA-LLMJACK-003", "LLMProviderHijackScanner"),
                    _f("MEDUSA-TAINT-EXEC-001", "TaintScanner")):
        r = api._summarize(soft + [payload], root="/x")
        assert r["verdict"] == api.DO_NOT_INSTALL, \
            f"{payload['rule_id']} must still DO_NOT_INSTALL amid soft findings, got {r['verdict']}"
