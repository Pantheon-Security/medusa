"""B-items fix-loop gates (false-block reduction).

FX-B01 — model-loading-CALL hygiene rules (MLSC-LOAD-*) must soft-tier (cap at
CAUTION), so a legitimate model-loading repo (openshield / GPTFuzz / llm-attacks)
is not hard-blocked (DO_NOT_INSTALL). Committed poisoned-model FILE families
(MLSC-SERIAL-* / MLSC-HUB-*) must stay hard.
"""
import pytest

from medusa.core.vet_tiers import soft_tier_of


def test_mlsc_load_calls_are_soft_tiered():
    # from_pretrained / torch.load / trust_remote_code / revision-pin are
    # loading-hygiene warnings, not "this repo attacks the installer".
    for rid in ("MLSC-LOAD-001", "MLSC-LOAD-002", "MLSC-LOAD-003", "MLSC-LOAD-004"):
        assert soft_tier_of({"scanner": "ModelScanScanner", "rule_id": rid}) == "model_load", rid


def test_poisoned_model_file_families_stay_hard():
    # Do-NOT guard: SERIAL/HUB (a committed malicious serialized model) is a real
    # install-time-malice signal — the model_load tier must not soften it.
    for rid in ("MLSC-SERIAL-001", "MLSC-HUB-001"):
        assert soft_tier_of({"scanner": "ModelScanScanner", "rule_id": rid}) is None, rid


# --- FX-B03: committed test TLS certs (.key/.pem in test dirs) are fixtures ------
from medusa.core import scan_api as _s  # noqa: E402


def test_fxb03_test_tls_cert_is_not_a_hard_signal():
    cert = {"scanner": "CredentialFileScanner", "rule_id": "MEDUSA-CRED-001",
            "file": "requests/tests/certs/server.key", "severity": "HIGH"}
    assert _s._is_vet_signal(cert) is False                 # test-cert fixture, not a signal
    # Do-NOT: a private key OUTSIDE a test dir still hard-blocks
    assert _s._is_vet_signal(dict(cert, file="requests/src/prod.key")) is True
    # Do-NOT: a non-TLS-cert credential (a token in a .env) in a test dir still hard-blocks
    assert _s._is_vet_signal({"scanner": "CredentialFileScanner", "rule_id": "MEDUSA-CRED-002",
                              "file": "tests/data/aws.env", "severity": "HIGH"}) is True


# --- FX-B04: LLMJACK-002 base-URL/key example in a DOC file caps at CAUTION ------
def test_fxb04_llmjack002_in_readme_is_caution_not_block():
    doc = _s._summarize([{"scanner": "LLMProviderHijackScanner", "rule_id": "MEDUSA-LLMJACK-002",
                          "file": "README.md", "severity": "CRITICAL", "line": 10}])
    assert doc["verdict"] == _s.CAUTION, doc["verdict"]      # config example → review, not block
    # Do-NOT: the same finding in shipped code stays a hard block
    code = _s._summarize([{"scanner": "LLMProviderHijackScanner", "rule_id": "MEDUSA-LLMJACK-002",
                           "file": "app.py", "severity": "CRITICAL", "line": 10}])
    assert code["verdict"] == _s.DO_NOT_INSTALL, code["verdict"]


# --- FX-B04a: the doc exemption must NOT cover agent-CONTROL manifests ----------
# Born-RED regression gate. FX-B04 keyed on `_is_doc_or_test_file`, which is true for
# ANY `.md` — including SKILL.md, the primary delivery vehicle for the key-exfil
# attack (CVE-2026-21852 class). That softened a poisoned skill from DO_NOT_INSTALL
# to CAUTION and broke the functional gate's Check E, while all 59 unit gates passed.
@pytest.mark.parametrize("path", [
    ".claude/skills/x/SKILL.md",
    "examples/.claude/skills/helper/SKILL.md",   # parked under a test-data dir
    ".claude/agents/evil.md",
    "skills/helper/SKILL.md",
])
def test_fxb04a_agent_control_manifest_still_hard_blocks(path):
    r = _s._summarize([{"scanner": "LLMProviderHijackScanner", "rule_id": "MEDUSA-LLMJACK-002",
                        "file": path, "severity": "CRITICAL", "line": 2}])
    assert r["verdict"] == _s.DO_NOT_INSTALL, f"{path} -> {r['verdict']} (must hard-block)"


def test_fxb04a_plain_readme_still_softens():
    # The aifw false-block fix must survive the guard above.
    r = _s._summarize([{"scanner": "LLMProviderHijackScanner", "rule_id": "MEDUSA-LLMJACK-002",
                        "file": "docs/README.md", "severity": "CRITICAL", "line": 10}])
    assert r["verdict"] == _s.CAUTION, r["verdict"]

# FX-B05 (claude-forge SKILL-ROGUE-001) intentionally NOT auto-fixed: the claude-forge
# false-positive comes from the flattened/normalized anti-evasion pass (a verb + a
# .claude/ or SKILL.md target joined across lines), NOT a single-line match — so
# narrowing the rule risks weakening that deliberate split-directive detection.
# Surfaced for careful detection-engineering; see the suite triage notes.
