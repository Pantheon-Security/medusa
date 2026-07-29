"""B-items fix-loop gates (false-block reduction).

FX-B01 — model-loading-CALL hygiene rules (MLSC-LOAD-*) must soft-tier (cap at
CAUTION), so a legitimate model-loading repo (openshield / GPTFuzz / llm-attacks)
is not hard-blocked (DO_NOT_INSTALL). Committed poisoned-model FILE families
(MLSC-SERIAL-* / MLSC-HUB-*) must stay hard.
"""
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
