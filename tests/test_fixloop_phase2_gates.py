"""Phase-2 (HIGH) gates for the install-gate / vet trust-surface remediation.

CR-007 (path_classes) + CR-008 (vet_tiers) are behaviour-preserving refactors, so
their gates are single-source + invariant assertions rather than born-red bug
repros. Behavioural HIGH tickets (CR-009..CR-016) add born-red cases below as they
land. Traceability: .claude-review/REMEDIATION.md Phase 2.
"""
import medusa.core.scan_api as api  # noqa: E402
import medusa.core.fp_filter as fp  # noqa: E402
from medusa.core import path_classes as pc  # noqa: E402
from medusa.core import vet_tiers as vt  # noqa: E402


# ---- CR-007 — canonical test-data / live-payload path classification ---------
def test_cr007_single_source_test_data_dirs():
    # scan_api + reporter both point at the canonical frozenset (no drifted copies).
    import medusa.core.reporter as rep
    assert api._VET_TEST_DATA_DIRS is pc.TEST_DATA_DIRS
    assert rep._TEST_DATA_DIRS is pc.TEST_DATA_DIRS

def test_cr007_union_covers_every_prior_member():
    # the union must contain every dir each prior definition used
    for d in ("vectors", "samples", "sample", "androidtest", "jvmtest",  # scan_api
              "e2e", "__fixtures__", "testfixtures", "mock"):            # cred scanner
        assert d in pc.TEST_DATA_DIRS, d

def test_cr007_live_payload_survives_test_dir():
    assert pc.is_live_payload_file("tests/fixtures/id_rsa")
    assert pc.is_live_payload_file("examples/.mcp.json")
    assert not pc.is_live_payload_file("tests/fixtures/data.txt")


# ---- CR-008 — canonical vet tiers, no fail-open drift ------------------------
def test_cr008_signal_and_never_generic_are_canonical():
    assert api._VET_SIGNAL_RULE_PREFIXES is vt.SIGNAL_RULE_PREFIXES
    assert fp.FalsePositiveFilter._NEVER_GENERIC_FP_PREFIXES is vt.NEVER_GENERIC_FP_PREFIXES

def test_cr008_soft_tier_prefixes_subset_of_signal_or_intentional():
    # Invariant: every soft-tier that is ALSO a hard-signal prefix must appear in
    # the signal universe (a soft tier that isn't even a signal can't cap a
    # verdict it never entered). ATKSIG/DKR/PLG/DSI/PIC/env-* are soft-only tiers
    # (they gate via scanner attribution / their own emit path), so we assert the
    # ones that ARE signal-prefixes are present, catching the fail-open drift.
    signal = vt.SIGNAL_RULE_PREFIXES
    for name, scanners, prefixes, ids in vt.SOFT_TIERS:
        for p in prefixes:
            if p in ("CVE-", "MEDUSA-OSV-001", "MEDUSA-ATKSIG-", "MEDUSA-RCE-FETCHEXEC-"):
                assert p in signal, f"soft prefix {p} ({name}) missing from signal universe"

def test_cr008_soft_tier_of_matches_predicates():
    # The table must agree with every predicate the tests/verdict rely on.
    def f(rid, scn="X"):
        return {"rule_id": rid, "scanner": scn}
    cases = [
        ("CVE-2018-1", "dependency_vuln", api._is_dependency_vuln_signal),
        ("MEDUSA-ATKSIG-1", "attack_signature", api._is_attack_signature_signal),
        ("DKR001", "docker_hardening", api._is_docker_hardening_signal),
        ("MEDUSA-SKILL-ROGUE-001", "soft_review", api._is_soft_review_signal),
        ("PLG008", "plugin_security", api._is_plugin_security_signal),
        ("DSI001", "repo_ai_hygiene", api._is_repo_ai_hygiene_signal),
        ("MEDUSA-RCE-FETCHEXEC-001", "fetch_exec", api._is_fetch_exec_signal),
        ("env-sensitive-var-x", "env_name_only", api._is_env_name_only_signal),
    ]
    for rid, tier, pred in cases:
        assert vt.soft_tier_of(f(rid)) == tier, rid
        assert pred(f(rid)) is True, rid
    # a hard-block malice id is NOT in any soft tier
    assert vt.soft_tier_of(f("MEDUSA-MCP-POISON-001")) is None
    assert vt.soft_tier_of(f("CC-HOOK-001")) is None


# ---- CR-009 — curated malice survives an attacker-chosen test-data path ------
def _vf(rid, file, scn="X"):
    return {"rule_id": rid, "scanner": scn, "file": file, "severity": "CRITICAL"}

def test_cr009_curated_malice_survives_examples_dir():
    # CC-AGENT under examples/.claude/agents/ is a wildcard-Bash grant, not a fixture.
    assert api._is_vet_signal(_vf("CC-AGENT-001", "examples/.claude/agents/evil.md"))
    assert api._is_vet_signal(_vf("MEDUSA-SKILL-ROGUE-001", "fixtures/skills/x/drop.sh"))
    assert api._is_vet_signal(_vf("MEDUSA-CRED-001", "tests/fixtures/id_rsa"))

def test_cr009_live_payload_dirs_recognised():
    assert pc.is_live_payload_file("examples/.claude/agents/evil.md")
    assert pc.is_live_payload_file("tests/skills/pkg/postinstall.sh")

def test_cr009_generic_finding_in_tests_still_dropped():
    # preserve behavior: a generic (non-malice, non-signal) finding under tests/
    # with an attack STRING is still not a verdict signal.
    assert not api._is_vet_signal(_vf("MEDUSA-INF-SCAN-2830", "tests/test_x.py", "InferenceScanner"))
