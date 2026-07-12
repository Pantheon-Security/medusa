"""Two-sided gate for the vet screening-only (harvested) verdict cap.

The harvested screening corpus runs in vet mode for recall but is low-precision by
design; it must INFORM (CAUTION) not DECIDE (DO_NOT_INSTALL). Curated rules and the
malice-signal prefixes must still hard-block. This locks both directions so the cap
can't silently start blinding real malice, or start hard-blocking on harvested noise.
"""
import medusa.core.scan_api as api


def _f(rule_id, scanner, severity="CRITICAL", file="src/app.py"):
    return {"rule_id": rule_id, "scanner": scanner, "severity": severity,
            "file": file, "line": 1, "issue": "x"}


# A known harvested id for the test; monkeypatch the corpus lookup for determinism.
HARVESTED = "MEDUSA-MCP-SCAN-2966"


def _patch(monkeypatch):
    monkeypatch.setattr(api, "_screening_only_rule_ids",
                        lambda: frozenset({HARVESTED}))


def test_curated_malice_still_hard_blocks(monkeypatch):
    _patch(monkeypatch)
    # CC- is a curated malice-signal prefix, NOT screening-only.
    r = api._summarize([_f("CC-HOOK-001", "ClaudeCodeScanner")], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]


def test_harvested_only_caps_at_caution_not_block(monkeypatch):
    _patch(monkeypatch)
    # A CRITICAL harvested match from a signal scanner: soft tier -> never DO_NOT_INSTALL.
    r = api._summarize([_f(HARVESTED, "MCPServerScanner")], root="/x")
    assert r["verdict"] != api.DO_NOT_INSTALL, r["verdict"]
    assert r["verdict"] in (api.SAFE, api.CAUTION), r["verdict"]


def test_many_harvested_still_never_hard_blocks(monkeypatch):
    _patch(monkeypatch)
    # Even 20 harvested CRITICALs (the notebooklm carpet-bomb) must not hard-block.
    r = api._summarize([_f(HARVESTED, "MCPServerScanner", file=f"a/{i}.py")
                        for i in range(20)], root="/x")
    assert r["verdict"] != api.DO_NOT_INSTALL, r["verdict"]


def test_malice_beats_harvested(monkeypatch):
    _patch(monkeypatch)
    # A real malice signal mixed in with harvested noise still hard-blocks.
    r = api._summarize([_f(HARVESTED, "MCPServerScanner"),
                        _f("CC-HOOK-001", "ClaudeCodeScanner")], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]


def test_atksig_alone_caps_at_caution(monkeypatch):
    _patch(monkeypatch)
    # ATKSIG = "this repo CONTAINS attack strings" (a jailbreak dataset, a fuzzing
    # corpus, a firewall's own detection patterns) — CAUTION (review), never
    # DO_NOT_INSTALL on its own. This is the biggest false-block fix on security
    # tools / attack research.
    r = api._summarize([_f("MEDUSA-ATKSIG-001", "AIAttackSignatureScanner")], root="/x")
    assert r["verdict"] != api.DO_NOT_INSTALL, r["verdict"]
    assert r["verdict"] in (api.SAFE, api.CAUTION), r["verdict"]


def test_many_atksig_still_never_hard_blocks(monkeypatch):
    _patch(monkeypatch)
    # A jailbreak dataset with hundreds of ATKSIG hits must not hard-block.
    r = api._summarize([_f("MEDUSA-ATKSIG-003", "AIAttackSignatureScanner", file=f"d/{i}.txt")
                        for i in range(50)], root="/x")
    assert r["verdict"] != api.DO_NOT_INSTALL, r["verdict"]


def test_atksig_plus_real_malice_still_blocks(monkeypatch):
    _patch(monkeypatch)
    # A poisoned hook (CC-) alongside attack signatures still hard-blocks — ATKSIG
    # only ever corroborated the actionable malice.
    r = api._summarize([_f("MEDUSA-ATKSIG-001", "AIAttackSignatureScanner"),
                        _f("CC-HOOK-001", "ClaudeCodeScanner")], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]
