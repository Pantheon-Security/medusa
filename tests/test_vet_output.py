"""Round-2 FP Phase 1 -- honest `medusa vet` human output.

A PC001 review flagged that the old vet summary led with the scary *total*
finding count (`171 total`) sitting next to a narrow `blocking 2` -- reading as
alarming even though the verdict blocks on the two signals only. These tests
pin the corrected PRESENTATION: lead with the VERDICT, then a headline that
separates BLOCKING from merely DETECTED (non-blocking) findings, list only the
blocking set, and offer ONE hint for the rest -- never dump all N findings.

Tests drive the real CLI entrypoint (Click's ``CliRunner``) and monkeypatch
``scan_api.vet_repo`` so no scan/network/git runs. ``--json`` must stay the raw
verdict dict, and exit codes must not move (SAFE=0, CAUTION=1, DO_NOT_INSTALL=2).
"""
import json as _json

from click.testing import CliRunner

from medusa.cli import main
from medusa.core import scan_api


def _run(fake, args=("vet", "some/dir"), monkeypatch=None):
    monkeypatch.setattr("medusa.core.scan_api.vet_repo", lambda *a, **k: fake)
    return CliRunner().invoke(main, list(args))


def test_caution_leads_with_blocking_not_total(monkeypatch):
    """CAUTION with 2 blocking out of 171 total: the headline separates the two
    counts, lists only the blocking findings, and never dumps all 171."""
    fake = {
        "verdict": scan_api.CAUTION,
        "score": 40,
        "counts_by_severity": {"HIGH": 2},
        "total_findings": 171,
        "blocking_findings": 2,
        "other_findings": 169,
        "top_findings": [
            {"severity": "HIGH", "rule_id": "MCP-POISON-002",
             "file": "server.py", "line": 10},
            {"severity": "HIGH", "rule_id": "SKILL-ANTIREFUSAL-001",
             "file": "SKILL.md", "line": 3},
        ],
        "target": "some/dir",
    }
    res = _run(fake, monkeypatch=monkeypatch)
    assert res.exit_code == 1, res.output  # CAUTION

    # Verdict still leads.
    assert res.output.splitlines()[0].startswith("VERDICT: CAUTION"), res.output
    # Honest headline: blocking count is the lead, detected is secondary.
    assert "2 blocking" in res.output, res.output
    assert "detected" in res.output, res.output
    assert "169" in res.output, res.output  # the non-blocking remainder count

    # Only the blocking set is listed by rule -- exactly two detail lines.
    detail_lines = [ln for ln in res.output.splitlines()
                    if ln.lstrip().startswith("[")]
    assert len(detail_lines) == 2, res.output
    assert "MCP-POISON-002" in res.output
    # The scary total is NOT presented as "171 total" and no 171-line dump.
    assert "171 total" not in res.output, res.output
    assert res.output.count("[HIGH]") == 2, res.output


def test_caution_shows_hint_for_nonblocking_remainder(monkeypatch):
    """When there are non-blocking detections, exactly one hint line points at
    `medusa scan` for the full report -- not an inline dump."""
    fake = {
        "verdict": scan_api.CAUTION, "score": 40,
        "total_findings": 171, "blocking_findings": 2, "other_findings": 169,
        "top_findings": [
            {"severity": "HIGH", "rule_id": "R1", "file": "a.py", "line": 1},
            {"severity": "HIGH", "rule_id": "R2", "file": "b.py", "line": 2},
        ],
        "target": "some/dir",
    }
    res = _run(fake, monkeypatch=monkeypatch)
    hint_lines = [ln for ln in res.output.splitlines()
                  if "non-blocking findings" in ln and "medusa scan" in ln]
    assert len(hint_lines) == 1, res.output


def test_safe_shows_zero_blocking_and_no_finding_dump(monkeypatch):
    """SAFE with 0 blocking / 5 detected: headline shows 0 blocking, no blocking
    list, exit 0."""
    fake = {
        "verdict": scan_api.SAFE, "score": 3,
        "total_findings": 5, "blocking_findings": 0, "other_findings": 5,
        "top_findings": [],
        "target": "some/dir",
    }
    res = _run(fake, monkeypatch=monkeypatch)
    assert res.exit_code == 0, res.output
    assert "0 blocking" in res.output, res.output
    # No blocking detail lines when nothing blocks.
    detail_lines = [ln for ln in res.output.splitlines()
                    if ln.lstrip().startswith("[")]
    assert detail_lines == [], res.output


def test_safe_clean_repo_no_hint(monkeypatch):
    """A truly clean SAFE repo (0/0) shows 0 blocking and emits no scan hint."""
    fake = {
        "verdict": scan_api.SAFE, "score": 0,
        "total_findings": 0, "blocking_findings": 0, "other_findings": 0,
        "top_findings": [], "target": "some/dir",
    }
    res = _run(fake, monkeypatch=monkeypatch)
    assert res.exit_code == 0, res.output
    assert "0 blocking" in res.output, res.output
    assert "non-blocking findings" not in res.output, res.output


def test_json_output_is_raw_dict_unchanged(monkeypatch):
    """`vet --json` must remain the raw verdict dict -- the headline/hint
    rendering is human-output only."""
    fake = {
        "verdict": scan_api.CAUTION, "score": 40,
        "total_findings": 171, "blocking_findings": 2, "other_findings": 169,
        "top_findings": [
            {"severity": "HIGH", "rule_id": "R1", "file": "a.py", "line": 1},
        ],
        "target": "some/dir",
    }
    res = _run(fake, args=("vet", "some/dir", "--json"), monkeypatch=monkeypatch)
    assert res.exit_code == 1, res.output
    parsed = _json.loads(res.output)
    assert parsed == fake  # byte-for-byte the same dict, no headline injected


def test_missing_count_keys_do_not_crash(monkeypatch):
    """A minimal verdict dict (older seam callers pass only verdict+score) must
    still render without KeyError and default to 0 blocking."""
    fake = {"verdict": scan_api.SAFE, "score": 1}
    res = _run(fake, monkeypatch=monkeypatch)
    assert res.exit_code == 0, res.output
    assert "VERDICT: SAFE" in res.output, res.output
    assert "0 blocking" in res.output, res.output
