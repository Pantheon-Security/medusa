#!/usr/bin/env python3
"""Build item #2: fingerprint baseline / suppression mode.

These are REAL end-to-end tests driven through the CLI (`CliRunner`) against a
synthetic temp directory containing findable issues. They exercise the three
contractual behaviours:

  1. `--write-baseline b.json` writes the current findings' fingerprints.
  2. Re-scanning with `--baseline b.json` suppresses all of those findings
     (0 new, N suppressed).
  3. Adding a NEW issue file and re-scanning with `--baseline b.json` surfaces
     only the new finding (1 new, N suppressed).

Plus unit-level coverage of the baseline helpers in
``medusa.core.baseline`` (fingerprint stability, load/write round-trip,
missing-file tolerance, apply split).

`--no-cache` is used throughout so a warm result cache never masks findings on
the repeated scans of the same directory.
"""

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from medusa.cli import main
from medusa.core.baseline import (
    apply_baseline,
    finding_fingerprint,
    load_baseline,
    write_baseline,
)


# A fixture line that reliably triggers a hardcoded-secret finding (mirrors the
# fixture used by tests/test_p2_empty_state.py::test_nonzero_findings...).
SECRET_LINE = 'SECRET_KEY = "hardcoded_secret_value_abc123!"\n'
SECOND_SECRET_LINE = 'API_TOKEN = "another_hardcoded_token_xyz789!"\n'


def _make_project(tmp_path: Path) -> Path:
    """Create a synthetic project dir with one findable file."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "config.py").write_text("# config\n" + SECRET_LINE)
    return proj


def _scan(runner: CliRunner, args):
    return runner.invoke(main, ["scan", *args, "--no-report", "--no-cache"])


def _parse_suppressed_and_new(output: str):
    """Pull the (suppressed, new) counts out of the baseline-applied line."""
    m = re.search(
        r"Baseline applied:\s*(\d+)\s+finding\(s\)\s+suppressed,\s*(\d+)\s+new",
        output,
    )
    assert m, f"Expected a 'Baseline applied' line in output:\n{output[-1500:]}"
    return int(m.group(1)), int(m.group(2))


# --------------------------------------------------------------------------- #
# Unit-level helper coverage
# --------------------------------------------------------------------------- #

class TestBaselineHelpers:
    def test_fingerprint_matches_reporter_formula(self):
        import hashlib

        finding = {
            "rule_id": "R1",
            "file": "a.py",
            "line": 12,
            "issue": "Hardcoded secret",
        }
        expected = hashlib.sha256(b"R1:a.py:12:Hardcoded secret").hexdigest()
        assert finding_fingerprint(finding) == expected

    def test_fingerprint_stable_and_field_sensitive(self):
        f1 = {"rule_id": "R1", "file": "a.py", "line": 1, "issue": "x"}
        f2 = {"rule_id": "R1", "file": "a.py", "line": 2, "issue": "x"}
        assert finding_fingerprint(f1) == finding_fingerprint(dict(f1))
        assert finding_fingerprint(f1) != finding_fingerprint(f2)

    def test_load_missing_file_returns_empty_set(self, tmp_path):
        assert load_baseline(tmp_path / "nope.json") == set()

    def test_load_malformed_file_returns_empty_set(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        assert load_baseline(bad) == set()

    def test_write_then_load_round_trip(self, tmp_path):
        findings = [
            {"rule_id": "R1", "file": "a.py", "line": 1, "issue": "x"},
            {"rule_id": "R2", "file": "b.py", "line": 2, "issue": "y"},
        ]
        path = tmp_path / "b.json"
        n = write_baseline(findings, path)
        assert n == 2
        loaded = load_baseline(path)
        assert loaded == {finding_fingerprint(f) for f in findings}

    def test_write_dedupes(self, tmp_path):
        f = {"rule_id": "R1", "file": "a.py", "line": 1, "issue": "x"}
        path = tmp_path / "b.json"
        n = write_baseline([f, dict(f)], path)
        assert n == 1

    def test_load_accepts_bare_list(self, tmp_path):
        path = tmp_path / "list.json"
        path.write_text(json.dumps(["aaa", "bbb"]))
        assert load_baseline(path) == {"aaa", "bbb"}

    def test_apply_splits_kept_and_suppressed(self):
        f1 = {"rule_id": "R1", "file": "a.py", "line": 1, "issue": "x"}
        f2 = {"rule_id": "R2", "file": "b.py", "line": 2, "issue": "y"}
        baseline = {finding_fingerprint(f1)}
        kept, suppressed = apply_baseline([f1, f2], baseline)
        assert kept == [f2]
        assert suppressed == [f1]

    def test_apply_empty_baseline_keeps_all(self):
        f1 = {"rule_id": "R1", "file": "a.py", "line": 1, "issue": "x"}
        kept, suppressed = apply_baseline([f1], set())
        assert kept == [f1]
        assert suppressed == []


# --------------------------------------------------------------------------- #
# End-to-end CLI behaviour
# --------------------------------------------------------------------------- #

@pytest.mark.slow  # each test runs a real CLI scan (full rule corpus reload, ~16-18s each)
class TestBaselineCLI:
    def test_write_baseline_records_fingerprints(self, tmp_path):
        proj = _make_project(tmp_path)
        baseline_file = tmp_path / "b.json"

        runner = CliRunner(mix_stderr=False)
        result = _scan(runner, [str(proj), "--write-baseline", str(baseline_file)])
        assert result.exit_code == 0, result.output

        assert baseline_file.exists(), "baseline file was not written"
        fps = load_baseline(baseline_file)
        assert len(fps) >= 1, (
            f"Expected at least one fingerprint written. Output:\n{result.output[-1500:]}"
        )
        # The CLI should report how many fingerprints it wrote.
        assert "Wrote baseline" in result.output

    def test_baseline_suppresses_known_findings(self, tmp_path):
        proj = _make_project(tmp_path)
        baseline_file = tmp_path / "b.json"
        runner = CliRunner(mix_stderr=False)

        # 1) Write the baseline.
        write_res = _scan(
            runner, [str(proj), "--write-baseline", str(baseline_file)]
        )
        assert write_res.exit_code == 0, write_res.output
        n_baseline = len(load_baseline(baseline_file))
        assert n_baseline >= 1

        # 2) Re-scan with the baseline applied — all known findings suppressed.
        apply_res = _scan(runner, [str(proj), "--baseline", str(baseline_file)])
        assert apply_res.exit_code == 0, apply_res.output
        suppressed, new = _parse_suppressed_and_new(apply_res.output)
        assert new == 0, f"Expected 0 new findings, got {new}\n{apply_res.output[-1500:]}"
        assert suppressed == n_baseline, (
            f"Expected {n_baseline} suppressed, got {suppressed}"
        )

    def test_new_issue_surfaces_past_baseline(self, tmp_path):
        proj = _make_project(tmp_path)
        baseline_file = tmp_path / "b.json"
        runner = CliRunner(mix_stderr=False)

        # 1) Baseline the original state.
        write_res = _scan(
            runner, [str(proj), "--write-baseline", str(baseline_file)]
        )
        assert write_res.exit_code == 0, write_res.output
        n_baseline = len(load_baseline(baseline_file))
        assert n_baseline >= 1

        # 2) Introduce a brand-new issue in a new file.
        (proj / "extra.py").write_text("# extra\n" + SECOND_SECRET_LINE)

        # 3) Re-scan with the baseline — only the new finding(s) surface.
        apply_res = _scan(runner, [str(proj), "--baseline", str(baseline_file)])
        assert apply_res.exit_code == 0, apply_res.output
        suppressed, new = _parse_suppressed_and_new(apply_res.output)
        assert suppressed == n_baseline, (
            f"Original findings should still be suppressed: expected "
            f"{n_baseline}, got {suppressed}\n{apply_res.output[-1500:]}"
        )
        assert new >= 1, (
            f"The newly added issue should surface as NEW, got {new} new\n"
            f"{apply_res.output[-1500:]}"
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-o", "addopts="]))
