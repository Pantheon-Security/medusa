"""Phase 5/6 CLI output-polish regression tests (`.claude-review/REMEDIATION.md`).

Covers the mechanical output/surface fixes on the REAL paths:

* PR-020 -- a cache-hit scan summary must not contradict itself: the SCAN
            COMPLETE box states the cache hit ("0 (N unchanged, cache hit)")
            instead of a bare "Files scanned: 0" beside "across N files"; the
            clean-state line is cache-aware too.
* PR-022 -- a clean scan (0 findings) collapses the per-scanner table to one
            summary line; a scan with findings still renders the full table.
* PR-023 -- (a) the skipped-scanner line reads "M scanners skipped -- no
            matching files (...)"; (b) report paths print absolute.
* PR-026 -- `medusa install` no longer auto-installs Node.js via winget on
            Windows; it prints an install hint and never invokes winget.
* PR-027 -- `medusa scan <file>` scans that single file instead of refusing.

The SCAN COMPLETE box and the per-scanner table are produced by the real
`MedusaParallelScanner`; CLI commands run through Click's `CliRunner`.
"""

import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from medusa.cli import main, _summarize_skip_languages
from medusa.core.parallel import MedusaParallelScanner, ScanResult


# --------------------------------------------------------------------------- #
# PR-020 -- cache-hit summary consistency
# --------------------------------------------------------------------------- #

def test_pr020_box_annotates_cache_hit(tmp_path, capsys):
    """A full cache hit renders the Files-scanned line with the cache-hit
    annotation, not a bare '0' that contradicts the 'across N files' line."""
    f = tmp_path / "util.py"
    f.write_text("x = 1\n")
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=True)

    cached = ScanResult(
        file=str(f), scanner="cached", issues=[], scan_time=0.0, cached=True,
    )
    scanner.generate_report([cached], tmp_path / "reports", formats=[])
    out = capsys.readouterr().out

    # The Files-scanned line must state the cache hit and the unchanged count.
    m = re.search(r"Files scanned:\s*0\s*\(1 unchanged, cache hit\)", out)
    assert m, out


def test_pr020_box_no_annotation_on_fresh_scan(tmp_path, capsys):
    """A fresh (non-cached) result must NOT gain the cache-hit annotation."""
    f = tmp_path / "util.py"
    f.write_text("x = 1\n")
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=True)
    fresh = ScanResult(
        file=str(f), scanner="PythonScanner", issues=[], scan_time=0.01,
        cached=False, scanner_stats={"PythonScanner": 0}, line_count=1,
    )
    scanner.generate_report([fresh], tmp_path / "reports", formats=[])
    out = capsys.readouterr().out
    assert "cache hit)" not in out, out
    assert re.search(r"Files scanned:\s*1\b", out), out


@pytest.mark.slow  # two real CLI scans (cache warm then hit), full corpus load
def test_pr020_rescan_clean_line_and_box_agree(tmp_path):
    """End-to-end: a re-scan (cache hit) must not print '0 scanners' beside
    'across 1 file'; the clean line states the cache hit instead."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    runner = CliRunner()
    first = runner.invoke(main, ["scan", str(tmp_path)])
    assert first.exit_code == 0, first.output
    second = runner.invoke(main, ["scan", str(tmp_path)])
    assert second.exit_code == 0, second.output
    out = second.output
    assert "cache hit" in out.lower(), out
    # The old contradiction ("across 1 file, 0 scanners") must be gone.
    assert not re.search(r"across\s+1\s+file,\s+0\s+scanners", out), out


# --------------------------------------------------------------------------- #
# PR-022 -- clean scan collapses the per-scanner table
# --------------------------------------------------------------------------- #

def test_pr022_clean_collapses_to_summary_line(tmp_path, capsys):
    """With 0 issues the final per-scanner render is a single summary line, not
    the full table."""
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    scanner_totals = {f"S{i}": {"files": 1, "issues": 0} for i in range(18)}
    scanner_expected = {f"S{i}": 1 for i in range(18)}

    scanner._print_final_scan_table(
        scanner_expected, scanner_totals, 1, 1, total_issues=0
    )
    out = capsys.readouterr().out
    assert "18 scanners checked, 0 issues" in out, out


def test_pr022_findings_still_render_table(tmp_path, capsys):
    """With findings the collapse must NOT apply — the full table renders (the
    one-line summary is absent)."""
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    scanner_totals = {"PythonScanner": {"files": 1, "issues": 2}}
    scanner_expected = {"PythonScanner": 1}

    scanner._print_final_scan_table(
        scanner_expected, scanner_totals, 1, 1, total_issues=2
    )
    out = capsys.readouterr().out
    assert "checked, 0 issues" not in out, out


def test_pr022_single_scanner_pluralization(tmp_path, capsys):
    """One scanner reads 'scanner', not 'scanners'."""
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    scanner._print_final_scan_table(
        {"S0": 1}, {"S0": {"files": 1, "issues": 0}}, 1, 1, total_issues=0
    )
    out = capsys.readouterr().out
    assert "1 scanner checked, 0 issues" in out, out


# --------------------------------------------------------------------------- #
# PR-023 -- microcopy + absolute report paths
# --------------------------------------------------------------------------- #

def test_pr023b_report_path_is_absolute(tmp_path, capsys):
    """Generated-report paths print absolute, not '../../..'-relative."""
    f = tmp_path / "util.py"
    f.write_text("x = 1\n")
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    result = ScanResult(
        file=str(f), scanner="PythonScanner", issues=[], scan_time=0.01,
        scanner_stats={"PythonScanner": 0}, line_count=1,
    )
    out_dir = tmp_path / "reports"
    scanner.generate_report([result], out_dir, formats=["json"])
    out = capsys.readouterr().out

    m = re.search(r"JSON\s+\S+\s+(\S+medusa-scan-\S+\.json)", out)
    assert m, out
    printed = m.group(1)
    assert printed.startswith("/"), f"report path not absolute: {printed}\n{out}"
    assert ".." not in printed, f"report path still relative-upward: {printed}"


def test_pr023a_skip_lang_helper_empty_when_no_languages():
    """The language helper returns '' (not the old 'matching' fallback) when no
    skipped scanner maps to a language, so the caller can drop the parenthetical."""
    class _A:
        skip_scanners = {"NotARealScanner"}
    assert _summarize_skip_languages(_A()) == ""


@pytest.mark.slow  # real CLI scan of a clean python file, full corpus load
def test_pr023a_skipped_line_phrasing(tmp_path):
    """The live skipped-scanner line reads 'scanners skipped -- no matching
    files (...)', not the old '(no ... files found)'."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    out = result.output
    assert "scanners skipped" in out, out
    assert "no matching files" in out, out
    assert "files found)" not in out, out


# --------------------------------------------------------------------------- #
# PR-027 -- scan a single file instead of refusing
# --------------------------------------------------------------------------- #

@pytest.mark.slow  # real CLI single-file scan, full corpus load
def test_pr027_scan_single_file_is_accepted(tmp_path):
    """`medusa scan <file>` scans just that file and exits clean; the old
    'Target must be a directory' refusal is gone."""
    f = tmp_path / "lonely.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    result = CliRunner().invoke(main, ["scan", str(f)])
    assert result.exit_code == 0, result.output
    assert "must be a directory" not in result.output, result.output
    assert "across 1 file" in result.output, result.output


def test_pr027_missing_path_still_errors_exit_2():
    """A nonexistent target still errors with exit 2 (unchanged)."""
    result = CliRunner().invoke(main, ["scan", "/no/such/path/here.py"])
    assert result.exit_code == 2, result.output
    assert "does not exist" in result.output, result.output


# --------------------------------------------------------------------------- #
# PR-026 -- no Node.js winget auto-install; print a hint instead
# --------------------------------------------------------------------------- #

def test_pr026_prints_hint_and_never_invokes_winget(monkeypatch, capsys):
    """On (mocked) Windows with npm tools failed, `_check_runtime_dependencies`
    prints the Node.js install hint and NEVER shells out to winget."""
    import medusa.cli as cli
    from medusa.platform import PackageManager

    # Guard: any version-check subprocess (winget lives here) is a failure.
    def _boom(*a, **k):
        raise AssertionError(f"subprocess invoked during install hint: {a}")

    monkeypatch.setattr(cli, "_safe_run_version_check", _boom)

    class _OS:
        value = "windows"

    class _PInfo:
        os_type = _OS()

    cli._check_runtime_dependencies(
        missing_tools=["eslint"],
        npm_tools_failed=["eslint"],
        platform_info=_PInfo(),
        pm=PackageManager.WINGET,
        yes=True,
    )
    out = capsys.readouterr().out
    assert "Node.js" in out, out
    # A hint points the user at an install source; it must not claim to install.
    assert "nodejs.org" in out or "winget install" in out, out
    assert "Installing Node.js" not in out, out


def test_pr026_non_windows_is_noop(monkeypatch, capsys):
    """Non-Windows platforms short-circuit (unchanged)."""
    import medusa.cli as cli
    from medusa.platform import PackageManager

    class _OS:
        value = "linux"

    class _PInfo:
        os_type = _OS()

    cli._check_runtime_dependencies(
        missing_tools=["eslint"], npm_tools_failed=["eslint"],
        platform_info=_PInfo(), pm=PackageManager.APT, yes=True,
    )
    assert capsys.readouterr().out == ""
