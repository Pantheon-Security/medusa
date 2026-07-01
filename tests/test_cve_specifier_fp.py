#!/usr/bin/env python3
"""
Regression tests for the CVE-specifier false-positive bug.

Both CVE scanners used to treat a MINIMUM / RANGE version specifier (``>=``,
``~=``, ``^``, ``<``, ...) as if it were an exact pin, so a manifest like
``certifi>=2023.5.7`` (which just says "at least 2023.5.7 — actual installed
version unknown") was matched against CVE ranges and produced phantom CRITICAL
findings. A range means "unknown installed version" and MUST NOT be flagged;
only an exact ``==`` pin (or an exact lockfile entry) is a concrete version.

These tests exercise the REAL scan path:
  - CriticalCVEScanner.scan_file() against the shipped local CVE database
    (no network), and
  - DependencyCVEScanner.scan() with the OSV network boundary mocked.
"""

from pathlib import Path

import pytest

from medusa.scanners.critical_cve_scanner import CriticalCVEScanner
from medusa.scanners.dependency_cve_scanner import DependencyCVEScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cve_findings(result):
    """Version-range CVE findings only (rule_id ``cve-...``), not sca-/import."""
    return [i for i in result.issues if (i.rule_id or "").startswith("cve-")]


def _cve_ids(result):
    return {(i.rule_id or "").lower() for i in _cve_findings(result)}


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# CriticalCVEScanner (local DB, no network)
# ---------------------------------------------------------------------------

def test_requirements_min_specifier_not_flagged(tmp_path):
    """`certifi>=2023.5.7` is a range, not a pin -> no CVE finding."""
    scanner = CriticalCVEScanner()
    # certifi>=2023.5.7 would, under the bug, be read as ==2023.5.7 and match
    # CVE-2023-37920 (vulnerable < 2023.7.22). It must NOT fire for a range.
    p = _write(tmp_path, "requirements.txt", "certifi>=2023.5.7\njinja2>=3.1.2\n")
    result = scanner.scan_file(p)
    assert _cve_findings(result) == [], _cve_ids(result)


def test_requirements_exact_vuln_pin_still_flagged(tmp_path):
    """`pyyaml==5.3.1` is an exact pin in a vulnerable range -> STILL flagged."""
    scanner = CriticalCVEScanner()
    p = _write(tmp_path, "requirements.txt", "pyyaml==5.3.1\n")
    ids = _cve_ids(scanner.scan_file(p))
    assert "cve-cve-2020-1747" in ids, ids


def test_pyproject_tox_pin_not_treated_as_install_dep(tmp_path):
    """An exact vuln pin under [tool.tox] is a test tool, not an install dep."""
    scanner = CriticalCVEScanner()
    content = (
        "[project]\n"
        'name = "myapp"\n'
        'version = "1.0.0"\n'
        "dependencies = [\n"
        '    "click>=7.0",\n'
        "]\n"
        "\n"
        "[tool.tox]\n"
        'deps = ["pyyaml==5.3.1"]\n'
    )
    p = _write(tmp_path, "pyproject.toml", content)
    assert _cve_findings(scanner.scan_file(p)) == [], _cve_ids(scanner.scan_file(p))


def test_pyproject_project_dependency_exact_pin_flagged(tmp_path):
    """An exact vuln pin under [project.dependencies] IS an install dep."""
    scanner = CriticalCVEScanner()
    content = (
        "[project]\n"
        'name = "myapp"\n'
        "dependencies = [\n"
        '    "pyyaml==5.3.1",\n'
        "]\n"
    )
    p = _write(tmp_path, "pyproject.toml", content)
    ids = _cve_ids(scanner.scan_file(p))
    assert "cve-cve-2020-1747" in ids, ids


def test_pyproject_poetry_caret_not_flagged(tmp_path):
    """Poetry `pyyaml = "^5.3.1"` is a caret range, not an exact pin."""
    scanner = CriticalCVEScanner()
    content = (
        "[tool.poetry.dependencies]\n"
        'python = "^3.10"\n'
        'pyyaml = "^5.3.1"\n'
    )
    p = _write(tmp_path, "pyproject.toml", content)
    assert _cve_findings(scanner.scan_file(p)) == [], _cve_ids(scanner.scan_file(p))


def test_pyproject_poetry_exact_pin_flagged(tmp_path):
    """Poetry `pyyaml = "==5.3.1"` (or bare "5.3.1") is an exact pin."""
    scanner = CriticalCVEScanner()
    content = (
        "[tool.poetry.dependencies]\n"
        'python = "^3.10"\n'
        'pyyaml = "==5.3.1"\n'
    )
    p = _write(tmp_path, "pyproject.toml", content)
    ids = _cve_ids(scanner.scan_file(p))
    assert "cve-cve-2020-1747" in ids, ids


# ---------------------------------------------------------------------------
# DependencyCVEScanner (OSV network boundary mocked)
# ---------------------------------------------------------------------------

def _osv_pyyaml_vuln(chunk):
    """Mock querybatch: pyyaml 5.3.1 is vulnerable, everything else is clean."""
    return [
        ["CVE-2020-1747"] if (n in ("pyyaml", "pyaml") and v == "5.3.1") else []
        for (n, v, e) in chunk
    ]


def _osv(scanner, monkeypatch):
    monkeypatch.setattr(scanner, "_post_querybatch", _osv_pyyaml_vuln)


def test_osv_requirements_min_specifier_not_queried(monkeypatch, tmp_path):
    """A `>=` spec is not a pin -> DependencyCVEScanner never flags it."""
    scanner = DependencyCVEScanner()
    _osv(scanner, monkeypatch)
    p = _write(tmp_path, "requirements.txt", "pyyaml>=5.3.1\n")
    osv = [i for i in scanner.scan(p).issues if i.rule_id == "MEDUSA-OSV-001"]
    assert osv == []


def test_osv_requirements_exact_pin_flagged(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    _osv(scanner, monkeypatch)
    p = _write(tmp_path, "requirements.txt", "pyyaml==5.3.1\n")
    osv = [i for i in scanner.scan(p).issues if i.rule_id == "MEDUSA-OSV-001"]
    assert len(osv) == 1


def test_osv_pyproject_tox_pin_not_treated_as_install_dep(monkeypatch, tmp_path):
    """OSV scanner must not read a [tool.tox] pin as an install dependency."""
    scanner = DependencyCVEScanner()
    _osv(scanner, monkeypatch)
    content = (
        "[project]\n"
        'name = "myapp"\n'
        "dependencies = [\n"
        '    "click==8.0.0",\n'
        "]\n"
        "\n"
        "[tool.tox]\n"
        'deps = ["pyyaml==5.3.1"]\n'
    )
    p = _write(tmp_path, "pyproject.toml", content)
    osv = [i for i in scanner.scan(p).issues if i.rule_id == "MEDUSA-OSV-001"]
    assert osv == []


def test_osv_pyproject_project_dependency_pin_flagged(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    _osv(scanner, monkeypatch)
    content = (
        "[project]\n"
        'name = "myapp"\n'
        "dependencies = [\n"
        '    "pyyaml==5.3.1",\n'
        "]\n"
    )
    p = _write(tmp_path, "pyproject.toml", content)
    osv = [i for i in scanner.scan(p).issues if i.rule_id == "MEDUSA-OSV-001"]
    assert len(osv) == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
