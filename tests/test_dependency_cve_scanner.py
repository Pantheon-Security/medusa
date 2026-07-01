#!/usr/bin/env python3
"""
Tests for DependencyCVEScanner (live OSV.dev CVE lookup for pinned deps).

All tests are offline and deterministic: the network boundary (_query_osv) is
monkeypatched. No real HTTP is ever performed.
"""

from pathlib import Path

import pytest

from medusa.scanners.dependency_cve_scanner import DependencyCVEScanner
from medusa.scanners.base import Severity
from medusa.scanners import registry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan(scanner, tmp_path, filename, content):
    p = tmp_path / filename
    p.write_text(content)
    return scanner.scan(p)


# ---------------------------------------------------------------------------
# Registration / wiring
# ---------------------------------------------------------------------------

def test_scanner_registered():
    names = {s.name for s in registry.get_all_scanners()}
    assert "DependencyCVEScanner" in names


def test_can_scan_matches_manifests_by_basename():
    s = DependencyCVEScanner()
    assert s.can_scan(Path("requirements.txt"))
    assert s.can_scan(Path("requirements-dev.txt"))
    assert s.can_scan(Path("pyproject.toml"))
    assert s.can_scan(Path("Pipfile"))
    assert s.can_scan(Path("Pipfile.lock"))
    assert s.can_scan(Path("poetry.lock"))
    assert s.can_scan(Path("package.json"))
    assert s.can_scan(Path("package-lock.json"))
    assert s.can_scan(Path("yarn.lock"))
    # Non-manifests with matching extensions must NOT be claimed.
    assert not s.can_scan(Path("notes.txt"))
    assert not s.can_scan(Path("config.toml"))
    assert not s.can_scan(Path("data.json"))


# ---------------------------------------------------------------------------
# Pure parse coverage (no network involved)
# ---------------------------------------------------------------------------

def test_parse_requirements_only_pins():
    s = DependencyCVEScanner()
    content = (
        "# comment\n"
        "flask==2.0.1\n"
        "requests>=2.0\n"          # range -> skipped
        "django\n"                 # unpinned -> skipped
        "-r other.txt\n"           # option line -> skipped
        "urllib3==1.26.5  # pinned with comment\n"
        "PyYAML[extra]==5.4.1 ; python_version>='3.8'\n"
    )
    deps = s._parse("requirements", content)
    names = {(n, v, e) for n, v, e, _ in deps}
    assert ("flask", "2.0.1", "PyPI") in names
    assert ("urllib3", "1.26.5", "PyPI") in names
    assert ("pyyaml", "5.4.1", "PyPI") in names
    assert all(n not in {"requests", "django"} for n, _, _ in names)
    assert len(deps) == 3


def test_parse_package_json_only_exact_pins():
    s = DependencyCVEScanner()
    content = (
        '{\n'
        '  "name": "demo",\n'
        '  "dependencies": {\n'
        '    "lodash": "4.17.20",\n'
        '    "express": "^4.18.0",\n'
        '    "react": "~17.0.0"\n'
        '  },\n'
        '  "devDependencies": {\n'
        '    "jest": "29.5.0",\n'
        '    "typescript": "*"\n'
        '  }\n'
        '}\n'
    )
    deps = s._parse("package_json", content)
    pins = {(n, v, e) for n, v, e, _ in deps}
    assert ("lodash", "4.17.20", "npm") in pins
    assert ("jest", "29.5.0", "npm") in pins
    # Caret / tilde / wildcard are not exact pins.
    assert all(n not in {"express", "react", "typescript"} for n, _, _ in pins)
    assert len(deps) == 2


def test_parse_requirements_reports_line_numbers():
    s = DependencyCVEScanner()
    content = "# header\nflask==2.0.1\n"
    deps = s._parse("requirements", content)
    assert deps == [("flask", "2.0.1", "PyPI", 2)]


# ---------------------------------------------------------------------------
# OSV lookup behavior (mocked network)
# ---------------------------------------------------------------------------

def test_vulnerable_dep_fires_osv_rule(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def fake_batch(chunk):
        # Return one vuln-id list per (name, version, ecosystem) in the chunk.
        return [
            ["CVE-2019-1010083"] if (n == "flask" and v == "0.5") else []
            for (n, v, e) in chunk
        ]

    monkeypatch.setattr(scanner, "_post_querybatch", fake_batch)

    result = _scan(scanner, tmp_path, "requirements.txt", "flask==0.5\nsafe-pkg==1.0.0\n")

    assert result.success
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.rule_id == "MEDUSA-OSV-001"
    assert issue.severity == Severity.HIGH
    assert "flask" in issue.message
    assert "0.5" in issue.message
    assert "CVE-2019-1010083" in issue.message
    assert issue.line == 1


def test_real_query_batch_swallows_errors(monkeypatch, tmp_path):
    """The genuine _post_querybatch must return None on a transport error and
    flip the run offline, never raise."""
    scanner = DependencyCVEScanner()

    def fake_urlopen(*args, **kwargs):
        raise OSError("no route to host")

    monkeypatch.setattr(
        "medusa.scanners.dependency_cve_scanner.urllib.request.urlopen",
        fake_urlopen,
    )

    # Direct call returns None without raising, and marks the run offline.
    assert scanner._post_querybatch([("flask", "0.5", "PyPI")]) is None
    assert scanner._offline is True

    # End-to-end scan also yields no findings and succeeds.
    result = _scan(scanner, tmp_path, "requirements.txt", "flask==0.5\n")
    assert result.success
    assert result.issues == []


def test_query_batch_timeout_swallowed(monkeypatch):
    scanner = DependencyCVEScanner()

    def fake_urlopen(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(
        "medusa.scanners.dependency_cve_scanner.urllib.request.urlopen",
        fake_urlopen,
    )
    assert scanner._post_querybatch([("requests", "2.19.1", "PyPI")]) is None
    assert scanner._offline is True


def test_clean_deps_yield_nothing(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    monkeypatch.setattr(scanner, "_post_querybatch", lambda chunk: [[] for _ in chunk])
    result = _scan(scanner, tmp_path, "requirements.txt", "flask==2.0.1\nrequests==2.31.0\n")
    assert result.success
    assert result.issues == []


def test_no_pins_yield_nothing(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    called = {"n": 0}

    def fake_batch(chunk):
        called["n"] += 1
        return [["CVE-XXXX"] for _ in chunk]

    monkeypatch.setattr(scanner, "_post_querybatch", fake_batch)
    # All unpinned/ranged -> no OSV queries, no findings.
    result = _scan(scanner, tmp_path, "requirements.txt", "flask>=2.0\nrequests\ndjango~=3.0\n")
    assert result.success
    assert result.issues == []
    assert called["n"] == 0


def test_in_run_cache_dedups_queries(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    chunks = []

    def fake_batch(chunk):
        chunks.append(list(chunk))
        return [[] for _ in chunk]

    monkeypatch.setattr(scanner, "_post_querybatch", fake_batch)
    # Same pin twice in one manifest -> a single batched query of one unique pin.
    _scan(scanner, tmp_path, "requirements.txt", "flask==2.0.1\nflask==2.0.1\n")
    assert chunks == [[("flask", "2.0.1", "PyPI")]]


# ---------------------------------------------------------------------------
# Vuln-id extraction (CVE preferred over OSV id)
# ---------------------------------------------------------------------------

def test_extract_vuln_ids_prefers_cve():
    s = DependencyCVEScanner()
    data = {
        "vulns": [
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2021-1234", "PYSEC-2021-1"]},
            {"id": "OSV-2020-99", "aliases": []},
        ]
    }
    assert s._extract_vuln_ids(data) == ["CVE-2021-1234", "OSV-2020-99"]


def test_extract_vuln_ids_empty_on_no_vulns():
    s = DependencyCVEScanner()
    assert s._extract_vuln_ids({}) == []
    assert s._extract_vuln_ids({"vulns": []}) == []
    assert s._extract_vuln_ids("not a dict") == []
