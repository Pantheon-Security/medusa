#!/usr/bin/env python3
"""
Phase 2 OSV reliability/performance tests (CR-013..CR-016).

Every test mocks the urllib boundary — NO real network is ever performed. These
exercise the REAL scan() path (parse -> batched querybatch -> findings), not
to_dict()/source-grep, so a regression in the wiring is caught.

Coverage:
- CR-014: a multi-dep manifest triggers exactly ONE urlopen call, to /v1/querybatch.
- CR-015: a transient 429 is retried once; a persistent 429 yields a
  MEDUSA-OSV-INCOMPLETE INFO finding (absence of findings is not read as clean).
- CR-013: offline (URLError) completes fast with no findings and no exception.
- CR-016: the same pin appearing in two manifests hits the network once.
"""

import io
import json
import urllib.error

import pytest

from medusa.scanners import dependency_cve_scanner as dcs
from medusa.scanners.dependency_cve_scanner import DependencyCVEScanner
from medusa.scanners.base import Severity


# ---------------------------------------------------------------------------
# urllib mock helpers
# ---------------------------------------------------------------------------

class _FakeResp:
    """Minimal urlopen() return value: a context manager exposing .read()."""

    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://api.osv.dev/v1/querybatch",
        code=code,
        msg="rate limited",
        hdrs=None,
        fp=io.BytesIO(b""),
    )


def _batch_payload(n_results: int, vuln_at=None):
    """Build a /v1/querybatch response of n_results, optionally a vuln at index."""
    results = []
    for i in range(n_results):
        if vuln_at is not None and i == vuln_at:
            results.append({"vulns": [{"id": "GHSA-test-0001"}]})
        else:
            results.append({})
    return {"results": results}


def _install_urlopen(monkeypatch, handler):
    """Patch the module-level urlopen with a call-counting handler.

    handler(req, calls) -> _FakeResp or raises. `calls` is the 1-based call
    index so a handler can fail-then-succeed.
    """
    state = {"n": 0, "urls": []}

    def fake_urlopen(req, timeout=None):
        state["n"] += 1
        state["urls"].append(req.get_full_url())
        return handler(req, state["n"])

    monkeypatch.setattr(dcs.urllib.request, "urlopen", fake_urlopen)
    return state


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# CR-014 — one batched querybatch call per manifest
# ---------------------------------------------------------------------------

def test_multi_dep_manifest_makes_one_querybatch_call(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    # 50 distinct pinned deps.
    lines = "".join(f"pkg{i}==1.0.{i}\n" for i in range(50))

    def handler(req, n):
        body = json.loads(req.data)
        assert "queries" in body and len(body["queries"]) == 50
        return _FakeResp(_batch_payload(len(body["queries"])))

    state = _install_urlopen(monkeypatch, handler)
    p = _write(tmp_path, "requirements.txt", lines)
    result = scanner.scan(p)

    assert result.success
    assert state["n"] == 1, f"expected exactly one HTTP call, got {state['n']}"
    assert "querybatch" in state["urls"][0]


def test_querybatch_maps_vuln_back_to_correct_dep(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()
    content = "safe-a==1.0.0\nvictim==0.5\nsafe-b==2.0.0\n"

    def handler(req, n):
        body = json.loads(req.data)
        # victim is the 2nd query (index 1).
        idx = next(i for i, q in enumerate(body["queries"])
                   if q["package"]["name"] == "victim")
        return _FakeResp(_batch_payload(len(body["queries"]), vuln_at=idx))

    _install_urlopen(monkeypatch, handler)
    result = scanner.scan(_write(tmp_path, "requirements.txt", content))

    assert result.success
    findings = [i for i in result.issues if i.rule_id == "MEDUSA-OSV-001"]
    assert len(findings) == 1
    assert "victim" in findings[0].message
    assert "0.5" in findings[0].message


# ---------------------------------------------------------------------------
# CR-015 — network-failure vs "no CVEs"; backoff on 429
# ---------------------------------------------------------------------------

def test_transient_429_retried_once_then_succeeds(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def handler(req, n):
        if n == 1:
            raise _http_error(429)
        body = json.loads(req.data)
        return _FakeResp(_batch_payload(len(body["queries"]), vuln_at=0))

    state = _install_urlopen(monkeypatch, handler)
    monkeypatch.setattr(dcs.time, "sleep", lambda *_a, **_k: None)

    result = scanner.scan(_write(tmp_path, "requirements.txt", "flask==0.5\n"))

    assert result.success
    assert state["n"] == 2, "expected one retry after a 429"
    assert any(i.rule_id == "MEDUSA-OSV-001" for i in result.issues)
    assert not any(i.rule_id == "MEDUSA-OSV-INCOMPLETE" for i in result.issues)


def test_persistent_429_emits_incomplete_info_and_no_false_clean(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def handler(req, n):
        raise _http_error(429)

    state = _install_urlopen(monkeypatch, handler)
    monkeypatch.setattr(dcs.time, "sleep", lambda *_a, **_k: None)

    result = scanner.scan(_write(tmp_path, "requirements.txt", "flask==0.5\n"))

    assert result.success
    assert state["n"] == 2, "expected exactly one retry (bounded)"
    incompletes = [i for i in result.issues if i.rule_id == "MEDUSA-OSV-INCOMPLETE"]
    assert len(incompletes) == 1, "absence of CVEs must not read as a clean bill of health"
    assert incompletes[0].severity == Severity.INFO
    # No false MEDUSA-OSV-001 finding invented on failure.
    assert not any(i.rule_id == "MEDUSA-OSV-001" for i in result.issues)


# ---------------------------------------------------------------------------
# CR-013 — offline short-circuit
# ---------------------------------------------------------------------------

def test_offline_urlerror_completes_fast_no_findings(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def handler(req, n):
        raise urllib.error.URLError("no route to host")

    state = _install_urlopen(monkeypatch, handler)
    # A budget-bounded run: many manifests must not each stall on the network.
    content = "".join(f"pkg{i}==1.0.{i}\n" for i in range(10))
    result = scanner.scan(_write(tmp_path, "requirements.txt", content))

    assert result.success
    assert result.issues == []
    # One transport failure flips the run offline; no INCOMPLETE noise for a
    # genuinely offline run.
    assert not any(i.rule_id == "MEDUSA-OSV-INCOMPLETE" for i in result.issues)
    assert scanner._offline is True
    assert state["n"] == 1


def test_offline_short_circuits_subsequent_manifests(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def handler(req, n):
        raise urllib.error.URLError("offline")

    state = _install_urlopen(monkeypatch, handler)
    scanner.scan(_write(tmp_path, "requirements.txt", "flask==0.5\n"))
    scanner.scan(_write(tmp_path, "requirements-dev.txt", "django==1.0.0\n"))

    # First manifest probes once; once offline, no further network attempts.
    assert state["n"] == 1


# ---------------------------------------------------------------------------
# CR-016 — the same pin across two manifests hits the network once
# ---------------------------------------------------------------------------

def test_same_pin_two_manifests_one_network_call(monkeypatch, tmp_path):
    scanner = DependencyCVEScanner()

    def handler(req, n):
        body = json.loads(req.data)
        return _FakeResp(_batch_payload(len(body["queries"])))

    state = _install_urlopen(monkeypatch, handler)
    scanner.scan(_write(tmp_path, "requirements.txt", "flask==2.0.1\n"))
    scanner.scan(_write(tmp_path, "requirements-dev.txt", "flask==2.0.1\n"))

    assert state["n"] == 1, "the per-run cache must dedup a pin across manifests"
