"""Gate for #22 — MEDUSA-INF-WEB-003 must not flag localhost as a cloud-metadata SSRF.

PC001 handover 2026-07-22-fp-realworld (#1, worst offender, 7x CRITICAL): the
`ssrf-cloud-metadata` rule listed `(?:localhost|127.0.0.1):\d+` alongside the real
metadata endpoints, so `http://localhost:3000/mcp` in help text / config was flagged
CRITICAL "SSRF target - cloud metadata endpoint" (confidence 0.0 = confidently wrong).
localhost/loopback is NOT a cloud-metadata endpoint (169.254.169.254 /
metadata.google.internal / metadata.azure.com). The loopback pattern is removed; the
real metadata IPs/hosts still fire.
"""
import re

import pytest
import yaml

from pathlib import Path

RULE_FILE = (Path(__file__).resolve().parent.parent / "medusa" / "rules" /
             "inference_infrastructure" / "inference_infrastructure_scanner.yaml")


def _load_rule(rule_id):
    doc = yaml.safe_load(RULE_FILE.read_text())
    rules = doc["rules"] if isinstance(doc, dict) else doc
    for r in rules:
        if isinstance(r, dict) and r.get("id") == rule_id:
            return r
    raise AssertionError(f"{rule_id} not found in {RULE_FILE}")


def test_metadata_rule_has_no_loopback_pattern():
    rule = _load_rule("MEDUSA-INF-WEB-003")
    for pat in rule["patterns"]:
        assert "localhost" not in pat and "127.0.0.1" not in pat and "127\\.0\\.0\\.1" not in pat, \
            f"cloud-metadata rule must not match loopback: {pat!r}"


def test_metadata_rule_still_matches_real_endpoints():
    rule = _load_rule("MEDUSA-INF-WEB-003")
    pats = [re.compile(p) for p in rule["patterns"]]
    for target in ("169.254.169.254", "metadata.google.internal", "metadata.azure.com"):
        assert any(p.search(target) for p in pats), f"must still flag real metadata endpoint: {target}"


def test_localhost_url_not_matched_by_metadata_rule():
    rule = _load_rule("MEDUSA-INF-WEB-003")
    pats = [re.compile(p) for p in rule["patterns"]]
    for benign in ("http://localhost:3000/mcp", "http://127.0.0.1:18060/mcp", "localhost:8080"):
        assert not any(p.search(benign) for p in pats), \
            f"localhost must NOT match the cloud-metadata rule: {benign}"
