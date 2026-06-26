#!/usr/bin/env python3
"""
FP-reduction dogfooding guards (Phase D).

Fast (no scan / no corpus load): protects the two things the FP-reduction work
established —
  1. MEDUSA's own rule/signature corpus + the stale backup stay OUT of the
     self-scan scope, so the tool never re-floods itself with ~18.6k self-matches
     on its own signature database.
  2. The benchmark-corpus false-positive reduction stays high (the number the
     README cites: ~97.9%).
"""
from pathlib import Path
import json
import yaml

REPO = Path(__file__).resolve().parent.parent


def test_self_scan_excludes_rule_corpus_and_backup():
    """.medusa.yml must exclude the rule/signature DATA + stale backup — else the
    self-scan re-flags its own signature database (the 21k -> 1.7k regression)."""
    cfg = yaml.safe_load((REPO / ".medusa.yml").read_text())
    paths = set(cfg.get("exclude", {}).get("paths", []))
    assert "medusa/rules/" in paths, "rule corpus must be excluded from self-scan (it's signature DATA)"
    assert "v2026.1-backup/" in paths, "stale backup dir must be excluded from self-scan"


def test_benchmark_fp_reduction_stays_high():
    """The README cites ~97.9% FP reduction on the benchmark corpus — guard the floor."""
    b = json.loads((REPO / "tests" / "benchmark_baseline.json").read_text())
    total = b.get("total_findings") or 0
    filtered = b.get("fp_filtered") or 0
    assert total > 0, "benchmark baseline missing total_findings"
    reduction = filtered / total
    assert reduction >= 0.95, f"benchmark FP reduction dropped to {reduction:.1%} (README claims ~97.9%)"


def test_readme_fp_claim_is_attributed():
    """The FP-reduction claim must state its method (benchmark corpus), not a vague
    'real-world projects' (the honesty fix)."""
    readme = (REPO / "README.md").read_text()
    assert "benchmark corpus" in readme, "FP-reduction claim should cite the benchmark corpus method"
