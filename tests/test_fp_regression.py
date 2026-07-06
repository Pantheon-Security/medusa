#!/usr/bin/env python3
"""
Golden-file FP regression tests.

Scans known reference projects and asserts the finding count stays below
a threshold. Catches FP explosions before they ship.

PORTABLE CORPUS (PR-009, 2026-07): reference projects live under
tests/corpus/ and tests/benchmark_corpus/ — both committed to the repo —
instead of machine-local paths like /home/ross/Documents/projects/canopy.
Those local paths never existed on any machine but Ross's, so this whole
test class silently skipped everywhere else, including CI. tests/corpus/
holds small, self-authored "clean" fixtures (not vendored third-party code,
so there's no licensing question) written to be realistic enough to trip
harvested keyword-mention rules (agent/model/prompt/token vocabulary used
in ordinary business logic) without containing any actual vulnerability —
exactly what an FP-explosion regression needs to catch.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

_CORPUS_ROOT = Path(__file__).parent / "corpus"
_BENCHMARK_CORPUS = Path(__file__).parent / "benchmark_corpus"

# Clean reference projects and their maximum acceptable finding counts.
# Update thresholds after verified improvements or when adding new rule categories.
# Format: scan the project, verify findings are correct, set threshold = count + ~20% buffer.
GOLDEN_FILES = {
    str(_CORPUS_ROOT / "clean_python_service"): {
        # 2026-07: 2 post-filter MEDIUM findings observed (SSRF on an internal
        # URL literal, "agent without callback" mention) — both low-signal,
        # expected noise for a small clean corpus. Threshold = 2 + buffer.
        "max_findings": 4,
        "description": "Self-authored clean Flask-style catalog/recommendation service",
    },
    str(_CORPUS_ROOT / "clean_js_frontend"): {
        # 2026-07: 0 findings observed on a small clean Vue+fetch frontend.
        # Small absolute buffer (not a percentage of zero) to tolerate minor
        # legitimate rule tuning without flapping the gate.
        "max_findings": 2,
        "description": "Self-authored clean Vue + fetch frontend",
    },
}

# Intentionally vulnerable corpus that SHOULD produce findings.
# We assert a MINIMUM count to catch rule breakage / over-filtering.
DETECTION_FILES = {
    str(_BENCHMARK_CORPUS): {
        # 2026-07: 8 findings observed via the same `medusa scan --output json`
        # path this test uses (command injection, root-user Dockerfile,
        # hardcoded credential, ...). Minimum set below the observed count so
        # legitimate FP tightening doesn't trip this, while still catching
        # wholesale rule breakage.
        "min_findings": 5,
        "description": "MEDUSA's own attack-sample corpus (already committed, used by test_regression.py)",
    },
}


def _run_scan(target_path: str) -> dict:
    """Run medusa scan and return parsed JSON results."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, "-m", "medusa", "scan", target_path,
             "--output", "json", "-o", tmpdir, "-w", "4"],
            capture_output=True, text=True, timeout=1800,
            env={**__import__("os").environ, "MEDUSA_NO_BANNER": "1"},
        )

        report_dir = Path(tmpdir)
        json_files = sorted(report_dir.glob("medusa-scan-*.json"))
        json_files = [f for f in json_files if "raw-payloads" not in f.name]
        if not json_files:
            return {"findings": [], "error": f"No JSON report found (exit={result.returncode})"}

        try:
            with open(json_files[-1]) as f:
                return json.load(f)
        except Exception as e:
            return {"findings": [], "error": str(e)}


@pytest.mark.slow
class TestFPRegression:
    """Golden-file tests to catch FP explosions."""

    @pytest.mark.parametrize("target_path,config", GOLDEN_FILES.items())
    def test_fp_below_threshold(self, target_path, config):
        """Finding count should stay below threshold on clean projects."""
        if not Path(target_path).exists():
            pytest.skip(f"Reference project not found: {target_path}")

        data = _run_scan(target_path)
        findings = data.get("findings", [])
        count = len(findings)

        # Show top issues for debugging
        if count > config["max_findings"]:
            from collections import Counter
            top = Counter(f["issue"][:60] for f in findings).most_common(10)
            detail = "\n".join(f"  {c:3d} {msg}" for msg, c in top)
            pytest.fail(
                f"{Path(target_path).name}: {count} findings "
                f"(max {config['max_findings']})\n"
                f"Top issues:\n{detail}"
            )

    @pytest.mark.parametrize("target_path,config", DETECTION_FILES.items())
    def test_detection_above_minimum(self, target_path, config):
        """Vulnerable repos should produce a minimum number of findings."""
        if not Path(target_path).exists():
            pytest.skip(f"Test target not found: {target_path}")

        data = _run_scan(target_path)
        findings = data.get("findings", [])
        count = len(findings)

        assert count >= config["min_findings"], (
            f"{Path(target_path).name}: only {count} findings "
            f"(expected >= {config['min_findings']}). "
            f"Rules may be broken or over-filtered."
        )


@pytest.mark.slow
class TestRuleQuality:
    """Validate rule patterns at the unit level. Each test walks and parses
    every YAML file under medusa/rules/ (~38s/test, ~115s for the class) —
    too slow for the per-PR fast set."""

    def test_no_broken_lookaheads(self):
        """No production rules should have .*(?!...) anti-pattern."""
        import re
        import yaml

        rules_dir = Path(__file__).parent.parent / "medusa" / "rules"
        broken = []

        for yf in rules_dir.rglob("*.yaml"):
            if "_runtime" in yf.name or "/archive/" in str(yf) or "/runtime/" in str(yf):
                continue
            try:
                with open(yf) as f:
                    data = yaml.safe_load(f)
                if not data or "rules" not in data:
                    continue
                for r in data["rules"]:
                    patterns = r.get("patterns", [])
                    if isinstance(patterns, list):
                        for p in patterns:
                            if isinstance(p, str) and re.search(r'\.\*\(\?!', p):
                                broken.append(f"{r.get('id', '?')}: {p[:50]}")
            except Exception:
                continue

        assert len(broken) == 0, (
            f"{len(broken)} rules have broken .*(?!...) patterns:\n"
            + "\n".join(f"  {b}" for b in broken[:10])
        )

    def test_all_patterns_compile(self):
        """Every regex pattern in production rules should compile."""
        import re
        import yaml

        rules_dir = Path(__file__).parent.parent / "medusa" / "rules"
        failures = []
        skipped = []  # files that could not be parsed — must stay at 0

        for yf in rules_dir.rglob("*.yaml"):
            if "_runtime" in yf.name or "/archive/" in str(yf) or "/runtime/" in str(yf):
                continue
            try:
                with open(yf) as f:
                    data = yaml.safe_load(f)
            except Exception as e:
                skipped.append(f"{yf.name}: {str(e)[:40]}")
                continue
            if not data or "rules" not in data:
                continue
            for r in data["rules"]:
                patterns = r.get("patterns", [])
                if isinstance(patterns, list):
                    for p in patterns:
                        if isinstance(p, str):
                            try:
                                re.compile(p, re.IGNORECASE)
                            except re.error as e:
                                failures.append(f"{r.get('id', '?')}: {str(e)[:40]}")

        # A parse failure must not let the test pass vacuously — assert no skips.
        assert not skipped, f"{len(skipped)} rule files failed to parse: {skipped[:5]}"
        # Every production pattern must compile. Current count is 0; this asserts
        # zero so any newly-introduced broken regex is caught before merge.
        assert len(failures) == 0, (
            f"{len(failures)} patterns fail to compile:\n"
            + "\n".join(f"  {f}" for f in failures[:15])
        )

    def test_no_trivially_broad_patterns(self):
        """No rule should match the word 'response' or 'request' as a standalone pattern."""
        import yaml

        rules_dir = Path(__file__).parent.parent / "medusa" / "rules"
        broad = []

        for yf in rules_dir.rglob("*.yaml"):
            if "_runtime" in yf.name or "/archive/" in str(yf) or "/runtime/" in str(yf):
                continue
            try:
                with open(yf) as f:
                    data = yaml.safe_load(f)
                if not data or "rules" not in data:
                    continue
                for r in data["rules"]:
                    patterns = r.get("patterns", [])
                    if isinstance(patterns, list):
                        for p in patterns:
                            if isinstance(p, str) and p.strip() in (
                                "request", "response", "import", "function",
                                "class", "return", "def", "var", "let", "const",
                            ):
                                broad.append(f"{r.get('id', '?')}: '{p}'")
            except Exception:
                continue

        assert len(broad) == 0, (
            f"{len(broad)} rules have trivially broad patterns:\n"
            + "\n".join(f"  {b}" for b in broad[:10])
        )
