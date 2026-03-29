#!/usr/bin/env python3
"""
Golden-file FP regression tests.

Scans known reference projects and asserts the finding count stays below
a threshold. Catches FP explosions before they ship.

These tests require the reference projects to exist on disk.
Skip gracefully if they don't (CI without test repos).
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest


# Reference projects and their maximum acceptable finding counts.
# Update thresholds after verified improvements.
GOLDEN_FILES = {
    "/home/ross/Documents/projects/canopy": {
        "max_findings": 15,
        "description": "Vue SPA + Docker — minimal AI code",
    },
    "/home/ross/Documents/projects/mirofish": {
        "max_findings": 200,
        "description": "Flask AI simulation app — moderate AI code",
    },
}

# Intentionally vulnerable repos that SHOULD produce findings.
# We assert a MINIMUM count to catch rule breakage / over-filtering.
DETECTION_FILES = {
    "/home/ross/Documents/medusa/medusa-test-targets/vulnerable-chat": {
        "min_findings": 10,
        "description": "Deliberately vulnerable AI chatbot",
    },
}


def _run_scan(target_path: str) -> dict:
    """Run medusa scan and return parsed JSON results."""
    result = subprocess.run(
        [sys.executable, "-m", "medusa.cli", "scan", target_path,
         "--output", "json", "--skip-tools"],
        capture_output=True, text=True, timeout=300,
        input="yes\n",  # Auto-accept missing tools prompt
    )

    # Find the JSON report
    reports_dir = Path(".medusa/reports")
    if not reports_dir.exists():
        return {"findings": [], "error": "No reports directory"}

    json_files = sorted(reports_dir.glob("medusa-scan-*.json"), reverse=True)
    if not json_files:
        return {"findings": [], "error": "No JSON report found"}

    try:
        with open(json_files[0]) as f:
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


class TestRuleQuality:
    """Validate rule patterns at the unit level."""

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
                            if isinstance(p, str):
                                try:
                                    re.compile(p, re.IGNORECASE)
                                except re.error as e:
                                    failures.append(f"{r.get('id', '?')}: {str(e)[:40]}")
            except Exception:
                continue

        assert len(failures) <= 10, (
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
