"""
Regression tests for MEDUSA Performance & Sustainability Overhaul.

Scans tests/benchmark_corpus/ and compares findings count to baseline.
On first run: creates baseline. On subsequent runs: asserts findings match.

NATIVE-SCOPED GATE (2026-07): the regression assertions are exact only on
MEDUSA-NATIVE findings (MEDUSA's own regex/AST/rule scanners, which are pure
Python and 100% deterministic). External-linter findings (hadolint, bandit,
gitleaks, semgrep, eslint, ...) are reported for visibility but NOT gated,
because their count depends on whichever version of the external binary is
installed in the environment running the test — that varies by machine/CI
image/timing and produced false reds/greens (observed 382/384/385 raw totals
for identical MEDUSA code, purely from external-tool version drift). See
`_is_external_tool_finding()` below for how the split is made.

The scan itself is run in-process (not via subprocess + JSON report) because
the JSON report only exposes post-FP-filter findings plus aggregate
pre-filter counts — it has no per-finding breakdown of the pre-filter set,
which is what the native/external split needs. Calling
`MedusaParallelScanner` + `standardize_issue` directly uses the exact same
code path `parallel.py.generate_report()` uses to build the pre-filter
findings list, so this isn't a reimplementation — it's the same production
path, just read one step earlier (before the FP filter runs).
"""
import json
import re
import time
from pathlib import Path

import pytest

BASELINE_FILE = Path(__file__).parent / "benchmark_baseline.json"
CORPUS_DIR = Path(__file__).parent / "benchmark_corpus"


# ---------------------------------------------------------------------------
# Native vs. external-tool classification
# ---------------------------------------------------------------------------

# Scanner classes whose findings are external-linter output — each of these
# shells out to a real binary (hadolint, bandit, gitleaks, semgrep, eslint,
# shellcheck, ...) via BaseScanner._run_command()/subprocess, so their finding
# count tracks that binary's installed version, not MEDUSA's code. Confirmed
# by reading get_tool_name()+scan_file() for every scanner in medusa/scanners/
# (2026-07). NOTE: LLMGuardScanner reports get_tool_name()=="llm-guard" but is
# NOT external — it's "always available - uses built-in static analysis
# patterns" (pure regex, no subprocess), so it is deliberately NOT in this set.
_EXTERNAL_TOOL_SCANNER_NAMES = frozenset({
    "AnsibleScanner", "BashScanner", "BatScanner", "ClojureScanner",
    "CMakeScanner", "CppScanner", "CSSScanner", "DartScanner",
    "DockerScanner", "ElixirScanner", "GarakScanner", "GitLeaksScanner",
    "GoScanner", "GraphQLScanner", "GroovyScanner", "HaskellScanner",
    "HTMLScanner", "JavaScanner", "JavaScriptScanner", "KotlinScanner",
    "KubernetesScanner", "LuaScanner", "MakeScanner", "ModelScanScanner",
    "NginxScanner", "PerlScanner", "PowerShellScanner", "ProtobufScanner",
    "PythonScanner", "RScanner", "RubyScanner", "ScalaScanner",
    "SemgrepScanner", "SolidityScanner", "SQLScanner", "SwiftScanner",
    "TerraformScanner", "TOMLScanner", "TrivyScanner", "TypeScriptScanner",
    "VimScanner", "XMLScanner", "YAMLScanner", "ZigScanner",
})

# rule_id patterns for the same external tools, used as a secondary/defensive
# check for any report path that carries a rule_id but not a scanner name.
# Confirmed against the actual corpus scan (2026-07): PythonScanner(bandit)
# emits B\d{3}, DockerScanner(hadolint) emits DL\d+, GitLeaksScanner emits
# GL-<name>. Trivy/semgrep patterns below are from reading their scanner
# source (semgrep's dotted check_id / trivy's CVE-/AVD-/TRIVY- prefixes);
# they don't fire on this 9-file corpus but are included for completeness.
_EXTERNAL_RULE_ID_PATTERNS = [
    re.compile(r"^B\d{3}$"),          # bandit
    re.compile(r"^DL\d+"),            # hadolint
    re.compile(r"^SC\d+"),            # shellcheck
    re.compile(r"^GL-"),              # gitleaks
    re.compile(r"^AVD-"),             # trivy (config/IaC checks)
    re.compile(r"^TRIVY-"),           # trivy (secret findings)
    re.compile(r"^CVE-\d{4}-\d+$"),   # trivy (vulnerability findings)
]


def _is_external_tool_finding(finding: dict) -> bool:
    """True if `finding` came from an external linter MEDUSA wraps, rather
    than a MEDUSA-native scanner. See module docstring for why this split
    exists and the comments above for how each set was verified."""
    scanner = finding.get("scanner") or ""
    if scanner in _EXTERNAL_TOOL_SCANNER_NAMES:
        return True
    rule_id = str(finding.get("rule_id") or "")
    return any(p.match(rule_id) for p in _EXTERNAL_RULE_ID_PATTERNS)


def _run_scan():
    """Run MEDUSA in-process on the benchmark corpus and return the
    native/external split of pre-filter findings plus native post-filter
    survivors. See module docstring for why this is in-process rather than
    subprocess + JSON report."""
    from medusa.core.finding_schema import standardize_issue
    from medusa.core.fp_filter import FalsePositiveFilter
    from medusa.core.parallel import MedusaParallelScanner

    start = time.time()
    scanner = MedusaParallelScanner(
        project_root=CORPUS_DIR,
        workers=2,
        use_cache=False,
    )
    files = scanner.find_scannable_files()
    results = scanner.scan_parallel(files)
    elapsed = round(time.time() - start, 2)

    findings = [
        standardize_issue(issue, result)
        for result in results
        for issue in result.issues
    ]

    native = [f for f in findings if not _is_external_tool_finding(f)]
    external = [f for f in findings if _is_external_tool_finding(f)]

    native_scanner_counts = {}
    for f in native:
        native_scanner_counts[f["scanner"]] = native_scanner_counts.get(f["scanner"], 0) + 1

    fp_filter = FalsePositiveFilter(CORPUS_DIR)
    native_retained, native_fps = fp_filter.filter_findings(native)

    return {
        "native_total": len(native),
        "external_total": len(external),
        "total_findings": len(findings),  # informational only, not gated
        "native_scanner_counts": native_scanner_counts,
        "native_survivors": len(native_retained),
        "native_fp_filtered": len(native_fps),
        "files_scanned": len(results),
        "elapsed_seconds": elapsed,
        "returncode": 0,
    }


def _load_baseline():
    """Load baseline from file, or return None if doesn't exist."""
    if BASELINE_FILE.exists():
        return json.loads(BASELINE_FILE.read_text())
    return None


def _save_baseline(results):
    """Save scan results as the baseline."""
    BASELINE_FILE.write_text(json.dumps(results, indent=2))


class TestRegression:
    """Regression tests comparing current scan to baseline."""

    def test_benchmark_corpus_exists(self):
        """Verify benchmark corpus files exist."""
        expected_files = [
            "sample_agent.py",
            "sample_web.py",
            "sample_k8s.yaml",
            "Dockerfile",
            "sample_prompt.md",
            "sample_mcp.json",
        ]
        for fname in expected_files:
            assert (CORPUS_DIR / fname).exists(), f"Missing benchmark file: {fname}"

    def test_scan_produces_findings(self):
        """Scan must produce at least some MEDUSA-native pre-filter findings."""
        results = _run_scan()
        assert results["native_total"] > 0, (
            f"Scan produced zero native pre-filter findings. "
            f"Return code: {results['returncode']}."
        )

    def test_findings_match_baseline(self):
        """Native pre-filter findings count must match the saved baseline
        exactly. External-linter findings are informational only (see module
        docstring) and are not asserted here."""
        baseline = _load_baseline()
        results = _run_scan()

        if baseline is None:
            _save_baseline(results)
            pytest.skip(
                f"Baseline created with {results['native_total']} native "
                f"pre-filter findings ({results['external_total']} external, "
                f"not gated)."
            )

        assert results["native_total"] == baseline["native_total"], (
            f"Native pre-filter finding count changed! "
            f"Baseline: {baseline['native_total']}, "
            f"Current: {results['native_total']}. "
            f"Scanner deltas: {_scanner_deltas(baseline, results)}"
        )

    def test_per_scanner_counts_stable(self):
        """Per-scanner native finding counts should not change."""
        baseline = _load_baseline()
        if baseline is None:
            pytest.skip("No baseline yet - run test_findings_match_baseline first")

        results = _run_scan()
        deltas = _scanner_deltas(baseline, results)

        if deltas:
            msg_parts = []
            for scanner, delta in deltas.items():
                msg_parts.append(
                    f"  {scanner}: {baseline['native_scanner_counts'].get(scanner, 0)} -> "
                    f"{results['native_scanner_counts'].get(scanner, 0)} ({delta:+d})"
                )
            pytest.fail(
                f"Native scanner counts changed:\n" + "\n".join(msg_parts)
            )

    def test_native_survivors_stable(self):
        """Native post-FP-filter survivor count should not change."""
        baseline = _load_baseline()
        if baseline is None:
            pytest.skip("No baseline yet")

        results = _run_scan()
        assert results["native_survivors"] == baseline["native_survivors"], (
            f"Native post-filter survivor count changed! "
            f"Baseline: {baseline['native_survivors']}, "
            f"Current: {results['native_survivors']}."
        )

    def test_timing_not_regressed(self):
        """Scan time must not be worse than 3x baseline (catches O(N) regressions, allows load variance)."""
        baseline = _load_baseline()
        if baseline is None:
            pytest.skip("No baseline yet")

        results = _run_scan()
        # 3x tolerance: MEDUSA's own reported time varies ~2x under CPU load
        # (parallel worker overhead). 3x catches true regressions (O(N) scanner
        # added, catastrophic backtracking) while ignoring normal load variance.
        max_allowed = baseline["elapsed_seconds"] * 3.0

        assert results["elapsed_seconds"] <= max_allowed, (
            f"Scan time regressed! "
            f"Baseline: {baseline['elapsed_seconds']}s, "
            f"Current: {results['elapsed_seconds']}s, "
            f"Max allowed: {max_allowed}s"
        )


def _scanner_deltas(baseline, current):
    """Calculate per-native-scanner count differences."""
    all_scanners = set(baseline.get("native_scanner_counts", {}).keys()) | set(
        current.get("native_scanner_counts", {}).keys()
    )
    deltas = {}
    for scanner in sorted(all_scanners):
        b = baseline.get("native_scanner_counts", {}).get(scanner, 0)
        c = current.get("native_scanner_counts", {}).get(scanner, 0)
        if b != c:
            deltas[scanner] = c - b
    return deltas


# Allow running standalone to create/update baseline
if __name__ == "__main__":
    import sys

    print("Running benchmark scan...")
    results = _run_scan()
    print(f"Native pre-filter findings: {results['native_total']}")
    print(f"External pre-filter findings (informational): {results['external_total']}")
    print(f"Native survivors (post-filter): {results['native_survivors']}")
    print(f"Native FP filtered: {results['native_fp_filtered']}")
    print(f"Files scanned: {results['files_scanned']}")
    print(f"Elapsed: {results['elapsed_seconds']}s")
    print(f"Native per scanner: {json.dumps(results['native_scanner_counts'], indent=2)}")

    if "--save-baseline" in sys.argv:
        _save_baseline(results)
        print(f"\nBaseline saved to {BASELINE_FILE}")
