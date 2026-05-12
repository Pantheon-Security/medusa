"""
Regression tests for MEDUSA Performance & Sustainability Overhaul.

Scans tests/benchmark_corpus/ and compares findings count to baseline.
On first run: creates baseline. On subsequent runs: asserts findings match.

Uses the pre-FP-filter total (fp_stats.total_findings) as the regression metric
since scanner output must be stable regardless of FP filter changes.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

BASELINE_FILE = Path(__file__).parent / "benchmark_baseline.json"
CORPUS_DIR = Path(__file__).parent / "benchmark_corpus"


_TOTAL_TIME_RE = re.compile(r"Total time:\s+([\d.]+)s")


def _run_scan():
    """Run medusa scan on the benchmark corpus and return parsed results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_dir = Path(tmpdir)
        start = time.time()
        result = subprocess.run(
            [
                sys.executable, "-m", "medusa", "scan",
                str(CORPUS_DIR), "--output", "json",
                "-o", str(report_dir),
            ],
            capture_output=True,
            text=True,
            timeout=300,  # Allow up to 5 min; wall-clock includes Semgrep/GitLeaks startup
            env={**os.environ, "MEDUSA_NO_BANNER": "1"},
        )
        wall_elapsed = time.time() - start

        # Prefer MEDUSA's own reported scan time (stable, excludes external-tool
        # subprocess startup overhead that varies ~60-100s by environment).
        # Fall back to wall clock only if the banner line is missing.
        m = _TOTAL_TIME_RE.search(result.stdout)
        elapsed = float(m.group(1)) if m else round(wall_elapsed, 2)

        # Find the JSON report file
        json_files = sorted(report_dir.glob("medusa-scan-*.json"))
        if not json_files:
            # Fallback: check .medusa/reports/ under corpus dir
            corpus_reports = sorted(
                (CORPUS_DIR / ".medusa" / "reports").glob("medusa-scan-*.json")
            )
            if corpus_reports:
                json_files = [corpus_reports[-1]]

        if not json_files:
            return {
                "total_findings": 0,
                "pre_filter_findings": 0,
                "scanner_counts": {},
                "severity_counts": {},
                "elapsed_seconds": round(elapsed, 2),
                "returncode": result.returncode,
                "error": "No JSON report file found",
            }

        with open(json_files[-1]) as f:
            data = json.load(f)

        # Extract pre-filter total (what scanners actually produced)
        fp_stats = data.get("fp_stats", {})
        pre_filter = fp_stats.get("total_findings", 0)

        # Extract post-filter findings for detail
        findings = data.get("findings", [])

        # Count per scanner from aggregations if available
        scanner_counts = {}
        aggregations = data.get("aggregations", {})
        if "by_scanner" in aggregations:
            raw = aggregations["by_scanner"]
            scanner_counts = {k: len(v) if isinstance(v, list) else (v if isinstance(v, (int, float)) else 0) for k, v in raw.items()}
        else:
            # Fall back to counting findings
            for f_item in findings:
                scanner = f_item.get("scanner", "unknown")
                scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        # Severity from report
        severity_counts = data.get("severity_breakdown", {})

        # Scan summary has the real numbers
        summary = data.get("scan_summary", {})

        return {
            "total_findings": pre_filter,  # Pre-FP-filter count
            "post_filter_findings": len(findings),
            "fp_filtered": fp_stats.get("likely_fps", 0),
            "scanner_counts": scanner_counts,
            "severity_counts": severity_counts,
            "files_scanned": summary.get("files_scanned", 0),
            "elapsed_seconds": round(elapsed, 2),
            "returncode": result.returncode,
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
        """Scan must produce at least some findings from the corpus."""
        results = _run_scan()
        assert results["total_findings"] > 0, (
            f"Scan produced zero pre-filter findings. "
            f"Return code: {results['returncode']}. "
            f"Error: {results.get('error', 'none')}"
        )

    def test_findings_match_baseline(self):
        """Pre-filter findings count must match the saved baseline exactly."""
        baseline = _load_baseline()
        results = _run_scan()

        if baseline is None:
            _save_baseline(results)
            pytest.skip(
                f"Baseline created with {results['total_findings']} pre-filter findings "
                f"({results.get('fp_filtered', 0)} FP-filtered). Run again to verify."
            )

        assert results["total_findings"] == baseline["total_findings"], (
            f"Pre-filter finding count changed! "
            f"Baseline: {baseline['total_findings']}, "
            f"Current: {results['total_findings']}. "
            f"Scanner deltas: {_scanner_deltas(baseline, results)}"
        )

    def test_per_scanner_counts_stable(self):
        """Per-scanner finding counts should not change."""
        baseline = _load_baseline()
        if baseline is None:
            pytest.skip("No baseline yet - run test_findings_match_baseline first")

        results = _run_scan()
        deltas = _scanner_deltas(baseline, results)

        if deltas:
            msg_parts = []
            for scanner, delta in deltas.items():
                msg_parts.append(
                    f"  {scanner}: {baseline['scanner_counts'].get(scanner, 0)} -> "
                    f"{results['scanner_counts'].get(scanner, 0)} ({delta:+d})"
                )
            pytest.fail(
                f"Scanner counts changed:\n" + "\n".join(msg_parts)
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
    """Calculate per-scanner count differences."""
    all_scanners = set(baseline.get("scanner_counts", {}).keys()) | set(
        current.get("scanner_counts", {}).keys()
    )
    deltas = {}
    for scanner in sorted(all_scanners):
        b = baseline.get("scanner_counts", {}).get(scanner, 0)
        c = current.get("scanner_counts", {}).get(scanner, 0)
        if b != c:
            deltas[scanner] = c - b
    return deltas


# Allow running standalone to create/update baseline
if __name__ == "__main__":
    print("Running benchmark scan...")
    results = _run_scan()
    print(f"Pre-filter findings: {results['total_findings']}")
    print(f"Post-filter findings: {results.get('post_filter_findings', 'N/A')}")
    print(f"FP filtered: {results.get('fp_filtered', 'N/A')}")
    print(f"Files scanned: {results.get('files_scanned', 'N/A')}")
    print(f"Elapsed: {results['elapsed_seconds']}s")
    print(f"Per scanner: {json.dumps(results.get('scanner_counts', {}), indent=2)}")

    if "--save-baseline" in sys.argv:
        _save_baseline(results)
        print(f"\nBaseline saved to {BASELINE_FILE}")
