"""Review-2 pipeline lane tests (RC-1, RM-3, RM-6).

Every test here exercises the REAL output path: it calls the actual report
generators (parallel.py `generate_report`, reporter.py `generate_html_report` /
`generate_markdown_report`) and asserts on the emitted JSON / HTML / Markdown.
We deliberately do NOT assert on `ScannerIssue.to_dict()` or any convenience
path — that false-green is exactly how the remediation regression (RC-1)
slipped through a prior gate.
"""

import json
from pathlib import Path

import pytest

from medusa.core.parallel import MedusaParallelScanner, ScanResult
from medusa.core.reporter import MedusaReportGenerator
from medusa.scanners.base import ScannerIssue, Severity


# ---------------------------------------------------------------------------
# RC-1 — remediation must survive the normal scan aggregation path
# ---------------------------------------------------------------------------

def _make_scan_result_with_remediation():
    """A ScanResult whose ScannerIssue carries a remediation string.

    The aggregator (parallel.py:1517-1545) reads result.scanner, result.file,
    result.issues and result.line_count, so all four are populated here.
    """
    issue = ScannerIssue(
        severity=Severity.HIGH,
        message="Hardcoded secret detected",
        line=12,
        code="API_KEY = 'sk-live-abc'",
        rule_id="secret-001",
        cwe_id=798,
        remediation="Do X",
    )
    return ScanResult(
        file="app/config.py",
        scanner="SecretsScanner",
        issues=[issue],
        scan_time=0.01,
        line_count=20,
    )


def test_rc1_remediation_in_json_real_path(tmp_path):
    """generate_report -> emitted JSON must carry remediation='Do X'.

    Exercises the ScannerIssue branch of the aggregator and the real JSON
    writer, not to_dict().
    """
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    result = _make_scan_result_with_remediation()

    scanner.generate_report(
        [result],
        output_dir=tmp_path,
        formats=["json"],
        ai_safe=False,
    )

    json_files = list(tmp_path.glob("medusa-scan-*.json"))
    assert json_files, "no JSON report emitted by generate_report"
    data = json.loads(json_files[0].read_text(encoding="utf-8"))

    findings = data["findings"]
    assert len(findings) == 1, f"expected 1 finding, got {len(findings)}"
    assert findings[0].get("remediation") == "Do X", (
        "remediation dropped on the real aggregation/JSON path "
        f"(finding={findings[0]!r})"
    )


def test_rc1_remediation_in_html_real_path(tmp_path):
    """generate_report(html) must render the remediation block in the HTML."""
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    result = _make_scan_result_with_remediation()

    scanner.generate_report(
        [result],
        output_dir=tmp_path,
        formats=["json", "html"],
        ai_safe=False,
    )

    html_files = list(tmp_path.glob("medusa-scan-*.html"))
    assert html_files, "no HTML report emitted by generate_report"
    html = html_files[0].read_text(encoding="utf-8")

    assert "Remediation:" in html, "remediation label missing from HTML"
    assert "Do X" in html, "remediation text missing from rendered HTML"


def test_rc1_remediation_dict_branch_real_path(tmp_path):
    """Cached findings arrive as dicts; the dict branch must keep remediation."""
    scanner = MedusaParallelScanner(project_root=tmp_path, use_cache=False)
    dict_result = ScanResult(
        file="app/legacy.py",
        scanner="SecretsScanner",
        issues=[
            {
                "_scanner_name": "SecretsScanner",
                "line_number": 5,
                "issue_severity": "HIGH",
                "issue_text": "Hardcoded secret",
                "rule_id": "secret-001",
                "remediation": "Rotate the key",
                "code": "TOKEN = 'x'",
            }
        ],
        scan_time=0.0,
        cached=True,
        line_count=10,
    )

    scanner.generate_report(
        [dict_result],
        output_dir=tmp_path,
        formats=["json"],
        ai_safe=False,
    )

    data = json.loads(
        next(tmp_path.glob("medusa-scan-*.json")).read_text(encoding="utf-8")
    )
    assert data["findings"][0].get("remediation") == "Rotate the key"


# ---------------------------------------------------------------------------
# RM-3 — HTML scanner-summary table uses the friendly display name
# ---------------------------------------------------------------------------

def test_rm3_html_summary_uses_display_name(tmp_path):
    """A finding from 'AIAttackSignatureScanner' must show the friendly label
    in the HTML Scanner Summary table, matching the finding cards."""
    gen = MedusaReportGenerator(output_dir=tmp_path)
    scan_results = {
        "findings": [
            {
                "scanner": "AIAttackSignatureScanner",
                "file": "agent.py",
                "line": 3,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "issue": "Prompt injection",
                "rule_id": "ai-001",
            }
        ],
        "files_scanned": 1,
        "total_lines_scanned": 10,
    }

    json_path = gen.generate_json_report(scan_results, tmp_path / "r.json", ai_safe=False)
    html_path = gen.generate_html_report(json_path, tmp_path / "r.html")
    html = html_path.read_text(encoding="utf-8")

    assert "AI Attack Signatures (always-on)" in html, (
        "friendly scanner display name missing from HTML"
    )
    # The raw class name must not leak inside a summary-table cell. It is
    # acceptable elsewhere (e.g. embedded JSON data attributes); we assert the
    # specific table-cell rendering uses the display name.
    assert (
        '>AIAttackSignatureScanner</td>' not in html
    ), "raw scanner class name leaked into a summary table cell"


# ---------------------------------------------------------------------------
# RM-6 — Markdown report uses text prefixes, not emoji, for severities
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI = {"🚨", "🔴", "🟡", "🔵", "⚪", "✨"}


def _has_emoji(text: str) -> bool:
    return any(ch in text for ch in _SEVERITY_EMOJI)


def test_rm6_markdown_severity_labels_no_emoji(tmp_path):
    """generate_markdown_report: severity table + finding headers carry no
    emoji; severities are rendered as text/bracket prefixes."""
    gen = MedusaReportGenerator(output_dir=tmp_path)
    scan_results = {
        "findings": [
            {
                "scanner": "SecretsScanner",
                "file": "a.py",
                "line": 1,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "issue": "Critical issue",
            },
            {
                "scanner": "SecretsScanner",
                "file": "b.py",
                "line": 2,
                "severity": "HIGH",
                "confidence": "HIGH",
                "issue": "High issue",
            },
        ],
        "files_scanned": 2,
        "total_lines_scanned": 20,
    }

    md_path = gen.generate_markdown_report(scan_results, tmp_path / "r.md", ai_safe=False)
    md = md_path.read_text(encoding="utf-8")

    assert not _has_emoji(md), "emoji found in markdown report severity output"
    # Severities present as text and finding headers use bracket prefixes.
    assert "**CRITICAL**" in md
    assert "### 1. [CRITICAL]" in md


def test_rm6_markdown_no_findings_no_emoji(tmp_path):
    """The empty-state line must not contain the sparkles emoji."""
    gen = MedusaReportGenerator(output_dir=tmp_path)
    scan_results = {"findings": [], "files_scanned": 1, "total_lines_scanned": 5}

    md_path = gen.generate_markdown_report(scan_results, tmp_path / "r.md", ai_safe=False)
    md = md_path.read_text(encoding="utf-8")

    assert not _has_emoji(md), "emoji found in markdown no-findings line"
    assert "No security issues found." in md


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
