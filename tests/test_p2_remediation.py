#!/usr/bin/env python3
"""
P2-3 gate: Remediation field on ScannerIssue and rendered in HTML report.

Expected state: RED — ScannerIssue has no 'remediation' field, and Rust/PHP
rule findings don't carry remediation text. HTML report does not render a
remediation section.

Post-fix state (must go GREEN after the fix lands):
  - ScannerIssue dataclass has a 'remediation' field (str, optional)
  - Scanning a Rust or PHP file that triggers a rule produces a finding
    with non-empty remediation (sourced from the rule's 'fix:' field)
  - The HTML report body contains a recognizable remediation section heading
    or class for findings that carry remediation text

Assumptions:
  - Rule.fix (already present in the Rule dataclass) is the source of
    remediation text and will be mapped to ScannerIssue.remediation at
    scan time in RuleBasedScanner._scan_with_rules().
  - 'fix' field is already on Rust rules (unsafe_memory.yaml has it).
  - PHP rules (injection.yaml) also carry 'fix:'.
"""

import pytest
from pathlib import Path


class TestScannerIssueRemediationField:
    """ScannerIssue must have a remediation field."""

    def test_scanner_issue_has_remediation_field(self):
        from medusa.scanners.base import ScannerIssue, Severity
        issue = ScannerIssue(severity=Severity.HIGH, message="test")
        assert hasattr(issue, 'remediation'), (
            "ScannerIssue must have a 'remediation' attribute"
        )

    def test_scanner_issue_remediation_default_is_none_or_empty(self):
        from medusa.scanners.base import ScannerIssue, Severity
        issue = ScannerIssue(severity=Severity.HIGH, message="test")
        # Default should be None or empty string (not an error)
        assert issue.remediation is None or issue.remediation == "", (
            "ScannerIssue.remediation should default to None or ''"
        )

    def test_scanner_issue_to_dict_includes_remediation(self):
        from medusa.scanners.base import ScannerIssue, Severity
        issue = ScannerIssue(
            severity=Severity.HIGH,
            message="test",
            remediation="Use safe API instead",
        )
        d = issue.to_dict()
        assert 'remediation' in d, "to_dict() must include 'remediation' key"


class TestRustRuleRemediationPopulated:
    """Rust rule findings must carry non-empty remediation (from rule fix: field)."""

    def test_rust_finding_has_remediation(self, tmp_path):
        """Scanning a .rs file with a mem::transmute call should produce a finding
        with a non-empty remediation field."""
        from medusa.scanners.rust_scanner import RustScanner

        rust_file = tmp_path / "unsafe_code.rs"
        # mem::transmute triggers MEDUSA-RUST-SCAN-040, which has a 'fix:' field
        rust_file.write_text(
            'fn main() {\n'
            '    let x: u32 = 42;\n'
            '    let y: i32 = unsafe { std::mem::transmute(x) };\n'
            '    println!("{}", y);\n'
            '}\n'
        )

        scanner = RustScanner()
        result = scanner.scan_file(rust_file)
        assert result.issues, (
            "Expected at least one finding from Rust unsafe_memory rule on mem::transmute"
        )
        finding = result.issues[0]
        assert hasattr(finding, 'remediation'), "ScannerIssue must have 'remediation'"
        assert finding.remediation, (
            "Rust rule finding must have non-empty remediation (sourced from rule 'fix:' field)"
        )


class TestPHPRuleRemediationPopulated:
    """PHP rule findings must carry non-empty remediation."""

    def test_php_finding_has_remediation(self, tmp_path):
        """Scanning a .php file with a SQL injection pattern should produce a
        finding with non-empty remediation."""
        from medusa.scanners.php_scanner import PHPScanner

        php_file = tmp_path / "app.php"
        # Triggers MEDUSA-PHP-SCAN-001, which has 'fix:' field
        php_file.write_text(
            '<?php\n'
            '$id = $_GET["id"];\n'
            '$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");\n'
        )

        scanner = PHPScanner()
        result = scanner.scan_file(php_file)
        assert result.issues, (
            "Expected at least one finding from PHP SQL injection rule"
        )
        finding = result.issues[0]
        assert hasattr(finding, 'remediation'), "ScannerIssue must have 'remediation'"
        assert finding.remediation, (
            "PHP rule finding must have non-empty remediation (sourced from rule 'fix:' field)"
        )


class TestHTMLReportRendersRemediation:
    """HTML report must include a remediation section for findings that carry it."""

    def test_html_report_has_remediation_section(self, tmp_path):
        from medusa.core.reporter import MedusaReportGenerator
        reporter = MedusaReportGenerator(output_dir=tmp_path)

        # A finding that includes a remediation field
        scan_results = {
            'findings': [{
                'scanner': 'RustScanner',
                'file': 'src/main.rs',
                'line': 3,
                'severity': 'MEDIUM',
                'confidence': 'HIGH',
                'issue': 'Rust: mem::transmute — type punning can cause UB',
                'rule_id': 'MEDUSA-RUST-SCAN-040',
                'remediation': 'Use safe conversions (From/TryFrom, bytemuck) instead of transmute.',
            }],
            'files_scanned': 1,
            'total_lines_scanned': 5,
        }
        json_path = reporter.generate_json_report(scan_results)
        html_path = reporter.generate_html_report(json_path)
        html_body = html_path.read_text()

        # The HTML must render the remediation text or a 'Remediation' section heading
        assert 'Remediation' in html_body or 'remediation' in html_body.lower(), (
            "HTML report must render a 'Remediation' section for findings that carry it"
        )
        assert 'bytemuck' in html_body or 'safe conversions' in html_body.lower(), (
            "HTML report must include the actual remediation text from the finding"
        )
