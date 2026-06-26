#!/usr/bin/env python3
"""
P2-2 gate: Scanner display names + report rendering.

Expected state: RED — neither scanner has display_name/description,
and the HTML/JSON report does not render a friendly scanner label per finding.

Post-fix state (must go GREEN after the fix lands):
  - AIAttackSignatureScanner.display_name is non-empty and != class name
  - ClaudeCodeScanner.display_name is non-empty and != class name
  - Both scanners expose a non-empty .description (one-line)
  - The JSON report finding dict carries a 'scanner_display_name' key (or equiv)
  - The HTML report body contains the friendly display_name text

Assumptions:
  - display_name will be a class-level or __init__-set attribute on the scanner
  - The JSON report finding dict is the authoritative check for the label
    (the HTML report is generated from the JSON, so if JSON has it, HTML will too)
"""

import json
import pytest
from pathlib import Path

from medusa.scanners.ai_attack_signature_scanner import AIAttackSignatureScanner
from medusa.scanners.claude_code_scanner import ClaudeCodeScanner


class TestScannerDisplayName:
    """Scanners must expose a human-readable display_name distinct from the class name."""

    def test_attack_sig_scanner_has_display_name(self):
        scanner = AIAttackSignatureScanner()
        assert hasattr(scanner, 'display_name'), (
            "AIAttackSignatureScanner must have a 'display_name' attribute"
        )
        assert scanner.display_name, "display_name must not be empty"
        assert scanner.display_name != scanner.__class__.__name__, (
            f"display_name {scanner.display_name!r} must differ from class name "
            f"{scanner.__class__.__name__!r}"
        )

    def test_claude_code_scanner_has_display_name(self):
        scanner = ClaudeCodeScanner()
        assert hasattr(scanner, 'display_name'), (
            "ClaudeCodeScanner must have a 'display_name' attribute"
        )
        assert scanner.display_name, "display_name must not be empty"
        assert scanner.display_name != scanner.__class__.__name__, (
            f"display_name {scanner.display_name!r} must differ from class name "
            f"{scanner.__class__.__name__!r}"
        )

    def test_attack_sig_scanner_has_description(self):
        scanner = AIAttackSignatureScanner()
        assert hasattr(scanner, 'description'), (
            "AIAttackSignatureScanner must have a 'description' attribute"
        )
        assert scanner.description, "description must not be empty"

    def test_claude_code_scanner_has_description(self):
        scanner = ClaudeCodeScanner()
        assert hasattr(scanner, 'description'), (
            "ClaudeCodeScanner must have a 'description' attribute"
        )
        assert scanner.description, "description must not be empty"


class TestReportRendersScannerLabel:
    """HTML and JSON reports must surface a friendly scanner label and rule_id per finding."""

    def _make_finding_with_rule_id(self) -> dict:
        return {
            'scanner': 'AIAttackSignatureScanner',
            'file': 'src/app.py',
            'line': 5,
            'severity': 'HIGH',
            'confidence': 'HIGH',
            'issue': 'DAN jailbreak detected',
            'rule_id': 'MEDUSA-ATKSIG-001',
        }

    def test_json_report_finding_has_rule_id(self, tmp_path):
        """JSON report findings must include rule_id."""
        from medusa.core.reporter import MedusaReportGenerator
        reporter = MedusaReportGenerator(output_dir=tmp_path)
        scan_results = {
            'findings': [self._make_finding_with_rule_id()],
            'files_scanned': 1,
            'total_lines_scanned': 10,
        }
        json_path = reporter.generate_json_report(scan_results)
        data = json.loads(json_path.read_text())
        assert data['findings'], "Expected at least one finding in JSON report"
        finding = data['findings'][0]
        assert 'rule_id' in finding, (
            "JSON report finding must include 'rule_id'"
        )
        assert finding['rule_id'] == 'MEDUSA-ATKSIG-001'

    def test_json_report_finding_has_scanner_display_name(self, tmp_path):
        """JSON report findings must include a friendly scanner label (scanner_display_name)."""
        from medusa.core.reporter import MedusaReportGenerator
        reporter = MedusaReportGenerator(output_dir=tmp_path)
        scan_results = {
            'findings': [self._make_finding_with_rule_id()],
            'files_scanned': 1,
            'total_lines_scanned': 10,
        }
        json_path = reporter.generate_json_report(scan_results)
        data = json.loads(json_path.read_text())
        finding = data['findings'][0]
        # The report should map the raw scanner class name to a friendly label
        assert 'scanner_display_name' in finding, (
            "JSON report finding must include 'scanner_display_name' (the friendly label)"
        )
        assert finding['scanner_display_name'], "scanner_display_name must not be empty"

    def test_html_report_contains_rule_id(self, tmp_path):
        """HTML report must render the rule_id for each finding."""
        from medusa.core.reporter import MedusaReportGenerator
        reporter = MedusaReportGenerator(output_dir=tmp_path)
        scan_results = {
            'findings': [self._make_finding_with_rule_id()],
            'files_scanned': 1,
            'total_lines_scanned': 10,
        }
        json_path = reporter.generate_json_report(scan_results)
        html_path = reporter.generate_html_report(json_path)
        html_body = html_path.read_text()
        assert 'MEDUSA-ATKSIG-001' in html_body, (
            "HTML report must render the finding's rule_id (MEDUSA-ATKSIG-001)"
        )
