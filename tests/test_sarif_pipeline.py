#!/usr/bin/env python3
"""
Gate P1-2 — SARIF works end-to-end.

Asserts:
- 'sarif' is an accepted --format choice on the scan CLI command.
- generate_report() (parallel.py) with formats=['sarif'] writes a valid
  SARIF 2.1.0 JSON file.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock


def _get_scan_format_param():
    """Return the --format Click parameter from the scan command."""
    from medusa.cli import main
    scan_cmd = main.commands.get('scan')
    if scan_cmd is None:
        scan_cmd = main.get_command(None, 'scan')
    assert scan_cmd is not None, "scan command not found"
    # output_formats is the attr name (--format is the cli name)
    fmt_param = next(
        (p for p in scan_cmd.params if p.name == 'output_formats'),
        None,
    )
    return fmt_param


class TestSARIFFormatChoice:
    """P1-2a: 'sarif' must be a valid --format choice."""

    def test_sarif_in_format_choices(self):
        """The scan --format option must include 'sarif' in its allowed choices."""
        fmt_param = _get_scan_format_param()
        assert fmt_param is not None, "--format / output_formats param not found on scan command"

        # Click Choice stores choices as a list on the type object
        choices = fmt_param.type.choices
        assert 'sarif' in choices, (
            f"'sarif' not in --format choices: {choices}"
        )

    def test_format_help_lists_sarif(self):
        """scan --help output must mention sarif as a format option."""
        from medusa.cli import main
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'sarif' in result.output, (
            "sarif not mentioned in scan --help output"
        )


class TestSARIFPipelineOutput:
    """P1-2b: generate_report() must produce a valid SARIF 2.1.0 file."""

    def _make_scan_result(self, file_path: Path):
        """Build a minimal ScanResult accepted by generate_report()."""
        from medusa.core.parallel import ScanResult

        issue = {
            'issue_text': 'Hardcoded secret detected',
            'issue_severity': 'HIGH',
            'issue_confidence': 'HIGH',
            'line_number': 5,
            'code': 'API_KEY = "sk-test-1234"',
        }

        return ScanResult(
            file=str(file_path),
            scanner='medusa-rules',
            issues=[issue],
            scan_time=0.01,
            cached=False,
            line_count=10,
        )

    def test_generate_report_writes_sarif_file(self, tmp_path):
        """generate_report with formats=['sarif'] must write a .sarif file."""
        from medusa.core.parallel import MedusaParallelScanner

        # Write a tiny source file so the result path is real
        src = tmp_path / "src.py"
        src.write_text('API_KEY = "sk-test-1234"\n')

        scanner = MedusaParallelScanner(project_root=tmp_path)
        results = [self._make_scan_result(src)]
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        scanner.generate_report(results, output_dir=output_dir, formats=['sarif'])

        sarif_files = list(output_dir.glob('*.sarif'))
        assert sarif_files, (
            f"No .sarif file found in {output_dir}. Files present: {list(output_dir.iterdir())}"
        )

    def test_generated_sarif_is_valid_json(self, tmp_path):
        """The .sarif file produced must be parseable as JSON."""
        from medusa.core.parallel import MedusaParallelScanner

        src = tmp_path / "src.py"
        src.write_text('API_KEY = "sk-test-1234"\n')

        scanner = MedusaParallelScanner(project_root=tmp_path)
        results = [self._make_scan_result(src)]
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        scanner.generate_report(results, output_dir=output_dir, formats=['sarif'])

        sarif_file = next(iter(output_dir.glob('*.sarif')))
        with open(sarif_file) as f:
            data = json.load(f)  # must not raise

        assert isinstance(data, dict), "SARIF file did not parse to a dict"

    def test_generated_sarif_version_is_2_1_0(self, tmp_path):
        """The .sarif file must declare version '2.1.0' at the top level."""
        from medusa.core.parallel import MedusaParallelScanner

        src = tmp_path / "src.py"
        src.write_text('API_KEY = "sk-test-1234"\n')

        scanner = MedusaParallelScanner(project_root=tmp_path)
        results = [self._make_scan_result(src)]
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        scanner.generate_report(results, output_dir=output_dir, formats=['sarif'])

        sarif_file = next(iter(output_dir.glob('*.sarif')))
        with open(sarif_file) as f:
            data = json.load(f)

        assert data.get('version') == '2.1.0', (
            f"Expected SARIF version '2.1.0', got: {data.get('version')!r}"
        )

    def test_generated_sarif_has_runs(self, tmp_path):
        """The .sarif file must contain a 'runs' array."""
        from medusa.core.parallel import MedusaParallelScanner

        src = tmp_path / "src.py"
        src.write_text('API_KEY = "sk-test-1234"\n')

        scanner = MedusaParallelScanner(project_root=tmp_path)
        results = [self._make_scan_result(src)]
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        scanner.generate_report(results, output_dir=output_dir, formats=['sarif'])

        sarif_file = next(iter(output_dir.glob('*.sarif')))
        with open(sarif_file) as f:
            data = json.load(f)

        assert 'runs' in data, "SARIF missing top-level 'runs' key"
        assert isinstance(data['runs'], list), "'runs' must be a list"
        assert len(data['runs']) >= 1, "'runs' must contain at least one entry"

    def test_reporter_generate_sarif_direct(self, tmp_path, sample_scan_results):
        """MedusaReportGenerator.generate_sarif_report() produces a valid SARIF 2.1.0 file."""
        from medusa.core.reporter import MedusaReportGenerator

        reporter = MedusaReportGenerator(output_dir=tmp_path)
        sarif_path = reporter.generate_sarif_report(sample_scan_results)

        assert sarif_path.exists(), f"SARIF file not written: {sarif_path}"
        assert sarif_path.suffix == '.sarif'

        with open(sarif_path) as f:
            data = json.load(f)

        assert data.get('version') == '2.1.0', (
            f"SARIF version mismatch: {data.get('version')!r}"
        )
