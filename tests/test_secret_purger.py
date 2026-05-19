"""Tests for `medusa secrets purge` redaction safety + correctness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from medusa.core.secret_obfuscator import write_report
from medusa.core.secret_purger import (
    build_plans_from_report,
    execute_plans,
)
from medusa.scanners.ai_chat_history_scanner import scan_file


def _scan_to_report(path: Path) -> dict:
    """Run scan_file + write_report and load the on-disk report back."""
    results = [scan_file(path)]
    report_path = write_report(results)
    with open(report_path) as f:
        return json.load(f)


def test_jsonl_redaction_preserves_other_lines(tmp_path: Path):
    """A redaction on one line must not touch the other lines."""
    path = tmp_path / "history.jsonl"
    planted = "ghp_" + "A" * 36
    path.write_text(
        '{"role":"user","content":"line 1 plain","ts":1}\n'
        f'{{"role":"user","content":"line 2 has {planted} inside","ts":2}}\n'
        '{"role":"user","content":"line 3 plain","ts":3}\n',
        encoding="utf-8",
    )

    report = _scan_to_report(path)
    plans = build_plans_from_report(report)
    results = execute_plans(plans)

    assert all(r.error is None for r in results), [r.error for r in results]
    assert sum(r.redactions_applied for r in results) == 1

    after = path.read_text(encoding="utf-8").splitlines()
    assert after[0] == '{"role":"user","content":"line 1 plain","ts":1}'
    assert planted not in after[1]
    assert "[REDACTED-MEDUSA-SECRET-GITHUB-PAT-" in after[1]
    assert after[2] == '{"role":"user","content":"line 3 plain","ts":3}'


def test_jsonl_still_parses_after_redaction(tmp_path: Path):
    """Every line of the redacted JSONL must still parse as JSON."""
    path = tmp_path / "history.jsonl"
    secrets = ["ghp_" + "B" * 36, "AKIAIOSFODNN7EXAMPLE", "hf_" + "C" * 35]
    lines = [
        f'{{"role":"user","content":"first {secrets[0]}","ts":1}}',
        f'{{"role":"user","content":"second {secrets[1]}","ts":2}}',
        f'{{"role":"user","content":"third {secrets[2]}","ts":3}}',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = _scan_to_report(path)
    plans = build_plans_from_report(report)
    results = execute_plans(plans)

    assert all(r.error is None for r in results), [r.error for r in results]

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            json.loads(line)  # must not raise


def test_backup_is_created_with_secure_mode(tmp_path: Path):
    """The backup file must exist and be mode 0o600."""
    path = tmp_path / "h.jsonl"
    path.write_text(
        '{"content":"x ghp_' + "D" * 36 + ' y"}\n',
        encoding="utf-8",
    )

    report = _scan_to_report(path)
    plans = build_plans_from_report(report)
    results = execute_plans(plans)

    assert results[0].error is None
    backup = results[0].backup_path
    assert backup is not None
    assert backup.exists()
    mode = backup.stat().st_mode & 0o777
    assert mode == 0o600, f"backup mode is {oct(mode)}; want 0o600"


def test_refuses_when_file_changed(tmp_path: Path):
    """If the file was modified between scan and purge, the purger
    must refuse and leave the file unchanged."""
    path = tmp_path / "history.txt"
    planted = "ghp_" + "E" * 36
    original = f"prefix---{planted}---suffix\n"
    path.write_text(original, encoding="utf-8")

    report = _scan_to_report(path)

    # User edits the file before purge.
    tampered = original.replace(planted, "ghp_" + "X" * 36)
    path.write_text(tampered, encoding="utf-8")

    plans = build_plans_from_report(report)
    results = execute_plans(plans)

    assert results[0].error is not None
    assert "file changed since scan" in results[0].error
    # File must be exactly what the user left it as.
    assert path.read_text(encoding="utf-8") == tampered


def test_multiple_redactions_same_file_offsets_stable(tmp_path: Path):
    """Redacting several secrets on the same line must keep offsets
    valid via reverse-order application."""
    path = tmp_path / "h.txt"
    s1 = "ghp_" + "F" * 36
    s2 = "AKIAIOSFODNN7EXAMPLE"
    content = f"first {s1} middle {s2} end\n"
    path.write_text(content, encoding="utf-8")

    report = _scan_to_report(path)
    assert len(report["findings"]) == 2

    plans = build_plans_from_report(report)
    results = execute_plans(plans)
    assert results[0].error is None
    assert results[0].redactions_applied == 2

    after = path.read_text(encoding="utf-8")
    assert s1 not in after
    assert s2 not in after
    assert "[REDACTED-MEDUSA-SECRET-GITHUB-PAT-" in after
    assert "[REDACTED-MEDUSA-SECRET-AWS-ACCESS-KEY-" in after


def test_partial_selection_via_indices(tmp_path: Path):
    """`build_plans_from_report` must honour the selected_indices filter."""
    path = tmp_path / "h.txt"
    s1 = "ghp_" + "G" * 36
    s2 = "AKIAIOSFODNN7EXAMPLE"
    path.write_text(f"{s1}\n{s2}\n", encoding="utf-8")

    report = _scan_to_report(path)
    indices_by_rule = {
        f["rule_id"]: i for i, f in enumerate(report["findings"])
    }
    only_github = [indices_by_rule["MEDUSA-SECRET-GITHUB-PAT"]]

    plans = build_plans_from_report(report, selected_indices=only_github)
    results = execute_plans(plans)
    assert results[0].error is None

    after = path.read_text(encoding="utf-8")
    assert s1 not in after  # redacted
    assert s2 in after  # not selected, must remain
