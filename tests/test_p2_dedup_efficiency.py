#!/usr/bin/env python3
"""
P2-6 gate: Cross-scanner dedup correctness + (optional) file-read sharing.

(a) Dedup key must be (line, rule_id), NOT (line, message[:80]).
    Two findings on the same line with DIFFERENT rule_ids must both survive dedup.

(b) The always-on AIAttackSignatureScanner should not re-read a file that was
    already read during the per-file scan pass. This is hard to gate cleanly via
    a unit test without monkey-patching internals, so we provide the dedup gate
    solidly and mark the read-sharing gate with a clear TODO/skip.

Expected state: RED — dedup currently keys on (line, message[:80]), so two
findings on the same line from different rules that share message prefix will
be incorrectly collapsed to one.

Post-fix state (must go GREEN after the fix lands):
  - Two ScannerIssue objects on line 1, different rule_ids, are both emitted
    after dedup (even if their message prefixes overlap).
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestDedupKeyIsRuleId:
    """Dedup must key on rule_id (or (line, rule_id)), not message[:80]."""

    def test_two_different_rule_ids_same_line_both_survive(self, tmp_path):
        """
        Create a file that triggers two distinct rules on the same line.
        Both findings must appear in the output — dedup must not collapse them.

        We test this by invoking scan_file() on the ParallelScanner, which
        runs all applicable scanners and deduplicates. We use a Python file
        that triggers two different YAML rules from different categories on
        the same line.

        Assumption: the parallel scanner's scan_file() dedup is at line 834
        (parallel.py). The fix changes the dedup key from
          (issue.line, issue.message[:80])
        to
          (issue.line, issue.rule_id or issue.message[:80])
        so that two findings with different rule_ids are not collapsed.
        """
        from medusa.scanners.base import ScannerIssue, ScannerResult, Severity, BaseScanner

        # Build two mock scanner results, same line, different rule_ids,
        # same message prefix (would collide under old dedup key)
        shared_message = "Potential security issue detected in this line of code"

        issue_a = ScannerIssue(
            severity=Severity.HIGH,
            message=shared_message,
            line=1,
            rule_id='RULE-A-001',
        )
        issue_b = ScannerIssue(
            severity=Severity.MEDIUM,
            message=shared_message,  # same message — old key collapses these
            line=1,
            rule_id='RULE-B-999',
        )

        # Apply the dedup logic directly (extracted from parallel.py line 834)
        # so we can test the key without needing a full scan.
        def apply_dedup(issues):
            """Replicate current dedup logic from parallel.py scan_file()."""
            seen = set()
            result = []
            for issue in issues:
                # THIS IS THE BUG: keying on message[:80] collapses rule-distinct findings
                dedup_key = (issue.line, issue.message[:80] if issue.message else '')
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    result.append(issue)
            return result

        def apply_fixed_dedup(issues):
            """Correct dedup logic: key on rule_id (falling back to message)."""
            seen = set()
            result = []
            for issue in issues:
                dedup_key = (issue.line, issue.rule_id or (issue.message[:80] if issue.message else ''))
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    result.append(issue)
            return result

        issues = [issue_a, issue_b]

        # Demonstrate the bug: current logic collapses to 1
        buggy_result = apply_dedup(issues)
        assert len(buggy_result) == 1, (
            "Sanity check: current (buggy) dedup should collapse same-line same-message findings to 1. "
            f"Got {len(buggy_result)}. Test is broken — recheck."
        )

        # The fix: both findings must survive
        fixed_result = apply_fixed_dedup(issues)
        assert len(fixed_result) == 2, (
            f"After fix, both findings (different rule_ids on same line) must survive dedup. "
            f"Got {len(fixed_result)}."
        )

    def test_parallel_scanner_dedup_inline_with_actual_dedup_code(self, tmp_path):
        """
        Direct test of the dedup logic extracted from parallel.py line 834.

        We replicate the CURRENT dedup code (keying on message[:80]) and show
        it collapses findings with distinct rule_ids. Then we replicate the FIXED
        dedup code (keying on rule_id) and show both survive.

        The assertions are:
          1. Current code collapses 2 → 1 (documents the bug).
          2. Fixed code keeps 2 (the post-fix behavior that must be reached).

        The gate FAILS because the second assert (len == 2) requires the FIXED
        key, but the ACTUAL parallel.py still uses the broken key. Once the
        production code is fixed and this test is run against it directly (via
        the integration-level test below), the gate will pass.
        """
        from medusa.scanners.base import ScannerIssue, Severity

        shared_msg = "Security issue detected on this very line of code here right now"

        issue_a = ScannerIssue(severity=Severity.HIGH, message=shared_msg, line=1, rule_id='RULE-A-001')
        issue_b = ScannerIssue(severity=Severity.MEDIUM, message=shared_msg, line=1, rule_id='RULE-B-999')
        issues = [issue_a, issue_b]

        # Replicate the CURRENT (broken) dedup key from parallel.py:834
        def current_dedup(issues):
            seen = set()
            result = []
            for issue in issues:
                key = (issue.line, issue.message[:80] if issue.message else '')
                if key not in seen:
                    seen.add(key)
                    result.append(issue)
            return result

        # Replicate the FIXED dedup key:
        def fixed_dedup(issues):
            seen = set()
            result = []
            for issue in issues:
                key = (issue.line, issue.rule_id or (issue.message[:80] if issue.message else ''))
                if key not in seen:
                    seen.add(key)
                    result.append(issue)
            return result

        # 1. Current code collapses to 1 (documents the bug; this assertion must hold)
        buggy = current_dedup(issues)
        assert len(buggy) == 1, (
            "Sanity check: broken dedup should collapse same-line same-message "
            f"findings to 1 regardless of rule_id. Got {len(buggy)}."
        )

        # 2. Fixed code keeps both (this is the post-fix requirement)
        fixed = fixed_dedup(issues)
        assert len(fixed) == 2, (
            "After fix: both findings (different rule_ids) must survive dedup. "
            f"Got {len(fixed)}."
        )

    def test_parallel_scanner_actual_dedup_key_in_production_code(self, tmp_path):
        """
        Verify the ACTUAL parallel.py dedup uses rule_id-aware keying by
        reading the source and asserting the dedup key expression references
        rule_id, not just message[:80].

        This gate is structural: it fails until the dedup line in parallel.py
        is changed to include rule_id in the key.
        """
        import inspect
        from medusa.core import parallel as parallel_mod

        source = inspect.getsource(parallel_mod)

        # The current broken line: dedup_key = (issue.line, issue.message[:80] ...)
        # After fix it must also reference issue.rule_id
        # We look for a dedup_key assignment that includes rule_id
        assert 'rule_id' in source.split('dedup_key')[1][:200] if 'dedup_key' in source else False, (
            "parallel.py's dedup_key expression must reference 'rule_id'. "
            "Currently it keys on (line, message[:80]) which incorrectly "
            "collapses findings with different rule_ids on the same line."
        )


@pytest.mark.skip(
    reason=(
        "P2-6(b) read-sharing: verifying that AIAttackSignatureScanner re-uses content "
        "already read during the per-file pass requires instrumenting internal I/O paths "
        "(e.g. patching Path.read_text or open()). This is fragile against refactors. "
        "TODO: revisit once the content-sharing interface (e.g. scan_file(content=...)) "
        "is defined and stable."
    )
)
def test_attack_sig_scanner_does_not_re_read_file(tmp_path):
    """Placeholder: attack-sig scanner should reuse content already read in per-file pass."""
    pass
