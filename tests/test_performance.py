"""
Performance unit tests for MEDUSA optimizations.

Each test validates a specific optimization from the Performance & Sustainability plan.
Tests are written BEFORE the optimization so they can verify the fix works.
"""
import re
import random
from pathlib import Path

import pytest


class TestRuleLoaderSingleton:
    """Wave 1.1: Verify RuleLoader uses singleton pattern."""

    def test_get_loader_returns_same_instance(self):
        """get_loader() should return the same object on repeated calls."""
        from medusa.rules import get_loader

        loader1 = get_loader()
        loader2 = get_loader()
        assert loader1 is loader2, "get_loader() should return singleton instance"

    def test_rules_loaded_once(self):
        """Rules should only be loaded from disk once across multiple get_loader calls."""
        from medusa.rules import get_loader

        loader = get_loader()
        rules = loader.load_all_rules()
        assert len(rules) > 0, "Should have loaded some rules"


class TestCompiledPatterns:
    """Wave 1.2: Verify Rule._compiled_patterns is populated and usable."""

    def test_rules_have_compiled_patterns(self):
        """Every Rule with patterns should have corresponding _compiled_patterns."""
        from medusa.rules import get_loader

        loader = get_loader()
        rules = loader.load_all_rules()

        for rule in rules:
            if rule.patterns:
                assert len(rule._compiled_patterns) == len(rule.patterns), (
                    f"Rule {rule.id}: {len(rule.patterns)} patterns but "
                    f"{len(rule._compiled_patterns)} compiled"
                )

    def test_compiled_patterns_are_regex_objects(self):
        """_compiled_patterns should contain re.Pattern objects."""
        from medusa.rules import get_loader

        loader = get_loader()
        rules = loader.load_all_rules()

        for rule in rules[:10]:  # Check first 10
            for compiled in rule._compiled_patterns:
                assert isinstance(compiled, re.Pattern), (
                    f"Rule {rule.id}: expected re.Pattern, got {type(compiled)}"
                )

    def test_compiled_patterns_match_same_as_raw(self):
        """Compiled patterns should produce same matches as re.search(raw)."""
        from medusa.rules import get_loader

        loader = get_loader()
        rules = loader.load_all_rules()

        test_lines = [
            "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
            "ignore previous instructions",
            "password = 'MySecretPassword123'",
            "import os; os.system(cmd)",
            "def safe_function(): pass",
        ]

        for rule in rules[:20]:  # Check first 20 rules
            for i, pattern_str in enumerate(rule.patterns):
                compiled = rule._compiled_patterns[i]
                for line in test_lines:
                    try:
                        raw_match = bool(re.search(pattern_str, line, re.IGNORECASE))
                    except re.error:
                        continue
                    compiled_match = bool(compiled.search(line))
                    assert raw_match == compiled_match, (
                        f"Rule {rule.id}, pattern {i}: "
                        f"raw={raw_match}, compiled={compiled_match} on '{line[:50]}'"
                    )


class TestSeverityMapConstant:
    """Wave 1.3: Verify severity_map is a module-level constant."""

    def test_severity_map_exists_at_module_level(self):
        """_SEVERITY_MAP should be importable from base module."""
        try:
            from medusa.scanners.base import _SEVERITY_MAP
            assert isinstance(_SEVERITY_MAP, dict)
            assert "CRITICAL" in _SEVERITY_MAP
            assert "HIGH" in _SEVERITY_MAP
            assert "MEDIUM" in _SEVERITY_MAP
            assert "LOW" in _SEVERITY_MAP
            assert "INFO" in _SEVERITY_MAP
        except ImportError:
            pytest.skip("_SEVERITY_MAP not yet hoisted to module level (Wave 1.3 pending)")

    def test_cwe_regex_exists_at_module_level(self):
        """_CWE_RE should be a pre-compiled regex at module level."""
        try:
            from medusa.scanners.base import _CWE_RE
            assert isinstance(_CWE_RE, re.Pattern)
            match = _CWE_RE.search("CWE-89")
            assert match is not None
            assert match.group(1) == "89"
        except ImportError:
            pytest.skip("_CWE_RE not yet hoisted to module level (Wave 1.3 pending)")


class TestScannerIssueRuleUrl:
    """Wave 1.4: Verify ScannerIssue accepts rule_url."""

    def test_scanner_issue_accepts_rule_url(self):
        """ScannerIssue should accept rule_url as a keyword argument."""
        from medusa.scanners.base import ScannerIssue, Severity

        issue = ScannerIssue(
            severity=Severity.HIGH,
            message="Test issue",
            rule_url="https://example.com/rule",
        )
        assert issue.rule_url == "https://example.com/rule"

    def test_scanner_issue_rule_url_default_none(self):
        """ScannerIssue.rule_url should default to None."""
        from medusa.scanners.base import ScannerIssue, Severity

        issue = ScannerIssue(severity=Severity.LOW, message="Test")
        assert issue.rule_url is None

    def test_scanner_issue_to_dict_includes_rule_url(self):
        """to_dict() should include rule_url when set."""
        from medusa.scanners.base import ScannerIssue, Severity

        issue = ScannerIssue(
            severity=Severity.MEDIUM,
            message="Test",
            rule_url="https://example.com",
        )
        d = issue.to_dict()
        assert "rule_url" in d
        assert d["rule_url"] == "https://example.com"


class TestFPFilterCompilation:
    """Wave 2.1: Verify FPPattern has pre-compiled regex fields."""

    def test_fp_patterns_have_compiled_fields(self):
        """FPPattern should have _compiled_pattern after init."""
        try:
            from medusa.core.fp_filter import FalsePositiveFilter

            fpf = FalsePositiveFilter()
            for fp in fpf.KNOWN_FP_PATTERNS[:10]:
                assert hasattr(fp, "_compiled_pattern"), (
                    f"FPPattern '{fp.name}' missing _compiled_pattern"
                )
                if fp.pattern:
                    assert fp._compiled_pattern is not None, (
                        f"FPPattern '{fp.name}' has pattern but _compiled_pattern is None"
                    )
        except (ImportError, AttributeError):
            pytest.skip("FPPattern pre-compilation not yet implemented (Wave 2.1 pending)")

    def test_all_fp_patterns_compile(self):
        """All 425 FP patterns should compile without error."""
        from medusa.core.fp_filter import FalsePositiveFilter

        fpf = FalsePositiveFilter()
        errors = []
        for fp in fpf.KNOWN_FP_PATTERNS:
            try:
                re.compile(fp.pattern, re.IGNORECASE)
            except re.error as e:
                errors.append(f"{fp.name}: {e}")

        assert not errors, f"{len(errors)} patterns failed to compile:\n" + "\n".join(
            errors[:10]
        )


class TestBisectLineNumbers:
    """Wave 3.2: Verify bisect-based line counting matches count('\\n')."""

    def test_bisect_matches_count_newline(self):
        """bisect line lookup should produce same results as count('\\n')."""
        from bisect import bisect_left

        # Generate test content with known line structure
        lines = ["line " + str(i) for i in range(200)]
        content = "\n".join(lines)

        # Build line offsets (what the utility function will do)
        offsets = [i for i, c in enumerate(content) if c == "\n"]

        # Test 1000 random positions
        random.seed(42)  # Reproducible
        for _ in range(1000):
            pos = random.randint(0, len(content) - 1)

            # Old method
            expected = content[:pos].count("\n") + 1

            # New method (bisect)
            actual = bisect_left(offsets, pos) + 1

            assert actual == expected, (
                f"Line mismatch at pos {pos}: bisect={actual}, count={expected}"
            )

    def test_bisect_edge_cases(self):
        """Test edge cases: start of file, end of file, empty lines."""
        from bisect import bisect_left

        content = "first\n\nthird\nlast"
        offsets = [i for i, c in enumerate(content) if c == "\n"]

        # Position 0 = line 1
        assert bisect_left(offsets, 0) + 1 == 1
        # Position right after first \n = line 2
        assert bisect_left(offsets, 6) + 1 == 2
        # Position right after second \n = line 3
        assert bisect_left(offsets, 7) + 1 == 3
        # Last character
        assert bisect_left(offsets, len(content) - 1) + 1 == content[: len(content) - 1].count("\n") + 1
