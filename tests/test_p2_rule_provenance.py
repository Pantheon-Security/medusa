#!/usr/bin/env python3
"""
P2-7 gate: Rule provenance — vetted vs harvested rules carry a distinguishing marker.

Expected state: RED — the Rule dataclass has no 'provenance' field; the loader
does not expose a provenance attribute; rule YAML files in bulk-harvested
directories do not carry a 'provenance:' or 'source:' top-level metadata key
that the loader reads.

Post-fix state (must go GREEN after the fix lands):
  - Rule dataclass carries a 'provenance' field (str, optional) with values like
    'curated', 'harvested', 'expansion', or similar.
  - RuleLoader (or get_loader()) exposes a way to query which rules are harvested
    vs curated — e.g. a method get_provenance_map() or similar, OR rules are
    attributable individually via rule.provenance.
  - Rust/PHP security rule files carry a 'source:' or 'provenance:' metadata key
    that the loader reads and attaches to each Rule object.

Assumptions:
  - 'curated' = attack_signatures/, rust_security/, php_security/ (hand-written,
    versioned, with fix: fields)
  - 'harvested' = files with 'source: paper-harvest-*', 'source: expansion*', etc.
    (already present in agentic_exploitation/ and others as seen in rule files)
  - The Rule dataclass 'fix' field already exists (sourced from YAML 'fix:').
  - The loader's _parse_rule() already reads top-level YAML metadata; provenance
    will be sourced from file-level metadata.source or rule-level provenance field.

This gate is minimal but real: it asserts the interface exists and is populated
for at least one known case of each provenance class.
"""

import pytest
from pathlib import Path


class TestRuleDataclassProvenance:
    """Rule dataclass must have a provenance field."""

    def test_rule_has_provenance_field(self):
        from medusa.rules import Rule, RuleSeverity
        rule = Rule(
            id='test-prov-001',
            name='Test',
            severity=RuleSeverity.HIGH,
            category='test',
            patterns=['test'],
            message='test',
        )
        assert hasattr(rule, 'provenance'), (
            "Rule dataclass must have a 'provenance' attribute (str, optional)"
        )

    def test_rule_provenance_defaults_to_none_or_empty(self):
        from medusa.rules import Rule, RuleSeverity
        rule = Rule(
            id='test-prov-002',
            name='Test',
            severity=RuleSeverity.MEDIUM,
            category='test',
            patterns=['test'],
            message='test',
        )
        assert rule.provenance is None or rule.provenance == '', (
            "Rule.provenance must default to None or '' when not specified"
        )


class TestLoaderExposesProvenance:
    """RuleLoader must make rule provenance queryable."""

    def test_loader_has_provenance_method_or_attribute(self):
        """Loader exposes provenance info — either via a method or attributable rules."""
        from medusa.rules import get_loader
        loader = get_loader()
        # Accept either a dedicated method or attributable via rule.provenance
        has_method = hasattr(loader, 'get_provenance_map') or hasattr(loader, 'get_rules_by_provenance')
        # If no dedicated method, provenance must at least be on Rule objects
        if not has_method:
            rules = loader.load_rules_from_dir('rust_security')
            if rules:
                assert hasattr(rules[0], 'provenance'), (
                    "Either RuleLoader must expose get_provenance_map() / get_rules_by_provenance(), "
                    "OR Rule objects must have a 'provenance' attribute. Neither is present."
                )


class TestCuratedRulesCarryProvenanceTag:
    """Curated rule files (rust_security, attack_signatures) must carry a provenance/source tag
    that the loader attaches to Rule objects."""

    def test_rust_rules_have_provenance(self):
        from medusa.rules import get_loader
        loader = get_loader()
        rules = loader.load_rules_from_dir('rust_security')
        assert rules, "Expected Rust security rules to load"
        # After fix: curated rules should have provenance set (not None/empty)
        rules_with_prov = [r for r in rules if getattr(r, 'provenance', None)]
        assert rules_with_prov, (
            f"Rust security rules (curated) must carry a non-empty provenance marker. "
            f"Loaded {len(rules)} rules, none have provenance set."
        )

    def test_attack_signature_rules_have_provenance(self):
        from medusa.rules import get_loader
        loader = get_loader()
        rules = loader.load_rules_from_dir('attack_signatures')
        assert rules, "Expected attack_signatures rules to load"
        rules_with_prov = [r for r in rules if getattr(r, 'provenance', None)]
        assert rules_with_prov, (
            f"attack_signatures rules (curated) must carry a non-empty provenance marker. "
            f"Loaded {len(rules)} rules, none have provenance set."
        )


class TestHarvestedRulesCarryProvenanceTag:
    """Bulk-harvested rule files must carry a provenance/source tag distinguishing them."""

    def test_agentic_exploitation_harvest_rules_have_provenance(self):
        """agentic_exploitation/ has source: paper-harvest-2026 in its YAML metadata.
        After the fix, rules loaded from it should expose provenance='harvested' (or similar)."""
        from medusa.rules import get_loader
        loader = get_loader()
        rules = loader.load_rules_from_dir('agentic_exploitation')
        if not rules:
            pytest.skip("agentic_exploitation rules not loaded — skipping")
        rules_with_prov = [r for r in rules if getattr(r, 'provenance', None)]
        assert rules_with_prov, (
            f"agentic_exploitation rules (harvested, source: paper-harvest-2026) must carry "
            f"a provenance marker. Loaded {len(rules)} rules, none have provenance set."
        )

    def test_provenance_distinguishes_curated_from_harvested(self):
        """Curated and harvested rules should have DIFFERENT provenance values."""
        from medusa.rules import get_loader
        loader = get_loader()

        curated = loader.load_rules_from_dir('rust_security')
        harvested = loader.load_rules_from_dir('agentic_exploitation')

        if not curated or not harvested:
            pytest.skip("Need both rust_security and agentic_exploitation rules for this check")

        curated_provs = {getattr(r, 'provenance', None) for r in curated}
        harvested_provs = {getattr(r, 'provenance', None) for r in harvested}

        # Remove None/empty — only compare populated values
        curated_provs.discard(None)
        curated_provs.discard('')
        harvested_provs.discard(None)
        harvested_provs.discard('')

        if not curated_provs or not harvested_provs:
            pytest.fail(
                "Both curated (rust_security) and harvested (agentic_exploitation) rules must "
                "have non-empty provenance markers for this check to be meaningful."
            )

        # They must not be identical (if they are, the tagging isn't distinguishing)
        assert curated_provs != harvested_provs, (
            f"Curated rules have provenance {curated_provs} and harvested rules have "
            f"{harvested_provs} — these should be DIFFERENT values to be distinguishable."
        )
