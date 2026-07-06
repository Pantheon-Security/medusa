"""PR-013 security invariant: harvested rules gate on screening mode, and vet ALWAYS
screens (so a future refactor cannot silently drop ~42k rules from pre-install vetting).

Sentinel review (2026-07-06) flagged that the wiring had no direct test: deleting the
`screening=True` at scan_api.vet_path would ship green while reintroducing a 42k-rule
vet false negative. These tests are that guard.
"""
from types import SimpleNamespace
import pytest

from medusa.scanners.base import RuleBasedScanner


def _gate(screening, all_rules, rules):
    """Call the provenance gate with a minimal fake self (avoids loading 42k rules)."""
    fake = SimpleNamespace(_screening=screening, _all_rules_override=all_rules,
                           _provenance_cache=None)
    return RuleBasedScanner._gate_provenance(fake, rules)


_RULES = [SimpleNamespace(provenance='curated'),
          SimpleNamespace(provenance='harvested'),
          SimpleNamespace(provenance=None)]


def test_default_mode_drops_only_harvested():
    provs = [r.provenance for r in _gate(False, False, _RULES)]
    assert 'harvested' not in provs      # gated out on a default self-scan
    assert 'curated' in provs            # curated always runs
    assert None in provs                 # unknown provenance runs (safe direction)


def test_screening_mode_keeps_everything():
    provs = [r.provenance for r in _gate(True, False, _RULES)]
    assert provs == ['curated', 'harvested', None]  # vet/--git/--screening run ALL rules


def test_all_rules_override_keeps_everything():
    provs = [r.provenance for r in _gate(False, True, _RULES)]
    assert 'harvested' in provs          # --all-rules escape hatch runs harvested in normal mode


def test_vet_path_constructs_scanner_with_screening_true(monkeypatch, tmp_path):
    """THE invariant: medusa vet must build its scanner with screening=True so harvested
    malware/poisoning rules run when vetting an untrusted repo. Guards scan_api.py."""
    (tmp_path / "sample.py").write_text("x = 1\n")
    captured = {}
    import medusa.core.parallel as par
    real = par.MedusaParallelScanner

    class _Spy(real):
        def __init__(self, *a, **kw):
            captured['screening'] = kw.get('screening')
            raise RuntimeError("stop-before-scan")  # short-circuit the (slow) scan

    monkeypatch.setattr(par, "MedusaParallelScanner", _Spy)
    from medusa.core.scan_api import vet_path
    try:
        vet_path(str(tmp_path))
    except Exception:
        pass  # we only care that the scanner was asked to screen
    assert captured.get('screening') is True, (
        "vet_path MUST pass screening=True — without it, harvested rules are gated OUT "
        "of pre-install vetting (42k-rule false negative)")


def test_curated_count_floor_guards_misclassification():
    """If a future rename/dir change silently reclassifies curated rules as harvested,
    the default scan would run near-nothing. Pin a floor well below today's 226."""
    from medusa.rules import RuleLoader
    rules = RuleLoader().load_all_rules()
    curated = sum(1 for r in rules if getattr(r, 'provenance', None) == 'curated')
    assert curated >= 150, f"curated rule count fell to {curated} (was ~226) — provenance misclassification?"
