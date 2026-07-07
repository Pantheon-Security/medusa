"""Gate: yaml.load with an explicit safe Loader= must NOT be flagged CRITICAL.

Regression for the self-scan FP introduced when the rule loader moved to
`yaml.load(f, Loader=CSafeLoader)` (PR-005 perf): WEB-DESER-002 and
MEDUSA-CODEGEN-SCAN-005 fired on that *safe* call because their lookahead only
recognised a hard-coded `yaml.SafeLoader`, not a variable or CSafeLoader.

Two-sided: the safe forms stop firing; the genuinely-unsafe bare `yaml.load(x)`
(and `yaml.unsafe_load`) still fire — the real CWE-502 signal is preserved.
"""
import re
import yaml as _yaml
from pathlib import Path

import pytest

RULES = Path(__file__).resolve().parent.parent / "medusa" / "rules"
WEB = RULES / "web_security" / "python_web_security.yaml"
CGS = RULES / "code_gen_security" / "code_gen_security_2025_scanner.yaml"

# What the safe rule-loader call and common user idioms look like:
SAFE_LINES = [
    "data = yaml.load(f, Loader=_YAML_LOADER)",       # the variable case (our loader)
    "data = yaml.load(f, Loader=yaml.CSafeLoader)",   # libyaml safe loader
    "data = yaml.load(f, Loader=yaml.SafeLoader)",    # canonical safe
    "cfg = yaml.load(text, Loader=SafeLoader)",        # imported-name safe
]
# What must STILL be caught (no safe loader chosen):
UNSAFE_LINES = [
    "data = yaml.load(untrusted_input)",              # bare -> defaults unsafe
    "obj = yaml.load(request.body)",
    "x = yaml.unsafe_load(payload)",                  # always unsafe
]


def _patterns_for(path, rule_id):
    docs = _yaml.safe_load(path.read_text())
    rules = docs if isinstance(docs, list) else docs.get("rules", docs)
    for r in rules:
        if r.get("id") == rule_id:
            return [re.compile(p) for p in r["patterns"]]
    raise AssertionError(f"{rule_id} not found in {path.name}")


@pytest.mark.parametrize("path,rule_id", [(WEB, "WEB-DESER-002"),
                                          (CGS, "MEDUSA-CODEGEN-SCAN-005")])
def test_safe_yaml_load_does_not_fire(path, rule_id):
    pats = _patterns_for(path, rule_id)
    for line in SAFE_LINES:
        assert not any(p.search(line) for p in pats), (
            f"{rule_id} FP: flagged safe {line!r}")


@pytest.mark.parametrize("path,rule_id", [(WEB, "WEB-DESER-002"),
                                          (CGS, "MEDUSA-CODEGEN-SCAN-005")])
def test_unsafe_yaml_load_still_fires(path, rule_id):
    pats = _patterns_for(path, rule_id)
    # bare yaml.load and unsafe_load must each be caught by at least one pattern
    for line in UNSAFE_LINES:
        if "unsafe_load" in line and rule_id == "MEDUSA-CODEGEN-SCAN-005":
            continue  # that rule targets load()/pickle, not unsafe_load specifically
        assert any(p.search(line) for p in pats), (
            f"{rule_id} MISS: failed to flag unsafe {line!r}")
