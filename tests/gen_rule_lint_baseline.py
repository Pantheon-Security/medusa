#!/usr/bin/env python3
"""Regenerate the PR-015 corpus-lint baseline (tests/rule_lint_baseline.json).

Run this ONLY as a deliberate, reviewed action after an intentional corpus
change legitimately adds/removes grandfathered violations. The pytest gate
(tests/test_rule_corpus_lint.py) fails on any NEW violation not in the baseline;
regenerating silently would defeat it, so this is a separate explicit script,
never invoked from a test.

    python3 tests/gen_rule_lint_baseline.py
"""
import collections
import json
from pathlib import Path

from medusa.core import rule_lint
from medusa.rules import RuleLoader

BASELINE = Path(__file__).parent / "rule_lint_baseline.json"


def main() -> None:
    rules = RuleLoader().load_all_rules()
    findings = rule_lint.corpus_findings(rules)
    by_check = collections.defaultdict(set)
    for rule_id, check, _detail in findings:
        by_check[check].add(rule_id)

    baseline = {check: sorted(ids) for check, ids in sorted(by_check.items())}
    baseline["_meta"] = {
        "description": (
            "PR-015 grandfathered corpus-lint violations. The gate fails only on "
            "NEW rule IDs not listed here. Do NOT hand-edit; regenerate via "
            "tests/gen_rule_lint_baseline.py after an intentional corpus change."
        ),
        "counts": {k: len(v) for k, v in baseline.items()},
    }
    with BASELINE.open("w") as f:
        json.dump(baseline, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"wrote {BASELINE} — counts: {baseline['_meta']['counts']}")


if __name__ == "__main__":
    main()
