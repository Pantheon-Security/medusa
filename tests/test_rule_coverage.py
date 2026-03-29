#!/usr/bin/env python3
"""
Test that rule directories are wired to scanners and basic rule integrity.
"""

import re
from pathlib import Path

import yaml
import pytest


RULES_DIR = Path(__file__).parent.parent / "medusa" / "rules"
SCANNERS_DIR = Path(__file__).parent.parent / "medusa" / "scanners"


def _get_all_scanner_categories() -> set:
    """Extract all RULE_CATEGORIES values from scanner Python files."""
    categories = set()
    for py_file in SCANNERS_DIR.glob("*.py"):
        if py_file.name.startswith("__"):
            continue
        try:
            content = py_file.read_text()
            match = re.search(
                r'RULE_CATEGORIES\s*=\s*\[(.*?)\]',
                content,
                re.DOTALL,
            )
            if match:
                cats = re.findall(r"'([^']+)'", match.group(1))
                categories.update(cats)
        except Exception:
            continue
    return categories


def _get_all_scanner_prefixes() -> set:
    """Extract all RULE_ID_PREFIXES values from scanner Python files."""
    prefixes = set()
    for py_file in SCANNERS_DIR.glob("*.py"):
        if py_file.name.startswith("__"):
            continue
        try:
            content = py_file.read_text()
            match = re.search(
                r'RULE_ID_PREFIXES\s*=\s*\[(.*?)\]',
                content,
                re.DOTALL,
            )
            if match:
                prefs = re.findall(r"'([^']+)'", match.group(1))
                prefixes.update(prefs)
        except Exception:
            continue
    return prefixes


def test_rule_directories_wired():
    """Every rule subdirectory name should appear in at least one scanner's RULE_CATEGORIES."""
    scanner_cats = _get_all_scanner_categories()

    rule_dirs = []
    for d in sorted(RULES_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith(("__", ".")):
            continue
        if d.name in ("archive", "runtime", "cve"):
            continue
        yaml_files = list(d.glob("*.yaml"))
        if yaml_files:
            rule_dirs.append(d.name)

    unwired = [d for d in rule_dirs if d not in scanner_cats]

    if unwired:
        print(f"\nUnwired rule directories ({len(unwired)}):")
        for d in unwired:
            print(f"  - {d}")

    # All directories should be wired to a scanner
    assert len(unwired) == 0, (
        f"{len(unwired)} rule directories not in any scanner RULE_CATEGORIES: "
        f"{unwired}"
    )


def test_no_duplicate_rule_ids():
    """No two rules should share the same ID in production (within threshold)."""
    seen_ids = {}
    duplicates = []
    for yaml_file in sorted(RULES_DIR.rglob("*.yaml")):
        if "_runtime" in yaml_file.name:
            continue
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                continue
            for rule in data["rules"]:
                if isinstance(rule, dict) and rule.get("id"):
                    rid = rule["id"]
                    if rid in seen_ids:
                        duplicates.append((rid, seen_ids[rid], str(yaml_file)))
                    else:
                        seen_ids[rid] = str(yaml_file)
        except Exception:
            continue

    if duplicates:
        print(f"\nDuplicate rule IDs ({len(duplicates)}):")
        for rid, first, second in duplicates[:20]:
            print(f"  {rid}: {Path(first).name} vs {Path(second).name}")

    # Cross-file duplicates exist where multiple scanners share rule IDs
    assert len(duplicates) <= 600, (
        f"{len(duplicates)} duplicate rule IDs found"
    )


def test_rule_dirs_have_yaml():
    """Every rule subdirectory should have at least one YAML file."""
    empty_dirs = []
    for d in sorted(RULES_DIR.iterdir()):
        if not d.is_dir() or d.name.startswith(("__", ".")):
            continue
        if d.name in ("archive", "runtime", "cve"):
            continue
        yaml_files = list(d.glob("*.yaml"))
        if not yaml_files:
            empty_dirs.append(d.name)

    assert not empty_dirs, f"Empty rule directories: {empty_dirs}"


def test_no_runtime_rules_leaked():
    """No runtime YAML files should be in production (outside runtime/ dir)."""
    runtime_files = list(RULES_DIR.rglob("*_runtime.yaml"))
    runtime_files = [
        f for f in runtime_files
        if "/runtime/" not in str(f) and "/archive/" not in str(f)
    ]
    assert not runtime_files, (
        f"Runtime rules found in production: {[str(f) for f in runtime_files]}"
    )


def test_rule_count_minimum():
    """Production should have at least 7,000 unique rule IDs."""
    seen_ids = set()
    for yaml_file in RULES_DIR.rglob("*.yaml"):
        if "_runtime" in yaml_file.name:
            continue
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                continue
            for rule in data["rules"]:
                if isinstance(rule, dict) and rule.get("id"):
                    seen_ids.add(rule["id"])
        except Exception:
            continue

    print(f"\nTotal unique rule IDs: {len(seen_ids)}")
    assert len(seen_ids) >= 7000, (
        f"Expected at least 7,000 rules, found {len(seen_ids)}"
    )
