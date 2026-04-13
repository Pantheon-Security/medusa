#!/usr/bin/env python3
"""
MEDUSA Unclaimed YAML Rule Scanner

Runs YAML rules that are NOT claimed by any dedicated scanner, ensuring they
fire based on file_types matching alone (not scanner confidence gating).

Most YAML rules are loaded by dedicated scanners (ModelAttackScanner loads
MODEL-ATK-* rules, OWASPLLMScanner loads LLM* rules, etc.). But some rules
have categories/prefixes that no scanner claims — they'd never fire without
this catch-all scanner.

This prevents the FP explosion that happens when ALL 9,000+ rules run on
every file, while ensuring orphaned rules still get executed.
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Set

from medusa.scanners.base import (
    RuleBasedScanner, ScannerResult, ScannerIssue, Severity, _SEVERITY_MAP, _CWE_RE,
)


# All code file extensions that YAML rules can target
_CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.rb',
    '.php', '.cs', '.cpp', '.c', '.h', '.hpp', '.swift', '.kt', '.kts',
    '.scala', '.lua', '.ex', '.exs', '.hs', '.clj', '.dart', '.groovy',
    '.pl', '.pm', '.r', '.ps1', '.sh', '.bash', '.bat', '.cmd',
    '.sql', '.graphql', '.gql', '.sol', '.zig', '.vim',
    '.yaml', '.yml', '.json', '.toml', '.xml', '.tf', '.hcl',
    '.dockerfile', '.env', '.ini', '.cfg', '.conf',
    '.md', '.markdown', '.rst', '.txt',
    '.html', '.htm', '.css', '.scss', '.less',
    '.proto', '.cmake', '.makefile', '.mk',
    '.ipynb',
}


def _get_claimed_categories_and_prefixes() -> tuple:
    """Collect all categories and ID prefixes claimed by registered scanners."""
    from medusa.scanners import registry
    claimed_categories: Set[str] = set()
    claimed_prefixes: Set[str] = set()
    for scanner in registry.get_all_scanners():
        if scanner.name == 'YAMLRuleScanner':
            continue
        if hasattr(scanner, 'RULE_CATEGORIES') and scanner.RULE_CATEGORIES:
            claimed_categories.update(scanner.RULE_CATEGORIES)
        if hasattr(scanner, 'RULE_ID_PREFIXES') and scanner.RULE_ID_PREFIXES:
            claimed_prefixes.update(scanner.RULE_ID_PREFIXES)
    return claimed_categories, claimed_prefixes


class YAMLRuleScanner(RuleBasedScanner):
    """
    Catch-all YAML Rule Scanner — runs only UNCLAIMED rules.

    Rules are "claimed" if their category or ID prefix is listed in any
    other scanner's RULE_CATEGORIES or RULE_ID_PREFIXES. Claimed rules
    are executed by their owning scanner (gated by that scanner's
    confidence score). Unclaimed rules run here on every matching file.
    """

    RULE_CATEGORIES = []
    RULE_ID_PREFIXES = []

    def __init__(self):
        super().__init__()
        self._unclaimed_rules = None
        self._unclaimed_loaded = False

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return list(_CODE_EXTENSIONS)

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in _CODE_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: Optional[str] = None) -> int:
        if self.can_scan(file_path):
            return 20
        return 0

    def _load_unclaimed_rules(self):
        """Load only rules not claimed by any other scanner."""
        if self._unclaimed_loaded:
            return

        from medusa.rules import get_loader
        loader = get_loader()
        all_rules = loader.load_all_rules()

        claimed_cats, claimed_prefixes = _get_claimed_categories_and_prefixes()

        self._unclaimed_rules = []
        for rule in all_rules:
            # Skip if category is claimed
            if rule.category in claimed_cats:
                continue
            # Skip if any prefix is claimed
            claimed = False
            for prefix in claimed_prefixes:
                if rule.id.startswith(prefix):
                    claimed = True
                    break
            if not claimed:
                self._unclaimed_rules.append(rule)

        self._unclaimed_loaded = True

    @property
    def unclaimed_rules(self):
        if not self._unclaimed_loaded:
            self._load_unclaimed_rules()
        return self._unclaimed_rules

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan file against unclaimed YAML rules whose file_types match."""
        start_time = time.time()

        try:
            if content is None:
                content = file_path.read_text(encoding='utf-8', errors='replace')
        except (OSError, IOError) as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

        lines = content.split('\n')
        scan_lines = lines[:self.MAX_RULE_SCAN_LINES] if len(lines) > self.MAX_RULE_SCAN_LINES else lines

        file_str = str(file_path)
        applicable_rules = [r for r in self.unclaimed_rules if r.matches_file_type(file_str)]

        issues = []
        seen = set()

        for rule in applicable_rules:
            for i, line in enumerate(scan_lines, 1):
                for compiled in rule._compiled_patterns:
                    try:
                        if compiled.search(line):
                            key = (rule.id, i)
                            if key in seen:
                                break
                            seen.add(key)

                            severity = _SEVERITY_MAP.get(rule.severity.value, Severity.MEDIUM)

                            cwe_id = None
                            cwe_link = None
                            if rule.cwe:
                                cwe_match = _CWE_RE.search(str(rule.cwe))
                                if cwe_match:
                                    cwe_id = int(cwe_match.group(1))
                                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

                            issues.append(ScannerIssue(
                                severity=severity,
                                message=rule.message,
                                line=i,
                                code=line.strip(),
                                rule_id=rule.id,
                                cwe_id=cwe_id,
                                cwe_link=cwe_link,
                                mitre_atlas=rule.mitre_atlas,
                                owasp_llm=rule.owasp_llm,
                            ))
                            break
                    except re.error:
                        continue

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )
