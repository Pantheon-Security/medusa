#!/usr/bin/env python3
"""
MEDUSA AI Security Rules Package

Provides centralized rule loading and pattern matching for AI security scanning.
Rules are defined in YAML format in the following directories:
- ai_security/: Prompt injection, jailbreaking, backdoors, supply chain
- agent_security/: Tool attacks, multi-agent, excessive agency
- rag_security/: Knowledge poisoning
- training_security/: Data poisoning
- compliance/: OWASP LLM 2025 mappings
"""

import logging
from bisect import bisect_left
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import re
import yaml
from dataclasses import dataclass, field
from enum import Enum

# CR-050 (resolved 2026.7.0): the two bundled patterns that emitted Python's
# "Possible nested set" FutureWarning (MEDUSA-PRIV-SCAN-1514, MEDUSA-PIA-SCAN-2531)
# were malformed-by-harvest and have been repaired (disjoint char classes). The
# blanket filterwarnings() suppression that used to live here is gone — if a new
# rule reintroduces a nested-set pattern, the FutureWarning now surfaces (and
# tests/test_rule_redos.py / the __post_init__ lint below flag it at compile).

_log = logging.getLogger(__name__)

# PR-005: prefer the libyaml-backed C parser when the build has it (~8x faster on
# the rule corpus: ~28s -> ~3.5s for one full pass). Silent fallback to the pure
# -python SafeLoader when libyaml is absent — no hard dependency is introduced.
# Both are the *safe* subset (no arbitrary object construction), so this is a
# pure speed change with identical parse semantics for rule files.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# Import integrity scanner for self-protection
try:
    from medusa.core.rule_integrity import check_rule_integrity, RuleIntegrityScanner
    _INTEGRITY_AVAILABLE = True
except ImportError:
    _INTEGRITY_AVAILABLE = False


class RuleSeverity(Enum):
    """Rule severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    """A single security rule"""
    id: str
    name: str
    severity: RuleSeverity
    category: str
    patterns: List[str]
    message: str
    description: str = ""
    owasp_llm: Optional[str] = None
    mitre_atlas: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    attack_success_rate: Optional[float] = None
    source_paper: Optional[str] = None
    source_cve: Optional[str] = None
    fix: Optional[str] = None
    # P2-3: remediation text surfaced on findings. Sourced from the rule's
    # `remediation:` field if present, otherwise falls back to `fix:` at scan
    # time. Kept as a distinct field so the scanner lane can read a stable name.
    remediation: Optional[str] = None
    # P2-7: provenance marker — 'curated' (hand-written, versioned rule sets like
    # rust_security/php_security/attack_signatures) vs 'harvested' (bulk paper/
    # extraction harvests). Derived by the loader from file/dir conventions when
    # not set explicitly on the rule.
    provenance: Optional[str] = None
    # PR-014: FP levers the harvest pipeline emits but the loader used to discard.
    # `pipeline_confidence` is the harvester's self-assessed precision for the
    # rule ('high'/'medium'/'low'); a 'low' rule is screening-only (see
    # is_screening_only() below), composing with the PR-013 provenance gate.
    # Missing = NEUTRAL — never inferred. `fp_guards` are benign example strings
    # the rule must NOT flag; carried for future FP-filter use, parsed here so the
    # metadata is no longer thrown away.
    pipeline_confidence: Optional[str] = None
    fp_guards: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    file_types: List[str] = field(default_factory=list)

    # Compiled regex patterns
    _compiled_patterns: List[re.Pattern] = field(default_factory=list, repr=False)
    _compiled_file_globs: List[str] = field(default_factory=list, repr=False)

    def __post_init__(self):
        """Compile regex patterns after initialization"""
        self._compiled_patterns = []
        for pattern in self.patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
            except re.error as e:
                _log.warning("Invalid regex pattern in rule %s (pattern skipped): %s — %s", self.id, pattern, e)
                continue
            # CR-050 follow-up: cheap static ReDoS/nested-set smell check. DEBUG-only
            # (silent on normal scans), so a misbehaving pattern is greppable in -v
            # logs without the per-search cost. See medusa/core/rule_lint.py.
            if _log.isEnabledFor(logging.DEBUG):
                from medusa.core import rule_lint
                smells = rule_lint.static_findings(pattern)
                if smells:
                    _log.debug("Lint smell %s in rule %s: %s", smells, self.id, pattern)
        # Normalize file_types globs for matching
        self._compiled_file_globs = []
        for ft in self.file_types:
            # Normalize: "*.py" → ".py", ".py" → ".py", "py" → ".py"
            if ft.startswith('*.'):
                self._compiled_file_globs.append(ft[1:])  # "*.py" → ".py"
            elif ft.startswith('.'):
                self._compiled_file_globs.append(ft)
            else:
                self._compiled_file_globs.append(f'.{ft}')

    def matches_file_type(self, file_path: str) -> bool:
        """Check if this rule should apply to the given file type."""
        if not self._compiled_file_globs:
            return True  # No restriction = matches all files
        file_lower = file_path.lower()
        return any(file_lower.endswith(g) for g in self._compiled_file_globs)

    def matches(self, content: str) -> List[re.Match]:
        """Check if content matches any rule patterns"""
        matches = []
        for compiled in self._compiled_patterns:
            for match in compiled.finditer(content):
                matches.append(match)
        return matches


def is_screening_only(rule) -> bool:
    """True if a rule should run ONLY in screening/vet/--all-rules mode.

    The single predicate behind the PR-013 provenance gate and its PR-014
    extension, so the loader owns the policy and the scanner just consumes it:

    - PR-013: harvested-provenance rules (bulk keyword greps that mention-match
      normal code) are screening-only.
    - PR-014: rules whose pipeline_confidence is 'low' are screening-only too —
      the harvester's own low-precision self-assessment composes with provenance.

    Missing confidence is NEUTRAL (never gated on that basis alone). Uses getattr
    so a lightweight stand-in object with only `provenance` (as in the PR-013
    invariant tests) still works without a pipeline_confidence attribute.
    """
    if getattr(rule, 'provenance', None) == 'harvested':
        return True
    conf = getattr(rule, 'pipeline_confidence', None)
    if conf is not None and str(conf).strip().lower() == 'low':
        return True
    return False


@dataclass
class RuleMatch:
    """A match found by a rule"""
    rule: Rule
    match: re.Match
    line_number: int
    line_content: str
    context_before: str = ""
    context_after: str = ""


class RuleLoader:
    """
    Loads and manages MEDUSA AI security rules from YAML files.

    Usage:
        loader = RuleLoader()
        rules = loader.load_all_rules()

        # Or load specific categories
        pi_rules = loader.load_rules_from_dir('ai_security')

        # Match content against rules
        matches = loader.match_content(content, rules)
    """

    # Default rules directory (relative to this file)
    RULES_DIR = Path(__file__).parent

    # P2-7: directories whose rules are hand-written/curated (versioned, with
    # fix: fields). Everything else defaults to harvested unless the filename
    # markers below say otherwise.
    _CURATED_DIRS = frozenset({
        'rust_security', 'php_security', 'attack_signatures',
        'cve', 'claude_code', 'web_security', 'code_gen_security',
    })
    # Filename substrings that mark bulk-harvested / auto-expanded rule files.
    _HARVEST_MARKERS = ('_harvest', '_extract_max', '_scanner_expansion', '_expansion')

    def __init__(self, rules_dir: Optional[Path] = None, skip_integrity_check: bool = False):
        """
        Initialize rule loader.

        Args:
            rules_dir: Optional custom rules directory
            skip_integrity_check: Skip integrity scan (use with caution)
        """
        self.rules_dir = rules_dir or self.RULES_DIR
        self._rules_cache: Dict[str, List[Rule]] = {}
        self._rules_by_id: Dict[str, Rule] = {}
        self._rules_by_id_src: Optional[List[Rule]] = None
        # P3-4: category -> rules index, built once from load_all_rules() and
        # reused by every RuleBasedScanner instead of each one re-walking all
        # ~42k rules to extract its categories. Rebuilt only when the underlying
        # rule list object changes (same invalidation idiom as _rules_by_id).
        self._rules_by_category: Dict[str, List[Rule]] = {}
        self._rules_by_category_src: Optional[List[Rule]] = None
        self._integrity_verified = False
        self._skip_integrity = skip_integrity_check

    def load_all_rules(self, force_reload: bool = False) -> List[Rule]:
        """
        Load all rules from all subdirectories.

        Args:
            force_reload: Force reload from disk even if cached

        Returns:
            List of all loaded rules
        """
        if not force_reload and 'all' in self._rules_cache:
            return self._rules_cache['all']

        # PR-004: reuse the parsed corpus across processes/instances before doing
        # any expensive work. The shared cache (in-process dict + HMAC-verified
        # disk pickle) is keyed on a stat fingerprint of the rule files and is
        # INDEPENDENT of the per-file scan-result cache — so a fresh `medusa vet`
        # process (which forces result-caching off to re-scan the target) still
        # skips the ~70s parse+integrity here. A fingerprint match means the rule
        # bytes are unchanged since the cache was built; the integrity scan that
        # gated that build therefore still holds, so we mark it verified and skip
        # the re-scan. Any cache miss falls through to the full cold path below.
        if not force_reload:
            from medusa.core import rule_cache
            cached = rule_cache.load(self.rules_dir)
            if cached is not None:
                self._rules_cache['all'] = cached
                self._integrity_verified = True
                return cached

        # Run integrity check before loading (prompt-in-a-prompt protection)
        if not self._skip_integrity and not self._integrity_verified:
            self._verify_rule_integrity()

        all_rules = []

        # Discover all rule subdirectories dynamically
        skip_dirs = {'__pycache__', 'archive', 'runtime'}
        subdirs = sorted(
            d.name for d in self.rules_dir.iterdir()
            if d.is_dir() and d.name not in skip_dirs
        )
        # Append runtime last. The free product ships no runtime rules and no
        # rules/runtime/ directory (runtime scanning belongs to the separate
        # hosted service). The loader still checks for the directory so it is a
        # harmless no-op when absent — it simply contributes no rules.
        subdirs.append('runtime')

        seen_ids: set = set()
        for subdir in subdirs:
            for rule in self.load_rules_from_dir(subdir, force_reload):
                if rule.id not in seen_ids:
                    seen_ids.add(rule.id)
                    all_rules.append(rule)

        self._rules_cache['all'] = all_rules
        # PR-004: publish the freshly-parsed corpus to the shared cache. Persist
        # to disk ONLY when the integrity scan actually ran for this build — an
        # unvetted parse (skip_integrity_check=True) is kept in-process only, so a
        # later vet can never load a disk blob that skips integrity against rules
        # this process never verified.
        from medusa.core import rule_cache
        rule_cache.store(
            self.rules_dir,
            all_rules,
            persist=self._integrity_verified and not self._skip_integrity,
        )
        return all_rules

    def load_rules_from_dir(self, subdir: str, force_reload: bool = False) -> List[Rule]:
        """
        Load rules from a specific subdirectory.

        Args:
            subdir: Subdirectory name (e.g., 'ai_security')
            force_reload: Force reload from disk

        Returns:
            List of rules from that directory
        """
        if not force_reload and subdir in self._rules_cache:
            return self._rules_cache[subdir]

        rules = []
        dir_path = self.rules_dir / subdir

        if not dir_path.exists():
            return rules

        for yaml_file in dir_path.glob('*.yaml'):
            file_rules = self.load_rules_from_file(yaml_file)
            rules.extend(file_rules)

        self._rules_cache[subdir] = rules
        return rules

    def _derive_provenance(self, filepath: Path, file_source: Optional[str]) -> str:
        """Classify a rule file as 'curated' or 'harvested' (P2-7).

        Precedence:
        1. Explicit file-level metadata.source naming a harvest/extraction.
        2. Filename markers (_harvest, _extract_max, _scanner_expansion).
        3. Curated directory allowlist.
        4. Default to 'harvested' (bulk pattern sets are the common case).
        """
        name = filepath.name.lower()
        if file_source:
            src = str(file_source).lower()
            if any(m in src for m in ('harvest', 'extract', 'expansion', 'paper-')):
                return 'harvested'
        if any(marker in name for marker in self._HARVEST_MARKERS):
            return 'harvested'
        # Directory-based curated classification
        parent = filepath.parent.name
        if parent in self._CURATED_DIRS:
            return 'curated'
        return 'harvested'

    def _verify_rule_integrity(self) -> None:
        """
        Verify rule files haven't been tampered with (prompt-in-a-prompt protection).

        This scans rule YAML files with hardcoded patterns BEFORE loading them.
        Prevents attackers from embedding malicious content in rule files.
        """
        if not _INTEGRITY_AVAILABLE:
            # Integrity scanner not available - continue without check
            self._integrity_verified = True
            return

        try:
            scanner = RuleIntegrityScanner(self.rules_dir)
            is_clean, violations = scanner.verify_integrity(max_retries=1)

            if is_clean:
                self._integrity_verified = True
            else:
                critical = [v for v in violations if v.severity == "CRITICAL"]
                if critical:
                    print(f"ERROR: {len(critical)} CRITICAL integrity violations in rule files — aborting rule load")
                    for v in critical[:5]:
                        print(f"  - {v.file}:{v.line_number} [{v.pattern_name}]")
                    raise RuntimeError(
                        f"Rule integrity check failed: {len(critical)} CRITICAL violations detected. "
                        "Rule files may have been tampered with."
                    )
                # Non-critical violations: warn and continue
                print(f"WARNING: {len(violations)} non-critical integrity violations in rule files")
                self._integrity_verified = True

        except RuntimeError:
            raise  # CRITICAL tamper detection — do not suppress
        except Exception as e:
            # Don't block on import errors or non-critical check failures
            print(f"Warning: Rule integrity check failed: {e}")
            self._integrity_verified = True

    def load_rules_from_file(self, filepath: Path) -> List[Rule]:
        """
        Load rules from a single YAML file.

        Supports multiple YAML formats:
        1. Standard: rules: [...]
        2. Root list: - id: ... (rules at document root)
        3. Category groups: category_name: [...] (rules grouped by category)

        Args:
            filepath: Path to YAML file

        Returns:
            List of rules from the file
        """
        rules = []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.load(f, Loader=_YAML_LOADER)
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Failed to load rules from {filepath}: {e}")
            return rules

        if not data:
            return rules

        # P2-7: determine provenance for every rule in this file. Honor an
        # explicit file-level metadata.source, then fall back to filename/dir
        # conventions.
        file_source = None
        if isinstance(data, dict):
            meta = data.get('metadata')
            if isinstance(meta, dict):
                file_source = meta.get('source')
            if file_source is None:
                file_source = data.get('source')
        default_provenance = self._derive_provenance(filepath, file_source)

        rules_data = []

        # Format 1: Standard format with 'rules:' key
        if isinstance(data, dict) and 'rules' in data:
            rules_data = data.get('rules', [])

        # Format 2: Root-level list (rules directly at document root)
        elif isinstance(data, list):
            rules_data = data

        # Format 3: Single rule as flat dict (id: at top level)
        elif isinstance(data, dict) and 'id' in data and ('patterns' in data or 'pattern' in data):
            rules_data = [data]

        # Format 4: Category groups (e.g., jailbreak: [...], exfiltration: [...])
        elif isinstance(data, dict):
            # Skip known metadata keys
            skip_keys = {'version', 'metadata', 'categories', 'ruleset',
                         'source_count', 'extraction_date', 'session_id', 'queries'}

            for key, value in data.items():
                if key in skip_keys:
                    continue
                # If value is a list of dicts with 'id' field, treat as rules
                if isinstance(value, list) and value:
                    if isinstance(value[0], dict) and 'id' in value[0]:
                        rules_data.extend(value)

        # Parse all collected rules
        for rule_data in rules_data:
            try:
                rule = self._parse_rule(rule_data, default_provenance=default_provenance)
                if rule:
                    rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to parse rule in {filepath}: {e}")

        return rules

    def _parse_rule(self, data: Dict[str, Any], default_provenance: Optional[str] = None) -> Optional[Rule]:
        """Parse a single rule from dictionary data.

        Handles field variations:
        - pattern/patterns (singular or plural)
        - owasp/owasp_llm (short or full name)
        - Generates default message if missing
        """
        # Must have at least id and patterns
        if 'id' not in data:
            return None

        # Handle pattern/patterns field variations
        patterns = data.get('patterns') or data.get('pattern')
        if not patterns:
            return None

        if isinstance(patterns, str):
            patterns = [patterns]

        # Handle dict-style patterns: [{regex: "...", description: "..."}]
        # Also handle runtime-style patterns: {request: [...], response: [...]}
        if isinstance(patterns, dict):
            # Runtime/proxy-style: extract inner pattern strings
            flat = []
            for key, val in patterns.items():
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            # {pattern: "...", location: "body"} or {regex: "..."}
                            p = item.get('regex') or item.get('pattern')
                            if p and isinstance(p, str):
                                flat.append(p)
                        elif isinstance(item, str):
                            flat.append(item)
                elif isinstance(val, str):
                    flat.append(val)
            patterns = flat
        else:
            patterns = [p['regex'] if isinstance(p, dict) and 'regex' in p else p
                        for p in patterns if isinstance(p, (str, dict))]
            patterns = [p for p in patterns if isinstance(p, str)]
        if not patterns:
            return None

        # Parse severity (default to MEDIUM if missing)
        severity_str = str(data.get('severity', 'MEDIUM')).upper()
        try:
            severity = RuleSeverity(severity_str)
        except ValueError:
            severity = RuleSeverity.MEDIUM

        # Generate default name if missing
        name = data.get('name', data['id'])

        # Generate default message if missing
        message = data.get('message', f"Security issue detected: {name}")

        # Parse references
        references = data.get('references', [])
        if isinstance(references, str):
            references = [references]

        # Handle owasp/owasp_llm variations
        owasp_llm = data.get('owasp_llm') or data.get('owasp')

        # Parse file_types (e.g., ['*.py', '*.js'])
        file_types = data.get('file_types') or data.get('file_type') or []
        if isinstance(file_types, str):
            file_types = [file_types]

        # PR-014: carry the harvest pipeline's FP metadata onto the rule instead
        # of discarding it. Keep pipeline_confidence as the raw string (normalized
        # only at the gate) so we never invent a value for rules lacking it.
        pipeline_confidence = data.get('pipeline_confidence')
        if pipeline_confidence is not None:
            pipeline_confidence = str(pipeline_confidence)
        fp_guards = data.get('fp_guards') or []
        if isinstance(fp_guards, str):
            fp_guards = [fp_guards]
        elif not isinstance(fp_guards, list):
            fp_guards = [str(fp_guards)]
        else:
            fp_guards = [str(g) for g in fp_guards]

        return Rule(
            id=data['id'],
            name=name,
            severity=severity,
            category=data.get('category', 'unknown'),
            patterns=patterns,
            message=message,
            description=data.get('description', ''),
            owasp_llm=owasp_llm,
            mitre_atlas=data.get('mitre_atlas'),
            cwe=data.get('cwe'),
            cvss=data.get('cvss'),
            attack_success_rate=data.get('attack_success_rate'),
            source_paper=data.get('source_paper'),
            source_cve=data.get('source_cve'),
            fix=data.get('fix'),
            # P2-3: prefer an explicit remediation, else reuse fix as remediation.
            remediation=data.get('remediation') or data.get('fix'),
            # P2-7: explicit rule-level provenance wins over the file default.
            provenance=data.get('provenance') or default_provenance,
            pipeline_confidence=pipeline_confidence,
            fp_guards=fp_guards,
            references=references,
            file_types=file_types,
        )

    def match_content(self, content: str, rules: Optional[List[Rule]] = None) -> List[RuleMatch]:
        """
        Match content against rules.

        Args:
            content: Text content to scan
            rules: Rules to match against (defaults to all rules)

        Returns:
            List of RuleMatch objects for all matches found
        """
        if rules is None:
            rules = self.load_all_rules()

        matches = []
        lines = content.split('\n')
        # Precompute newline offsets once: line number via bisect is O(log n)
        # per match instead of O(pos) re-scanning the prefix for every match.
        _nl_offsets = [i for i, c in enumerate(content) if c == '\n']

        for rule in rules:
            rule_matches = rule.matches(content)

            for match in rule_matches:
                # Find line number
                start_pos = match.start()
                line_num = bisect_left(_nl_offsets, start_pos) + 1

                # Get line content
                if 0 < line_num <= len(lines):
                    line_content = lines[line_num - 1]
                else:
                    line_content = match.group(0)

                # Get context (2 lines before/after)
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 2)
                context_before = '\n'.join(lines[start_line:line_num - 1])
                context_after = '\n'.join(lines[line_num:end_line])

                matches.append(RuleMatch(
                    rule=rule,
                    match=match,
                    line_number=line_num,
                    line_content=line_content,
                    context_before=context_before,
                    context_after=context_after,
                ))

        return matches

    def _ensure_category_index(self) -> Dict[str, List[Rule]]:
        """Build (once) and return the category -> rules index.

        P3-4: each RuleBasedScanner used to call load_all_rules() and re-walk the
        full ~42k-rule list to pull out the few categories it cares about. That is
        O(rules) per scanner. Building the index once and slicing it is O(1) per
        category lookup thereafter. Invalidated only when the underlying rule list
        object is replaced (e.g. force_reload), matching the _rules_by_id idiom.
        """
        all_rules = self.load_all_rules()
        if self._rules_by_category_src is not all_rules:
            index: Dict[str, List[Rule]] = {}
            for rule in all_rules:
                index.setdefault(rule.category, []).append(rule)
            self._rules_by_category = index
            self._rules_by_category_src = all_rules
        return self._rules_by_category

    def get_rules_by_category(self, category: str) -> List[Rule]:
        """Get rules filtered by category (O(1) via the cached category index).

        Returns the loader's own list for the category; callers that mutate the
        result should copy it first.
        """
        return self._ensure_category_index().get(category, [])

    def get_rules_for_categories(self, categories) -> List[Rule]:
        """Get all rules belonging to any of the given categories (P3-4).

        Convenience for scanners that select several categories at once. Preserves
        rule order within each category and de-duplicates rules that somehow live
        under more than one requested category lookup. Uses the cached index so it
        does not re-walk the full rule list per scanner.
        """
        index = self._ensure_category_index()
        result: List[Rule] = []
        seen_ids: Set[str] = set()
        for category in categories:
            for rule in index.get(category, []):
                if rule.id not in seen_ids:
                    seen_ids.add(rule.id)
                    result.append(rule)
        return result

    def get_rules_by_severity(self, severity: RuleSeverity) -> List[Rule]:
        """Get rules filtered by severity"""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.severity == severity]

    def get_rules_by_owasp(self, owasp_id: str) -> List[Rule]:
        """Get rules mapped to a specific OWASP LLM Top 10 category"""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.owasp_llm == owasp_id]

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID (O(1) via an index rebuilt only when the
        underlying rule list changes)."""
        all_rules = self.load_all_rules()
        if self._rules_by_id_src is not all_rules:
            self._rules_by_id = {r.id: r for r in all_rules}
            self._rules_by_id_src = all_rules
        return self._rules_by_id.get(rule_id)

    def get_categories(self) -> Set[str]:
        """Get all unique categories (keys of the cached category index)."""
        return set(self._ensure_category_index().keys())

    def get_provenance_map(self) -> Dict[str, int]:
        """Return a count of loaded rules by provenance (P2-7).

        Keys are provenance markers ('curated', 'harvested', or '' when a rule
        carries no marker). Lets callers/UX distinguish vetted from bulk-harvested
        rules and report the split.
        """
        all_rules = self.load_all_rules()
        counts: Dict[str, int] = {}
        for rule in all_rules:
            key = rule.provenance or ''
            counts[key] = counts.get(key, 0) + 1
        return counts

    def get_rules_by_provenance(self, provenance: str) -> List[Rule]:
        """Get rules filtered by provenance marker (e.g. 'curated', 'harvested')."""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.provenance == provenance]

    def get_stats(self) -> Dict[str, Any]:
        """Get rule statistics"""
        all_rules = self.load_all_rules()

        severity_counts = {}
        for severity in RuleSeverity:
            severity_counts[severity.value] = len([r for r in all_rules if r.severity == severity])

        owasp_counts = {}
        for rule in all_rules:
            if rule.owasp_llm:
                # owasp_llm is typed Optional[str], but some rules supply a list
                # (YAML `owasp: [LLM01, LLM02]`). Normalize to individual keys so
                # we never use an unhashable list as a dict key.
                owasp_values = rule.owasp_llm if isinstance(rule.owasp_llm, list) else [rule.owasp_llm]
                for owasp_value in owasp_values:
                    owasp_counts[owasp_value] = owasp_counts.get(owasp_value, 0) + 1

        return {
            'total_rules': len(all_rules),
            'by_severity': severity_counts,
            'by_owasp': owasp_counts,
            'categories': list(self.get_categories()),
        }


# Singleton instance for convenience
_loader_instance: Optional[RuleLoader] = None


def get_loader() -> RuleLoader:
    """Get the singleton RuleLoader instance"""
    global _loader_instance
    if _loader_instance is None:
        _loader_instance = RuleLoader()
    return _loader_instance


def load_all_rules() -> List[Rule]:
    """Convenience function to load all rules"""
    return get_loader().load_all_rules()


def match_content(content: str, rules: Optional[List[Rule]] = None) -> List[RuleMatch]:
    """Convenience function to match content against rules"""
    return get_loader().match_content(content, rules)


def get_stats() -> Dict[str, Any]:
    """Convenience function to get rule statistics"""
    return get_loader().get_stats()
