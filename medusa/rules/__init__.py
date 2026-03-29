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

from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import re
import yaml
from dataclasses import dataclass, field
from enum import Enum

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
                print(f"Warning: Invalid regex pattern in rule {self.id}: {pattern} - {e}")
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

    def __init__(self, rules_dir: Optional[Path] = None, skip_integrity_check: bool = False):
        """
        Initialize rule loader.

        Args:
            rules_dir: Optional custom rules directory
            skip_integrity_check: Skip integrity scan (use with caution)
        """
        self.rules_dir = rules_dir or self.RULES_DIR
        self._rules_cache: Dict[str, List[Rule]] = {}
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
        # Run integrity check before loading (prompt-in-a-prompt protection)
        if not self._skip_integrity and not self._integrity_verified:
            self._verify_rule_integrity()

        if not force_reload and 'all' in self._rules_cache:
            return self._rules_cache['all']

        all_rules = []

        # Discover all rule subdirectories dynamically
        skip_dirs = {'__pycache__', 'archive', 'runtime'}
        subdirs = sorted(
            d.name for d in self.rules_dir.iterdir()
            if d.is_dir() and d.name not in skip_dirs
        )
        # Always append runtime last (requires license check)
        subdirs.append('runtime')

        seen_ids: set = set()
        for subdir in subdirs:
            for rule in self.load_rules_from_dir(subdir, force_reload):
                if rule.id not in seen_ids:
                    seen_ids.add(rule.id)
                    all_rules.append(rule)

        self._rules_cache['all'] = all_rules
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
        # Runtime rules require a paid license
        if subdir == 'runtime':
            try:
                from medusa.core.licensing import can_use_runtime_filters
                if not can_use_runtime_filters():
                    return []
            except ImportError:
                return []  # Licensing module not available — skip runtime rules

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

        except Exception as e:
            # Don't block on integrity check failures
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
        # Runtime rule files require a paid license
        if '_runtime' in filepath.name or filepath.parent.name == 'runtime':
            try:
                from medusa.core.licensing import can_use_runtime_filters
                if not can_use_runtime_filters():
                    return []
            except ImportError:
                return []  # Licensing module not available — skip runtime rules

        rules = []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Failed to load rules from {filepath}: {e}")
            return rules

        if not data:
            return rules

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
                rule = self._parse_rule(rule_data)
                if rule:
                    rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to parse rule in {filepath}: {e}")

        return rules

    def _parse_rule(self, data: Dict[str, Any]) -> Optional[Rule]:
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

        for rule in rules:
            rule_matches = rule.matches(content)

            for match in rule_matches:
                # Find line number
                start_pos = match.start()
                line_num = content[:start_pos].count('\n') + 1

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

    def get_rules_by_category(self, category: str) -> List[Rule]:
        """Get rules filtered by category"""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.category == category]

    def get_rules_by_severity(self, severity: RuleSeverity) -> List[Rule]:
        """Get rules filtered by severity"""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.severity == severity]

    def get_rules_by_owasp(self, owasp_id: str) -> List[Rule]:
        """Get rules mapped to a specific OWASP LLM Top 10 category"""
        all_rules = self.load_all_rules()
        return [r for r in all_rules if r.owasp_llm == owasp_id]

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID"""
        all_rules = self.load_all_rules()
        for rule in all_rules:
            if rule.id == rule_id:
                return rule
        return None

    def get_categories(self) -> Set[str]:
        """Get all unique categories"""
        all_rules = self.load_all_rules()
        return {r.category for r in all_rules}

    def get_stats(self) -> Dict[str, Any]:
        """Get rule statistics"""
        all_rules = self.load_all_rules()

        severity_counts = {}
        for severity in RuleSeverity:
            severity_counts[severity.value] = len([r for r in all_rules if r.severity == severity])

        owasp_counts = {}
        for rule in all_rules:
            if rule.owasp_llm:
                owasp_counts[rule.owasp_llm] = owasp_counts.get(rule.owasp_llm, 0) + 1

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
