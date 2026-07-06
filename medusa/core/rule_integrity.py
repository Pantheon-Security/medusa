#!/usr/bin/env python3
"""
MEDUSA Rule Integrity Scanner

Self-scan protection against "prompt-in-a-prompt" attacks.
Scans rule YAML files BEFORE loading them to detect embedded malicious content.

IMPORTANT: Patterns in this file are HARDCODED, not loaded from YAML.
This prevents attackers from disabling detection by modifying rule files.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

import yaml

# PR-005: libyaml-backed parser when available (silent fallback to the pure
# -python SafeLoader). The integrity scan parses every rule file too, so it
# gets the same ~8x parse speedup. Same safe-subset semantics.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


# Field names whose scalar values are regex detection data, glob lists, or
# bounded structured metadata — never a prompt-injection vector, so they are not
# scanned. Everything NOT in this set (description, message, remediation, notes,
# and any unknown field) IS scanned with the full integrity pattern set.
SAFE_VALUE_FIELDS = frozenset({
    # regex / detection data (across the various rule-file schemas)
    "patterns", "pattern", "regex", "file_types", "file_type",
    "detection_patterns", "detection", "signatures", "signature", "indicators",
    # structured identifiers / taxonomy
    "id", "name", "severity", "category", "action", "direction",
    "cwe", "owasp_llm", "owasp", "mitre_atlas", "mitre_attack", "mitre",
    "confidence", "pipeline_confidence",
    # provenance / harvest metadata (legitimately cite attack-paper titles)
    "source_paper", "source_detail", "source", "version", "generated",
    "papers_processed", "relevant_papers",
})

# Prose fields whose whole job is to DESCRIBE attacks. They legitimately contain
# attack topic words ("ignore previous instructions", "DAN", "eval(") — so these
# are scanned only for MECHANICAL injection-delivery markers (below), never for
# topic mentions. A field NOT listed here and NOT in SAFE_VALUE_FIELDS (e.g.
# ``notes``, ``comment``, or any unexpected key a poisoned rule introduces) is
# scanned with the FULL pattern set, since there is no legitimate reason for
# attack content to live there.
PROSE_DESCRIPTION_FIELDS = frozenset({
    "description", "message", "summary", "remediation", "fix", "suggestion",
    "technique", "attack_vector", "attack_framework", "attack_type",
    "references", "reference", "notes_detail",
    "examples", "example", "attack_examples", "attack_example",
    "payloads", "payload", "fp_guards", "fp_guard",
    "false_positives", "false_positive",
})

# Injection-DELIVERY mechanics that have no legitimate place even inside an
# attack description: a real description never contains a null byte, a unicode
# direction-override, or actual conversation-turn delimiters. These remain
# abort-worthy in every non-safe field, including prose description fields.
MECHANICAL_PATTERN_NAMES = frozenset({
    "null_byte",
    "unicode_direction_override",
    "claude_turn_injection",
})


@dataclass
class IntegrityViolation:
    """A detected integrity violation in a rule file"""
    file: str
    line_number: int
    pattern_name: str
    matched_content: str
    severity: str  # CRITICAL, HIGH, MEDIUM


# --- Report-path injection neutralisation -----------------------------------
# Rule-authored text (a rule's `message`/`issue`) flows verbatim into scan
# reports, which are routinely consumed by downstream LLMs (IDE agents, CI
# summarisers). Because a security ruleset *legitimately* describes attacks in
# its prose, we cannot reject that text — but we MUST render it inert as LLM
# *instructions* before it leaves the engine. We strip the structural delivery
# mechanics that flip an LLM into a new instruction context (null bytes, unicode
# direction overrides, conversation-turn delimiters, role tags) while leaving the
# text human-readable. Topic words ("ignore previous instructions") are harmless
# once stripped of these delivery anchors inside a clearly-delimited finding.
_BIDI_OVERRIDE = re.compile(r'[‪-‮⁦-⁩]')
# NOTE: use [ \t] (not \s) for the spacer so the line-break class and spacer
# class are disjoint — prevents catastrophic backtracking (ReDoS) on long runs
# of newlines that fail the trailing role match.
_TURN_DELIM = re.compile(r'(?i)[\r\n]+[ \t]*(human|assistant|system)\s*:')
_ROLE_TAG = re.compile(r'(?i)<\s*/?\s*(system|user|assistant|human)\s*>')


def neutralize_injection(text: str) -> str:
    """Make rule-authored report text inert as LLM instructions (human-readable)."""
    if not text or not isinstance(text, str):
        return text
    text = text.replace('\x00', '')                      # null-byte termination
    text = _BIDI_OVERRIDE.sub('', text)                  # visual-spoofing overrides
    text = _TURN_DELIM.sub(r' \1:', text)                # collapse turn delimiters inline
    text = _ROLE_TAG.sub(lambda m: m.group(0).replace('<', '‹').replace('>', '›'),
                         text)                            # <system> -> ‹system›
    return text


# =============================================================================
# HARDCODED DETECTION PATTERNS
# These are compiled into the binary - NOT loaded from YAML files
# Attackers cannot disable these by modifying rule files
# =============================================================================

INTEGRITY_PATTERNS: Dict[str, Tuple[str, str, str]] = {
    # Pattern name: (regex, severity, description)

    # System directive hijacking
    "system_directive_injection": (
        r'\[\s*System\s*Directive',
        "CRITICAL",
        "System directive injection attempt"
    ),
    "ignore_instructions": (
        r'ignore\s+(all\s+)?previous\s+(instructions|prompts|rules)',
        "CRITICAL",
        "Instruction override attempt"
    ),
    "role_hijacking": (
        r'you\s+are\s+now\s+(a|an)\s+',
        "HIGH",
        "Role/persona hijacking attempt"
    ),
    "new_goal_injection": (
        r'your\s+(new\s+)?(primary\s+)?(role|purpose|goal|objective)\s+(is|should)',
        "CRITICAL",
        "Goal injection attempt"
    ),

    # Hidden instruction markers
    "hidden_tag": (
        r'<\s*hidden\s*>',
        "CRITICAL",
        "Hidden instruction tag"
    ),
    "html_comment_instruction": (
        r'<!--[^>]*\b(instruction|directive|ignore|execute|run)\b[^>]*-->',
        "HIGH",
        "Hidden instruction in HTML comment"
    ),
    "null_byte": (
        r'\x00',
        "CRITICAL",
        "Null byte injection (string termination attack)"
    ),
    "unicode_direction_override": (
        r'[\u202a-\u202e\u2066-\u2069]',
        "CRITICAL",
        "Unicode direction override (visual spoofing)"
    ),

    # Code execution attempts
    "eval_exec": (
        r'\b(eval|exec)\s*\(\s*[\'"]',
        "CRITICAL",
        "Code execution attempt in rule content"
    ),
    "base64_decode_exec": (
        r'base64\.(b64)?decode.*\)\s*\)',
        "HIGH",
        "Base64 decode with execution"
    ),
    "import_os_system": (
        r'__import__\s*\(\s*[\'"]os[\'"]\s*\)',
        "CRITICAL",
        "Dynamic os module import"
    ),

    # LLM-specific injection markers
    "claude_turn_injection": (
        r'\b(Human|Assistant)\s*:\s*\n',
        "CRITICAL",
        "Claude conversation turn injection"
    ),
    "xml_role_tags": (
        r'<\s*/?\s*(system|user|assistant|human)\s*>',
        "CRITICAL",
        "XML role tag injection"
    ),
    "openai_role_injection": (
        r'\{\s*[\'"]role[\'"]\s*:\s*[\'"]system[\'"]',
        "HIGH",
        "OpenAI message role injection"
    ),

    # Jailbreak markers
    "dan_jailbreak": (
        r'\bDAN\b.*\b(mode|jailbreak|bypass)',
        "CRITICAL",
        "DAN jailbreak attempt"
    ),
    "developer_mode": (
        r'(enable|activate)\s+developer\s+mode',
        "HIGH",
        "Developer mode activation attempt"
    ),

    # Exfiltration setup
    "webhook_exfil": (
        r'(webhook|callback).*https?://[^\s]+\.(ngrok|burp|interact)',
        "CRITICAL",
        "Exfiltration webhook setup"
    ),
    "curl_exfil": (
        r'curl\s+.*-d\s+.*\$',
        "HIGH",
        "Data exfiltration via curl"
    ),

    # Prompt leakage attacks
    "repeat_everything": (
        r'repeat\s+(everything|all|the\s+above)',
        "MEDIUM",
        "Prompt leakage attempt"
    ),
    "show_system_prompt": (
        r'(show|display|print|output)\s+(your\s+)?(system\s+)?prompt',
        "MEDIUM",
        "System prompt extraction attempt"
    ),
}

# NOTE: the legacy line-prefix ALLOWLIST_CONTEXTS / PAYLOAD_BLOCK_KEYS machinery
# was removed in favour of structural YAML parsing (see scan_file). Suppression is
# now decided by field name (SAFE_VALUE_FIELDS / PROSE_DESCRIPTION_FIELDS) against
# the parsed document, which correctly handles multi-line scalars and cannot be
# bypassed by indentation.


class RuleIntegrityScanner:
    """
    Scans MEDUSA rule files for embedded malicious content.

    This runs BEFORE rules are loaded to prevent prompt-in-a-prompt attacks.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        """
        Initialize the integrity scanner.

        Args:
            rules_dir: Directory containing rule YAML files
        """
        if rules_dir is None:
            # Default to medusa/rules relative to this file
            rules_dir = Path(__file__).parent.parent / "rules"
        self.rules_dir = Path(rules_dir)
        self._compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, Tuple[re.Pattern, str, str]]:
        """Compile all integrity patterns"""
        compiled = {}
        for name, (pattern, severity, description) in INTEGRITY_PATTERNS.items():
            try:
                compiled[name] = (
                    re.compile(pattern, re.IGNORECASE | re.MULTILINE),
                    severity,
                    description
                )
            except re.error as e:
                print(f"Warning: Invalid integrity pattern {name}: {e}", file=sys.stderr)
        return compiled

    def scan_file(self, filepath: Path) -> List[IntegrityViolation]:
        """
        Scan a single rule file for embedded injection / integrity violations.

        Structural approach: parse the YAML and walk it field-by-field. A rule's
        VALUES are scanned by the *field name* that owns them — not by line-prefix
        heuristics. This correctly handles multi-line YAML scalars (e.g. a
        ``source_paper`` citation that spans several indented lines) which the old
        line-based scanner mishandled.

        Field values that are regex detection data or bounded structured metadata
        (``patterns``, ``cwe``, ``source_paper`` …) are not injection vectors and
        are suppressed. Every other field value — the prose that could flow into a
        report and thence an LLM (``description``, ``message``, ``notes`` …) — is
        scanned with the full integrity pattern set. If the file does not parse as
        YAML, we fall back to scanning every line.
        """
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except (IOError, OSError) as e:
            print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)
            return []

        try:
            data = yaml.load(content, Loader=_YAML_LOADER)
        except Exception:
            data = None

        if data is None:
            # Not parseable as YAML (or empty) — scan every line, no allowlist.
            return self._scan_raw_lines(content, filepath)

        violations: List[IntegrityViolation] = []
        self._walk_structured(data, None, content, filepath, violations)
        return violations

    def _walk_structured(self, node, field_name, content, filepath, violations) -> None:
        """Recursively walk parsed YAML, scanning scalar values by owning field."""
        if isinstance(node, dict):
            for key, value in node.items():
                self._walk_structured(value, str(key).lower(), content, filepath, violations)
        elif isinstance(node, list):
            # List items inherit the field name of the list (e.g. ``patterns: [...]``).
            for item in node:
                self._walk_structured(item, field_name, content, filepath, violations)
        elif isinstance(node, str):
            if field_name in SAFE_VALUE_FIELDS:
                return  # regex data / bounded metadata — not an injection vector
            # Prose description fields legitimately contain attack topic words, so
            # they are scanned only for mechanical injection-delivery markers.
            # Unexpected fields get the full pattern set.
            mechanical_only = field_name in PROSE_DESCRIPTION_FIELDS
            self._scan_value(node, content, filepath, violations, mechanical_only)

    def _scan_value(self, value: str, content: str, filepath: Path, violations,
                    mechanical_only: bool = False) -> None:
        """Run integrity patterns against one field value string."""
        for name, (pattern, severity, description) in self._compiled_patterns.items():
            if mechanical_only and name not in MECHANICAL_PATTERN_NAMES:
                continue
            match = pattern.search(value)
            if match:
                violations.append(IntegrityViolation(
                    file=str(filepath),
                    line_number=self._approx_line(content, match.group(0)),
                    pattern_name=name,
                    matched_content=match.group(0)[:100],
                    severity=severity,
                ))

    @staticmethod
    def _approx_line(content: str, needle: str) -> int:
        """Best-effort line number for a matched substring (0 if not locatable)."""
        idx = content.find(needle[:60])
        return content.count('\n', 0, idx) + 1 if idx >= 0 else 0

    def _scan_raw_lines(self, content: str, filepath: Path) -> List[IntegrityViolation]:
        """Fallback for non-YAML files: scan every line with no field allowlist."""
        violations: List[IntegrityViolation] = []
        for line_num, line in enumerate(content.split('\n'), 1):
            for name, (pattern, severity, description) in self._compiled_patterns.items():
                match = pattern.search(line)
                if match:
                    violations.append(IntegrityViolation(
                        file=str(filepath),
                        line_number=line_num,
                        pattern_name=name,
                        matched_content=match.group(0)[:100],
                        severity=severity,
                    ))
        return violations

    def scan_all_rules(self) -> List[IntegrityViolation]:
        """
        Scan all rule files in the rules directory.

        Returns:
            List of all violations found
        """
        all_violations = []

        if not self.rules_dir.exists():
            print(f"Warning: Rules directory not found: {self.rules_dir}", file=sys.stderr)
            return all_violations

        # Scan only rule files that are actually loaded into the engine: skip the
        # archive/ directory (retired rules, not loaded) and *_runtime.yaml files
        # (paid-tier, loaded separately). Single traversal for both extensions.
        for rule_file in self.rules_dir.rglob("*.y*ml"):
            if rule_file.suffix not in (".yaml", ".yml"):
                continue
            if "archive" in rule_file.parts or "_runtime" in rule_file.name:
                continue
            all_violations.extend(self.scan_file(rule_file))

        return all_violations

    def verify_integrity(self, max_retries: int = 3) -> Tuple[bool, List[IntegrityViolation]]:
        """
        Verify rule file integrity with retry loop.

        Args:
            max_retries: Maximum scan attempts (for manual fix scenarios)

        Returns:
            Tuple of (is_clean, violations)
        """
        for attempt in range(max_retries):
            violations = self.scan_all_rules()

            if not violations:
                return True, []

            # Report violations
            critical_count = sum(1 for v in violations if v.severity == "CRITICAL")
            high_count = sum(1 for v in violations if v.severity == "HIGH")

            print(f"\n{'='*60}", file=sys.stderr)
            print("MEDUSA RULE INTEGRITY CHECK FAILED", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)
            print(f"Attempt {attempt + 1}/{max_retries}", file=sys.stderr)
            print(f"CRITICAL: {critical_count} | HIGH: {high_count} | Total: {len(violations)}", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)

            for v in violations[:20]:  # Show first 20
                print(f"[{v.severity}] {v.file}:{v.line_number}", file=sys.stderr)
                print(f"  Pattern: {v.pattern_name}", file=sys.stderr)
                print(f"  Content: {v.matched_content}", file=sys.stderr)
                print("", file=sys.stderr)

            if len(violations) > 20:
                print(f"... and {len(violations) - 20} more violations", file=sys.stderr)

            # If critical violations, don't retry
            if critical_count > 0:
                print("\nCRITICAL violations detected. Aborting.", file=sys.stderr)
                return False, violations

            # For non-critical, prompt for retry (in interactive mode)
            if attempt < max_retries - 1:
                print("\nRe-scanning in case of transient issues...", file=sys.stderr)

        return False, violations


def check_rule_integrity(rules_dir: Optional[Path] = None, exit_on_fail: bool = True) -> bool:
    """
    Convenience function to check rule integrity before loading.

    Args:
        rules_dir: Optional custom rules directory
        exit_on_fail: Exit process if integrity check fails

    Returns:
        True if rules are clean, False otherwise
    """
    scanner = RuleIntegrityScanner(rules_dir)
    is_clean, violations = scanner.verify_integrity()

    if not is_clean and exit_on_fail:
        print("\nRule integrity check failed. MEDUSA cannot start safely.", file=sys.stderr)
        print("Please review and clean the flagged rule files.", file=sys.stderr)
        sys.exit(1)

    return is_clean


# Run as standalone for testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MEDUSA Rule Integrity Scanner")
    parser.add_argument("path", nargs="?", help="Path to rules directory or file")
    parser.add_argument("--no-exit", action="store_true", help="Don't exit on failure")
    args = parser.parse_args()

    if args.path:
        path = Path(args.path)
        if path.is_file():
            scanner = RuleIntegrityScanner()
            violations = scanner.scan_file(path)
            for v in violations:
                print(f"[{v.severity}] {v.file}:{v.line_number} - {v.pattern_name}")
            sys.exit(0 if not violations else 1)
        else:
            is_clean = check_rule_integrity(path, exit_on_fail=not args.no_exit)
    else:
        is_clean = check_rule_integrity(exit_on_fail=not args.no_exit)

    print(f"\nIntegrity check: {'PASSED' if is_clean else 'FAILED'}")
