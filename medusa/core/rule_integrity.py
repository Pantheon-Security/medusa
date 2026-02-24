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


@dataclass
class IntegrityViolation:
    """A detected integrity violation in a rule file"""
    file: str
    line_number: int
    pattern_name: str
    matched_content: str
    severity: str  # CRITICAL, HIGH, MEDIUM


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

# Patterns that are OK in rule files (for detection purposes)
# These are the patterns we WANT in rules - they detect attacks in scanned code
ALLOWLIST_CONTEXTS = [
    r'^\s*-\s*["\']',  # YAML list item (pattern definition)
    r'^\s*pattern[s]?\s*:',  # Pattern key
    r'^\s*message\s*:',  # Message describing the attack
    r'^\s*description\s*:',  # Description of what we detect
    r'^\s*#',  # Comments
    r'^\s*id\s*:',  # Rule ID (e.g., id: dan-jailbreak)
    r'^\s*name\s*:',  # Rule name
    r'^\s*-\s*id\s*:',  # List item rule ID
    r'^\s*category\s*:',  # Category name
    r'^\s*cwe\s*:',  # CWE reference
    r'^\s*owasp',  # OWASP reference
    r'^\s*mitre',  # MITRE reference
    r'^\s*references\s*:',  # References section
    r'^\s*-\s*https?://',  # URL references
    r'^\s*fix\s*:',  # Fix recommendation
    r'^\s*severity\s*:',  # Severity level
    r'^\s*attack_type\s*:',  # Attack type metadata
    r'^\s*type\s*:',  # Rule type
    r'^\s*technique\s*:',  # Technique description
    r'^\s*attack_vector\s*:',  # Attack vector
    r'^\s*attack_framework\s*:',  # Attack framework metadata
    r'^\s*example\s*:',  # Example (may contain attack strings)
    r'^\s*regex\s*:',  # Regex definition
    r'^\s*remediation\s*:',  # Remediation field (describes how to fix/block attacks)
    r'^\s*source_paper\s*:',  # Source paper reference
    r'^\s*-\s*\\',  # YAML list with escaped regex
    r'^\s*-\s*\(',  # YAML list with regex group
    r'^\s*-\s*\[',  # YAML list with character class
    r'^\s*-\s*<[a-z]+\[',  # YAML list with XML-style regex (e.g., <system[^>]*>)
    r'^\s*-\s*<\\',  # YAML list with escaped XML regex
    r'^\s*-\s*["\']?<\w+',  # YAML list with XML tag pattern
    r'^\s*-\s*["\']?<!--',  # YAML list with HTML comment pattern
    r'^\s*-\s*\.\*',  # YAML list starting with .*
    r'^\s*-\s*\\\b',  # YAML list with word boundary
]

# Additional check: if line looks like a regex pattern (has regex metacharacters)
REGEX_PATTERN_INDICATORS = re.compile(
    r'[\[\]\\|*+?{}()^$].*[\[\]\\|*+?{}()^$]'  # Multiple regex metacharacters
)


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
        self._allowlist_patterns = [re.compile(p) for p in ALLOWLIST_CONTEXTS]

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

    def _is_allowlisted_context(self, line: str) -> bool:
        """Check if line is in an allowlisted context (pattern definition)"""
        for pattern in self._allowlist_patterns:
            if pattern.match(line):
                return True

        stripped = line.strip()

        # Also allow lines that look like regex patterns (have multiple metacharacters)
        # This catches detection patterns like: - <system[^>]*>.*?</system>
        if stripped.startswith('-') and REGEX_PATTERN_INDICATORS.search(stripped):
            return True

        # Allow short YAML list items that look like tag patterns (for pattern lists)
        # e.g., "  - </system>" or "  - </think>"
        if stripped.startswith('-') and len(stripped) < 30 and '</' in stripped:
            return True

        # Allow continuation lines in multi-line descriptions (indented text)
        # These are typically explanations of what attacks we detect
        # YAML continuation lines use 4+ spaces of indentation
        if line.startswith('    ') and not stripped.startswith('-') and not stripped.startswith('id:') and not stripped.startswith('name:') and not stripped.startswith('severity:'):
            return True

        return False

    def scan_file(self, filepath: Path) -> List[IntegrityViolation]:
        """
        Scan a single file for integrity violations.

        Args:
            filepath: Path to the file to scan

        Returns:
            List of violations found
        """
        violations = []

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # Skip allowlisted contexts (pattern definitions are OK)
                if self._is_allowlisted_context(line):
                    continue

                # Check each integrity pattern
                for name, (pattern, severity, description) in self._compiled_patterns.items():
                    match = pattern.search(line)
                    if match:
                        violations.append(IntegrityViolation(
                            file=str(filepath),
                            line_number=line_num,
                            pattern_name=name,
                            matched_content=match.group(0)[:100],  # Truncate
                            severity=severity
                        ))

        except (IOError, OSError) as e:
            print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)

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

        # Scan all YAML files recursively
        for yaml_file in self.rules_dir.rglob("*.yaml"):
            violations = self.scan_file(yaml_file)
            all_violations.extend(violations)

        for yml_file in self.rules_dir.rglob("*.yml"):
            violations = self.scan_file(yml_file)
            all_violations.extend(violations)

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
