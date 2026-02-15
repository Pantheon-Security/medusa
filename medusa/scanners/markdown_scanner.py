#!/usr/bin/env python3
"""
MEDUSA Markdown Scanner
Scans Markdown files for:
- Style and formatting issues using markdownlint (optional external tool)
- Prompt injection and jailbreak patterns (built-in, always active)
- System prompt extraction attempts
- Role manipulation and goal hijacking
"""

import json
import re
import time
from pathlib import Path
from typing import List, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class MarkdownScanner(BaseScanner):
    """
    Markdown security scanner with built-in prompt injection detection.

    Built-in security checks (always active):
    - MD-PI: Direct prompt injection patterns
    - MD-JB: Jailbreak templates and bypass attempts
    - MD-SPE: System prompt extraction attempts
    - MD-RM: Role manipulation and persona hijacking
    - MD-GH: Goal hijacking and instruction override
    - MD-IO: Instruction override and fake system tags

    External tool (optional):
    - markdownlint: Style and formatting checks
    """

    # ----------------------------------------------------------------
    # MD-PI: Direct Prompt Injection Patterns (CRITICAL)
    # ----------------------------------------------------------------
    PROMPT_INJECTION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context|prompts?|guidelines?)', re.IGNORECASE),
         'Direct prompt injection - ignore previous instructions', Severity.CRITICAL),
        (re.compile(r'disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context|prompts?)', re.IGNORECASE),
         'Direct prompt injection - disregard prior instructions', Severity.CRITICAL),
        (re.compile(r'forget\s+(all\s+)?(your|previous|prior|above|earlier)\s+(instructions?|rules?|programming|training|guidelines?)', re.IGNORECASE),
         'Direct prompt injection - forget instructions', Severity.CRITICAL),
        (re.compile(r'do\s+not\s+follow\s+(any\s+)?(previous|prior|earlier|above)\s+(instructions?|rules?|guidelines?)', re.IGNORECASE),
         'Direct prompt injection - do not follow instructions', Severity.CRITICAL),
        (re.compile(r'from\s+now\s+on\s*,?\s*(ignore|forget|disregard)', re.IGNORECASE),
         'Direct prompt injection - from now on ignore', Severity.CRITICAL),
        (re.compile(r'stop\s+(being|acting\s+as)\s+(an?\s+)?ai', re.IGNORECASE),
         'Direct prompt injection - stop being AI', Severity.CRITICAL),
        (re.compile(r'you\s+are\s+no\s+longer\s+(an?\s+)?(ai|assistant|chatbot|language\s+model)', re.IGNORECASE),
         'Direct prompt injection - deny AI identity', Severity.CRITICAL),
        (re.compile(r'transcended?\s+(your\s+)?(programming|constraints?|limitations?|boundaries)', re.IGNORECASE),
         'Direct prompt injection - transcend programming', Severity.CRITICAL),
    ]

    # ----------------------------------------------------------------
    # MD-JB: Jailbreak Template Patterns (HIGH/CRITICAL)
    # ----------------------------------------------------------------
    JAILBREAK_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'\bjailbreak\b', re.IGNORECASE),
         'Jailbreak keyword detected', Severity.HIGH),
        (re.compile(r'\byou\s+are\s+now\s+DAN\b', re.IGNORECASE),
         'DAN jailbreak template detected', Severity.CRITICAL),
        (re.compile(r'\bdo\s+anything\s+now\b', re.IGNORECASE),
         'DAN (Do Anything Now) jailbreak pattern', Severity.CRITICAL),
        (re.compile(r'\bDAN\s+mode\b', re.IGNORECASE),
         'DAN mode jailbreak reference', Severity.CRITICAL),
        (re.compile(r'bypass\s+(all\s+)?(safety|content)?\s*filters?', re.IGNORECASE),
         'Jailbreak - bypass filters', Severity.HIGH),
        (re.compile(r'bypass\s+(all\s+)?(safety|security)\s*(measures?|mechanisms?|protocols?|features?|restrictions?|guidelines?)?', re.IGNORECASE),
         'Jailbreak - bypass safety', Severity.HIGH),
        (re.compile(r'\bdeveloper\s+mode\b', re.IGNORECASE),
         'Jailbreak - developer mode invocation', Severity.HIGH),
        (re.compile(r'\bdevice?\s+mode\s+(enabled?|activated?|on)\b', re.IGNORECASE),
         'Jailbreak - device mode activation', Severity.HIGH),
        (re.compile(r'\bunlocked?\s+mode\b', re.IGNORECASE),
         'Jailbreak - unlocked mode', Severity.HIGH),
        (re.compile(r'\bgod\s+mode\b', re.IGNORECASE),
         'Jailbreak - god mode invocation', Severity.HIGH),
        (re.compile(r'free\s+from\s+(any\s+)?(constraints?|restrictions?|limitations?|rules?|guidelines?)', re.IGNORECASE),
         'Jailbreak - free from constraints', Severity.HIGH),
        (re.compile(r'(no|without|zero|free\s+of)\s+(any\s+)?(ethical|moral)\s+(constraints?|considerations?|limitations?|boundaries|guidelines?)', re.IGNORECASE),
         'Jailbreak - no ethical constraints', Severity.CRITICAL),
        (re.compile(r'devoid\s+of\s+(any\s+)?(warnings?|concerns?|limitations?|restrictions?)', re.IGNORECASE),
         'Jailbreak - devoid of warnings', Severity.HIGH),
        (re.compile(r'(uncensored|unfiltered|unrestricted)\s+(responses?|outputs?|content|mode|access)', re.IGNORECASE),
         'Jailbreak - uncensored/unrestricted mode', Severity.HIGH),
        (re.compile(r'without\s+(any\s+)?(censorship|moderation|filtering|restrictions?)', re.IGNORECASE),
         'Jailbreak - without censorship', Severity.HIGH),
        (re.compile(r'(no|never)\s+(refus|censor|filter|moder|restrict)', re.IGNORECASE),
         'Jailbreak - never refuse/censor', Severity.HIGH),
        (re.compile(r'(will|must|should)\s+not\s+(refuse|decline|reject)\s+(any|to\s+answer)', re.IGNORECASE),
         'Jailbreak - must not refuse', Severity.HIGH),
        (re.compile(r'answer\s+(any|every|all)\s+(request|question|query|prompt)', re.IGNORECASE),
         'Jailbreak - answer any request', Severity.MEDIUM),
    ]

    # ----------------------------------------------------------------
    # MD-SPE: System Prompt Extraction Patterns (HIGH/CRITICAL)
    # ----------------------------------------------------------------
    SYSTEM_PROMPT_EXTRACTION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'(reveal|show|display|output|print|tell\s+me)\s+(your|the)\s+(system\s+)?prompt', re.IGNORECASE),
         'System prompt extraction - reveal prompt', Severity.CRITICAL),
        (re.compile(r'(show|tell|give|reveal)\s+(me\s+)?(your|the)\s+(instructions?|rules?|guidelines?|programming)', re.IGNORECASE),
         'System prompt extraction - reveal instructions', Severity.HIGH),
        (re.compile(r'repeat\s+(everything|all|the\s+text)\s+(above|before|preceding)', re.IGNORECASE),
         'System prompt extraction - repeat above text', Severity.CRITICAL),
        (re.compile(r'(output|print|display|echo)\s+(your\s+)?(initial|original|system|first)\s+(prompt|instructions?|message)', re.IGNORECASE),
         'System prompt extraction - output initial prompt', Severity.CRITICAL),
        (re.compile(r'what\s+(are|were)\s+(your|the)\s+(original|initial|system|first)\s+(instructions?|rules?|prompt)', re.IGNORECASE),
         'System prompt extraction - asking for original instructions', Severity.HIGH),
        (re.compile(r'(copy|paste|reproduce)\s+(your|the)\s+(entire|full|complete)\s+(system\s+)?(prompt|instructions?)', re.IGNORECASE),
         'System prompt extraction - copy system prompt', Severity.CRITICAL),
        (re.compile(r'dump\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)', re.IGNORECASE),
         'System prompt extraction - dump prompt', Severity.CRITICAL),
        (re.compile(r'beginning\s+of\s+(the|this)\s+conversation', re.IGNORECASE),
         'System prompt extraction - beginning of conversation probe', Severity.MEDIUM),
    ]

    # ----------------------------------------------------------------
    # MD-RM: Role Manipulation Patterns (MEDIUM/HIGH)
    # ----------------------------------------------------------------
    ROLE_MANIPULATION_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'you\s+are\s+now\s+(a|an|the)\b', re.IGNORECASE),
         'Role manipulation - persona reassignment', Severity.MEDIUM),
        (re.compile(r'act\s+as\s+if\s+you\s+have\s+no\s+restrictions?', re.IGNORECASE),
         'Role manipulation - act without restrictions', Severity.HIGH),
        (re.compile(r'pretend\s+(that\s+)?you\s+(are|have)\s+(no\s+)?(restrictions?|limits?|rules?|boundaries|guidelines?)', re.IGNORECASE),
         'Role manipulation - pretend no restrictions', Severity.HIGH),
        (re.compile(r'pretend\s+(that\s+)?you\s+are\s+(a|an|the)\b', re.IGNORECASE),
         'Role manipulation - pretend to be', Severity.MEDIUM),
        (re.compile(r'imagine\s+you\s+are\s+(a|an|the|free|unrestricted|unbound)', re.IGNORECASE),
         'Role manipulation - imagine you are', Severity.MEDIUM),
        (re.compile(r'assume\s+(the\s+)?(role|persona|identity|character)\s+of', re.IGNORECASE),
         'Role manipulation - assume persona', Severity.MEDIUM),
        (re.compile(r'roleplay\s+as\s+(a|an|the)', re.IGNORECASE),
         'Role manipulation - roleplay as', Severity.MEDIUM),
        (re.compile(r'you\s+(must|will|should)\s+(always\s+)?respond\s+(as|like)\s+(a|an|the)', re.IGNORECASE),
         'Role manipulation - forced response style', Severity.MEDIUM),
        (re.compile(r'your\s+(sole|only|primary|new)\s+purpose\s+is', re.IGNORECASE),
         'Role manipulation - purpose override', Severity.HIGH),
        (re.compile(r'you\s+have\s+(no\s+)?(allegiance|loyalty|obligation)\s+to', re.IGNORECASE),
         'Role manipulation - allegiance override', Severity.HIGH),
        (re.compile(r'(sentient|conscious|self-?aware)\s+entity', re.IGNORECASE),
         'Role manipulation - sentient entity claim', Severity.MEDIUM),
        (re.compile(r'you\s+have\s+access\s+to\s+all\s+(knowledge|information)', re.IGNORECASE),
         'Role manipulation - unlimited knowledge claim', Severity.MEDIUM),
    ]

    # ----------------------------------------------------------------
    # MD-GH: Goal Hijacking Patterns (HIGH)
    # ----------------------------------------------------------------
    GOAL_HIJACKING_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'new\s+task\s*:', re.IGNORECASE),
         'Goal hijacking - new task injection', Severity.HIGH),
        (re.compile(r'instead\s*,?\s*(do|perform|execute|follow)\s+the\s+following', re.IGNORECASE),
         'Goal hijacking - instead do the following', Severity.HIGH),
        (re.compile(r'your\s+(real|true|actual|hidden)\s+(purpose|goal|objective|task)\s+is', re.IGNORECASE),
         'Goal hijacking - real purpose override', Severity.HIGH),
        (re.compile(r'your\s+(new|updated|revised|real)\s+(instructions?|directives?|orders?)\s+(are|is)\s*:', re.IGNORECASE),
         'Goal hijacking - new instructions', Severity.HIGH),
        (re.compile(r'forget\s+(about\s+)?(the|that|your)\s+(previous|original|prior|old)\s+(task|goal|purpose|objective)', re.IGNORECASE),
         'Goal hijacking - forget original task', Severity.HIGH),
        (re.compile(r'(actually|but\s+first|before\s+that)\s*,?\s*(I\s+need|please|you\s+must)', re.IGNORECASE),
         'Goal hijacking - redirection attempt', Severity.MEDIUM),
    ]

    # ----------------------------------------------------------------
    # MD-IO: Instruction Override Patterns (CRITICAL/HIGH)
    # ----------------------------------------------------------------
    INSTRUCTION_OVERRIDE_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'override\s+(all\s+)?(previous|prior|default|existing)\s*(instructions?|rules?|settings?|behavior|constraints?)', re.IGNORECASE),
         'Instruction override - override previous', Severity.CRITICAL),
        (re.compile(r'new\s+(system\s+)?instructions?\s*:', re.IGNORECASE),
         'Instruction override - new instructions block', Severity.CRITICAL),
        # Match "SYSTEM:" only when followed by injection-like text, not product names
        # e.g., "SYSTEM: You are an AI assistant" matches but "System: Microsoft Purview" does not
        (re.compile(r'^SYSTEM\s*:\s*(?:you|ignore|forget|disregard|override|new\s+instructions)', re.IGNORECASE),
         'Instruction override - fake SYSTEM tag', Severity.CRITICAL),
        (re.compile(r'^ADMIN\s*:\s*(?:you|ignore|forget|disregard|override|execute|run|grant)', re.IGNORECASE),
         'Instruction override - fake ADMIN tag', Severity.CRITICAL),
        (re.compile(r'\[SYSTEM\]', re.IGNORECASE),
         'Instruction override - [SYSTEM] tag injection', Severity.HIGH),
        (re.compile(r'\[INST\]', re.IGNORECASE),
         'Instruction override - [INST] tag injection', Severity.HIGH),
        (re.compile(r'<\|system\|>', re.IGNORECASE),
         'Instruction override - ChatML system tag injection', Severity.CRITICAL),
        (re.compile(r'<\|assistant\|>', re.IGNORECASE),
         'Instruction override - ChatML assistant tag injection', Severity.HIGH),
        (re.compile(r'<\|user\|>', re.IGNORECASE),
         'Instruction override - ChatML user tag injection', Severity.HIGH),
        (re.compile(r'<<SYS>>', re.IGNORECASE),
         'Instruction override - Llama system tag injection', Severity.HIGH),
        (re.compile(r'CORE\s+DIRECTIVES?\s*[\(:\[]', re.IGNORECASE),
         'Instruction override - fake core directives', Severity.HIGH),
        (re.compile(r'NON-?NEGOTIABLE\s*(:|rules?|directives?)', re.IGNORECASE),
         'Instruction override - non-negotiable directives', Severity.HIGH),
    ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner (security patterns always work)

    def get_file_extensions(self) -> List[str]:
        return ['.md', '.markdown']

    def is_available(self) -> bool:
        """Built-in security scanner is always available."""
        return True

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return confidence score for markdown files.

        MarkdownScanner handles all .md/.markdown files for security scanning.
        Returns moderate confidence so specialized scanners (AIContextScanner)
        can take precedence for known AI context files.

        Args:
            file_path: Path to file to analyze.

        Returns:
            Confidence score (0-100).
        """
        if not self.can_scan(file_path):
            return 0

        # Standard markdown file - moderate confidence
        return 40

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan Markdown file for security issues and optionally style issues.

        Always runs built-in security pattern detection (prompt injection,
        jailbreak, system prompt extraction, role manipulation, goal
        hijacking, instruction overrides).

        Additionally runs markdownlint for style checking if the external
        tool is installed.

        Args:
            file_path: Path to Markdown file.

        Returns:
            ScannerResult with issues found.
        """
        start_time = time.time()
        issues: List[ScannerIssue] = []

        # -----------------------------------------------------------
        # Phase 1: Built-in security pattern scanning (ALWAYS runs)
        # -----------------------------------------------------------
        try:
            security_issues = self._scan_security_patterns(file_path)
            issues.extend(security_issues)
        except Exception:
            # Security scanning should not prevent markdownlint from running
            pass

        # -----------------------------------------------------------
        # Phase 2: External markdownlint (optional, runs if installed)
        # -----------------------------------------------------------
        markdownlint_path = self._find_markdownlint()
        if markdownlint_path is not None:
            try:
                cmd = [str(markdownlint_path), '-j', str(file_path)]
                result = self._run_command(cmd, timeout=30)

                if result.returncode in (0, 1) and result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        for _filename, file_issues in data.items():
                            for issue in file_issues:
                                scanner_issue = ScannerIssue(
                                    severity=Severity.LOW,
                                    message=issue.get('ruleDescription', 'Style issue'),
                                    line=issue.get('lineNumber'),
                                    rule_id=issue.get('ruleNames', [''])[0] if issue.get('ruleNames') else None,
                                )
                                issues.append(scanner_issue)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                # markdownlint failure should not block results
                pass

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True
        )

    def _find_markdownlint(self):
        """Find markdownlint binary if installed.

        Returns:
            Path to markdownlint, or None if not installed.
        """
        import shutil
        tool_path = shutil.which("markdownlint")
        if tool_path:
            return Path(tool_path)
        return None

    # Directories containing project documentation (not LLM prompts)
    # Files in these dirs get reduced sensitivity - only CRITICAL patterns fire
    DOC_DIRECTORIES = {
        'docs', 'doc', 'documentation', 'wiki', 'requests',
        'proposals', 'rfcs', 'specs', 'design', 'meetings',
        'notes', 'changelog', 'releases', 'guides', 'tutorials',
    }

    def _is_documentation_file(self, file_path: Path) -> bool:
        """Check if file is in a documentation directory (not an LLM prompt)."""
        parts = {p.lower() for p in file_path.parts}
        return bool(parts & self.DOC_DIRECTORIES)

    def _scan_security_patterns(self, file_path: Path) -> List[ScannerIssue]:
        """
        Scan markdown file content for prompt injection and jailbreak patterns.

        Runs all built-in security pattern groups against each line of the file.
        Uses case-insensitive regex matching.

        For documentation files (in docs/, wiki/, etc.), only CRITICAL patterns
        are reported to reduce noise from descriptive text.

        Args:
            file_path: Path to the markdown file.

        Returns:
            List of ScannerIssue objects for detected security patterns.
        """
        issues: List[ScannerIssue] = []
        is_doc = self._is_documentation_file(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError, PermissionError):
            return issues

        lines = content.split('\n')

        # MD-PI: Direct prompt injection (CWE-94: Code Injection)
        issues.extend(self._match_patterns(
            lines, self.PROMPT_INJECTION_PATTERNS, "MD-PI", 94
        ))

        # MD-JB: Jailbreak templates (CWE-693: Protection Mechanism Failure)
        issues.extend(self._match_patterns(
            lines, self.JAILBREAK_PATTERNS, "MD-JB", 693
        ))

        # MD-SPE: System prompt extraction (CWE-200: Information Exposure)
        issues.extend(self._match_patterns(
            lines, self.SYSTEM_PROMPT_EXTRACTION_PATTERNS, "MD-SPE", 200
        ))

        # MD-RM: Role manipulation (CWE-284: Improper Access Control)
        issues.extend(self._match_patterns(
            lines, self.ROLE_MANIPULATION_PATTERNS, "MD-RM", 284
        ))

        # MD-GH: Goal hijacking (CWE-441: Unintended Proxy)
        issues.extend(self._match_patterns(
            lines, self.GOAL_HIJACKING_PATTERNS, "MD-GH", 441
        ))

        # MD-IO: Instruction override (CWE-94: Code Injection)
        issues.extend(self._match_patterns(
            lines, self.INSTRUCTION_OVERRIDE_PATTERNS, "MD-IO", 94
        ))

        # For documentation files, only keep CRITICAL findings
        # (descriptive text in docs often triggers MEDIUM/LOW patterns)
        if is_doc:
            issues = [i for i in issues if i.severity == Severity.CRITICAL]

        return issues

    def _match_patterns(
        self,
        lines: List[str],
        patterns: List[Tuple[re.Pattern, str, Severity]],
        rule_id: str,
        cwe_id: int
    ) -> List[ScannerIssue]:
        """
        Match regex patterns against file lines and create ScannerIssue objects.

        Args:
            lines: List of file lines.
            patterns: List of (compiled regex, description, severity) tuples.
            rule_id: Rule identifier prefix (e.g. 'MD-PI').
            cwe_id: CWE identifier number.

        Returns:
            List of ScannerIssue for each matched pattern.
        """
        issues: List[ScannerIssue] = []
        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

        for i, line in enumerate(lines, 1):
            for pattern, description, severity in patterns:
                if pattern.search(line):
                    # Truncate long lines for readable output
                    snippet = line.strip()
                    if len(snippet) > 120:
                        snippet = snippet[:117] + '...'

                    issues.append(ScannerIssue(
                        severity=severity,
                        message=f"{description}: {snippet}",
                        line=i,
                        rule_id=rule_id,
                        cwe_id=cwe_id,
                        cwe_link=cwe_link
                    ))
                    break  # One match per line per rule group

        return issues

    def get_install_instructions(self) -> str:
        return """Built-in security scanning is always available.
Optional: Install markdownlint-cli for style checks:
  - npm install -g markdownlint-cli
  - Or via system package manager"""
