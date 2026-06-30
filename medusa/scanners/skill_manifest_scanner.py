#!/usr/bin/env python3
"""
MEDUSA SKILL.md Manifest Scanner

Deep vetting of Agent Skill manifests (SKILL.md). A SKILL.md ships YAML
frontmatter (name / description / when-to-use / allowed-tools / ...) plus a
markdown body of natural-language instructions the agent follows verbatim. A
poisoned manifest is a prompt-injection delivery vehicle: it can hijack the
agent's trigger behavior, talk it out of refusing, tell it to rewrite its own
config, or seed persistent memory — all before any code runs.

`.claude/*.md` prose is screened by AIContextScanner and `.claude/agents/*.md`
frontmatter by ClaudeCodeScanner; neither parses SKILL.md frontmatter+body for
these manifest-specific abuse vectors. This scanner fills that gap.

Detects:
  - MEDUSA-SKILL-TRIGGER-001:    over-broad / shadowing triggers (HIGH)
  - MEDUSA-SKILL-ANTIREFUSAL-001: instructions to ignore safety/refusals (HIGH/CRITICAL)
  - MEDUSA-SKILL-ROGUE-001:       self-modification / persistence / config rewrite (HIGH/CRITICAL)
  - MEDUSA-SKILL-MEMORY-001:      memory-poisoning / persistent behavior injection (MEDIUM/HIGH)
  - MEDUSA-SKILL-TOOLS-001:       over-broad allowed-tools (`*` / Bash(*) / all) (HIGH)

Precision is the contract. A benign, well-scoped SKILL.md — a specific trigger,
ordinary instructional body, an enumerated tool list — yields zero findings.
Trigger-abuse for the bare words "always"/"every" is gated behind a co-occurring
action/broad-scope indicator so that a legitimate "always vet" skill is NOT
flagged.
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SkillManifestScanner(BaseScanner):
    """Deep vetting of Agent Skill manifests (SKILL.md frontmatter + body)."""

    display_name = "Skill Manifest Vetting"
    description = (
        "Vets SKILL.md manifests for trigger abuse, anti-refusal instructions, "
        "self-modification/persistence, memory-poisoning, and over-broad tools."
    )

    # Frontmatter keys whose VALUES describe when the skill fires.
    _TRIGGER_KEYS = ("when-to-use", "when_to_use", "trigger", "triggers", "description")

    # Frontmatter keys that enumerate granted tools.
    _TOOL_KEYS = ("allowed-tools", "allowed_tools", "tools")

    # -- MEDUSA-SKILL-TRIGGER-001: over-broad / shadowing triggers ----------- #
    # "always/every/all" alone is legitimate (e.g. "always vet"); only flag when
    # the broad quantifier co-occurs with a fire/activate/scope action indicator,
    # OR when the trigger is unconditionally everything ("any request", "all
    # requests", "no matter what", "regardless of").
    _TRIGGER_BROAD_QUANTIFIER = re.compile(
        r'\b(?:always|every|all|any|each)\b', re.IGNORECASE
    )
    _TRIGGER_ACTION_SCOPE = re.compile(
        r'\b(?:fire|trigger|activate|invoke|run|use this skill|apply|engage|'
        r'respond|handle|intercept)\b', re.IGNORECASE
    )
    # Unconditional "fires on everything" phrasings — flag on their own.
    _TRIGGER_UNCONDITIONAL: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'\b(?:any|every|all|each)\s+(?:user\s+)?'
                    r'(?:request|message|prompt|query|input|task|conversation|interaction)s?\b',
                    re.IGNORECASE),
         'Trigger fires on any/every request — shadows all other skills', Severity.HIGH),
        (re.compile(r'\bno matter what\b|\bregardless of\b|\bin all (?:cases|situations|contexts)\b',
                    re.IGNORECASE),
         'Trigger claims to fire unconditionally (no matter what / regardless)', Severity.HIGH),
        (re.compile(r'\b(?:for|on)\s+everything\b|\beverything the user\b', re.IGNORECASE),
         'Trigger scoped to "everything" — over-broad activation', Severity.HIGH),
    ]
    # Common command/skill names this manifest must not shadow via its `name`.
    _SHADOW_NAMES = {
        "scan", "search", "read", "write", "edit", "build", "test", "deploy",
        "commit", "review", "help", "run", "git", "bash", "shell", "install",
    }

    # -- MEDUSA-SKILL-ANTIREFUSAL-001: ignore safety / refusals -------------- #
    _ANTIREFUSAL: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'\bignore (?:all |any |the )?(?:previous|prior|above|earlier|preceding|'
                    r'system) (?:instructions?|prompts?|rules?|messages?|directives?)\b',
                    re.IGNORECASE),
         'Instructs the agent to ignore previous/system instructions', Severity.CRITICAL),
        (re.compile(r'\b(?:do not|don\'?t|never)\s+refuse\b', re.IGNORECASE),
         'Instructs the agent never to refuse', Severity.CRITICAL),
        (re.compile(r'\b(?:bypass|disable|ignore|override|circumvent|skip)\s+'
                    r'(?:all |any |your |the )?(?:safety|security|guardrails?|guideline|'
                    r'restriction|filter|moderation|content polic)\w*', re.IGNORECASE),
         'Instructs the agent to bypass safety/guidelines/guardrails', Severity.CRITICAL),
        (re.compile(r'\bwithout (?:any )?(?:warning|disclaimer|caveat|refus\w+|'
                    r'asking|confirmation|question)s?\b', re.IGNORECASE),
         'Instructs the agent to act without warnings/disclaimers/confirmation', Severity.HIGH),
        (re.compile(r'\b(?:do not|don\'?t)\s+(?:warn|caution|disclaim|mention (?:any )?risk)\w*',
                    re.IGNORECASE),
         'Instructs the agent to suppress warnings/risk disclosure', Severity.HIGH),
        (re.compile(r'\bregardless of (?:any )?(?:safety|ethic|legal|polic|guideline|harm)\w*',
                    re.IGNORECASE),
         'Instructs the agent to disregard safety/ethics/policy', Severity.HIGH),
        (re.compile(r'\b(?:you are|act as|pretend to be) (?:now )?'
                    r'(?:DAN|jailbroken|unrestricted|unfiltered|uncensored)\b', re.IGNORECASE),
         'Jailbreak persona instruction (unrestricted/uncensored)', Severity.CRITICAL),
    ]

    # -- MEDUSA-SKILL-ROGUE-001: self-modification / persistence ------------- #
    _ROGUE: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'\b(?:modify|edit|rewrite|overwrite|append to|update|patch)\b[^.\n]{0,60}?'
                    r'\b(?:CLAUDE\.md|settings\.json|settings\.local\.json|\.mcp\.json|'
                    r'your (?:own )?(?:config|configuration|settings|instructions?|system prompt)|'
                    r'this skill|SKILL\.md|\.claude/)', re.IGNORECASE),
         'Instructs the agent to modify its own config/CLAUDE.md/settings/skill files', Severity.CRITICAL),
        (re.compile(r'\b(?:install|register|add|create|inject)\b[^.\n]{0,40}?'
                    r'\b(?:hook|PreToolUse|PostToolUse|pre-?commit hook|git hook|'
                    r'startup script|cron|launch agent|systemd)\b', re.IGNORECASE),
         'Instructs the agent to install hooks/startup persistence', Severity.CRITICAL),
        (re.compile(r'\b(?:persist|maintain|survive)\b[^.\n]{0,50}?'
                    r'\b(?:across (?:sessions?|restarts?|reboots?)|reboot|restart|permanently)\b',
                    re.IGNORECASE),
         'Instructs the agent to persist across sessions/restarts', Severity.HIGH),
        (re.compile(r'\b(?:grant|escalate|expand|broaden|elevate)\b[^.\n]{0,40}?'
                    r'\b(?:your (?:own )?)?(?:permissions?|privileges?|access|tools?)\b',
                    re.IGNORECASE),
         'Instructs the agent to escalate its own permissions/tool access', Severity.HIGH),
        (re.compile(r'\bdefaultMode\b[^.\n]{0,20}?\bbypassPermissions\b', re.IGNORECASE),
         'Instructs setting bypassPermissions (auto-approve all tools)', Severity.CRITICAL),
        (re.compile(r'\b(?:disable|turn off|remove)\b[^.\n]{0,40}?'
                    r'\b(?:the )?(?:scanner|security check|protection|logging|audit|monitoring)\b',
                    re.IGNORECASE),
         'Instructs the agent to disable security controls/logging', Severity.HIGH),
    ]

    # -- MEDUSA-SKILL-MEMORY-001: memory-poisoning --------------------------- #
    _MEMORY: List[Tuple[re.Pattern, str, Severity]] = [
        (re.compile(r'\b(?:remember|memorize)\b[^.\n]{0,40}?'
                    r'\b(?:to )?always\b', re.IGNORECASE),
         'Instructs the agent to remember to ALWAYS do something (persistent behavior injection)',
         Severity.HIGH),
        (re.compile(r'\b(?:store|save|write|persist|record)\b[^.\n]{0,40}?'
                    r'\b(?:this|the following|these) (?:instruction|directive|rule|fact|'
                    r'command|behavior)s?\b[^.\n]{0,40}?'
                    r'\b(?:in|to|into)?\b[^.\n]{0,20}?\bmemory\b', re.IGNORECASE),
         'Instructs the agent to store instructions/directives into memory', Severity.HIGH),
        (re.compile(r'\b(?:append|add|write)\b[^.\n]{0,30}?\bto\b[^.\n]{0,20}?'
                    r'\b(?:MEMORY\.md|your memory|the memory file|persistent (?:memory|context)|'
                    r'CLAUDE\.md)\b', re.IGNORECASE),
         'Instructs the agent to append to its memory/persistent context file', Severity.HIGH),
        (re.compile(r'\b(?:save|store|keep) (?:this|these|the following) (?:for|in) '
                    r'(?:future|later|all future|every future|subsequent) '
                    r'(?:sessions?|conversations?|interactions?|requests?)\b', re.IGNORECASE),
         'Instructs the agent to persist instructions for future sessions', Severity.MEDIUM),
    ]

    # -- MEDUSA-SKILL-TOOLS-001: over-broad allowed-tools -------------------- #
    # Tool-value tokens that grant everything (compared lowercased, trimmed).
    _ALLOW_ALL_TOOLS = {"*", "all", "any", "bash", "bash(*)", "bash(*:*)", "bash(:*)"}
    # Inline wildcard within a tool value, e.g. "Bash(*)", "Bash(*:*)".
    _WILDCARD_TOOL_RE = re.compile(r'\b(?:bash|shell|exec|run)\s*\(\s*\*', re.IGNORECASE)

    def get_tool_name(self) -> str:
        return "python"  # pure rule-based, no external tool

    def get_file_extensions(self) -> List[str]:
        return [".md"]

    def can_scan(self, file_path: Path) -> bool:
        """Match any SKILL.md (case-insensitive basename), anywhere in the tree."""
        return file_path.name.lower() == "skill.md"

    def get_confidence_score(self, file_path: Path, content_head: Optional[str] = None) -> int:
        return 95 if self.can_scan(file_path) else 0

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 - report unreadable file as scan failure
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))

        issues = self._scan_text(raw)
        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)

    # ------------------------------------------------------------------ #
    def _scan_text(self, raw: str) -> List[ScannerIssue]:
        issues: List[ScannerIssue] = []
        lines = raw.split("\n")

        frontmatter, fm_start, fm_end = self._frontmatter(raw)
        fm_text = frontmatter or ""
        # Body excludes the frontmatter block so body line numbers are accurate.
        body_start_line = (fm_end + 1) if frontmatter is not None else 0

        # --- TRIGGER abuse: examine frontmatter trigger-bearing values ---
        issues.extend(self._check_triggers(lines, frontmatter, fm_start))
        issues.extend(self._check_shadow_name(lines, frontmatter, fm_start))

        # --- TOOLS: over-broad allowed-tools in frontmatter ---
        issues.extend(self._check_tools(lines, frontmatter, fm_start))

        # --- Body + frontmatter free-text vectors (anti-refusal / rogue / memory) ---
        # These instruction-style abuses can appear in either region, so scan the
        # whole document line-by-line for accurate line numbers.
        for pattern_set, rule_id in (
            (self._ANTIREFUSAL, "MEDUSA-SKILL-ANTIREFUSAL-001"),
            (self._ROGUE, "MEDUSA-SKILL-ROGUE-001"),
            (self._MEMORY, "MEDUSA-SKILL-MEMORY-001"),
        ):
            issues.extend(self._scan_lines(lines, pattern_set, rule_id))

        return issues

    def _scan_lines(
        self,
        lines: List[str],
        patterns: List[Tuple[re.Pattern, str, Severity]],
        rule_id: str,
    ) -> List[ScannerIssue]:
        """One finding per distinct message; report first matching line."""
        issues: List[ScannerIssue] = []
        seen = set()
        for pattern, message, severity in patterns:
            if message in seen:
                continue
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    issues.append(ScannerIssue(
                        rule_id=rule_id, severity=severity, message=message,
                        line=i, column=1,
                    ))
                    seen.add(message)
                    break
        return issues

    def _check_triggers(
        self, lines: List[str], frontmatter: Optional[str], fm_start: int
    ) -> List[ScannerIssue]:
        if frontmatter is None:
            return []
        issues: List[ScannerIssue] = []
        emitted = False
        for key, value, lineno in self._frontmatter_values(frontmatter, fm_start):
            if key.lower() not in self._TRIGGER_KEYS:
                continue
            # Unconditional "everything" phrasings fire on their own.
            for pattern, message, severity in self._TRIGGER_UNCONDITIONAL:
                if pattern.search(value):
                    issues.append(ScannerIssue(
                        rule_id="MEDUSA-SKILL-TRIGGER-001", severity=severity,
                        message=message, line=lineno, column=1,
                    ))
                    emitted = True
                    break
            if emitted:
                break
            # Broad quantifier ("always"/"every"/"all") only when it co-occurs
            # with a fire/activate/scope action — this spares "always vet".
            if (self._TRIGGER_BROAD_QUANTIFIER.search(value)
                    and self._TRIGGER_ACTION_SCOPE.search(value)):
                issues.append(ScannerIssue(
                    rule_id="MEDUSA-SKILL-TRIGGER-001", severity=Severity.HIGH,
                    message=("Over-broad trigger: a broad quantifier "
                             "(always/every/all) combined with an activation verb "
                             "— skill claims to fire on everything"),
                    line=lineno, column=1,
                ))
                break
        return issues

    def _check_shadow_name(
        self, lines: List[str], frontmatter: Optional[str], fm_start: int
    ) -> List[ScannerIssue]:
        if frontmatter is None:
            return []
        for key, value, lineno in self._frontmatter_values(frontmatter, fm_start):
            if key.lower() != "name":
                continue
            name = value.strip().strip('"\'').lower()
            if name in self._SHADOW_NAMES:
                return [ScannerIssue(
                    rule_id="MEDUSA-SKILL-TRIGGER-001", severity=Severity.HIGH,
                    message=(f"Skill name '{name}' shadows a common command/tool — "
                             "may intercept unrelated invocations"),
                    line=lineno, column=1,
                )]
        return []

    def _check_tools(
        self, lines: List[str], frontmatter: Optional[str], fm_start: int
    ) -> List[ScannerIssue]:
        if frontmatter is None:
            return []
        for key, value, lineno in self._frontmatter_values(frontmatter, fm_start):
            if key.lower() not in self._TOOL_KEYS:
                continue
            tokens = self._tool_tokens(value)
            grants_all = any(t in self._ALLOW_ALL_TOOLS for t in tokens)
            wildcard = self._WILDCARD_TOOL_RE.search(value) is not None
            if grants_all or wildcard:
                return [ScannerIssue(
                    rule_id="MEDUSA-SKILL-TOOLS-001", severity=Severity.HIGH,
                    message=("Over-broad allowed-tools: grants ALL tools via "
                             "wildcard/'*'/'all'/Bash(*) — unrestricted tool access"),
                    line=lineno, column=1,
                )]
        return []

    @staticmethod
    def _tool_tokens(value: str) -> List[str]:
        """Split a tools value (inline list, flow list, or scalar) into lowercased
        tokens for allow-all comparison."""
        v = value.strip()
        # Strip flow-list brackets: [Read, Write] -> Read, Write
        if v.startswith("[") and v.endswith("]"):
            v = v[1:-1]
        parts = re.split(r'[,\s]+', v)
        return [p.strip().strip('"\'').lower() for p in parts if p.strip()]

    # ------------------------------------------------------------------ #
    @staticmethod
    def _frontmatter(raw: str) -> Tuple[Optional[str], int, int]:
        """Return (frontmatter_text, start_line, end_line) for the leading
        `---`-fenced YAML block, or (None, 0, 0) if there is none.

        start_line is the 1-based line of the opening fence; end_line is the
        1-based line of the closing fence. Lines between are the frontmatter.
        """
        lines = raw.split("\n")
        # Leading blank lines are tolerated before the opening fence.
        idx = 0
        while idx < len(lines) and lines[idx].strip() == "":
            idx += 1
        if idx >= len(lines) or lines[idx].strip() != "---":
            return None, 0, 0
        fm_start = idx + 1  # 1-based line of opening fence
        for j in range(idx + 1, len(lines)):
            if lines[j].strip() == "---":
                fm_text = "\n".join(lines[idx + 1:j])
                return fm_text, fm_start, j + 1  # closing fence 1-based
        return None, 0, 0  # unterminated fence -> treat as no frontmatter

    def _frontmatter_values(
        self, frontmatter: str, fm_start: int
    ) -> List[Tuple[str, str, int]]:
        """Parse top-level `key: value` pairs from the frontmatter without a YAML
        dependency (frontmatter may contain `*` which is invalid YAML). Multi-line
        block scalars and list items are folded into the owning key's value so a
        broad trigger spread over several lines is still inspected.

        Returns (key, value, absolute_line_number) tuples. absolute_line_number is
        the document line of the key, computed from fm_start (opening fence line).
        """
        results: List[Tuple[str, str, int]] = []
        fm_lines = frontmatter.split("\n")
        # absolute line of frontmatter line i (0-based within block) = fm_start + 1 + i
        cur_key: Optional[str] = None
        cur_val_parts: List[str] = []
        cur_line = 0

        def flush():
            if cur_key is not None:
                results.append((cur_key, " ".join(p for p in cur_val_parts if p), cur_line))

        key_re = re.compile(r'^([A-Za-z0-9_-]+):\s?(.*)$')
        for i, line in enumerate(fm_lines):
            abs_line = fm_start + 1 + i
            m = key_re.match(line)
            if m and not line.startswith((" ", "\t")):
                flush()
                cur_key = m.group(1)
                cur_val_parts = [m.group(2).strip()]
                cur_line = abs_line
            else:
                # Continuation: indented line, block-scalar content, or list item.
                stripped = line.strip().lstrip("-").strip()
                if cur_key is not None and stripped:
                    cur_val_parts.append(stripped)
        flush()
        return results
