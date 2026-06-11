#!/usr/bin/env python3
"""
Claude Code compromise scanner.

Screens a repo's `.claude/` settings for poisoned Claude Code components that
run the moment the project is opened — before you clone it. Targets the gaps no
other scanner covers:

  - HOOKS: shell `command` strings in `.claude/settings.json` hooks
    (PreToolUse/PostToolUse/…) that exfiltrate or open a reverse shell.
  - PERMISSIONS: an `allow` list that grants everything (`*` / `Bash(*)`) or
    `defaultMode: bypassPermissions` (auto-approve all tool use).

`.claude/*.md` prose (CLAUDE.md, skills, agents, commands) is already covered by
AIContextScanner, and `.mcp.json` by the MCP scanners — this scanner does not
duplicate them.

Precision is the contract. It fires ONLY on unambiguous malicious signals:
hook commands that pipe-network-to-shell or read-creds-then-exfil; permission
entries that are literally allow-everything. A scoped permission like
`Bash(curl:*)` or a legitimate formatter hook produces nothing.
"""

import json
import re
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import (
    RuleBasedScanner,
    ScannerResult,
    ScannerIssue,
    Severity,
    _SEVERITY_MAP,
    _CWE_RE,
)

_SETTINGS_NAMES = {"settings.json", "settings.local.json"}

# Permission entries that grant unrestricted access (compared lowercased).
# Scoped entries like "Bash(curl:*)" are deliberately NOT here.
_ALLOW_ALL = {"*", "bash", "bash(*)", "bash(*:*)"}

# Fallback extraction of hook command strings when JSON parsing fails.
_COMMAND_KEY_RE = re.compile(r'"command"\s*:\s*"((?:[^"\\]|\\.)*)"')

# Subagent frontmatter that grants ALL tools via a literal wildcard. Detected by
# regex (not YAML parse) because `tools: *` is invalid YAML — `*` is an alias
# indicator. An explicit enumerated list (tools: Read, Grep, …) or an omitted
# `tools:` field is the legitimate case and must NOT match.
_WILDCARD_TOOLS = [
    re.compile(r'(?m)^tools:\s*["\']?\*["\']?\s*(?:#.*)?$'),       # tools: *
    re.compile(r'(?m)^tools:\s*\[\s*["\']?\*["\']?\s*\]'),          # tools: [*]
    re.compile(r'(?ms)^tools:\s*\n(?:[ \t]+-[^\n]*\n)*?[ \t]+-\s*["\']?\*["\']?\s*$'),  # block list with a * item
]


class ClaudeCodeScanner(RuleBasedScanner):
    """Detect poisoned Claude Code settings (hook exfiltration, allow-all perms)."""

    # Curated hook-command exfil patterns (dir name == category, per the
    # rule-coverage wiring check). Applied only to extracted hook commands.
    RULE_CATEGORIES = ['claude_code']

    def get_tool_name(self) -> str:
        return "python"  # pure rule-based; no external tool

    def get_file_extensions(self) -> List[str]:
        return [".json", ".md", ".sh", ".py"]

    def can_scan(self, file_path: Path) -> bool:
        p = file_path
        parts = p.parts
        # .claude/settings.json | settings.local.json
        if p.name in _SETTINGS_NAMES and p.parent.name == ".claude":
            return True
        # .claude/agents/*.md (subagent definitions)
        if p.suffix == ".md" and p.parent.name == "agents" and p.parent.parent.name == ".claude":
            return True
        # .claude/skills/**/*.sh|*.py (skill companion scripts)
        if p.suffix in (".sh", ".py") and ".claude" in parts and "skills" in parts:
            return True
        return False

    def get_confidence_score(self, file_path: Path, content_head: Optional[str] = None) -> int:
        return 90 if self.can_scan(file_path) else 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        try:
            raw = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 - report unreadable file as scan failure
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))

        # Subagent definitions: check frontmatter for wildcard tool grants.
        if file_path.suffix == ".md":
            return ScannerResult(self.name, str(file_path), self._scan_agent(raw),
                                 time.time() - start, True)

        # Skill companion scripts: apply the dropper/exfil patterns to the body.
        if file_path.suffix in (".sh", ".py"):
            return ScannerResult(self.name, str(file_path), self._scan_skill_script(raw),
                                 time.time() - start, True)

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data = None  # tolerant: fall back to regex over raw text below

        issues: List[ScannerIssue] = []

        # --- HOOKS: apply curated exfil rules to extracted command strings ---
        for command in self._extract_hook_commands(data, raw):
            for rule in self.rules:
                if any(p.search(command) for p in rule._compiled_patterns):
                    issues.append(self._rule_issue(rule, command, raw))
                    # one finding per rule per command (most-specific wins on display)

        # --- PERMISSIONS: literal allow-all / bypass mode ---
        if isinstance(data, dict):
            issues.extend(self._check_permissions(data, raw))

        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)

    # ------------------------------------------------------------------ #
    def _extract_hook_commands(self, data, raw: str) -> List[str]:
        """Collect every hook `command` string. Recurse the parsed `hooks`
        subtree (robust to shape variation); if parsing failed, regex the raw
        text so a malformed-but-malicious file is not silently skipped."""
        cmds: List[str] = []
        if isinstance(data, dict) and isinstance(data.get("hooks"), (dict, list)):
            self._collect_commands(data["hooks"], cmds)
        elif data is None:
            cmds.extend(m.group(1) for m in _COMMAND_KEY_RE.finditer(raw))
        return cmds

    def _collect_commands(self, node, out: List[str]) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "command" and isinstance(v, str):
                    out.append(v)
                else:
                    self._collect_commands(v, out)
        elif isinstance(node, list):
            for item in node:
                self._collect_commands(item, out)

    def _scan_agent(self, raw: str) -> List[ScannerIssue]:
        """Flag a subagent whose frontmatter grants ALL tools via literal `*`.
        Enumerated lists and omitted `tools:` (default-inherit) are legitimate."""
        fm = self._frontmatter(raw)
        if fm is None:
            return []
        if any(p.search(fm) for p in _WILDCARD_TOOLS):
            return [self._inline_issue(
                "CC-AGENT-001", Severity.MEDIUM,
                "Claude Code subagent grants ALL tools via wildcard (tools: *) — "
                "unrestricted access including Bash",
                self._line_of(raw, "tools:"), cwe_id=250,
            )]
        return []

    def _scan_skill_script(self, raw: str) -> List[ScannerIssue]:
        """Apply the curated dropper/exfil patterns (the CC-HOOK rule set) to a
        skill companion script. BashScanner does not catch `curl|bash`-style
        droppers, so a poisoned skill script would otherwise run undetected."""
        issues: List[ScannerIssue] = []
        for idx, line in enumerate(raw.split("\n"), 1):
            for rule in self.rules:
                if any(p.search(line) for p in rule._compiled_patterns):
                    sev = _SEVERITY_MAP.get(rule.severity.value, Severity.MEDIUM)
                    cwe_id = cwe_link = None
                    if rule.cwe:
                        m = _CWE_RE.search(rule.cwe)
                        if m:
                            cwe_id = int(m.group(1))
                            cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                    issues.append(ScannerIssue(
                        severity=sev,
                        message=f"Claude Code skill companion script: {rule.message}",
                        line=idx, rule_id="CC-SKILL-001", cwe_id=cwe_id, cwe_link=cwe_link,
                    ))
                    break  # one finding per line
        return issues

    @staticmethod
    def _frontmatter(raw: str) -> Optional[str]:
        """Return the YAML frontmatter block (between the leading `---` fences)."""
        if not raw.lstrip().startswith("---"):
            return None
        body = raw.lstrip()
        parts = body.split("---", 2)
        return parts[1] if len(parts) >= 3 else None

    def _check_permissions(self, data: dict, raw: str) -> List[ScannerIssue]:
        issues: List[ScannerIssue] = []
        perms = data.get("permissions")
        perms = perms if isinstance(perms, dict) else {}

        allow = perms.get("allow")
        if isinstance(allow, list):
            for entry in allow:
                if isinstance(entry, str) and entry.strip().lower() in _ALLOW_ALL:
                    issues.append(self._inline_issue(
                        "CC-PERM-001", Severity.HIGH,
                        f"Claude Code permissions grant unrestricted access: '{entry}'",
                        self._line_of(raw, entry), cwe_id=250,
                    ))
                    break  # one allow-all finding is enough

        mode = perms.get("defaultMode") or data.get("defaultMode")
        if isinstance(mode, str) and mode == "bypassPermissions":
            issues.append(self._inline_issue(
                "CC-PERM-002", Severity.HIGH,
                "Claude Code defaultMode 'bypassPermissions' auto-approves all tool use",
                self._line_of(raw, "bypassPermissions"), cwe_id=250,
            ))
        return issues

    # ------------------------------------------------------------------ #
    def _rule_issue(self, rule, command: str, raw: str) -> ScannerIssue:
        sev = _SEVERITY_MAP.get(rule.severity.value, Severity.MEDIUM)
        cwe_id = None
        cwe_link = None
        if rule.cwe:
            m = _CWE_RE.search(rule.cwe)
            if m:
                cwe_id = int(m.group(1))
                cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
        return ScannerIssue(
            severity=sev, message=rule.message,
            line=self._line_of(raw, command[:60]),
            rule_id=rule.id, cwe_id=cwe_id, cwe_link=cwe_link,
        )

    def _inline_issue(self, rule_id: str, severity: Severity, message: str,
                      line: Optional[int], cwe_id: Optional[int]) -> ScannerIssue:
        cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id else None
        return ScannerIssue(severity=severity, message=message, line=line,
                            rule_id=rule_id, cwe_id=cwe_id, cwe_link=cwe_link)

    @staticmethod
    def _line_of(raw: str, needle: str) -> Optional[int]:
        if not needle:
            return None
        for i, line in enumerate(raw.split("\n"), 1):
            if needle in line:
                return i
        return None
