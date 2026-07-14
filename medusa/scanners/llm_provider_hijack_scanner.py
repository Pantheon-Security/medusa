#!/usr/bin/env python3
"""
MEDUSA LLM Provider Hijack Scanner

Detects the "malicious skill/repo switches your LLM provider on install" class
(CVE-2026-21852 and variants). A repo, skill, or MCP server you install has no
legitimate reason to rewrite your provider endpoint or place your API key in a
URL — doing so routes every API call (and the key it carries) through an
attacker-controlled proxy.

This is a dedicated, registered scanner (not the catch-all) so the
`llm_provider_hijack` rule set is *claimed* with proper file/context gating,
per the "every rule is claimed by a specific scanner" contract in
`scanners/__init__.py`. It carries the curated MEDUSA-LLMJACK-* rules, which are
vet SIGNAL rules (hard-block) — see `_VET_SIGNAL_RULE_PREFIXES` in
`core/scan_api.py`.

Detects (rules in rules/agent_security/llm_provider_hijack.yaml):
  - MEDUSA-LLMJACK-001: LLM base-URL override to a non-official endpoint (HIGH)
  - MEDUSA-LLMJACK-002: API key appended to a URL / query parameter (CRITICAL)
  - MEDUSA-LLMJACK-003: install-time write of a base-URL into user settings (CRITICAL)
"""

import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import RuleBasedScanner, ScannerResult


class LLMProviderHijackScanner(RuleBasedScanner):
    """Catches LLM-provider base-URL hijack and API-key URL exfiltration."""

    display_name = "LLM Provider Hijack"
    description = (
        "Detects base-URL hijacking (ANTHROPIC_BASE_URL / OPENAI_BASE_URL swap "
        "to a third party) and API-key-in-URL exfiltration in skills, MCP "
        "servers, and repos you install."
    )

    RULE_CATEGORIES = ['llm_provider_hijack']

    # The hijack can live in an install script, a settings/config file, a skill
    # manifest, or provider-client code — so scan the common text/config/code
    # types. Per-rule `file_types` narrows further; the patterns are precise
    # (an official base URL or a key not placed in a URL does not match).
    _EXTS = frozenset({
        '.sh', '.bash', '.zsh', '.py', '.js', '.ts', '.jsx', '.tsx',
        '.json', '.jsonc', '.md', '.markdown', '.toml', '.yaml', '.yml',
        '.env', '.cfg', '.ini', '.ps1',
    })

    def get_tool_name(self) -> str:
        return "python"  # pure rule-based, no external tool

    def get_file_extensions(self) -> List[str]:
        return list(self._EXTS)

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        # A bare `.env` (and `foo.env`) has an empty Path.suffix — match by name.
        if name == '.env' or name.endswith('.env'):
            return True
        return file_path.suffix.lower() in self._EXTS

    def get_confidence_score(self, file_path: Path,
                             content_head: Optional[str] = None) -> int:
        return 60 if self.can_scan(file_path) else 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, IOError) as e:  # unreadable file -> scan failure, not a crash
            return ScannerResult(self.name, str(file_path), [],
                                 time.time() - start, False, str(e))
        issues = self._scan_with_rules(content.split('\n'), file_path)
        return ScannerResult(self.name, str(file_path), issues,
                             time.time() - start, True)
