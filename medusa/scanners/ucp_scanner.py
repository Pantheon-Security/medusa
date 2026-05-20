#!/usr/bin/env python3
"""MEDUSA UCP (Universal Commerce Protocol) Scanner.

Owns every YAML rule whose ID starts with ``MEDUSA-UCP-``. Runs only on
files that look like UCP code: imports of UCP SDKs, references to UCP
discovery endpoints (``/.well-known/ucp``), UCP config keys, or filenames
that signal UCP integration. The content gate keeps the 33 UCP rules
from firing on unrelated Python/JS/TS files and producing noise.

Threat model targeted:
    - Google UCP (Universal Commerce Protocol) — launched 2026-01-11
    - AP2 bridge code that interacts with UCP discovery / mandates
    - Shopify / Stripe / PayPal / Walmart / Target UCP integrations

The scanner adds no inline patterns of its own; all detection logic lives
in ``medusa/rules/agent_security/ucp_vulnerabilities.yaml``. The class
exists to (a) own the rule prefix so the rules don't fall to the
catch-all scanner, and (b) gate execution on a content check so the
patterns don't fire across the whole project.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import (
    RuleBasedScanner,
    ScannerIssue,
    ScannerResult,
    filter_contextual_fps,
)


class UCPScanner(RuleBasedScanner):
    """Scan UCP integration code against MEDUSA-UCP-* rules."""

    # Claim every UCP rule by ID prefix. We deliberately don't claim
    # categories — UCP shares categories (authentication, authorization,
    # transport_security, ...) with several other scanners, and claiming
    # them here would cause duplicate findings.
    RULE_ID_PREFIXES = ["MEDUSA-UCP-"]
    RULE_CATEGORIES: List[str] = []

    # File extensions the scanner inspects. JSON / YAML are included so
    # we can catch UCP discovery configs and ``.well-known/ucp`` content.
    _FILE_EXTENSIONS = [".py", ".js", ".ts", ".tsx", ".jsx", ".mjs",
                        ".json", ".yaml", ".yml", ".md", ".java", ".go"]

    # Strong signals: UCP-specific imports, SDK references, or the
    # canonical discovery endpoint.
    _UCP_IMPORT_PATTERNS = [
        r"(?i)\bfrom\s+ucp\b",
        r"(?i)\bimport\s+ucp\b",
        r"(?i)require\(['\"]ucp[^'\"]*['\"]\)",
        r"(?i)from\s+['\"]ucp[^'\"]*['\"]",
        r"(?i)@google[/-]ucp",
        r"(?i)@ucp[/-](?:client|server|sdk|agent|merchant)",
    ]

    # Weaker signals: UCP discovery / config keys that strongly suggest
    # a UCP integration even without an SDK import.
    _UCP_USAGE_PATTERNS = [
        r"\.well-known/ucp\b",
        r"(?i)ucp[_-](?:endpoint|discovery|agent|merchant|catalog|mandate)",
        r"(?i)\"ucp\.(?:discovery|agent|merchant|catalog|mandate)",
        r"(?i)UCP-Agent\s*[:=]",
        r"(?i)idempotency[-_]key",  # UCP/AP2 transaction header
        r"(?i)x-ucp-(?:agent|merchant|signature)",
    ]

    def get_tool_name(self) -> str:
        return "python"  # built-in scanner

    def get_file_extensions(self) -> List[str]:
        return list(self._FILE_EXTENSIONS)

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self._FILE_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return high confidence for files that import UCP SDKs."""
        if not self.can_scan(file_path):
            return 0

        try:
            if content_head is not None:
                content = content_head
            else:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(10000)

            for pattern in self._UCP_IMPORT_PATTERNS:
                if re.search(pattern, content):
                    return 90

            for pattern in self._UCP_USAGE_PATTERNS:
                if re.search(pattern, content):
                    return 70

            name = file_path.name.lower()
            if "ucp" in name or "agent-commerce" in name:
                return 50

            return 0
        except OSError:
            return 0

    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as exc:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"read failed: {exc}",
            )

        if not self._is_ucp_file(content, file_path):
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        lines = content.split("\n")
        issues: List[ScannerIssue] = list(self._scan_with_rules(lines, file_path))
        issues = filter_contextual_fps(issues, file_path, content)

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )

    def _is_ucp_file(self, content: str, file_path: Path) -> bool:
        """File-gate: must look like UCP code before rules apply."""
        for pattern in self._UCP_IMPORT_PATTERNS + self._UCP_USAGE_PATTERNS:
            if re.search(pattern, content):
                return True
        # Filename-only signal is intentionally weak — require at least
        # the filename to mention UCP if no content signal hit. Keeps
        # noise off random `.py` files.
        name = file_path.name.lower()
        if "ucp" in name and file_path.suffix.lower() in self._FILE_EXTENSIONS:
            return True
        return False
