#!/usr/bin/env python3
"""MEDUSA AP2 (Agent Payments Protocol) Scanner.

Owns every YAML rule whose ID starts with ``MEDUSA-AP2-``. Runs only on
files that look like AP2 code: imports of AP2 SDKs, references to
payment mandates / Verifiable Digital Credentials (VDCs), AP2 transport
headers, or filenames that signal an AP2 integration. The content gate
keeps the 20 AP2 rules from firing on unrelated source files and
generating noise.

Threat model targeted:
    - Google AP2 / Cloud Security Alliance Agent Payments Protocol
    - Payment mandates: signature verification, expiry, nonces, amount caps
    - Verifiable Digital Credentials (VDCs) for agent identity
    - Bridge code between AP2 and MCP / A2A / UCP

The scanner has no inline detection logic; rules live in
``medusa/rules/agent_security/ap2_vulnerabilities.yaml``.
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


class AP2Scanner(RuleBasedScanner):
    """Scan AP2 integration code against MEDUSA-AP2-* rules."""

    RULE_ID_PREFIXES = ["MEDUSA-AP2-"]
    RULE_CATEGORIES: List[str] = []

    _FILE_EXTENSIONS = [".py", ".js", ".ts", ".tsx", ".jsx", ".mjs",
                        ".json", ".yaml", ".yml", ".md", ".java", ".go"]

    # Strong signals: explicit AP2 imports or SDK references.
    _AP2_IMPORT_PATTERNS = [
        r"(?i)\bfrom\s+ap2\b",
        r"(?i)\bimport\s+ap2\b",
        r"(?i)require\(['\"]ap2[^'\"]*['\"]\)",
        r"(?i)from\s+['\"]ap2[^'\"]*['\"]",
        r"(?i)@google[/-]ap2",
        r"(?i)@ap2[/-](?:client|server|sdk|mandate|wallet)",
        r"(?i)ap2[._-]protocol",
    ]

    # Weaker signals: AP2 mandate / VDC vocabulary or AP2 transport
    # headers. Each signal is specific enough to AP2 that hitting one
    # is a high-confidence indicator.
    _AP2_USAGE_PATTERNS = [
        r"(?i)\bpayment[._-]mandate\b",
        r"(?i)\bsign(?:ed|ing)\s+mandate\b",
        r"(?i)\bcart[._-]mandate\b",
        r"(?i)\bintent[._-]mandate\b",
        r"(?i)x-ap2-(?:signature|nonce|mandate|wallet)",
        r"(?i)\bvdc[._-](?:issuer|holder|verifier)",
        r"(?i)verifiable[._-]digital[._-]credential",
        r"(?i)checkout\.session\b",  # AP2 sessions
    ]

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return list(self._FILE_EXTENSIONS)

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self._FILE_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        if not self.can_scan(file_path):
            return 0

        try:
            if content_head is not None:
                content = content_head
            else:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(10000)

            for pattern in self._AP2_IMPORT_PATTERNS:
                if re.search(pattern, content):
                    return 90

            for pattern in self._AP2_USAGE_PATTERNS:
                if re.search(pattern, content):
                    return 70

            name = file_path.name.lower()
            if "ap2" in name or "agent-payments" in name or "agentic-payments" in name:
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

        if not self._is_ap2_file(content, file_path):
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

    def _is_ap2_file(self, content: str, file_path: Path) -> bool:
        for pattern in self._AP2_IMPORT_PATTERNS + self._AP2_USAGE_PATTERNS:
            if re.search(pattern, content):
                return True
        name = file_path.name.lower()
        if ("ap2" in name or "agent-payments" in name) and file_path.suffix.lower() in self._FILE_EXTENSIONS:
            return True
        return False
