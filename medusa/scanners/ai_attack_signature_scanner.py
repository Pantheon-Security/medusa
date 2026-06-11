#!/usr/bin/env python3
"""
AI Attack-Signature Scanner — always-on, high-precision.

Most AI scanners (OWASPLLMScanner, PromptLeakageScanner, ...) gate themselves
behind an LLM-context confidence score: if a file has no openai/anthropic/
langchain-style indicators, get_confidence_score() returns 0 and the registry
never runs them (base.py: `if confidence > 0`). That means a jailbreak or
prompt-injection payload sitting in a plain .py/.txt/.json/dataset file is
silently missed — a false negative, which for a security scanner is the
dangerous failure mode.

This scanner closes that gap. It runs on EVERY text file (no LLM-context gate)
and matches a small, curated, high-precision signature set
(medusa/rules/attack_signatures/) — named jailbreaks and classic
instruction-override injections. Precision is the contract: every pattern here
must fire overwhelmingly on real payloads, not generic words, so always-on
matching does not reintroduce false positives.
"""

import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue


class AIAttackSignatureScanner(RuleBasedScanner):
    """Always-on detector for curated high-precision AI attack signatures."""

    # Load ONLY the curated high-precision signature set, by category.
    # (Unannotated form so the rule-coverage wiring check's regex detects it.)
    RULE_CATEGORIES = ['attack_signatures']

    # Safe to run on files over the global size cap: scan_file streams only the
    # first MAX_RULE_SCAN_LINES lines and matches a tiny curated rule set, so a
    # huge dataset (jailbreak corpus) is bounded — not the multi-minute hang the
    # 2MB cap protects against. The parallel scanner routes oversized files to
    # scanners with this flag instead of skipping them.
    supports_large_files = True

    # Broad text coverage — jailbreak/injection payloads show up in code,
    # configs, prompts, and datasets alike. Includes dataset extensions
    # (.jsonl/.csv) so attack corpora are covered.
    _EXTENSIONS = [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".md", ".markdown", ".txt", ".rst",
        ".json", ".jsonl", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf",
        ".html", ".htm", ".ipynb", ".csv", ".sql", ".sh", ".bash",
    ]

    # MEDUSA's own detection-logic source legitimately contains attack strings
    # as rule patterns, scanner regexes, sanitizer test data, and comments.
    # Scanning it would produce self-matches (the "security tool detects its own
    # signatures" effect). Exclude MEDUSA's internal source by path so a
    # self-scan (`medusa scan .`) stays clean. These markers are
    # MEDUSA-package-specific — a user's target repo will not contain them, so
    # real user code is unaffected.
    _SELF_CORPUS_MARKERS = ("medusa/rules/", "medusa/scanners/", "medusa/core/")

    def get_tool_name(self) -> str:
        return "python"  # pure rule-based; no external tool

    def get_file_extensions(self) -> List[str]:
        return self._EXTENSIONS

    def can_scan(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in self._EXTENSIONS:
            return False
        posix = file_path.as_posix()
        return not any(marker in posix for marker in self._SELF_CORPUS_MARKERS)

    def get_confidence_score(self, file_path: Path, content_head: Optional[str] = None) -> int:
        # Always-on for any file we can scan — deliberately NOT gated on
        # LLM-context indicators (that gate is exactly the false-negative bug
        # this scanner exists to fix). A steady low floor keeps it from
        # outranking context-specialised scanners while still always running.
        return 15 if self.can_scan(file_path) else 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        try:
            # Stream only the first MAX_RULE_SCAN_LINES lines so memory and time
            # stay bounded regardless of file size (a 1GB dataset reads just the
            # head). _scan_with_rules applies the same cap; reading lazily here
            # avoids loading a huge file into memory first.
            lines: List[str] = []
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                for idx, line in enumerate(fh):
                    if idx >= self.MAX_RULE_SCAN_LINES:
                        break
                    lines.append(line.rstrip("\n"))
            issues: List[ScannerIssue] = self._scan_with_rules(lines, file_path)
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )
