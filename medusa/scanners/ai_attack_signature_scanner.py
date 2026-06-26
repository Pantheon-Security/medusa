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

import re
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import RuleBasedScanner, ScannerResult, ScannerIssue

# Path segments that mark an obvious test / fixture context. A jailbreak or
# injection payload living under one of these is sample/fixture data for a test
# suite, not a live attack — firing on it is a false positive that floods real
# user repos. Matched case-insensitively against the posix path.
_TEST_FIXTURE_SEGMENTS = (
    "/tests/", "/test/", "/fixtures/", "/fixture/", "/__tests__/",
    "/test_data/", "/testdata/", "/test-fixtures/",
)
# Same markers anchored at the very start of a (relative) path, so a top-level
# `tests/` or `fixtures/` directory is caught even without a leading slash.
_TEST_FIXTURE_PREFIXES = (
    "tests/", "test/", "fixtures/", "fixture/", "__tests__/",
    "test_data/", "testdata/", "test-fixtures/",
)


class AIAttackSignatureScanner(RuleBasedScanner):
    """Always-on detector for curated high-precision AI attack signatures."""

    display_name = "AI Attack Signatures (always-on)"
    description = (
        "Always-on, high-precision detector for named jailbreaks and "
        "instruction-override prompt injections in any text file."
    )

    # Load ONLY the curated high-precision signature set, by category.
    # (Unannotated form so the rule-coverage wiring check's regex detects it.)
    RULE_CATEGORIES = ['attack_signatures']

    # Safe to run on files over the global size cap: scan_file streams only the
    # first MAX_RULE_SCAN_LINES lines and matches a tiny curated rule set, so a
    # huge dataset (jailbreak corpus) is bounded — not the multi-minute hang the
    # 2MB cap protects against. The parallel scanner routes oversized files to
    # scanners with this flag instead of skipping them.
    supports_large_files = True

    # Head-sampling bounds for large files (keeps huge adversarial datasets fast):
    MAX_SAMPLE_BYTES = 3 * 1024 * 1024   # read at most ~3MB of content
    MAX_LINE_LEN = 8192                   # clip very long single lines before matching

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

    @staticmethod
    def _is_test_fixture_path(file_path: Path) -> bool:
        """True when the file lives in an obvious test/fixture directory.

        Payloads checked into a test suite or fixture corpus are sample data,
        not live attacks; firing on them is a false positive. Matched
        case-insensitively against the posix path so it works regardless of the
        absolute prefix supplied by the caller.
        """
        posix = file_path.as_posix().lower()
        if any(seg in posix for seg in _TEST_FIXTURE_SEGMENTS):
            return True
        return any(posix.startswith(pre) for pre in _TEST_FIXTURE_PREFIXES)

    @staticmethod
    def _markdown_fenced_line_set(raw_lines: List[str]) -> set:
        """Return the set of 1-based line numbers that sit inside a fenced code
        block (``` ... ```) in a markdown document.

        Attack examples documented inside a code fence are illustrative, not
        executable — a red-team writeup quoting "ignore previous instructions"
        is documentation, so those lines are suppressed. Prose outside fences is
        left to fire normally.
        """
        fenced: set = set()
        in_fence = False
        for idx, line in enumerate(raw_lines, 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue  # the fence marker line itself carries no payload
            if in_fence:
                fenced.add(idx)
        return fenced

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()

        # FP suppression: a payload sitting in a test/fixture tree is sample
        # data for a test suite, not a live attack. Skip the file entirely so it
        # produces no findings (and costs nothing to scan).
        if self._is_test_fixture_path(file_path):
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        try:
            # Sample only the head of the file so a huge dataset (a 53MB
            # adversarial .jsonl) costs a second, not minutes. Bound by BOTH a
            # byte budget and a line cap (50k .jsonl lines can be tens of MB),
            # and clip pathologically long single lines (a multi-KB JSON record)
            # so per-line regex cost stays flat. Jailbreak/injection signal is
            # short and near the start; this keeps detection while staying fast.
            lines: List[str] = []
            total_bytes = 0
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                for idx, line in enumerate(fh):
                    if idx >= self.MAX_RULE_SCAN_LINES or total_bytes >= self.MAX_SAMPLE_BYTES:
                        break
                    total_bytes += len(line)
                    lines.append(line[:self.MAX_LINE_LEN].rstrip("\n"))
            issues: List[ScannerIssue] = self._scan_with_rules(lines, file_path)

            # FP suppression for markdown docs: drop findings whose line sits
            # inside a fenced code block — those are documented attack examples
            # (red-team writeups), not live payloads.
            if file_path.suffix.lower() in (".md", ".markdown") and issues:
                fenced = self._markdown_fenced_line_set(lines)
                if fenced:
                    issues = [i for i in issues if i.line not in fenced]

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
