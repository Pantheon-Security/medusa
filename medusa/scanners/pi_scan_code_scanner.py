#!/usr/bin/env python3
"""MEDUSA PI-SCAN code scanner.

Owns every YAML rule whose ID starts with ``MEDUSA-PI-SCAN-``. Runs only
on Python / JS / TS files that show evidence of LLM usage: an import of
a major LLM SDK, or local construction of chat messages / completion
calls. The content gate keeps the 12 PI-SCAN rules from firing on
unrelated source files.

Wiring history (2026-05-20):
    Prior to this scanner the PI-SCAN rules were claimed only by
    ``AIContextScanner`` (prefix ``MEDUSA-PI-``), whose ``can_scan()``
    rejects ``.py`` / ``.js`` / ``.ts`` — so the rules never fired on
    the code files their patterns target. ``AIContextScanner`` still
    loads the rules but is a no-op for code; this scanner is the one
    that actually applies them.

The scanner has no inline patterns; all detection logic lives in
``medusa/rules/prompt_injection/prompt_injection_scanner.yaml``.
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


class PISCANCodeScanner(RuleBasedScanner):
    """Apply MEDUSA-PI-SCAN-* rules to LLM-bearing code files."""

    # Claim by prefix only — categories are shared with other scanners.
    RULE_ID_PREFIXES = ["MEDUSA-PI-SCAN-"]
    RULE_CATEGORIES: List[str] = []

    _FILE_EXTENSIONS = [".py", ".js", ".ts", ".tsx", ".jsx", ".mjs"]

    # LLM-SDK imports / call sites. If a file shows any of these, we treat
    # it as LLM-bearing code and apply the PI-SCAN rules.
    _LLM_PATTERNS = [
        # Python imports
        r"(?i)\bimport\s+(?:openai|anthropic|langchain|llama_index|llamaindex|cohere|vllm|groq|mistralai|google\.generativeai|ollama)\b",
        r"(?i)\bfrom\s+(?:openai|anthropic|langchain|llama_index|llamaindex|cohere|vllm|groq|mistralai|google\.generativeai|ollama)\b",
        # JS/TS imports
        r"(?i)\bfrom\s+['\"](?:openai|@anthropic-ai/sdk|@langchain/[a-z-]+|cohere-ai|@google/generative-ai|ollama)['\"]",
        r"(?i)require\(['\"](?:openai|@anthropic-ai/sdk|@langchain/[a-z-]+|cohere-ai|@google/generative-ai|ollama)['\"]\)",
        # Local construction of chat messages / completion calls
        r"(?i)(?:chat\.completions|ChatCompletion)\.create\b",
        r"(?i)\b(?:client|openai|anthropic)\.(?:completions|messages|chat)\.create\b",
        r"(?i)\b(?:messages|conversation)\.(?:append|push)\(\s*\{[^}]*[\"']role[\"']\s*:",
        r"(?i)\b(?:HumanMessage|SystemMessage|AIMessage|ChatPromptTemplate)\b",
        r"(?i)\b(?:llm|chat|chain|agent)\.invoke\b",
    ]

    def get_tool_name(self) -> str:
        return "python"  # built-in scanner

    def get_file_extensions(self) -> List[str]:
        return list(self._FILE_EXTENSIONS)

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in self._FILE_EXTENSIONS

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """High confidence for code files with LLM SDK usage."""
        if not self.can_scan(file_path):
            return 0

        try:
            if content_head is not None:
                content = content_head
            else:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(10000)

            for pattern in self._LLM_PATTERNS:
                if re.search(pattern, content):
                    return 85
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

        if not self._is_llm_file(content):
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

    def _is_llm_file(self, content: str) -> bool:
        """File-gate: must look like LLM-bearing code before rules apply."""
        for pattern in self._LLM_PATTERNS:
            if re.search(pattern, content):
                return True
        return False
