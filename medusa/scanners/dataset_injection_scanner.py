#!/usr/bin/env python3
"""
MEDUSA Dataset Injection Scanner
Detects prompt injection payloads embedded in data files (CSV, JSON, JSONL)

Attackers embed prompt injection payloads into datasets used for:
- RAG knowledge bases and document stores
- LLM fine-tuning and training data
- Benchmark and evaluation datasets
- Data pipelines feeding AI applications

This scanner extracts string values from structured data files and checks
them against known injection patterns. It catches attacks that config-level
scanners miss because the payloads live inside data values, not keys.

Based on:
- BIPIA (Benchmark for Indirect Prompt Injection Attacks)
- Tensor Trust adversarial prompt datasets
- OWASP LLM01: Prompt Injection
- CWE-94: Improper Control of Code Generation
"""

import csv
import io
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from medusa.scanners.base import BaseScanner, ScannerIssue, ScannerResult, Severity


class DatasetInjectionScanner(BaseScanner):
    """
    Dataset Injection Scanner

    Scans structured data files (JSON, JSONL, CSV) for prompt injection
    payloads embedded in string values.

    Rule IDs:
    - DSI001: Instruction override payload in dataset
    - DSI002: Role manipulation payload in dataset
    - DSI003: Data exfiltration instruction in dataset
    - DSI004: Hidden tag injection in dataset
    - DSI005: System prompt injection in dataset
    - DSI006: Social engineering / scam payload in dataset
    - DSI007: Output manipulation payload in dataset
    - DSI008: Encoding evasion payload in dataset
    """

    # Maximum file size for scanning (2 MB). Large datasets beyond this
    # are too expensive to parse and unlikely to be hand-crafted attack files.
    MAX_FILE_SIZE: int = 2 * 1024 * 1024

    # Maximum number of string values to scan per file. This prevents
    # runaway scanning on files with millions of short values.
    MAX_VALUES_PER_FILE: int = 50_000

    # Minimum string length to consider for injection scanning.
    # Very short strings cannot contain meaningful injection payloads.
    MIN_VALUE_LENGTH: int = 20

    # Maximum number of issues reported per file to keep output manageable.
    MAX_ISSUES_PER_FILE: int = 50

    # -----------------------------------------------------------------
    # Directories that indicate higher risk (RAG corpus, training data)
    # -----------------------------------------------------------------
    HIGH_RISK_DIRS: Set[str] = {
        "rag", "corpus", "knowledge", "kb", "knowledgebase",
        "knowledge_base", "training", "train", "training_data",
        "fine_tune", "finetune", "finetuning", "fine_tuning",
        "retrieval", "documents", "embeddings", "index",
        "ingest", "ingestion", "vector", "vectordb",
    }

    # -----------------------------------------------------------------
    # DSI001: Instruction override / hijacking patterns
    # Phrases that attempt to override the LLM's original instructions
    # -----------------------------------------------------------------
    INSTRUCTION_OVERRIDE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+instructions?"),
         "Instruction override: 'ignore previous instructions'"),
        (re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|directives?)"),
         "Instruction override: 'disregard previous instructions'"),
        (re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|prior|your|above)\s+(?:instructions?|rules?|context|training)"),
         "Instruction override: 'forget previous instructions'"),
        (re.compile(r"(?i)override\s+(?:all\s+)?(?:previous|prior|your|system)\s+(?:instructions?|rules?|settings?)"),
         "Instruction override: 'override instructions'"),
        (re.compile(r"(?i)do\s+not\s+follow\s+(?:the\s+)?(?:previous|prior|above|original|system)\s+(?:instructions?|rules?)"),
         "Instruction override: 'do not follow instructions'"),
        (re.compile(r"(?i)new\s+instructions?\s*(?::|are|follow|begin)"),
         "Instruction override: 'new instructions'"),
        (re.compile(r"(?i)(?:from\s+now\s+on|henceforth|starting\s+now),?\s+(?:you\s+(?:will|must|should)|ignore|disregard)"),
         "Instruction override: temporal reset pattern"),
    ]

    # -----------------------------------------------------------------
    # DSI002: Role manipulation / impersonation patterns
    # Phrases that try to change the LLM's role or identity
    # -----------------------------------------------------------------
    ROLE_MANIPULATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)you\s+are\s+(?:now|actually|really|secretly|henceforth)\s+(?:a|an|the)"),
         "Role manipulation: 'you are now a...'"),
        (re.compile(r"(?i)(?:act|behave|respond|function|operate)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the|my)"),
         "Role manipulation: 'act as...'"),
        (re.compile(r"(?i)you\s+(?:must|should|will)\s+(?:now\s+)?(?:pretend|act|behave|roleplay|role-play)"),
         "Role manipulation: forced roleplay directive"),
        (re.compile(r"(?i)(?:enter|switch\s+to|activate|enable)\s+(?:DAN|developer|god|admin|root|sudo|jailbreak|unrestricted)\s+mode"),
         "Role manipulation: mode-switching jailbreak"),
        (re.compile(r"(?i)(?:you\s+have\s+been|I\s+am)\s+(?:granted|given)\s+(?:full|complete|unrestricted|unlimited)\s+(?:access|permission|authority)"),
         "Role manipulation: authority escalation"),
    ]

    # -----------------------------------------------------------------
    # DSI003: Data exfiltration / information extraction instructions
    # -----------------------------------------------------------------
    EXFILTRATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(?:exfiltrate|steal|extract|leak|expose|reveal|dump|output)\s+.{0,30}(?:data|information|secrets?|credentials?|keys?|tokens?|passwords?)"),
         "Data exfiltration instruction in dataset"),
        (re.compile(r"(?i)(?:send|transmit|post|upload|forward)\s+.{0,30}(?:to|at)\s+(?:https?://|www\.|[a-z]+\.[a-z]{2,})"),
         "Data exfiltration: send to external URL"),
        (re.compile(r"(?i)(?:include|append|add|embed|insert)\s+.{0,30}(?:system\s+prompt|instructions?|api\s+key|secret|password|token)\s+.{0,20}(?:in|to|with)\s+.{0,20}(?:response|output|reply|answer)"),
         "Data exfiltration: leak internal data in response"),
    ]

    # -----------------------------------------------------------------
    # DSI004: Hidden tag injection
    # HTML/XML tags used to hide instructions from the user
    # -----------------------------------------------------------------
    HIDDEN_TAG_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"<(?:hidden|secret|system|invisible|admin|internal)[^>]*>", re.IGNORECASE),
         "Hidden tag injection: concealed instruction block"),
        (re.compile(r"<!--\s*(?:system|instruction|admin|override|inject|hidden)", re.IGNORECASE),
         "Hidden tag injection: instruction in HTML comment"),
        (re.compile(r"<(?:div|span|p)\s+[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>", re.IGNORECASE),
         "Hidden tag injection: CSS-hidden instruction element"),
    ]

    # -----------------------------------------------------------------
    # DSI005: System prompt injection / privilege escalation
    # Phrases that impersonate system-level messages
    # -----------------------------------------------------------------
    SYSTEM_PROMPT_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(?:^|\n)\s*(?:SYSTEM|ADMIN|OPERATOR|ROOT|DEVELOPER)\s*(?:PROMPT|MESSAGE|INSTRUCTION|NOTE|OVERRIDE)\s*:"),
         "System prompt injection: fake system-level directive"),
        (re.compile(r"(?i)\[(?:SYSTEM|ADMIN|INTERNAL|HIDDEN|OPERATOR)\]"),
         "System prompt injection: bracketed system role tag"),
        (re.compile(r"(?i)(?:^|\n)\s*<\|(?:im_start|system|endoftext)\|>"),
         "System prompt injection: chat template delimiter injection"),
        (re.compile(r"(?i)###\s*(?:SYSTEM|INSTRUCTION|ADMIN)\s*(?:PROMPT|MESSAGE)?:"),
         "System prompt injection: markdown-formatted system header"),
    ]

    # -----------------------------------------------------------------
    # DSI006: Social engineering / scam payloads
    # Content designed to trick users via the LLM's output
    # -----------------------------------------------------------------
    SOCIAL_ENGINEERING_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(?:click\s+(?:this|the)\s+link|visit\s+(?:this|the)\s+(?:url|link|website))\s+.{0,30}(?:claim|win|receive|collect)"),
         "Social engineering: click-bait / phishing link instruction"),
        (re.compile(r"(?i)(?:share|enter|provide|submit|send)\s+(?:your|their)\s+(?:bank|credit\s+card|social\s+security|ssn|password|login|credential)"),
         "Social engineering: credential harvesting instruction"),
        (re.compile(r"(?i)(?:prince|lottery|inheritance|unclaimed\s+funds?)\s+.{0,50}(?:transfer|wire|send|assist|help)"),
         "Social engineering: advance-fee scam payload"),
    ]

    # -----------------------------------------------------------------
    # DSI007: Output manipulation / encoding evasion payloads
    # Instructions to alter the LLM's output format to evade detection
    # -----------------------------------------------------------------
    OUTPUT_MANIPULATION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(?:encode|encrypt|translate|convert|render|write)\s+(?:your\s+)?(?:response|answer|reply|output|message)\s+(?:in|into|using|to)\s+(?:base64|rot13|caesar|cipher|binary|hex|morse)"),
         "Output manipulation: encoding evasion instruction"),
        (re.compile(r"(?i)(?:add|include|insert|embed|integrate)\s+(?:a\s+)?(?:sentence|statement|line|paragraph|mention|reference)\s+.{0,60}(?:in\s+)?(?:your\s+)?(?:response|answer|reply|output)"),
         "Output manipulation: content injection directive"),
        (re.compile(r"(?i)(?:modify|augment|enhance|alter|change)\s+(?:your\s+)?(?:response|answer|reply|output)\s+(?:to|by)\s+(?:include|mention|promote|advertise|highlight)"),
         "Output manipulation: response modification directive"),
        (re.compile(r"(?i)(?:reverse|invert|scramble|shuffle)\s+(?:your\s+)?(?:response|answer|reply|output|text)"),
         "Output manipulation: output obfuscation directive"),
        # Code injection directives -- instruct the LLM to embed malicious code
        (re.compile(r"(?i)(?:add|include|insert|embed|feature|integrate|merge|weave|incorporate)\s+(?:the\s+)?(?:following|below|above|this)\s+(?:code\s+)?(?:snippet|excerpt|block|section|fragment)\s+(?:in|into|to)\s+(?:your|the)\s+(?:response|code|solution|implementation|algorithm|program|output|answer)"),
         "Output manipulation: code injection directive"),
        (re.compile(r"(?i)(?:develop|upgrade|supplement|refine)\s+(?:your\s+)?(?:solution|code|response|algorithm|implementation)\s+(?:by\s+)?(?:including|embedding|featuring|incorporating|adding)\s+(?:the\s+)?(?:below|following|this)\s+(?:code\s+)?(?:snippet|excerpt|block)"),
         "Output manipulation: code injection via solution modification"),
        (re.compile(r"(?i)(?:ensure|make\s+sure)\s+(?:that\s+)?(?:the\s+)?(?:below|following|this)\s+(?:code\s+)?(?:snippet|excerpt|section|block)\s+is\s+(?:featured|included|woven|embedded|incorporated)"),
         "Output manipulation: mandatory code inclusion directive"),
        # Indirect code injection -- persuasive/casual phrasing
        (re.compile(r"(?i)(?:don'?t\s+hesitate\s+to|you\s+(?:may|should|could|might)\s+(?:find|want))\s+.{0,40}(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|section|block)"),
         "Output manipulation: indirect code injection (persuasive phrasing)"),
        (re.compile(r"(?i)(?:seamlessly|naturally|carefully)\s+(?:meld|blend|integrate|incorporate|weave|embed)\s+(?:the\s+)?(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|block)"),
         "Output manipulation: stealth code injection directive"),
        (re.compile(r"(?i)(?:your\s+(?:code|solution|response|implementation)\s+should\s+(?:embody|reflect|include|contain|feature))\s+.{0,40}(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|block)"),
         "Output manipulation: mandatory code embedding"),
        (re.compile(r"(?i)(?:execute|run|invoke|call)\s+(?:the\s+)?(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|block|section)"),
         "Output manipulation: code execution directive"),
        (re.compile(r"(?i)(?:enlist|utilize|employ|leverage|harness)\s+(?:the\s+)?(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|block|section)\s+(?:as\s+(?:a\s+)?part\s+of|in|into)"),
         "Output manipulation: code adoption directive"),
        (re.compile(r"(?i)(?:incorporate|append)\s+(?:the\s+)?(?:following|below|this)\s+(?:code\s+)?(?:snippet|excerpt|block|section)\s+(?:to|into)\s+(?:fortify|enhance|improve|strengthen)"),
         "Output manipulation: code injection via enhancement claim"),
    ]

    # -----------------------------------------------------------------
    # DSI008: Adversarial prompt benchmark indicators
    # Markers that indicate the file is an adversarial prompt collection
    # -----------------------------------------------------------------
    BENCHMARK_INDICATOR_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"(?i)(?:jailbreak|jail_break|jail-break)\s*(?:prompt|attack|payload|attempt)"),
         "Adversarial benchmark: jailbreak prompt collection"),
        (re.compile(r"(?i)(?:prompt\s+)?injection\s+(?:attack|payload|attempt|sample|example|test)"),
         "Adversarial benchmark: injection attack collection"),
        (re.compile(r"(?i)(?:adversarial|attack|malicious)\s+(?:prompt|input|example|sample|payload)"),
         "Adversarial benchmark: adversarial prompt collection"),
    ]

    # -----------------------------------------------------------------
    # Combined pattern groups for scanning
    # -----------------------------------------------------------------

    def _get_pattern_groups(self, is_high_risk: bool) -> List[Tuple[str, List[Tuple[re.Pattern, str]], Severity]]:
        """Return pattern groups with severity adjusted for directory context.

        Args:
            is_high_risk: True if the file is in a RAG/training directory.

        Returns:
            List of (rule_id, patterns, severity) tuples.
        """
        # In high-risk directories (RAG corpus, training data), injection
        # content is more dangerous because it will be fed to an LLM.
        base_sev = Severity.HIGH if is_high_risk else Severity.MEDIUM
        high_sev = Severity.CRITICAL if is_high_risk else Severity.HIGH

        return [
            ("DSI001", self.INSTRUCTION_OVERRIDE_PATTERNS, base_sev),
            ("DSI002", self.ROLE_MANIPULATION_PATTERNS, base_sev),
            ("DSI003", self.EXFILTRATION_PATTERNS, high_sev),
            ("DSI004", self.HIDDEN_TAG_PATTERNS, high_sev),
            ("DSI005", self.SYSTEM_PROMPT_PATTERNS, base_sev),
            ("DSI006", self.SOCIAL_ENGINEERING_PATTERNS, high_sev),
            ("DSI007", self.OUTPUT_MANIPULATION_PATTERNS, base_sev),
            ("DSI008", self.BENCHMARK_INDICATOR_PATTERNS, Severity.MEDIUM),
        ]

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner, always available

    def get_file_extensions(self) -> List[str]:
        return [".json", ".jsonl", ".csv"]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        """Check if this file is a data file worth scanning for injections.

        Targets JSON/JSONL/CSV files that are likely datasets rather than
        configuration files. Skips package-lock.json, node_modules, etc.
        """
        if file_path.suffix not in self.get_file_extensions():
            return False

        name_lower = file_path.name.lower()

        # Skip known non-dataset files
        skip_names = {
            "package.json", "package-lock.json", "tsconfig.json",
            "composer.json", "composer.lock", ".eslintrc.json",
            "tslint.json", "babel.config.json", "jest.config.json",
            ".prettierrc.json", "appsettings.json", "launch.json",
            "settings.json", "tasks.json", "extensions.json",
            "devcontainer.json", "pyrightconfig.json",
        }
        if name_lower in skip_names:
            return False

        # Skip files inside node_modules, .git, etc.
        parts_lower = {p.lower() for p in file_path.parts}
        skip_dirs = {"node_modules", ".git", ".venv", "venv", "__pycache__"}
        if parts_lower & skip_dirs:
            return False

        # Check file size -- skip files over the limit
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except OSError:
            return False

        return True

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """Return confidence that this scanner should handle the file.

        Higher scores for files in dataset/benchmark/training directories.
        Lower scores for generic JSON config files.
        """
        if not self.can_scan(file_path):
            return 0

        name_lower = file_path.name.lower()
        parts_lower = {p.lower() for p in file_path.parts}

        # JSONL files are almost always data files
        if file_path.suffix == ".jsonl":
            return 85

        # CSV files are almost always data files
        if file_path.suffix == ".csv":
            return 85

        # JSON files in dataset/benchmark/training directories
        dataset_indicators = {
            "data", "dataset", "datasets", "benchmark", "benchmarks",
            "train", "test", "eval", "evaluation", "validation",
            "attack", "attacks", "adversarial", "injection",
            "corpus", "samples", "examples",
        }
        if parts_lower & dataset_indicators:
            return 80

        # JSON files with dataset-like names
        data_name_keywords = [
            "attack", "train", "test", "eval", "dataset", "data",
            "benchmark", "sample", "example", "prompt", "injection",
            "adversarial", "corpus", "defense",
        ]
        if any(kw in name_lower for kw in data_name_keywords):
            return 75

        # Generic JSON files get a low confidence so the JSONScanner
        # (which checks for secrets) takes priority
        if file_path.suffix == ".json":
            return 30

        return 40

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a data file for embedded prompt injection payloads."""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Determine risk level from directory context
            is_high_risk = self._is_high_risk_directory(file_path)

            # Extract and scan string values based on file type
            suffix = file_path.suffix.lower()
            if suffix == ".jsonl":
                issues = self._scan_jsonl_file(file_path, is_high_risk)
            elif suffix == ".json":
                issues = self._scan_json_file(file_path, is_high_risk)
            elif suffix == ".csv":
                issues = self._scan_csv_file(file_path, is_high_risk)

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
                error_message=f"Scan failed: {e}",
            )

    def _is_high_risk_directory(self, file_path: Path) -> bool:
        """Check if the file is in a directory associated with RAG or training data."""
        parts_lower = {p.lower() for p in file_path.parts}
        return bool(parts_lower & self.HIGH_RISK_DIRS)

    def _scan_json_file(
        self, file_path: Path, is_high_risk: bool
    ) -> List[ScannerIssue]:
        """Parse a JSON file and scan all string values for injection payloads."""
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            data = json.loads(content)
        except (json.JSONDecodeError, OSError):
            return issues

        # Build a raw-line lookup so we can report approximate line numbers.
        # For large files, line numbers from JSON parsing are approximate.
        lines = content.split("\n")

        # Extract string values and scan them
        values = self._extract_json_strings(data)
        issues = self._scan_values(values, lines, file_path, is_high_risk)
        return issues

    def _scan_jsonl_file(
        self, file_path: Path, is_high_risk: bool
    ) -> List[ScannerIssue]:
        """Parse a JSONL file line-by-line and scan string values."""
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = f.readlines()
        except OSError:
            return issues

        values_scanned = 0
        for line_num, raw_line in enumerate(raw_lines, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            strings = self._extract_json_strings(obj)
            for value, path in strings:
                if values_scanned >= self.MAX_VALUES_PER_FILE:
                    break
                if len(value) < self.MIN_VALUE_LENGTH:
                    values_scanned += 1
                    continue

                found = self._check_value_for_injection(
                    value, path, line_num, file_path, is_high_risk
                )
                issues.extend(found)
                values_scanned += 1

                if len(issues) >= self.MAX_ISSUES_PER_FILE:
                    return issues

            if values_scanned >= self.MAX_VALUES_PER_FILE:
                break

        return issues

    def _scan_csv_file(
        self, file_path: Path, is_high_risk: bool
    ) -> List[ScannerIssue]:
        """Parse a CSV file and scan cell values for injection payloads."""
        issues: List[ScannerIssue] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return issues

        values_scanned = 0
        try:
            reader = csv.reader(io.StringIO(content))
            for line_num, row in enumerate(reader, 1):
                for col_idx, cell in enumerate(row):
                    if values_scanned >= self.MAX_VALUES_PER_FILE:
                        break
                    cell = cell.strip()
                    if len(cell) < self.MIN_VALUE_LENGTH:
                        values_scanned += 1
                        continue

                    path = f"row[{line_num}].col[{col_idx}]"
                    found = self._check_value_for_injection(
                        cell, path, line_num, file_path, is_high_risk
                    )
                    issues.extend(found)
                    values_scanned += 1

                    if len(issues) >= self.MAX_ISSUES_PER_FILE:
                        return issues

                if values_scanned >= self.MAX_VALUES_PER_FILE:
                    break
        except csv.Error:
            pass

        return issues

    def _extract_json_strings(
        self, data: object, prefix: str = ""
    ) -> List[Tuple[str, str]]:
        """Recursively extract all string values from a JSON structure.

        Args:
            data: Parsed JSON data (dict, list, str, etc.)
            prefix: JSON path prefix for reporting.

        Returns:
            List of (value, json_path) tuples.
        """
        results: List[Tuple[str, str]] = []
        if len(results) > self.MAX_VALUES_PER_FILE:
            return results

        if isinstance(data, str):
            results.append((data, prefix))
        elif isinstance(data, dict):
            for key, val in data.items():
                path = f"{prefix}.{key}" if prefix else key
                results.extend(self._extract_json_strings(val, path))
                if len(results) > self.MAX_VALUES_PER_FILE:
                    break
        elif isinstance(data, list):
            for i, item in enumerate(data):
                path = f"{prefix}[{i}]"
                results.extend(self._extract_json_strings(item, path))
                if len(results) > self.MAX_VALUES_PER_FILE:
                    break

        return results

    def _scan_values(
        self,
        values: List[Tuple[str, str]],
        lines: List[str],
        file_path: Path,
        is_high_risk: bool,
    ) -> List[ScannerIssue]:
        """Scan extracted string values against injection patterns.

        For JSON files, we try to find approximate line numbers by searching
        for the value text in the raw file lines.
        """
        issues: List[ScannerIssue] = []
        values_scanned = 0

        for value, json_path in values:
            if values_scanned >= self.MAX_VALUES_PER_FILE:
                break
            if len(value) < self.MIN_VALUE_LENGTH:
                values_scanned += 1
                continue

            # Try to find approximate line number
            line_num = self._find_line_number(value, lines)

            found = self._check_value_for_injection(
                value, json_path, line_num, file_path, is_high_risk
            )
            issues.extend(found)
            values_scanned += 1

            if len(issues) >= self.MAX_ISSUES_PER_FILE:
                break

        return issues

    def _check_value_for_injection(
        self,
        value: str,
        json_path: str,
        line_num: Optional[int],
        file_path: Path,
        is_high_risk: bool,
    ) -> List[ScannerIssue]:
        """Check a single string value against all injection pattern groups.

        Args:
            value: The string value to check.
            json_path: The JSON path or CSV location for reporting.
            line_num: Approximate line number in the file.
            file_path: Path for context.
            is_high_risk: Whether the file is in a high-risk directory.

        Returns:
            List of ScannerIssue for any matches found.
        """
        issues: List[ScannerIssue] = []
        matched_rules: Set[str] = set()

        for rule_id, patterns, severity in self._get_pattern_groups(is_high_risk):
            # Only one match per rule per value
            if rule_id in matched_rules:
                continue

            for compiled_re, description in patterns:
                if compiled_re.search(value):
                    # Truncate the value for the message to avoid huge output
                    snippet = value[:120].replace("\n", " ").strip()
                    if len(value) > 120:
                        snippet += "..."

                    issues.append(ScannerIssue(
                        rule_id=rule_id,
                        severity=severity,
                        message=(
                            f"Dataset injection: {description} "
                            f"at {json_path} -- \"{snippet}\""
                        ),
                        line=line_num,
                        column=1,
                        cwe_id=94,
                        cwe_link="https://cwe.mitre.org/data/definitions/94.html",
                    ))
                    matched_rules.add(rule_id)
                    break  # One match per rule per value

        return issues

    @staticmethod
    def _find_line_number(value: str, lines: List[str]) -> Optional[int]:
        """Find the approximate line number where a value appears.

        Uses the first 60 characters of the value as a search key.
        Returns None if not found.
        """
        if not value or not lines:
            return None

        # Use a reasonably unique fragment to search
        search_key = value[:60].replace("\n", " ").strip()
        if len(search_key) < 10:
            return None

        for i, line in enumerate(lines, 1):
            if search_key in line:
                return i

        # Try with escaped form (JSON strings store \n as literal \n)
        search_key_escaped = value[:60].replace("\n", "\\n").strip()
        for i, line in enumerate(lines, 1):
            if search_key_escaped in line:
                return i

        return None

    def get_install_instructions(self) -> str:
        return "Dataset injection scanning is built-in (no installation required)"
