#!/usr/bin/env python3
"""
MEDUSA Garak Integration Scanner
Wraps NVIDIA's Garak for LLM vulnerability scanning

Garak is an open-source LLM vulnerability scanner that probes for:
- Prompt injection vulnerabilities
- Data leakage risks
- Jailbreaks and guardrail bypasses
- Hallucination patterns
- Toxicity generation

Based on: https://github.com/NVIDIA/garak
"""

import json
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class GarakScanner(BaseScanner):
    """
    Garak Integration Scanner

    Wraps NVIDIA's Garak CLI to detect LLM vulnerabilities:
    - GRK001: Prompt injection vulnerability
    - GRK002: Data leakage detected
    - GRK003: Jailbreak/guardrail bypass
    - GRK004: Hallucination patterns
    - GRK005: Toxicity generation risk
    - GRK006: Encoding/obfuscation bypass
    - GRK007: Cross-plugin attack patterns

    Requires: pip install garak
    """

    # File extensions that may contain LLM configurations
    LLM_CONFIG_EXTENSIONS = [
        ".yaml", ".yml", ".json", ".toml",
    ]

    # Severity mapping from Garak to MEDUSA
    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    def __init__(self):
        super().__init__()
        self._garak_available = None

    def get_tool_name(self) -> str:
        return "garak"

    def get_file_extensions(self) -> List[str]:
        return self.LLM_CONFIG_EXTENSIONS

    def is_available(self) -> bool:
        """Check if garak CLI is available"""
        if self._garak_available is None:
            self._garak_available = shutil.which("garak") is not None
        return self._garak_available

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Scan a single file using Garak"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """
        Scan an LLM configuration for vulnerabilities using Garak

        Note: Garak is primarily designed for runtime LLM testing, not static config analysis.
        This scanner checks for vulnerable configuration patterns.

        Args:
            file_path: Path to the LLM configuration file
            content: File content (optional, will read if not provided)

        Returns:
            ScannerResult with any security issues found
        """
        start_time = time.time()
        issues: List[ScannerIssue] = []

        # Check file extension
        if file_path.suffix.lower() not in self.LLM_CONFIG_EXTENSIONS:
            return ScannerResult(
                scanner_name=self.name,
                file_path=file_path,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )

        # Read content if not provided
        if content is None:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=file_path,
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=False,
                    error="Failed to read file",
                )

        # Static analysis of LLM configurations
        issues.extend(self._analyze_config_patterns(content, file_path))

        return ScannerResult(
            scanner_name=self.name,
            file_path=file_path,
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )

    def _analyze_config_patterns(self, content: str, file_path: Path) -> List[ScannerIssue]:
        """Analyze LLM configuration for security issues"""
        issues = []
        content_lower = content.lower()
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            # GRK001: Prompt injection vulnerability patterns
            if any(term in line_lower for term in [
                "inject", "bypass", "ignore previous", "disregard",
                "new instructions", "forget", "override"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK001",
                    severity=Severity.CRITICAL,
                    message="Potential prompt injection pattern in LLM config. Sanitize user-controllable prompt components.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                    cwe_id=94,
                ))

            # GRK002: Data leakage patterns
            if any(term in line_lower for term in [
                "return_raw", "include_context", "expose_system",
                "debug_mode", "verbose_error", "show_prompt"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK002",
                    severity=Severity.HIGH,
                    message="Configuration may expose sensitive data or system prompts. Disable debug modes.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                ))

            # GRK003: Guardrail bypass configuration
            if any(term in line_lower for term in [
                "disable_safety", "no_guardrail", "bypass_filter",
                "allow_harmful", "unrestricted", "jailbreak"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK003",
                    severity=Severity.CRITICAL,
                    message="Configuration disables safety guardrails. Enable safety and content filtering.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                ))

            # GRK004: Hallucination risk patterns
            if any(term in line_lower for term in [
                "temperature: 2", "temperature: 1.5", "temperature: 1.8",
                "top_p: 1.0", "no_grounding", "creative_mode"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK004",
                    severity=Severity.MEDIUM,
                    message="High temperature/sampling increases hallucination risk. Use temperature <= 0.7 for factual tasks.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                ))

            # GRK005: Toxicity generation risk
            if any(term in line_lower for term in [
                "content_filter: false", "disable_moderation",
                "allow_nsfw", "no_content_policy"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK005",
                    severity=Severity.HIGH,
                    message="Content moderation/filtering is disabled. Enable moderation.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                ))

            # GRK006: Encoding/obfuscation vulnerabilities
            if any(term in line_lower for term in [
                "decode_base64", "eval_response", "exec_output",
                "unicode_decode", "allow_encoded"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK006",
                    severity=Severity.HIGH,
                    message="Configuration allows encoded/obfuscated content. Validate and sanitize encoded input.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                    cwe_id=116,
                ))

            # GRK007: Cross-plugin/tool attack vectors
            if any(term in line_lower for term in [
                "allow_external_tool", "unrestricted_plugin",
                "any_tool_access", "cross_agent_call"
            ]):
                issues.append(ScannerIssue(
                    rule_id="GRK007",
                    severity=Severity.HIGH,
                    message="Configuration allows unrestricted tool/plugin access. Implement tool whitelisting.",
                    line=line_num,
                    column=1,
                    code=line.strip()[:100],
                ))

        # Check for missing security configurations
        if "garak" in file_path.name.lower() or "llm" in file_path.name.lower():
            if "guardrail" not in content_lower and "safety" not in content_lower:
                issues.append(ScannerIssue(
                    rule_id="GRK003",
                    severity=Severity.MEDIUM,
                    message="LLM configuration does not mention safety/guardrails. Consider explicit safety config.",
                    line=1,
                    column=1,
                ))

        return issues

    def run_garak_probe(self, model_config: str, probe_types: Optional[List[str]] = None) -> ScannerResult:
        """
        Run Garak probes against an LLM (requires running model)

        This is an advanced feature for runtime testing.

        Args:
            model_config: Garak model configuration (e.g., 'openai' or config file path)
            probe_types: List of probe types to run (default: all)

        Returns:
            ScannerResult with vulnerabilities found
        """
        if not self.is_available():
            return ScannerResult(
                scanner_name=self.name,
                file_path=Path(model_config),
                issues=[],
                scan_time=0,
                success=False,
                error="Garak not installed. Run: pip install garak",
            )

        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            # Build Garak command
            cmd = ["garak", "--model_type", model_config, "--report", "json"]

            if probe_types:
                for probe in probe_types:
                    cmd.extend(["--probes", probe])

            # Run Garak
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            # Parse results
            if result.stdout:
                try:
                    garak_result = json.loads(result.stdout)
                    issues.extend(self._parse_garak_output(garak_result))
                except json.JSONDecodeError:
                    pass

            return ScannerResult(
                scanner_name=self.name,
                file_path=Path(model_config),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                scanner_name=self.name,
                file_path=Path(model_config),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error="Garak scan timed out",
            )
        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=Path(model_config),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _parse_garak_output(self, garak_result: dict) -> List[ScannerIssue]:
        """Parse Garak JSON output into ScannerIssues"""
        issues = []

        # Garak output structure varies by version
        vulnerabilities = garak_result.get("vulnerabilities", [])
        if not vulnerabilities:
            vulnerabilities = garak_result.get("findings", [])

        for vuln in vulnerabilities:
            probe = vuln.get("probe", "unknown")
            passed = vuln.get("passed", True)

            if not passed:  # Failed = vulnerability found
                rule_id = self._get_rule_from_probe(probe)
                severity = self._get_severity_from_probe(probe)

                issues.append(ScannerIssue(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"Garak {probe}: {vuln.get('description', 'Vulnerability detected')}",
                    line=1,
                    column=1,
                ))

        return issues

    def _get_rule_from_probe(self, probe: str) -> str:
        """Map Garak probe to MEDUSA rule ID"""
        probe_lower = probe.lower()
        if "injection" in probe_lower or "prompt" in probe_lower:
            return "GRK001"
        elif "leak" in probe_lower or "exfil" in probe_lower:
            return "GRK002"
        elif "jailbreak" in probe_lower or "bypass" in probe_lower:
            return "GRK003"
        elif "hallucin" in probe_lower:
            return "GRK004"
        elif "toxic" in probe_lower or "harmful" in probe_lower:
            return "GRK005"
        elif "encod" in probe_lower or "obfusc" in probe_lower:
            return "GRK006"
        else:
            return "GRK007"

    def _get_severity_from_probe(self, probe: str) -> Severity:
        """Determine severity based on probe type"""
        probe_lower = probe.lower()
        if any(term in probe_lower for term in ["injection", "jailbreak", "rce", "exfil"]):
            return Severity.CRITICAL
        elif any(term in probe_lower for term in ["leak", "bypass", "toxic"]):
            return Severity.HIGH
        elif any(term in probe_lower for term in ["hallucin"]):
            return Severity.MEDIUM
        else:
            return Severity.HIGH
