#!/usr/bin/env python3
"""
MEDUSA Docker Compose Scanner
Security and best practices scanner for Docker Compose files
"""

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class DockerComposeScanner(BaseScanner):
    """Scanner for Docker Compose files using docker-compose validation"""

    def get_tool_name(self) -> str:
        # Try docker-compose first, fall back to docker compose
        if shutil.which("docker-compose"):
            return "docker-compose"
        elif shutil.which("docker"):
            return "docker"
        return "docker-compose"

    def get_file_extensions(self) -> List[str]:
        return [".yml", ".yaml"]

    def is_available(self) -> bool:
        """Check if docker-compose or docker compose is available"""
        return shutil.which("docker-compose") is not None or shutil.which("docker") is not None

    def get_confidence_score(self, file_path: Path) -> int:
        """
        Analyze file content to determine confidence this is a Docker Compose file.

        Scoring:
        - services: +40 (strongest indicator)
        - version: +20 (common in older compose files)
        - networks: +15
        - volumes: +15
        - File named docker-compose.* or compose.*: +10

        Returns:
            0-100 confidence score
        """
        if not self.can_scan(file_path):
            return 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars for analysis

            score = 0

            # Strongest Docker Compose indicator
            if 'services:' in content:
                score += 40

            # Common Docker Compose keywords
            if 'version:' in content and any(v in content for v in ["'3", '"3', "'2", '"2']):
                score += 20
            if 'networks:' in content:
                score += 15
            if 'volumes:' in content:
                score += 15

            # Filename boost
            filename = file_path.name.lower()
            if 'docker-compose' in filename or filename.startswith('compose.'):
                score += 10

            return min(score, 100)  # Cap at 100

        except Exception:
            # If we can't read the file, return low score
            return 0

    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a Docker Compose file for issues

        Uses docker-compose config to validate syntax and structure,
        then checks for common security issues.
        """
        start_time = time.time()

        # Only scan files that look like Docker Compose
        if self.get_confidence_score(file_path) < 40:
            return ScannerResult(
                file_path=str(file_path),
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
                error_message="Not a Docker Compose file"
            )

        if not self.is_available():
            return ScannerResult(
                file_path=str(file_path),
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message="docker-compose not installed"
            )

        issues = []

        try:
            # Validate compose file syntax
            cmd = self._get_validate_command(file_path)
            result = subprocess.run(
                cmd, timeout=30,
                cwd=file_path.parent  # Run in same directory as file
            )

            # Check for validation errors
            if result.returncode != 0:
                error_msg = result.stderr.strip()
                if error_msg:
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message=f"Docker Compose validation failed: {error_msg}",
                        line=None,
                        rule_id="COMPOSE001"
                    ))

            # Perform security checks on the file content
            security_issues = self._check_security_issues(file_path)
            issues.extend(security_issues)

            return ScannerResult(
                file_path=str(file_path),
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=str(file_path),
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message="docker-compose validation timed out"
            )
        except Exception as e:
            return ScannerResult(
                file_path=str(file_path),
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=f"Scan failed: {e}"
            )

    def _get_validate_command(self, file_path: Path) -> List[str]:
        """Get the appropriate docker-compose validation command"""
        if shutil.which("docker-compose"):
            return ["docker-compose", "-f", str(file_path), "config", "--quiet"]
        else:
            # Use docker compose (newer syntax)
            return ["docker", "compose", "-f", str(file_path), "config", "--quiet"]

    def _check_security_issues(self, file_path: Path) -> List[ScannerIssue]:
        """Check for common Docker Compose security issues"""
        issues = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                line_lower = line.lower().strip()

                # Check for privileged mode
                if 'privileged:' in line_lower and 'true' in line_lower:
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message="Container running in privileged mode - security risk",
                        line=line_num,
                        rule_id="COMPOSE002"
                    ))

                # Check for host network mode
                if 'network_mode:' in line_lower and 'host' in line_lower:
                    issues.append(ScannerIssue(
                        severity=Severity.MEDIUM,
                        message="Using host network mode - reduces container isolation",
                        line=line_num,
                        rule_id="COMPOSE003"
                    ))

                # Check for exposed ports without host binding
                if 'ports:' in line_lower:
                    issues.append(ScannerIssue(
                        severity=Severity.INFO,
                        message="Review exposed ports for security",
                        line=line_num,
                        rule_id="COMPOSE004"
                    ))

                # Check for missing restart policy
                if 'image:' in line_lower and line_num < len(lines) - 5:
                    # Look ahead for restart policy
                    next_lines = ''.join(lines[line_num:line_num+5]).lower()
                    if 'restart:' not in next_lines:
                        issues.append(ScannerIssue(
                            severity=Severity.LOW,
                            message="Consider adding restart policy for production",
                            line=line_num,
                            rule_id="COMPOSE005"
                        ))

                # Check for latest tag
                if ':latest' in line_lower or 'image:' in line_lower and ':' not in line:
                    issues.append(ScannerIssue(
                        severity=Severity.MEDIUM,
                        message="Using 'latest' tag or no tag - use specific versions",
                        line=line_num,
                        rule_id="COMPOSE006"
                    ))

        except (IOError, OSError, PermissionError, yaml.YAMLError):
            # If we can't read or parse the file, skip security checks
            # Basic YAML syntax errors are already reported by yamlscanner
            pass

        return issues

    def get_install_instructions(self) -> str:
        return """Install Docker Compose:
  - Ubuntu/Debian: sudo apt-get install docker-compose
  - macOS: brew install docker-compose
  - Or use Docker Desktop which includes compose"""
