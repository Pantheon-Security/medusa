#!/usr/bin/env python3
"""
MEDUSA Docker Compose Scanner
Security and best practices scanner for Docker Compose files
"""

import json
import re
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

    def get_confidence_score(self, file_path: Path, content_head: str = None) -> int:
        """
        Analyze file content to determine confidence this is a Docker Compose file.

        Scoring:
        - services: +40 (strongest indicator)
        - version: +20 (common in older compose files)
        - networks: +15
        - volumes: +15
        - File named docker-compose.* or compose.*: +10

        Args:
            file_path: Path to file to analyze.
            content_head: Optional pre-read file head (first 8KB).

        Returns:
            0-100 confidence score
        """
        if not self.can_scan(file_path):
            return 0

        try:
            if content_head is not None:
                content = content_head[:1000]
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(1000)

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
                capture_output=True, text=True,
                cwd=file_path.parent  # Run in same directory as file
            )

            # Check for validation errors
            if result.returncode != 0:
                error_msg = (result.stderr or result.stdout or '').strip()
                if error_msg:
                    # Extract first line only for clean output
                    first_line = error_msg.split('\n')[0].strip()
                    issues.append(ScannerIssue(
                        severity=Severity.HIGH,
                        message=f"Docker Compose validation error: {first_line}",
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

                # Check for ports bound to all interfaces (0.0.0.0)
                # Only flag when explicitly binding to 0.0.0.0 or using bare port
                # notation like "8080:80" (which defaults to 0.0.0.0)
                if re.match(r'\s*-\s*["\']?(?:0\.0\.0\.0:)?\d+:\d+', line):
                    # Skip if bound to localhost/127.0.0.1
                    if '127.0.0.1:' not in line and 'localhost:' not in line:
                        issues.append(ScannerIssue(
                            severity=Severity.INFO,
                            message="Port exposed to all interfaces (consider binding to 127.0.0.1)",
                            line=line_num,
                            rule_id="COMPOSE004"
                        ))

                # Check for missing restart policy (skip dev compose files)
                is_dev_compose = any(kw in file_path.name.lower()
                                     for kw in ['dev', 'local', 'test', 'debug'])
                if not is_dev_compose and 'image:' in line_lower and line_num < len(lines) - 5:
                    # Look ahead for restart policy within the service block
                    next_lines = ''.join(lines[line_num:line_num+10]).lower()
                    if 'restart:' not in next_lines:
                        issues.append(ScannerIssue(
                            severity=Severity.LOW,
                            message="Consider adding restart policy for production",
                            line=line_num,
                            rule_id="COMPOSE005"
                        ))

                # Check for latest tag (only on image: lines)
                if 'image:' in line_lower:
                    # Extract image reference after 'image:'
                    match = re.search(r'image:\s*["\']?([^"\'#\s]+)', line, re.IGNORECASE)
                    if match:
                        image_ref = match.group(1)
                        # Skip variable references like ${IMAGE}
                        if not image_ref.startswith('$'):
                            if image_ref.endswith(':latest') or ':' not in image_ref:
                                issues.append(ScannerIssue(
                                    severity=Severity.MEDIUM,
                                    message="Using 'latest' tag or no tag - use specific versions",
                                    line=line_num,
                                    rule_id="COMPOSE006"
                                ))

        except (IOError, OSError, PermissionError, ValueError):
            # If we can't read or parse the file, skip security checks
            # Basic YAML syntax errors are already reported by yamlscanner
            pass

        return issues

    def get_install_instructions(self) -> str:
        return """Install Docker Compose:
  - Ubuntu/Debian: sudo apt-get install docker-compose
  - macOS: brew install docker-compose
  - Or use Docker Desktop which includes compose"""
