#!/usr/bin/env python3
"""
MEDUSA Base Scanner Class
Abstract base class for all security scanner implementations
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess
import shutil


class Severity(Enum):
    """Issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScannerIssue:
    """Individual security issue found by scanner"""
    severity: Severity
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    code: Optional[str] = None
    rule_id: Optional[str] = None
    cwe_id: Optional[int] = None
    cwe_link: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'severity': self.severity.value,
            'message': self.message,
            'line': self.line,
            'column': self.column,
            'code': self.code,
            'rule_id': self.rule_id,
            'cwe_id': self.cwe_id,
            'cwe_link': self.cwe_link,
        }


@dataclass
class ScannerResult:
    """Result from scanning a file"""
    scanner_name: str
    file_path: str
    issues: List[ScannerIssue]
    scan_time: float
    success: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'scanner': self.scanner_name,
            'file': self.file_path,
            'issues': [issue.to_dict() for issue in self.issues],
            'scan_time': self.scan_time,
            'success': self.success,
            'error': self.error_message,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all MEDUSA scanners

    Each scanner implements:
    - File type detection (which files it can scan)
    - Tool availability check (is the scanner installed?)
    - Scanning logic (how to run the scanner)
    - Result parsing (how to interpret scanner output)
    """

    def __init__(self):
        self.name = self.__class__.__name__
        self.tool_name = self.get_tool_name()
        self.tool_path = self._find_tool()

    @abstractmethod
    def get_tool_name(self) -> str:
        """
        Return the name of the CLI tool this scanner uses
        Example: 'bandit', 'shellcheck', 'yamllint'
        """
        pass

    @abstractmethod
    def get_file_extensions(self) -> List[str]:
        """
        Return list of file extensions this scanner handles
        Example: ['.py'], ['.sh', '.bash'], ['.yml', '.yaml']
        """
        pass

    @abstractmethod
    def scan_file(self, file_path: Path) -> ScannerResult:
        """
        Scan a single file and return results

        Args:
            file_path: Path to file to scan

        Returns:
            ScannerResult with issues found
        """
        pass

    def can_scan(self, file_path: Path) -> bool:
        """
        Check if this scanner can handle the given file

        Args:
            file_path: Path to file to check

        Returns:
            True if this scanner can scan the file
        """
        return file_path.suffix in self.get_file_extensions()

    def is_available(self) -> bool:
        """
        Check if the scanner tool is installed and available

        Returns:
            True if tool is available
        """
        return self.tool_path is not None

    def _find_tool(self) -> Optional[Path]:
        """
        Find the scanner tool in system PATH or active virtual environment

        Returns:
            Path to tool executable, or None if not found
        """
        import os
        import sys

        # Check virtual environment first
        # Method 1: VIRTUAL_ENV environment variable (set when venv is activated)
        venv_path = os.getenv('VIRTUAL_ENV')

        # Method 2: Detect venv from sys.prefix (works even when not activated)
        if not venv_path and hasattr(sys, 'prefix') and hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                venv_path = sys.prefix

        if venv_path:
            venv_bin = Path(venv_path) / 'bin' / self.tool_name
            if venv_bin.exists() and os.access(str(venv_bin), os.X_OK):
                return venv_bin

        # Fall back to system PATH
        tool_path = shutil.which(self.tool_name)
        return Path(tool_path) if tool_path else None

    def _run_command(self, cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """
        Run a command and return the result

        Args:
            cmd: Command and arguments to run
            timeout: Timeout in seconds

        Returns:
            CompletedProcess result
        """
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

    def get_install_instructions(self) -> str:
        """
        Get installation instructions for this scanner's tool

        Returns:
            Human-readable install instructions
        """
        return f"Install {self.tool_name} to enable {self.name} scanning"


class ScannerRegistry:
    """
    Registry of all available scanners
    Automatically discovers and manages scanner instances
    """

    def __init__(self):
        self.scanners: List[BaseScanner] = []

    def register(self, scanner: BaseScanner):
        """Register a scanner instance"""
        self.scanners.append(scanner)

    def get_scanner_for_file(self, file_path: Path) -> Optional[BaseScanner]:
        """
        Find the appropriate scanner for a file

        Args:
            file_path: Path to file

        Returns:
            Scanner instance that can handle the file, or None
        """
        for scanner in self.scanners:
            if scanner.can_scan(file_path) and scanner.is_available():
                return scanner
        return None

    def get_all_scanners(self) -> List[BaseScanner]:
        """Get all registered scanners"""
        return self.scanners

    def get_available_scanners(self) -> List[BaseScanner]:
        """Get only scanners with tools installed"""
        return [s for s in self.scanners if s.is_available()]

    def get_missing_tools(self) -> List[str]:
        """Get list of scanner tools that are not installed"""
        return [s.tool_name for s in self.scanners if not s.is_available()]
