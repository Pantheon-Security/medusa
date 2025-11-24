#!/usr/bin/env python3
"""
MEDUSA R Scanner
Code quality scanner for R using lintr
"""

import json, time
import shutil
import subprocess
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class RScanner(BaseScanner):
    """Scanner for R files using lintr"""

    def get_tool_name(self) -> str:
        return "Rscript"

    def get_file_extensions(self) -> List[str]:
        return [".R", ".r"]

    def is_available(self) -> bool:
        """Check if R is installed"""
        return shutil.which("Rscript") is not None

    def scan_file(self, file_path: Path) -> ScannerResult:
        start_time = time.time()
        """Scan an R file with lintr"""
        if not self.is_available():
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="R not installed. Install from: https://www.r-project.org/"
            )

        try:
            # Run lintr via Rscript
            r_script = f"""
            if (!requireNamespace("lintr", quietly = TRUE)) {{
                stop("lintr not installed")
            }}
            library(jsonlite)
            lints <- lintr::lint("{file_path}")
            if (length(lints) > 0) {{
                result <- lapply(lints, function(x) {{
                    list(
                        line = x$line_number,
                        column = x$column_number,
                        type = x$type,
                        message = x$message,
                        linter = x$linter
                    )
                }})
                cat(toJSON(result, auto_unbox = TRUE))
            }} else {{
                cat("[]")
            }}
            """

            result = self._run_command([str(self.tool_path), "-e", r_script], timeout=30
            )

            # Check for lintr not installed
            if "lintr not installed" in result.stderr:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message="lintr not installed. Install with: install.packages('lintr')"
                )

            if result.returncode != 0 and not result.stdout:
                return ScannerResult(
                    file_path=file_path,
                    scanner_name=self.name,
                    issues=[],
                    scan_time=time.time() - start_time, error_message=f"lintr failed: {result.stderr}"
                )

            issues = []

            # Parse JSON output
            if result.stdout.strip() and result.stdout.strip() != "[]":
                data = json.loads(result.stdout)

                for item in data:
                    issues.append(ScannerIssue(
                        line=item.get("line", 0),
                        column=item.get("column", 0),
                        severity=self._map_severity(item.get("type", "warning")),
                        code=item.get("linter", "unknown"),
                        message=item.get("message", "Unknown issue"),
                        rule_url=f"https://lintr.r-lib.org/reference/{item.get('linter', '')}.html"
                    ))

            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=issues,
                scan_time=time.time() - start_time, success=True
            )

        except subprocess.TimeoutExpired:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message="lintr timed out"
            )
        except json.JSONDecodeError as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Failed to parse lintr output: {e}"
            )
        except Exception as e:
            return ScannerResult(
                file_path=file_path,
                scanner_name=self.name,
                issues=[],
                scan_time=time.time() - start_time, error_message=f"Scan failed: {e}"
            )

    def _map_severity(self, r_type: str) -> Severity:
        """Map lintr type to MEDUSA severity"""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'style': Severity.LOW,
        }
        return severity_map.get(r_type.lower(), Severity.MEDIUM)
