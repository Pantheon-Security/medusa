"""Shared standardization of raw scanner issues into a common finding dict.

Both :func:`medusa.core.scan_api._extract_findings` (the vet path) and
:meth:`medusa.core.parallel.MedusaParallelScanner.generate_report` (the report
path) turn raw scanner output — either a legacy ``dict`` or a
:class:`~medusa.scanners.base.ScannerIssue` object — into a normalized finding
dict. They previously re-implemented the same field-name fallbacks
independently, so a field rename in one place would silently default severity to
``MEDIUM`` in the other and a CRITICAL could render as SAFE via the vet path
(CR-019). This is the single source of truth for those fallbacks.

Callers add presentation-specific keys (confidence / cwe / remediation / code,
FP filtering, injection-neutralization of the ``issue`` text) on top of the
base dict returned here.
"""

from __future__ import annotations


def _severity_str(raw) -> str:
    """Resolve a raw severity (enum or string) to its string form.

    Handles a :class:`~enum.Enum` (``.value``) and a plain string identically,
    defaulting to ``"MEDIUM"`` only when the value is falsy — matching the prior
    behavior of both consumers (which used ``... or "MEDIUM"`` / an explicit
    ``"MEDIUM"`` fallback).
    """
    return str(getattr(raw, "value", raw) or "MEDIUM")


def standardize_issue(issue, result) -> dict:
    """Normalize one raw scanner ``issue`` into a common finding dict.

    ``result`` is the owning :class:`ScanResult` (used for scanner/file
    attribution). Returns keys: ``scanner``, ``file``, ``line``, ``severity``,
    ``issue``, ``rule_id``. Captures the field-name fallbacks both consumers
    must agree on:

    * severity   : ``issue_severity`` | ``severity``
    * issue text : ``issue_text`` | ``message``
    * line       : ``line_number`` | ``line``
    * scanner    : per-issue ``_scanner_name`` | ``result.scanner``
    """
    scanner = getattr(result, "scanner", None) or "unknown"
    file = getattr(result, "file", None)

    if isinstance(issue, dict):
        return {
            "scanner": issue.get("_scanner_name", scanner) or "unknown",
            "file": file,
            "line": issue.get("line_number", issue.get("line", 0)),
            "severity": _severity_str(
                issue.get("issue_severity", issue.get("severity", "MEDIUM"))
            ),
            "issue": str(issue.get("issue_text", issue.get("message", str(issue)))),
            "rule_id": issue.get("rule_id"),
        }

    return {
        "scanner": scanner,
        "file": file,
        "line": getattr(issue, "line", 0),
        "severity": _severity_str(getattr(issue, "severity", "MEDIUM")),
        "issue": str(getattr(issue, "message", "")),
        "rule_id": getattr(issue, "rule_id", None),
    }
