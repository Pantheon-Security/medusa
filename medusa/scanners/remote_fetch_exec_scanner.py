#!/usr/bin/env python3
"""Fetch-then-execute-remote-script detector — a swappable-source RCE surface.

A repo/skill that downloads a script from a remote URL and executes it with no
integrity check (no checksum, no signature, no version/commit pin) is running whatever
that server returns AT THAT MOMENT, with the user's privileges. The URL can serve
different bytes at any time — compromise, hijack, a malicious redirect — so a
"trusted domain today" is not a guarantee. This is the classic ``curl … | bash``
supply-chain risk, in two forms:

  PIPE  — ``curl|wget <http-url> | (sudo)? (bash|sh|python|…)``  (single line)
  SPLIT — ``curl|wget <http-url> -o FILE`` … then ``bash|sh|python FILE``
          — including ``subprocess.run(["bash", FILE])`` (list-arg, no shell=True),
          the exact form that EVADES pipe/shell detection. agent-reach's installer
          used this split form with the comment "without invoking a shell pipeline".

The scanner is file-level: for the split form it correlates the download TARGET
(the ``-o``/redirect destination) with a later execute of that SAME token, so a purely
local ``bash ./scripts/build.sh`` (no remote fetch) is NOT flagged. Documentation that
merely mentions a ``curl | bash`` install line is excluded (docs file types skipped) —
this fires on code that ACTIVELY fetch-executes, not on prose about it.

Severity HIGH (review, not auto-block): many legitimate installers (nvm, rustup,
homebrew) fetch-execute, so this is a "review this install path" signal — it drives the
vet verdict to CAUTION, not an automatic DO_NOT_INSTALL, and shows prominently in scan.
"""
import re
import time
from pathlib import Path
from typing import List

from medusa.scanners.base import BaseScanner, ScannerIssue, ScannerResult, Severity

# Interpreters that execute a script argument.
_INTERP = r"(?:sudo\s+)?(?:bash|sh|zsh|ksh|dash|python[0-9.]*|ruby|perl|node|source|\.)"
_FETCH = r"(?:curl|wget)"

# PIPE form: fetch a remote URL piped straight into an interpreter.
_PIPE_RE = re.compile(
    r"(?i)\b" + _FETCH + r"\b[^\n|]*\bhttps?://[^\n|]*\|\s*" + _INTERP + r"\b"
)

# SPLIT form — download target capture (shell `-o FILE` / `-O FILE` / `> FILE`, and the
# subprocess list form `"curl", …, "https://…", …, "-o", target`).
# NOTE: the first span is possessive (`\S++`) so the engine cannot backtrack
# character-by-character into the following lazy `[^\n]*?` when the trailing
# -o/-O/> anchor is absent — that overlap was catastrophic ReDoS (a 2 MB line ran
# for hours). Possessive is correctness-preserving here (verified identical matches).
_DL_FLAG_RE = re.compile(
    r"(?i)\b" + _FETCH + r"\b[^\n]*\bhttps?://\S++[^\n]*?\s(?:-o|--output|-O)\s+"
    r"['\"]?([\w./${}~-]+)['\"]?"
)
_DL_REDIR_RE = re.compile(
    r"(?i)\b" + _FETCH + r"\b[^\n]*\bhttps?://\S++[^\n]*?>\s*['\"]?([\w./${}~-]+)"
)
_DL_SUBPROC_RE = re.compile(
    r"(?i)['\"]" + _FETCH + r"['\"][^\n]*https?://[^\n]*['\"](?:-o|--output|-O)['\"]"
    r"\s*,\s*([\w.]+)"
)

# SPLIT form — execute-of-target capture (shell `bash FILE`, subprocess `"bash", FILE`).
_EXEC_SHELL_RE = re.compile(
    r"(?im)(?:^|[;&|]|\bsudo\s+)\s*(?:bash|sh|zsh|ksh|dash|python[0-9.]*|ruby|perl|source|\.)"
    r"\s+['\"]?([\w./${}~-]+)"
)
_EXEC_SUBPROC_RE = re.compile(
    r"(?i)['\"](?:bash|sh|zsh|ksh|dash|python[0-9.]*|ruby|perl)['\"]\s*,\s*([\w.]+)"
)

_MAX_BYTES = 2 * 1024 * 1024
# Documentation file types: a README mentioning `curl | bash` is install PROSE, not the
# repo actively fetch-executing — excluded to avoid flagging every tool's install docs.
_DOC_SUFFIXES = (".md", ".markdown", ".rst", ".adoc", ".txt")
_CODE_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".ksh", ".py", ".js", ".mjs", ".cjs", ".ts",
    ".rb", ".pl", ".yml", ".yaml", ".dockerfile",
)
_CODE_NAMES = frozenset({"dockerfile", "makefile", "justfile"})


def _norm(tok: str) -> str:
    """Normalize a captured target token for correlation (strip quotes/space)."""
    return (tok or "").strip().strip("'\"")


class RemoteFetchExecScanner(BaseScanner):
    """Flags download-a-remote-script-then-execute-it (curl|bash and its split form)."""

    display_name = "Remote Fetch-Exec"
    description = ("Detects fetching a remote script (curl/wget) and executing it with "
                   "no integrity check — the curl|bash supply-chain risk, including the "
                   "split download-to-file then bash-file form that evades pipe detection.")

    def get_tool_name(self) -> str:
        return "python"

    def get_file_extensions(self) -> List[str]:
        return list(_CODE_SUFFIXES)

    def can_scan(self, file_path: Path) -> bool:
        n = file_path.name.lower()
        if n.endswith(_DOC_SUFFIXES):
            return False
        return n.endswith(_CODE_SUFFIXES) or n in _CODE_NAMES

    def get_confidence_score(self, file_path: Path, content_head=None) -> int:
        return 80 if self.can_scan(file_path) else 0

    def is_available(self) -> bool:
        return True

    def _line_of(self, content: str, pos: int) -> int:
        return content.count("\n", 0, pos) + 1

    def scan_file(self, file_path: Path) -> ScannerResult:
        start = time.time()
        # Defense in depth: never scan a doc/non-code file even if called directly —
        # a README's `curl | bash` install line is prose, not the repo fetch-executing.
        if not self.can_scan(file_path):
            return ScannerResult(self.name, str(file_path), [], time.time() - start, True)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]
        except (OSError, IOError) as e:
            return ScannerResult(self.name, str(file_path), [], time.time() - start, False, str(e))

        issues: List[ScannerIssue] = []
        seen_lines = set()

        def _add(line: int, msg: str):
            if line in seen_lines:
                return
            seen_lines.add(line)
            issues.append(ScannerIssue(
                severity=Severity.HIGH,
                message=msg,
                line=line,
                rule_id="MEDUSA-RCE-FETCHEXEC-001",
                cwe_id=494,   # Download of Code Without Integrity Check
            ))

        # PIPE form
        for m in _PIPE_RE.finditer(content):
            _add(self._line_of(content, m.start()),
                 "Remote script fetched and piped straight into a shell/interpreter "
                 "(curl|bash) — no integrity check; the remote URL can serve arbitrary "
                 "code executed with your privileges")

        # SPLIT form: collect remote-download targets, then match an execute of the same token.
        dl_targets = {}
        for rx in (_DL_FLAG_RE, _DL_REDIR_RE, _DL_SUBPROC_RE):
            for m in rx.finditer(content):
                tok = _norm(m.group(1))
                if tok:
                    dl_targets.setdefault(tok, self._line_of(content, m.start()))
        if dl_targets:
            for rx in (_EXEC_SHELL_RE, _EXEC_SUBPROC_RE):
                for m in rx.finditer(content):
                    tok = _norm(m.group(1))
                    if tok in dl_targets:
                        _add(self._line_of(content, m.start()),
                             "Executes a script previously downloaded from a remote URL "
                             f"('{tok}') with no integrity check (checksum/signature/pin) "
                             "— split curl-download-then-execute; the source can be swapped "
                             "to run arbitrary code with your privileges")

        return ScannerResult(self.name, str(file_path), issues, time.time() - start, True)
