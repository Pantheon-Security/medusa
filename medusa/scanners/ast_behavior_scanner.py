#!/usr/bin/env python3
"""
MEDUSA AST Behavioral Scanner

Parses Python source with the `ast` module to flag dangerous *behaviors* that
regex-based scanners miss because the risk lives in the data-flow shape, not in
a literal token. A literal `exec("print(1)")` is comparatively benign; the real
risk is `exec(payload)` where the argument is computed at runtime.

Detects:
- MEDUSA-AST-EXEC-001: exec()/eval()/compile(...,'exec') with a NON-literal
  argument (variable, call result, concatenation, f-string).
- MEDUSA-AST-REFLECT-001: reflective dispatch on a dangerous module, e.g.
  getattr(os, name)(...) / getattr(subprocess, ...) / getattr(__builtins__, ...).
- MEDUSA-AST-DYNIMPORT-001: dynamic import of a NON-literal module name via
  __import__(var) or importlib.import_module(var).
- MEDUSA-AST-SHELL-001: subprocess.*(cmd, shell=True) where the command is a
  variable / f-string / concatenation rather than a constant string.
- MEDUSA-AST-OBFUS-001: decode-then-execute chain, e.g.
  exec(base64.b64decode(blob)) / eval(codecs.decode(...)).

Design notes:
- Pure-literal exec/eval forms are intentionally NOT flagged here (low risk and
  high FP rate); the non-literal/dynamic forms are the real attack surface.
- On a SyntaxError (e.g. Python 2 source, partial file) the scanner returns no
  issues rather than failing the whole scan.
"""

import ast
import time
from pathlib import Path
from typing import List, Optional

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity
from medusa.scanners._ast_utils import _func_name, _attr_root


# Modules whose attributes, when fetched reflectively and called, indicate an
# attempt to dodge static detection of dangerous calls (os.system, subprocess.*).
_REFLECT_DANGEROUS_MODULES = {"os", "subprocess", "__builtins__", "builtins", "importlib"}

# Names of the decode primitives that, when wrapping an exec/eval argument,
# indicate an obfuscated payload (decode-then-execute).
_DECODE_FUNCS = {
    "b64decode", "b16decode", "b32decode", "b85decode", "a85decode",
    "decodebytes", "decode", "unhexlify", "decompress", "fromhex",
}


class AstBehaviorScanner(BaseScanner):
    """AST-based behavioral scanner for dangerous Python dynamic-execution patterns."""

    display_name = "AST Behavioral"
    description = (
        "Parses Python with the ast module to flag dynamic exec/eval, reflective "
        "dangerous calls, dynamic imports, variable shell=True, and decode-then-exec "
        "obfuscation that regex scanners miss."
    )

    def get_tool_name(self) -> str:
        return "python"  # pure in-process AST analysis; no external tool

    def get_file_extensions(self) -> List[str]:
        return [".py"]

    def is_available(self) -> bool:
        return True

    def can_scan(self, file_path: Path) -> bool:
        return file_path.suffix == ".py"

    def scan_file(self, file_path: Path) -> ScannerResult:
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 - unreadable file is a scan failure
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Not parseable as Python 3 — degrade gracefully, no findings.
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=True,
            )
        except Exception as e:  # noqa: BLE001 - any other parse error is a failure
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

        visitor = _BehaviorVisitor()
        try:
            visitor.visit(tree)
        except (RecursionError, RuntimeError):
            # Pathologically deep/recursive AST — degrade gracefully like the
            # SyntaxError branch, returning whatever was collected so far.
            pass
        issues = visitor.issues

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )


def _is_literal(node: ast.AST) -> bool:
    """True if the node is a compile-time constant string/bytes (safe-ish), i.e.
    a Constant str/bytes or a concatenation/join of only such constants."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes))
    # A JoinedStr with no FormattedValue parts is effectively a constant string,
    # but any f-string with interpolation is treated as non-literal (dynamic).
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    return False


def _contains_decode_call(node: ast.AST) -> bool:
    """True if the subtree contains a call to a known decode/decompress primitive,
    signalling a decode-then-execute obfuscation chain."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _func_name(sub.func)
            if name in _DECODE_FUNCS:
                return True
    return False


class _BehaviorVisitor(ast.NodeVisitor):
    """Walks the AST collecting ScannerIssues for dangerous dynamic behaviors."""

    def __init__(self) -> None:
        self.issues: List[ScannerIssue] = []

    def _add(self, rule_id: str, severity: Severity, message: str,
             node: ast.AST, cwe_id: Optional[int] = None) -> None:
        cwe_link = (
            f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id else None
        )
        self.issues.append(ScannerIssue(
            rule_id=rule_id,
            severity=severity,
            message=message,
            line=getattr(node, "lineno", None),
            column=(getattr(node, "col_offset", 0) or 0) + 1,
            cwe_id=cwe_id,
            cwe_link=cwe_link,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        name = _func_name(node.func)

        # --- MEDUSA-AST-OBFUS-001: decode-then-execute (check before generic exec) ---
        # exec/eval whose argument tree contains a decode/decompress primitive.
        if name in ("exec", "eval") and node.args:
            if _contains_decode_call(node.args[0]):
                self._add(
                    "MEDUSA-AST-OBFUS-001", Severity.CRITICAL,
                    f"Obfuscated payload execution: {name}() of a decoded/decompressed "
                    "value (decode-then-execute chain)",
                    node, cwe_id=94,
                )
                self.generic_visit(node)
                return

        # --- MEDUSA-AST-EXEC-001: dynamic exec/eval/compile ---
        if name in ("exec", "eval") and node.args:
            if not _is_literal(node.args[0]):
                self._add(
                    "MEDUSA-AST-EXEC-001", Severity.CRITICAL,
                    f"Dynamic code execution: {name}() called with a non-literal "
                    "argument (runtime-computed code)",
                    node, cwe_id=95,
                )
        elif name == "compile" and len(node.args) >= 3:
            mode = node.args[2]
            is_exec_mode = isinstance(mode, ast.Constant) and mode.value == "exec"
            if is_exec_mode and not _is_literal(node.args[0]):
                self._add(
                    "MEDUSA-AST-EXEC-001", Severity.HIGH,
                    "Dynamic code compilation: compile(..., 'exec') with a "
                    "non-literal source",
                    node, cwe_id=95,
                )

        # --- MEDUSA-AST-REFLECT-001: reflective dangerous dispatch ---
        # getattr(<dangerous-module>, <name>) — the result is typically called.
        if name == "getattr" and node.args:
            target = node.args[0]
            root = None
            if isinstance(target, ast.Name):
                root = target.id
            elif isinstance(target, ast.Attribute):
                root = _attr_root(target)
            if root in _REFLECT_DANGEROUS_MODULES:
                self._add(
                    "MEDUSA-AST-REFLECT-001", Severity.HIGH,
                    f"Reflective dispatch on dangerous module '{root}' via getattr() "
                    "— evades static detection of os/subprocess/builtins calls",
                    node, cwe_id=470,
                )

        # --- MEDUSA-AST-DYNIMPORT-001: dynamic import of a non-literal name ---
        if name == "__import__" and node.args:
            if not _is_literal(node.args[0]):
                self._add(
                    "MEDUSA-AST-DYNIMPORT-001", Severity.HIGH,
                    "Dynamic import: __import__() with a non-literal module name",
                    node, cwe_id=470,
                )
        elif name == "import_module" and node.args:
            # importlib.import_module(var) — guard on the attribute root when present.
            root = _attr_root(node.func) if isinstance(node.func, ast.Attribute) else None
            if (root in (None, "importlib")) and not _is_literal(node.args[0]):
                self._add(
                    "MEDUSA-AST-DYNIMPORT-001", Severity.HIGH,
                    "Dynamic import: importlib.import_module() with a non-literal "
                    "module name",
                    node, cwe_id=470,
                )

        # --- MEDUSA-AST-SHELL-001: subprocess.*(cmd, shell=True) with dynamic cmd ---
        if isinstance(node.func, ast.Attribute) and _attr_root(node.func) == "subprocess":
            shell_true = any(
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true and node.args:
                cmd = node.args[0]
                if not _is_literal(cmd) and not self._is_literal_list(cmd):
                    self._add(
                        "MEDUSA-AST-SHELL-001", Severity.HIGH,
                        "Shell command injection risk: subprocess call with "
                        "shell=True and a non-literal command (variable/f-string/concat)",
                        node, cwe_id=78,
                    )

        self.generic_visit(node)

    @staticmethod
    def _is_literal_list(node: ast.AST) -> bool:
        """True for a list/tuple whose elements are all constant strings — the
        safe argv form that is benign even with shell=True semantics."""
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(
                isinstance(e, ast.Constant) and isinstance(e.value, (str, bytes))
                for e in node.elts
            )
        return False
