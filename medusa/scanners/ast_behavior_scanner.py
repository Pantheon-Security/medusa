#!/usr/bin/env python3
"""
MEDUSA AST Behavioral Scanner

Parses Python source with the `ast` module to flag dangerous *behaviors* that
regex-based scanners miss because the risk lives in the data-flow shape, not in
a literal token. A literal `exec("print(1)")` is comparatively benign; the real
risk is `exec(payload)` where the argument is computed at runtime.

Detects:
- MEDUSA-AST-EXEC-001: exec()/eval()/compile(...,'exec') with a NON-literal
  argument (variable, call result, concatenation, f-string). Severity is tiered
  by argument source: CRITICAL for a tainted (untrusted-input-derived) argument,
  demoted to HIGH/MEDIUM for a merely locally-computed one (dual-use).
- MEDUSA-AST-REFLECT-001: reflective dispatch on a dangerous module, e.g.
  getattr(os, name)(...) / getattr(subprocess, ...) / getattr(__builtins__, ...),
  OR getattr/setattr with a TAINTED attribute name. The benign fallback idiom
  getattr(mod, "literal", default) is NOT flagged.
- MEDUSA-AST-DYNIMPORT-001: dynamic import of a NON-literal module name via
  __import__(var) or importlib.import_module(var). MEDIUM for a locally-derived
  name (plugin/loader code), HIGH when the name is tainted.
- MEDUSA-AST-SHELL-001: subprocess.*(cmd, shell=True) where the command is a
  variable / f-string / concatenation rather than a constant string.
- MEDUSA-AST-OBFUS-001: decode-then-execute chain, e.g.
  exec(base64.b64decode(blob)) / eval(codecs.decode(...)).

Design notes:
- Pure-literal exec/eval forms are intentionally NOT flagged here (low risk and
  high FP rate); the non-literal/dynamic forms are the real attack surface.
- exec/eval/compile/dynamic-import/reflection detection is never suppressed on a
  non-literal argument — severity is DEMOTED when the source is not demonstrably
  untrusted. A false negative on a real RCE is worse than a low-severity FP.
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

# Untrusted (attacker-controllable) sources. When a risky sink's argument is
# derived from one of these the finding is escalated; a sink acting on a literal
# or a locally-derived value is dual-use (formatter / plugin-loader / parser code)
# and is reported at a DEMOTED severity instead of suppressed. The heuristic is
# deliberately conservative: a False means "not demonstrably untrusted", which
# lowers severity rather than dropping the finding.
_TAINT_ROOTS = {"request", "flask_request", "req"}  # HTTP request objects
_TAINT_NAMES = {
    "user_input", "userinput", "untrusted", "untrusted_input", "payload",
    "attacker_input", "user_supplied", "external_input", "raw_input",
    "user_data", "request_data", "req_data",
}
_TAINT_CALL_NAMES = {"input", "getenv"}  # builtin input(), os.getenv()

# LLM / model output is untrusted input for the purpose of exec/eval/import/reflect
# sinks (OWASP LLM02 — insecure output handling). Executing model output is a
# top-tier risk, so these sources escalate the SAME as a request object.
# Attribute-access shapes on a model response object:
_TAINT_LLM_ATTRS = {
    "text", "content", "message", "choices", "completion", "output", "response",
}
# Substrings that mark a variable as carrying model/LLM output (llm_response,
# model_output, gpt_result, chat_response, completion, agent_reply, ...):
_TAINT_LLM_NAME_TOKENS = (
    "llm", "gpt", "claude", "model", "completion", "response", "chat",
    "ai_", "agent_",
)


def _is_tainted(node: ast.AST) -> bool:
    """Best-effort taint check: True if the expression subtree references an
    untrusted source — an HTTP request object (``request.args``/``.form``/
    ``.data`` ...), ``sys.argv``/``os.environ``, ``input()``/``os.getenv()``,
    LLM/model output (``result.text``, ``response.content``, ``llm_response`` ...),
    or a conventionally-named user-input variable. Used only to TIER severity,
    never to gate detection: an un-tainted risky call is still reported, demoted."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            lid = sub.id.lower()
            if lid in _TAINT_NAMES:
                return True
            if any(tok in lid for tok in _TAINT_LLM_NAME_TOKENS):
                return True  # llm_response / model_output / gpt_result / ...
        elif isinstance(sub, ast.Attribute):
            root = _attr_root(sub)
            if root in _TAINT_ROOTS:
                return True
            if root == "sys" and sub.attr == "argv":
                return True
            if root == "os" and sub.attr == "environ":
                return True
            if sub.attr in _TAINT_LLM_ATTRS:
                return True  # result.text / response.content / mo.choices ...
        elif isinstance(sub, ast.Call):
            fn = _func_name(sub.func)
            if fn in _TAINT_CALL_NAMES:
                return True
            if fn == "get" and _attr_root(sub.func) in _TAINT_ROOTS:
                return True  # request.args.get(...) style access
    return False


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
        # exec/eval/compile ARE real RCE sinks, but a formatter/parser running them
        # on its OWN content is dual-use. CRITICAL is reserved for a demonstrably
        # untrusted (tainted) argument; a locally-computed argument is demoted but
        # still reported (never suppressed).
        if name in ("exec", "eval") and node.args:
            if not _is_literal(node.args[0]):
                tainted = _is_tainted(node.args[0])
                self._add(
                    "MEDUSA-AST-EXEC-001",
                    Severity.CRITICAL if tainted else Severity.HIGH,
                    f"Dynamic code execution: {name}() called with a "
                    + ("tainted (untrusted-input-derived)" if tainted
                       else "non-literal runtime-computed")
                    + " argument",
                    node, cwe_id=95,
                )
        elif name == "compile" and len(node.args) >= 3:
            mode = node.args[2]
            is_exec_mode = isinstance(mode, ast.Constant) and mode.value == "exec"
            if is_exec_mode and not _is_literal(node.args[0]):
                tainted = _is_tainted(node.args[0])
                self._add(
                    "MEDUSA-AST-EXEC-001",
                    Severity.HIGH if tainted else Severity.MEDIUM,
                    "Dynamic code compilation: compile(..., 'exec') with a "
                    + ("tainted" if tainted else "non-literal")
                    + " source",
                    node, cwe_id=95,
                )

        # --- MEDUSA-AST-REFLECT-001: reflective dangerous dispatch ---
        # Two attacker-relevant shapes:
        #  (a) getattr(<dangerous-module>, <name>) — reflectively fetching an
        #      os/subprocess/builtins attribute to dodge static detection; and
        #  (b) getattr/setattr(obj, <tainted-name>) — the attribute NAME itself is
        #      attacker-controlled (e.g. request.args['attr']).
        # The benign fallback idiom getattr(mod, "literal", default) — a
        # string-literal name WITH a default, the normal "fetch attr or fall back"
        # pattern (e.g. `getattr(os, "O_BINARY", 0)`) — is explicitly NOT flagged.
        if name in ("getattr", "setattr") and node.args:
            target = node.args[0]
            root = None
            if isinstance(target, ast.Name):
                root = target.id
            elif isinstance(target, ast.Attribute):
                root = _attr_root(target)
            name_arg = node.args[1] if len(node.args) >= 2 else None
            name_is_literal_str = (
                isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)
            )
            # getattr(obj, name, default): a default is the safe-fallback signature.
            has_default = name == "getattr" and len(node.args) >= 3
            benign_fallback = name_is_literal_str and has_default

            if name == "getattr" and root in _REFLECT_DANGEROUS_MODULES and not benign_fallback:
                self._add(
                    "MEDUSA-AST-REFLECT-001", Severity.HIGH,
                    f"Reflective dispatch on dangerous module '{root}' via getattr() "
                    "— evades static detection of os/subprocess/builtins calls",
                    node, cwe_id=470,
                )
            elif name_arg is not None and _is_tainted(name_arg):
                self._add(
                    "MEDUSA-AST-REFLECT-001", Severity.HIGH,
                    f"Attacker-controlled attribute access: {name}() with a "
                    "tainted (untrusted-input-derived) attribute name",
                    node, cwe_id=470,
                )

        # --- MEDUSA-AST-DYNIMPORT-001: dynamic import of a non-literal name ---
        # Dynamic import of a LITERAL or locally-derived module name is normal
        # plugin/loader code, so a non-literal name is reported at MEDIUM; only a
        # TAINTED (user/request-derived) module name — an actual attacker-controlled
        # import — is escalated to HIGH.
        if name == "__import__" and node.args:
            if not _is_literal(node.args[0]):
                tainted = _is_tainted(node.args[0])
                self._add(
                    "MEDUSA-AST-DYNIMPORT-001",
                    Severity.HIGH if tainted else Severity.MEDIUM,
                    "Dynamic import: __import__() with a "
                    + ("tainted (untrusted-input-derived)" if tainted else "non-literal")
                    + " module name",
                    node, cwe_id=470,
                )
        elif name == "import_module" and node.args:
            # importlib.import_module(var) — guard on the attribute root when present.
            root = _attr_root(node.func) if isinstance(node.func, ast.Attribute) else None
            if (root in (None, "importlib")) and not _is_literal(node.args[0]):
                tainted = _is_tainted(node.args[0])
                self._add(
                    "MEDUSA-AST-DYNIMPORT-001",
                    Severity.HIGH if tainted else Severity.MEDIUM,
                    "Dynamic import: importlib.import_module() with a "
                    + ("tainted (untrusted-input-derived)" if tainted else "non-literal")
                    + " module name",
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
