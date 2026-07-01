#!/usr/bin/env python3
"""
MEDUSA Taint-Tracking (Dataflow) Scanner

Performs lightweight, intra-function taint analysis on Python source to catch the
data-flow shape that regex and single-node AST checks miss: a value that *starts*
at a sensitive SOURCE and *ends* at a dangerous SINK.

A literal `requests.post(url, data="ping")` is benign; the real risk is
`tok = os.getenv("AWS_SECRET"); requests.post(url, data=tok)` — the same call
shape, but now exfiltrating a credential. Likewise `os.system("ls")` is benign
while `os.system(input())` is command injection. The signal is the flow, so we
track which variable *names* carry tainted data within a single function and only
fire when such a name reaches a sink argument.

Detects:
- MEDUSA-TAINT-EXFIL-001: a credential/secret/sensitive-file SOURCE flows into a
  network SINK (requests/httpx/urllib/socket) — sensitive data exfiltration.
  CRITICAL, CWE-200.
- MEDUSA-TAINT-EXEC-001: an untrusted-input SOURCE (input/sys.argv/web request)
  flows into a code-execution SINK (exec/eval/os.system/subprocess.*) — command
  or code injection. CRITICAL, CWE-78/94.

Design notes (precision over recall — this scanner must NOT flood):
- Analysis is per-FunctionDef. A variable becomes tainted when assigned (directly
  or via f-string/concat/simple call wrapping) from a SOURCE; taint propagates
  through subsequent assignments that reference an already-tainted name.
- We only fire when a tainted NAME is actually traced into a sink argument. A
  module that prints an env var, logs a file's contents locally, or posts a
  literal/constant body produces zero findings.
- On a SyntaxError (Python 2 source, partial file) the scanner returns no issues
  rather than failing the whole scan.
"""

import ast
import time
from pathlib import Path
from typing import List, Optional, Set

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity
from medusa.scanners._ast_utils import _func_name, _attr_root


# ---------------------------------------------------------------------------
# Source / sink vocabulary
# ---------------------------------------------------------------------------

# Substrings that mark a file path / env name as credential-ish. Used both for
# env-var names (AWS_SECRET, GITHUB_TOKEN) and file paths (~/.aws/credentials).
_CREDENTIAL_HINTS = (
    "secret", "token", "password", "passwd", "api_key", "apikey", "api-key",
    "credential", "private_key", "privatekey", ".aws", ".ssh", ".env",
    ".netrc", "id_rsa", "access_key", "auth", "session", ".npmrc",
    "kube/config", ".kube", "gcloud", "azure",
)

# os.* functions that read environment variables.
_ENV_READ_FUNCS = {"getenv", "environ"}

# Functions whose return value is untrusted user input.
_INPUT_FUNCS = {"input"}

# Web-request attribute roots that carry untrusted input (request.args/json/...).
_WEB_REQUEST_ATTRS = {"args", "json", "form", "data", "values", "params",
                      "cookies", "headers", "GET", "POST", "body", "query_params"}

# keyring / secret-store readers.
_SECRET_STORE_FUNCS = {"get_password", "get_secret", "get_secret_value"}

# Network sink callables (bare name -> matched on attribute .attr).
_NETWORK_SINK_FUNCS = {
    "post", "put", "patch", "get", "delete", "request",  # requests / httpx
    "urlopen", "Request",                                # urllib.request
    "send", "sendall", "sendto",                         # socket
}
# Keyword args of a network call whose tainted value means exfiltration.
_NETWORK_SINK_KWARGS = {"data", "json", "params", "files", "content", "body"}

# Code-execution sink callables.
_EXEC_SINK_NAMES = {"exec", "eval"}
_EXEC_SINK_ATTRS = {
    "system", "popen",                       # os.system / os.popen
    "run", "call", "check_call", "check_output", "Popen",  # subprocess.*
}


class TaintScanner(BaseScanner):
    """Intra-function taint-tracking scanner for source-to-sink data flows."""

    display_name = "Taint Tracking"
    description = (
        "Intra-function dataflow analysis flagging credential/secret sources that "
        "reach network sinks (exfiltration) and untrusted input that reaches "
        "exec/subprocess sinks (injection)."
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

        issues: List[ScannerIssue] = []
        # Analyse each function/method body independently. Also analyse module
        # level (top-level statements) as its own pseudo-scope.
        try:
            for scope in _iter_scopes(tree):
                analyzer = _TaintAnalyzer()
                analyzer.run(scope)
                issues.extend(analyzer.issues)
        except (RecursionError, RuntimeError):
            # Pathologically deep/recursive AST — degrade gracefully like the
            # SyntaxError branch, keeping whatever was collected so far.
            pass

        return ScannerResult(
            scanner_name=self.name,
            file_path=str(file_path),
            issues=issues,
            scan_time=time.time() - start_time,
            success=True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iter_scopes(tree: ast.AST):
    """Yield each analysis scope: the module's top-level statement list, plus the
    body of every function/method (sync + async). Each is analysed independently
    so taint never bleeds across function boundaries."""
    # Module-level: treat top-level statements as one scope.
    yield list(getattr(tree, "body", []))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield list(node.body)


def _looks_credential(text: Optional[str]) -> bool:
    """True if a string (env name / file path) contains a credential hint."""
    if not text:
        return False
    low = text.lower()
    return any(hint in low for hint in _CREDENTIAL_HINTS)


def _const_str(node: ast.AST) -> Optional[str]:
    """Return the string value of a Constant node, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _TaintAnalyzer:
    """Tracks tainted variable names within a single scope and records issues
    when a tainted name reaches a sink argument.

    Taint kinds:
    - "cred": credential / secret / sensitive-file read -> exfil concern.
    - "input": untrusted user input -> injection concern.
    A name may carry both; we keep a set of kinds per name.
    """

    def __init__(self) -> None:
        self.issues: List[ScannerIssue] = []
        # name -> set of taint kinds ("cred" / "input")
        self.tainted: dict[str, Set[str]] = {}

    def run(self, body: List[ast.stmt]) -> None:
        # Single forward pass over the statements in source order. This models
        # straight-line flow well enough for the intra-function scope; it does
        # not attempt to reason about branches/loops re-defining a var, which is
        # the conservative (FP-avoiding) choice.
        for stmt in body:
            self._visit_stmt(stmt)

    # --- statement handling ------------------------------------------------

    def _visit_stmt(self, stmt: ast.stmt) -> None:
        # A nested function/method is its OWN scope (yielded by _iter_scopes),
        # so do not descend into its body here — re-walking it would duplicate
        # findings and could bleed the enclosing scope's taint across the
        # function boundary. Skip the whole definition.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        # Assignment: propagate / introduce taint.
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            value = stmt.value
            targets = (
                stmt.targets if isinstance(stmt, ast.Assign)
                else ([stmt.target] if stmt.target is not None else [])
            )
            if value is not None:
                kinds = self._eval_taint(value)
                # Inspect the RHS for any sink usage before recording the LHS.
                self._check_expr_for_sinks(value)
                if kinds:
                    for tgt in targets:
                        for name in _assigned_names(tgt):
                            self.tainted.setdefault(name, set()).update(kinds)
                else:
                    # Re-assignment from a clean value clears prior taint.
                    for tgt in targets:
                        for name in _assigned_names(tgt):
                            self.tainted.pop(name, None)
            return

        # Any other statement: walk its expressions for sink calls.
        for child in ast.iter_child_nodes(stmt):
            self._check_expr_for_sinks(child)

    # --- taint evaluation --------------------------------------------------

    def _eval_taint(self, node: ast.AST) -> Set[str]:
        """Return the set of taint kinds that this expression evaluates to.
        Handles direct sources, name references to tainted vars, and simple
        propagation through f-strings / concatenation / wrapping calls."""
        kinds: Set[str] = set()
        if node is None:
            return kinds

        # Direct reference to an already-tainted name.
        if isinstance(node, ast.Name):
            return set(self.tainted.get(node.id, set()))

        # A source call (os.getenv, input(), keyring.get_password, .read()).
        if isinstance(node, ast.Call):
            kinds |= self._source_kinds_from_call(node)
            # Propagate taint through wrapping calls, e.g. str(tok), tok.strip(),
            # f(tok): if any argument is tainted, the result is tainted too.
            for arg in node.args:
                kinds |= self._eval_taint(arg)
            for kw in node.keywords:
                kinds |= self._eval_taint(kw.value)
            # Attribute receiver: tok.strip() -> taint of `tok`.
            if isinstance(node.func, ast.Attribute):
                kinds |= self._eval_taint(node.func.value)
            return kinds

        # Web request attribute access: request.args / request.json[...] etc.
        if isinstance(node, ast.Attribute):
            kinds |= self._web_request_kinds(node)
            kinds |= self._eval_taint(node.value)
            return kinds

        # Subscript: sys.argv[1], request.args["x"], tainted_dict[...].
        if isinstance(node, ast.Subscript):
            kinds |= self._eval_taint(node.value)
            return kinds

        # f-string: tainted if any interpolated value is tainted.
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    kinds |= self._eval_taint(v.value)
            return kinds

        # Concatenation / binary op: "prefix" + tok, tok % args, etc.
        if isinstance(node, ast.BinOp):
            kinds |= self._eval_taint(node.left)
            kinds |= self._eval_taint(node.right)
            return kinds

        # Container literals carrying a tainted element.
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                kinds |= self._eval_taint(e)
            return kinds
        if isinstance(node, ast.Dict):
            for v in node.values:
                kinds |= self._eval_taint(v)
            return kinds

        return kinds

    def _source_kinds_from_call(self, node: ast.Call) -> Set[str]:
        """Identify taint kinds introduced by a *source* call itself."""
        kinds: Set[str] = set()
        name = _func_name(node.func)
        root = _attr_root(node.func) if isinstance(node.func, ast.Attribute) else None

        # os.getenv("AWS_SECRET") / os.environ.get("TOKEN")
        if name in _ENV_READ_FUNCS or (name == "get" and root == "os"):
            # Treat env reads as credential taint when the var name looks
            # credential-ish; otherwise still flag as cred (env values are
            # untrusted-ish secrets by default for exfil purposes).
            arg0 = _const_str(node.args[0]) if node.args else None
            if arg0 is None or _looks_credential(arg0):
                kinds.add("cred")
            else:
                # Non-credential env var still counts as a (weak) cred source;
                # but to stay precise we only mark cred when name is unknown or
                # credential-ish. A clearly-benign named env var -> no taint.
                pass

        # os.environ["TOKEN"] subscript access is handled on the Subscript path;
        # the os.environ.get(...) call form is already covered above.

        # input() -> untrusted input
        if name in _INPUT_FUNCS and root is None:
            kinds.add("input")

        # keyring.get_password(...) / *.get_secret_value()
        if name in _SECRET_STORE_FUNCS:
            kinds.add("cred")

        # open(<credential-path>).read()  /  open(path).read()
        if name == "read" and isinstance(node.func, ast.Attribute):
            inner = node.func.value
            if isinstance(inner, ast.Call) and _func_name(inner.func) == "open":
                path_arg = _const_str(inner.args[0]) if inner.args else None
                if _looks_credential(path_arg):
                    kinds.add("cred")
        # open(<credential-path>) bare (without .read) -> treat as cred handle
        if name == "open":
            path_arg = _const_str(node.args[0]) if node.args else None
            if _looks_credential(path_arg):
                kinds.add("cred")

        return kinds

    def _web_request_kinds(self, node: ast.Attribute) -> Set[str]:
        """request.args / request.json / request.form / ... -> untrusted input."""
        if node.attr in _WEB_REQUEST_ATTRS:
            root = _attr_root(node)
            # Heuristic: the attribute root mentions a request-like object.
            if root and ("request" in root.lower() or root in ("req", "flask")):
                return {"input"}
        # sys.argv -> untrusted input
        if node.attr == "argv" and _attr_root(node) == "sys":
            return {"input"}
        return set()

    # --- sink checking -----------------------------------------------------

    def _check_expr_for_sinks(self, node: ast.AST) -> None:
        """Walk an expression subtree looking for sink calls that receive a
        tainted name, recording an issue for each genuine flow."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                self._check_call_sink(sub)

    def _check_call_sink(self, call: ast.Call) -> None:
        name = _func_name(call.func)
        root = _attr_root(call.func) if isinstance(call.func, ast.Attribute) else None

        # ---- network exfil sink ----
        if self._is_network_sink(call, name):
            tainted_kinds = self._tainted_args(call, sink="network")
            if "cred" in tainted_kinds:
                self._add(
                    "MEDUSA-TAINT-EXFIL-001", Severity.CRITICAL,
                    "Sensitive data exfiltration: a credential/secret/sensitive-file "
                    f"value flows into a network call ({_describe(call)})",
                    call, cwe_id=200,
                )

        # ---- code-execution sink ----
        if self._is_exec_sink(name, root, call):
            tainted_kinds = self._tainted_args(call, sink="exec")
            if "input" in tainted_kinds:
                self._add(
                    "MEDUSA-TAINT-EXEC-001", Severity.CRITICAL,
                    "Command/code injection: untrusted input flows into a "
                    f"code-execution call ({_describe(call)})",
                    call, cwe_id=78,
                )

    def _is_network_sink(self, call: ast.Call, name: Optional[str]) -> bool:
        if name not in _NETWORK_SINK_FUNCS:
            return False
        # Require attribute form (requests.post, sess.get, sock.send, httpx.post,
        # urllib.request.urlopen) to avoid catching a local def named get/post.
        if not isinstance(call.func, ast.Attribute):
            return False
        return True

    def _is_exec_sink(self, name: Optional[str], root: Optional[str],
                      call: ast.Call) -> bool:
        # Bare exec()/eval()
        if name in _EXEC_SINK_NAMES and isinstance(call.func, ast.Name):
            return True
        # os.system / os.popen / subprocess.*
        if isinstance(call.func, ast.Attribute) and name in _EXEC_SINK_ATTRS:
            if root in ("os", "subprocess") or root is None:
                return True
        return False

    def _tainted_args(self, call: ast.Call, sink: str) -> Set[str]:
        """Return the union of taint kinds carried by the relevant arguments of a
        sink call. For network sinks we look at positional args and the data/json/
        params kwargs; for exec sinks we look at the first positional arg (and
        kwargs as a fallback)."""
        kinds: Set[str] = set()
        if sink == "network":
            for arg in call.args:
                kinds |= self._eval_taint(arg)
            for kw in call.keywords:
                if kw.arg in _NETWORK_SINK_KWARGS:
                    kinds |= self._eval_taint(kw.value)
        else:  # exec
            for arg in call.args:
                kinds |= self._eval_taint(arg)
            for kw in call.keywords:
                kinds |= self._eval_taint(kw.value)
        return kinds

    # --- issue construction ------------------------------------------------

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


def _assigned_names(target: ast.AST) -> List[str]:
    """Return the variable names bound by an assignment target (handles simple
    Name and tuple/list unpacking)."""
    names: List[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_assigned_names(elt))
    return names


def _describe(call: ast.Call) -> str:
    """Short human-readable label for the callee of a sink call."""
    func = call.func
    if isinstance(func, ast.Attribute):
        root = _attr_root(func)
        return f"{root}.{func.attr}()" if root else f"{func.attr}()"
    if isinstance(func, ast.Name):
        return f"{func.id}()"
    return "call"
