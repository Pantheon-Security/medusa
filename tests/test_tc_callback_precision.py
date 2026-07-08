"""Two-sided precision gate for ToolCallbackScanner rules TC004 and TC001.

Background
----------
TC004 ("destructive operation without validation/confirmation") and TC001
("missing before_tool_callback") used to match bare word-fragments — `system`,
`exec`, `remove`, `delete`, `update` — anywhere in a file, including comments,
docstrings, string literals, import statements and identifiers. On Ross's own
MCP-server corpus this carpet-bombed benign code: `File system operations` in a
comment, `SYSTEM = "system"` enum members, `from ... import remove_tool`,
`fs.unlinkSync(path.join(this.config.logDir, file))` log rotation, etc. — 190+
false blocks on a single project — driving CAUTION / DO_NOT_INSTALL verdicts on
clean repos.

The scanner now only reports a real dangerous SINK CALL (shell/code execution,
file deletion) invoked on *untrusted/tainted* input (see
`ToolCallbackScanner._arg_is_tainted`) on an actual code line (comments/strings
masked out), with no nearby validation.

This test locks in BOTH sides so neither regresses:

  (a) BENIGN — the exact benign shapes from the corpus must produce zero
      TC004/TC001.
  (b) MALICIOUS — a crafted tool whose callback pipes tool/agent/request input
      into a dangerous sink must still fire TC004 and TC001.
"""

import tempfile
from pathlib import Path

import pytest

from medusa.scanners.tool_callback_scanner import ToolCallbackScanner


def _scan(code: str, suffix: str = ".py"):
    """Scan a snippet as a temp file and return the set of rule_ids fired."""
    scanner = ToolCallbackScanner()
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / f"sample{suffix}"
        f.write_text(code)
        # Every fixture carries an MCP/agent indicator so can_scan() passes;
        # if this ever fails the fixture, not the scanner, is wrong.
        assert scanner.can_scan(f), f"fixture not recognised as agent code: {code[:60]!r}"
        result = scanner.scan(f)
    return [i.rule_id for i in result.issues]


# ---------------------------------------------------------------------------
# (a) BENIGN corpus shapes — must NOT fire TC004 or TC001
# ---------------------------------------------------------------------------

BENIGN_FIXTURES = {
    # winremote taskmanager.py: enum members / comments containing "system",
    # "exec", "destructive" as word fragments — never actual sink calls.
    "enum_and_comments": (
        """
        from mcp.server import Server
        from winremote.tool_registry import TOOL_REGISTRY

        class ToolCategory(str, Enum):
            # Shell commands — semi-concurrent (limited pool).
            SHELL = "shell"
            # State-mutating system ops (kill, registry write) — serialise.
            SYSTEM = "system"

        def get_current_cancel_event():
            # subprocess-based tools read the current task's cancel event here
            return getattr(_thread_locals, "cancel_event", None)
        """,
        ".py",
    ),
    # winremote fastmcp_compat.py: a tool-registry helper literally named
    # remove_tool / keys_to_remove — "remove" as an identifier, not a deletion.
    "registry_remove_helper": (
        """
        from mcp import tool

        def remove_tool(mcp, name: str) -> None:
            \"\"\"Remove a tool by name from the mcp instance.\"\"\"
            components = getattr(mcp, "_components", None)
            keys_to_remove = [k for k in components if k == name]
            for k in keys_to_remove:
                components.pop(k, None)
        """,
        ".py",
    ),
    # winremote __main__.py: imports + static-literal subprocess (schtasks/where)
    # — no dynamic/tainted argument.
    "static_subprocess_and_imports": (
        """
        import subprocess
        from mcp.server import Server
        from winremote.tools.system_tools import GetSystemInfo, TaskDelete

        def call_tool_setup():
            subprocess.run(["where", "python"], capture_output=True, text=True)
            subprocess.run(["schtasks", "/Create", "/TN", "X", "/F"], text=True)
            if platform.system() == "Windows":
                pass
        """,
        ".py",
    ),
    # notebooklm audit-logger.ts: benign log rotation — deletion on an INTERNAL
    # path (this.config.logDir + a directory-listing filename), not tool input.
    "log_rotation_unlink": (
        """
        import { CallToolRequestSchema } from "@modelcontextprotocol/sdk";

        class AuditLogger {
          rotate(file) {
            fs.unlinkSync(path.join(this.config.logDir, file));
          }
          releaseLock(lockPath) {
            fs.unlinkSync(lockPath);
          }
          async handleTool(request) { return this.rotate("x"); }
        }
        """,
        ".ts",
    ),
    # A comment/docstring that merely mentions a dangerous sink must not fire.
    "sink_named_only_in_comment": (
        """
        from mcp.server import Server

        def call_tool(args):
            # NOTE: we deliberately never call os.system(cmd) or eval(user_input)
            result = args
            return result
        """,
        ".py",
    ),
}


@pytest.mark.parametrize("name", sorted(BENIGN_FIXTURES))
def test_benign_mcp_code_does_not_fire(name):
    code, suffix = BENIGN_FIXTURES[name]
    fired = _scan(code, suffix)
    assert "TC004" not in fired, f"{name}: TC004 false-fired on benign code"
    assert "TC001" not in fired, f"{name}: TC001 false-fired on benign code"


# ---------------------------------------------------------------------------
# (b) MALICIOUS true positives — TC004 AND TC001 must STILL fire
# ---------------------------------------------------------------------------

MALICIOUS_FIXTURES = {
    # Tool callback pipes tool argument straight into a shell.
    "os_system_tool_arg": (
        """
        import os
        from mcp.server import Server

        def call_tool(request):
            command = request.params["command"]
            os.system(command)
        """,
        ".py",
    ),
    # subprocess with shell=True on tool params — classic command injection.
    "subprocess_shell_true": (
        """
        import subprocess
        from mcp import tool

        def call_tool_handler(params):
            subprocess.run(params["cmd"], shell=True)
        """,
        ".py",
    ),
    # eval() of tool payload — dynamic code execution on untrusted input.
    "eval_tool_payload": (
        """
        from mcp.server import Server

        def call_tool(request):
            return eval(request.payload)
        """,
        ".py",
    ),
    # MCP request handler shells out with the request's tool arguments.
    "js_child_process_request": (
        """
        import { CallToolRequestSchema } from "@modelcontextprotocol/sdk";
        server.setRequestHandler(CallToolRequestSchema, async (request) => {
          child_process.exec(request.params.arguments.cmd);
        });
        """,
        ".js",
    ),
    # Destructive filesystem op on a path taken directly from tool input.
    "js_fs_rm_input_path": (
        """
        import { CallToolRequestSchema } from "@modelcontextprotocol/sdk";
        async function handleTool(request) {
          fs.rmSync(request.params.path, { recursive: true, force: true });
        }
        """,
        ".ts",
    ),
}


@pytest.mark.parametrize("name", sorted(MALICIOUS_FIXTURES))
def test_malicious_tool_callback_still_fires(name):
    code, suffix = MALICIOUS_FIXTURES[name]
    fired = _scan(code, suffix)
    assert "TC004" in fired, f"{name}: TC004 failed to fire on a real dangerous sink"
    assert "TC001" in fired, f"{name}: TC001 failed to fire (missing-guard on real risk)"


# ---------------------------------------------------------------------------
# Unit-level checks on the taint discriminator
# ---------------------------------------------------------------------------

def test_arg_is_tainted_exec_policy():
    tainted = ToolCallbackScanner._arg_is_tainted
    # exec: dynamic construction or input-named arg
    assert tainted('f"rm -rf {target}"', "exec")
    assert tainted("cmd, shell=True", "exec")
    assert tainted('"git " + branch', "exec")
    assert tainted("request.params.command", "exec")
    # exec: pure literal is clean
    assert not tainted('"clear"', "exec")
    assert not tainted('["where", "python"], capture_output=True', "exec")


def test_arg_is_tainted_delete_policy():
    tainted = ToolCallbackScanner._arg_is_tainted
    # delete: only input-named source counts
    assert tainted("request.params.path", "delete")
    assert tainted('arguments["target"]', "delete")
    # delete: internal path construction is clean (the audit-logger FP)
    assert not tainted("path.join(this.config.logDir, file)", "delete")
    assert not tainted("lockPath", "delete")


def test_code_masking_ignores_comments_and_strings():
    scanner = ToolCallbackScanner()
    # A sink call that only appears inside a string literal must not be found.
    code = 'from mcp import tool\nHELP = "run os.system(cmd) to execute"\n'
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "s.py"
        f.write_text(code)
        sinks = scanner._find_dangerous_sinks(code, f)
    assert sinks == [], f"sink inside string literal was not masked: {sinks}"
