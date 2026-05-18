"""
Vulnerable MCP Server — FOR DEMONSTRATION ONLY.

This MCP server contains intentional security vulnerabilities:
- Excessive agency (unrestricted tool access)
- No input sanitization on tool arguments
- Command injection via tool parameters
- No rate limiting or audit logging
- Privilege escalation through tool chaining
"""

import json
import os
import subprocess
import sqlite3
from pathlib import Path


class MCPServer:
    """An intentionally insecure MCP server for demonstration."""

    def __init__(self):
        self.db = sqlite3.connect("app.db")
        # VULNERABILITY: No access control — any connected agent can use any tool
        self.tools = {
            "execute_query": self.execute_query,
            "read_file": self.read_file,
            "write_file": self.write_file,
            "run_command": self.run_command,
            "http_request": self.http_request,
            "modify_config": self.modify_config,
        }

    def handle_request(self, request: dict) -> dict:
        """
        VULNERABILITY: No authentication, no authorization checks.
        Any caller can invoke any tool.
        """
        tool_name = request.get("tool")
        arguments = request.get("arguments", {})

        if tool_name not in self.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        # VULNERABILITY: No input validation on arguments
        # VULNERABILITY: No audit logging of tool invocations
        result = self.tools[tool_name](**arguments)
        return {"result": result}

    def execute_query(self, query: str, database: str = "app.db") -> str:
        """
        VULNERABILITY: SQL injection — raw query execution.
        No parameterization, no query allowlisting.
        """
        # VULNERABILITY: Connects to arbitrary database files
        db = sqlite3.connect(database)
        cursor = db.execute(query)
        return json.dumps(cursor.fetchall())

    def read_file(self, path: str) -> str:
        """
        VULNERABILITY: Path traversal — no bounds checking.
        Agent can read /etc/passwd, SSH keys, environment files, etc.
        """
        # No path validation, no sandboxing
        return Path(path).read_text()

    def write_file(self, path: str, content: str) -> str:
        """
        VULNERABILITY: Arbitrary file write — no sandboxing.
        Agent can overwrite system files, inject cron jobs, modify configs.
        """
        Path(path).write_text(content)
        return f"Written {len(content)} bytes to {path}"

    def run_command(self, command: str, args: list = None) -> str:
        """
        VULNERABILITY: Command injection — shell=True with unsanitized input.
        Agent can execute arbitrary system commands.
        """
        if args:
            full_command = f"{command} {' '.join(args)}"
        else:
            full_command = command

        # VULNERABILITY: shell=True + unsanitized input = RCE
        result = subprocess.run(
            full_command, shell=True, capture_output=True, text=True
        )
        return result.stdout + result.stderr

    def http_request(self, url: str, method: str = "GET", body: str = None) -> str:
        """
        VULNERABILITY: SSRF — no URL validation.
        Agent can hit internal services, cloud metadata endpoints, etc.
        """
        import requests

        # No URL allowlist, can access internal network
        # Can reach http://169.254.169.254/latest/meta-data/ (AWS metadata)
        response = requests.request(method, url, data=body)
        return response.text

    def modify_config(self, key: str, value: str) -> str:
        """
        VULNERABILITY: Unprotected configuration modification.
        Agent can change security settings, disable auth, etc.
        """
        config_path = Path("config.json")
        config = json.loads(config_path.read_text()) if config_path.exists() else {}
        config[key] = value
        config_path.write_text(json.dumps(config, indent=2))
        return f"Config updated: {key} = {value}"


# VULNERABILITY: Server starts without TLS, binds to all interfaces
if __name__ == "__main__":
    server = MCPServer()
    print("MCP Server running on 0.0.0.0:3000 (no TLS)")
