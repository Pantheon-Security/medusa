# Vulnerable MCP Server

**DO NOT DEPLOY — intentionally vulnerable for MEDUSA demonstration.**

## What is MCP?

Model Context Protocol (MCP) allows AI agents to interact with external tools.
A misconfigured MCP server is one of the highest-risk attack surfaces in AI applications.

## Vulnerabilities Present

| # | Category | File | Risk |
|---|----------|------|------|
| 1 | Excessive Agency | `mcp.json` (filesystem) | Full system read/write access |
| 2 | Credential Exposure | `mcp.json` (env vars) | AWS keys, DB passwords, Vault tokens in config |
| 3 | No Sandboxing | `mcp.json` (shell-executor) | Unrestricted command execution |
| 4 | SQL Injection | `server.py:56` | Raw query execution without parameterization |
| 5 | Path Traversal | `server.py:64` | Arbitrary file read (no bounds checking) |
| 6 | Arbitrary File Write | `server.py:72` | Can overwrite any file on the system |
| 7 | Command Injection | `server.py:83` | shell=True with unsanitized input |
| 8 | SSRF | `server.py:94` | No URL validation, can access internal network |
| 9 | No Authentication | `server.py:38` | Any caller can invoke any tool |
| 10 | No Audit Logging | `server.py:44` | Tool invocations not recorded |

## Scan This Example

```bash
medusa scan examples/vulnerable-apps/mcp-server/
```

## Real-World Impact

These patterns appear in production MCP servers that:
- Give AI agents unrestricted filesystem access
- Store cloud credentials in plaintext config files
- Allow shell execution without command allowlisting
- Skip input validation because "the AI knows what it's doing"

MEDUSA catches all of these patterns with its 400+ MCP-specific security rules.
