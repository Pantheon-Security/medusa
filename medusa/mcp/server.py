"""MEDUSA MCP gatekeeper server (stdio).

A Model Context Protocol server that lets an MCP client (Claude Code, Cursor,
ChatGPT/Codex) vet untrusted code BEFORE installing or running it, and check
for leaked credentials. It is a thin protocol layer over
``medusa.core.scan_api`` — it adds no detection logic of its own.

Tools exposed:
  - scan_repo(url_or_path)  : vet a local repo path or remote git URL
  - scan_skill(path)        : vet a skill directory / SKILL.md
  - secrets_scan(path?)     : scan for leaked credentials (host discovery if no path)

All three are READ-ONLY (no state changes, no installs, no writes to the
target). Each returns a concise human+machine-readable verdict string:
verdict label, numeric score, and the top findings.

Transport is stdio only — this server is launched per-client by the MCP host
and inherits process isolation. There is no HTTP listener, so DNS-rebinding /
Origin concerns do not apply here.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from medusa.core import scan_api

mcp = FastMCP("medusa")


def _format_verdict(result: dict) -> str:
    """Render a vet result dict as a concise verdict string for the LLM.

    Leads with the verdict + score so the client can decide quickly, then
    lists the worst findings. Includes the raw JSON so an agent can parse it
    deterministically if needed.
    """
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("score", 0)
    target = result.get("target", "")
    counts = result.get("counts_by_severity", {}) or {}
    total = result.get("total_findings", 0)
    error = result.get("error")

    lines = [
        f"VERDICT: {verdict}  (risk score {score})",
        f"Target: {target}",
    ]
    if error:
        lines.append(f"Note: {error}")

    sev_bits = [f"{sev}={counts[sev]}" for sev in
                ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                if counts.get(sev)]
    lines.append(f"Findings: {total} total" + (f" ({', '.join(sev_bits)})" if sev_bits else ""))

    top = result.get("top_findings") or []
    if top:
        lines.append("Top findings:")
        for f in top:
            loc = f.get("file", "")
            line = f.get("line")
            where = f"{loc}:{line}" if line else loc
            lines.append(
                f"  [{f.get('severity')}] {f.get('issue', '')} "
                f"({f.get('scanner', '')} {f.get('rule_id') or ''}) {where}".rstrip()
            )

    if verdict == scan_api.DO_NOT_INSTALL:
        lines.append("RECOMMENDATION: Do NOT install/run this. Review the findings above first.")
    elif verdict == scan_api.CAUTION:
        lines.append("RECOMMENDATION: Proceed with caution — review the findings before installing.")
    else:
        lines.append("RECOMMENDATION: No blocking issues found.")

    lines.append("")
    lines.append("JSON: " + json.dumps(result, default=str))
    return "\n".join(lines)


def _format_secrets(result: dict) -> str:
    """Render a secrets_scan result dict as a concise string (values masked)."""
    count = result.get("count", 0)
    files = result.get("files_with_findings", 0)
    target = result.get("target", "")
    error = result.get("error")

    lines = [
        f"SECRETS: {count} credential(s) across {files} file(s)",
        f"Target: {target}",
    ]
    if error:
        lines.append(f"Note: {error}")

    summary = result.get("findings_summary") or []
    if summary:
        lines.append("Findings (values masked):")
        for f in summary:
            lines.append(
                f"  [{f.get('severity')}] {f.get('name')} ({f.get('issuer')}) "
                f"{f.get('file')}:{f.get('line')}"
            )
        lines.append("Action: rotate these credentials and run `medusa secrets purge` to redact.")
    else:
        lines.append("No credentials detected.")

    lines.append("")
    lines.append("JSON: " + json.dumps(result, default=str))
    return "\n".join(lines)


@mcp.tool()
def scan_repo(url_or_path: str) -> str:
    """Security-vet a code repository BEFORE installing or running it.

    Use this whenever the user is about to clone, install, or run code from
    an external source (a GitHub URL, a downloaded repo, a plugin). Pass a
    remote git URL (it will be shallow-cloned in a sandboxed temp dir and
    deleted afterward) or an existing local directory/file path.

    Returns a verdict — SAFE, CAUTION, or DO_NOT_INSTALL — with a numeric
    risk score and the top security findings. DO_NOT_INSTALL means the code
    has critical or multiple high-severity issues; do not run it.

    Args:
        url_or_path: A git URL (https://github.com/owner/repo) or a local
            filesystem path to a directory or file.
    """
    result = scan_api.vet_repo(url_or_path)
    return _format_verdict(result)


@mcp.tool()
def scan_skill(path: str) -> str:
    """Security-vet an agent skill BEFORE installing it.

    Use this before installing a Claude/agent skill from an untrusted source.
    Point it at the skill directory or its SKILL.md — the whole skill
    directory (including any bundled scripts, the real risk surface) is
    scanned.

    Returns a verdict — SAFE, CAUTION, or DO_NOT_INSTALL — with a risk score
    and top findings.

    Args:
        path: Local path to the skill directory or its SKILL.md file.
    """
    result = scan_api.vet_skill(path)
    return _format_verdict(result)


@mcp.tool()
def secrets_scan(path: str = "") -> str:
    """Scan for leaked credentials (API keys, tokens, secrets).

    Use this to check whether secrets have leaked into a file/directory, or —
    when called with no path — to scan the host's AI-chat and shell history
    for credentials that may have been pasted into a conversation.

    Secret VALUES are never returned (only masked metadata), so the result is
    safe to read aloud or keep in context.

    Args:
        path: A file or directory to scan. Leave empty to scan host AI-chat
            and shell history (the default credential-leak surface).
    """
    result = scan_api.secrets_scan(path if path else None)
    return _format_secrets(result)


def main() -> None:
    """Run the MEDUSA MCP gatekeeper server over stdio.

    Phase 2 wires this to a `medusa mcp` CLI command. Safe to call directly:
    `python3 -m medusa.mcp.server`.
    """
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
