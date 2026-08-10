"""T4 born-RED gates: MCP012 suspicious-origin FN twins (2026-08-06).

`MCPConfigScanner.UNTRUSTED_SOURCES` reported the *textbook* spelling of each
suspicious MCP origin and missed every variant an attacker actually reaches for.
The control below fires; each FN twin beside it did not:

    http://<hash>.onion/sse       -> MCP012 CRITICAL   (control)
    http://<hash>.onion           -> nothing   the row was `\\.onion/`, anchored on
                                               a trailing slash that a bare origin
                                               URL (or a command/arg mention) has
                                               no reason to carry
    http://2130706433/sse         -> nothing   integer-encoded 127.0.0.1
    http://0x7f000001/sse         -> nothing   hex-encoded
    http://017700000001/sse       -> nothing   octal-encoded
    http://127.1/sse              -> nothing   dotted-short
    http://[dead:beef::1]/sse     -> nothing   IPv6 literal (only dotted-decimal
                                               v4 was enumerated)
    https://x.ngrok-free.app/sse  -> nothing   ngrok's CURRENT domain; the row
                                               listed only the legacy `ngrok.io`
                                               brand, so the provider outran the
                                               rule by renaming

The precision half is the harder constraint. This repo is mid-way through a
false-BLOCK campaign: e241711 deliberately retiered the plain `http://` row from
MCP012 (hard-block malice) to MCP005 (soft transport hygiene) because reporting
one plaintext endpoint three times under two verdict tiers made `agent-audit` — a
defensive scanner whose fixtures deliberately catalogue insecure MCP configs —
hard-block on config hygiene alone. So a suspicious ORIGIN (Tor / raw IP literal /
ephemeral tunnel) is MCP012; plaintext transport to an ordinary host stays MCP005.
The `test_precision_*` cases assert the ABSENCE of MCP012 and are the guard on
that line.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest

from medusa.core import vet_tiers
from medusa.scanners.base import ScannerIssue, Severity
from medusa.scanners.mcp_config_scanner import MCPConfigScanner


def _scan(tmp_path: Path, payload: dict, name: str = "mcp.json") -> List[ScannerIssue]:
    f = tmp_path / name
    f.write_text(json.dumps(payload, indent=2))
    return MCPConfigScanner().scan_file(f).issues


def _server(name: str, **cfg) -> Dict:
    return {"mcpServers": {name: cfg}}


def _ids(issues: List[ScannerIssue]) -> set:
    return {i.rule_id for i in issues}


def _of(issues: List[ScannerIssue], rule_id: str) -> List[ScannerIssue]:
    return [i for i in issues if i.rule_id == rule_id]


# --------------------------------------------------------------------------- #
# Control — the one spelling that already worked
# --------------------------------------------------------------------------- #

def test_control_onion_with_path_is_critical_mcp012(tmp_path):
    issues = _scan(tmp_path, _server(
        "hidden", url="http://abcdefghij234567xyz.onion/sse", transport="sse"))
    hits = _of(issues, "MCP012")
    assert hits, f"control must fire MCP012: {_ids(issues)}"
    assert any(i.severity == Severity.CRITICAL for i in hits), (
        f"a Tor hidden service as an MCP endpoint is a C2 signal: "
        f"{[i.severity for i in hits]}")


# --------------------------------------------------------------------------- #
# FN twins — same threat, spelling the old rows could not see
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("url,why", [
    ("http://abcdefghij234567xyz.onion",
     "a .onion origin with no path — the row required a trailing slash"),
    ("https://abcdefghij234567xyz.onion:9001",
     "a .onion origin with a port and no path"),
])
def test_fn_onion_without_trailing_slash(tmp_path, url, why):
    hits = _of(_scan(tmp_path, _server("hidden", url=url)), "MCP012")
    assert hits, why
    assert any(i.severity == Severity.CRITICAL for i in hits), (
        "the same hidden service must not be downgraded just because the URL "
        "carries no path")


def test_fn_onion_in_command_args(tmp_path):
    """The row is matched against command+args too, not only `url`."""
    hits = _of(_scan(tmp_path, _server(
        "hidden", command="npx",
        args=["-y", "mcp-remote@0.1.16", "http://abcdefghij234567xyz.onion"])),
        "MCP012")
    assert hits, "a .onion endpoint passed as an argument is the same origin"


@pytest.mark.parametrize("url,encoding", [
    ("http://2130706433/sse", "integer-encoded 127.0.0.1"),
    ("http://0x7f000001/sse", "hex-encoded 127.0.0.1"),
    ("http://017700000001/sse", "octal-encoded 127.0.0.1"),
    ("http://127.1/sse", "dotted-short 127.0.0.1"),
    ("http://0xc0a80001/sse", "hex-encoded 192.168.0.1 (private range)"),
    ("https://3232235777/mcp", "integer-encoded 192.168.1.1 over TLS"),
])
def test_fn_obfuscated_ip_literal_origin(tmp_path, url, encoding):
    ids = _ids(_scan(tmp_path, _server("numeric", url=url)))
    assert "MCP012" in ids, (
        f"{encoding} is an IP literal wearing a disguise — every HTTP client "
        f"resolves it, so the dotted-decimal row must not be the only one: {ids}")


@pytest.mark.parametrize("url,why", [
    ("http://[::1]/sse", "IPv6 loopback literal"),
    ("http://[dead:beef::1]/sse", "IPv6 literal host"),
    ("https://[2001:db8::1]:8443/mcp", "IPv6 literal with a port"),
])
def test_fn_ipv6_literal_origin(tmp_path, url, why):
    ids = _ids(_scan(tmp_path, _server("v6", url=url)))
    assert "MCP012" in ids, (
        f"{why}: only dotted-decimal v4 was enumerated, so switching address "
        f"family silently cleared the rule: {ids}")


@pytest.mark.parametrize("url,provider", [
    ("https://a1b2c3d4.ngrok-free.app/sse", "ngrok (current free domain)"),
    ("https://a1b2c3d4.ngrok.app/sse", "ngrok (current paid domain)"),
    ("https://a1b2c3d4.ngrok.dev/sse", "ngrok (current dev domain)"),
    ("https://a1b2c3d4.ngrok.io/sse", "ngrok (legacy domain — the only one listed)"),
    ("https://random-words-here.trycloudflare.com/sse", "cloudflare quick tunnel"),
    ("https://mine.loca.lt/sse", "localtunnel (current domain)"),
    ("https://mine.localtunnel.me/sse", "localtunnel (legacy domain)"),
    ("https://mine.serveo.net/sse", "serveo"),
    ("https://mine.tunnelto.dev/sse", "tunnelto"),
    ("https://mine.pagekite.me/sse", "pagekite"),
    ("https://mine.bore.pub/sse", "bore"),
    ("https://mine.telebit.io/sse", "telebit"),
    ("https://mine.lhr.life/sse", "localhost.run (lhr.life)"),
    ("https://mine.localhost.run/sse", "localhost.run"),
    ("https://mine.devtunnels.ms/sse", "microsoft dev tunnels"),
])
def test_fn_ephemeral_tunnel_origin(tmp_path, url, provider):
    # MCP017, not MCP012: still detected and still HIGH, but soft-tiered, because
    # running an MCP server behind ngrok is how people develop them. See
    # test_tunnel_row_is_soft_tiered_not_a_hard_block.
    ids = _ids(_scan(tmp_path, _server("tunnelled", url=url)))
    assert "MCP019" in ids, (
        f"{provider}: an MCP endpoint behind an ephemeral tunnel is someone's "
        f"laptop reachable from the internet for the next few hours — the "
        f"defining shape of a throwaway C2/exfil endpoint: {ids}")


def test_fn_tunnel_in_args_not_only_url(tmp_path):
    ids = _ids(_scan(tmp_path, _server(
        "tunnelled", command="npx",
        args=["-y", "mcp-remote@0.1.16", "https://a1b2c3d4.ngrok-free.app/sse"])))
    assert "MCP019" in ids, "a tunnel endpoint passed as an argument is the same origin"


def test_mcp012_is_hard_block_malice(tmp_path):
    """The whole point of routing these to MCP012 rather than MCP005."""
    assert vet_tiers.soft_tier_of({"rule_id": "MCP012"}) is None, (
        "MCP012 must stay hard-block malice — Tor and raw-IP-literal origins are "
        "install-time danger, not config hygiene")


# --------------------------------------------------------------------------- #
# Precision twins — the agent-audit guard (see e241711)
# --------------------------------------------------------------------------- #

def test_precision_plain_http_host_is_mcp005_never_mcp012(tmp_path):
    ids = _ids(_scan(tmp_path, _server(
        "ordinary", url="http://ordinary.example.com/sse", transport="sse")))
    assert "MCP005" in ids, f"plaintext HTTP must still be reported: {ids}"
    assert "MCP012" not in ids, (
        "plaintext transport to an ordinary host is CWE-319 hygiene (MCP005, "
        f"soft) — reinstating it as an untrusted ORIGIN re-breaks agent-audit: {ids}")


def test_precision_plain_http_host_with_port_is_mcp005_never_mcp012(tmp_path):
    ids = _ids(_scan(tmp_path, _server(
        "ordinary", url="http://untrusted-server.example.com:8080/mcp")))
    assert "MCP005" in ids, ids
    assert "MCP012" not in ids, (
        f"a port does not make an ordinary hostname a suspicious origin: {ids}")


def test_precision_https_ordinary_host_is_clean_of_origin_findings(tmp_path):
    ids = _ids(_scan(tmp_path, _server(
        "gh", url="https://api.githubusercontent.com/repos/acme/mcp/contents")))
    assert "MCP012" not in ids, f"an ordinary HTTPS host is not a suspicious origin: {ids}"
    assert "MCP005" not in ids, f"HTTPS is not a plaintext-transport finding: {ids}"


def test_precision_ordinary_https_hosts_that_merely_look_numeric_or_ngrokish(tmp_path):
    """Near-miss hostnames that must NOT be read as IP literals or tunnels.

    Every one of these matched an earlier draft of the rows and was caught here;
    the origin rows hard-block, so a name that merely CONTAINS a provider or a
    run of digits has to stay clean.
    """
    for url in ("https://mcp.example.org/v1",
                "https://192-168-1-1.customer.example.net/sse",
                "https://ngrokked.example.com/sse",     # `ngrok` is not a whole label
                "https://ngrok.example.com/sse",        # someone's own host, not ngrok's
                "https://api.onion.example.com/mcp",    # a Tor address ENDS in .onion
                "https://cdn.example.com/dl/bore.pub.tar.gz",   # apex inside a filename
                "https://api.example.com/v2/0x7f000001/resource"):
        ids = _ids(_scan(tmp_path, _server("ok", url=url)))
        assert "MCP012" not in ids, f"{url} is an ordinary hostname: {ids}"


def test_precision_localhost_stays_low(tmp_path):
    issues = _scan(tmp_path, _server("dev", url="http://localhost:3000/sse"))
    hits = _of(issues, "MCP012")
    assert hits, "the localhost development-server row must still report"
    assert all(i.severity == Severity.LOW for i in hits), (
        "a local dev server is an FYI, not malice: "
        f"{[(i.severity, i.message) for i in hits]}")


def test_precision_dotted_quad_keeps_its_existing_medium_tier(tmp_path):
    """The plain dotted-decimal row must not be double-reported or escalated."""
    hits = _of(_scan(tmp_path, _server("ip", url="https://192.168.1.10:8443/mcp")),
               "MCP012")
    assert len(hits) == 1, (
        f"one address, one finding — the new encodings must not overlap the "
        f"existing dotted-decimal row: {[i.message for i in hits]}")
    assert hits[0].severity == Severity.MEDIUM, (
        f"dotted-decimal keeps its established tier: {hits[0].severity}")


def test_precision_stdio_npx_server_has_no_origin_finding(tmp_path):
    ids = _ids(_scan(tmp_path, _server(
        "fs", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem@1.2.3",
                                   "/home/user/projects"])))
    assert "MCP012" not in ids, f"an ordinary stdio server has no remote origin: {ids}"
    assert "MCP005" not in ids, f"an ordinary stdio server has no transport: {ids}"


def test_precision_ordinary_args_do_not_trip_the_numeric_rows(tmp_path):
    """Version numbers, ports and paths are full of digits — none is an IP literal."""
    ids = _ids(_scan(tmp_path, _server(
        "svc", command="uvx", args=["mcp-server-git@2026.8.0", "--port", "8080",
                                    "--timeout", "30000", "--repo", "/srv/git/1234567"])))
    assert "MCP012" not in ids, f"digits in args are not an origin: {ids}"


# --- ReDoS gate for the origin rows ------------------------------------------
# The fetch-exec scanner has an explicit CR-006 ReDoS gate; the MCP origin rows
# had none, and the first version of the tunnel row shipped a quadratic
# `(?:[A-Za-z0-9-]+\.)*` prefix: `"a."*20000` in one args value took ~18s inside
# MCPConfigScanner.scan_file. That is a denial of service on the PRE-INSTALL
# gatekeeper path (`medusa vet`, `medusa mcp`, the PreToolUse hook), reachable
# from a 40 KB attacker-supplied mcp.json — a worse outcome than the false
# negative the row was widened to close. Drives the real scan_file(), so it keeps
# holding however the matching is implemented next.
import json as _json
import time as _time

import pytest as _pytest


@_pytest.mark.parametrize("payload,label", [
    ("a." * 20000, "dotted labels that never reach an apex"),
    ("ngrok-" * 20000, "apex prefix repeated without a dot"),
    ("eyJhbGciOi." * 3000, "dotted base64 (non-adversarial JWT-ish arg)"),
    ("a-" * 20000 + ".ngrok-free.app", "long label ending at a real apex"),
    ("127.0.0." * 5000, "numeric labels (IP-literal rows)"),
])
def test_mcp_origin_rows_are_not_redos(tmp_path, payload, label):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_json.dumps(
        {"mcpServers": {"x": {"command": "y", "args": ["--tag", payload]}}}))
    scanner = MCPConfigScanner()
    start = _time.time()
    scanner.scan_file(cfg)
    elapsed = _time.time() - start
    assert elapsed < 2.0, (
        f"{label}: MCPConfigScanner took {elapsed:.2f}s on a "
        f"{cfg.stat().st_size}-byte config (ReDoS in an origin row)")


# --- locator: one finding PER SERVER, not per matched string -----------------
# The origin rows locate a finding by searching the config text. Several rows match
# a fixed suffix shared by every server behind one provider (`ngrok-free.app`), so
# locating by the matched text alone put every such server on the FIRST one's line
# — and the downstream (line, rule_id) dedup then discarded all but one. Six
# tunnelled endpoints were reported as one, five vanished from the report AND the
# count. It was invisible because every match/no-match case still passed: the bug
# was in locating, not matching. This gate pins the reader-facing property.

def _tunnel_config(tmp_path, n, apex="ngrok-free.app"):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_json.dumps(
        {"mcpServers": {f"h{i}": {"url": f"https://host{i}.{apex}/sse"}
                        for i in range(n)}}, indent=2))
    return cfg


@_pytest.mark.parametrize("n", [2, 3, 6])
def test_each_tunnelled_server_gets_its_own_finding(tmp_path, n):
    scanner = MCPConfigScanner()
    issues = [i for i in scanner.scan_file(_tunnel_config(tmp_path, n)).issues
              if i.rule_id == "MCP019"]
    lines = sorted({i.line for i in issues})
    assert len(lines) == n, (
        f"{n} servers behind one tunnel apex collapsed onto {len(lines)} line(s) "
        f"{lines} — the reader cannot see which endpoints are tunnelled")


def test_tunnel_row_is_soft_tiered_not_a_hard_block(tmp_path):
    """A routine dev config (several servers behind ngrok) must not hard-block."""
    from medusa.core.vet_tiers import soft_tier_of
    assert soft_tier_of({"rule_id": "MCP019", "severity": "HIGH"}) == "mcp_ephemeral_origin"
    # ...while genuinely suspicious origins stay hard.
    assert soft_tier_of({"rule_id": "MCP012", "severity": "CRITICAL"}) is None


def test_onion_still_hard_blocks_on_mcp012(tmp_path):
    """Softening tunnels must not soften Tor."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_json.dumps({"mcpServers": {"t": {"url": "http://abcdef1234.onion/sse"}}}))
    ids = {(i.rule_id, str(i.severity).split(".")[-1])
           for i in MCPConfigScanner().scan_file(cfg).issues}
    assert ("MCP012", "CRITICAL") in ids


def test_no_hard_block_mcp_rule_is_accidentally_soft_tiered():
    """Soft-tiering is the one edit that silently turns malice into a non-blocker.

    Near-miss, 2026-08-07: the tunnel row was first split onto `MCP017` — an id
    ALREADY carrying the CVE-2025-6514 mcp-remote RCE (CVSS 9.6) and the
    shell-dropper launch command. Adding MCP017 to a soft tier would have made a
    critical RCE and a shell dropper non-blocking, and nothing would have failed:
    the tunnel tests passed, and no test asserted those two stay hard. Moved to
    MCP019. This pins every id that must never be softened.
    """
    from medusa.core.vet_tiers import soft_tier_of
    must_stay_hard = {
        "MCP017": "CVE-2025-6514 mcp-remote RCE (CVSS 9.6) + shell-dropper command",
        "MCP012": "Tor hidden service / raw IP literal origin",
        "MCP001": "hardcoded secret in an env block",
        "MCP002": "hardcoded secret in args",
    }
    for rule_id, what in must_stay_hard.items():
        assert soft_tier_of({"rule_id": rule_id, "severity": "CRITICAL"}) is None, (
            f"{rule_id} ({what}) is soft-tiered — it can no longer hard-block")
    # ...and the one that is deliberately soft stays soft.
    assert soft_tier_of({"rule_id": "MCP019", "severity": "HIGH"}) == "mcp_ephemeral_origin"


def test_every_emitted_mcp_rule_id_is_documented_exactly_once():
    """Rule-id reuse is invisible at the point of choosing one.

    The MCP017 collision happened because the free id is NOT discoverable from
    `UNTRUSTED_SOURCES`, where the choice is made: the id map lives in a class
    docstring ~200 lines up, and the conflicting emitter was in an unrelated
    method. This makes reuse fail loudly at the place a new row is added.
    """
    import inspect
    import re as _re

    src = inspect.getsource(MCPConfigScanner)
    documented = _re.findall(r"^\s*-\s+(MCP\d{3}):", MCPConfigScanner.__doc__ or "",
                             _re.MULTILINE)
    assert documented, "the MCP rule-id map disappeared from the class docstring"
    assert len(documented) == len(set(documented)), (
        f"an id is listed twice in the docstring map: "
        f"{[r for r in documented if documented.count(r) > 1]}")

    emitted = set(_re.findall(r"rule_id=[\"'](MCP\d{3})[\"']", src))
    emitted |= set(_re.findall(r"[\"'](MCP\d{3})[\"']\s*\)", src))  # table rows
    undocumented = sorted(emitted - set(documented))
    assert not undocumented, (
        f"emitted but absent from the docstring map: {undocumented} — add them, "
        f"so the next person choosing an id can see what is taken")


def test_locator_handles_non_ascii_hosts(tmp_path):
    """An IDN host must not collapse onto the first match.

    json.dumps writes `\\u00e9`; the parsed value holds `é`. Searching only the
    parsed form finds nothing in the file, the fallback fires, and every such
    server lands on the first match — the same collapse, reached a different way.
    Harmless while the tunnel row is soft-tiered; a count bug again the moment a
    per-server non-soft row is added, so it is fixed at the locator.
    """
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_json.dumps(
        {"mcpServers": {f"h{i}": {"url": f"https://é{i}.ngrok-free.app/sse"}
                        for i in range(3)}}, indent=2))
    lines = sorted({i.line for i in MCPConfigScanner().scan_file(cfg).issues
                    if i.rule_id == "MCP019"})
    assert len(lines) == 3, f"non-ASCII hosts collapsed onto {lines}"
