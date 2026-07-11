"""`medusa secrets` command group.

Host-scoped credential scanner. Wired into the main CLI via
`main.add_command(secrets)` in `medusa/cli.py`.

Subcommands:
    secrets scan         — find credentials in chat / shell history
    secrets purge        — interactively redact findings in place

This module intentionally keeps networking, telemetry, and reporting
helpers out of its dependency graph: the input files contain some of
the most sensitive data on a developer's machine, and nothing here
should ever phone home.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import click

from medusa.core.chat_history_discovery import Target, list_targets
from medusa.core.secret_obfuscator import (
    load_latest_report,
    load_report,
    mask_finding,
    mask_secret,
    write_report,
)
from medusa.core.secret_patterns import SECRET_PATTERNS_BY_ID
from medusa.core.secret_purger import (
    build_plans_from_report,
    execute_plans,
)
from medusa.scanners.ai_chat_history_scanner import (
    FileScanResult,
    SecretFinding,
    scan_file,
)


def _format_finding(finding: SecretFinding, reveal: bool) -> str:
    """One-line description suitable for terminal output."""
    sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    rendered = finding.secret if reveal else mask_finding(finding)
    location = f"{finding.file_path}:{finding.line}:{finding.column}"
    return f"  [{sev}] {finding.name} ({finding.issuer})\n      {location}\n      {rendered}"


def _summarise(results: List[FileScanResult]) -> tuple[int, int]:
    """Return (total_findings, files_with_findings)."""
    total = sum(len(r.findings) for r in results)
    hot = sum(1 for r in results if r.findings)
    return total, hot


@click.group()
def secrets():
    """Scan and purge credentials in AI chat history and shell history.

    Operates on host artefacts in $HOME, not on project files. By default,
    secret values in reports are masked — pass --reveal to see them.

    Examples:
        medusa secrets scan                       # scan all known histories
        medusa secrets scan --path ~/notes.md     # scan a specific file
        medusa secrets purge                      # interactively redact
    """


@secrets.command(name="scan")
@click.option(
    "--path",
    "explicit_paths",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    multiple=True,
    help="Scan one specific file. May be passed multiple times. "
         "Bypasses host discovery.",
)
@click.option(
    "--source",
    "source_filter",
    type=str,
    default=None,
    help="Limit auto-discovery to a comma-separated kind list: "
         "ai-chats, shell, all. Default: all sources.",
)
@click.option(
    "--reveal",
    is_flag=True,
    default=False,
    help="Show actual secret values in the output instead of masked. "
         "Requires a typed confirmation; the report becomes a secrets dump.",
)
@click.option(
    "--exit-code",
    "exit_code",
    is_flag=True,
    default=False,
    help="Exit non-zero (1) if any credential is found (git-diff convention). "
         "Use in gates/hooks so a detection actually blocks; default is 0.",
)
def secrets_scan(explicit_paths: tuple[Path, ...], source_filter: Optional[str],
                 reveal: bool, exit_code: bool):
    """Scan host artefacts (or explicit --path files) for credentials."""
    if reveal:
        click.echo(
            "\n  ⚠  --reveal will print actual secret values to this terminal.\n"
            "     The output may be captured by terminal scrollback, screen\n"
            "     recordings, shell history, or paste buffers.\n",
            err=True,
        )
        confirmation = click.prompt(
            "  Type 'I UNDERSTAND' to continue",
            default="",
            show_default=False,
        )
        if confirmation.strip() != "I UNDERSTAND":
            click.echo("  Aborted — values stay masked.\n", err=True)
            return

    # Build the target list: explicit --path wins; otherwise discover.
    targets_to_scan: List[tuple[Path, str]] = []  # (path, source_label)
    if explicit_paths:
        targets_to_scan = [(p, "explicit") for p in explicit_paths]
    else:
        try:
            filter_list = [s.strip() for s in source_filter.split(",")] if source_filter else None
            discovered = list_targets(filter_list)
        except ValueError as exc:
            click.echo(f"  Error: {exc}\n  Valid sources: ai-chats, shell, all\n", err=True)
            raise click.exceptions.Exit(2)
        if not discovered:
            click.echo(
                "  No AI chat or shell history files found on this host.\n"
                "  Pass --path <file> to scan a specific file.\n",
                err=True,
            )
            raise click.exceptions.Exit(0)
        targets_to_scan = [(t.path, t.source) for t in discovered]

    click.echo(f"\n  Scanning {len(targets_to_scan)} file(s)...\n")

    results: List[FileScanResult] = []
    for path, label in targets_to_scan:
        result = scan_file(path, source_label=label)
        results.append(result)

    total, hot = _summarise(results)

    if total == 0:
        click.echo("  ✓ No credentials detected.\n")
        return

    # Group output by source label so the user can spot "everything from
    # claude-code goes here, everything from bash there".
    by_source: dict[str, list[FileScanResult]] = {}
    for result in results:
        if not result.findings:
            continue
        label = result.findings[0].source_label or "explicit"
        by_source.setdefault(label, []).append(result)

    for label in sorted(by_source):
        click.echo(f"  ── {label} " + "─" * max(2, 60 - len(label)))
        for result in by_source[label]:
            click.echo(f"  {result.file_path}  ({len(result.findings)} finding(s))")
            for finding in result.findings:
                click.echo(_format_finding(finding, reveal=reveal))
        click.echo()

    sev_word = "credential" if total == 1 else "credentials"
    click.echo(f"  Total: {total} {sev_word} across {hot} file(s).")

    # Persist for the purger and for the user's own records. The report
    # contains raw secrets — written mode 0o600 under ~/.medusa/.
    if total > 0:
        report_path = write_report(results)
        click.echo(f"  Report:  {report_path}")
        click.echo(f"  (also linked as ~/.medusa/secrets-scan/latest.json)")

    if not reveal:
        click.echo(
            "\n  Values are masked. Re-run with --reveal to show full values, or\n"
            "  run `medusa secrets purge` to interactively redact in place.\n"
        )

    # total > 0 here (the total == 0 branch returned early). With --exit-code the
    # command fails so a gate/hook that runs it blocks (default stays exit 0).
    if exit_code:
        raise click.exceptions.Exit(1)


def _mask_for_report_finding(finding: dict) -> str:
    """Mask the raw secret string from a report-on-disk finding using
    the same prefix policy as a live SecretFinding."""
    pattern = SECRET_PATTERNS_BY_ID.get(finding.get("rule_id", ""))
    prefix = pattern.mask_prefix if pattern else 6
    return mask_secret(finding.get("secret", ""), prefix)


@secrets.command(name="purge")
@click.argument("scan_id", required=False)
@click.option(
    "--all",
    "purge_all",
    is_flag=True,
    default=False,
    help="Redact every finding without prompting. Requires --yes-i-know.",
)
@click.option(
    "--yes-i-know",
    is_flag=True,
    default=False,
    help="Required co-flag for --all. Acknowledges that you are about "
         "to modify host artefacts non-interactively.",
)
def secrets_purge(scan_id: Optional[str], purge_all: bool, yes_i_know: bool):
    """Interactively redact credentials from the most recent scan.

    Without arguments, loads `~/.medusa/secrets-scan/latest.json`.
    Pass a SCAN_ID like 20260519-074116 to use a specific report.

    For each finding you'll see:
        [y]es redact   [n]o skip   [s]kip rest of this file
        [a]ll remaining   [q]uit   [?] help
    """
    if scan_id:
        report = load_report(scan_id)
        if report is None:
            click.echo(f"  No report found for scan-id {scan_id!r}.\n", err=True)
            raise click.exceptions.Exit(2)
    else:
        report = load_latest_report()
        if report is None:
            click.echo(
                "  No scan reports found. Run `medusa secrets scan` first.\n",
                err=True,
            )
            raise click.exceptions.Exit(2)

    findings = report.get("findings", [])
    if not findings:
        click.echo("  Report has no findings — nothing to purge.\n")
        return

    if purge_all and not yes_i_know:
        click.echo(
            "  --all requires --yes-i-know. Refusing to redact non-interactively\n"
            "  without explicit acknowledgement.\n",
            err=True,
        )
        raise click.exceptions.Exit(2)

    if purge_all:
        selected = list(range(len(findings)))
    else:
        selected = _interactive_select(findings)
        if not selected:
            click.echo("  Nothing selected. No changes made.\n")
            return

    plans = build_plans_from_report(report, selected_indices=selected)
    click.echo(
        f"\n  Applying {sum(len(p.redactions) for p in plans.values())} "
        f"redaction(s) across {len(plans)} file(s)...\n"
    )

    results = execute_plans(plans)

    applied = 0
    failed = 0
    for r in results:
        if r.error:
            failed += 1
            click.echo(f"  ✗ {r.file_path}  ({r.error})")
        else:
            applied += r.redactions_applied
            click.echo(f"  ✓ {r.file_path}  ({r.redactions_applied} redacted)")
            if r.backup_path:
                click.echo(f"      backup → {r.backup_path}")

    click.echo()
    if failed:
        click.echo(f"  {applied} redacted, {failed} file(s) failed.")
    else:
        click.echo(f"  Done. {applied} redaction(s) applied.")


_PURGE_HELP = """\

      y — redact this finding
      n — skip this finding
      s — skip every remaining finding in this file
      a — accept every remaining finding (this and all that follow)
      q — quit; apply what's been accepted so far
      ? — show this help

"""


def _interactive_select(findings: List[dict]) -> List[int]:
    """Walk the findings and collect a list of indices the user wants to
    redact. Returns indices into the input list, in original order.
    """
    selected: List[int] = []
    accept_all = False
    skip_file: Optional[str] = None

    # Sort by file then by line so we walk findings in a coherent
    # order. Map back to original indices.
    ordered = sorted(
        range(len(findings)),
        key=lambda i: (findings[i]["file_path"], findings[i]["line"]),
    )

    for idx in ordered:
        f = findings[idx]
        current_file = f["file_path"]

        if skip_file is not None and skip_file != current_file:
            skip_file = None
        if skip_file == current_file:
            continue
        if accept_all:
            selected.append(idx)
            continue

        sev = f.get("severity", "?")
        click.echo(
            f"\n  [{sev}] {f.get('name', f.get('rule_id'))}"
            f"  ({f.get('issuer', '')})"
        )
        click.echo(f"      {current_file}:{f.get('line')}:{f.get('column')}")
        click.echo(f"      {_mask_for_report_finding(f)}")

        while True:
            choice = click.prompt("    redact?  [y/n/s/a/q/?]", default="n", show_default=False).strip().lower()
            if choice == "?":
                click.echo(_PURGE_HELP)
                continue
            if choice in {"y", "yes"}:
                selected.append(idx)
                break
            if choice in {"n", "no", ""}:
                break
            if choice == "s":
                skip_file = current_file
                break
            if choice == "a":
                accept_all = True
                selected.append(idx)
                break
            if choice == "q":
                return selected
            click.echo("    (use one of: y, n, s, a, q, ?)")

    return selected
