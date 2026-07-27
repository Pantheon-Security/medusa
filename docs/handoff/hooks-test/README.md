# MEDUSA Hooks Test Battery — ready to run against the next build

Comprehensive test for the `medusa hooks` subsystem — the plumbing that puts medusa in the
editor/agent loop. Complements the PC001 scan/vet battery (`medusa-validate-*.sh`, shipped in the
PC001 test packet); this one covers
what that doesn't: the hooks install/uninstall lifecycle, the surgical-safety guarantee, per-scope
isolation, and the RUNTIME behaviour of every installed hook.

## Run it (against the updated build)

```bash
# 1. install the new wheel into the venv first (per the PC001 guide §0), then:
~/menv3/bin/python docs/handoff/hooks-test/our-hooks-battery.py
```

Expected: `RESULT: 25/25 passed`. Any `[XX ]` line names the check + the observed value.

- Paths auto-discover: `medusa` from `$PATH`/`~/menv3`, and the PreToolUse hook script from the
  installed `medusa` package (survives a python minor bump, e.g. 3.14 → 3.15).
- Override the binary if needed: `MEDUSA_BIN=/path/to/medusa ~/menv3/bin/python …`.
- All fixtures are throwaway temp dirs — it never touches your real project or `$HOME` config.
  (It does spawn `medusa mcp` briefly for the gatekeeper handshake and runs `git init` in temp dirs.)

## What it checks (25 assertions across 5 areas)

| Area | Checks |
|------|--------|
| **A. Lifecycle & idempotency** | install --all creates all 6 artifacts; `status` = 7/7; 2× install doesn't duplicate hooks/MCP; uninstall clears; clean-dir uninstall is a safe no-op |
| **B. Surgical safety** | a user's OWN PreToolUse hook, `env` key, MCP server, and pre-commit logic ALL survive install+uninstall while medusa-owned entries are removed |
| **C. Per-scope isolation** | `--cursor` / `--codex` / `--pre-commit` / `--claude-mcp` each create ONLY their own artifact |
| **D. Runtime behaviour** | PreToolUse: allow benign / bypass env / **fail-closed when medusa absent** / cwd-secret allowed (scans `$HOME` by design) / clean install allowed. pre-commit: blocks a staged secret, allows clean. MCP: `medusa mcp` handshake lists `scan_repo`/`scan_skill`/`secrets_scan` |
| **E. Validity** | generated JSON/TOML parse; pre-commit executable + shebang |

## Known result on the 2026-07-20 build (baseline)
25/25, one LOW cosmetic nit: `hooks uninstall` leaves empty `{}`/empty-TOML files for artifacts it
created (the medusa *entry* is removed and `status` reports absent — cosmetic only). If the next
build tidies that, the corresponding assertion still passes (it checks entries removed, not files
deleted).

## Fixture gotchas baked in (so results stay honest)
- Uses a well-formed AWS access-key format and a real-format `ghp_…` PAT for secret detection — NOT
  the allowlisted AWS **example** key (`AKIA…EXAMPLE`), which scanners deliberately ignore. The
  fixtures are assembled from fragments in the script so no complete token literal is committed.
- The PreToolUse hook's `secrets scan` targets `$HOME` chat/shell history, not project files — the
  cwd-secret check expects allow (0) accordingly.

See the 2026-07-22 hooks handover (`HANDOVER-medusa-2026-07-22-hooks.md`, kept in the PC001 handoff
archive) for the full write-up.
