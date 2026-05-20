# `medusa secrets` — AI Chat & Shell History Credential Scanner

> Find leaked API keys, tokens, and credentials in your AI chat history and shell
> history before someone else does.

## Why this exists

Developers paste credentials into AI assistants constantly during normal work:

- *"deploy this with `pypi-AgEI...`"*
- *"use my `ghp_...` to push the branch"*
- *"the AWS key is `AKIAIO...`"*

The assistants keep those conversations on disk in plaintext:

| Tool | File |
|---|---|
| Claude Code | `~/.claude/history.jsonl`, `~/.claude/projects/*/history.jsonl` |
| Cursor | `~/.config/Cursor/User/workspaceStorage/**/*chat*.json` |
| VS Code Copilot | `~/.config/Code/User/workspaceStorage/**/chatSessions/*.json` |
| Zed | `~/.local/share/zed/conversations/*` |
| Gemini CLI | `~/.gemini/history/**` |
| Aider | `~/.aider.chat.history.md`, `~/.aider.input.history` |
| Codex CLI | `~/.codex/history.jsonl`, `~/.codex/history/**` |
| Claude Desktop | `~/.config/Claude/`, `~/Library/Application Support/Claude/` (macOS) |

Plus shell histories:

| Shell / REPL | File |
|---|---|
| Bash | `~/.bash_history` |
| Zsh | `~/.zsh_history` (handles extended-history format) |
| Fish | `~/.local/share/fish/fish_history` |
| Python REPL | `~/.python_history` |
| Node REPL | `~/.node_repl_history` |
| psql | `~/.psql_history` |
| MySQL | `~/.mysql_history` |
| IRB | `~/.irb_history` |
| redis-cli | `~/.rediscli_history` |
| sqlite | `~/.sqlite_history` |

Anyone with read access to `$HOME` — or any future malware with shell access —
can `grep -r 'pypi-\|sk-ant-\|sk-\|ghp_\|AKIA' ~/` and harvest production
credentials in seconds. Most developers have never audited what's in these
files; in practice the answer is usually "a lot."

`medusa secrets scan` finds them. `medusa secrets purge` cleans them up.

---

## Commands

### `medusa secrets scan`

Discover and scan host artefacts.

```bash
medusa secrets scan                       # all chat + shell sources (default)
medusa secrets scan --source ai-chats     # AI assistants only
medusa secrets scan --source shell        # shell histories only
medusa secrets scan --source ai-chats,shell  # multi-source (= default)

medusa secrets scan --path FILE.json      # explicit single file
medusa secrets scan --path A --path B     # multiple explicit files

medusa secrets scan --reveal              # show real values (requires typed confirmation)
```

**Output**: a per-finding listing grouped by tool, plus a JSON report written
mode `0o600` to `~/.medusa/secrets-scan/secrets-<timestamp>.json` and symlinked
as `latest.json` for the purger.

### `medusa secrets purge`

Interactively walk findings from the most recent (or named) scan and redact
each one you accept.

```bash
medusa secrets purge                      # uses ~/.medusa/secrets-scan/latest.json
medusa secrets purge 20260519-074452      # uses a specific scan
medusa secrets purge --all --yes-i-know   # non-interactive batch mode (CI / power users)
```

**Interactive prompts:**

| Key | Meaning |
|---|---|
| `y` | Redact this finding |
| `n` | Skip this finding |
| `s` | Skip every remaining finding in this file |
| `a` | Accept every remaining finding (this and all that follow) |
| `q` | Quit; apply what's been accepted so far |
| `?` | Show this help |

---

## What's detected (21 issuers)

### AI providers
- **Anthropic** — `sk-ant-(api03|admin01)-...`
- **OpenAI** — `sk-...`, `sk-proj-...`, `sk-svcacct-...`, `sk-admin-...`
- **HuggingFace** — `hf_...`
- **Replicate** — `r8_...`
- **Cohere** — `co-...`

### Package registries
- **PyPI** — `pypi-AgE...`
- **npm** — `npm_...`

### Source forges
- **GitHub** — `ghp_...` (classic), `github_pat_...` (fine-grained), `gho_...` (OAuth), `ghs_/ghu_...` (App)
- **GitLab** — `glpat-...`

### Cloud
- **AWS** — `AKIA`, `ASIA`, `AGPA`, `AROA`, `AIPA`, `ANPA`, `ANVA`, `ABIA`, `ACCA` access key IDs
- **GCP** — service-account JSON `private_key_id` fingerprints

### Payments & communications
- **Stripe** — `sk_live_...`, `rk_live_...`
- **Slack** — `xoxb-`, `xoxp-`, `xoxo-`, `xoxa-` tokens
- **SendGrid** — `SG.<id>.<secret>`
- **Twilio** — `SK<32hex>`
- **Discord** — webhook URLs

### Cryptography
- **PEM private keys** — RSA, DSA, EC, OpenSSH, PGP, encrypted

---

## Safety properties

The feature is designed assuming the data it touches is the most sensitive on
the developer's machine. Every action takes one of two paths: *fail safe*
(refuse with a clear error) or *succeed with audit trail*.

| Guarantee | How it's enforced |
|---|---|
| **Local-only output.** Reports never leave the machine. | All write paths target `~/.medusa/secrets-scan/`. No HTTP client, no telemetry hook, no upload code in the module's dependency graph. |
| **Owner-only file permissions.** Reports + backups are mode `0o600`. | `os.open(..., O_CREAT, 0o600)`. `os.chmod(parent_dir, 0o700)`. |
| **Mask by default.** Console output is safe to screenshot. | `SecretObfuscator.mask_finding()` runs in the print path; `--reveal` requires the literal string `I UNDERSTAND` to be typed at a prompt. |
| **Backup before write.** No file is modified before a backup is on disk. | `shutil.copy2` to `~/.medusa/secrets-scan/backups/<run-id>/<mirrored-path>` runs before any redaction. |
| **JSONL stays parseable.** Redacting inside a chat message can't break the JSON document. | Replacement marker `[REDACTED-<RULE>-<RUN>]` contains no `"` / `\` / control chars. After redaction, every affected line is re-parsed; a parse failure aborts the write. |
| **Refuse on drift.** Won't clobber an edit the user made between scan and purge. | Before splicing, the byte range is re-read and compared against the secret recorded in the scan. Mismatch → abort, no partial redaction. |
| **Atomic write.** No half-written file possible. | Write to `<file>.medusa-tmp` in the same directory, then `os.replace`. On any exception the temp file is deleted and the original stays untouched. |
| **Per-provider safety cap.** A misconfigured glob can't enumerate `$HOME`. | If a discovery provider returns more than 500 files, the entire provider's output is dropped. |

---

## Architecture

```
medusa secrets scan
       │
       ▼
  chat_history_discovery.list_targets()  → [Target(path, source, kind), ...]
       │
       ▼
  ai_chat_history_scanner.scan_file(path) → FileScanResult
       │  (uses secret_patterns.SECRET_PATTERNS, 21 entries)
       ▼
  SecretObfuscator.mask_finding(...)      ← DEFAULT ON
       │  (--reveal bypasses, gated by typed confirmation)
       ▼
  write_report(results)                   → ~/.medusa/secrets-scan/secrets-<ts>.json (mode 0o600)
                                            ~/.medusa/secrets-scan/latest.json (symlink)
```

```
medusa secrets purge
       │
       ▼
  load_latest_report()  /  load_report(scan_id)
       │
       ▼
  _interactive_select(findings)  →  selected_indices: List[int]
       │
       ▼
  build_plans_from_report(report, selected_indices)
       │
       ▼
  execute_plans({path: FilePurgePlan}, run_id)
       │
       ├── For each plan:
       │    1. Read file, verify every byte range still matches expected_secret
       │    2. If any mismatch: refuse the whole plan (file_changed_since_scan)
       │    3. shutil.copy2 → ~/.medusa/secrets-scan/backups/<run-id>/<mirrored>
       │    4. Splice redactions in reverse-offset order
       │    5. For .json / .jsonl: re-parse every touched line
       │    6. Atomic write: temp file + os.replace
       │
       ▼
  List[PurgeResult] (file, redactions_applied, backup_path, error)
```

### Source layout

| File | Purpose |
|---|---|
| `medusa/core/secret_patterns.py` | 21 `SecretPattern` records (regex, severity, mask prefix, issuer label) |
| `medusa/core/chat_history_discovery.py` | Source providers; per-provider 500-file safety cap |
| `medusa/core/secret_obfuscator.py` | Masking + on-disk report I/O |
| `medusa/core/secret_purger.py` | JSONL-safe redaction engine; offset-stable batch splicing |
| `medusa/scanners/ai_chat_history_scanner.py` | Host-scoped scanner (not registered with the project scanner_registry) |
| `medusa/cli_secrets.py` | Click command group + scan/purge subcommands |

### Test coverage

| File | Coverage |
|---|---|
| `tests/test_ai_chat_history_scanner.py` | Every shipped pattern fires on its planted fixture; offset round-trip; Anthropic-not-double-matched-as-OpenAI; clean-file false-positive check; oversize-file skip; masking never includes full secret |
| `tests/test_secret_purger.py` | JSONL preservation; JSONL post-redact still parses; backup mode `0o600`; refuse-on-mismatch; multiple-redactions-same-file offset stability; partial selection via indices |
| `tests/test_chat_history_discovery.py` | Discovery surfaces real artefacts; `--source` filter semantics; runaway-provider safety cap; cross-provider deduplication |

---

## FAQ

**Q. Will this send my secrets anywhere?**
No. The module's dependency graph has no network client, no telemetry, no
report-upload path. Reports are local-only under `~/.medusa/secrets-scan/`.

**Q. Can I trust the redaction not to break my chat history?**
For JSON/JSONL files, every touched line is re-parsed after redaction. If the
parse fails, the write is aborted before it lands. The replacement marker
contains no characters that need JSON escaping. There's also a byte-identical
backup taken before any write — `cp backup original` restores it.

**Q. What if I edit the file between scan and purge?**
The purger refuses. Before splicing, it re-reads the byte range recorded by
the scan and compares against the expected secret string. Any mismatch and
the whole file's plan is aborted — partial application is impossible.

**Q. What about non-text data (Claude Desktop's IndexedDB, Cursor's sqlite)?**
The current scanner reads files as UTF-8 with replacement for invalid bytes,
so binary stores will scan but rarely produce meaningful hits, and the purger
won't try to redact inside binary data structures it can't parse. SQLite-aware
extraction is a future enhancement.

**Q. Can I add a new credential pattern?**
Add a `SecretPattern(...)` entry to `medusa/core/secret_patterns.py`. The
scanner picks it up automatically; no other wiring needed. A test in
`test_ai_chat_history_scanner.py` should confirm the pattern fires on a
planted fixture.

**Q. Can I add a new source (e.g. browser password DB, AWS CLI cache)?**
Add a `_discover_<source>()` function to `medusa/core/chat_history_discovery.py`
and append it to `SOURCE_PROVIDERS`. The 500-file safety cap protects against
overly broad globs.

**Q. Why not just delete the lines/messages containing secrets?**
Two reasons. First, the file's other content (project context, instructions,
your work) is yours and useful; only the secret needs to go. Second, deleting
lines could break invariants the upstream tool relies on (line counts,
message IDs, JSON object identity). Marker-based redaction keeps the
surrounding structure intact.

**Q. Is this free?**
Yes — free tier, no license required.

---

## Roadmap

- macOS / Windows path coverage parity (Linux is most complete today)
- SQLite-aware extraction for Cursor / Claude Desktop chat stores
- `medusa secrets restore <run-id>` — one-shot rollback from a purge run's backup tree
- Additional secret pattern coverage as new issuers are reported
- Optional GitHub Actions / pre-commit integration so a paste-secret-into-chat moment is caught before it's pushed elsewhere
