# v2026.5.8 — `medusa secrets`

> **Your PyPI token might be in your Claude chat history right now.**
> v2026.5.8 ships the tool to find it — and the tool to fix it.

## The headline

Developers paste credentials into AI assistants every day. The assistants keep
those conversations in plaintext on disk. Anyone with read access to `$HOME`
can harvest production secrets in seconds.

**`medusa secrets scan`** finds them. **`medusa secrets purge`** cleans them up.

```bash
$ medusa secrets scan
  ...
  Total: 13 credentials across 1 file(s).
  Report:  /home/ross/.medusa/secrets-scan/secrets-20260519-074452.json
```

```bash
$ medusa secrets purge

  [CRITICAL] PyPI API token (pypi)
      /home/ross/.claude/history.jsonl:125:94
      pypi-AgEIc***...***
    redact?  [y/n/s/a/q/?]: y
  ...
  ✓ /home/ross/.claude/history.jsonl  (13 redacted)
      backup → /home/ross/.medusa/secrets-scan/backups/20260519-074452/...
```

## What's detected (21 issuers)

| Category | Providers |
|---|---|
| 🤖 **AI providers** | Anthropic · OpenAI · HuggingFace · Replicate · Cohere |
| 📦 **Package registries** | PyPI · npm |
| 🐙 **Source forges** | GitHub PAT (classic + fine-grained + OAuth + App) · GitLab PAT |
| ☁️ **Cloud** | AWS access keys · GCP service-account JSON |
| 💳 **Payments / comms** | Stripe live + restricted · Slack bot/user · SendGrid · Twilio · Discord webhooks |
| 🔑 **Cryptography** | PEM private keys (RSA · DSA · EC · OpenSSH · PGP · encrypted) |

## Where it scans

**AI chat histories** — Claude Code, Claude Desktop, Cursor, Zed, VS Code Copilot,
Gemini CLI, Aider, Codex CLI.

**Shell histories** — bash, zsh, fish, python REPL, node REPL, psql, mysql, irb,
redis-cli, sqlite.

Filter with `--source ai-chats` or `--source shell`. Or scan a specific file
(e.g. a ChatGPT export) with `--path <file>`.

## Safety properties

- 🔒 **Local-only.** No telemetry. No network calls. Reports mode `0o600` under `~/.medusa/secrets-scan/`. Never written to project trees.
- 🙈 **Masked by default.** Output is `pypi-AgEIc***...***` — safe to screenshot. `--reveal` requires typed `I UNDERSTAND` to reveal full values.
- 💾 **Backup before write.** Every redaction is preceded by a byte-identical backup; `cp` restores it.
- 🧩 **JSONL-safe.** Redaction marker contains no JSON-unsafe characters. Modified lines are re-parsed; a parse failure aborts the write.
- 🛑 **Refuse on drift.** If the source file changed between scan and purge, the purger refuses rather than risk clobbering an edit.

## Try it

```bash
pip install -U medusa-security==2026.5.8
medusa secrets scan
```

## Documentation

- **[Full secrets scanner guide](https://github.com/Pantheon-Security/medusa/blob/main/docs/SECRETS_SCANNER.md)** — architecture, all 21 patterns, safety details, FAQ
- **[CHANGELOG](https://github.com/Pantheon-Security/medusa/blob/main/CHANGELOG.md)** — full release notes

## Quality

- 28 new unit tests for the secrets feature; full suite **419 passed / 10 skipped / 0 failed**
- Benchmark corpus regression: **5/5 passed**
- Security hardening tests: **55/55 passed**
- Self-scan on MEDUSA itself: 879 files scanned, 0 crashes
- End-to-end manual verification against real chat-history layouts on Linux: scan + report write + interactive purge + JSONL re-parse + backup-and-restore round-trip all clean

## Tier

**Free.** No license required.

---

**Previous release**: v2026.5.7 — Indirect PI rules, supply chain import-pattern scanner, macOS/Windows multiprocessing fix.
