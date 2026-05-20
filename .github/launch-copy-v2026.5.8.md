# v2026.5.8 launch copy — pick and adapt

Short copy blocks for tweets, posts, Discord, blog hooks. Not committed
in-product; staging file for marketing.

---

## Tweet / short post (280 chars)

> Your PyPI token might be in your Claude chat history right now.
>
> `medusa secrets scan` finds it. `medusa secrets purge` cleans it up.
>
> 21 credential issuers. AI chat + shell history. Free.
>
> `pip install -U medusa-security`
>
> 🔗 https://github.com/Pantheon-Security/medusa

---

## Tweet (longer / thread starter)

> 🧵 Devs paste API keys into AI assistants every day:
>
> "deploy with `pypi-AgEI...`"
> "push using `ghp_...`"
> "the AWS key is `AKIA...`"
>
> Claude / Cursor / Copilot keep those in plaintext on disk. Anyone with shell
> access can grep `$HOME` and harvest them.
>
> We just shipped the fix. 👇

> `medusa secrets scan` walks every AI assistant's chat store + your shell history
> and detects 21 credential types — Anthropic, OpenAI, PyPI, GitHub PATs,
> AWS, GCP, Stripe, Slack, private keys.

> `medusa secrets purge` walks each finding `[y/n]` and redacts in place.
> Byte-identical backup before write. JSONL stays parseable. Refuses on drift.
> Local-only — no telemetry, ever.

> Free tier. v2026.5.8 out now.
> `pip install -U medusa-security && medusa secrets scan`

---

## Hacker News / Reddit post title

> Show HN: medusa secrets — scan your Claude / Cursor / shell history for leaked API keys, then redact them in place

## Hacker News post body

> Hey HN — shipping a feature this week that addresses a pattern we've all
> done a hundred times without thinking about it.
>
> When you paste an API key into an AI assistant — `pypi-AgEI...`, `ghp_...`,
> `sk-ant-...`, whatever — that key is now sitting in plaintext on your disk.
> Claude Code, Cursor, Copilot, Zed, ChatGPT desktop, Gemini, Aider — they
> all keep conversation transcripts locally for legitimate reasons (context,
> restart, multi-session). They're all world-readable to anyone with shell
> access. Most developers have never audited what's in those files.
>
> So we built `medusa secrets` into MEDUSA (our open-source AI security
> scanner). Two commands:
>
> `medusa secrets scan` — walks AI assistant chat stores + shell histories
> (~/.bash_history, ~/.zsh_history, fish, psql, mysql, ...) and detects 21
> credential types (Anthropic, OpenAI, HuggingFace, PyPI, npm, GitHub PATs,
> AWS, GCP, Stripe, Slack, SendGrid, Twilio, Discord webhooks, PEM private keys).
> Values masked in output by default; `--reveal` requires typed
> "I UNDERSTAND" because the report itself becomes a secrets dump.
>
> `medusa secrets purge` — walks findings interactively `[y/n/s/a/q]` and
> redacts the secret in place. Mandatory byte-identical backup before write.
> JSONL-safe splicing — the redaction marker contains no JSON-unsafe chars and
> every touched line is re-parsed afterwards. Refuses if the source file
> changed between scan and purge (so you can't clobber an edit you forgot
> about). Local-only — no telemetry, no upload code in the module's
> dependency graph.
>
> Free tier, no license required.
>
> `pip install -U medusa-security && medusa secrets scan`
>
> Repo: https://github.com/Pantheon-Security/medusa
> Docs: https://github.com/Pantheon-Security/medusa/blob/main/docs/SECRETS_SCANNER.md
>
> First test runs we've done usually surface a handful to a few dozen real
> credentials per developer — keys people had no idea were sitting there.
>
> Happy to answer Q's about architecture, threat model, etc.

---

## Discord / Slack one-liner

> 🚨 v2026.5.8 out: `medusa secrets scan` finds API keys hiding in your AI
> chat history (`~/.claude/history.jsonl`, Cursor, Copilot, Zed, ...) and
> shell history. `medusa secrets purge` redacts them in place. Free.
> `pip install -U medusa-security`

---

## Email subject lines (newsletter)

- "Your PyPI token is in your Claude chat history. Here's how to find it."
- "The secret hiding in your AI assistant's chat log"
- "MEDUSA v2026.5.8: scan & purge leaked credentials from AI chat history"
- "21 credential types, 2 commands, 0 telemetry — medusa secrets"

---

## LinkedIn (longer)

> When you paste an API key into an AI assistant — and we all do this, all the
> time — that key is now sitting in plaintext on your disk. Claude Code,
> Cursor, Copilot, Zed, ChatGPT desktop, Gemini, Aider: all of them store the
> conversation transcript locally for legitimate reasons (context, restart,
> multi-session). All of them are world-readable to anyone with shell access.
>
> We just shipped a fix in MEDUSA v2026.5.8:
>
> • `medusa secrets scan` — finds credentials in every AI assistant's chat
>   store, plus your shell history. 21 issuer types (cloud, AI, payments,
>   private keys, source forges).
>
> • `medusa secrets purge` — interactively redacts each finding in place.
>   Mandatory backup before write. JSONL-safe so chat files keep parsing.
>   Refuses if the file changed since the scan. No telemetry, ever.
>
> Free tier. `pip install -U medusa-security`.
>
> The first scan most developers run finds credentials they had no idea were
> sitting there. Run it once on your own machine and see.
