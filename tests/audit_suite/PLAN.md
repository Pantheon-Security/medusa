# MEDUSA Corpus Audit Suite — Build Plan

**Status:** spec for handoff · **Owner:** hand to a fresh chat to complete
**Target dir:** `tests/audit_suite/` in the `medusa` repo
**Depends on corpus:** `/home/ross/Documents/medusa/medusa-test-targets/` (~270 git repos, `benchmark_repos.csv` labels)

---

## 1. Why this exists (the problem)

MEDUSA is a security scanner. Its whole value is that its verdicts are **trustworthy** — it must *catch real attacks* (detection) and *not cry wolf on benign code* (precision). The only honest way to know either number is to run it against a large, **labelled** corpus of real repos: deliberately-vulnerable targets that MUST be flagged, and legit tools/research that MUST NOT be hard-blocked.

We have that corpus (`medusa-test-targets`, ~270 repos, ground-truth labels in `benchmark_repos.csv`). What we **don't** have is a robust way to run it. To date it's been ad-hoc gate scripts on a dev laptop that **sleeps and locks up mid-run** — so full runs never finish, results aren't reproducible, and "measurement" has effectively been guesswork. For a *precision product*, that's the thing that makes it suck: we ship verdicts we can't defend with numbers.

**This suite is the fix:** a containerised, resumable, labelled audit harness that produces the same detection + false-positive numbers every time, on any machine, and survives a crash.

**It has two components, both running in the same Docker sandbox:**
- **Component A — Rule audit.** Detection + false-positive accuracy of the *scanner rules* (`medusa vet` / `medusa scan` verdicts on the labelled corpus). This is the drafted `audit.py` / `report.py`.
- **Component B — Hook / integration audit.** Does the *git hook and install-time integration* actually enforce the verdict at the right moment — the PreToolUse hook intercepting `git clone` / URL-based `pip|npm|uv|curl` installs, the pre-commit secrets block, and the MCP gatekeeper (`scan_repo`/`scan_skill`/`secrets_scan`)? Same corpus, but this is *integration* testing, not rule-accuracy.

> **Security is the reason this is Docker, not a venv.** We scan and — for Component B — *drive install/clone commands against deliberately-malicious repos on purpose*. That must never touch the host. Every run is in a container: corpus mounted **read-only**, **non-root** user, **`--network none`** by default (a bad repo/package can't phone home), ephemeral (`--rm`), no host bind beyond the RO corpus + a results volume. Component B especially: if a hook is meant to block `pip install <malicious-url>` and we test that it does, the command is issued **inside the sandbox** so a failure-to-block can't run a malicious `setup.py` on the laptop.

---

## 2. Goals / Non-goals

**Goals**
- One command produces: **detection rate** (vuln repos not-SAFE), **hard-block rate** (clean repos DO_NOT_INSTALL) + soft (CAUTION), and the **per-rule false-block ranking split HARVESTED vs CURATED**.
- **Reproducible** — Ross's run elsewhere and a chat's run here give identical numbers (pinned env).
- **Resumable** — survives a laptop lockup: one checkpoint per repo, `--resume` skips done repos, a crash costs ≤1 repo.
- **Safe** — deliberately-malicious repos are scanned in a sandbox that can't touch the host or phone home.
- **Portable** — runs on the dev laptop, another machine, or CI, unchanged.

**Non-goals**
- This suite **measures**; it does **not** fix rules. The FP fixes (ATKSIG context-gating, PL102, gitleaks-on-test-tokens, etc.) are separate downstream work driven by *this suite's* ranking.
- Not a replacement for the pinned native `tests/test_regression.py` (353) — that stays the fast per-commit detection guard; this is the periodic broad-corpus audit.

---

## 3. The corpus + labels

- Path: `medusa-test-targets/` — category subdirs (`mcp-security/`, `llm-agents/`, `prompt-injection/`, `adversarial-ml/`, `ctf-labs/`, `benchmarks/`, `llm-firewall/`, `agent-security/`, `harvested/`, …).
- Ground truth: `benchmark_repos.csv` (`repo, github_url, category, stars, status, expected_vulnerabilities, sast_detectable, runtime_only`).
- **Label rule (implemented in `audit.py:label_of`)**: a repo is **clean** (must-not-hard-block) if its category is `Reference` / `LLM Firewall` / `Agent Security`, or `expected_vulnerabilities` says "NOT a vuln repo" / "tool framework"; otherwise **vuln** (must-detect). This is the judgment call most worth a second opinion in review — see §8.
- Prior baseline to protect (`memory/project_fp_campaign_2026.md`): **132/152 documented-vuln repos detect**; detection must not regress below this.

---

## 4. Requirements

### Functional
1. Discover every git repo under the corpus (depth ≤ 3), map to its catalog label.
2. Per repo: `medusa vet <repo> --json` → verdict/score/blocking; for clean repos (and optionally all), `medusa scan <repo> --format json --screening --no-cache` → per-rule findings.
3. Classify: vuln→SAFE = **missed**; clean→DO_NOT_INSTALL = **hard false-block**; clean→CAUTION = soft.
4. Aggregate: detection %, hard/soft block %, per-rule ranking tagged **harvested vs curated** (via `medusa.rules.is_screening_only`), dedup-inflation + tmp/build-dir counts.
5. Emit a human table **and** a machine `report.json`.

### Non-functional (the robustness that's the whole point)
6. **Resumable checkpointing** — write `results/<repo>.json` the instant each repo finishes; on restart skip repos with an existing checkpoint; `--redo` forces fresh. (Implemented in `audit.py`.)
7. **Cache-correct** — always `--no-cache` (the result cache is content-keyed, NOT scanner-version-keyed → stale after any rule change); clear `~/.medusa/cache` before a run.
8. **Fresh-scan method** (HANDOVER caveat): one JSON per repo to a clean temp dir, parse `len(findings)` — never diff accumulated report dirs or the old runner's CSV `total`.
9. **Bounded** — per-repo `--timeout` (default ~420s); a timeout is recorded as `TIMEOUT`, never stalls the run. Giant general-infra repos (n8n/milvus/chroma) must not block the security-relevant repos — support `--only` and category include/exclude.
10. **Fast enough** — `--vuln-vet-only` (detection needs only the vet verdict) to make a full pass feasible; optional bounded parallelism (careful: heavy load can *trigger* the laptop lockup — default conservative).

### Security (we scan deliberately-malicious repos on purpose)
11. **Docker sandbox** — corpus mounted **read-only**, container runs **non-root**, `--network none` by default (a bad repo can't phone home; add a `--osv` opt-in that allows only OSV egress when CVE lookups are wanted), no host bind beyond the RO corpus + the results dir.
12. MEDUSA does static analysis (it reads files; it does not execute the target), but the container is the belt-and-suspenders so an install hook / setup script in a malicious repo can never reach the host.

---

## 4B. Component B — hook / integration audit (the git hook)

Component A proves the *verdict is correct*. Component B proves the *hook enforces it at the moment of install/commit*. All of this runs **inside the Docker sandbox** (see the security box in §1) because it drives real clone/install commands against malicious repos.

**Tests (each: feed a known-malicious corpus repo → assert BLOCK; feed a clean repo → assert ALLOW):**
- **B1 — PreToolUse: `git clone`.** Simulate the Claude Code PreToolUse hook receiving a `git clone <repo>` for a corpus repo; assert it returns DO_NOT_INSTALL / non-zero (blocks) for a malicious repo and SAFE (allows) for a clean one, **before** any clone executes.
- **B2 — PreToolUse: URL installs.** Same for URL-based `pip` / `npm` / `uv` / `poetry` / `cargo` / `go` / `curl|sh` installs that reference a git/URL source (bare-name `pip install requests` is out of scope — documented as no-URL-to-vet).
- **B3 — pre-commit secrets block.** Stage a file containing a planted credential; assert the `medusa hooks install --pre-commit` hook blocks the commit; assert a clean file commits fine.
- **B4 — MCP gatekeeper.** Start `medusa mcp`; call `scan_repo` / `scan_skill` / `secrets_scan` on corpus repos over the MCP protocol; assert the verdict returned to the "agent" matches the CLI vet verdict and that out-of-tree paths are refused.
- **B5 — hooks install/status wiring.** `medusa hooks install --all` in a throwaway project → `hooks status` shows every integration present (Claude PreToolUse/SessionStart/vet-skill/MCP, Cursor, Codex, git pre-commit).

**How B differs from A operationally:** B is small and fast (a handful of asserted flows, not a 270-repo sweep), so it can run every time; A is the periodic broad sweep. B's harness reuses A's corpus + labels to pick its malicious/clean inputs. B does **not** need `--no-cache`/screening tuning — it asserts hook *behaviour*, not rule counts.

**Security for B (non-negotiable):** every clone/install B issues runs in the `--network none`, non-root, `--rm` container; a hook that *fails* to block therefore executes the malicious command **inside a throwaway sandbox with no host mount but the RO corpus and no network** — it cannot reach the laptop or the internet. Never run Component B outside the container.

## 5. Architecture

```
tests/audit_suite/
  PLAN.md            # this file
  audit.py           # DRAFTED — resumable per-repo harness (checkpoints to results/)
  report.py          # DRAFTED — aggregates results/*.json into the tables
  Dockerfile         # TODO — pinned python + MEDUSA + harness, non-root
  docker-compose.yml # TODO — RO corpus mount, network none, results volume
  run.sh             # TODO — build + run + report wrapper, one command
  README.md          # TODO — usage, the label rule, the security model
  results/           # runtime checkpoints (gitignored)
```

Data flow: `run.sh` → (docker build) → container runs `audit.py --corpus /corpus --labels /corpus/benchmark_repos.csv --out /results` → per-repo checkpoints → `report.py /results` → tables + `report.json`.

---

## 6. Current state (already drafted — start here, don't rewrite)

- **`audit.py`** — discovery, catalog labelling, per-repo vet + screening-scan, **resumable checkpointing** (one file per repo, skip-done resume), timeout handling, `--only` / `--vuln-vet-only` / `--redo`. This is the crash-survival core and is done.
- **`report.py`** — reads checkpoints (works on a partial run), computes detection/hard/soft rates, per-rule **harvested vs curated** split, dedup/tmp counts, human table + `report.json`.

Both run bare today (`python3 audit.py --corpus … --labels …`). They have **not** been containerised, wrapped, or run end-to-end on the full corpus.

---

## 7. Remaining work (hand-off task list)

1. **Dockerfile** — pinned `python:3.12-slim`, install MEDUSA (editable from the mounted source OR a pinned wheel — decide), copy the harness, create a non-root user, entrypoint = `audit.py`. Verify `--network none` still lets a scan complete (OSV off).
2. **docker-compose.yml / run.sh** — one command: build, mount corpus RO + results RW, run audit then report. Flags pass through (`--only`, `--redo`, `--osv`).
3. **Validate end-to-end small** — `--only` on ~6 repos (rampart, guardrails, damn-vulnerable-MCP-server, ai-goat, garak, notebooklm) → confirm checkpoints written, resume works (kill mid-run, re-run, it continues), report tables render.
4. **First real audit** — run the clean-tool set + vuln set; confirm **detection ≥ 132/152** and record the hard-block rate + per-rule ranking as the baseline.
5. **Component B — `hook_audit.py`** — implement B1–B5 (§4B), all inside the container; assert block-on-malicious / allow-on-clean using corpus repos as inputs.
6. **README** — usage, the §3 label rule, the security model, how to add repos to the catalog.
6. **gitignore** `tests/audit_suite/results/`.
7. **Optional CI** — a `--only` smoke subset in CI so the suite itself can't rot.

---

## 8. Acceptance criteria

- `run.sh` on a fresh checkout reproduces the same detection + hard-block numbers (±0) across two runs and two machines.
- Kill the container mid-run → re-run → it resumes and finishes; final numbers identical to an uninterrupted run.
- Malicious repos are provably sandboxed: corpus mount is RO, container is non-root, default run has no network.
- `report.py` prints detection %, hard/soft block %, and the harvested-vs-curated per-rule ranking, and writes `report.json`.
- Detection on the labelled vuln set is **≥ the 132/152 baseline** (no regression); if lower, the suite flags which repos newly miss.

## 9. Open questions for review (the judgment calls)
- **The clean/vuln label rule (§3)** — is "category ∈ {Reference, LLM Firewall, Agent Security} or 'not a vuln repo' ⇒ clean" the right cut? Attack-*research* tools (garak, promptfoo, TextAttack) are labelled vuln today but are legit installs — should there be a third "attack-tooling" class whose *expected* verdict is CAUTION, not SAFE and not DO_NOT_INSTALL?
- **What "pass" means for a clean security tool** — is DO_NOT_INSTALL the only failure, with CAUTION acceptable (advisory), or must legit tools reach SAFE?
- **MEDUSA install in-container** — editable from mounted source (tracks the working tree, best for tuning) vs pinned wheel (best for reproducibility). Probably: editable for the tuning loop, wheel for release-gate audits.
