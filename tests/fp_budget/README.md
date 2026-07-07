# Clean-repo FP budget (PR-016)

Reproducible precision measurement: full `medusa scan` (default mode) over popular
known-clean OSS repos, counting post-filter findings per repo.

```bash
python3 scripts/fp_budget/measure_clean_repo_budget.py
```

## Measured 2026-07-07 (2026.8.0, post dual-use hardening)

10 clean repos (black/jinja/flask/typer/starlette/rich/requests/click/alembic/chalk):

- **CRITICAL FPs: near-zero** — 6/10 repos have 0 CRITICAL; median 0, max 3.
  (Down from the pre-hardening harvest-rule nightmare + dual-use over-flagging.)
- **vet verdict: SAFE** on every clean repo (the flagship gate is precise).
- Full-scan MED+ median 11.5 — roughly half is external-linter output (bandit/semgrep,
  not MEDUSA rules); the rest is honest MEDIUM-level dual-use detection. The scary tier
  (CRITICAL) is what matters for trust, and it's effectively clean.

The remaining MEDIUM volume is a tracked, diminishing-returns tuning target; the
harvest-FP nightmare and the CRITICAL-on-clean-code problem are solved.
