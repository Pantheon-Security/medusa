# MEDUSA corpus-validation gate

The pre-launch trust gate for the flagship `medusa vet` verdict. Measures, against
a REAL corpus of repos, the numbers that decide whether the verdict is trustworthy.

## Run

```bash
python3 tests/corpus_gate/corpus_gate.py \
  --good  ~/Documents ~/dev ~/projects \   # roots holding your KNOWN-GOOD projects
  --vuln  ~/test-repos/vulnerable \        # roots holding KNOWN-VULNERABLE test repos
  --medusa "$(command -v medusa)" \
  --out    ~/medusa_corpus_report.json
```

- Auto-discovers git repos under each root (`--good-repos` / `--vuln-repos` for explicit lists).
- **GATE PASS** (exit 0) requires: 0% false-block on known-good, 100% detection on
  known-vuln, 0 dedup inflation, 0 findings in tmp/build dirs, 0 empty-dir-as-SAFE.

## What it reports
- **False-block rate** — known-good repos that returned CAUTION/DO_NOT_INSTALL (each is an FP).
- **Detection rate** — known-vuln repos correctly not-SAFE.
- **Per-rule FP ranking** — which rules drive the false blocks (targeted fixes).
- **Dedup / tmp / empty-dir** regressions from the 2026-07-08 Mac shakedown.
