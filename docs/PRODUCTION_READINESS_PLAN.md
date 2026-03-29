# MEDUSA Production Readiness Plan

**Date**: 2026-03-13
**Goal**: Get MEDUSA fully production-ready for GitHub sync with 10,000+ scanner rules and an automated rule harvesting pipeline.

---

## Current State

| Asset | Status | Count |
|-------|--------|-------|
| Scanner rules (medusa-rules/scanners/) | Consolidated | 9,600+ unique |
| Runtime rules (medusa-rules/runtime/) | Exists, needs consolidation | ~3,760 JSON |
| Runtime rules (runtime-temp backup) | Backed up from production | ~2,410 YAML |
| CVE rules (medusa-rules/cve/) | Exists | 536 |
| Production repo rule count references | Updated to 7,000+ | Done |
| MinerHub harvesting pipeline | Online, collecting daily | ~2,500 files queued |
| Rule extraction scripts | Partially built | Needs automation |

---

## Phase 1: Clean Up & Commit (NOW)

### 1.1 Production Repo Cleanup
- [ ] Review uncommitted changes in `medusa/core/fp_filter.py`
- [ ] Review uncommitted changes in `medusa/core/reporter.py`
- [ ] Review uncommitted changes in `medusa/rules/__init__.py`
- [ ] Review scanner changes: `base.py`, `gitleaks_scanner.py`, `mcp_server_scanner.py`, `semgrep_scanner.py`, `trivy_scanner.py`
- [ ] Remove runtime rules mixed into production `rules/` directories (they're backed up in `runtime-temp/`)
- [ ] Clean up `rules/archive/` (all runtime YAMLs — already backed up)
- [ ] Ensure `.gitignore` excludes `*_runtime.yaml` and `rules/runtime/`

### 1.2 Sync Production Rules from medusa-rules
- [ ] Promote all 9,600+ scanner rules from `medusa-rules/scanners/` → `medusa/medusa/rules/`
- [ ] Run duplicate ID check: `python3 medusa-rules/scripts/check_duplicate_ids.py`
- [ ] Verify rule loading: `python3 -c "from medusa.rules import get_stats; print(get_stats())"`

### 1.3 Commit & Push
- [ ] Stage rule reorganisation (deletions + new category dirs)
- [ ] Stage core file changes
- [ ] Stage rule count updates (cli.py, reporter.py, README.md, etc.)
- [ ] Commit: `feat: Reorganise rules into 43 categories, 7,000+ scanner rules`
- [ ] Push to GitHub

---

## Phase 2: Rule Pipeline Automation (NEXT)

### 2.1 MinerHub → medusa-rules Pipeline
MinerHub (`minershub.theshellnet.com`) runs 24/7 collecting:
- **PaperMiner**: White papers from arXiv, security conferences
- **CVEMiner**: New CVEs with AI/ML relevance
- **ModelMiner**: Model vulnerability findings
- **RepoMiner**: Tracked repo security patterns

Current gap: ~2,500 files queued for rule extraction.

- [ ] Build `harvest.py` script that pulls from MinerHub queue via MCP
- [ ] Extract attack patterns from harvested research
- [ ] Generate YAML scanner rules (using yaml-rule-engineer skill)
- [ ] Auto-categorise into the 43 subject directories
- [ ] Run duplicate ID check before merge
- [ ] Validate rules (syntax, regex compilation, FP check)

### 2.2 Extraction Scripts
Existing scripts to integrate:
- `medusa-2026-dev/scripts/convert_and_merge_ucp.py`
- `medusa-2026-dev/scripts/coverage_check.py`
- `medusa-rules/scripts/check_duplicate_ids.py`

Need to build:
- [ ] `medusa-rules/scripts/extract_rules.py` — pull patterns from research markdown
- [ ] `medusa-rules/scripts/validate_rules.py` — syntax + regex + FP check
- [ ] `medusa-rules/scripts/promote.sh` — copy approved rules to production
- [ ] `medusa-rules/scripts/promote_all.sh` — batch promote all categories

### 2.3 Automated Pipeline (Target)
```
MinerHub (24/7 collection)
    ↓
medusa-rules/incoming/        ← raw research files land here
    ↓
extract_rules.py              ← pull attack patterns, generate YAML
    ↓
medusa-rules/staging/{subject}/ ← rules awaiting validation
    ↓
validate_rules.py             ← syntax, regex, duplicate ID, FP filter
    ↓
medusa-rules/scanners/{subject}/ ← approved rules (source of truth)
    ↓
promote.sh                    ← copy to production repo
    ↓
medusa/medusa/rules/{subject}/  ← production (GitHub)
```

---

## Phase 3: Scale Architecture (FUTURE)

As rules grow past 10,000+, the current architecture will need optimisation.

### 3.1 Current Bottlenecks
- All 7,000+ rules loaded and regex-compiled on startup (~20,000 `re.compile()` calls)
- O(rules × lines × patterns) scan loop — no file-type filtering
- Every `RuleBasedScanner` calls `load_all_rules()` even for a subset
- 193 YAML files parsed via `yaml.safe_load()` on first scan

### 3.2 Optimisation Options (evaluate when needed)
- **Lazy category loading**: Only load rule categories relevant to the file being scanned
- **Pre-compiled rule cache**: Pickle/marshal compiled patterns to skip YAML parse + re.compile on startup
- **File-extension filtering**: Tag rules with applicable file types, skip irrelevant rules
- **Multi-pattern matching**: Aho-Corasick or `re2` for batch pattern matching instead of individual regex
- **Category-based scanner auto-generation**: Auto-create scanners for new categories instead of manual mapping

### 3.3 Rule Count Projections
| Milestone | Scanner Rules | Timeline |
|-----------|--------------|----------|
| Current | 9,600+ | Now |
| +2,500 queued harvest | ~10,000 | Next 2-4 weeks |
| Automated pipeline running | ~15,000 | Q2 2026 |
| Full MinerHub integration | 20,000+ | Q3 2026 |

---

## Phase 4: Runtime Rules Consolidation (AFTER)

- [ ] Consolidate runtime YAML (from `runtime-temp/`) into `medusa-rules/runtime/`
- [ ] Deduplicate against existing JSON runtime rules
- [ ] Decide format: keep YAML or convert all to JSON for proxy
- [ ] Update runtime rule count in paid-tier docs

---

## Phase 5: Quality & Testing

### 5.1 False Positive Tuning
- [ ] Run scan against `medusa-test-targets/` with new rules
- [ ] Update `fp_filter.py` patterns for new categories
- [ ] Target: maintain 96%+ FP reduction rate

### 5.2 Benchmark Validation
- [ ] Run benchmark suite against 77+ test repos
- [ ] Compare TP/FP rates against baseline
- [ ] Document any regression

### 5.3 CI/CD
- [ ] GitHub Action validates rule syntax on PR
- [ ] Automated duplicate ID check on PR
- [ ] FP rate regression test in CI

---

## Key Locations

| What | Where |
|------|-------|
| Production repo | `/home/ross/Documents/medusa/medusa` |
| Rules source-of-truth | `/home/ross/Documents/medusa/medusa-rules/scanners/` |
| Runtime rules (JSON) | `/home/ross/Documents/medusa/medusa-rules/runtime/` |
| Runtime backup (YAML) | `/home/ross/Documents/medusa/medusa-rules/runtime-temp/` |
| Dev/staging rules | `/home/ross/Documents/medusa/medusa-2026-dev/rules/` |
| CVE rules | `/home/ross/Documents/medusa/medusa-rules/cve/` |
| Test targets | `/home/ross/Documents/medusa/medusa-test-targets/` |
| MinerHub | `https://minershub.theshellnet.com/mcp` |
| Pipeline scripts | `/home/ross/Documents/medusa/medusa-rules/scripts/` |
| Proxy (Zig) | `/home/ross/Documents/medusa/proxy/` |

---

## Slash Commands & Tools

| Command | Purpose |
|---------|---------|
| `/update-rule-counts` | Update rule count references across all project files |
| `/bump-version` | Bump version number across project |
| `/medusa-scan` | Run security scan |
| `/rule-validator` | Validate YAML rule syntax and schema |
| `/yaml-rule-engineer` | Generate rules from research |
| MinerHub MCP | Query harvest queue, stats, research topics |
