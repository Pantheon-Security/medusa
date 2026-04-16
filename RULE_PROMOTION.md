# MEDUSA Rule Promotion Process

> Repeatable workflow for promoting rules from `medusa-rules` into production, with smoke testing and benchmark validation against real vulnerable repos.

## Current State Snapshot (2026-04-12)

### Production (`medusa/medusa/rules/`)
| Metric | Value |
|--------|-------|
| Scanner YAML rules | 9,556 |
| Categories | 48 |
| CVE rules | 309 (production only — not in rules repo) |

### Rules Repo — Scanner YAML (`medusa-rules/scanners/`)
| Metric | Value |
|--------|-------|
| Scanner YAML files | 198 |
| Scanner YAML rules | 21,057 |
| Categories | 48 |

> Runtime JSON rules (`medusa-rules/runtime/`) are for the proxy — out of scope for this process.

### Delta: Rules Repo vs Production
**11,501 new scanner rules** waiting to be promoted across 43 categories.

**Largest gaps (>500 new rules):**

| Category | Repo | Prod | New |
|----------|------|------|-----|
| agent_security | 2,869 | 843 | +2,026 |
| dp_attacks | 2,093 | 100 | +1,993 |
| inference_infrastructure | 1,282 | 165 | +1,117 |
| prompt_injection_attacks | 1,352 | 288 | +1,064 |
| model_extraction | 1,219 | 223 | +996 |
| privacy_attacks | 1,095 | 129 | +966 |
| rag_vulnerabilities | 710 | 100 | +610 |

**New category not in prod:** `dependency_intent_validation` (59 rules)

**Prod-only (not in repo):** `cve/` (309 rules — sourced from CVEMiner, separate pipeline)

### Test Targets (`medusa-test-targets/`)
- **103 repos** with real vulnerabilities (MCP servers, LLM agents, prompt injection, data poisoning, CTFs)
- **86 baseline scan results** in `scan_results_v2026.2_full85/`
- **Benchmark CSV** with expected vulnerabilities per repo: `benchmark_repos.csv`
- Languages: Python (3,215 files), JS/TS (1,044), C (208), Go (26), Rust (23)

---

## Promotion Workflow

Run this process each session when adding new rules. Each step must pass before moving to the next.

### Step 0: Orient

```bash
# What's new in the rules repo since last promotion?
cd /home/ross/Documents/medusa/medusa-rules
git log --oneline -10

# Quick count comparison
python3 -c "
import yaml, os
def count(d):
    t = 0
    for r, _, fs in os.walk(d):
        for f in fs:
            if f.endswith(('.yaml','.yml')):
                try:
                    data = yaml.safe_load(open(os.path.join(r,f)))
                    if data and isinstance(data, dict) and 'rules' in data:
                        t += len(data['rules'])
                    elif data and isinstance(data, list):
                        t += len(data)
                except: pass
    return t
prod = count('../medusa/medusa/rules')
repo = count('scanners')
print(f'Production: {prod}  |  Repo: {repo}  |  Delta: {repo - prod}')
"
```

### Step 1: Select Category to Promote

Pick one category at a time. Prioritise by:
1. Categories with the largest delta (most new rules)
2. Categories covering active threat areas (MCP, agents, prompt injection)
3. Categories with matching test targets available

```bash
# Example: promote agent_security
CATEGORY="agent_security"

# List new files in repo not yet in production
diff <(ls medusa-rules/scanners/$CATEGORY/ | sort) \
     <(ls medusa/medusa/rules/$CATEGORY/ | sort) | grep "^<"
```

### Step 2: Validate Rule Quality

Before copying anything, validate the rules.

```bash
# Check for duplicate IDs across the new files + existing prod rules
cd /home/ross/Documents/medusa/medusa-rules
python3 scripts/check_duplicate_ids.py

# Validate YAML syntax and required fields
python3 -c "
import yaml, sys, os

CATEGORY = '$CATEGORY'
errors = []
for f in os.listdir(f'scanners/{CATEGORY}'):
    if not f.endswith(('.yaml', '.yml')): continue
    path = f'scanners/{CATEGORY}/{f}'
    try:
        data = yaml.safe_load(open(path))
        if not data or 'rules' not in data:
            errors.append(f'{f}: no rules key')
            continue
        for i, rule in enumerate(data['rules']):
            if 'id' not in rule: errors.append(f'{f}: rule {i} missing id')
            if 'patterns' not in rule and 'pattern' not in rule:
                errors.append(f'{f}: rule {rule.get(\"id\",i)} missing patterns')
            if 'severity' not in rule: errors.append(f'{f}: rule {rule.get(\"id\",i)} missing severity')
    except yaml.YAMLError as e:
        errors.append(f'{f}: YAML parse error: {e}')

if errors:
    print(f'FAIL: {len(errors)} issues')
    for e in errors[:20]: print(f'  {e}')
    sys.exit(1)
else:
    print('PASS: all rules valid')
"
```

**Required fields for scanner YAML rules:**
- `id` — unique identifier (e.g., `AGENT-SEC-001`)
- `name` — kebab-case name
- `severity` — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `patterns` — list of regex strings
- `message` — description of what was detected

**Watch for:**
- Duplicate IDs (across files AND with existing production rules)
- Empty pattern lists
- Regex that won't compile (`python3 -c "import re; re.compile('...')"`)
- Overly broad patterns that will FP on normal code (e.g., bare `import`, `open`, `print`)

### Step 3: Copy to Production

```bash
CATEGORY="agent_security"

# Copy new files only (don't overwrite existing)
for f in /home/ross/Documents/medusa/medusa-rules/scanners/$CATEGORY/*.yaml; do
    basename=$(basename "$f")
    dest="/home/ross/Documents/medusa/medusa/medusa/rules/$CATEGORY/$basename"
    if [ ! -f "$dest" ]; then
        cp "$f" "$dest"
        echo "ADDED: $basename"
    else
        echo "SKIP (exists): $basename"
    fi
done
```

### Step 4: Smoke Test — Does MEDUSA Still Load?

```bash
cd /home/ross/Documents/medusa/medusa

# Quick load test — rules parse without errors
medusa scan --help 2>&1 | head -5

# Scan a tiny target to verify no crashes
medusa scan /home/ross/Documents/medusa/medusa-test-targets/damn-vulnerable-MCP-server \
    --quick 2>&1 | tail -20
```

**Pass criteria:**
- No Python tracebacks
- No YAML parse errors
- Scan completes with findings count > 0

### Step 5: Benchmark Against Test Targets

Run against the full test target suite and compare to baseline.

```bash
cd /home/ross/Documents/medusa/medusa

# Full benchmark scan (takes ~5-10 min for all 103 repos)
RESULTS_DIR="/home/ross/Documents/medusa/medusa-test-targets/scan_results_$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

for target in /home/ross/Documents/medusa/medusa-test-targets/*/; do
    name=$(basename "$target")
    # Skip non-repo directories and files
    [ ! -d "$target/.git" ] && [ ! -f "$target/README.md" ] && continue
    echo "Scanning: $name"
    medusa scan "$target" --output json \
        -e node_modules/ -e .venv/ -e __pycache__/ \
        > "$RESULTS_DIR/$name.json" 2>"$RESULTS_DIR/$name.stderr" || true
done
```

### Step 6: Compare Results to Baseline

```bash
python3 -c "
import json, os, sys

BASELINE = '/home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85'
CURRENT  = '$RESULTS_DIR'  # set from Step 5

print(f'{'Repo':<40} {'Baseline':>10} {'Current':>10} {'Delta':>10}')
print('-' * 72)

total_base, total_curr = 0, 0
regressions = []

for f in sorted(os.listdir(BASELINE)):
    if not f.endswith('.json'): continue
    name = f.replace('.json', '')
    curr_path = os.path.join(CURRENT, f)

    try:
        base_data = json.load(open(os.path.join(BASELINE, f)))
        base_count = len(base_data.get('findings', base_data if isinstance(base_data, list) else []))
    except: base_count = 0

    try:
        curr_data = json.load(open(curr_path))
        curr_count = len(curr_data.get('findings', curr_data if isinstance(curr_data, list) else []))
    except: curr_count = 0

    delta = curr_count - base_count
    total_base += base_count
    total_curr += curr_count

    flag = ''
    if curr_count < base_count:
        flag = ' <-- REGRESSION'
        regressions.append(name)

    print(f'{name:<40} {base_count:>10} {curr_count:>10} {delta:>+10}{flag}')

print('-' * 72)
print(f'{'TOTAL':<40} {total_base:>10} {total_curr:>10} {total_curr - total_base:>+10}')

if regressions:
    print(f'\nREGRESSIONS ({len(regressions)} repos lost findings):')
    for r in regressions: print(f'  - {r}')
    sys.exit(1)
else:
    print('\nNo regressions detected.')
"
```

**Pass criteria:**
- Zero regressions (no repo should have FEWER findings than baseline)
- New findings should be in the promoted category
- No new findings in unrelated categories (would indicate broken regex matching everything)

### Step 7: Spot-Check New Findings

Manually review a sample of new findings to check for false positives.

```bash
# Extract new findings only (not in baseline) for one repo
python3 -c "
import json
REPO = 'damn-vulnerable-MCP-server'
base = json.load(open(f'/home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85/{REPO}.json'))
curr = json.load(open(f'$RESULTS_DIR/{REPO}.json'))

base_ids = {f.get('rule_id', f.get('id', '')) for f in base.get('findings', base if isinstance(base, list) else [])}
new = [f for f in curr.get('findings', curr if isinstance(curr, list) else []) if f.get('rule_id', f.get('id', '')) not in base_ids]

print(f'New findings: {len(new)}')
for f in new[:10]:
    print(f'  [{f.get(\"severity\",\"?\")}] {f.get(\"rule_id\",\"?\")} — {f.get(\"message\",\"\")[:80]}')
    print(f'    File: {f.get(\"file\",\"?\")}:{f.get(\"line\",\"?\")}')
"
```

**FP red flags:**
- Finding in a README, docs, or comment (detection in non-code context)
- Pattern matching on common variable names (`key`, `token`, `secret` in benign context)
- Same file flagged 10+ times by similar rules (pattern too broad)

### Step 8: Update Baseline

If all checks pass, update the baseline for next time.

```bash
# Archive old baseline
mv /home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85 \
   /home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85_pre_$(date +%Y%m%d)

# Promote current as new baseline
mv "$RESULTS_DIR" /home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85
```

### Step 9: Commit

```bash
cd /home/ross/Documents/medusa/medusa
git add medusa/rules/$CATEGORY/
git status  # Review what's staged
git diff --cached --stat  # Confirm scope
# Wait for user approval before committing
```

---

## Existing Tooling (in `medusa-rules/scripts/`)

| Script | Purpose |
|--------|---------|
| `check_duplicate_ids.py` | Find duplicate rule IDs across all files |
| `fix_invalid_regex.py` | Fix regex compilation errors |
| `fix_missing_categories.py` | Ensure all rules have category field |
| `fix_numeric_severity.py` | Convert CVSS numbers to severity strings |
| `fix_patternless_rules.py` | Handle rules missing patterns |
| `dedupe_rules.py` | Remove duplicate rules by content hash |

---

## Key Paths

| What | Path |
|------|------|
| Production rules | `/home/ross/Documents/medusa/medusa/medusa/rules/` |
| Rules repo (scanners) | `/home/ross/Documents/medusa/medusa-rules/scanners/` |
| Test targets | `/home/ross/Documents/medusa/medusa-test-targets/` |
| Baseline results | `/home/ross/Documents/medusa/medusa-test-targets/scan_results_v2026.2_full85/` |
| Benchmark CSV | `/home/ross/Documents/medusa/medusa-test-targets/benchmark_repos.csv` |
| Validation scripts | `/home/ross/Documents/medusa/medusa-rules/scripts/` |

---

## Quick Reference: Single-Category Promotion

```bash
# End-to-end for one category
CATEGORY="agent_security"

# 1. Validate
cd /home/ross/Documents/medusa/medusa-rules
python3 scripts/check_duplicate_ids.py

# 2. Copy new files
for f in scanners/$CATEGORY/*.yaml; do
    dest="../medusa/medusa/rules/$CATEGORY/$(basename $f)"
    [ ! -f "$dest" ] && cp "$f" "$dest" && echo "ADDED: $(basename $f)"
done

# 3. Smoke test
cd /home/ross/Documents/medusa/medusa
medusa scan /home/ross/Documents/medusa/medusa-test-targets/damn-vulnerable-MCP-server --quick

# 4. Benchmark (pick 3-5 relevant targets)
for repo in damn-vulnerable-MCP-server damn-vulnerable-llm-agent rogue-agents; do
    medusa scan /home/ross/Documents/medusa/medusa-test-targets/$repo --output json \
        > /tmp/medusa_test_$repo.json 2>&1
    echo "$repo: $(python3 -c "import json; print(len(json.load(open('/tmp/medusa_test_$repo.json')).get('findings',[])))" 2>/dev/null || echo 'parse error') findings"
done

# 5. Review and commit (show diff first, wait for approval)
```
