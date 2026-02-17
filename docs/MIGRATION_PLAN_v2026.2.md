# MEDUSA v2026.2 Migration Plan

**Date:** 2026-01-29
**Status:** Planning
**Goal:** Simplify architecture, focus on AI rules, eliminate installer complexity

---

## Executive Summary

Shift MEDUSA from "install 47 linters" to "AI rules engine + detect available tools". This eliminates Windows installer nightmares while strengthening our core value proposition.

---

## Current State (v2026.1.x)

```
MEDUSA v2026.1.x
├── 74 Scanner wrappers
├── 47 external tools to install
├── Complex installer (winget/choco/npm/pip/brew/apt)
├── Windows PATH refresh issues
├── Admin rights required (Chocolatey)
├── Days of cross-platform testing
└── 2,600 AI rules (the actual value)
```

**Pain Points:**
- Windows installer takes days to test
- Chocolatey requires admin rights
- PATH not refreshing after installs
- 47 tools across 6 package managers
- Platform-specific failures (swiftlint, etc.)
- User confusion about what to install

---

## Future State (v2026.2.0)

```
MEDUSA v2026.2.0
├── AI Rules Engine (CORE)
│   ├── 3,200+ YAML rules (no install)
│   ├── CVE Miner auto-updates rules
│   ├── Web Security Scanner (built-in)
│   └── MCP Vulnerability Scanner (built-in)
│
├── Detected Tools (OPTIONAL)
│   ├── Auto-detect installed linters
│   ├── Use what's available
│   └── Skip what's missing (no error)
│
└── Minimal Install (OPTIONAL)
    ├── modelscan (pip)
    ├── garak (pip)
    └── semgrep (pip)
```

---

## Migration Phases

### Phase 1: Installer Simplification (Week 1)
**Goal:** Remove complex multi-package-manager installer

| Action | Details |
|--------|---------|
| Remove `medusa install --all` | No longer installs 47 tools |
| Keep `medusa install --check` | Shows detected vs missing tools |
| Add `medusa install --ai-tools` | Installs only: modelscan, garak, semgrep |
| Remove Chocolatey integration | Eliminates admin requirement |
| Remove winget integration | Simplifies Windows |
| Keep pip/npm for AI tools only | Cross-platform, no admin |

**Files to modify:**
- `medusa/cli.py` - Simplify install command
- `medusa/platform/installers/` - Remove or deprecate most
- `medusa/scanners/base.py` - Graceful skip if tool missing

### Phase 2: Detect-Only Mode (Week 1)
**Goal:** Scanners detect and use available tools without requiring install

```python
# Before (v2026.1)
def scan(path):
    if not tool_installed:
        raise Error("Install shellcheck first")

# After (v2026.2)
def scan(path):
    if not tool_installed:
        logger.debug("shellcheck not found, skipping shell analysis")
        return []  # Graceful skip
```

**Behavior change:**
| Scenario | Before | After |
|----------|--------|-------|
| Tool missing | Error/warning | Silent skip |
| Tool found | Use it | Use it |
| `--check` flag | "Missing: X" | "Available: Y, Optional: Z" |

### Phase 3: AI Rules as Primary (Week 2)
**Goal:** YAML rules become the primary scanning mechanism

```
Scan Priority:
1. AI Rules (YAML) - Always runs, no dependencies
2. Built-in Scanners - Web security, MCP, patterns
3. External Tools - Only if detected
```

**Files to modify:**
- `medusa/core/scanner.py` - Prioritize YAML rules
- `medusa/rules/` - Ensure comprehensive coverage
- Remove dependency on external tools for core functionality

### Phase 4: CVE Miner Integration (Week 2)
**Goal:** Auto-update rules from CVE Miner

```
CVE Miner → YAML Rules → MEDUSA
         ↓
    Daily sync from EUVD/OSV
         ↓
    Auto-generate detection rules
         ↓
    MEDUSA rules grow automatically
```

**New commands:**
```bash
# Sync latest CVE rules
medusa rules update

# Show rule statistics
medusa rules stats

# Show CVE coverage
medusa rules cves
```

---

## What Gets Removed

### Installer Components (DELETE)
```
medusa/platform/installers/
├── windows.py          → SIMPLIFY (pip only)
├── linux.py            → SIMPLIFY (pip only)
├── macos.py            → SIMPLIFY (pip only)
├── cross_platform.py   → KEEP (npm for 2-3 tools)
└── windows_scripts/    → DELETE
    ├── install-checkmake.ps1
    └── ...
```

### Package Manager Integrations (REMOVE)
- Chocolatey (`choco`)
- Winget
- Homebrew (keep for optional use)
- APT/YUM/DNF/Pacman

### Tools No Longer Auto-Installed (47 → 3)

**REMOVE from auto-install:**
```
shellcheck, hadolint, docker-compose, markdownlint-cli,
eslint, tflint, golangci-lint, rubocop, phpstan,
cargo-clippy, sqlfluff, stylelint, htmlhint, ktlint,
cppcheck, checkstyle, typescript, scalastyle, perlcritic,
Rscript, ansible-lint, kube-linter, taplo, xmllint,
buf, graphql-schema-linter, solhint, luacheck, mix,
hlint, clj-kondo, dart, codenarc, vim-vint, cmakelang,
checkmake, gixy, zig, trivy, gitleaks
```

**KEEP for `medusa install --ai-tools`:**
```
modelscan   - ML model security (pip)
garak       - LLM vulnerability scanner (pip)
semgrep     - Pattern matching (pip)
```

---

## What Stays

### Core Components (KEEP)
```
medusa/
├── rules/              # 3,200+ YAML rules (THE PRODUCT)
├── core/
│   ├── scanner.py      # Main scanning engine
│   ├── pattern_analyzer.py
│   ├── fp_filter.py
│   └── reporter.py
├── scanners/
│   ├── base.py         # Graceful tool detection
│   ├── yaml_scanner.py # YAML rules engine
│   ├── mcp_server_scanner.py
│   └── web_security_scanner.py
└── cli.py              # Simplified commands
```

### Scanner Wrappers (KEEP but make optional)
Keep all 74 scanner wrappers but make them:
- Detect tool automatically
- Skip gracefully if missing
- No install prompts

---

## User Communication

### Changelog Entry
```markdown
## v2026.2.0 - AI-First Release

### Breaking Changes
- `medusa install --all` no longer installs 47 external tools
- External linters are now optional (detected if present)

### New Features
- `medusa install --ai-tools` installs core AI security tools
- `medusa rules update` syncs latest CVE-based rules
- Faster startup (no tool validation)
- Works without admin rights on Windows

### Why This Change?
MEDUSA's value is the 3,200+ AI security rules, not wrapping
47 linters. This release focuses on what makes MEDUSA unique:
AI/ML security scanning that works out of the box.

### Migration Guide
If you need specific linters:
- Install them yourself (apt/brew/choco/npm)
- MEDUSA auto-detects and uses them
- No configuration needed
```

### CLI Output Changes

**Before:**
```
Found 47 missing tools:
  • shellcheck
  • eslint
  • ...
Install all 47 missing tools? [Y/n]:
```

**After:**
```
MEDUSA v2026.2.0 - AI Security Scanner

Core: 3,247 AI rules loaded ✓
      Web security scanner ✓
      MCP vulnerability scanner ✓

Detected tools: bandit ✓, yamllint ✓, semgrep ✓
Optional tools: shellcheck, eslint, hadolint (install for deeper analysis)

Ready to scan.
```

---

## Backwards Compatibility

### Supported
- All existing YAML rules continue to work
- All scanner wrappers continue to work (if tool installed)
- CLI commands unchanged (scan, check, etc.)
- Config file format unchanged

### Not Supported
- `medusa install --all` behavior (now shows message)
- Automatic Chocolatey installation
- Automatic winget installation

### Deprecation Warnings
```python
# In cli.py
@click.option('--all', is_flag=True, hidden=True)
def install(all):
    if all:
        console.print("[yellow]⚠️  --all is deprecated in v2026.2[/yellow]")
        console.print("Use: medusa install --ai-tools")
        console.print("Or install linters manually and MEDUSA will detect them.")
```

---

## Testing Matrix (Simplified)

### Before (v2026.1)
| Platform | Package Managers | Tools | Test Time |
|----------|------------------|-------|-----------|
| Windows | winget, choco, npm, pip | 47 | 2-3 days |
| macOS | brew, npm, pip | 47 | 1 day |
| Linux | apt, npm, pip | 47 | 1 day |

### After (v2026.2)
| Platform | Package Managers | Tools | Test Time |
|----------|------------------|-------|-----------|
| Windows | pip | 3 | 1 hour |
| macOS | pip | 3 | 1 hour |
| Linux | pip | 3 | 1 hour |

**90% reduction in test time**

---

## Implementation Checklist

### Phase 1: Installer Simplification
- [ ] Add `--ai-tools` flag to install command
- [ ] Deprecate `--all` flag with warning
- [ ] Remove Chocolatey installer code
- [ ] Remove winget installer code
- [ ] Keep pip installer (cross-platform)
- [ ] Update `--check` to show "detected" vs "optional"

### Phase 2: Graceful Detection
- [ ] Update `BaseScanner.is_available()` - no error if missing
- [ ] Update `ScannerRegistry.get_missing_tools()` - rename to `get_optional_tools()`
- [ ] Remove install prompts from scan workflow
- [ ] Add debug logging for skipped scanners

### Phase 3: AI Rules Priority
- [ ] Ensure YAML rules run first
- [ ] Verify full coverage without external tools
- [ ] Update rule count in banner
- [ ] Add `medusa rules stats` command

### Phase 4: CVE Miner Integration
- [ ] Add `medusa rules update` command
- [ ] Connect to CVE Miner database
- [ ] Auto-generate rules from new CVEs
- [ ] Add `medusa rules cves` command

### Phase 5: Documentation
- [ ] Update README.md
- [ ] Update CHANGELOG.md
- [ ] Update installation docs
- [ ] Remove Windows installer troubleshooting

---

## Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | Phase 1-2 | Simplified installer, detect-only mode |
| 2 | Phase 3-4 | AI rules priority, CVE Miner integration |
| 3 | Phase 5 | Documentation, release v2026.2.0 |

---

## Success Metrics

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| Install test time | 3 days | 1 hour | ✓ |
| Admin rights needed | Yes | No | ✓ |
| External dependencies | 47 | 3 | ✓ |
| Windows issues | Many | Zero | ✓ |
| AI rule coverage | 2,600 | 3,500+ | ✓ |
| User install friction | High | Zero | ✓ |

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Users expect linter installs | Clear messaging, deprecation warnings |
| Reduced scan coverage | AI rules compensate, user can install tools |
| Breaking existing workflows | Keep all commands, just change behavior |

---

## Phase 5: CVE Research Program (NEW)

**Goal:** Discover and submit CVEs, build credibility

### CVE Discovery Sources

| Source | Method | Target |
|--------|--------|--------|
| RepoMiner | Scan top AI/ML repos with MEDUSA | 3 CVEs |
| Benchmark repos | Deep scan our 77 test targets | 3 CVEs |
| PaperMiner | Find papers with unpatched vulns | 2 CVEs |
| Manual research | Deep dive LangChain/PyTorch/etc | 2 CVEs |

### CVE Submission Workflow

```
1. DISCOVER
   └─ Miners find potential vulnerability

2. VALIDATE
   ├─ Reproduce the issue
   ├─ Confirm exploitability
   └─ Assess impact (CVSS score)

3. REPORT
   ├─ Contact maintainer (90-day disclosure)
   ├─ Provide PoC and remediation advice
   └─ Coordinate patch release

4. SUBMIT
   ├─ Request CVE ID (MITRE/GitHub/etc)
   ├─ Credit: "Discovered by Pantheon Security"
   └─ Publish advisory on our blog

5. INTEGRATE
   ├─ CVEMiner ingests the new CVE
   ├─ MEDUSA has detection rule from day 0
   └─ Marketing: update CVE count on website
```

### Credibility Targets

| Milestone | Target Date | Impact |
|-----------|-------------|--------|
| First CVE submitted | Q1 2026 | Proof of concept |
| 5 CVEs | Q2 2026 | "Security researchers" |
| 10 CVEs | Q3 2026 | Conference talk material |
| 25 CVEs | Q4 2026 | Industry recognition |

### Marketing Assets from CVEs

- NVD listing: "Discovered by Pantheon Security"
- Security advisories on blog (SEO + backlinks)
- "X CVEs discovered" badge on website
- Conference talks: "How we found CVE-XXXX"
- Media coverage for critical vulns

---

## Phase 6: Miner Ecosystem Automation

**Goal:** Fully automated rule generation pipeline

### Current State

| Miner | Location | Status |
|-------|----------|--------|
| CVEMiner | `/Documents/general/CVEMiner` | ✅ Working |
| PaperMiner | `/Documents/general/PaperMiner` | ✅ Working |
| RepoMiner | `/Documents/RepoMiner` | ✅ Built |
| NotebookLM MCP | Integrated | ✅ Working |

### Automation Pipeline

```python
# Daily automated pipeline (cron)
async def daily_medusa_update():
    # 1. CVEMiner: Fetch new CVEs
    new_cves = await cveminer.sync(['euvd', 'osv', 'nvd'])
    cve_rules = await cveminer.generate_rules(new_cves)

    # 2. RepoMiner: Check trending AI/ML repos
    trending = await repominer.trending(language='python', topic='machine-learning')

    # 3. PaperMiner: Find new research papers
    papers = await paperminer.search(keywords=AI_SECURITY_KEYWORDS)

    # 4. NotebookLM: Extract patterns from papers
    for paper in papers[:5]:  # Daily quota
        patterns = await notebooklm.extract(paper, EXTRACTION_PROMPT)
        paper_rules = await paperminer.to_rules(patterns)

    # 5. Validate and deploy
    all_rules = cve_rules + paper_rules
    validated = await medusa.validate(all_rules)
    await medusa.deploy(validated, target='ai_security/')

    # 6. Report
    await slack.notify(f"Deployed {len(validated)} new rules")
```

### Tiered Update Frequency

| Tier | CVEMiner | PaperMiner | RepoMiner |
|------|----------|------------|-----------|
| FREE | Weekly | Monthly | - |
| Professional | Daily | Weekly | Monthly |
| Enterprise | Real-time | Daily | Weekly |

---

## Updated Product Positioning

### Before (v2026.1)
> "MEDUSA - Multi-Language Security Scanner with 74 analyzers"

### After (v2026.2)
> "MEDUSA - AI Security Research Platform"
>
> - 3,200+ detection rules (and growing daily)
> - X CVEs discovered by our research team
> - Automated rule generation from CVEs, papers, and repos
> - The scanner that improves itself

---

## Conclusion

MEDUSA v2026.2 transforms from "scanner that wraps linters" to "AI security research platform":

1. **Rules ARE the product** - 3,200+ patterns, auto-growing
2. **ModelScan integration** - Only external tool we need
3. **Miner ecosystem** - CVE + Paper + Repo miners feed rules
4. **CVE research** - We discover, not just detect
5. **Credibility flywheel** - CVEs → Trust → Users → More discoveries

**We're not a scanner company. We're a security research company with a scanner.**
