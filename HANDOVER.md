# MEDUSA Development Handover

## Current Version: **v2025.2.0.18**

**Published:**
- PyPI: https://pypi.org/project/medusa-security/2025.2.0.18/
- GitHub: https://github.com/Pantheon-Security/medusa (tag: v2025.2.0.18)

**Stats:** ~8,500+ total downloads, ~1,500/day

---

## Feature Complete: Version Fingerprinting System ✅

**Purpose:** Protect user-upgraded tools from being uninstalled by MEDUSA.

**How it works:**
1. When MEDUSA installs a tool, it captures the version in `~/.medusa/installed_tools.json`
2. On uninstall, MEDUSA compares manifest version vs current version
3. If version changed (user upgraded), tool is SKIPPED (protected)
4. `--force` flag overrides this protection

**Key function:** `_detect_tool_version()` in `medusa/cli.py:59-158`

**Strategies:**
1. Query package manager directly (npm list -g / pip show) - most reliable
2. Fall back to running tool with --version flag

### Test Results:

| Platform | Install | Version Capture | Protection | Force Override |
|----------|---------|-----------------|------------|----------------|
| Windows  | ✅ | ✅ | ✅ | ✅ |
| Ubuntu   | ✅ | ✅ | ✅ | ✅ |

**Example Output (Version Protection):**
```
[DEBUG]   Skipped: eslint (version changed: 9.39.2 → 9.39.1)
...
Tool 'eslint' version changed (9.39.2 → 9.39.1)
Skipping to protect your manual upgrade. Use --force to override.
```

---

## Bug Fixes in This Session (v2025.2.0.11 - v2025.2.0.18)

| Version | Bug | Fix |
|---------|-----|-----|
| v2025.2.0.11 | `UnboundLocalError: choco_installer` | Initialize choco_installer early |
| v2025.2.0.13 | `NameError: Optional not defined` | Add `from typing import Optional` |
| v2025.2.0.14 | npm tools show `version: null` | Query `npm list -g` directly |
| v2025.2.0.15 | `NameError: ToolMapper not defined` | Add import inside function |
| v2025.2.0.16 | Single tool uninstall ignores version protection | Check skipped_tools before uninstall |
| v2025.2.0.17 | Version detection missing pm_hint during scan | Pass package_manager from manifest |
| v2025.2.0.18 | **CRITICAL:** IDE init overwrites user files | Check if file exists before writing |

### v2025.2.0.18 - Critical IDE File Overwrite Bug

**Severity:** CRITICAL - Data loss for users

**Problem:** `medusa init --ide` was silently overwriting existing user files:
- `CLAUDE.md`
- `GEMINI.md`
- `AGENTS.md`
- `.github/copilot-instructions.md`

**Impact:** Any user who ran `medusa init` with IDE integration lost their custom IDE configuration files.

**Fix:** Added existence check before writing:
```python
# OLD (destructive)
with open(claude_md_file, 'w') as f:
    f.write(claude_md)

# NEW (safe)
if not claude_md_file.exists():
    with open(claude_md_file, 'w') as f:
        f.write(claude_md)
```

**File:** `medusa/ide/claude_code.py` - lines 64-70, 441-447, 582-588, 741-747

---

## Key Files

| File | Purpose |
|------|---------|
| `medusa/cli.py` | Main CLI - install/uninstall commands, version detection |
| `medusa/platform/install_manifest.py` | Manifest tracking (`~/.medusa/installed_tools.json`) |
| `medusa/platform/installers/base.py` | ToolMapper, package name mappings |
| `medusa/platform/installers/cross_platform.py` | NpmInstaller, PipInstaller |
| `docs/TROUBLESHOOTING.md` | User docs (added PowerShell execution policy section) |

---

## Publishing Workflow

### Bump Version:
```bash
/bump-version 2025.2.0.X
# Or manually:
python3 scripts/bump_version.py --version 2025.2.0.X
```

### Build & Publish:
```bash
# Commit changes first
git add -u && git commit -m "fix: Description (vX.X.X.X)"

# Tag
git tag vX.X.X.X

# Push
git push && git push --tags

# Build
rm -rf dist/ && .venv/bin/python -m build

# Upload to PyPI
.venv/bin/twine upload dist/medusa_security-X.X.X.X*
```

### PyPI Credentials:
- Stored in `~/.pypirc` or use `TWINE_USERNAME` / `TWINE_PASSWORD` env vars
- Or token-based auth via `__token__` username

---

## Windows-Specific Notes

### PowerShell Execution Policy Issue
- Fresh Win11 has `Restricted` policy
- Blocks `npm.ps1` (but not `npm.cmd`)
- MEDUSA uses `npm.cmd` internally - works fine
- Users running npm manually need: `npm.cmd` or `Set-ExecutionPolicy RemoteSigned`
- **Documented in:** `docs/TROUBLESHOOTING.md`

### PATH Refresh Issue
- After `npm install -g`, Windows doesn't refresh PATH in current session
- Solution: Query `npm.cmd list -g` instead of running tool binary
- Same for pip: Use `pip show` instead of running tool

---

## Security Check Completed

**Wiz Shai-Hulud 2 Supply Chain Attack** - MEDUSA is NOT affected:
- No npm dependencies in project itself
- All linters we install (eslint, prettier, etc.) are official packages
- Attack targets plugin ecosystems (medusa-plugin-*, @posthog/*, etc.)
- Our linters are core tools from established maintainers

---

## Pending Items

1. **Website Audit** - Review and update website content to match current version
2. **PyPI Description Review** - Ensure package description is current
3. **GitHub README Review** - Check README reflects v2025.2.0.17 features
4. **Fresh VM Test** - Optional full install test on clean Windows/Linux

---

*Last updated: 2025-11-26*
*Session ended at: v2025.2.0.18*
*Tests passed: Windows ✅ Ubuntu ✅*
