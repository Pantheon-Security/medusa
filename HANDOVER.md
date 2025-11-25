# MEDUSA Development Handover

## Current Version: **v2025.2.0.15**

**Published:**
- PyPI: https://pypi.org/project/medusa-security/2025.2.0.15/
- GitHub: https://github.com/Pantheon-Security/medusa (tag: v2025.2.0.15)

**Stats:** ~8,500+ total downloads, ~1,500/day

---

## Recent Changes (v2025.2.0.12 - v2025.2.0.15)

### Feature: Version Fingerprinting System

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

### Bug Fixes in This Session:

| Version | Bug | Fix |
|---------|-----|-----|
| v2025.2.0.11 | `UnboundLocalError: choco_installer` | Initialize choco_installer early |
| v2025.2.0.13 | `NameError: Optional not defined` | Add `from typing import Optional` |
| v2025.2.0.14 | npm tools show `version: null` | Query `npm list -g` directly |
| v2025.2.0.15 | `NameError: ToolMapper not defined` | Add import inside function |

---

## Pending Test

**ESLint version capture test** - Need to verify fix works:

```powershell
# On Windows - uninstall first (eslint already installed)
npm.cmd uninstall -g eslint

# Reinstall with MEDUSA
medusa install eslint --debug

# Check manifest - should have real version
type $env:USERPROFILE\.medusa\installed_tools.json

# Expected:
# "eslint": {
#   "installed_by_medusa": true,
#   "package_manager": "npm",
#   "version": "9.15.0"  <-- Should NOT be null
# }
```

**Then test version protection:**
```powershell
# Manually edit manifest to change version (simulate user upgrade)
# Or: npm.cmd install -g eslint@latest

# Try uninstall - should SKIP eslint
medusa uninstall eslint --debug
# Expected: "Skipped: eslint (version changed: X.X.X → Y.Y.Y)"
```

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

### PATH Refresh Issue
- After `npm install -g`, Windows doesn't refresh PATH in current session
- Solution: Query `npm.cmd list -g` instead of running tool binary
- Same for pip: Use `pip show` instead of running tool

---

## Security Check Completed

**Wiz Shai-Hulud 2 Supply Chain Attack** - MEDUSA is NOT affected:
- No npm dependencies in project
- All linters we install (eslint, prettier, etc.) are official packages
- Attack targets plugin ecosystems (medusa-plugin-*, @posthog/*, etc.)

---

## Next Steps

1. Complete eslint version capture test on Windows
2. Test full `medusa install --all` with version capture
3. Test `medusa uninstall --all` with version protection
4. Consider fresh VM test for clean install experience

---

*Last updated: 2025-11-25*
*Session ended at: v2025.2.0.15*
