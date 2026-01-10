# MEDUSA Release Checklist

Comprehensive checklist for releasing new MEDUSA versions. Follow in order.

---

## CRITICAL: User Approval Required

**Claude MUST ask for user permission before:**
- Making any git commits
- Pushing to remote
- Uploading to PyPI
- Creating GitHub releases
- Version bumps

Show the user what will be done and wait for explicit "yes" or "go ahead" before proceeding.

---

## Pre-Release Verification

- [ ] All tests passing
- [ ] No uncommitted 2026 WIP files staged
- [ ] On correct branch (main or release branch)

---

## 1. Version Bump

### pyproject.toml
- [ ] `version = "X.X.X.X"` - Update version number
- [ ] `description` - Update if features changed
- [ ] `keywords` - Add new keywords if relevant

### Verify tool configs NOT corrupted
- [ ] `[tool.ruff] target-version` = `"py310"` (NOT package version)
- [ ] `[tool.mypy] python_version` = `"3.10"` (NOT package version)

---

## 2. Documentation Updates

### README.md - Scanner Counts (grep for old numbers!)
- [ ] Line ~12: Header tagline (e.g., "73 specialized analyzers")
- [ ] Line ~21: "across **X different languages**"
- [ ] Line ~25: "**X Specialized Scanners**" in Key Features
- [ ] Line ~27: "**X+ rules**" for AI Agent Security
- [ ] Line ~962: Roadmap "Completed" section scanner count
- [ ] Line ~963: Roadmap AI rules count

### README.md - Version References
- [ ] "What's New" section - update version number
- [ ] Any version-specific feature callouts

### CHANGELOG.md
- [ ] Add new version entry under `[Unreleased]`
- [ ] Include date in format `YYYY-MM-DD`
- [ ] Categorize changes: Added, Changed, Fixed, Removed, Security

---

## 3. Build & Test

```bash
# Clean build
rm -rf dist/ build/ *.egg-info

# Build
.venv/bin/python -m build

# Verify wheel contents (no 2026 WIP files!)
unzip -l dist/*.whl | grep -E "(rules/|research/)" && echo "WARNING: WIP FILES IN WHEEL!"
```

---

## 4. PyPI Release

```bash
# Upload to PyPI
.venv/bin/twine upload dist/*

# Verify live (may take 1-2 min to propagate)
pip index versions medusa-security | head -2
```

---

## 5. Git Push

```bash
# Stage ONLY release files
git add pyproject.toml CHANGELOG.md README.md [other-changed-files]

# Verify no WIP files staged
git status

# Commit
git commit -m "release: vX.X.X.X - Brief description"

# Push
git push origin main
```

---

## 6. GitHub Release (DON'T FORGET!)

> **THIS IS OFTEN FORGOTTEN!** PyPI upload does NOT create a GitHub Release.
> Users see releases at: https://github.com/Pantheon-Security/medusa/releases/

```bash
# Create GitHub Release
gh release create vX.X.X.X \
  --title "vX.X.X.X - Release Title" \
  --notes "$(cat <<'EOF'
## What's Changed

### Added/Fixed/Changed
- Feature or fix description

## Installation
\`\`\`bash
pip install --upgrade medusa-security
\`\`\`
EOF
)"

# VERIFY it's marked as "Latest"
gh release list --limit 2
```

---

## 7. Post-Release Verification

- [ ] `pip index versions medusa-security` - Shows new version
- [ ] `gh release list --limit 1` - Shows new release as Latest
- [ ] https://github.com/Pantheon-Security/medusa/releases/ - New release visible

---

## Release Summary (Copy-Paste Order)

```bash
# 1. Build
rm -rf dist/ build/ *.egg-info && .venv/bin/python -m build

# 2. PyPI
.venv/bin/twine upload dist/*

# 3. Git
git add pyproject.toml CHANGELOG.md README.md
git status  # VERIFY no WIP files!
git commit -m "release: vX.X.X.X - Description"
git push origin main

# 4. GitHub Release (DON'T SKIP!)
gh release create vX.X.X.X --title "vX.X.X.X - Title" --generate-notes

# 5. Verify
pip index versions medusa-security | head -1
gh release list --limit 1
```

---

## Quick Checks

```bash
# Find stale scanner counts in README
grep -n "64\|70\|73" README.md

# Check all version locations
grep -n "version" pyproject.toml | head -3
gh release list --limit 1
pip index versions medusa-security | head -1
```

---

## Scanner Count History

| Version | Scanners | AI Rules |
|---------|----------|----------|
| 2025.9.0.9 | 73 | 180+ |
| 2025.9.0.0 | 70 | 180+ |
| 2025.8.x | 64 | 150+ |

Update this table when scanner count changes!

---

## Common Mistakes

| Mistake | How to Avoid |
|---------|--------------|
| **Forgetting GitHub Release** | Always run `gh release create` after PyPI upload |
| **Stale scanner counts** | `grep -n "64\|70\|73" README.md` before release |
| **Staging WIP files** | Always check `git status` before commit |
| **Corrupted tool configs** | Verify `tool.ruff` and `tool.mypy` have Python versions not package versions |
