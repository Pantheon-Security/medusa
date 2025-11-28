# MEDUSA Release Checklist

Complete checklist for publishing a new MEDUSA release. Follow these steps in order.

---

## Pre-Release Checklist

### 1. Code Quality
- [ ] All new features have been tested locally
- [ ] Run MEDUSA on itself: `medusa scan .`
- [ ] No CRITICAL or HIGH issues in scan results
- [ ] All imports work: `python -c "from medusa.scanners import registry; print(len(registry.scanners))"`

### 2. Documentation Updates
- [ ] Update `README.md` with new features/scanners
- [ ] Update `docs/SCANNERS.md` if new scanners added
- [ ] Update `docs/AI_SECURITY.md` if AI features changed
- [ ] Update statistics (scanner count, rule count, etc.)
- [ ] Check all links work

### 3. Version Consistency
- [ ] Decide version number (see [Versioning Guide](#versioning-guide))
- [ ] Note: Version bump happens during release process

---

## Release Process

### Step 1: Final Commit
Ensure all feature commits are pushed:
```bash
git status
git add .
git commit -m "feat: [description]"
git push origin main
```

### Step 2: Bump Version
Use the slash command or script:
```bash
# Via slash command (recommended)
/bump-version 2025.X.Y.Z

# Or directly
python3 scripts/bump_version.py --version 2025.X.Y.Z
```

This updates:
- `medusa/__init__.py`
- `pyproject.toml`
- `.claude/claude.md`

### Step 3: Commit Version Bump
```bash
git add -u
git commit -m "chore: Version bump X.Y.Z.W → A.B.C.D"
git push origin main
```

### Step 4: Create Git Tag
```bash
git tag v2025.X.Y.Z
git push --tags
```

### Step 5: Create GitHub Release
```bash
gh release create v2025.X.Y.Z \
  --title "🎯 v2025.X.Y.Z - [Release Name]" \
  --notes "[Release notes - see template below]"
```

### Step 6: Build & Publish to PyPI
```bash
# Build
python -m build

# Upload to PyPI
.venv/bin/twine upload dist/*

# Or test first on Test PyPI
.venv/bin/twine upload --repository testpypi dist/*
```

### Step 7: Verify Release
- [ ] Check PyPI page: https://pypi.org/project/medusa-security/
- [ ] Check GitHub releases: https://github.com/Pantheon-Security/medusa/releases
- [ ] Test install: `pip install --upgrade medusa-security`
- [ ] Verify version: `medusa --version`

---

## Release Notes Template

```markdown
# 🎯 v2025.X.Y.Z - [Descriptive Release Name]

**MEDUSA v2025.X.Y.Z** - [One-line summary]

## 🆕 What's New

### [Feature Category 1]
- Feature description
- Another feature

### [Feature Category 2]
| Item | Details |
|------|---------|
| New Scanner | Description |
| New Rules | Count |

## 📊 By The Numbers

| Metric | Previous | Current | Change |
|--------|----------|---------|--------|
| Total Scanners | X | Y | +Z |
| AI Rules | X | Y | +Z% |
| Languages | X | Y | +Z |

## 🐛 Bug Fixes
- Fix description (#issue)

## 📚 Documentation
- New/updated docs

## 🚀 Quick Start

\`\`\`bash
pip install --upgrade medusa-security
medusa scan .
\`\`\`

---

**Full Changelog**: https://github.com/Pantheon-Security/medusa/compare/vOLD...vNEW

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

---

## Versioning Guide

MEDUSA uses **CalVer + SemVer hybrid**: `YYYY.MAJOR.MINOR.PATCH`

| Component | When to Increment | Example |
|-----------|-------------------|---------|
| **YYYY** | New calendar year | 2025 → 2026 |
| **MAJOR** | Major feature release, breaking changes | 2025.7 → 2025.8 |
| **MINOR** | New features, scanners, enhancements | 2025.8.0 → 2025.8.1 |
| **PATCH** | Bug fixes, docs, minor improvements | 2025.8.0.0 → 2025.8.0.1 |

### Version Examples

| Change Type | Version Change |
|-------------|----------------|
| New scanner category (AI Security) | 2025.7 → 2025.8 |
| Added 3 new scanners | 2025.8.0 → 2025.8.1 |
| Bug fix in scanner | 2025.8.1.0 → 2025.8.1.1 |
| Documentation only | 2025.8.1.1 → 2025.8.1.2 |

---

## Post-Release Checklist

### Announcements
- [ ] Update Discord/community (if applicable)
- [ ] Tweet/social media (if applicable)
- [ ] Update website (if applicable)

### Monitoring
- [ ] Check PyPI download stats
- [ ] Monitor GitHub issues for bug reports
- [ ] Check GitHub Actions CI status

### Cleanup
- [ ] Close related GitHub issues
- [ ] Update project board/milestones
- [ ] Archive old release branches (if any)

---

## Quick Commands Reference

```bash
# Check current version
grep "version" pyproject.toml | head -1

# View recent commits
git log --oneline -10

# View releases
gh release list --limit 5

# View specific release
gh release view v2025.X.Y.Z

# Delete a release (if needed)
gh release delete v2025.X.Y.Z

# Delete a tag (if needed)
git tag -d v2025.X.Y.Z
git push origin --delete v2025.X.Y.Z
```

---

## Troubleshooting

### PyPI Upload Fails
```bash
# Check twine is installed
pip install twine

# Check credentials
cat ~/.pypirc

# Use token auth
twine upload dist/* -u __token__ -p pypi-YOUR-TOKEN
```

### Version Mismatch
```bash
# Verify all files have same version
grep -r "2025\." pyproject.toml medusa/__init__.py
```

### Tag Already Exists
```bash
# Delete local and remote tag
git tag -d v2025.X.Y.Z
git push origin --delete v2025.X.Y.Z

# Recreate
git tag v2025.X.Y.Z
git push --tags
```

---

## Release Cadence

| Release Type | Frequency | Examples |
|--------------|-----------|----------|
| **Major** (2025.X) | Monthly or major features | AI Security, MCP Scanning |
| **Minor** (2025.X.Y) | Weekly or multiple features | New scanners, enhancements |
| **Patch** (2025.X.Y.Z) | As needed | Bug fixes, docs |

---

*Last Updated: 2025-11-28*
