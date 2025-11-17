# GitHub Setup Guide - MEDUSA

**Quick setup for testing with personal repo**

---

## Step 1: Initialize Git Repository

```bash
cd /home/ross-churchill/Documents/medusa

# Initialize git
git init

# Add all files
git add .

# Create initial commit
git commit -m "Initial commit - MEDUSA v0.7.0.0

- 42-language security scanner
- Docker support (8 distributions tested)
- GitHub Actions CI/CD workflows
- Complete documentation"
```

---

## Step 2: Create GitHub Repository

1. Go to: https://github.com/new
2. **Repository name**: `medusa`
3. **Description**: `MEDUSA - The 42-Headed Universal Security Scanner`
4. **Visibility**: ✅ **Private** (for now)
5. **DON'T initialize** with README, .gitignore, or license (we have them)
6. Click **Create repository**

---

## Step 3: Push to GitHub

```bash
# Add remote (replace with your actual repo URL)
git remote add origin https://github.com/ross-churchill/medusa.git

# Rename branch to main (if needed)
git branch -M main

# Push to GitHub
git push -u origin main
```

---

## Step 4: Verify GitHub Actions

1. Go to: https://github.com/ross-churchill/medusa/actions
2. You should see workflows running automatically
3. Check the test results:
   - ✅ Test Installation (Ubuntu 22.04, 24.04 × Python 3.10, 3.11, 3.12)
   - ✅ Test Docker Build
   - ✅ Test Multi-Distribution
   - ✅ Lint and Format Check

---

## What Gets Tested on Each Push:

### 1. Installation Testing (6 jobs)
- Ubuntu 22.04 + Python 3.10, 3.11, 3.12
- Ubuntu 24.04 + Python 3.10, 3.11, 3.12

Tests:
- `medusa --version`
- `medusa init`
- `medusa scan`
- `medusa install --check`

### 2. Docker Testing
- Builds Dockerfile.simple
- Tests scan in container
- Verifies version

### 3. Multi-Distribution Testing
- Runs `test-docker-install.sh`
- Tests Ubuntu 22.04, 24.04, Debian 12

### 4. Code Quality
- Black formatting check
- Ruff linting
- MyPy type checking

---

## GitHub Actions Workflow Files Created:

- `.github/workflows/test.yml` - Main CI/CD pipeline

---

## Future Enhancements (When Ready for Launch):

### 1. Create Organization
```bash
# When ready to go public:
# 1. Create org: medusa-security
# 2. Transfer repo: ross-churchill/medusa → medusa-security/medusa
# 3. GitHub handles redirects automatically
```

### 2. GitHub Pages
```bash
# Enable GitHub Pages for documentation
# Settings → Pages → Source: main branch /docs folder
```

### 3. Add Badges to README
```markdown
![Tests](https://github.com/medusa-security/medusa/workflows/MEDUSA%20CI%20Tests/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
```

### 4. Release Workflow
- Create GitHub releases
- Publish to PyPI
- Build and push Docker images to Docker Hub

---

## Quick Commands Reference

```bash
# Check status
git status

# Add changes
git add .

# Commit
git commit -m "Your message"

# Push
git push

# Pull latest
git pull

# View commit log
git log --oneline -10

# Create new branch
git checkout -b feature/new-feature

# View remotes
git remote -v
```

---

## Troubleshooting

### Issue: Permission denied (publickey)
**Solution**: Set up SSH keys or use HTTPS with personal access token

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub: Settings → SSH and GPG keys
```

### Issue: Large files rejected
**Solution**: Files > 100MB need Git LFS

```bash
git lfs install
git lfs track "*.whl"
git add .gitattributes
```

---

## Current Repository Status

- ✅ Git workflows created
- ✅ .gitignore configured
- ✅ Multi-distro testing (8/8 passing)
- ✅ Docker support complete
- ✅ Documentation comprehensive
- 🚀 Ready to initialize git and push!

---

## Next Steps

1. Run the commands in **Step 1** (initialize git)
2. Create private repo on GitHub (**Step 2**)
3. Push code (**Step 3**)
4. Watch CI/CD tests run (**Step 4**)
5. When ready: Go public + create organization

---

**Status**: Ready to push to GitHub!
**Expected CI/CD time**: ~5-10 minutes per workflow run
