# Feature Request: On-Demand Scanner Installation

**Date**: 2025-11-15
**Priority**: HIGH
**Category**: UX Improvement
**Status**: PROPOSED

---

## 🎯 Problem Statement

Currently, MEDUSA prompts users to install **all 42 scanners** during `medusa init`, which:
- Takes a long time (installing 42 tools)
- Uses significant disk space
- Installs tools the user may never need
- Poor UX for users who only work with specific languages

**Example**:
- Python-only developer doesn't need Go, Rust, Swift scanners
- Frontend developer doesn't need Terraform, Ansible, Solidity scanners
- DevOps engineer may only need YAML, Docker, Shell scanners

---

## 💡 Proposed Solution

### Option A: Install Mode Selection (First Run)

When running `medusa init` for the first time, prompt user:

```
🔧 MEDUSA Initialization Wizard

Scanner Installation Mode:
  1) Install all scanners (42 tools) - Recommended for teams
  2) Install detected scanners only (3 tools found for your project)
  3) Install on-demand (install when first needed) - Recommended
  4) Manual (I'll install tools myself)

Choice [3]:
```

### Option B: Smart Auto-Detection

```
🔧 MEDUSA Initialization Wizard

Step 2/4: Scanner Installation...
✓ Detected project languages:
  • Python (15 files)
  • YAML (3 files)
  • Markdown (2 files)

Install scanners for detected languages? (bandit, yamllint, markdownlint) [Y/n]:
```

### Option C: Lazy Installation (On-Demand)

When scanner is needed but not installed:

```bash
$ medusa scan .

🐍 MEDUSA v0.7.0.0 - Security Scan

📁 Found Python files but bandit is not installed.

Install bandit now? [Y/n]: y
  ⏳ Installing bandit via pip...
  ✅ Installed bandit

Scanning...
```

---

## 🎨 Implementation Design

### 1. Configuration Option

Add to `.medusa.yml`:
```yaml
installation:
  mode: on-demand  # Options: all, detected, on-demand, manual
  auto_install: true
  confirm_before_install: true
```

### 2. CLI Flow Update

```python
# medusa/cli.py in init()

def init(ide, force, install):
    # ... existing code ...

    # New: Installation mode selection
    install_mode = click.prompt(
        'Scanner installation mode',
        type=click.Choice(['all', 'detected', 'on-demand', 'manual']),
        default='on-demand'
    )

    if install_mode == 'all':
        install_all_scanners()
    elif install_mode == 'detected':
        install_detected_scanners(project_languages)
    elif install_mode == 'on-demand':
        config['installation']['mode'] = 'on-demand'
        console.print("[yellow]Scanners will be installed when first needed[/yellow]")
    else:  # manual
        console.print("[dim]You can install tools later with 'medusa install'[/dim]")
```

### 3. On-Demand Installation

```python
# medusa/core/scanner.py

def scan_file(file_path, scanner):
    if not scanner.is_available():
        if config.get('installation', {}).get('auto_install'):
            if config.get('installation', {}).get('confirm_before_install'):
                if click.confirm(f"Install {scanner.tool_name}?"):
                    install_scanner(scanner.tool_name)
            else:
                install_scanner(scanner.tool_name)
        else:
            console.print(f"[yellow]Skipping {file_path}: {scanner.tool_name} not installed[/yellow]")
            return None

    return scanner.scan(file_path)
```

---

## 📊 User Personas & Use Cases

### Persona 1: Solo Python Developer
**Wants**: Only Python scanning (bandit, yamllint)
**Benefit**: Installs 2 tools instead of 42
**Time Saved**: ~15 minutes
**Disk Saved**: ~500MB

### Persona 2: Full-Stack Team
**Wants**: All scanners for comprehensive coverage
**Benefit**: One-time setup, always ready
**Use Case**: CI/CD pipelines, shared projects

### Persona 3: Learning/Experimenting
**Wants**: Try MEDUSA without commitment
**Benefit**: Quick start, tools install as needed
**Use Case**: First-time users, evaluation

### Persona 4: Security Consultant
**Wants**: Manual control over tools
**Benefit**: Uses existing tool installations
**Use Case**: Pre-configured security workstations

---

## ✅ Benefits

### User Experience
- ✅ Faster onboarding (seconds vs minutes)
- ✅ Lower disk usage (2-5 tools vs 42)
- ✅ Less overwhelming for new users
- ✅ Flexibility for different workflows

### Technical
- ✅ Backward compatible (defaults to existing behavior)
- ✅ Configurable per-project
- ✅ Clear user intentions captured in config
- ✅ Better for CI/CD (install only what's needed)

### Business
- ✅ Lower barrier to entry
- ✅ Better first-run experience
- ✅ Scales better (doesn't install unused tools)
- ✅ More professional UX

---

## 🚧 Implementation Plan

### Phase 1: Core Functionality (1-2 hours)
- [ ] Add `installation.mode` to config schema
- [ ] Implement mode selection in `medusa init`
- [ ] Add detected language scanner list
- [ ] Test basic flow

### Phase 2: On-Demand Installation (2-3 hours)
- [ ] Implement lazy scanner loading
- [ ] Add confirmation prompts
- [ ] Handle installation failures gracefully
- [ ] Test edge cases (network failures, permission issues)

### Phase 3: Polish & Documentation (1 hour)
- [ ] Update README with new workflow
- [ ] Add examples to docs
- [ ] Update init wizard messages
- [ ] Add tests

**Total Estimated Effort**: 4-6 hours

---

## 🧪 Testing Strategy

### Test Cases
1. **New user, no tools installed**
   - Select "on-demand" mode
   - Scan triggers installation prompt
   - Verify tool installs correctly

2. **New user, some tools installed**
   - Select "detected" mode
   - Verify only missing detected tools install
   - Skip already-installed tools

3. **Team setup**
   - Select "all" mode
   - Verify all 42 scanners attempt installation
   - Handle failures gracefully

4. **Manual mode**
   - Select "manual"
   - Verify no auto-installation happens
   - Scanner reports tools as missing

### Edge Cases
- Network failure during on-demand install
- Permission denied during installation
- Tool installation fails midway
- Config file missing/corrupted

---

## 🎯 Success Metrics

### Quantitative
- Reduce average init time from 15min to <1min for on-demand mode
- Increase adoption rate (easier first-run experience)
- Reduce "abandoned installation" rate

### Qualitative
- User feedback: "Much easier to get started"
- "Doesn't feel overwhelming anymore"
- "Love the on-demand approach"

---

## 🔄 Alternatives Considered

### Alternative 1: Profile-Based Installation
```
Profiles:
  • python-dev (bandit, yamllint, mypy)
  • web-dev (eslint, stylelint, htmlhint)
  • devops (shellcheck, hadolint, yamllint, ansible-lint)
  • full (all 42 scanners)
```
**Pros**: Easy to understand
**Cons**: Rigid, doesn't adapt to project

### Alternative 2: Package Groups
```yaml
scanner_groups:
  python: [bandit, mypy, pylint]
  javascript: [eslint, jshint]
  web: [stylelint, htmlhint]
```
**Pros**: Modular, mix and match
**Cons**: More complex config

### Alternative 3: Post-Install Setup
```
$ medusa setup
  → Scans project
  → Suggests relevant tools
  → Installs selected tools
```
**Pros**: Guided experience
**Cons**: Extra command to remember

**Chosen**: Option A (Install Mode Selection) + Option C (On-Demand)
- Best balance of simplicity and power
- Familiar pattern (like package manager confirmations)
- Works well for all personas

---

## 📝 Configuration Examples

### Example 1: On-Demand (Default for new users)
```yaml
installation:
  mode: on-demand
  auto_install: true
  confirm_before_install: true
```

### Example 2: Auto-Install Detected Only (CI/CD)
```yaml
installation:
  mode: detected
  auto_install: true
  confirm_before_install: false  # No prompts in CI
```

### Example 3: Manual (Advanced users)
```yaml
installation:
  mode: manual
  auto_install: false
```

### Example 4: Install All (Team environments)
```yaml
installation:
  mode: all
  auto_install: true
  confirm_before_install: true
```

---

## 💬 User Feedback (Simulated)

> "Finally! I don't need to install 42 tools just to scan my Python project. On-demand is perfect." - Solo Developer

> "Love the detected mode. It found exactly what I needed and installed just those 3 tools." - Frontend Developer

> "We use 'all' mode in CI/CD. One Docker layer, everything installed, perfect for teams." - DevOps Engineer

> "The on-demand prompts are helpful. I learn what tools are available as I scan different file types." - New User

---

## 🚀 Next Steps

1. **Get user feedback** on this proposal
2. **Create GitHub issue** for tracking
3. **Implement Phase 1** (core functionality)
4. **Test with real users**
5. **Iterate based on feedback**
6. **Ship in v0.8.0**

---

## 📎 Related Issues

- #TBD: Installation takes too long
- #TBD: Too many tools for simple projects
- #TBD: Better first-run experience

---

**Proposed By**: Testing Session on Ubuntu 24.04
**Impact**: HIGH - Significantly improves UX
**Effort**: MEDIUM - 4-6 hours implementation
**Risk**: LOW - Backward compatible, opt-in
