# MEDUSA Docker Multi-Distribution Testing Plan

**Purpose**: Test MEDUSA installation across major Linux distributions
**Status**: READY TO EXECUTE (after Docker install)
**Date**: 2025-11-15

---

## 🎯 Testing Goals

1. **Verify cross-distribution compatibility**
2. **Test package manager variations** (apt, yum, dnf, pacman, apk)
3. **Identify distribution-specific issues**
4. **Validate installation on minimal systems**

---

## 🐳 Linux Distributions to Test

### Tier 1: Debian-based (Primary Targets)
| Distro | Base | Package Manager | Priority | Status |
|--------|------|-----------------|----------|--------|
| **Ubuntu 22.04 LTS** | Debian | apt | P0 | ✅ Tested (previous session) |
| **Ubuntu 24.04 LTS** | Debian | apt | P0 | ⏸️ Paused (we tested real hardware) |
| **Debian 12 (Bookworm)** | Debian | apt | P0 | ✅ Tested (previous session) |
| **Debian 11 (Bullseye)** | Debian | apt | P1 | 📋 TODO |

### Tier 2: RedHat-based (Enterprise)
| Distro | Base | Package Manager | Priority | Status |
|--------|------|-----------------|----------|--------|
| **Fedora 40** | RHEL | dnf | P1 | 📋 TODO |
| **Rocky Linux 9** | RHEL | dnf | P1 | 📋 TODO |
| **AlmaLinux 9** | RHEL | dnf | P1 | 📋 TODO |
| **CentOS Stream 9** | RHEL | dnf | P2 | 📋 TODO |

### Tier 3: Other Major Distros
| Distro | Base | Package Manager | Priority | Status |
|--------|------|-----------------|----------|--------|
| **Arch Linux** | Independent | pacman | P1 | 📋 TODO |
| **Alpine Linux** | Independent | apk | P2 | 📋 TODO |
| **openSUSE Leap** | Independent | zypper | P2 | 📋 TODO |

---

## 📦 What We Test On Each Distro

### Installation Tests
1. ✅ **Package installation** - pip install from wheel
2. ✅ **Dependency resolution** - All deps install correctly
3. ✅ **Binary creation** - `medusa` command works
4. ✅ **Version check** - `medusa --version`

### Functionality Tests
1. ✅ **Init command** - Creates `.medusa.yml`
2. ✅ **Scanner detection** - Finds available tools
3. ✅ **Basic scan** - Scans test files
4. ✅ **Config generation** - Claude Code integration

### Tool Installation Tests
1. ⚠️ **Bandit via system pkg** - `apt/dnf/pacman install python3-bandit`
2. ⚠️ **Bandit via pip fallback** - `pip install bandit`
3. ⚠️ **ShellCheck installation** - System package
4. ⚠️ **Package name mappings** - Correct names per distro

---

## 🚀 Quick Start: Install Docker

```bash
# Ubuntu 24.04 Docker installation
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Verify installation
docker --version
docker run hello-world
```

**Note**: Log out and back in after adding user to docker group

---

## 🧪 Test Script (Already Exists!)

We have `test-docker-install.sh` that tests:
- Ubuntu 22.04
- Ubuntu 24.04
- Debian 12

### Current Script
```bash
#!/bin/bash
# MEDUSA Phase 6 Docker Installation Test

MEDUSA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="0.7.0.0"

test_distro() {
    local distro=$1
    local python_pkg=$2

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" bash -c "
        # 9-step test process
        # (install, verify, init, scan, etc.)
    "
}

test_distro "ubuntu:22.04" "python3"
test_distro "ubuntu:24.04" "python3"
test_distro "debian:12" "python3"
```

---

## 📋 Extended Test Script (Proposal)

```bash
#!/bin/bash
# MEDUSA Phase 6 - Extended Multi-Distro Testing

VERSION="0.7.0.0"

# Test more distributions
echo "🐳 Testing on 10 Linux distributions..."

# Debian-based
test_distro "ubuntu:22.04" "python3" "apt"
test_distro "ubuntu:24.04" "python3" "apt"
test_distro "debian:12" "python3" "apt"
test_distro "debian:11" "python3" "apt"

# RedHat-based
test_distro "fedora:40" "python3" "dnf"
test_distro "rockylinux:9" "python3" "dnf"
test_distro "almalinux:9" "python3" "dnf"

# Other
test_distro "archlinux:latest" "python" "pacman"
test_distro "alpine:latest" "python3" "apk"
test_distro "opensuse/leap:15" "python3" "zypper"
```

---

## 🎯 Expected Results Per Distro

### Ubuntu 22.04 / 24.04
```
✅ python3: Pre-installed
✅ pip3: Requires python3-pip
✅ venv: Requires python3-venv
✅ bandit: Available as python3-bandit
✅ yamllint: Available as yamllint
✅ shellcheck: Available as shellcheck
```

### Debian 11 / 12
```
✅ python3: Pre-installed
✅ pip3: Requires python3-pip
✅ venv: Requires python3-venv
✅ bandit: Available as python3-bandit (same as Ubuntu)
✅ yamllint: Available as yamllint
✅ shellcheck: Available as shellcheck
```

### Fedora 40
```
✅ python3: Pre-installed
✅ pip3: Built-in with python3
✅ venv: Built-in with python3
⚠️ bandit: Available as 'bandit' (NOT python3-bandit)
✅ yamllint: Available as yamllint
✅ ShellCheck: Available as ShellCheck (capital S)
```

### Rocky Linux 9 / AlmaLinux 9
```
✅ python3: Pre-installed (3.9)
✅ pip3: Built-in
✅ venv: Built-in
⚠️ bandit: Available via EPEL or pip
⚠️ yamllint: Available via EPEL or pip
✅ ShellCheck: Available as ShellCheck
```

### Arch Linux
```
✅ python: Pre-installed
✅ pip: Built-in
✅ venv: Built-in
✅ bandit: Available in AUR or pip
⚠️ yamllint: Available as yamllint (community repo)
✅ shellcheck: Available as shellcheck
```

### Alpine Linux
```
⚠️ python3: Must install python3
⚠️ pip: Requires py3-pip
⚠️ venv: Requires python3-dev
⚠️ bandit: Only via pip
⚠️ yamllint: Only via pip
⚠️ shellcheck: Available as shellcheck (community)
```

---

## 🐛 Known Distribution-Specific Issues

### Package Name Variations

| Tool | Ubuntu/Debian | Fedora/RHEL | Arch | Alpine |
|------|---------------|-------------|------|--------|
| bandit | python3-bandit | bandit | pip only | pip only |
| yamllint | yamllint | yamllint | yamllint | pip only |
| shellcheck | shellcheck | ShellCheck | shellcheck | shellcheck |
| python-pip | python3-pip | python3-pip | python-pip | py3-pip |

### Python Version Differences
- **Ubuntu 22.04**: Python 3.10
- **Ubuntu 24.04**: Python 3.12
- **Debian 12**: Python 3.11
- **Fedora 40**: Python 3.12
- **RHEL 9**: Python 3.9
- **Alpine**: Python 3.11

### Package Manager Quirks
- **apt**: Requires `apt update` first
- **dnf**: Slower than apt, better dependency resolution
- **pacman**: Requires `-Sy` for update, `-S` for install
- **apk**: Minimal packages, requires `--update` flag

---

## 📊 Test Matrix Template

| Distro | Python | pip | venv | Install | Init | Scan | Tools | Result |
|--------|--------|-----|------|---------|------|------|-------|--------|
| Ubuntu 22.04 | 3.10 | ✅ | ✅ | ✅ | ✅ | ✅ | 3/42 | ✅ PASS |
| Ubuntu 24.04 | 3.12 | ✅ | ✅ | ✅ | ✅ | ✅ | 3/42 | ✅ PASS |
| Debian 12 | 3.11 | ✅ | ✅ | ✅ | ✅ | ✅ | 3/42 | ✅ PASS |
| Debian 11 | 3.9 | ? | ? | ? | ? | ? | ? | 📋 TODO |
| Fedora 40 | 3.12 | ? | ? | ? | ? | ? | ? | 📋 TODO |
| Rocky 9 | 3.9 | ? | ? | ? | ? | ? | ? | 📋 TODO |
| Arch | Latest | ? | ? | ? | ? | ? | ? | 📋 TODO |
| Alpine | 3.11 | ? | ? | ? | ? | ? | ? | 📋 TODO |

---

## 🔧 Issues to Watch For

### Common Issues
1. **Python version incompatibility** - MEDUSA requires >=3.10
2. **Missing python3-venv** - Required for venv creation
3. **Package name mismatches** - bandit vs python3-bandit
4. **Permission issues** - Docker runs as root by default
5. **Network timeouts** - pip install can be slow

### Distribution-Specific
1. **RHEL/Rocky/Alma**: May need EPEL repository
2. **Alpine**: Uses musl libc, may have compatibility issues
3. **Arch**: AUR packages require manual confirmation
4. **Fedora**: Newer packages, may expose compatibility bugs

---

## 🎬 Running the Tests

### Option 1: Existing Script (3 distros)
```bash
./test-docker-install.sh
```

### Option 2: Individual Distro Test
```bash
docker run --rm -v "$PWD/dist:/dist:ro" -w /tmp ubuntu:22.04 bash -c "
    apt update -qq
    apt install -y python3-pip python3-venv
    pip3 install /dist/medusa_security-0.7.0.0-py3-none-any.whl
    medusa --version
"
```

### Option 3: Extended Test (10 distros)
```bash
# Create extended script
cat > test-all-distros.sh << 'EOF'
#!/bin/bash
# Test all major Linux distributions

for distro in \
    ubuntu:22.04 \
    ubuntu:24.04 \
    debian:12 \
    fedora:40 \
    archlinux:latest \
    alpine:latest
do
    echo "Testing $distro..."
    # ... test logic ...
done
EOF

chmod +x test-all-distros.sh
./test-all-distros.sh
```

---

## 📈 Success Criteria

### Per Distribution
- [ ] ✅ Python 3.10+ available or installable
- [ ] ✅ pip install succeeds
- [ ] ✅ `medusa --version` shows v0.7.0.0
- [ ] ✅ `medusa init` creates config
- [ ] ✅ `medusa scan` executes without crash
- [ ] ✅ At least 2-3 scanners available

### Overall
- [ ] ✅ 80%+ distributions pass all tests
- [ ] ✅ Critical distros (Ubuntu 22/24, Debian 12, Fedora) pass
- [ ] ✅ Package name mappings correct for each distro
- [ ] ✅ No crashes or critical errors

---

## 🚀 Next Steps

### Immediate (If Docker Available)
1. Install Docker on Ubuntu 24.04
2. Run existing test script (3 distros)
3. Document results

### Short Term
1. Add Fedora testing
2. Add Arch Linux testing
3. Update package mappings based on results

### Medium Term
1. Test on all 10 distributions
2. Create test matrix spreadsheet
3. Update installer code for each distro

---

## 💡 Tips for Docker Testing

### Performance
```bash
# Pull all images first (parallel downloads)
docker pull ubuntu:22.04 ubuntu:24.04 debian:12 fedora:40 &

# Clean up after tests
docker system prune -f
```

### Debugging
```bash
# Interactive test (don't remove container)
docker run -it -v "$PWD/dist:/dist:ro" ubuntu:22.04 bash

# Inside container, run commands manually
apt update
apt install -y python3-pip python3-venv
pip3 install /dist/medusa_security-0.7.0.0-py3-none-any.whl
medusa --version
```

### Logging
```bash
# Save test output
./test-docker-install.sh 2>&1 | tee docker-test-results.log

# Parse results
grep "PASSED\|FAILED" docker-test-results.log
```

---

## 📊 Time Estimates

| Task | Time | Difficulty |
|------|------|------------|
| Install Docker | 5 min | Easy |
| Test 3 distros (existing script) | 10 min | Easy |
| Test 10 distros (extended) | 30 min | Easy |
| Fix distro-specific bugs | 1-3 hours | Medium |
| Update package mappings | 30 min | Easy |
| Document results | 30 min | Easy |

**Total**: 2-4 hours for comprehensive multi-distro testing

---

**Ready to install Docker and start testing?**

We can test 10+ Linux distributions in under an hour!
