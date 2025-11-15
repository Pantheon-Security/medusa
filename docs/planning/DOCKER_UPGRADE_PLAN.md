# MEDUSA Docker Image - Future Enhancement

**Status**: 📋 Planned
**Priority**: Medium
**Created**: 2025-11-01

## Problem Statement

**Current Limitation**: MEDUSA requires all linters to be installed on the target machine:
- ❌ QNAP (Bash 3.2) - No shellcheck, bandit, hadolint, etc.
- ❌ Remote servers - May not have Python, Go, Node.js for linters
- ❌ Embedded systems - Limited package managers
- ✅ Ubuntu dev machine - Has all tools (pip, apt, npm)

**Impact**: Remote scanning on QNAP/embedded systems only gets basic pattern matching, not full 24-headed security analysis.

---

## Solution: MEDUSA Docker Image

Create a self-contained Docker image with **all 24 security scanners pre-installed**.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  MEDUSA Docker Image (chimera/medusa-scanner:latest)       │
├─────────────────────────────────────────────────────────────┤
│  Base: ubuntu:24.04 (or python:3.12-slim)                  │
│                                                             │
│  Installed Tools:                                           │
│  ✅ ShellCheck (bash)         ✅ Bandit (python)           │
│  ✅ golangci-lint (go)        ✅ hadolint (docker)         │
│  ✅ yamllint (yaml)           ✅ tflint (terraform)        │
│  ✅ ESLint (js/ts)            ✅ markdownlint (markdown)   │
│  ✅ Syft + Grype (SBOM)       ✅ PowerShell analyzer       │
│  ✅ sqlmap (SQL injection)    ✅ nosqlmap (NoSQL)          │
│                                                             │
│  Entry Point: /app/medusa.sh                               │
│  Volume Mount: /scan (target directory)                    │
└─────────────────────────────────────────────────────────────┘
```

### Usage Examples

#### 1. Local Docker Scan
```bash
# Scan local directory
docker run --rm -v /path/to/scan:/scan chimera/medusa-scanner:latest

# Scan with results output
docker run --rm -v /path/to/scan:/scan -v /tmp/results:/results \
  chimera/medusa-scanner:latest --output /results/report.json
```

#### 2. Remote QNAP Scan (via Docker API)
```bash
# Upload MEDUSA image to QNAP Docker
docker save chimera/medusa-scanner:latest | \
  ssh ross@192.168.1.200 "docker load"

# Run scan on QNAP via SSH
ssh ross@192.168.1.200 "docker run --rm \
  -v /share/ZFS43_DATA/monitoring:/scan \
  chimera/medusa-scanner:latest"
```

#### 3. Portainer Stack Deployment
```yaml
# medusa-scanner-stack.yml
services:
  medusa:
    image: chimera/medusa-scanner:latest
    volumes:
      - /share/ZFS43_DATA:/scan:ro
      - /share/ZFS55_DATA/medusa-results:/results
    command: ["--scan-project", "/scan", "--output", "/results/report.json"]
    restart: "no"  # One-shot scan
```

#### 4. Scheduled Scans (Cron in Container)
```yaml
services:
  medusa-scheduled:
    image: chimera/medusa-scanner:latest
    volumes:
      - /share/ZFS43_DATA:/scan:ro
      - /share/ZFS55_DATA/medusa-results:/results
    environment:
      - SCAN_SCHEDULE="0 2 * * *"  # Daily at 2 AM
      - SCAN_PATH=/scan
      - OUTPUT_PATH=/results
    restart: unless-stopped
```

---

## Dockerfile

```dockerfile
FROM ubuntu:24.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl wget git \
    python3 python3-pip \
    nodejs npm \
    golang-go \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip3 install --no-cache-dir \
    bandit \
    yamllint \
    sqlmap

# Install Go linters
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
    sh -s -- -b /usr/local/bin

# Install hadolint (Dockerfile linter)
RUN wget -O /usr/local/bin/hadolint \
    https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 && \
    chmod +x /usr/local/bin/hadolint

# Install tflint (Terraform)
RUN curl -s https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash

# Install Node.js linters
RUN npm install -g \
    eslint \
    markdownlint-cli

# Install SBOM tools
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Copy MEDUSA script
WORKDIR /app
COPY medusa.sh /app/medusa.sh
RUN chmod +x /app/medusa.sh

# Create scan directory
VOLUME ["/scan", "/results"]

# Entry point
ENTRYPOINT ["/app/medusa.sh"]
CMD ["/scan"]
```

---

## Build & Publish

```bash
# Build image
cd /home/ross/qnap/qnap_chimera/.claude/agents/medusa
docker build -t chimera/medusa-scanner:latest .

# Test locally
docker run --rm -v /tmp/test:/scan chimera/medusa-scanner:latest

# Save for QNAP
docker save chimera/medusa-scanner:latest -o medusa-scanner.tar

# Upload to QNAP
scp medusa-scanner.tar ross@192.168.1.200:/tmp/
ssh ross@192.168.1.200 "docker load -i /tmp/medusa-scanner.tar"

# Optional: Push to registry
docker tag chimera/medusa-scanner:latest ghcr.io/yourusername/medusa-scanner:latest
docker push ghcr.io/yourusername/medusa-scanner:latest
```

---

## Benefits

### ✅ **Bypasses Tool Installation**
- No need to install 24+ linters on QNAP
- Works on any system with Docker
- Consistent tool versions across all scans

### ✅ **Portable & Reproducible**
- Same scan results on Ubuntu, QNAP, embedded systems
- Version-locked tools (no "works on my machine")
- Easy to distribute (single Docker image)

### ✅ **Scheduled Scans**
- Run daily/weekly security scans automatically
- Store results in persistent volume
- Email/webhook alerts on critical findings

### ✅ **CI/CD Integration**
```yaml
# .github/workflows/security.yml
- name: MEDUSA Security Scan
  run: |
    docker run --rm -v $PWD:/scan \
      chimera/medusa-scanner:latest --fail-on high
```

### ✅ **Multi-Platform Support**
- Build for `linux/amd64` (Ubuntu, QNAP)
- Build for `linux/arm64` (Raspberry Pi, DGX Spark)
- Use Docker Buildx for multi-arch images

---

## Image Size Optimization

**Current estimate**: ~800MB (all 24 tools)

**Optimization strategies**:
1. **Multi-stage build** - Copy only binaries, not build tools
2. **Alpine base** - Use `python:3.12-alpine` instead of Ubuntu (saves 400MB)
3. **Minimal tools** - Create `medusa-core` (bash/python/docker only) vs `medusa-full` (all 24)
4. **Layer caching** - Order RUN commands by change frequency

**Optimized size target**: ~200-300MB

---

## Future Enhancements

### 1. **Web API**
```dockerfile
# Add Flask API server
RUN pip3 install flask flask-cors

EXPOSE 8080
CMD ["python3", "/app/medusa-api.py"]
```

**Usage**:
```bash
curl -X POST http://qnap:8080/scan -F 'files=@Dockerfile'
```

### 2. **Result Dashboard**
- Mount `/results` volume
- Generate HTML reports with charts
- Historical scan comparison

### 3. **Webhook Notifications**
```bash
docker run --rm -v /scan:/scan \
  -e WEBHOOK_URL="https://discord.com/api/webhooks/..." \
  chimera/medusa-scanner:latest
```

### 4. **Custom Patterns**
```bash
docker run --rm -v /scan:/scan -v /custom-patterns.json:/config/patterns.json \
  chimera/medusa-scanner:latest
```

---

## Implementation Checklist

- [ ] Create Dockerfile with all 24 linters
- [ ] Test build locally on Ubuntu
- [ ] Optimize image size (<300MB)
- [ ] Add multi-arch support (amd64, arm64)
- [ ] Update medusa-remote.sh to support Docker mode
- [ ] Create Portainer stack template
- [ ] Add GitHub Actions workflow for auto-builds
- [ ] Document in MEDUSA.md
- [ ] Create example scan results
- [ ] Add to Claude Code skill (`/medusa docker`)

---

## Skill Integration

Update `.claude/skills/medusa.md`:

```markdown
## Docker Mode (Bypasses Tool Installation)

```bash
# Build MEDUSA Docker image
/medusa docker build

# Scan using Docker (works on any machine!)
/medusa docker scan <host> <path>

# Example: Scan QNAP without installing linters
/medusa docker scan 192.168.1.200 /share/ZFS43_DATA/monitoring
```

**Benefits**: All 24 linters pre-installed, no need to install on target!
```

---

## Estimated Effort

| Task | Time | Difficulty |
|------|------|------------|
| Create Dockerfile | 1-2 hours | Easy |
| Test & optimize | 1-2 hours | Medium |
| Update wrapper scripts | 1 hour | Easy |
| Multi-arch build | 1 hour | Medium |
| Documentation | 1 hour | Easy |
| **TOTAL** | **5-7 hours** | **Medium** |

---

## Priority Justification

**Medium Priority** because:
- ✅ Current bash script works fine on Ubuntu (dev machine)
- ⚠️ QNAP scans are limited (missing linters) but not critical yet
- 🎯 **High value** once we have more remote scans or CI/CD needs
- 🚀 **Low effort** (5-7 hours) for high portability gain

**Trigger to increase priority**:
- Need to scan multiple QNAP shares regularly
- Want CI/CD security checks in GitHub Actions
- Need to distribute MEDUSA to other team members
- Want automated scheduled scans on QNAP

---

**Next Steps When Ready**:
1. Read this document
2. Run `/medusa docker build` (future skill)
3. Test on QNAP: `/medusa docker scan 192.168.1.200 /share/ZFS43_DATA`
4. Deploy as Portainer stack for scheduled scans

**Created**: 2025-11-01
**Last Updated**: 2025-11-01
**Status**: 📋 Documented, ready for implementation
