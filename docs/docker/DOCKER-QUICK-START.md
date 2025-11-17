# 🐳 MEDUSA Docker Quick Start

**Version**: 0.9.1
**Status**: ✅ Production Ready
**Last Updated**: 2025-11-15

---

## ⚡ Quick Commands

```bash
# Build the image (if needed)
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."

# Scan current directory
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"

# Scan with custom workers
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --workers 4"

# Interactive shell
sg docker -c "docker run --rm -it medusa:latest /bin/bash"

# Check version
sg docker -c "docker run --rm medusa:latest --version"
```

---

## 📦 Available Images

| Image | Tag | Size | Purpose |
|-------|-----|------|---------|
| medusa-security | latest | 295MB | Current version (v0.9.1) |
| medusa-security | v0.9.1 | 295MB | Tagged release |
| medusa-security | simple | 295MB | Same as latest |
| medusa-security | production | 295MB | Multi-stage build |
| medusa-test | latest | 395MB | With pytest & dev tools |

---

## 📁 Files Created

### Docker Configuration
- `Dockerfile` - Multi-stage production build
- `Dockerfile.simple` - Fast build (uses pre-built wheel) ⭐
- `Dockerfile.test` - Testing with dev dependencies
- `docker-compose.yml` - Compose config (optional)
- `.dockerignore` - Build optimization
- `Makefile` - Convenient shortcuts

### Documentation
- `DOCKER.md` - Complete Docker guide (8.6KB)
- `DOCKER-TESTING.md` - Test plan
- `DOCKER-TEST-RESULTS.md` - Test results
- `DOCKER-QUICK-START.md` - This file

### Code
- `dist/medusa_security-0.9.1.1-py3-none-any.whl` - Built package

---

## 🔧 Common Tasks

### Build Fresh Image
```bash
# Rebuild the wheel
source .venv/bin/activate && python -m build --wheel

# Build Docker image
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."
```

### Scan Different Directories
```bash
# Scan another project
sg docker -c "docker run --rm -v /path/to/project:/workspace:ro medusa:latest scan /workspace"

# Scan with reports in /tmp
sg docker -c "docker run --rm -v $(pwd):/workspace:ro -v /tmp/reports:/reports medusa:latest scan /workspace -o /reports"
```

### Test in Container
```bash
# Run pytest
sg docker -c "docker run --rm medusa-test:latest"

# Interactive testing
sg docker -c "docker run --rm -it medusa-test:latest /bin/bash"
```

### Check What's Available
```bash
# List images
sg docker -c "docker images | grep medusa"

# Check installed scanners
sg docker -c "docker run --rm medusa:latest install --check"

# View config
sg docker -c "docker run --rm -v $(pwd):/workspace:ro medusa:latest config"
```

---

## 🎯 Use Cases

### 1. Quick Security Scan
```bash
cd /path/to/your/project
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"
```

### 2. CI/CD Pipeline
```yaml
# .github/workflows/security.yml
- name: MEDUSA Security Scan
  run: |
    docker pull medusa-security:latest
    docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --fail-on high
```

### 3. Multi-Distribution Testing
```bash
# Test on Ubuntu 22.04, 24.04, Debian 12
bash test-docker-install.sh
```

---

## 🐛 Troubleshooting

### Permission Denied
**Issue**: `permission denied while trying to connect to Docker daemon`

**Solution**: Use `sg docker -c` prefix:
```bash
sg docker -c "docker run --rm medusa:latest --version"
```

Or open a new terminal after running:
```bash
sudo usermod -aG docker $USER
```

### Old Version Showing
**Issue**: Still seeing v6.1.0

**Solution**: Rebuild the image:
```bash
source .venv/bin/activate
python -m build --wheel
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."
```

### Read-Only Filesystem Error
**Issue**: Can't write cache/reports

**Solution**: Use read-write mount or custom output:
```bash
# Read-write mount
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"

# Custom output location
sg docker -c "docker run --rm -v $(pwd):/workspace:ro -v /tmp:/reports medusa:latest scan /workspace -o /reports"
```

---

## 📚 Full Documentation

For comprehensive information, see:
- **DOCKER.md** - Complete usage guide
- **README.md** - MEDUSA overview
- **.claude/claude.md** - Project context

---

## ✅ Verification Checklist

Run these to verify everything works:

```bash
# 1. Check images exist
sg docker -c "docker images | grep medusa"

# 2. Test version
sg docker -c "docker run --rm medusa:latest --version"
# Should show: MEDUSA v0.9.1.1

# 3. Test help
sg docker -c "docker run --rm medusa:latest --help"

# 4. Test config
sg docker -c "docker run --rm medusa:latest config"

# 5. Test scan
sg docker -c "docker run --rm -v $(pwd):/workspace:ro medusa:latest scan /workspace --workers 2"
# Should show: MEDUSA Parallel Scanner v0.9.1
```

All showing v0.9.1? ✅ You're ready to go!

---

## 🚀 Next Steps

1. ✅ All Docker images built
2. ✅ Version numbers consistent (v0.9.1)
3. ✅ Documentation complete
4. 📦 Optional: Push to Docker Hub
5. 🔄 Optional: Set up CI/CD
6. 📝 Optional: Add more tests

---

**Status**: Ready for production use! 🎉
