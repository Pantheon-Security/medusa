# MEDUSA Project Context for Claude Code

## Project Overview

**MEDUSA v0.7.0.0** - The 42-Headed Security Guardian
- Universal security scanner for all languages and platforms
- Python-based CLI tool with 42 different language scanners
- Parallel processing for high performance
- Full Docker support for testing and deployment

## Quick Reference

### Docker Commands (Use with `sg docker -c`)

```bash
# Build Images
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."
make docker-build-simple

# Run MEDUSA
sg docker -c "docker run --rm medusa:latest --version"
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"

# Interactive Shell
sg docker -c "docker run --rm -it medusa:latest /bin/bash"

# List Images
sg docker -c "docker images | grep medusa"

# Clean Up
sg docker -c "docker rmi medusa-security:latest"
make docker-clean
```

### Local Development Commands

```bash
# Virtual Environment
source .venv/bin/activate

# Build Distribution
python -m build --wheel

# Install Locally
pip install -e .

# Run MEDUSA
medusa --version
medusa scan .
medusa init
medusa install --check
```

### Testing

```bash
# Run Tests
pytest tests/ -v

# Build and Test in Docker
sg docker -c "docker build -f Dockerfile.test -t medusa-test ."
sg docker -c "docker run --rm medusa-test"

# Test Installation Script
bash test-docker-install.sh
```

## Project Structure

```
medusa/
├── medusa/                  # Main package
│   ├── cli.py              # CLI entry point
│   ├── core/               # Core functionality
│   ├── scanners/           # 42 language scanners
│   ├── platform/           # Platform-specific installers
│   └── ide/                # IDE integrations
├── tests/                  # Test suite
├── dist/                   # Built wheels
├── docs/                   # Documentation
├── .claude/                # Claude Code configuration
│   ├── agents/medusa/      # MEDUSA agent
│   └── commands/           # Slash commands
├── Dockerfile              # Multi-stage production build
├── Dockerfile.simple       # Fast build (pre-built wheel)
├── Dockerfile.test         # Testing image
├── docker-compose.yml      # Compose configuration
├── Makefile               # Convenient commands
├── pyproject.toml         # Package configuration
└── .medusa.yml            # MEDUSA config

Key Files:
- pyproject.toml:1         # Package metadata and dependencies
- medusa/cli.py:1          # Main CLI entry point
- medusa/core/parallel.py  # Parallel scanning engine
- .medusa.yml:1            # Configuration file
```

## Docker Setup

### Files Created
- **Dockerfile** - Production multi-stage build
- **Dockerfile.simple** - Fast build using pre-built wheel (RECOMMENDED)
- **Dockerfile.test** - Testing with dev dependencies
- **docker-compose.yml** - Compose services
- **.dockerignore** - Excludes .claude/, .venv/, etc.
- **Makefile** - Convenient Docker commands
- **DOCKER.md** - Complete Docker documentation

### Image Information
- **Name**: `medusa-security:latest` / `medusa-security:simple`
- **Size**: ~295MB
- **Base**: python:3.11-slim
- **User**: medusa (non-root, uid 1000)
- **Entrypoint**: medusa
- **Workdir**: /workspace

### Common Docker Workflows

#### Quick Scan
```bash
# Scan current project
make docker-scan

# Or manually
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"
```

#### Development
```bash
# Interactive shell
sg docker -c "docker run --rm -it -v $(pwd):/workspace medusa:latest /bin/bash"

# Inside container
medusa scan /workspace
medusa install --check
```

#### Testing
```bash
# Build test image
make docker-build-test

# Run tests
make docker-test
```

#### Rebuild
```bash
# Rebuild from scratch
sg docker -c "docker build --no-cache -f Dockerfile.simple -t medusa:latest ."

# Or with Make
make docker-clean
make docker-build-simple
```

## Important Notes

### Docker Permissions
- User is in docker group (ross-churchill)
- Use `sg docker -c "command"` until you log out/in
- Or open new terminal for docker group to be active
- All whitelisted docker commands work with `sg docker -c`

### Volume Mounts
- **Read-only**: `-v $(pwd):/workspace:ro` - Prevents writes
- **Read-write**: `-v $(pwd):/workspace` - Allows cache/reports
- Reports go to `.medusa/reports/` by default

### Building
- Always build wheel first: `python -m build --wheel`
- Wheel location: `dist/medusa_security-0.7.0.0-py3-none-any.whl`
- Dockerfile.simple is fastest (uses pre-built wheel)
- Dockerfile does full build from source

## MEDUSA Configuration

### .medusa.yml
```yaml
version: 0.7.0
scanners:
  enabled: []     # Empty = all enabled
  disabled: []    # List to disable
fail_on: high     # critical | high | medium | low
exclude:
  paths:
    - node_modules/
    - .venv/
    - dist/
  files:
    - "*.min.js"
workers: null       # null = auto-detect
cache_enabled: true
```

### IDE Integration
- Claude Code: ✅ Fully supported
- Commands: `/medusa-scan`
- Agent: `.claude/agents/medusa/`
- Auto-scan on save: Configurable

## Common Tasks

### Build Distribution Wheel
```bash
# Clean old builds
rm -rf dist/ build/ *.egg-info/

# Build new wheel
python -m build --wheel

# Verify
ls -lh dist/*.whl
```

### Update Docker Image
```bash
# 1. Build new wheel
python -m build --wheel

# 2. Rebuild Docker image
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."

# 3. Test
sg docker -c "docker run --rm medusa:latest --version"
```

### Test Multi-Platform
```bash
# Test on Ubuntu 22.04, 24.04, Debian 12
bash test-docker-install.sh
```

### Scan Project
```bash
# Local
medusa scan .

# Docker
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"

# Quick scan (cache)
medusa scan . --quick
```

## Troubleshooting

### Docker Permission Denied
```bash
# Add to docker group (already done)
sudo usermod -aG docker $USER

# Activate group
newgrp docker
# Or log out and log back in

# Check group membership
groups | grep docker
```

### Build Fails - Wheel Not Found
```bash
# Build the wheel first
python -m build --wheel

# Verify it exists
ls dist/*.whl
```

### Container Can't Write
```bash
# Use read-write mount
sg docker -c "docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace"

# Or specify output directory
sg docker -c "docker run --rm -v $(pwd):/workspace:ro -v /tmp/reports:/reports medusa:latest scan /workspace -o /reports"
```

### Clean Docker Cache
```bash
# Clean images
make docker-clean

# Clean build cache
make docker-prune

# Or manually
sg docker -c "docker builder prune -f"
```

## Development Workflow

### Making Changes
1. Edit code in `medusa/`
2. Test locally: `medusa scan .`
3. Build wheel: `python -m build --wheel`
4. Build Docker: `make docker-build-simple`
5. Test Docker: `make docker-scan`
6. Run tests: `pytest tests/ -v`

### Testing Changes
```bash
# Local testing
pip install -e .
medusa scan .

# Docker testing
python -m build --wheel
make docker-build-simple
make docker-scan

# Multi-platform testing
bash test-docker-install.sh
```

## Resources

- **README**: README.md - General documentation
- **Docker Guide**: DOCKER.md - Complete Docker reference
- **Changelog**: CHANGELOG.md - Version history
- **Config**: .medusa.yml - MEDUSA configuration
- **PyProject**: pyproject.toml - Package metadata

## Version Info

- **Current Version**: 0.7.0.0
- **Python Required**: >=3.10
- **Development Status**: Beta (Production Ready)
- **License**: MIT

## Quick Tips

1. **Always use `sg docker -c` for docker commands** until you open a new terminal
2. **Use Makefile shortcuts** when possible (e.g., `make docker-scan`)
3. **Read DOCKER.md** for comprehensive Docker documentation
4. **Use Dockerfile.simple** for fastest builds
5. **Build wheel first** before building Docker images
6. **Check .dockerignore** if files aren't being copied to image

## Makefile Quick Reference

```bash
make help              # Show all commands
make docker-setup      # Configure Docker access
make docker-build      # Build production image
make docker-build-simple   # Build simple image (fastest)
make docker-build-test     # Build test image
make docker-run        # Run MEDUSA help
make docker-scan       # Scan current directory
make docker-test       # Run tests
make docker-shell      # Interactive shell
make docker-clean      # Remove images
make docker-prune      # Clean build cache
make test-install      # Run installation test script
```

---

**Last Updated**: 2025-11-15
**Docker Images**: Built and tested ✅
**Status**: Ready for development and testing
