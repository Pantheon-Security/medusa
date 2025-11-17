# MEDUSA Docker Testing Plan

**Version**: 0.7.0.0
**Date**: 2025-11-15
**Status**: In Progress

---

## Testing Categories

### 1. Basic Functionality Tests

#### 1.1 Version Command
- **Test**: `docker run --rm medusa:latest --version`
- **Expected**: MEDUSA v0.7.0.0
- **Status**: ⏳ Pending

#### 1.2 Help Command
- **Test**: `docker run --rm medusa:latest --help`
- **Expected**: Full help text with commands
- **Status**: ⏳ Pending

#### 1.3 Init Command
- **Test**: Initialize MEDUSA in a temp directory inside container
- **Command**:
  ```bash
  docker run --rm medusa:latest sh -c "cd /tmp && mkdir test && cd test && medusa init --ide claude-code --force"
  ```
- **Expected**: .medusa.yml created
- **Status**: ⏳ Pending

---

### 2. Scanning Tests

#### 2.1 Basic Scan
- **Test**: Scan MEDUSA project itself
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace
  ```
- **Expected**: Successful scan with results
- **Status**: ⏳ Pending

#### 2.2 Read-Only Mount
- **Test**: Scan with read-only volume
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace:ro medusa:latest scan /workspace
  ```
- **Expected**: Scan completes (may warn about cache)
- **Status**: ⏳ Pending

#### 2.3 Read-Write Mount
- **Test**: Scan with writable volume
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace
  ```
- **Expected**: Scan completes, cache/reports written
- **Status**: ⏳ Pending

#### 2.4 Custom Output Directory
- **Test**: Specify output location
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace:ro -v /tmp/medusa-reports:/reports medusa:latest scan /workspace -o /reports
  ```
- **Expected**: Reports in /tmp/medusa-reports/
- **Status**: ⏳ Pending

---

### 3. Performance Tests

#### 3.1 Different Worker Counts
- **Test**: Run with 1, 2, 4, and 8 workers
- **Commands**:
  ```bash
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --workers 1
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --workers 2
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --workers 4
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --workers 8
  ```
- **Expected**: Performance comparison, all complete successfully
- **Status**: ⏳ Pending

#### 3.2 Quick Scan
- **Test**: Quick scan (cache test)
- **Command**:
  ```bash
  # First scan
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace
  # Second scan (should use cache)
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --quick
  ```
- **Expected**: Second scan faster, shows cache hits
- **Status**: ⏳ Pending

#### 3.3 Full Scan
- **Test**: Force full scan (ignore cache)
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace medusa:latest scan /workspace --force
  ```
- **Expected**: All files scanned, cache ignored
- **Status**: ⏳ Pending

---

### 4. Docker Image Tests

#### 4.1 Dockerfile (Multi-Stage Build)
- **Test**: Build and test production image
- **Commands**:
  ```bash
  docker build -t medusa:production .
  docker run --rm medusa:production --version
  docker images | grep medusa
  ```
- **Expected**: Smaller image size, working binary
- **Status**: ⏳ Pending

#### 4.2 Dockerfile.simple
- **Test**: Fast build image (already built)
- **Commands**:
  ```bash
  docker build -f Dockerfile.simple -t medusa:simple .
  docker run --rm medusa:simple --version
  ```
- **Expected**: Quick build, working binary
- **Status**: ✅ Completed (already tested)

#### 4.3 Dockerfile.test
- **Test**: Testing image with pytest
- **Commands**:
  ```bash
  docker build -f Dockerfile.test -t medusa:test .
  docker run --rm -v $(pwd):/workspace medusa:test
  ```
- **Expected**: Tests run, coverage report
- **Status**: ⏳ Pending

---

### 5. Docker Compose Tests

#### 5.1 Main Service
- **Test**: Run default medusa service
- **Command**:
  ```bash
  docker-compose up medusa
  ```
- **Expected**: Scans workspace directory
- **Status**: ⏳ Pending

#### 5.2 Dev Service
- **Test**: Interactive development environment
- **Command**:
  ```bash
  docker-compose run --rm medusa-dev
  ```
- **Expected**: Bash shell, can run medusa commands
- **Status**: ⏳ Pending

#### 5.3 Test Service
- **Test**: Run test suite
- **Command**:
  ```bash
  docker-compose up medusa-test
  ```
- **Expected**: Tests execute successfully
- **Status**: ⏳ Pending

---

### 6. Tool Installation Tests

#### 6.1 Check Available Scanners
- **Test**: List installed scanners
- **Command**:
  ```bash
  docker run --rm medusa:latest install --check
  ```
- **Expected**: List of available/missing tools
- **Status**: ⏳ Pending

#### 6.2 Install Tools
- **Test**: Install additional security tools
- **Command**:
  ```bash
  docker run --rm -it medusa:latest sh -c "medusa install --tool bandit --yes"
  ```
- **Expected**: Tool installs successfully
- **Status**: ⏳ Pending

---

### 7. Multi-Distribution Tests

#### 7.1 Test Script Execution
- **Test**: Run test-docker-install.sh
- **Command**:
  ```bash
  bash test-docker-install.sh
  ```
- **Expected**: All 3 distributions pass (Ubuntu 22.04, 24.04, Debian 12)
- **Status**: ⏳ Pending

#### 7.2 Individual Distribution Tests
- **Test Ubuntu 22.04**:
  ```bash
  docker run --rm -v $(pwd)/dist:/dist:ro ubuntu:22.04 bash -c "
    apt-get update -qq &&
    apt-get install -y -qq python3 python3-pip &&
    pip3 install /dist/medusa_security-0.7.0.0-py3-none-any.whl --break-system-packages &&
    medusa --version
  "
  ```
- **Expected**: Successful installation and version output
- **Status**: ⏳ Pending

---

### 8. Interactive Tests

#### 8.1 Interactive Shell
- **Test**: Run bash inside container
- **Command**:
  ```bash
  docker run --rm -it -v $(pwd):/workspace medusa:latest /bin/bash
  ```
- **Manual Tests Inside**:
  - `medusa --version`
  - `medusa scan /workspace`
  - `medusa install --check`
  - `cd /workspace && ls -la`
- **Expected**: All commands work
- **Status**: ⏳ Pending

#### 8.2 Config Command
- **Test**: View configuration
- **Command**:
  ```bash
  docker run --rm -v $(pwd):/workspace medusa:latest config
  ```
- **Expected**: Display current config
- **Status**: ⏳ Pending

---

### 9. Makefile Tests

#### 9.1 Test All Make Targets
- **Commands**:
  ```bash
  make help
  make docker-build-simple
  make docker-run
  make docker-scan
  make docker-shell (interactive)
  make docker-clean
  make docker-prune
  ```
- **Expected**: All targets work correctly
- **Status**: ⏳ Pending

---

### 10. Edge Cases & Error Handling

#### 10.1 Empty Directory
- **Test**: Scan empty directory
- **Command**:
  ```bash
  mkdir -p /tmp/empty-test
  docker run --rm -v /tmp/empty-test:/workspace medusa:latest scan /workspace
  ```
- **Expected**: Graceful handling, "0 files found" message
- **Status**: ⏳ Pending

#### 10.2 Non-existent Directory
- **Test**: Scan non-existent path
- **Command**:
  ```bash
  docker run --rm medusa:latest scan /nonexistent
  ```
- **Expected**: Error message, non-zero exit code
- **Status**: ⏳ Pending

#### 10.3 Permission Issues
- **Test**: Read-only filesystem
- **Command**:
  ```bash
  docker run --rm --read-only -v $(pwd):/workspace:ro medusa:latest scan /workspace
  ```
- **Expected**: Scan works, warns about unable to write cache
- **Status**: ⏳ Pending

---

### 11. Security Tests

#### 11.1 Non-Root User
- **Test**: Verify running as non-root
- **Command**:
  ```bash
  docker run --rm medusa:latest sh -c "whoami && id"
  ```
- **Expected**: User is 'medusa' (uid 1000)
- **Status**: ⏳ Pending

#### 11.2 Image Scan
- **Test**: Scan Docker image itself for vulnerabilities
- **Command**:
  ```bash
  docker run --rm medusa:latest scan /app
  ```
- **Expected**: Security report for MEDUSA itself
- **Status**: ⏳ Pending

---

## Test Execution Order

### Phase 1: Basic Validation (Quick Tests)
1. ✅ Build Dockerfile.simple (completed)
2. ⏳ Test version command
3. ⏳ Test help command
4. ⏳ Basic scan test

### Phase 2: Core Functionality
5. ⏳ Volume mount tests (ro/rw)
6. ⏳ Output directory test
7. ⏳ Init command test
8. ⏳ Scanner availability check

### Phase 3: Performance & Options
9. ⏳ Worker count tests
10. ⏳ Quick vs full scan
11. ⏳ Cache testing

### Phase 4: Alternative Builds
12. ⏳ Build multi-stage Dockerfile
13. ⏳ Build and test Dockerfile.test
14. ⏳ Docker Compose tests

### Phase 5: Advanced Testing
15. ⏳ Multi-distribution tests
16. ⏳ Interactive shell tests
17. ⏳ Makefile commands
18. ⏳ Edge cases

### Phase 6: Documentation
19. ⏳ Document all results
20. ⏳ Create summary report

---

## Test Results Template

### Test: [Test Name]
- **Date**: YYYY-MM-DD
- **Docker Image**: medusa:version
- **Command**: `command here`
- **Result**: ✅ Pass / ❌ Fail / ⚠️ Warning
- **Output**:
  ```
  command output here
  ```
- **Notes**: Additional observations
- **Issues**: Any problems encountered

---

## Success Criteria

- ✅ All basic commands work (version, help, scan)
- ✅ All three Dockerfiles build successfully
- ✅ Volume mounts work correctly (ro and rw)
- ✅ Scans complete without errors
- ✅ Multi-distribution tests pass
- ✅ Docker Compose services work
- ✅ Makefile commands execute correctly
- ✅ Container runs as non-root user
- ✅ Edge cases handled gracefully

---

## Testing Commands Quick Reference

```bash
# Basic setup
sg docker -c "docker build -f Dockerfile.simple -t medusa:latest ."

# Run a test
sg docker -c "docker run --rm medusa:latest --version"

# Clean up
sg docker -c "docker rmi medusa:latest"
make docker-clean

# View logs
sg docker -c "docker logs <container-id>"

# Inspect image
sg docker -c "docker inspect medusa:latest"
sg docker -c "docker history medusa:latest"
```

---

**Testing Started**: 2025-11-15
**Expected Completion**: TBD
**Tester**: Claude Code
**Status**: Ready to begin
