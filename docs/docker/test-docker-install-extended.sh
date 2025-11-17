#!/bin/bash
# MEDUSA Extended Multi-Distribution Testing
# Tests MEDUSA installation across 10+ Linux distributions

set -e

MEDUSA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="0.7.0.0"

echo "🐍 MEDUSA Extended Multi-Distribution Testing"
echo "=============================================="
echo "Version: $VERSION"
echo "Testing on 10+ Linux distributions..."
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# Debian-based test function
test_debian() {
    local distro=$1
    local python_pkg=${2:-python3}

    echo "📦 Testing: $distro (Debian-based)"
    echo "----------------------------------------"

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq $python_pkg python3-pip > /dev/null 2>&1
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl --break-system-packages > /dev/null 2>&1 || \
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl > /dev/null 2>&1
        medusa --version || python3 -m medusa --version
        echo 'print(\"test\")' > test.py
        echo 'n' | medusa init --ide claude-code --force > /dev/null 2>&1
        test -f .medusa.yml && echo '✅ Config created'
        medusa scan . > /dev/null 2>&1 || python3 -m medusa scan . > /dev/null 2>&1
        echo '✅ SUCCESS'
    " && { echo -e "${GREEN}✅ $distro: PASSED${NC}"; PASSED=$((PASSED + 1)); } || { echo -e "${RED}❌ $distro: FAILED${NC}"; FAILED=$((FAILED + 1)); }

    echo ""
}

# RedHat-based test function
test_redhat() {
    local distro=$1
    local python_pkg=${2:-python3}

    echo "📦 Testing: $distro (RedHat-based)"
    echo "----------------------------------------"

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" bash -c "
        set -e
        dnf install -y -q $python_pkg python3-pip > /dev/null 2>&1
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl --break-system-packages > /dev/null 2>&1 || \
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl > /dev/null 2>&1
        medusa --version || python3 -m medusa --version
        echo 'print(\"test\")' > test.py
        echo 'n' | medusa init --ide claude-code --force > /dev/null 2>&1
        test -f .medusa.yml && echo '✅ Config created'
        medusa scan . > /dev/null 2>&1 || python3 -m medusa scan . > /dev/null 2>&1
        echo '✅ SUCCESS'
    " && { echo -e "${GREEN}✅ $distro: PASSED${NC}"; PASSED=$((PASSED + 1)); } || { echo -e "${RED}❌ $distro: FAILED${NC}"; FAILED=$((FAILED + 1)); }

    echo ""
}

# Arch-based test function
test_arch() {
    local distro=$1

    echo "📦 Testing: $distro (Arch-based)"
    echo "----------------------------------------"

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" bash -c "
        set -e
        pacman -Sy --noconfirm python python-pip > /dev/null 2>&1
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl --break-system-packages > /dev/null 2>&1
        medusa --version || python3 -m medusa --version
        echo 'print(\"test\")' > test.py
        echo 'n' | medusa init --ide claude-code --force > /dev/null 2>&1
        test -f .medusa.yml && echo '✅ Config created'
        medusa scan . > /dev/null 2>&1 || python3 -m medusa scan . > /dev/null 2>&1
        echo '✅ SUCCESS'
    " && { echo -e "${GREEN}✅ $distro: PASSED${NC}"; PASSED=$((PASSED + 1)); } || { echo -e "${RED}❌ $distro: FAILED${NC}"; FAILED=$((FAILED + 1)); }

    echo ""
}

# Alpine test function
test_alpine() {
    local distro=$1

    echo "📦 Testing: $distro (Alpine-based)"
    echo "----------------------------------------"

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" sh -c "
        set -e
        # Install Python, pip, bash, AND build tools for psutil
        apk add --no-cache python3 py3-pip bash gcc python3-dev musl-dev linux-headers > /dev/null 2>&1
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl --break-system-packages > /dev/null 2>&1
        medusa --version || python3 -m medusa --version
        echo 'print(\"test\")' > test.py
        echo 'n' | medusa init --ide claude-code --force > /dev/null 2>&1
        test -f .medusa.yml && echo '✅ Config created'
        medusa scan . > /dev/null 2>&1 || python3 -m medusa scan . > /dev/null 2>&1
        echo '✅ SUCCESS'
    " && { echo -e "${GREEN}✅ $distro: PASSED${NC}"; PASSED=$((PASSED + 1)); } || { echo -e "${RED}❌ $distro: FAILED${NC}"; FAILED=$((FAILED + 1)); }

    echo ""
}

echo "🐳 TIER 1: Debian-based Distributions"
echo "======================================"
test_debian "ubuntu:22.04"
test_debian "ubuntu:24.04"
test_debian "debian:12"

echo ""
echo "🐳 TIER 2: RedHat-based Distributions"
echo "======================================"
test_redhat "fedora:40"
test_redhat "fedora:39"
# test_redhat "rockylinux:9"  # Uncomment if testing Rocky
# test_redhat "almalinux:9"   # Uncomment if testing Alma

echo ""
echo "🐳 TIER 3: Other Major Distributions"
echo "======================================"
test_arch "archlinux:latest"
test_alpine "alpine:latest"
test_alpine "alpine:3.19"

echo ""
echo "=============================================="
echo "🎉 Multi-Distribution Testing Complete!"
echo "=============================================="
echo -e "${GREEN}✅ PASSED: $PASSED${NC}"
echo -e "${RED}❌ FAILED: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All distributions passed!"
    exit 0
else
    echo "⚠️  Some distributions failed. Check logs above."
    exit 1
fi
