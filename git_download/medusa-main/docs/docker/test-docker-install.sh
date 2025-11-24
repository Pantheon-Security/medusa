#!/bin/bash
# MEDUSA Phase 6 Docker Installation Test
# Tests clean installation in Docker containers

set -e

MEDUSA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="0.7.0.0"

echo "🐍 MEDUSA Phase 6 - Docker Installation Test"
echo "================================================"
echo "Version: $VERSION"
echo "Testing in isolated Docker containers..."
echo ""

# Test function
test_distro() {
    local distro=$1
    local python_pkg=$2

    echo "📦 Testing: $distro"
    echo "----------------------------------------"

    docker run --rm \
        -v "$MEDUSA_DIR/dist:/dist:ro" \
        -w /tmp \
        "$distro" bash -c "
        set -e

        echo '✅ Step 1: Update package manager'
        apt-get update -qq

        echo '✅ Step 2: Install Python'
        apt-get install -y -qq $python_pkg python3-pip > /dev/null 2>&1

        echo '✅ Step 3: Skip pip upgrade (using system pip)'
        # Note: Ubuntu 24.04+ has pip 24.0 via Debian which cannot be upgraded
        # This is fine - pip 24.0 is sufficient for MEDUSA

        echo '✅ Step 4: Install MEDUSA from wheel'
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl --break-system-packages > /dev/null 2>&1 || \
        pip3 install /dist/medusa_security-$VERSION-py3-none-any.whl > /dev/null 2>&1

        echo '✅ Step 5: Verify installation'
        medusa --version || python3 -m medusa --version

        echo '✅ Step 6: Test init command (non-interactive)'
        mkdir -p /tmp/test-project
        cd /tmp/test-project
        echo 'print(\"Hello World\")' > test.py
        echo 'n' | medusa init --ide claude-code --force || echo 'n' | python3 -m medusa init --ide claude-code --force

        echo '✅ Step 7: Verify config created'
        test -f .medusa.yml && echo 'Config file exists'

        echo '✅ Step 8: Check available scanners'
        (medusa install --check || python3 -m medusa install --check) | head -5

        echo '✅ Step 9: Test basic scan (with available tools only)'
        medusa scan . || python3 -m medusa scan .

        echo '✅ SUCCESS: All tests passed on $distro'
    " && echo "✅ $distro: PASSED" || echo "❌ $distro: FAILED"

    echo ""
}

# Test on multiple distributions
echo "Starting tests on 3 distributions..."
echo ""

test_distro "ubuntu:22.04" "python3"
test_distro "ubuntu:24.04" "python3"
test_distro "debian:12" "python3"

echo "================================================"
echo "🎉 Phase 6 Docker Testing Complete!"
echo "================================================"
