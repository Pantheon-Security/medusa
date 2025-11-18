#!/bin/bash
set -e

# Test MEDUSA installation across multiple Linux distributions
# This script verifies that the wheel can be installed and run on various distros

echo "🐍 Testing MEDUSA installation across multiple Linux distributions"
echo "=================================================================="

WHEEL_FILE=$(ls dist/*.whl | head -n 1)
if [ -z "$WHEEL_FILE" ]; then
    echo "❌ Error: No wheel file found in dist/"
    exit 1
fi

# Get just the filename (not the path)
WHEEL_FILENAME=$(basename "$WHEEL_FILE")

echo "📦 Using wheel: $WHEEL_FILE"
echo ""

# Test counter
TOTAL=0
PASSED=0
FAILED=0

# Function to test installation on a distro
test_distro() {
    local distro=$1
    local base_image=$2
    local python_pkg=$3
    local pip_pkg=$4

    TOTAL=$((TOTAL + 1))
    echo "Testing $distro..."

    # Create a temporary Dockerfile
    cat > Dockerfile.test <<EOF
FROM $base_image
RUN apt-get update && apt-get install -y $python_pkg $pip_pkg git build-essential python3-dev && rm -rf /var/lib/apt/lists/* || \
    yum install -y $python_pkg $pip_pkg git gcc python3-devel || \
    apk add --no-cache $python_pkg $pip_pkg git gcc python3-dev musl-dev linux-headers
COPY $WHEEL_FILE /tmp/$WHEEL_FILENAME
RUN pip3 install /tmp/$WHEEL_FILENAME || pip install /tmp/$WHEEL_FILENAME
CMD ["medusa", "--version"]
EOF

    # Build and test
    if docker build -f Dockerfile.test -t medusa-test-$distro . > /tmp/test-$distro.log 2>&1; then
        if docker run --rm medusa-test-$distro > /tmp/run-$distro.log 2>&1; then
            echo "  ✅ $distro: PASSED"
            PASSED=$((PASSED + 1))
        else
            echo "  ❌ $distro: FAILED (runtime error)"
            FAILED=$((FAILED + 1))
            cat /tmp/run-$distro.log
        fi
    else
        echo "  ❌ $distro: FAILED (build error)"
        FAILED=$((FAILED + 1))
        tail -20 /tmp/test-$distro.log
    fi

    # Cleanup
    rm -f Dockerfile.test
    docker rmi -f medusa-test-$distro > /dev/null 2>&1 || true
    echo ""
}

# Test Debian-based distributions
echo "📋 Testing Debian-based distributions"
echo "--------------------------------------"
test_distro "debian-12" "debian:12-slim" "python3" "python3-pip"
test_distro "ubuntu-22.04" "ubuntu:22.04" "python3" "python3-pip"
test_distro "ubuntu-24.04" "ubuntu:24.04" "python3" "python3-pip"

# Test Alpine (musl-based)
echo "📋 Testing Alpine Linux (musl)"
echo "-------------------------------"
cat > Dockerfile.test <<EOF
FROM alpine:latest
RUN apk add --no-cache python3 py3-pip git gcc python3-dev musl-dev linux-headers
COPY $WHEEL_FILE /tmp/$WHEEL_FILENAME
RUN pip3 install --break-system-packages /tmp/$WHEEL_FILENAME
CMD ["medusa", "--version"]
EOF

TOTAL=$((TOTAL + 1))
echo "Testing alpine..."
if docker build -f Dockerfile.test -t medusa-test-alpine . > /tmp/test-alpine.log 2>&1; then
    if docker run --rm medusa-test-alpine > /tmp/run-alpine.log 2>&1; then
        echo "  ✅ alpine: PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "  ❌ alpine: FAILED (runtime error)"
        FAILED=$((FAILED + 1))
        cat /tmp/run-alpine.log
    fi
else
    echo "  ❌ alpine: FAILED (build error)"
    FAILED=$((FAILED + 1))
    tail -20 /tmp/test-alpine.log
fi
rm -f Dockerfile.test
docker rmi -f medusa-test-alpine > /dev/null 2>&1 || true
echo ""

# Summary
echo "=================================================================="
echo "📊 Test Results Summary"
echo "=================================================================="
echo "Total distributions tested: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "⚠️  Some tests failed"
    exit 1
fi
