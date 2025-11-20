#!/bin/bash
# Docker Setup Script for MEDUSA
# Run this once to configure Docker access

set -e

echo "🐳 MEDUSA Docker Setup"
echo "====================="
echo ""

# Check if user is in docker group
if groups "$USER" | grep -q '\bdocker\b'; then
    echo "✅ User is already in docker group"
else
    echo "📋 Adding user to docker group..."
    echo "   This requires sudo permission"
    sudo usermod -aG docker "$USER"
    echo "✅ User added to docker group"
    echo ""
    echo "⚠️  IMPORTANT: You must log out and log back in for changes to take effect"
    echo "   Or run: newgrp docker"
fi

echo ""
echo "🔍 Testing Docker access..."
if docker ps > /dev/null 2>&1; then
    echo "✅ Docker is accessible"
else
    echo "⚠️  Docker is not accessible yet"
    echo "   Run: newgrp docker"
    echo "   Or log out and log back in"
fi

echo ""
echo "📦 Available Dockerfiles:"
echo "   - Dockerfile         : Multi-stage production build"
echo "   - Dockerfile.simple  : Fast build using pre-built wheel"
echo "   - Dockerfile.test    : Testing with dev dependencies"
echo ""
echo "🚀 Quick start:"
echo "   docker build -f Dockerfile.simple -t medusa:latest ."
echo "   docker run --rm -v \$(pwd):/workspace medusa:latest scan /workspace"
echo ""
