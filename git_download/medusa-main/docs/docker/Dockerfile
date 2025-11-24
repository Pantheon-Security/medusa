# MEDUSA Security Scanner - Docker Image
# Multi-stage build for optimal image size

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY medusa/ ./medusa/

# Build the wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="Pantheon Security <security@pantheonsecurity.io>"
LABEL description="MEDUSA - The 42-Headed Security Guardian"
LABEL version="0.9.0.0"

WORKDIR /app

# Install runtime dependencies and common security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Copy wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install MEDUSA
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Create non-root user for security
RUN useradd -m -u 1000 medusa && \
    chown -R medusa:medusa /app

USER medusa

# Verify installation
RUN medusa --version

# Set working directory for scans
WORKDIR /workspace

# Default command
ENTRYPOINT ["medusa"]
CMD ["--help"]
