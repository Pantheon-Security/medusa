# MEDUSA Docker Makefile
# Convenient commands for building and testing Docker containers

.PHONY: help docker-build docker-build-simple docker-build-test docker-run docker-test docker-scan docker-clean

VERSION := 0.7.0.0

help:
	@echo "🐍 MEDUSA Docker Commands"
	@echo "=========================="
	@echo ""
	@echo "Setup:"
	@echo "  make docker-setup        - Configure Docker access (adds user to docker group)"
	@echo ""
	@echo "Build:"
	@echo "  make docker-build        - Build production image (multi-stage)"
	@echo "  make docker-build-simple - Build simple image (uses pre-built wheel, fastest)"
	@echo "  make docker-build-test   - Build test image (includes dev dependencies)"
	@echo "  make docker-build-all    - Build all images"
	@echo ""
	@echo "Run:"
	@echo "  make docker-run          - Run MEDUSA help"
	@echo "  make docker-scan         - Scan current directory"
	@echo "  make docker-test         - Run tests in container"
	@echo "  make docker-shell        - Interactive shell in container"
	@echo ""
	@echo "Clean:"
	@echo "  make docker-clean        - Remove all MEDUSA Docker images"
	@echo "  make docker-prune        - Clean Docker build cache"
	@echo ""
	@echo "Test Script:"
	@echo "  make test-install        - Run test-docker-install.sh script"
	@echo ""

# Setup Docker access
docker-setup:
	@bash docker-setup.sh

# Build production image (multi-stage)
docker-build:
	docker build -t medusa-security:$(VERSION) -t medusa-security:latest .

# Build simple image (fastest, uses pre-built wheel)
docker-build-simple:
	docker build -f Dockerfile.simple -t medusa-security:simple -t medusa-security:latest .

# Build test image
docker-build-test:
	docker build -f Dockerfile.test -t medusa-test:$(VERSION) -t medusa-test:latest .

# Build all images
docker-build-all: docker-build docker-build-simple docker-build-test

# Run MEDUSA help
docker-run:
	docker run --rm medusa-security:latest --help

# Scan current directory
docker-scan:
	docker run --rm -v $(PWD):/workspace:ro medusa-security:latest scan /workspace

# Run tests
docker-test:
	docker run --rm -v $(PWD):/workspace medusa-test:latest

# Interactive shell
docker-shell:
	docker run --rm -it -v $(PWD):/workspace medusa-security:latest /bin/bash

# Run the installation test script
test-install:
	@bash test-docker-install.sh

# Clean up images
docker-clean:
	docker rmi -f medusa-security:$(VERSION) medusa-security:latest medusa-security:simple || true
	docker rmi -f medusa-test:$(VERSION) medusa-test:latest || true

# Prune Docker build cache
docker-prune:
	docker builder prune -f

# Compose commands
compose-up:
	docker-compose up medusa

compose-dev:
	docker-compose run --rm medusa-dev

compose-test:
	docker-compose up medusa-test

compose-down:
	docker-compose down
