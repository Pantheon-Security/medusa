# Docker Compose V2 - Installed! ✅

## Installation Complete

Docker Compose V2 installed at: `~/.docker/cli-plugins/docker-compose`

**Version**: v2.40.3

## Usage

Use `docker compose` (with space, not hyphen):

```bash
# Config validation
sg docker -c "docker compose config"

# Run services
sg docker -c "docker compose run --rm medusa --version"
sg docker -c "docker compose run --rm medusa scan /workspace"

# Interactive dev
sg docker -c "docker compose run --rm medusa-dev"

# Run tests
sg docker -c "docker compose run --rm medusa-test"

# List services
sg docker -c "docker compose ps"

# Clean up
sg docker -c "docker compose down"
```

## docker-compose.yml Updated

- Removed obsolete `version: '3.8'` line
- Ready to use with Compose V2

## All Set! ✅

Docker + Docker Compose fully working now!
