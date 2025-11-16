# Changelog

All notable changes to MEDUSA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Tool version management system with `tool-versions.lock`
- Script to capture latest versions from PyPI, npm, GitHub
- Integrated release script combining MEDUSA + tool version bumps

## [0.9.1.0] - 2024-11-16

### Changed
- **Rebranded to Pantheon Security**
- Updated all URLs to `pantheonsecurity.io`
- Updated author/maintainer to "Pantheon Security"
- Updated Docker labels with new branding
- Updated email contact to `security@pantheonsecurity.io`

### Added
- SBOM (Software Bill of Materials) for transparency
- SECURITY.md with vulnerability disclosure policy
- CODE_OF_CONDUCT.md based on Contributor Covenant 2.1
- Tool version lock file with 36 pinned tool versions

### Fixed
- Docker build compatibility across platforms

## [0.9.0.0] - 2024-11-15

### Added
- Multi-IDE integration support
  - Claude Code: `.claude/` directory with agents and commands
  - Gemini CLI: `.gemini/commands/*.toml` files
  - OpenAI Codex: `AGENTS.md` context file
  - GitHub Copilot: `.github/copilot-instructions.md`
  - Cursor: `.cursor/mcp-config.json`
- Smart installation with pre-scan file detection
- Version bump automation script

### Changed
- Enhanced CLI with `--ide` flag for `init` command
- Improved documentation in README

## [0.8.0.0] - 2024-11-14

### Added
- Cross-platform testing (Ubuntu, Windows, macOS)
- Docker support with multi-stage builds
- PyPI package distribution

### Changed
- Improved scanner detection and installation
- Enhanced error handling and logging

### Fixed
- Windows Unicode compatibility issues
- macOS installation paths

## [0.7.0.0] - 2024-11-13

### Added
- Initial public release
- Support for 42 programming languages
- Parallel scanning with configurable workers
- HTML and JSON report generation
- Caching for faster repeat scans

---

## Version History Legend

- **[Unreleased]**: Changes in development
- **[X.X.X.X]**: Released versions
- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Vulnerability fixes
