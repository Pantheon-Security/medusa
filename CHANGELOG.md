# Changelog

All notable changes to MEDUSA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2025.3.0.0] - 2025-11-27

### Added
- **IDE Config Backup System**: MEDUSA now backs up IDE configuration files before modifying them
  - New `medusa backup` command with `--list`, `--restore`, `--restore-latest`, `--cleanup` options
  - Backups stored in `~/.medusa/backups/{project}/{timestamp}/`
  - Automatic backup during `medusa init` with IDE integration
  - Dry-run support for restore operations
- **IDEBackupManager**: New `medusa/ide/backup.py` module for backup/restore functionality

### Changed
- All IDE setup functions now accept `backup_manager` parameter and return backed up files list
- `medusa init` displays backup location and restore instructions when files are backed up
- Version scheme changed from `0.x.x` to `YYYY.MINOR.PATCH.BUILD` format

### Fixed
- **IDE Integration Audit (v2025.2.0.21)**: All IDE templates now match vendor specifications
  - Cursor MCP: Removed invalid fields, kept only `command` and `args`
  - Gemini TOML: Rewritten to official `description` + `prompt` format
  - Copilot: Removed hardcoded version and external links
  - CLAUDE.md/GEMINI.md: Simplified to concise bullet points
- **Critical File Overwrite Bug (v2025.2.0.18)**: Fixed IDE files being overwritten without checking existence
- **Cursor MCP Filename (v2025.2.0.19)**: Changed `mcp-config.json` to correct `mcp.json`
- **AGENTS.md Format (v2025.2.0.20)**: Rewritten to meet OpenAI Codex standards

## [0.11.2] - 2025-01-19

### Fixed
- **Windows Tool Reinstall Loop**: Fixed critical bug where tools installed successfully but prompted to reinstall on every scan
- **Tool Installation Cache**: Created `.medusa/installed_tools.json` cache to track installed tools across scans in same terminal session
- Windows PATH refresh issue: Tools installed via winget/chocolatey/npm update registry PATH, but existing PowerShell sessions don't reload PATH automatically
- Scanners now check cache before PATH lookup, preventing false "tool not found" results

### Added
- `medusa/platform/tool_cache.py`: New ToolCache class for tracking tool installations
- Cache integration in BaseScanner to check installed tools before PATH lookup
- Automatic cache marking in CLI after successful tool installations

## [0.11.1] - 2025-01-19

### Fixed
- **Windows UTF-8 Encoding**: Fixed critical Windows bug where report generation failed with `UnicodeEncodeError: 'charmap' codec can't encode character` when writing JSON/HTML/Markdown files containing emojis
- Added explicit `encoding='utf-8'` to all file writes in reporter module

## [0.11.0] - 2025-01-19

### Added
- **Multi-Format Reports**: New `--format` CLI option to export reports in JSON, HTML, or Markdown
  - `medusa scan . --format json` - Machine-readable JSON for CI/CD
  - `medusa scan . --format html` - Beautiful glassmorphism UI
  - `medusa scan . --format markdown` - Documentation-friendly for GitHub
  - `medusa scan . --format all` - Generate all formats simultaneously
- **Markdown Report Generator**: New executive summary report with severity breakdown and CWE links
- **Improved Report Structure**: Standardized findings format across all export types

### Changed
- Default behavior now generates both JSON and HTML reports (previously just JSON)
- Refactored report generation to use reporter module directly instead of subprocess
- Report files now include timestamp in filename for better organization

## [0.10.10] - 2025-01-18

### Fixed
- **ChocolateyInstaller**: Added `shutil.which()` PATH check for faster, more reliable tool detection
- **PipInstaller**: Added `shutil.which()` PATH check to prevent false negatives
- All Windows package managers now use consistent detection pattern

## [0.10.9] - 2025-01-18

### Fixed
- **WingetInstaller**: Fixed tool detection bug where tools were marked as "not installed" even after successful installation
- **NpmInstaller**: Fixed same detection issue for npm-based tools
- Changed `is_installed()` to check PATH first using `shutil.which()`, then fallback to parsing package manager output
- Prevents tools from being reinstalled on every scan

### Changed
- Tool detection now prioritizes PATH checks over subprocess return codes for reliability

## [0.10.8] - 2025-01-18

### Added
- **Scanners Used**: New output line showing which security tools actually ran during the scan
- Improves transparency for users to verify tools are being executed correctly

## [0.10.0] - 2025-01-17

### Added
- **Full Windows Native Support**: Complete auto-installation support for Windows via winget, chocolatey, and npm
- **Windows Package Managers**: Integrated winget and chocolatey installers for seamless Windows experience
- **Node.js Auto-Installation**: Automatic Node.js installation on Windows when npm tools are needed
- **Registry PATH Refresh**: Dynamic PATH updates after package installation on Windows
- **Comprehensive Windows Testing**: Verified all features work on native Windows (not just WSL)

### Changed
- Updated CLI to handle Windows encoding issues (UTF-8 enforcement)
- Improved error messages for Windows users
- Enhanced Windows-specific documentation

### Fixed
- Windows terminal emoji rendering issues
- PATH detection on Windows after tool installation

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
