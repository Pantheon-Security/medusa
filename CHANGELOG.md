# Changelog

All notable changes to MEDUSA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2026.5.5] - 2026-04-18

### Security

Red-team review (2026-04-17) found 10 hardening opportunities across the
scanner pipeline. This release ships 8 of them; two findings (license key
crypto, IDE symlink race) are deferred to separate sprints. No CVEs are
disclosed against v2026.5.4 — these are defense-in-depth improvements.

- **C-1: Scanner argv injection defenses.** A malicious repo containing a
  file literally named `--config=https://evil.tld/rce.yaml` would previously
  have had the filename re-parsed as an option by semgrep and trivy, causing
  them to fetch attacker-controlled rule YAML from the network. Two fixes:
  (a) insert `--` separator before the trailing path positional in semgrep,
  trivy-config, and trivy-fs cmd lists; (b) new `BaseScanner._reject_if_dash_prefixed()`
  helper that short-circuits dash-prefixed basenames without invoking any
  external tool. GitLeaks uses `--source <value>` form and is safe-by-construction;
  the rejection helper still applies to it for defense-in-depth.

- **H-1 + M-2: Git URL SSRF defense.** `medusa scan --git <URL>` previously
  accepted any http(s)/ssh URL with no validation, enabling SSRF against
  loopback, RFC1918, link-local (AWS IMDS at 169.254.169.254), and internal
  DNS. Now validated in two layers: (a) default hostname allowlist of
  github.com, gitlab.com, bitbucket.org, codeberg.org plus their subdomains
  (exact or subdomain match; suffix attacks like `github.com.evil.tld`
  rejected); (b) DNS rebinding defense — every resolved IP is checked via
  `ipaddress.ip_address().is_private/is_loopback/is_link_local/is_reserved/is_multicast`
  and the URL is rejected if ANY resolved IP fails. New `--allow-any-host`
  flag on `medusa scan` opts out of the hostname allowlist; the private-IP
  check still applies regardless.

- **H-2a: File cache HMAC integrity.** `~/.medusa/cache/file_cache.json`
  previously loaded without integrity check, so an attacker with write
  access to a dev workstation or CI runner could forge cache entries
  marking vulnerable files clean, silently suppressing scan findings.
  Cache is now wrapped in `{"hmac": <hex>, "entries": {...}}` with a
  machine-local HMAC-SHA256 key at `~/.medusa/cache/.hmac_key` (mode 0600,
  generated on first run). Tampered, missing-HMAC (v5.4 upgrade), or
  corrupted caches are silently discarded and rebuilt from a fresh pass.
  Key rotation is `rm ~/.medusa/cache/.hmac_key`.

- **H-2b: Cached findings included in reports.** The report aggregation
  loop previously had `if not result.cached:` which silently dropped
  cached findings from the report entirely. A user hitting cache on a
  vulnerable file saw a clean report. Removed. Finding counts are now
  accurate on warm caches (total_lines_scanned under-counts but that's a
  cosmetic UX number).

- **M-1: Markdown report escape.** Source code containing triple-backticks
  (```) previously broke out of the code fence in generated markdown
  reports, allowing stored XSS / phishing payload delivery via GitHub /
  GitLab / any markdown renderer. New `_md_code_fence()` uses a fence one
  backtick longer than the longest run of consecutive backticks in the
  content, and `_md_sanitize_inline()` strips backticks/newlines from
  filenames before interpolation into inline spans.

- **L-1 + M-3: Dead HTML builder deletion.** Removed `_build_modern_findings_html`
  and `_build_findings_html` from `reporter.py` — both were dead code
  (unreachable from any live call path) AND both interpolated severity
  fields into `style="..."` attributes without html-escape. Deletion is
  the fix.

- **L-3: History file resilience.** `scan_history.json` load was previously
  unguarded; a corrupted file or injected JSON (from a world-writable
  reports dir) crashed the scan. Now wrapped in try/except with schema
  validation (list of dicts required), silent reset on malformed input.

### Testing

- New `tests/test_security_hardening.py` with 55 test cases covering
  every finding above: argv injection mocks, basename rejection, SSRF
  allowlist + DNS-rebind + escape-hatch, cache HMAC tamper + upgrade +
  rotation, markdown fence breakout payloads, history file corruption.
- Full suite: 378 pass + 55 new security tests, 11 pre-existing failures
  (test_simple_installer, test_git_scan, test_fp_regression) confirmed
  independent of this release.

### Deferred (tracked for future sprints)

- **C-2: License HMAC forgery.** `medusa/core/licensing.py` uses a keyless
  SHA-256 truncated to 16 hex chars as a "signature" — anyone can forge
  Professional or Enterprise license keys in three lines of Python.
  Requires Ed25519 migration + license server coordination. Tracking
  separately.
- **L-2: IDE setup symlink race.** `medusa/ide/claude_code.py` writes
  through symlinked `.claude/` paths. Local attacker only; defer to next
  minor release.

## [2026.5.4] - 2026-04-16

### Changed

- **FP Patterns Migrated to YAML** - Moved 583 false positive patterns from `medusa/core/fp_patterns_db.py` (6,746 LOC Python) to per-scanner YAML files in `medusa/core/fp_patterns/` (27 files, one per scanner plus `_universal.yaml`).
  - New `load_known_fp_patterns()` loader in `fp_filter.py` with strict schema validation (`FPPatternSchemaError` on unknown keys, invalid `FPReason` enum values, or missing required fields).
  - Preserves deterministic load order: ASCII-sorted filenames, source order within each file.
  - Zero behavior change: `FalsePositiveFilter._FP_BY_SCANNER` bucket dict is byte-identical, regression benchmark findings unchanged (7 issues, 291 FPs filtered, 97.7% reduction).
- **Documentation** - Added `RULE_PROMOTION.md` documenting the repeatable workflow for promoting rules from `medusa-rules` → production, with smoke testing and benchmark validation against `medusa-test-targets/`.

### Removed

- **`medusa/core/fp_patterns_db.py`** - 6,746 LOC of hardcoded Python FP patterns. Data now lives in YAML; editing patterns no longer requires a code change.

### Net Impact

- **−2,815 LOC** repo-wide (−6,746 Python, +3,505 YAML, +141 loader)
- **FP patterns editable by non-Python contributors** via YAML
- **Pattern count now trivially countable** (`yq`, `grep`, etc.) — previously required AST parsing

## [2026.3.0.0] - 2026-02-16

### Fixed

- **Scanner Attribution Bug** - Parallel scan findings were all attributed to the first scanner that processed each file. Fixed per-issue `_scanner_name` tracking in `parallel.py` so findings correctly report their originating scanner.
- **SteganographyScanner FPs** - Added compound gate requiring BOTH input handler indicators AND AI keyword indicators. Tightened role marker pattern to require line-start context. Eliminates FPs on files that merely mention AI terminology.
- **LLMGuardScanner FPs** - Toxicity check (LLG004) now requires actual LLM API call patterns (e.g., `chat.completions`, `messages.create`) before flagging missing toxicity checks. Output variable patterns narrowed to LLM-specific names.
- **MCPServerScanner FPs** - Tightened 3 patterns: time-based detection requires schema/tool context, `mcp-remote` requires dependency/config context, tool poisoning patterns require specific phrasing.
- **RAGSecurityScanner FPs** - HTTP source pattern narrowed from generic `source|url|path` to RAG-specific variable names (`source_url`, `document_path`, etc.). RAG poisoning pattern changed to space-only separator (won't match `rag_poisoning` variable names).
- **MultiAgentScanner FPs** - Added compound gate requiring BOTH multi-agent keywords AND actual framework imports/API calls (e.g., `from crewai import`, `Agent(`, `Crew(`). Prevents FPs on files that mention "crewai" or "agent-to-agent" in string literals or classification data.
- **Tool Poisoning Rule FPs** - Tightened patterns in `tool_attacks.yaml` and `mcp_vulnerabilities.yaml` to require specific context rather than broad substring matches.

### Changed

- **FP Filter Expanded** - 430 → 508 patterns (96.8% FP reduction rate on real-world projects)
  - 78 new patterns from scanner precision tuning and benchmark validation
- **Compound Scanner Gates** - SteganographyScanner, LLMGuardScanner, and MultiAgentScanner now use compound gates that require both keyword presence AND framework-specific imports/API calls
- **Self-Scan Baseline** - 115 → 114 findings (YAMLScanner removal)

### Removed

- **YAMLScanner (yamllint)** - Removed yamllint integration. It produced only style lint (indentation, missing `---`), not security findings. YAML security is fully covered by Trivy, Semgrep, and MEDUSA's own built-in rules. Scanner types reduced from 42 to 41.

## [2026.2.4] - 2026-02-15

### Performance

- **52% Scan Time Reduction** - Comprehensive performance overhaul on MEDUSA's own codebase (17.1s → 8.2s)
- **12.7% Faster on Large Projects** - Real-world benchmark on 4,124-file project (13,711s → 11,976s)
- **Single-Pass File Discovery** - Replaced 57 separate `rglob()` calls with one `os.walk()` traversal, pre-compiling exclusion patterns to a single regex
- **Scanner Pre-Mapping Cache** - First 8KB of each file read once and shared across all scanners, eliminating redundant file I/O during confidence scoring
- **FP Filter Pre-Compilation** - 7 hot-path regex patterns compiled at class level instead of per-finding
- **OWASP Scanner Pattern Hoisting** - 10 `re.compile()` calls moved from per-line loop to class-level constants
- **Live Table Responsiveness** - Capped multiprocessing pool chunksize at 8 to prevent batched results freezing the progress display on large projects

### Changed

- **Structural Refactoring** - Major code quality improvements:
  - `mcp_config_scanner.py`: Split 335-line god method (CC=98) into 7 focused sub-methods
  - `cli.py`: Split `init()` (CC=91) into 4 functions, replaced 5 IDE copy-paste branches with data-driven loop
  - `fp_filter.py`: Extracted 4,684 lines of pattern data to `fp_patterns_db.py`, reducing filter logic to 675 lines
  - `parallel.py`: Removed 189 lines of dead code, consolidated stats accumulation (5x dedup)
  - `reporter.py`: Removed dead code (`parse_bandit_json`, legacy `main()`), pre-compiled SARIF regex patterns
- **FP Filter Expanded** - 425 → 430 patterns (93.9% FP reduction rate, up from 93.3%)
  - 5 new patterns from OpenClaw benchmark: chat extension toxicity checks, import-line LLM API calls, Graph API type definitions, documentation placeholder IDs, system prompt security boundaries
- **Config Dataclass** - Added missing `ide_openai_enabled` and `ide_copilot_enabled` fields (P0 bug fix)

### Fixed

- **Live Progress Table Freezing** - On projects with 4,000+ files, the progress table appeared frozen because multiprocessing pool chunksize grew to 179. Now capped at 8 for smooth updates.
- **Config P0 Bug** - `MedusaConfig.from_dict()` crashed on configs with OpenAI Codex or GitHub Copilot IDE settings
- **Dead Code Removal** - Removed unused `_scan_with_bandit()`, `_scan_with_medusa()`, legacy `main()` functions, and unreachable imports across 6 modules

## [2026.2.1] - 2026-02-11

### Added
- **React2Shell CVE Detection** - Merged React2ShellScanner into CriticalCVEScanner with 10 new CVE entries (CCVE-124 to CCVE-133) covering CVE-2025-55182 (React Server Components RCE) and CVE-2025-66478 (Next.js RCE) across all affected version ranges
- **pnpm-lock.yaml Support** - CriticalCVEScanner now parses pnpm lockfiles for vulnerability detection (scoped package support included)
- **CVE Database** - Increased from 123 to 133 curated critical CVEs
- **FP Filter Patterns** - Expanded from 255 to 395 false positive patterns across 17 benchmark repos

### Changed
- **Scanner Count** - Reduced from 77 to 76 (React2ShellScanner merged into CriticalCVEScanner)
- **Config File Visibility** - Default config is now `medusa.yml` (visible on macOS) with `.medusa.yml` as legacy fallback
- **Platform-Aware Install Hints** - All 34 external linter scanners now use dynamic `get_install_hint()` with OS-specific commands (Linux/macOS/Windows) and PEP 668 pipx detection
- **Progress Table Rendering** - Fixed Rich Live table printing dozens of times on macOS by using stderr and TTY detection

### Fixed
- **FP Filter Test File Regex** - Fixed `test[s]?[/_]` matching `medusa-test/` directory path, suppressing all findings in test scan directories
- **Cache Error Noise** - Silenced `[Errno 2]` cache update errors when directories are deleted during scan
- **Version Strings** - Updated all hardcoded `v2026.2` references to `v2026.2.1` across CLI, README, and docs

### Removed
- **React2ShellScanner** - Standalone scanner deleted; all React/Next.js CVE detection now handled by CriticalCVEScanner via the curated YAML database

## [2026.2.0] - 2026-02-09

### Added
- **PromptInjectionCodeScanner** (PIC001-PIC008) - Detects unsanitized user input flowing into LLM API calls in Python source code: f-string injection, ChatML token injection, role manipulation, unsafe template rendering, tainted prompt variables
- **DatasetInjectionScanner** (DSI001-DSI008) - Detects prompt injection payloads hidden in CSV, JSON, and JSONL data files used for RAG ingestion and model training
- **Agent Protocol Security Rules** - 91 new rules for emerging agent protocols:
  - **UCP Vulnerabilities** (33 rules) - Universal Commerce Protocol: discovery endpoints, agent identity, signing keys, JSON-LD context, product data injection, fraud detection
  - **AP2 Vulnerabilities** (20 rules) - Agent Payment Protocol: credential provider trust, payment token security, transaction integrity, PCI-DSS compliance
  - **ACP Vulnerabilities** (38 rules) - Agent Communication Protocol: MCP/A2A/ACP security, prompt injection, supply chain, backdoor detection, cross-tool attacks, DoS, multimodal attacks
- **CVEMiner Critical CVEs** - 123 critical CVE entries covering PyPI, npm, Maven, Cargo, Go, Gem ecosystems including LangChain, LlamaIndex, PyTorch, MCP, Log4Shell, Spring4Shell, XZ Utils
- **Pantheon Security Logo** - HTML reports now feature the official Pantheon Security branding
- Scanner count increased from 75 to 77

### Changed
- **Simplified Installation**: MEDUSA now only manages `modelscan` via `medusa install --ai-tools`
- **AI Rules First**: 3,200+ AI security detection patterns work out of the box
- **External Linters Optional**: Auto-detected if present, not installed by MEDUSA
- **CLI Cleanup**: Removed 1,500+ lines of legacy installer code

### Fixed
- **CLI Skip Display** - "Skipped (not needed): 34" now shows which languages are absent (e.g., "34 scanners skipped (no Go, Ruby, PHP, Rust files found)")
- **HTML Linter Banner** - "36 External Linters Not Installed" now only shows linters relevant to detected project languages
- **Progress Table** - Fixed scanners showing "Active" at 91-93% while overall scan shows 100% complete
- **Markdown Report Version** - Fixed `{__version__}` rendering literally instead of actual version number
- **Docker Compose Scanner** - Fixed NameError crash on YAML parse failures (`yaml.YAMLError` referenced without import)
- **Bare Exception Handling** - Replaced bare `except:` with `except Exception:` in parallel.py and cli.py
- **Packaging** - Fixed setuptools including unintended files in wheel distribution

### Deprecated
- `medusa install --all` - Use `--ai-tools` instead
- `medusa uninstall <tool>` for non-modelscan tools - Use your package manager

### Removed
- Legacy PowerShell installation scripts
- Complex multi-package-manager tool installation
- 60-tool installer management

## [2025.9.1.1] - 2026-01-15

### Added

- **10 Content-Based FP Detection Rules** - New patterns to reduce false positives on non-secret content:
  - `masked_asterisks` - 10+ asterisks indicate redacted values (95% confidence)
  - `crlf_line_ending` - Windows line endings / ShellCheck SC1017 (90%)
  - `html_encoded_mask` - HTML-encoded masked values in reports (92%)
  - `sentry_dsn` - Sentry DSNs are public by design (90%)
  - `example_marker` - Values marked as example/sample/test/mock (92%)
  - `placeholder_text` - YOUR_/REPLACE_/CHANGEME/TODO:/FIXME: markers (95%)
  - `fedauth_cookie` - Session cookies in forensic captures (85%)
  - `env_var_bash` - ${VAR} references not hardcoded values (92%)
  - `env_var_windows` - %VAR% references (92%)
  - `redacted_marker` - REDACTED/MASKED/[REMOVED]/[HIDDEN]/XXXXXXX (95%)

### Fixed

- **Expanded Scan Exclusions** - Project-specific exclusions to reduce FPs when scanning MEDUSA itself:
  - Scan outputs: `.medusa/`, `medusa_output/`
  - Research extractions: `docs/research/nblm/`, `docs/codex/`, `docs/falsepositives/`, `docs/docker/`
  - Test folders: `tests/`, `test-install/`, `**/fixtures/`, `**/mocks/`
  - IDE configs: `.claude/`, `.idea/`, `.vscode/`, `.cursor/`
  - Linter configs: `.hadolint.yaml`, `.semgrep.*`, `.gitleaks.toml`, `.eslintrc*`, etc.
  - Total FP patterns: 44 → 54

## [2025.9.1.0] - 2026-01-11

### Added

- **Multi-Scanner Architecture** - Improved parallel scanning with better FP filtering
- **Enhanced FP Filter** - Additional patterns for Go, Docker, and Trivy false positives

## [2025.9.0.14] - 2026-01-10

### Fixed

- **pyproject.toml** - Fixed corrupted `tool.ruff` and `tool.mypy` settings that had package version instead of Python version

## [2025.9.0.13] - 2026-01-10

### Added

- **Template File Scanning** - Added .template, .tpl, .example, .sample, .dist extensions to file discovery
- **Config File Scanning** - Added .ini, .cfg, .conf, .toml extensions for secret detection

## [2025.9.0.12] - 2026-01-10

### Fixed

- **CRITICAL: Scanner Cache Bug** - Fixed `_find_tool()` returning dummy path `<cached:toolname>` which broke ALL 40+ scanners using external tools
- **Gitleaks Output** - Fixed `/dev/stdout` not working in subprocess mode by using temp file

## [2025.9.0.11] - 2026-01-09

### Added

- **Enhanced FP Filter Patterns** - Additional false positive detection patterns

## [2025.9.0.10] - 2026-01-09

### Fixed

- **Codex/Sandbox Compatibility** - Multiprocessing now gracefully falls back to sequential scanning when semaphore creation fails (affects Codex CLI, Docker containers, restricted sandboxes)
- **File Path Validation** - `medusa scan <file>` now shows friendly error instead of crashing with NotADirectoryError
- **Version Reporting** - JSON and Markdown reports now show correct version instead of hardcoded 0.11.1

### Changed

- Added `.gitignore` entries for 2026 development files

## [2025.9.0.9] - 2026-01-05

### Fixed

- **README Scanner Count** - Updated all references from 64 to 73 scanners
- **AI Rules Count** - Updated from 50+ to 180+ rules throughout documentation
- **pyproject.toml** - Fixed corrupted tool.ruff and tool.mypy Python version settings

## [2025.9.0.8] - 2026-01-05

### Changed

- **PyPI Metadata Update** - Updated package description and keywords
  - New description: "AI-first security scanner with 73+ analyzers, intelligent false positive reduction, and 180+ AI agent security rules"
  - Added AI-focused keywords: `ai-security`, `llm-security`, `mcp`, `agent-security`, `prompt-injection`, `rag-security`, `false-positive-reduction`

## [2025.9.0.7] - 2026-01-05

### Fixed

- **False Positive Filter Improvements** - 15 new Go-specific FP patterns
  - MD5/SHA1 for cache keys, directory sharding, temp file naming (non-crypto)
  - MD5 for duplicate detection with partial file sampling
  - `math/rand` in mock/fake/stub files and `Insecure*` named functions
  - `:latest` tag in test/CI Dockerfiles (Playwright, dev, e2e)
  - MD5/SHA1 when SHA256/SHA512 also offered (user-selectable algorithms)
  - New FP reasons: `CACHE_KEY`, `DUPLICATE_DETECTION`, `INTENTIONAL_WEAK`, `MOCK_FILE`, `TEST_DOCKERFILE`
  - Mock files get higher confidence (0.88) vs general test files (0.70)
  - Added Go patterns: `_test.go`, `testdata/`, `mock.go`, `fake.go`, `stub.go`

## [2025.9.0.1] - 2025-12-15

### Added

- **GitLeaksScanner** - Secret detection using GitLeaks v8.30.0
  - API keys (AWS, GCP, Azure, GitHub, etc.)
  - Private keys (SSH, PGP, RSA)
  - Database credentials and OAuth tokens
  - 100+ secret patterns with CWE-798 mapping

- **SemgrepScanner** - Advanced SAST using Semgrep v1.145.0
  - Uses `p/security-audit` ruleset for comprehensive coverage
  - SQL injection, XSS, command injection detection
  - OWASP severity boosting for top categories
  - CWE extraction from findings

- **TrivyScanner** - Container/IaC vulnerability scanning using Trivy v0.68.1
  - Dockerfile misconfigurations
  - Kubernetes manifest issues
  - Terraform/CloudFormation security
  - Dependency vulnerabilities (npm, pip, go, etc.)
  - Secret detection

### Changed

- Scanner count increased from 70 to 73

## [2025.9.0.0] - 2025-12-15

### Added - Major Release: 6 New Security Scanners

**70 Total Scanners** - MEDUSA now includes 70 independent security scanner implementations.

#### New Scanners

- **PostQuantumScanner** (PQC001-PQC010) - Quantum-vulnerable cryptography detection
  - RSA, ECDSA, ECDH, Diffie-Hellman flagged as quantum-vulnerable
  - Classical key sizes detected (RSA-2048, P-256 curves)
  - Crypto-agility anti-patterns identified
  - Recommends NIST FIPS 203/204/205 standards (ML-KEM, ML-DSA, SLH-DSA)

- **SteganographyScanner** (STG001-STG010) - Hidden payloads in multimodal AI
  - Zero-width Unicode characters (`\u200b`, `\u200c`, `\u200d`, `\ufeff`)
  - Control token injection (`[INST]`, `<|im_start|>`, `Human:`, `Assistant:`)
  - Homoglyph attacks (Cyrillic/Greek lookalikes)
  - LSB steganography patterns
  - Base64 payloads in prompts

- **HyperparameterScanner** (HPT001-HPT010) - ML training sabotage detection
  - Extreme learning rates (>=1.0 or <=1e-7)
  - Untrusted training configs from remote URLs
  - Disabled regularization/early stopping
  - Suspicious weight initialization

- **PluginSecurityScanner** (PLG001-PLG010) - Cross-Plugin Request Forgery (CPRF)
  - Cross-plugin data access vulnerabilities
  - Chat history exposure to plugins
  - Plugin command injection
  - Missing plugin authentication

- **ExcessiveAgencyScanner** (EXA001-EXA010) - Over-permissioned AI agents
  - Unrestricted tool access (`tools: "*"`)
  - Missing `before_tool_callback` validation
  - Unbounded action loops
  - Disabled human-in-the-loop controls
  - Recursive agent calls without depth limits

- **DockerMCPScanner** (DKR001-DKR010) - Container security for MCP servers
  - Root user detection
  - Unpinned base images
  - Exposed ports and volumes
  - Missing security options

### Enhanced

- **OWASPLLMScanner** - Added CVE-2024-5184, prompt obfuscation patterns
- **ModelAttackScanner** - Added CVE-2019-20634, CVE-2023-4969, GPU attacks
- **MCPConfigScanner** - Enhanced OAuth spec detection, new MCP patterns
- **MCPServerScanner** - Added PowerShell injection, more tool poisoning patterns
- **AgentMemoryScanner** - Memory poisoning, vector injection, cross-session attacks
- **MultiAgentScanner** - Prompt infection, LLM tagging, consensus bypass
- **LLMOpsScanner** - Ray/Shadow Ray CVEs, LoRA adapter security, GPU memory leaks

### Changed

- AI Security rule count increased from 150+ to 180+
- Scanner count increased from 64 to 70

## [2025.8.5.12] - 2025-12-11

### Fixed
- **Critical: Zero False Positives from Dependencies** - Virtual environments and pip packages are now automatically excluded
  - Added 50+ default exclusion patterns for all package managers (npm, pip, cargo, go, ruby, etc.)
  - Config now **merges** user paths with mandatory exclusions instead of replacing them
  - Mandatory exclusions: `site-packages/`, `dist-packages/`, `node_modules/`, `lib/python*/`, `__pycache__/`, `.git/`
- **Auto-Detect Virtual Environments** - Automatically finds and excludes venvs via `pyvenv.cfg` marker
- **Bare Exception Handling** - Fixed 11 bare `except:` clauses in `macos.py` with specific exception types
- **React2Shell Scanner** - Fixed exception handling with specific types (`OSError`, `IOError`, `UnicodeDecodeError`)
- **YAML Example Files** - Added document start headers (`---`) to example CI/CD files

### Changed
- **Improved Exclusion Matching** - Pattern matching now checks if exclusion pattern appears anywhere in full path
- **Wildcard Pattern Support** - Patterns like `*-env/` now properly match `medusa-env/`, `python-env/`, etc.

### Updated
- semgrep: 1.144.0 → 1.145.0
- trivy: 0.67.2 → 0.68.1
- ruff: 0.14.5 → 0.14.8
- black: 25.11.0 → 25.12.0
- mypy: 1.18.2 → 1.19.0
- pytest: 9.0.1 → 9.0.2
- coverage: 7.11.3 → 7.13.0
- beautifulsoup4: 4.14.2 → 4.14.3
- rpds-py: 0.29.0 → 0.30.0

## [2025.8.5.11] - 2025-12-10

### Added
- **macOS Helpful Hints**: When security tools fail to install on macOS, MEDUSA now displays helpful troubleshooting hints
  - `swiftlint`: Suggests Xcode CLI tools setup
  - `perlcritic`: Suggests C compiler installation
  - `codenarc`: Suggests SDKMAN installation steps
- New `INSTALL_HINTS` dict and `get_install_hint()` method in `HomebrewInstaller`

### Fixed
- **Scanner Regex Performance**: Fixed 21 regex patterns across 5 AI security scanners to reduce false positives
  - `ai_context_scanner.py`: 8 pattern fixes (bounded quantifiers, word boundaries)
  - `tool_callback_scanner.py`: 3 pattern fixes (OR grouping, bounded patterns)
  - `owasp_llm_scanner.py`: 4 pattern fixes
  - `prompt_leakage_scanner.py`: 3 pattern fixes
  - `rag_security_scanner.py`: 3 pattern fixes
- **MCP Server Scanner**: Fixed false positive for CVE-2025-6514 detection
- Greedy `.*` patterns replaced with bounded `{0,N}` quantifiers to prevent matching across entire files
- Word boundaries `\b` added to prevent partial word matches
- OR grouping fixes: `a|b.*c` corrected to `(a|b).*c` for proper precedence

## [2025.8.5.10] - 2025-12-10

### Fixed
- **macOS RubyGem Detection**: Fixed rubocop incorrectly showing "failed" when gem install actually succeeded
  - Gem returns exit code 0 with PATH warning, which is not a failure
  - Now correctly reports "✅ Installed via gem (add gem bin to PATH)"

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
