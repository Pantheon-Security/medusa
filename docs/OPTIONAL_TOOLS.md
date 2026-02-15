# Optional Security Tools Guide

MEDUSA v2026.2 works out of the box with **3,000+ AI security rules**. External linters are **optional** - they enhance coverage but aren't required.

> **Note:** MEDUSA detects and uses these tools automatically if installed. We don't install or manage them - please refer to each vendor's official documentation for installation and support.

```bash
medusa install --check    # See what's installed and available
```

---

## All Supported Tools (41)

### Security Scanners

| Tool | Purpose | Official Docs |
|------|---------|---------------|
| [semgrep](https://semgrep.dev/docs/) | Multi-language SAST | https://semgrep.dev/docs/ |
| [trivy](https://trivy.dev/) | Container/IaC scanner | https://trivy.dev/ |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets detection | https://github.com/gitleaks/gitleaks |
| [modelscan](https://github.com/protectai/modelscan) | ML model security | https://github.com/protectai/modelscan |
| [garak](https://docs.garak.ai/garak) | LLM vulnerability scanner | https://docs.garak.ai/garak |

### Language Linters

| Tool | Language | Official Docs |
|------|----------|---------------|
| [shellcheck](https://www.shellcheck.net/) | Bash/Shell | https://www.shellcheck.net/ |
| [eslint](https://eslint.org/docs/latest/) | JavaScript | https://eslint.org/docs/latest/ |
| [tsc](https://www.typescriptlang.org/) | TypeScript | https://www.typescriptlang.org/ |
| [cppcheck](https://cppcheck.sourceforge.io/) | C/C++ | https://cppcheck.sourceforge.io/ |
| [checkstyle](https://checkstyle.sourceforge.io/) | Java | https://checkstyle.sourceforge.io/ |
| [ktlint](https://pinterest.github.io/ktlint/) | Kotlin | https://pinterest.github.io/ktlint/ |
| [rubocop](https://docs.rubocop.org/rubocop/) | Ruby | https://docs.rubocop.org/rubocop/ |
| [phpstan](https://phpstan.org/) | PHP | https://phpstan.org/ |
| [clippy](https://doc.rust-lang.org/clippy/) | Rust (via cargo) | https://doc.rust-lang.org/clippy/ |
| [swiftlint](https://github.com/realm/SwiftLint) | Swift | https://github.com/realm/SwiftLint |
| [dart](https://dart.dev/tools/dart-analyze) | Dart | https://dart.dev/tools/dart-analyze |
| [scalastyle](https://www.scalastyle.org/) | Scala | https://www.scalastyle.org/ |
| [hlint](https://github.com/ndmitchell/hlint) | Haskell | https://github.com/ndmitchell/hlint |
| [perlcritic](https://metacpan.org/pod/Perl::Critic) | Perl | https://metacpan.org/pod/Perl::Critic |
| [luacheck](https://github.com/lunarmodules/luacheck) | Lua | https://github.com/lunarmodules/luacheck |
| [zig](https://ziglang.org/) | Zig | https://ziglang.org/ |
| [Rscript](https://lintr.r-lib.org/) | R (lintr) | https://lintr.r-lib.org/ |
| [mix](https://hexdocs.pm/credo/) | Elixir (credo) | https://hexdocs.pm/credo/ |
| [clj-kondo](https://github.com/clj-kondo/clj-kondo) | Clojure | https://github.com/clj-kondo/clj-kondo |
| [codenarc](https://codenarc.org/) | Groovy | https://codenarc.org/ |
| [solhint](https://github.com/protofire/solhint) | Solidity | https://github.com/protofire/solhint |
| [vint](https://github.com/Vimjas/vint) | Vim script | https://github.com/Vimjas/vint |

### Config & Data Linters

| Tool | Format | Official Docs |
|------|--------|---------------|
| [sqlfluff](https://docs.sqlfluff.com/) | SQL | https://docs.sqlfluff.com/ |
| [xmllint](https://gnome.pages.gitlab.gnome.org/libxml2/xmllint.html) | XML | https://gnome.pages.gitlab.gnome.org/libxml2/xmllint.html |
| [taplo](https://taplo.tamasfe.dev/) | TOML | https://taplo.tamasfe.dev/ |
| [stylelint](https://stylelint.io/) | CSS/SCSS | https://stylelint.io/ |
| [htmlhint](https://htmlhint.com/) | HTML | https://htmlhint.com/ |
| [buf](https://buf.build/docs/lint/) | Protobuf | https://buf.build/docs/lint/ |
| [graphql-schema-linter](https://github.com/cjoudrey/graphql-schema-linter) | GraphQL | https://github.com/cjoudrey/graphql-schema-linter |

### Infrastructure Linters

| Tool | Target | Official Docs |
|------|--------|---------------|
| [ansible-lint](https://docs.ansible.com/projects/lint/) | Ansible | https://docs.ansible.com/projects/lint/ |
| [kube-linter](https://docs.kubelinter.io/) | Kubernetes | https://docs.kubelinter.io/ |
| [gixy](https://github.com/yandex/gixy) | Nginx | https://github.com/yandex/gixy |
| [checkmake](https://github.com/checkmake/checkmake) | Makefiles | https://github.com/checkmake/checkmake |
| [cmake-lint](https://github.com/cmake-lint/cmake-lint) | CMake | https://github.com/cmake-lint/cmake-lint |
| [pwsh](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview) | PowerShell | https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview |
| [docker-compose](https://docs.docker.com/compose/) | Docker | https://docs.docker.com/compose/ |

---

## Quick Install by Package Manager

### pip (Python tools)

```bash
pip install semgrep modelscan garak sqlfluff ansible-lint cmakelint vim-vint gixy
```

### npm (Node.js tools)

```bash
npm install -g eslint typescript stylelint htmlhint solhint graphql-schema-linter
```

### brew (macOS)

```bash
brew install shellcheck trivy gitleaks cppcheck ktlint swiftlint rubocop hlint
```

### apt (Debian/Ubuntu)

```bash
sudo apt install shellcheck cppcheck libxml2-utils
```

### cargo (Rust)

```bash
cargo install taplo-cli
```

---

## Troubleshooting

### Tool Not Detected

If MEDUSA doesn't detect a tool you've installed:

1. **Check it's in your PATH:**
   ```bash
   which <tool-name>  # Linux/macOS
   where <tool-name>  # Windows
   ```

2. **Restart your terminal** after installation

3. **Verify it runs:**
   ```bash
   <tool-name> --version
   ```

### Installation Issues

For installation problems, please visit the tool's official documentation linked in the tables above. We cannot provide support for third-party tool installation - please contact the respective tool vendors.

---

## MEDUSA Support

MEDUSA-specific issues (detection not working, scan errors, etc.):
- GitHub Issues: https://github.com/Pantheon-Security/medusa/issues

---

*Last updated: 2026-01-30 | MEDUSA v2026.2.0*
