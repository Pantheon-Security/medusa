# 🔍 MEDUSA Scanner Reference

Complete reference for all 42 security scanners supported by MEDUSA.

---

## Overview

MEDUSA integrates 42 different security scanning tools to provide comprehensive coverage across all major programming languages, configuration files, and infrastructure code.

### Scanner Categories

- **Backend Languages** (9 scanners)
- **JVM Languages** (3 scanners)
- **Functional Languages** (5 scanners)
- **Mobile Development** (2 scanners)
- **Frontend & Styling** (3 scanners)
- **Infrastructure as Code** (4 scanners)
- **Configuration Files** (5 scanners)
- **Shell & Scripts** (4 scanners)
- **Documentation** (2 scanners)
- **Other Languages** (5 scanners)

**Total: 42 scanners**

---

## Backend Languages

### 1. Python - Bandit

**Scanner**: bandit
**Extensions**: `.py`
**Installation**: `pip install bandit`

**What it scans:**
- SQL injection vulnerabilities
- Hard-coded passwords and secrets
- Insecure cryptography usage
- Shell command injection (subprocess with shell=True)
- Insecure deserialization
- XML vulnerabilities (XXE)
- Path traversal issues

**Example issue:**
```python
# CRITICAL: Hard-coded password
password = "admin123"  # B105: hardcoded_password_string

# HIGH: Shell injection
os.system(user_input)  # B605: start_process_with_a_shell
```

**Configuration**: Uses `.bandit` file or inline `# nosec` comments

---

### 2. JavaScript/TypeScript - ESLint

**Scanner**: eslint
**Extensions**: `.js`, `.jsx`, `.ts`, `.tsx`
**Installation**: `npm install -g eslint`

**What it scans:**
- Security best practices
- Code quality issues
- Potential runtime errors
- Unsafe RegExp patterns
- DOM XSS vulnerabilities
- Prototype pollution

**Example issue:**
```javascript
// HIGH: eval() usage
eval(userInput);  // no-eval

// MEDIUM: Unsafe regex
const re = new RegExp(userInput);  // security/detect-unsafe-regex
```

**Configuration**: Uses `.eslintrc.json` or `eslint.config.js`

---

### 3. Go - golangci-lint

**Scanner**: golangci-lint
**Extensions**: `.go`
**Installation**: `brew install golangci-lint` or download binary

**What it scans:**
- Security vulnerabilities (gosec)
- Code quality (staticcheck)
- Error handling issues
- Inefficient code patterns
- Deprecated function usage
- Race conditions

**Example issue:**
```go
// HIGH: Weak random number generator
import "math/rand"
token := rand.Int()  // G404: Use crypto/rand instead

// MEDIUM: Unchecked error
file, _ := os.Open("data.txt")  // errcheck
```

**Configuration**: Uses `.golangci.yml`

---

### 4. Ruby - RuboCop

**Scanner**: rubocop
**Extensions**: `.rb`, `.rake`, `.gemspec`
**Installation**: `gem install rubocop`

**What it scans:**
- Security vulnerabilities
- Code style violations
- Potential bugs
- Performance issues
- Best practice violations

**Example issue:**
```ruby
# HIGH: SQL injection
User.where("name = '#{params[:name]}'")  # Security/SQLInjection

# MEDIUM: Weak crypto
require 'digest/md5'
Digest::MD5.hexdigest(password)  # Security/WeakHash
```

**Configuration**: Uses `.rubocop.yml`

---

### 5. PHP - PHPStan

**Scanner**: phpstan
**Extensions**: `.php`
**Installation**: `composer global require phpstan/phpstan`

**What it scans:**
- Type safety issues
- Undefined variables and methods
- Dead code detection
- SQL injection patterns
- XSS vulnerabilities
- Insecure file operations

**Example issue:**
```php
// HIGH: SQL injection
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];  // phpstan-security

// MEDIUM: Undefined variable
echo $undefinedVar;  // Variable $undefinedVar might not be defined
```

**Configuration**: Uses `phpstan.neon` or `phpstan.neon.dist`

---

### 6. Rust - Clippy

**Scanner**: cargo-clippy
**Extensions**: `.rs`
**Installation**: `rustup component add clippy`

**What it scans:**
- Unsafe code patterns
- Performance issues
- Idiomatic Rust violations
- Potential bugs
- Deprecated syntax

**Example issue:**
```rust
// HIGH: Unsafe code without safety comment
unsafe {
    *ptr = 42;  // clippy::undocumented_unsafe_blocks
}

// MEDIUM: Inefficient string concatenation
let s = "Hello".to_string() + " " + "World";  // clippy::string_add
```

**Configuration**: Uses `clippy.toml` or inline `#[allow(clippy::...)]`

---

### 7. Java - Checkstyle

**Scanner**: checkstyle
**Extensions**: `.java`
**Installation**: `apt install checkstyle` or download JAR

**What it scans:**
- Code style violations
- Potential bugs
- Security anti-patterns
- Best practice violations
- Complexity issues

**Example issue:**
```java
// HIGH: Hardcoded password
String password = "admin123";  // checkstyle:IllegalTokenText

// MEDIUM: Missing JavaDoc
public void processData() {  // checkstyle:MissingJavadocMethod
    // ...
}
```

**Configuration**: Uses `checkstyle.xml`

---

### 8. C/C++ - cppcheck

**Scanner**: cppcheck
**Extensions**: `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp`
**Installation**: `apt install cppcheck` or `brew install cppcheck`

**What it scans:**
- Memory leaks
- Buffer overflows
- Null pointer dereferences
- Uninitialized variables
- Resource leaks
- Dead code

**Example issue:**
```cpp
// CRITICAL: Buffer overflow
char buf[10];
strcpy(buf, longString);  // error: buffer overflow

// HIGH: Memory leak
int* ptr = new int[100];
return;  // error: memory leak
```

**Configuration**: Command-line flags or `cppcheck.cfg`

---

### 9. C# - Roslynator

**Scanner**: roslynator
**Extensions**: `.cs`
**Installation**: `dotnet tool install -g roslynator.dotnet.cli`

**What it scans:**
- Code quality issues
- Security vulnerabilities
- Performance problems
- Best practice violations
- Null reference issues

**Example issue:**
```csharp
// HIGH: SQL injection
string query = "SELECT * FROM Users WHERE Id = " + userId;  // RCS1155

// MEDIUM: Null reference
string name = user.Name;  // RCS1202: Possible null reference
```

**Configuration**: Uses `.editorconfig` or `roslynator.config`

---

## JVM Languages

### 10. Kotlin - ktlint

**Scanner**: ktlint
**Extensions**: `.kt`, `.kts`
**Installation**: `brew install ktlint`

**What it scans:**
- Kotlin code style
- Best practices
- Potential bugs
- Security issues

**Example issue:**
```kotlin
// MEDIUM: Missing trailing comma
val list = listOf(
    "item1",
    "item2"  // missing trailing comma
)
```

---

### 11. Scala - Scalastyle

**Scanner**: scalastyle
**Extensions**: `.scala`
**Installation**: Download JAR or use sbt plugin

**What it scans:**
- Scala style guide compliance
- Code quality
- Potential bugs

---

### 12. Groovy - CodeNarc

**Scanner**: codenarc
**Extensions**: `.groovy`, `.gradle`
**Installation**: Add to Gradle or download JAR

**What it scans:**
- Groovy best practices
- Security issues
- Code quality

---

## Functional Languages

### 13. Haskell - HLint

**Scanner**: hlint
**Extensions**: `.hs`, `.lhs`
**Installation**: `cabal install hlint` or `stack install hlint`

**What it scans:**
- Haskell best practices
- Code simplification opportunities
- Type usage issues

---

### 14. Elixir - Credo

**Scanner**: credo
**Extensions**: `.ex`, `.exs`
**Installation**: Add to `mix.exs` dependencies

**What it scans:**
- Elixir code consistency
- Refactoring opportunities
- Security patterns

---

### 15. Erlang - Elvis

**Scanner**: elvis
**Extensions**: `.erl`, `.hrl`
**Installation**: Download or use rebar3 plugin

**What it scans:**
- Erlang style guide
- Code quality
- Best practices

---

### 16. F# - FSharpLint

**Scanner**: fsharplint
**Extensions**: `.fs`, `.fsx`
**Installation**: `dotnet tool install -g dotnet-fsharplint`

**What it scans:**
- F# style guide
- Code quality
- Best practices

---

### 17. Clojure - clj-kondo

**Scanner**: clj-kondo
**Extensions**: `.clj`, `.cljs`, `.cljc`
**Installation**: `brew install clj-kondo`

**What it scans:**
- Syntax errors
- Type mismatches
- Unused variables
- Deprecated functions

---

## Mobile Development

### 18. Swift - SwiftLint

**Scanner**: swiftlint
**Extensions**: `.swift`
**Installation**: `brew install swiftlint`

**What it scans:**
- Swift style guide compliance
- Code quality
- Potential bugs
- Security issues

**Example issue:**
```swift
// HIGH: Force unwrapping
let value = optional!  // force_unwrapping

// MEDIUM: Long line
let veryLongLineOfCodeThatExceedsTheMaximumLineLength = true  // line_length
```

---

### 19. Objective-C - OCLint

**Scanner**: oclint
**Extensions**: `.m`, `.mm`
**Installation**: `brew install oclint`

**What it scans:**
- Objective-C code quality
- Potential bugs
- Best practices

---

## Frontend & Styling

### 20. CSS/SCSS/Sass/Less - Stylelint

**Scanner**: stylelint
**Extensions**: `.css`, `.scss`, `.sass`, `.less`
**Installation**: `npm install -g stylelint`

**What it scans:**
- CSS syntax errors
- Style inconsistencies
- Best practices
- Browser compatibility

**Example issue:**
```css
/* MEDIUM: Invalid color */
color: #00; /* color-no-invalid-hex */

/* LOW: Duplicate property */
.class {
  color: red;
  color: blue; /* declaration-block-no-duplicate-properties */
}
```

---

### 21. HTML - HTMLHint

**Scanner**: htmlhint
**Extensions**: `.html`, `.htm`
**Installation**: `npm install -g htmlhint`

**What it scans:**
- HTML syntax errors
- Accessibility issues
- Best practices
- SEO problems

**Example issue:**
```html
<!-- HIGH: Missing alt attribute -->
<img src="photo.jpg">  <!-- img-alt-require -->

<!-- MEDIUM: Inline style -->
<div style="color: red;">  <!-- attr-no-unnecessary-whitespace -->
```

---

### 22. Vue.js - ESLint (with Vue plugin)

**Scanner**: eslint
**Extensions**: `.vue`
**Installation**: `npm install -g eslint eslint-plugin-vue`

**What it scans:**
- Vue.js best practices
- Template syntax errors
- Component structure issues

---

## Infrastructure as Code

### 23. Terraform - tflint

**Scanner**: tflint
**Extensions**: `.tf`, `.tfvars`
**Installation**: `brew install tflint`

**What it scans:**
- Terraform syntax errors
- AWS/Azure/GCP best practices
- Security misconfigurations
- Resource naming issues

**Example issue:**
```hcl
# HIGH: Public S3 bucket
resource "aws_s3_bucket" "example" {
  acl = "public-read"  # tflint: public bucket detected
}

# MEDIUM: Missing required tags
resource "aws_instance" "web" {
  # Missing tags
}
```

---

### 24. Ansible - ansible-lint

**Scanner**: ansible-lint
**Extensions**: `.yml`, `.yaml` (playbooks)
**Installation**: `pip install ansible-lint`

**What it scans:**
- Ansible best practices
- Security issues
- Deprecated module usage
- YAML syntax

**Example issue:**
```yaml
# HIGH: Command instead of module
- name: Install package
  command: apt-get install nginx  # ansible-lint: use apt module instead

# MEDIUM: Missing become
- name: Edit system file
  copy:
    dest: /etc/nginx/nginx.conf  # requires become: yes
```

---

### 25. Kubernetes - kubeval

**Scanner**: kubeval
**Extensions**: `.yml`, `.yaml` (manifests)
**Installation**: `brew install kubeval`

**What it scans:**
- Kubernetes manifest syntax
- API version compatibility
- Resource specification errors

---

### 26. CloudFormation - cfn-lint

**Scanner**: cfn-lint
**Extensions**: `.yml`, `.yaml`, `.json` (templates)
**Installation**: `pip install cfn-lint`

**What it scans:**
- CloudFormation syntax
- Resource properties
- Security best practices

---

## Configuration Files

### 27. YAML - yamllint

**Scanner**: yamllint
**Extensions**: `.yml`, `.yaml`
**Installation**: `pip install yamllint`

**What it scans:**
- YAML syntax errors
- Formatting issues
- Best practices

**Example issue:**
```yaml
# MEDIUM: Trailing spaces
key: value

# LOW: Too many blank lines


key2: value2
```

---

### 28. JSON - built-in parser

**Scanner**: python json module
**Extensions**: `.json`
**Installation**: Built-in (no installation needed)

**What it scans:**
- JSON syntax errors
- Malformed structures

**Example issue:**
```json
{
  "key": "value",  // CRITICAL: Trailing comma
}
```

---

### 29. TOML - taplo

**Scanner**: taplo
**Extensions**: `.toml`
**Installation**: `cargo install taplo-cli`

**What it scans:**
- TOML syntax errors
- Formatting issues

---

### 30. XML - xmllint

**Scanner**: xmllint
**Extensions**: `.xml`
**Installation**: `apt install libxml2-utils` (usually pre-installed)

**What it scans:**
- XML syntax errors
- Well-formedness
- Schema validation

---

### 31. Protobuf - buf lint

**Scanner**: buf
**Extensions**: `.proto`
**Installation**: `brew install buf`

**What it scans:**
- Protobuf syntax
- Style guide compliance
- Breaking changes

---

## Shell & Scripts

### 32. Bash/Shell - ShellCheck

**Scanner**: shellcheck
**Extensions**: `.sh`, `.bash`
**Installation**: `apt install shellcheck` or `brew install shellcheck`

**What it scans:**
- Syntax errors
- Quoting issues
- Security vulnerabilities
- Portability problems

**Example issue:**
```bash
# CRITICAL: Unquoted variable (injection risk)
rm -rf $dir/*  # SC2086: Quote to prevent word splitting

# HIGH: Using [ instead of [[
if [ $var = "value" ]; then  # SC2166: Prefer [[ for conditionals
```

---

### 33. PowerShell - PSScriptAnalyzer

**Scanner**: Invoke-ScriptAnalyzer
**Extensions**: `.ps1`, `.psm1`
**Installation**: `Install-Module -Name PSScriptAnalyzer`

**What it scans:**
- PowerShell best practices
- Security issues
- Performance problems

---

### 34. Lua - luacheck

**Scanner**: luacheck
**Extensions**: `.lua`
**Installation**: `luarocks install luacheck`

**What it scans:**
- Lua syntax
- Unused variables
- Global variable usage

---

### 35. Perl - perlcritic

**Scanner**: perlcritic
**Extensions**: `.pl`, `.pm`
**Installation**: `cpan Perl::Critic`

**What it scans:**
- Perl best practices
- Code quality
- Security issues

---

## Documentation

### 36. Markdown - markdownlint

**Scanner**: markdownlint-cli
**Extensions**: `.md`
**Installation**: `npm install -g markdownlint-cli`

**What it scans:**
- Markdown syntax
- Formatting consistency
- Link validity
- Heading structure

**Example issue:**
```markdown
# Heading

This is a paragraph.
<!-- MEDIUM: No blank line before heading -->
## Subheading

<!-- LOW: Trailing spaces -->
Some text.
```

---

### 37. reStructuredText - rst-lint

**Scanner**: restructuredtext-lint
**Extensions**: `.rst`
**Installation**: `pip install restructuredtext-lint`

**What it scans:**
- RST syntax errors
- Directive usage
- Link references

---

## Other Languages

### 38. SQL - SQLFluff

**Scanner**: sqlfluff
**Extensions**: `.sql`
**Installation**: `pip install sqlfluff`

**What it scans:**
- SQL syntax
- Code formatting
- Anti-patterns
- Security issues

**Example issue:**
```sql
-- HIGH: SQL injection pattern
SELECT * FROM users WHERE id = ' + userId + ';  -- sqlfluff:L001

-- MEDIUM: SELECT *
SELECT * FROM users;  -- sqlfluff:L009
```

---

### 39. R - lintr

**Scanner**: lintr
**Extensions**: `.r`, `.R`
**Installation**: R package `install.packages("lintr")`

**What it scans:**
- R code style
- Best practices
- Potential bugs

---

### 40. Dart - dart analyze

**Scanner**: dart analyze
**Extensions**: `.dart`
**Installation**: Included with Dart SDK

**What it scans:**
- Dart syntax
- Type safety
- Best practices

---

### 41. Solidity - solhint

**Scanner**: solhint
**Extensions**: `.sol`
**Installation**: `npm install -g solhint`

**What it scans:**
- Solidity security issues
- Smart contract best practices
- Gas optimization

**Example issue:**
```solidity
// CRITICAL: Reentrancy vulnerability
function withdraw() public {
    msg.sender.call.value(balance)("");  // solhint: reentrancy
    balance = 0;
}

// HIGH: tx.origin usage
require(tx.origin == owner);  // solhint: avoid-tx-origin
```

---

### 42. Docker - hadolint

**Scanner**: hadolint
**Extensions**: `Dockerfile`, `Dockerfile.*`
**Installation**: `brew install hadolint`

**What it scans:**
- Dockerfile best practices
- Security issues
- Layer optimization
- Build efficiency

**Example issue:**
```dockerfile
# HIGH: Using latest tag
FROM ubuntu:latest  # DL3007: Use specific version

# MEDIUM: Missing HEALTHCHECK
FROM nginx:1.21
# Missing HEALTHCHECK instruction

# LOW: Multiple RUN commands
RUN apt-get update
RUN apt-get install -y curl  # DL3059: Combine RUN commands
```

---

## Scanner Configuration

### Disabling Scanners

Edit `.medusa.yml`:

```yaml
scanners:
  disabled:
    - bandit       # Disable Python scanner
    - eslint       # Disable JavaScript scanner
    - rubocop      # Disable Ruby scanner
```

### Installing Specific Scanners

```bash
# Install only Python scanner
medusa install --tool bandit

# Check installed scanners
medusa install --check
```

### Custom Scanner Rules

Most scanners support configuration files:

- `.bandit` - Bandit configuration
- `.eslintrc.json` - ESLint rules
- `.rubocop.yml` - RuboCop rules
- `phpstan.neon` - PHPStan configuration
- `.golangci.yml` - GolangCI-Lint settings

Place these in your project root and MEDUSA will respect them.

---

## Adding New Scanners

To add a new scanner to MEDUSA:

1. Create scanner class in `medusa/scanners/`
2. Inherit from `BaseScanner`
3. Implement required methods
4. Register in `medusa/scanners/__init__.py`
5. Add tool mapping in `medusa/platform/installers/base.py`

See `docs/development/adding-scanners.md` for detailed guide.

---

## Scanner Statistics

| Category | Scanners | Coverage |
|----------|----------|----------|
| Backend | 9 | Python, JS/TS, Go, Ruby, PHP, Rust, Java, C/C++, C# |
| JVM | 3 | Kotlin, Scala, Groovy |
| Functional | 5 | Haskell, Elixir, Erlang, F#, Clojure |
| Mobile | 2 | Swift, Objective-C |
| Frontend | 3 | CSS/SCSS, HTML, Vue |
| IaC | 4 | Terraform, Ansible, Kubernetes, CloudFormation |
| Config | 5 | YAML, JSON, TOML, XML, Protobuf |
| Shell | 4 | Bash, PowerShell, Lua, Perl |
| Docs | 2 | Markdown, RST |
| Other | 5 | SQL, R, Dart, Solidity, Docker |
| **Total** | **42** | **100+ file extensions** |

---

**Last Updated**: 2025-11-15
**MEDUSA Version**: 0.7.0.0
