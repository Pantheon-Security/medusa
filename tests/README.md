# MEDUSA Test Suite

## Quick Start

```bash
# Run all tests
pytest tests/ --ignore=tests/test_api_basic.py -v

# Run with coverage
pytest tests/ --ignore=tests/test_api_basic.py --cov=medusa --cov-report=html

# Run specific module
pytest tests/test_licensing.py -v
pytest tests/test_rules.py -v
pytest tests/test_reporter.py -v
pytest tests/test_fp_filter.py -v
pytest tests/test_simple_installer.py -v

# Run simple installer tests with detailed coverage
pytest tests/test_simple_installer.py -v --cov=medusa.platform.installers.simple --cov-report=term-missing
```

## Test Files

| File | Tests | Coverage | Description |
|------|-------|----------|-------------|
| `conftest.py` | - | - | Pytest fixtures (licenses, rules, scan data) |
| `test_licensing.py` | 38 | 82% | License tier management and feature gating |
| `test_rules.py` | 40 | 85% | YAML rule loading and pattern matching |
| `test_reporter.py` | 29 | 67% | SARIF, JSON, HTML, Markdown report generation |
| `test_fp_filter.py` | 33 | 94% | False positive detection and filtering |
| `test_simple_installer.py` | 39 | 100% | v2026.2 simplified installer (AI tools only) |
| **Total** | **179** | **85%** | **Core modules average** |

## Test Coverage

### Licensing Module (82%)
- License tier validation (FREE, PRO, ENTERPRISE)
- Feature gating (runtime_filters, api_access, custom_rules)
- License file loading (env var, global, project)
- License expiration handling
- License caching

### Rules Module (85%)
- YAML rule parsing (3 formats supported)
- Runtime rules licensing (FREE users excluded)
- Pattern compilation and regex matching
- Rule filtering (severity, category, OWASP)
- Content matching with line numbers

### Reporter Module (67%)
- SARIF 2.1.0 specification compliance
- GitHub Code Scanning integration
- Severity mapping (CRITICAL→error, etc.)
- Security score calculation (0-100)
- Multiple output formats (JSON, HTML, Markdown)

### FP Filter Module (94%)
- Docstring/comment detection
- Security wrapper patterns
- Test/mock file detection
- Known FP patterns (Go hash, masked passwords)
- Severity adjustment based on confidence

### Simple Installer Module (100%)
- Virtualenv detection (venv vs system)
- Pip command generation (sys.executable -m pip vs pip3)
- AI tool installation (modelscan)
- Tool detection (bandit, semgrep, shellcheck, etc.)
- CLI commands (install --check, install --ai-tools, uninstall)
- Deprecation warnings (--all flag)

## Requirements

```bash
pip install pytest pytest-cov
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run tests
  run: |
    pip install pytest pytest-cov
    pytest tests/ --ignore=tests/test_api_basic.py --cov=medusa --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v4
  with:
    file: coverage.xml
```

## Coverage Goals

- [x] Licensing: 80%+ ✅ (82%)
- [x] Rules: 80%+ ✅ (85%)
- [x] FP Filter: 80%+ ✅ (94%)
- [x] Simple Installer: 80%+ ✅ (100%)
- [x] Reporter: 60%+ ✅ (67%)
- [ ] Scanners: 50%+ (future)
- [ ] CLI: 50%+ (future)

## Test Patterns

### Mocking Licenses
```python
from unittest.mock import patch

# Mock environment variable
with patch.dict(os.environ, {'MEDUSA_LICENSE_KEY': key}):
    manager = LicenseManager()
    license_info = manager.get_license()

# Mock file path
with patch.object(manager, 'GLOBAL_LICENSE_PATH', temp_file):
    license_info = manager.get_license()
```

### Testing Rules
```python
# Test runtime filter gating
with patch('medusa.core.licensing.can_use_runtime_filters', return_value=True):
    loader = RuleLoader()
    rules = loader.load_rules_from_file(runtime_rule_file)
    assert len(rules) > 0  # Loaded for PRO tier
```

### Testing SARIF
```python
def test_sarif_structure(tmp_path, sample_scan_results):
    reporter = MedusaReportGenerator(output_dir=tmp_path)
    sarif_path = reporter.generate_sarif_report(sample_scan_results)

    with open(sarif_path) as f:
        sarif = json.load(f)

    assert sarif['version'] == '2.1.0'
    assert 'runs' in sarif
```

### Testing Simple Installer
```python
from unittest import mock
from medusa.platform.installers.simple import install_ai_tools

def test_install_in_virtualenv():
    """Test AI tools installation in virtualenv"""
    with mock.patch('medusa.platform.installers.simple._in_virtualenv', return_value=True):
        with mock.patch('subprocess.run') as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr='')

            result = install_ai_tools()

            # Verify --user flag NOT used in venv
            cmd = mock_run.call_args[0][0]
            assert '--user' not in cmd
            assert result['modelscan']['status'] == 'installed'
```

## Fixtures Available

From `conftest.py`:

- `free_license` - FREE tier LicenseInfo
- `pro_license` - PRO tier LicenseInfo
- `enterprise_license` - ENTERPRISE tier LicenseInfo
- `expired_pro_license` - Expired PRO license
- `temp_license_file` - Temporary license.json
- `sample_rules` - List of Rule objects
- `sample_scan_results` - Scan findings dict
- `sample_rule_yaml` - YAML rule file
- `sample_runtime_rule_yaml` - Runtime YAML rule
- `vulnerable_code_sample` - Python file with issues
- `clean_code_sample` - Secure Python code

## Troubleshooting

### ModuleNotFoundError: fastapi
Skip API tests if FastAPI not installed:
```bash
pytest tests/ --ignore=tests/test_api_basic.py
```

### Coverage not showing
Make sure you're testing the installed package:
```bash
pip install -e .
pytest --cov=medusa
```

### Tests taking too long
Run in parallel:
```bash
pytest tests/ -n auto
```

## Contributing

When adding new tests:

1. Add fixtures to `conftest.py` if reusable
2. Follow existing test class structure
3. Aim for 80%+ coverage on new modules
4. Include edge cases and error handling
5. Use descriptive test names

Example:
```python
class TestNewFeature:
    """Test new feature functionality"""
    
    def test_feature_works_with_valid_input(self):
        """Test that feature works correctly with valid input"""
        # Arrange
        input_data = create_test_data()
        
        # Act
        result = new_feature(input_data)
        
        # Assert
        assert result.is_valid
        assert result.output == expected_output
```

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [MEDUSA Documentation](https://pantheonsecurity.io)
