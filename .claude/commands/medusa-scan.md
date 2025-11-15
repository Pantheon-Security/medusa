# MEDUSA Security Scan

Run MEDUSA security scanner on the project or specific files.

## Usage

```bash
/medusa-scan [options]
```

## Examples

### Quick scan (changed files only)
```bash
/medusa-scan --quick
```

### Full project scan
```bash
/medusa-scan
```

### Scan specific directory
```bash
/medusa-scan src/
```

### Scan with custom workers
```bash
/medusa-scan --workers 8
```

### Fail on high severity
```bash
/medusa-scan --fail-on high
```

## Command

```bash
medusa scan . --quick
```

## Integration

This command integrates with MEDUSA's 42-headed security scanner, providing:

- ✅ 42 language/format support
- ✅ Auto-detection of file types
- ✅ Parallel scanning for speed
- ✅ Beautiful HTML/JSON reports
- ✅ Inline issue annotations

## Configuration

Edit `.medusa.yml` to customize:
- Exclusion patterns
- Scanner enable/disable
- Severity thresholds
- IDE integration settings

## Learn More

- Documentation: https://docs.medusa-security.dev
- Report Issues: https://github.com/chimera/medusa/issues
