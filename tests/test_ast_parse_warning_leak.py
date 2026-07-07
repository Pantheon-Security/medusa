"""Gate: the AST scanners must not leak the SCANNED target's own SyntaxWarnings.

Regression from a Windows scan of ai-goat, where sloppy target code produced
`<unknown>:44: SyntaxWarning: invalid escape sequence '\\/'` in MEDUSA's own scan
output — leaked from an unguarded `ast.parse(content)` (filename defaults to
`<unknown>`). The parse is now wrapped in warnings.catch_warnings()/ignore.
"""
import warnings
import pytest

from medusa.scanners.ast_behavior_scanner import AstBehaviorScanner
from medusa.scanners.taint_scanner import TaintScanner

# Target code with invalid escape sequences ('\/' and '\ '): parsing this WOULD
# emit SyntaxWarnings if not suppressed.
SLOPPY = "def f(p):\n    a = '\\/etc/passwd'\n    b = '\\ trailing'\n    return a + b\n"


@pytest.mark.parametrize("scanner_cls", [AstBehaviorScanner, TaintScanner])
def test_ast_scanner_does_not_leak_target_syntaxwarning(scanner_cls, tmp_path):
    p = tmp_path / "sloppy_target.py"
    p.write_text(SLOPPY)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        scanner_cls().scan_file(p)          # must not raise, must not warn
    leaked = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert not leaked, (
        f"{scanner_cls.__name__} leaked the target's SyntaxWarning into output: "
        f"{[str(w.message) for w in leaked]}"
    )
