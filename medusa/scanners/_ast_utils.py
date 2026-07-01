"""Shared AST helpers for the in-process Python scanners.

The AST behavioral scanner and the taint-tracking scanner both need to resolve
a call's bare name and the root of an attribute chain. These two helpers were
byte-for-byte duplicated in both modules; they live here so the two scanners
share one definition (precedent: ``scanners/_ml_context.py``).
"""

import ast
from typing import Optional


def _func_name(node: ast.AST) -> Optional[str]:
    """Return the bare callable name for a Call.func: `eval`, `exec`, `b64decode`,
    `import_module`, `system`, etc. For attribute access (a.b.c) returns the last
    attribute (`c`); for a Name returns its id."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _attr_root(node: ast.AST) -> Optional[str]:
    """For an Attribute chain like `os.path`, return the root Name id (`os`)."""
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return None
