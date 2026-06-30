#!/usr/bin/env python3
"""
Tests for AstBehaviorScanner — the Python AST behavioral scanner.

Each test writes a synthetic .py file to a tmp dir, runs the REAL scan_file
path, and asserts on the emitted rule_ids. A clean benign module must produce
zero findings (negative case); each malicious form must fire its rule.
"""

from pathlib import Path

import pytest

from medusa.scanners.ast_behavior_scanner import AstBehaviorScanner


@pytest.fixture
def scanner() -> AstBehaviorScanner:
    return AstBehaviorScanner()


def _scan(scanner: AstBehaviorScanner, tmp_path: Path, code: str) -> set:
    f = tmp_path / "sample.py"
    f.write_text(code)
    result = scanner.scan_file(f)
    assert result.success
    return {issue.rule_id for issue in result.issues}


# --------------------------------------------------------------------------- #
# Negative case: a clean benign module fires nothing.
# --------------------------------------------------------------------------- #
def test_benign_module_no_findings(scanner, tmp_path):
    code = '''
import os
import subprocess
import json


def add(a, b):
    return a + b


def read_config(path):
    with open(path) as fh:
        return json.load(fh)


def run_ls():
    # literal command, no shell=True -> safe
    return subprocess.run(["ls", "-la"], capture_output=True)


def safe_literal_exec():
    # pure literal exec is intentionally not flagged
    exec("x = 1")
    eval("1 + 1")


CONFIG = os.environ.get("CONFIG", "default")
'''
    assert _scan(scanner, tmp_path, code) == set()


# --------------------------------------------------------------------------- #
# Positive cases
# --------------------------------------------------------------------------- #
def test_dynamic_exec_variable(scanner, tmp_path):
    code = '''
def run(payload_var):
    exec(payload_var)
'''
    assert "MEDUSA-AST-EXEC-001" in _scan(scanner, tmp_path, code)


def test_dynamic_eval_concat(scanner, tmp_path):
    code = '''
def run(user_input):
    eval("result = " + user_input)
'''
    assert "MEDUSA-AST-EXEC-001" in _scan(scanner, tmp_path, code)


def test_compile_exec_nonliteral(scanner, tmp_path):
    code = '''
def run(src):
    code_obj = compile(src, "<string>", "exec")
    return code_obj
'''
    assert "MEDUSA-AST-EXEC-001" in _scan(scanner, tmp_path, code)


def test_reflective_os_system(scanner, tmp_path):
    code = '''
import os

def run(cmd):
    getattr(os, "system")(cmd)
'''
    assert "MEDUSA-AST-REFLECT-001" in _scan(scanner, tmp_path, code)


def test_reflective_builtins_eval(scanner, tmp_path):
    code = '''
def run(name, payload):
    fn = getattr(__builtins__, "eval")
    return fn(payload)
'''
    assert "MEDUSA-AST-REFLECT-001" in _scan(scanner, tmp_path, code)


def test_dynamic_import_dunder(scanner, tmp_path):
    code = '''
def load(modname):
    return __import__(modname)
'''
    assert "MEDUSA-AST-DYNIMPORT-001" in _scan(scanner, tmp_path, code)


def test_dynamic_import_importlib(scanner, tmp_path):
    code = '''
import importlib

def load(modname):
    return importlib.import_module(modname)
'''
    assert "MEDUSA-AST-DYNIMPORT-001" in _scan(scanner, tmp_path, code)


def test_subprocess_shell_true_variable(scanner, tmp_path):
    code = '''
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
'''
    assert "MEDUSA-AST-SHELL-001" in _scan(scanner, tmp_path, code)


def test_subprocess_shell_true_fstring(scanner, tmp_path):
    code = '''
import subprocess

def run(target):
    subprocess.call(f"ping {target}", shell=True)
'''
    assert "MEDUSA-AST-SHELL-001" in _scan(scanner, tmp_path, code)


def test_base64_decode_then_exec(scanner, tmp_path):
    code = '''
import base64

def run(blob):
    exec(base64.b64decode(blob))
'''
    rules = _scan(scanner, tmp_path, code)
    assert "MEDUSA-AST-OBFUS-001" in rules


def test_base64_decode_then_eval(scanner, tmp_path):
    code = '''
import base64

def run(blob):
    return eval(base64.b64decode(blob).decode())
'''
    assert "MEDUSA-AST-OBFUS-001" in _scan(scanner, tmp_path, code)


# --------------------------------------------------------------------------- #
# Guards / FP avoidance
# --------------------------------------------------------------------------- #
def test_literal_exec_not_flagged(scanner, tmp_path):
    code = 'exec("a = 1")\neval("2 + 2")\n'
    assert _scan(scanner, tmp_path, code) == set()


def test_subprocess_literal_argv_shell_true_not_flagged(scanner, tmp_path):
    # constant string command with shell=True is benign (no injection vector)
    code = '''
import subprocess
subprocess.run("ls -la", shell=True)
'''
    assert "MEDUSA-AST-SHELL-001" not in _scan(scanner, tmp_path, code)


def test_literal_dynamic_import_not_flagged(scanner, tmp_path):
    code = '''
import importlib
importlib.import_module("os")
mod = __import__("json")
'''
    assert "MEDUSA-AST-DYNIMPORT-001" not in _scan(scanner, tmp_path, code)


def test_syntax_error_returns_empty(scanner, tmp_path):
    code = "def broken(:\n    pass\n"
    f = tmp_path / "broken.py"
    f.write_text(code)
    result = scanner.scan_file(f)
    assert result.success
    assert result.issues == []


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #
def test_scanner_is_registered():
    from medusa.scanners import registry

    names = {s.__class__.__name__ for s in registry.scanners}
    assert "AstBehaviorScanner" in names


def test_line_numbers_reported(scanner, tmp_path):
    code = '''
import os


def run(cmd):
    getattr(os, "system")(cmd)
'''
    f = tmp_path / "lines.py"
    f.write_text(code)
    result = scanner.scan_file(f)
    reflect = [i for i in result.issues if i.rule_id == "MEDUSA-AST-REFLECT-001"]
    assert reflect and reflect[0].line == 6
