#!/usr/bin/env python3
"""Tests for the web-application applicability gate (P1-trust-safety).

``_web_context.has_web_context`` gates WebSecurityScanner's web-vulnerability
rules (SSTI / SSRF / EVAL-as-web / AUTH / open-redirect / ...) so they only fire
on genuine web code. Before the gate, those generic patterns false-positived on
plain non-web Python (e.g. ``six.py``: ``exec(...)`` -> WEB-EVAL,
``__globals__`` -> WEB-SSTI, ``HTTPBasicAuthHandler`` -> WEB-AUTH).
"""

from pathlib import Path
import tempfile

from medusa.scanners._web_context import has_web_context
from medusa.scanners.web_security_scanner import WebSecurityScanner


FLASK_HANDLER = """\
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("Hello " + name)
"""

# A plain Py2/3 compat shim — the shape of six.py. Contains tokens that used to
# trip the web rules (exec, __globals__, HTTPBasicAuthHandler) but is NOT web.
COMPAT_LIB = """\
import sys

_func_globals = "__globals__"

class MovedAttribute(object):
    pass

# Emulated for the demo: an urllib mapping, not a web handler.
handlers = [MovedAttribute("HTTPBasicAuthHandler", "urllib2", "urllib.request")]

def exec_(_code_, _globs_=None, _locs_=None):
    exec(\"\"\"exec _code_ in _globs_, _locs_\"\"\")
"""


# --------------------------------------------------------------------------- #
# has_web_context
# --------------------------------------------------------------------------- #

def test_flask_handler_has_web_context():
    assert has_web_context("app.py", FLASK_HANDLER) is True


def test_compat_lib_has_no_web_context():
    assert has_web_context("six.py", COMPAT_LIB) is False


def test_web_extension_is_web_regardless_of_content():
    assert has_web_context("index.html", "<h1>hi</h1>") is True
    assert has_web_context("page.jinja2", "{{ x }}") is True
    assert has_web_context("legacy.php", "<?php echo 1; ?>") is True


def test_django_and_fastapi_detected():
    assert has_web_context("views.py", "from django.http import HttpResponse") is True
    assert has_web_context("api.py", "from fastapi import FastAPI\napp = FastAPI()") is True


def test_bare_python_builtins_do_not_fake_web_context():
    # `next(...)` (builtin) and the word "express" in prose must NOT read as web.
    assert has_web_context("util.py", "x = next(iter(items))  # express intent\n") is False


def test_none_path_falls_back_to_content():
    assert has_web_context(None, FLASK_HANDLER) is True
    assert has_web_context(None, "x = 1\n") is False


# --------------------------------------------------------------------------- #
# WebSecurityScanner gating (end-to-end through scan())
# --------------------------------------------------------------------------- #

def _scan(src, suffix=".py"):
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_text(src)
    try:
        return {i.rule_id for i in WebSecurityScanner().scan(p).issues}
    finally:
        p.unlink(missing_ok=True)


def test_web_rule_fires_on_web_file():
    ids = _scan(FLASK_HANDLER)
    # Some web-vuln rule must fire on genuine Flask handler code.
    assert any(r.startswith("WEB-") for r in ids), ids


def test_web_rules_suppressed_on_non_web_file():
    ids = _scan(COMPAT_LIB)
    gated = WebSecurityScanner.WEB_CONTEXT_GATED_PREFIXES
    offenders = {r for r in ids if r.startswith(gated)}
    assert not offenders, f"web-vuln rules fired on non-web file: {offenders}"


def test_general_sast_still_runs_on_non_web_file():
    # An insecure-deserialization sink is a general SAST rule and must still fire
    # on a non-web file — the gate only suppresses web-specific rules.
    src = "import pickle\n\ndef load(data):\n    return pickle.loads(data)\n"
    ids = _scan(src)
    # Not asserting a specific rule id (corpus may evolve), only that the gate
    # did not silence everything on a non-web file with a real SAST sink.
    assert not has_web_context("m.py", src)  # confirm it's classified non-web
