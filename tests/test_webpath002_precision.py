#!/usr/bin/env python3
"""
Precision tests for WEB-PATH-002 (unsafe-file-upload, HIGH).

Round-2 FP Phase 4c: WEB-PATH-002's first pattern was a bare ``\\.filename`` that
matched EVERY ``.filename`` attribute access in any codebase — ``self.filename``,
``template.filename``, ``exc_value.filename`` — producing a large FP tail (12 on
pallets/jinja, 29 across benign repos). None of those are file uploads.

The fix requires the ``.filename`` to be reached through an uploaded-file object
(``request.files`` / ``FileStorage`` / a ``files[...]`` access) — the actual
CWE-22 sink where a client-controlled filename lands unsanitised. The two precise
werkzeug-``save`` patterns are unchanged.

These tests drive the REAL scan path — code written to a Flask file and scanned by
WebSecurityScanner.scan — and pin the asymmetric behaviour. The crafted content
carries a Flask import so ``has_web_context`` recognises it as web code (the same
condition a real Flask upload handler satisfies).
"""

from pathlib import Path

from medusa.scanners.web_security_scanner import WebSecurityScanner


WEB_PATH_002 = "WEB-PATH-002"

# Minimal Flask context so has_web_context() classifies the file as web code.
_FLASK_HEADER = "from flask import request, Flask\napp = Flask(__name__)\n\n"


def _scan_ids(tmp_path: Path, name: str, body: str):
    fp = tmp_path / name
    fp.write_text(_FLASK_HEADER + body, encoding="utf-8")
    return [i.rule_id for i in WebSecurityScanner().scan(fp).issues]


def _fires_002(tmp_path: Path, name: str, body: str) -> bool:
    return WEB_PATH_002 in _scan_ids(tmp_path, name, body)


# ── FP class: a plain ``.filename`` attribute access must NOT fire ───────────

def test_self_filename_assignment_does_not_fire(tmp_path):
    # jinja: `self.filename = filename` — object bookkeeping, not an upload.
    body = "class Template:\n    def __init__(self, filename):\n        self.filename = filename\n"
    assert not _fires_002(tmp_path, "tmpl.py", body), (
        "bare self.filename attribute access must not trip WEB-PATH-002"
    )


def test_template_filename_read_does_not_fire(tmp_path):
    # jinja: `template.filename or "<unknown>"` — reading an attribute for a name.
    body = 'def name(template):\n    return template.filename or "<unknown>"\n'
    assert not _fires_002(tmp_path, "loader.py", body), (
        "template.filename read must not trip WEB-PATH-002"
    )


def test_exc_value_filename_does_not_fire(tmp_path):
    # jinja: `exc_value.filename` — traceback/exception introspection.
    body = "def report(exc_value):\n    return exc_value.filename\n"
    assert not _fires_002(tmp_path, "debug.py", body), (
        "exc_value.filename introspection must not trip WEB-PATH-002"
    )


# ── TP class: a client-controlled upload filename must STILL fire ────────────

def test_request_files_filename_via_var_fires(tmp_path):
    # `f = request.files[...]; name = f.filename` — the classic unsanitised sink.
    body = "@app.route('/u', methods=['POST'])\ndef u():\n    f = request.files['upload']; name = f.filename\n    return name\n"
    assert _fires_002(tmp_path, "up1.py", body), (
        "request.files[...] .filename upload sink must fire WEB-PATH-002"
    )


def test_request_files_filename_chained_fires(tmp_path):
    # `fn = request.files['x'].filename; open("/up/"+fn)` — path built from it.
    body = "@app.route('/u', methods=['POST'])\ndef u():\n    fn = request.files['x'].filename; open(\"/up/\"+fn)\n"
    assert _fires_002(tmp_path, "up2.py", body), (
        "chained request.files[...].filename must fire WEB-PATH-002"
    )


def test_request_files_save_still_fires(tmp_path):
    # The precise werkzeug save pattern (second pattern) is unchanged.
    body = "@app.route('/u', methods=['POST'])\ndef u():\n    request.files['x'].save('/uploads/' + name)\n"
    assert _fires_002(tmp_path, "up3.py", body), (
        "request.files[...].save(...) upload must still fire WEB-PATH-002"
    )
