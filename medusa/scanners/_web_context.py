#!/usr/bin/env python3
"""
Shared web-application content-applicability gate.

The :class:`~medusa.scanners.web_security_scanner.WebSecurityScanner` loads a
large corpus of web-vulnerability rules (SSTI / SSRF / open-redirect / basic-auth
-over-HTTP / eval-as-web / XXE / session / CSRF / framework-specific Flask &
Django patterns). Many of those rules match very generic tokens — ``exec(...)``,
``__globals__``, ``HTTPBasicAuthHandler``, a string-concatenated URL — and fire
on plain non-web Python (e.g. ``six.py``, a Py2/3 compat shim), producing the
bulk of that scanner's false positives.

This module provides a single, conservative *applicability gate*: report a
web-vulnerability rule ONLY when the file shows genuine web context — it is a
template, a PHP file, or it imports / uses a web framework or request/response
machinery. A real SSTI/SSRF/etc. in actual web code still carries that context,
so it still fires; coverage is preserved and no rule is removed.

Mirrors :mod:`medusa.scanners._ml_context` (the ML/AI applicability gate) in
spirit and shape.

Design notes:
  * Extension check is a fast, unambiguous positive: ``.html`` / ``.jinja`` /
    ``.php`` / ``.vue`` / ... are web by definition.
  * Word boundaries keep framework tokens (``flask`` / ``bottle`` / ``sanic``)
    from matching inside unrelated identifiers.
  * The token list is deliberately broad on the web side (coverage-first): we
    would rather keep a web signal and accept a rare benign match than drop a
    framework token and miss a real web vuln in code that uses it.
"""

import re
from pathlib import Path

# File extensions that ARE web content by definition (templates / server pages /
# component frameworks). A file with one of these never needs a content check.
_WEB_EXTENSIONS = frozenset({
    ".html", ".htm", ".xhtml",
    ".jinja", ".jinja2", ".j2", ".twig", ".mustache", ".hbs", ".handlebars",
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".erb", ".ejs", ".njk", ".liquid",
    ".vue", ".svelte", ".astro",
    ".jsp", ".asp", ".aspx", ".cshtml", ".razor",
})

# Single source of truth for "does this file do web / HTTP-request-handling work?".
# Case-insensitive; matched against full file content.
_WEB_CONTEXT_RE = re.compile(
    r'(?:'
    # --- Python web frameworks (import / usage) ---
    r'\b(?:flask|django|fastapi|starlette|aiohttp|bottle|tornado|sanic'
    r'|falcon|pyramid|quart|cherrypy|web2py|werkzeug|webob|morepath|hug'
    r'|responder|masonite|django_ninja|ninja|flask_restful|flask_restx)\b'
    # --- Framework decorators / request-response machinery ---
    r'|@app\.(?:route|get|post|put|delete|patch|websocket|before_request'
    r'|after_request|errorhandler)'
    r'|@(?:router|bp|blueprint|api|application)\.(?:route|get|post|put|delete|patch)'
    r'|@require_(?:GET|POST|http_methods)'
    r'|\brender_template\b|\brender_template_string\b|\bjsonify\b|\burl_for\b'
    r'|\bmake_response\b|\bHttpResponse\b|\bJsonResponse\b|\bHttpResponseRedirect\b'
    r'|\bredirect\s*\(|\brequest\.(?:args|form|values|json|files|cookies|headers|GET|POST)'
    r'|\bsession\[|\bflash\s*\(|\babort\s*\(\s*\d'
    # --- WSGI / ASGI entrypoints ---
    r'|def\s+application\s*\(\s*environ|\bwsgi\b|\basgi\b|\bstart_response\b'
    r'|urlpatterns\b|INSTALLED_APPS\b|MIDDLEWARE\b'
    # --- JS / TS web frameworks (import/require-gated: bare words like `next`
    #     collide with the Python builtin and `express`/`react` appear in prose) ---
    r'|(?:require\(\s*|from\s+|import\s+[^;\n]*from\s+)["\']'
    r'(?:express|koa|hapi|fastify|@nestjs/[\w.-]+|next|nuxt|remix|sveltekit'
    r'|@angular/[\w.-]+|react-router|react-dom)["\']'
    r'|http\.createServer|app\.(?:get|post|put|delete|use|listen)\s*\('
    # --- Generic HTTP server / routing phrasing (web-anchored) ---
    r'|\brouter\b|\bendpoint\b|\bviewset\b'
    r'|\bhttp_response\b|\bhttp_request\b|\btemplate_string\b'
    r')',
    re.IGNORECASE,
)


def has_web_context(path, content: str) -> bool:
    """True when the file shows genuine web / HTTP-request-handling context.

    Used to gate web-vulnerability rules (SSTI / SSRF / open-redirect / basic-auth
    / eval-as-web / XXE / session / framework-specific) so their generic patterns
    do not fire on benign non-web code (compat shims, plain utility libraries).

    A web-native file extension (``.html`` / ``.jinja`` / ``.php`` / ``.vue`` /
    ...) is web by definition; otherwise we look for a web-framework import,
    request/response machinery, a WSGI/ASGI entrypoint, or JS web-framework use
    in the content. ``path`` may be a ``str`` or ``pathlib.Path`` (or ``None``,
    in which case only the content is consulted).
    """
    if path is not None:
        try:
            if Path(str(path)).suffix.lower() in _WEB_EXTENSIONS:
                return True
        except (TypeError, ValueError):
            pass

    if not content:
        return False

    return bool(_WEB_CONTEXT_RE.search(content))
