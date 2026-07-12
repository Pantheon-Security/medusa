"""Gate: the plugin scanner skips minified/bundled files (not user plugins).

Corpus FP: PLG009 (CRITICAL) fired on a vendored, minified highlight.js line in
mdBook (a doc tool) -> DO_NOT_INSTALL on benign normal code. A 10k-char minified
line matches almost any pattern. Two-sided: minified bundle -> no PLG findings; a
real hand-written insecure plugin -> still fires.
"""
from pathlib import Path
from medusa.scanners.plugin_security_scanner import PluginSecurityScanner


def _issues(content, name="x.js"):
    return PluginSecurityScanner().scan(Path(name), content=content).issues


def test_minified_bundle_is_skipped():
    # one > 1000-char line (a minified bundle) that mentions plugin/exec/tool
    minified = "var plugin=function(e){" + "a();" * 400 + "exec(x);tool_input=request;return e};"
    assert max(len(l) for l in minified.split("\n")) > 1000
    assert _issues(minified) == []


def test_real_insecure_plugin_still_fires():
    code = (
        "def execute_plugin(cmd):\n"
        "    tool_input = request.args\n"
        "    os.system(cmd)\n"
    )
    assert len(_issues(code)) > 0
