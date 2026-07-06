"""PR-006: medusa vet prints a progress heartbeat to STDERR only; stdout stays the verdict."""
from click.testing import CliRunner
import medusa.cli as cli
import medusa.core.scan_api as sa


def _fake_vet_repo(target, allow=None):
    return {'verdict': 'SAFE', 'score': 0, 'blocking_findings': 0,
            'total_findings': 0, 'other_findings': 0, 'top_findings': []}


def test_progress_to_stderr_verdict_to_stdout(monkeypatch):
    monkeypatch.setattr(sa, 'vet_repo', _fake_vet_repo)
    r = CliRunner(mix_stderr=False).invoke(cli.main, ['vet', '/some/path'])
    assert 'VERDICT' in r.stdout
    assert 'Vetting' not in r.stdout
    assert 'Vetting' in r.stderr


def test_json_mode_has_no_progress_line(monkeypatch):
    monkeypatch.setattr(sa, 'vet_repo', _fake_vet_repo)
    r = CliRunner(mix_stderr=False).invoke(cli.main, ['vet', '/some/path', '--json'])
    assert 'Vetting' not in r.stdout
    assert r.stdout.lstrip().startswith('{')
