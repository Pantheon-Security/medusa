"""PR-007: 'could not vet' is an ERROR (exit 3, no VERDICT line), never a CAUTION verdict."""
from click.testing import CliRunner
import medusa.cli as cli
import medusa.core.scan_api as sa


def test_unresolvable_target_is_error_exit_3():
    # A bare non-path, non-URL string can't be a local path or a git URL -> ERROR.
    r = CliRunner(mix_stderr=False).invoke(cli.main, ['vet', 'not-a-real-target-xyz'])
    assert r.exit_code == 3, f"expected exit 3 (ERROR), got {r.exit_code}"
    assert 'VERDICT' not in r.stdout                 # never dress an error as a verdict
    assert 'ERROR' in r.stderr                       # error goes to stderr


def test_error_verdict_constant_distinct():
    assert sa.ERROR == 'ERROR'
    assert sa.ERROR not in (sa.SAFE, sa.CAUTION, sa.DO_NOT_INSTALL)
