"""Real Linux file recovery, confined to pytest-owned temporary files."""
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

from scripts import capture_snapshot as collector
from sentinel.snapshots import parse_snapshot, compare
from sentinel.recovery import plan

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Requires actual Linux and GNU tools')
builder = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'fixtures/build_snapshot_demo.py'))


@pytest.mark.parametrize('case', ['restore', 'stale', 'wrong_host', 'mode_changed', 'symlink'])
def test_linux_file_recovery(tmp_path, case):
    for tool in ('bash', 'realpath', 'stat', 'sha256sum', 'mktemp', 'cp', 'base64', 'mv'):
        if not shutil.which(tool):
            pytest.skip(f'Required GNU/Linux tool unavailable: {tool}')
    target = tmp_path / "safe' config.conf"
    original = "Port=443\nLiteral=$(touch never-execute)\nUnicode=café\n"
    current = b'Port=4444\n'
    target.write_bytes(original.encode())
    target.chmod(0o600)
    old = collector.files([str(target)], True)
    target.write_bytes(current)
    new = collector.files([str(target)], True)
    a, b = builder['snapshots']()
    for value, items in ((a, old), (b, new)):
        value['host']['id'] = 'b' * 64 if case == 'wrong_host' else collector.host_id()
        value['sections']['files']['items'] = items
    left = parse_snapshot(json.dumps(a).encode(), source_file='before.json', upload_id='before')
    right = parse_snapshot(json.dumps(b).encode(), source_file='after.json', upload_id='after')
    _, changes = compare(left, right)
    change = next(c for c in changes if c['category'] == 'files' and c['field'] == 'sha256')
    recovery = plan(change, left, right, baseline_trusted=True)
    assert recovery['status'] == 'ready_for_manual_review'
    if case == 'stale':
        target.write_bytes(b'changed again')
    if case == 'mode_changed':
        target.chmod(0o640)
    if case == 'symlink':
        other = tmp_path / 'other.conf'
        other.write_bytes(current)
        target.unlink()
        target.symlink_to(other)
    expected = target.read_bytes()
    result = subprocess.run(['bash', '-c', recovery['script']], cwd=tmp_path,
                            capture_output=True, timeout=15)
    backups = list(tmp_path.glob('*.sentinel-backup.*'))
    if case == 'restore':
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        assert target.read_bytes() == original.encode()
        assert len(backups) == 1 and backups[0].read_bytes() == current
        fields = collector.files([str(target)], False)[0]['values']
        assert all(fields[key] == new[0]['values'][key] for key in ('mode', 'uid', 'gid'))
        assert not (tmp_path / 'never-execute').exists()
    else:
        assert result.returncode != 0
        assert target.read_bytes() == expected
        assert not backups
    assert not list(tmp_path.glob('*.sentinel-temp.*'))
