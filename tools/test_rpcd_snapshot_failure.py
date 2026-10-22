#!/usr/bin/env python3
"""All writes take place in an exact-image copy in private Linux namespaces."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from r92_recovery_probe import message, write
from r92_compat_probe import Fixture, integer, string, response_data
from r93_rpcd_reconnect import Service


def inner(root, side, fault):
    fixture = Fixture(root, side, 'rpcd')
    service = None
    try:
        config = root / 'etc/config/v030probe'
        first = root / 'etc/config/v030first'
        first_original = "config test 'section'\n option value 'first-before'\n"
        write(first, first_original)
        original = "config test 'section'\n option value 'before'\n option padding '" + 'x' * 9000 + "'\n"
        write(config, original)
        fixture.start_bus()
        service = Service(fixture)
        fixture.start_subject(obj='iwinfo')
        client = fixture.connect()
        session, uci = client.lookup('session'), client.lookup('uci')
        code, replies = client.invoke(session, 'create', integer('timeout', 60))
        assert code == 0
        sid = response_data(replies)[0][b'ubus_rpc_session']
        args = string('ubus_rpc_session', sid)
        pair = message('', 1, string('', 'v030*') + string('', 'write'))
        assert client.invoke(session, 'grant', args + string('scope', 'uci') + message('objects', 1, pair))[0] == 0
        change = args + string('config', 'v030probe') + string('section', 'section') + message('values', 2, string('value', 'after'))
        assert client.invoke(uci, 'set', change)[0] == 0
        change = args + string('config', 'v030first') + string('section', 'section') + message('values', 2, string('value', 'first-after'))
        assert client.invoke(uci, 'set', change)[0] == 0
        run = root / ('var/run/rpcd' if side == 'original' else 'var/run/rpcd-rs')
        snapshot = run / 'snapshot-files'
        # Session runtime names are independent of bearer tokens since 25.12.6.
        # This disposable fixture has exactly one session staging this package.
        candidates = [path for path in run.glob('uci-*') if (path / 'v030probe').is_file()]
        assert len(candidates) == 1, candidates
        delta = candidates[0]
        if side == 'candidate':
            assert delta.name != 'uci-' + sid.decode(), 'delta directory exposes the session token'
        before_delta = {p.name: p.read_bytes() for p in delta.iterdir()}
        limited = run / ('snapshot-delta' if fault == 'full-delta' else 'snapshot-files')
        if fault != 'healthy':
            limited.mkdir(parents=True, exist_ok=True)
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=4096', 'none', str(limited)], check=True)
        code, _ = client.invoke(uci, 'apply', args + integer('timeout', 2) + message('rollback', 7, b'\x01'))
        after_apply = config.read_bytes()
        first_after_apply = first.read_bytes()
        snapshot_path = snapshot / 'v030probe'
        snapshot_bytes = snapshot_path.read_bytes() if snapshot_path.exists() else b''
        time.sleep(2.5)
        final = config.read_bytes()
        first_final = first.read_bytes()
        observed = {'side': side, 'fault': fault, 'apply_code': code,
                    'original_bytes': len(original.encode()), 'snapshot_bytes': len(snapshot_bytes),
                    'after_apply_bytes': len(after_apply), 'final_bytes': len(final),
                    'modified': b'after' in after_apply, 'restored': final == original.encode(),
                    'first_unchanged': first_final == first_original.encode(),
                    'alive': fixture.subject.poll() is None}
        write(fixture.output / 'result.json', json.dumps(observed, indent=2) + '\n')
        print(json.dumps(observed), flush=True)
        if fault == 'healthy':
            assert code == 0 and observed['modified'] and observed['restored'] and observed['first_unchanged']
        elif side == 'candidate':
            assert code != 0, 'apply accepted an incomplete snapshot'
            assert first_after_apply == first_original.encode(), 'earlier package was committed before a later snapshot failed'
            assert after_apply == original.encode() and observed['restored'] and observed['first_unchanged']
            assert {p.name: p.read_bytes() for p in delta.iterdir()} == before_delta, 'failed apply consumed deltas'
            assert not service.events, 'failed apply emitted config.change'
            # Even a fresh unchecked apply must fail explicitly when the
            # implementation cannot make the snapshots it always creates.
            unchecked, _ = client.invoke(uci, 'apply', args + message('rollback', 7, b'\x00'))
            assert unchecked != 0 and config.read_bytes() == original.encode()
            assert first.read_bytes() == first_original.encode()
            assert {p.name: p.read_bytes() for p in delta.iterdir()} == before_delta
            assert not service.events
            subprocess.run(['umount', str(limited)], check=True)
            # No pending apply state may block the exact same session retry.
            code, _ = client.invoke(uci, 'apply', args + integer('timeout', 1) + message('rollback', 7, b'\x01'))
            assert code == 0 and b'after' in config.read_bytes()
            assert fixture.wait(lambda: config.read_bytes() == original.encode(), timeout=3)
            assert first.read_bytes() == first_original.encode()
            print('PASS: rejected incomplete batch, preserved deltas, retry and rollback recovered', flush=True)
    finally:
        if service:
            service.close()
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inner':
        return inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    parser = argparse.ArgumentParser()
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--sides', nargs='+', choices=['original', 'candidate'], default=['candidate'])
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    assert os.geteuid() == 0 and sys.platform == 'linux'
    assert args.repeat > 0
    args.output.mkdir(parents=True, exist_ok=False)
    for side in args.sides:
        for fault in ['healthy', 'full-files', 'full-delta']:
            for repeat in range(args.repeat):
                destination = args.output / f'{side}-{fault}-{repeat}'
                with tempfile.TemporaryDirectory(prefix='v030-rpcd-') as temporary:
                    root = Path(temporary) / 'root'
                    # Preserve exact-image metadata and device nodes; copytree
                    # cannot copy special files from an extracted rootfs.
                    subprocess.run(['cp', '-a', str(args.rootfs), str(root)], check=True)
                    for directory in ['tmp/out', 'tmp/run/ubus', 'tmp/lock', 'tmp/state']:
                        (root / directory).mkdir(parents=True, exist_ok=True)
                    shutil.copy2(args.binary, root / 'tmp/rpcd-rs')
                    result = subprocess.run(['timeout', '-k', '3', '30', 'unshare', '--mount', '--net', '--pid', '--fork', '--kill-child',
                                             sys.executable, str(Path(__file__).resolve()), '--inner', str(root), side, fault], capture_output=True)
                    shutil.copytree(root / 'tmp/out', destination)
                    (destination / 'driver.log').write_bytes(result.stdout + result.stderr)
                    print(side, fault, repeat, result.returncode, result.stdout.decode(errors='replace'), flush=True)
                    if result.returncode:
                        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
