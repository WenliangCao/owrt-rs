#!/usr/bin/env python3
"""Check pending UCI apply ownership through the exact image HTTP bridge.

All network and filesystem writes stay in disposable Linux namespaces.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from r92_recovery_probe import message, write
from r92_compat_probe import Fixture, integer, string, response_data
from r93_rpcd_reconnect import Service


def inner(root, side, caller):
    fixture = Fixture(root, side, 'rpcd')
    service = None
    try:
        original = "config test 'section'\n option value 'before'\n"
        config = root / 'etc/config/v030owner'
        write(config, original)
        fixture.start_bus()
        service = Service(fixture)
        fixture.start_subject(obj='iwinfo')
        fixture.start('/usr/sbin/uhttpd', '-f', '-h', '/www', '-u', '/ubus',
                      '-p', '127.0.0.1:18888')

        def http_ready():
            try:
                with socket.create_connection(('127.0.0.1', 18888), timeout=0.1):
                    return True
            except OSError:
                return False

        assert fixture.wait(http_ready), 'exact image HTTP bridge did not start'
        client = fixture.connect()
        session, uci = client.lookup('session'), client.lookup('uci')

        def create():
            code, replies = client.invoke(session, 'create', integer('timeout', 60))
            assert code == 0
            return response_data(replies)[0][b'ubus_rpc_session']

        def grant(sid, scope, obj, function):
            pair = message('', 1, string('', obj) + string('', function))
            code, _ = client.invoke(session, 'grant', string('ubus_rpc_session', sid)
                                    + string('scope', scope) + message('objects', 1, pair))
            assert code == 0

        owner = create()
        other = create()
        grant(owner, 'uci', 'v030owner', 'write')
        for sid in (owner, other):
            grant(sid, 'ubus', 'uci', 'apply')
        other_args = string('ubus_rpc_session', other)
        code, replies = client.invoke(session, 'access', other_args + string('scope', 'uci')
                                      + string('object', 'v030owner') + string('function', 'write'))
        assert code == 0 and not response_data(replies)[0][b'access']
        owner_args = string('ubus_rpc_session', owner)
        change = owner_args + string('config', 'v030owner') + string('section', 'section')
        change += message('values', 2, string('value', 'after'))
        assert client.invoke(uci, 'set', change)[0] == 0
        assert client.invoke(uci, 'apply', owner_args + integer('timeout', 2)
                             + message('rollback', 7, b'\x01'))[0] == 0
        assert b'after' in config.read_bytes(), 'first apply never changed the config'
        sid = other if caller == 'other' else owner
        request = urllib.request.Request('http://127.0.0.1:18888/ubus',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'call',
                             'params': [sid.decode(), 'uci', 'apply', {'rollback': False}]}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3) as response:
            reply = json.load(response)
        status = reply['result'][0]
        run = root / ('var/run/rpcd' if side == 'original' else 'var/run/rpcd-rs')
        retained = (run / 'snapshot-files/v030owner').exists()
        time.sleep(2.5)
        restored = config.read_bytes() == original.encode()
        observed = {'side': side, 'caller': caller, 'http_reply': reply,
                    'snapshot_retained_after_request': retained, 'restored': restored,
                    'other_has_config_write': False, 'alive': fixture.subject.poll() is None}
        write(fixture.output / 'result.json', json.dumps(observed, indent=2) + '\n')
        print(json.dumps(observed), flush=True)
        if caller == 'owner':
            assert status == 0 and not retained and not restored, 'owner unchecked apply changed behavior'
        elif side == 'candidate':
            assert status == 6 and retained and restored, 'another session cancelled the pending rollback'
        else:
            assert status == 0 and not retained and not restored, 'reference behavior changed'
    finally:
        if service:
            service.close()
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inner':
        return inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--sides', nargs='+', choices=['original', 'candidate'], default=['candidate'])
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    assert os.geteuid() == 0 and sys.platform == 'linux' and args.repeat > 0
    args.output.mkdir(parents=True, exist_ok=False)
    failures = 0
    for side in args.sides:
        for caller in ['other', 'owner']:
            for repeat in range(args.repeat):
                destination = args.output / f'{side}-{caller}-{repeat}'
                with tempfile.TemporaryDirectory(prefix='v030-owner-') as temporary:
                    root = Path(temporary) / 'root'
                    # Preserve exact-image metadata and device nodes; copytree
                    # cannot copy special files from an extracted rootfs.
                    subprocess.run(['cp', '-a', str(args.rootfs), str(root)], check=True)
                    for directory in ['tmp/out', 'tmp/run/ubus', 'tmp/lock', 'tmp/state']:
                        (root / directory).mkdir(parents=True, exist_ok=True)
                    shutil.copy2(args.binary, root / 'tmp/rpcd-rs')
                    result = subprocess.run(['timeout', '-k', '3', '20', 'unshare', '--mount', '--net',
                        '--pid', '--fork', '--kill-child', sys.executable, str(Path(__file__).resolve()),
                        '--inner', str(root), side, caller], capture_output=True)
                    shutil.copytree(root / 'tmp/out', destination)
                    (destination / 'driver.log').write_bytes(result.stdout + result.stderr)
                    print(side, caller, repeat, result.returncode, result.stdout.decode(errors='replace'), flush=True)
                    failures += result.returncode != 0
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
