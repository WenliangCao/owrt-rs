#!/usr/bin/env python3
"""Transient rollback write failures in disposable exact-image namespaces."""
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
        config = root / 'etc/config/v030restore'
        original = b"config test 'section'\n option value 'before'\n option padding '" + b'x' * 9000 + b"'\n"
        config.write_bytes(original)
        config.chmod(0o640)
        fixture.start_bus()
        service = Service(fixture)
        fixture.start_subject(obj='iwinfo')
        client = fixture.connect()
        session, uci = client.lookup('session'), client.lookup('uci')
        status, replies = client.invoke(session, 'create', integer('timeout', 60))
        assert status == 0
        sid = response_data(replies)[0][b'ubus_rpc_session']
        args = string('ubus_rpc_session', sid)
        pair = message('', 1, string('', 'v030restore') + string('', 'write'))
        assert client.invoke(session, 'grant', args + string('scope', 'uci') + message('objects', 1, pair))[0] == 0
        change = args + string('config', 'v030restore') + string('section', 'section') + message('values', 2, string('value', 'after'))
        assert client.invoke(uci, 'set', change)[0] == 0
        assert client.invoke(uci, 'delete', args + string('config', 'v030restore') + string('section', 'section') + string('option', 'padding'))[0] == 0
        run = root / ('var/run/rpcd' if side == 'original' else 'var/run/rpcd-rs')
        # Session runtime names are independent of bearer tokens since 25.12.6.
        # This disposable fixture has exactly one session staging this package.
        candidates = [path for path in run.glob('uci-*') if (path / 'v030restore').is_file()]
        assert len(candidates) == 1, candidates
        delta = candidates[0]
        if side == 'candidate':
            assert delta.name != 'uci-' + sid.decode(), 'delta directory exposes the session token'
        assert client.invoke(uci, 'apply', args + integer('timeout', 2) + message('rollback', 7, b'\x01'))[0] == 0
        assert b'after' in config.read_bytes()
        assert fixture.wait(lambda: len(service.events) == 1)
        snapshot = run / 'snapshot-files/v030restore'
        if fault == 'cancel':
            if side == 'candidate':
                # The existing cross-session protection must remain intact.
                other_status, other_replies = client.invoke(session, 'create', integer('timeout', 60))
                assert other_status == 0
                other = response_data(other_replies)[0][b'ubus_rpc_session']
                assert client.invoke(uci, 'apply', string('ubus_rpc_session', other))[0] == 6
                assert snapshot.exists()
            # The owner may make its pending apply permanent. This removes the
            # snapshots; the retry path must not mistake it for a storage fault.
            assert client.invoke(uci, 'apply', args)[0] == 0
            time.sleep(2.4)
            commit_code = client.invoke(uci, 'commit', args + string('config', 'v030restore'))[0]
            confirm_code = client.invoke(uci, 'confirm', args)[0]
            observations = {'side': side, 'fault': fault, 'commit_code': commit_code,
                            'confirm_code': confirm_code, 'alive': fixture.subject.poll() is None}
            write(fixture.output / 'result.json', json.dumps(observations, indent=2) + '\n')
            print(json.dumps(observations), flush=True)
            assert commit_code == 0 and confirm_code == 5 and observations['alive']
            return
        saved_delta = (run / 'snapshot-delta/v030restore').read_bytes()
        expected_owners = None
        link_target = None
        applied = config.read_bytes()
        if fault == 'ownership':
            # Change installed ownership after apply to isolate restoration
            # from UCI commit's separate file-replacement behavior.
            expected_owners = [(12345, 23456), (34567, 45678)]
            os.chown(config, *expected_owners[0])
            os.chown(delta / 'v030restore', *expected_owners[1])
        elif fault == 'dangling':
            link_target = config.with_name('v030restore-target')
            config.unlink()
            config.symlink_to(link_target.name)
        # A bind mount changes only this namespace, leaving the base image intact.
        target = delta if fault.startswith('delta') else config.parent
        if fault == 'full':
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=4096', 'none', str(target)], check=True)
            config.write_bytes(applied)
            config.chmod(0o640)
        elif fault not in ('healthy', 'ownership', 'dangling'):
            subprocess.run(['mount', '--bind', str(target), str(target)], check=True)
            subprocess.run(['mount', '-o', 'remount,bind,ro', str(target)], check=True)
        rollback_code = None
        if fault == 'manual':
            rollback_code = client.invoke(uci, 'rollback', args)[0]
        else:
            time.sleep(2.4)
        retained = snapshot.exists() and snapshot.read_bytes() == original
        during = config.read_bytes() if config.exists() else None
        link_retained = config.is_symlink()
        finalize_code = None
        retained_after_finalize = None
        events_during_fault = len(service.events)
        if fault in ('delta-cancel', 'delta-confirm'):
            method = 'apply' if fault == 'delta-cancel' else 'confirm'
            finalize_code = client.invoke(uci, method, args)[0]
            retained_after_finalize = snapshot.exists() and snapshot.read_bytes() == original
        if fault == 'full':
            # Make the same filesystem writable without hiding a partial copy.
            subprocess.run(['mount', '-o', 'remount,size=1048576', str(target)], check=True)
        elif fault not in ('healthy', 'ownership', 'dangling'):
            subprocess.run(['umount', str(target)], check=True)
        if link_target is not None:
            link_target.write_bytes(applied)
            link_target.chmod(0o640)
        recovered = fixture.wait(lambda: config.read_bytes() == original and not snapshot.exists(), timeout=4)
        delta_restored = (delta / 'v030restore').read_bytes() == saved_delta
        notified = fixture.wait(lambda: len(service.events) == 2, timeout=2)
        actual_owners = [(p.stat().st_uid, p.stat().st_gid) for p in [config, delta / 'v030restore']]
        observations = {'side': side, 'fault': fault, 'rollback_code': rollback_code,
                        'expected_owners': expected_owners, 'actual_owners': actual_owners,
                        'link_retained_during_fault': link_retained, 'link_retained_after_restore': config.is_symlink(),
                        'link_target_restored': link_target.read_bytes() == original if link_target else None,
                        'snapshot_retained_on_error': retained, 'during_original': during == original,
                        'finalize_code': finalize_code, 'snapshot_retained_after_finalize': retained_after_finalize,
                        'events_during_fault': events_during_fault, 'notified_after_restore': notified,
                        'recovered_after_fault': recovered, 'delta_restored': delta_restored,
                        'permissions': config.stat().st_mode & 0o777,
                        'alive': fixture.subject.poll() is None}
        write(fixture.output / 'result.json', json.dumps(observations, indent=2) + '\n')
        print(json.dumps(observations), flush=True)
        if side == 'candidate':
            if fault not in ('healthy', 'ownership'):
                assert retained, 'rollback discarded its only snapshot after a failed restore'
            if fault == 'manual':
                assert rollback_code != 0, 'manual rollback reported success after failed restore'
            if fault == 'full':
                assert during == applied, 'failed copy truncated the currently installed config'
            if fault in ('delta-cancel', 'delta-confirm'):
                assert during == original and events_during_fault == 1, 'fixture missed partial rollback'
                assert finalize_code != 0, 'owner finalized a partially restored apply'
                assert retained_after_finalize, 'owner discarded the pending recovery snapshot'
            if fault == 'ownership':
                assert actual_owners == expected_owners, 'rollback changed existing file ownership'
            if fault == 'dangling':
                assert during is None and link_retained and config.is_symlink(), 'rollback replaced a dangling symlink'
                assert link_target.read_bytes() == original, 'rollback failed to restore the symlink target'
            assert recovered and delta_restored and notified and observations['alive']
            assert observations['permissions'] == 0o640
            assert client.invoke(uci, 'confirm', args)[0] == 5, 'rollback timer/owner was not cleared'
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
    parser.add_argument('--faults', nargs='+', choices=['healthy', 'manual', 'timer', 'delta', 'full', 'cancel', 'delta-cancel', 'delta-confirm', 'ownership', 'dangling'], default=['healthy', 'manual', 'timer', 'delta', 'full', 'delta-cancel', 'delta-confirm', 'ownership', 'dangling'])
    args = parser.parse_args()
    assert os.geteuid() == 0 and sys.platform == 'linux' and args.repeat > 0
    args.output.mkdir(parents=True, exist_ok=False)
    failures = []
    for side in args.sides:
        for fault in args.faults:
            for repeat in range(args.repeat):
                destination = args.output / f'{side}-{fault}-{repeat}'
                with tempfile.TemporaryDirectory(prefix='v030-restore-') as temporary:
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
                        failures.append(destination.name)
    (args.output / 'failures.json').write_text(json.dumps(failures) + '\n')
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
