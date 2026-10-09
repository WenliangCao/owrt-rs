#!/usr/bin/env python3
"""Exact-image CLI broken-pipe regression in disposable Linux namespaces.

The parent closes the pipe's read end before spawning the writer. Both SIG_IGN
and SIG_DFL are installed immediately before exec (Popen restore_signals=False).
Every row compares stdout/stderr bytes and shell-visible status, retaining raw
wait status so a shell wrapper's 141 cannot hide an ELF's SIGPIPE termination.
No physical router is used. Core dumps are disabled before exec.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

from r92_compat_probe import Fixture

CASES = [
    ('fw4-network', 'fw4', ['-q', 'network', 'wan6']),
    ('fw4-device', 'fw4', ['device', 'eth1']),
    ('fw4-zone', 'fw4', ['zone', 'wan']),
    ('fw4-zone-device', 'fw4', ['zone', 'wan', 'eth1']),
    ('fw4-missing-zone', 'fw4', ['zone', 'missing']),
    ('fw4-usage', 'fw4', ['usage']),
    ('fw4-print', 'fw4', ['print']),
    ('fw4-print-no-bus', 'fw4', ['print']),
    ('fw4-check', 'fw4', ['check']),
    ('fw4-check-output', 'fw4', ['-v', 'check']),
    ('fw4-reload-sets-output', 'fw4', ['-v', 'reload-sets']),
    ('fw4-quiet-check', 'fw4', ['-q', 'check']),
    ('fw4-reload-sets', 'fw4', ['reload-sets']),
    ('fw4-start-nft-early', 'fw4', ['start']),
    ('fw4-reload-nft-early', 'fw4', ['reload']),
    ('fw4-restart-nft-early', 'fw4', ['restart']),
    ('fw4-check-nft-early', 'fw4', ['check']),
    ('fw4-restart-abort', 'fw4', ['restart']),
    ('fw4-start-clean', 'fw4', ['start']),
    ('fw4-start-output', 'fw4', ['-v', 'start']),
    ('fw4-reload', 'fw4', ['reload']),
    ('fw4-restart', 'fw4', ['restart']),
    ('fw4-stop', 'fw4', ['stop']),
    ('fw4-flush', 'fw4', ['flush']),
    ('fw4-includes', 'fw4', ['includes']),
    ('fw4-already-started', 'fw4', ['start']),
    ('fw4-missing-state', 'fw4', ['network', 'wan6']),
    ('uci-add', 'uci', ['add', 'health', 'health']),
    ('uci-get', 'uci', ['get', 'health.entry.value']),
    ('uci-show', 'uci', ['show', 'health']),
    ('uci-export', 'uci', ['export', 'health']),
    ('uci-changes', 'uci', ['changes', 'health']),
    ('uci-help', 'uci', ['help']),
    ('uci-unknown-option', 'uci', ['-z']),
    ('uci-missing-argument', 'uci', ['-c']),
    ('uci-not-found', 'uci', ['get', 'missing.entry.value']),
    ('uci-parse-error', 'uci', ['show', 'broken']),
]
IDENTITIES = ('sbin/fw4', 'usr/bin/ucode', 'bin/busybox', 'sbin/uci')
EXPECTED_STOCK = {
    'sbin/fw4': 'c240b413a4cf80617ac1a71f601d2e0edae46b0493e3c00fbe883b2446e4a1a6',
    'usr/bin/ucode': '51b711c8e0016ddde3998ce66e23b387f9e57417c40f3c2c40f2694be5e29450',
    'bin/busybox': '54d4139265132254e5601cb65d8617a928d5d5867c044ef701d53b973daafe09',
    'sbin/uci': '050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observe(root, command, closed, disposition):
    def before_exec():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGPIPE, signal.SIG_IGN if disposition == 'ignore' else signal.SIG_DFL)

    write_fd = None
    if closed != 'none':
        read_fd, write_fd = os.pipe()
        os.close(read_fd)  # Must happen before the child can write, never head(1).
    try:
        completed = subprocess.run(
            ['chroot', str(root), *command], stdin=subprocess.DEVNULL,
            stdout=write_fd if closed == 'stdout' else subprocess.PIPE,
            stderr=write_fd if closed == 'stderr' else subprocess.PIPE,
            preexec_fn=before_exec, restore_signals=False, timeout=8,
        )
    finally:
        if write_fd is not None:
            os.close(write_fd)
    result = {'wait_status': completed.returncode,
              'shell_status': completed.returncode if completed.returncode >= 0 else 128 - completed.returncode}
    for stream in ('stdout', 'stderr'):
        data = getattr(completed, stream)
        result[stream + '_hex'] = data.hex() if data is not None else None
        result[stream + '_sha256'] = hashlib.sha256(data).hexdigest() if data is not None else None
    return result


def inner(root, rounds, side):
    fixture = Fixture(root, 'original', 'fw4')
    try:
        # Only nft execution is replaced. Rendering, ucode, libc, the shell and
        # ubus server are the exact image; the namespace owns all kernel state.
        nft = root / 'usr/sbin/nft'
        nft.unlink()
        nft.write_text('#!/bin/sh\ncase " $* " in *" --json "*) printf \'{"nftables":[]}\\n\';; *" -f "*) [ -e /tmp/nft-early ] && exit 7; cat >/dev/null;; esac\ncase " $* " in *" -e "*) echo nft-sentinel;; esac\nexit 0\n')
        nft.chmod(0o755)
        fixture.start_bus()
        defaults = "config defaults\n option input 'ACCEPT'\n option output 'ACCEPT'\n option forward 'DROP'\n option auto_includes '0'\n"
        rows = []
        for repeat in range(rounds):
            for name, component, arguments in CASES:
                for closed in ('none', 'stdout', 'stderr'):
                    for disposition in ('ignore', 'default'):
                        early = root / 'tmp/nft-early'
                        early.unlink(missing_ok=True)
                        config = defaults
                        if name.endswith('nft-early'):
                            early.touch()
                            # More than a pipe buffer: deterministic EPIPE when
                            # the nft child exits without ever reading stdin.
                            config += ''.join(f"config rule\n option name 'rule{i}'\n option proto 'tcp'\n option dest_port '{10000+i}'\n option target 'ACCEPT'\n" for i in range(512))
                        if name == 'fw4-restart-abort':
                            config = "config defaults\n option input 'INVALID'\n"
                        (root / 'etc/config/firewall').write_text(config)
                        state = root / 'tmp/run/fw4.state'
                        state.write_text(json.dumps({'zones': [{'name': 'wan', 'network': [{'device': 'wan6'}], 'match_rules': [{'devices_pos': ['eth1', 'eth2']}]}], 'ipsets': [], 'includes': []}))
                        if name in ('fw4-missing-state', 'fw4-start-clean', 'fw4-start-output', 'fw4-start-nft-early'):
                            state.unlink()
                        if name == 'fw4-includes':
                            state.write_text(json.dumps({'zones': [], 'ipsets': [], 'includes': [{'type': 'script', 'path': '/tmp/health-include.sh'}]}))
                            (root / 'tmp/health-include.sh').write_text('echo include-sentinel\n')
                        (root / 'etc/config/health').write_text("config health 'entry'\n option value 'hello'\n")
                        (root / 'etc/config/broken').write_text("config 'unterminated\n")
                        delta = root / 'tmp/.uci'
                        if delta.exists():
                            shutil.rmtree(delta)
                        delta.mkdir()
                        if name == 'uci-changes':
                            (delta / 'health').write_text("health.entry.value='changed'\n")
                        socket = root / 'tmp/run/ubus/ubus.sock'
                        hidden = socket.with_name('hidden.sock')
                        if name == 'fw4-print-no-bus':
                            socket.rename(hidden)
                        try:
                            command = ['/sbin/' + component, *arguments]
                            if name == 'fw4-includes' and side == 'stock':
                                command = ['/bin/busybox', 'env', 'ACTION=includes', '/usr/bin/utpl', '-S', '/usr/share/firewall4/main.uc']
                            row = observe(root, command, closed, disposition)
                        finally:
                            if hidden.exists():
                                hidden.rename(socket)
                        row['stderr_compared_hex'] = row['stderr_hex']
                        if name == 'fw4-restart-abort' and closed != 'stderr':
                            # Existing compatibility policy: preserve the raw
                            # ucode interpreter traceback, compare the wrapper's
                            # operational warning without fabricating that trace.
                            warning = b'The rendered ruleset contains errors, not doing firewall restart.\n'
                            data = bytes.fromhex(row['stderr_hex'])
                            assert data.endswith(warning), row
                            row['stderr_compared_hex'] = warning.hex()
                        row.update(case=name, repeat=repeat + 1, closed=closed, sigpipe=disposition)
                        rows.append(row)
        (root / 'tmp/out/observations.json').write_text(json.dumps(rows, indent=2) + '\n')
    finally:
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inner':
        inner(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('bins', type=Path, help='directory with fw4-rs and uci-rs')
    parser.add_argument('output', type=Path)
    parser.add_argument('--rounds', type=int, default=4)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    if os.geteuid() != 0 or sys.platform != 'linux':
        parser.error('run as root on Linux (normally sudo -n)')
    stock = {path: digest(args.rootfs / path) for path in IDENTITIES}
    assert stock == EXPECTED_STOCK, ('not the pinned OpenWrt 25.12.5 oracle', stock)
    args.output.mkdir(parents=True, exist_ok=False)
    observed = {}
    candidates = {component: digest(args.bins / (component + '-rs')) for component in ('fw4', 'uci')}
    for side in ('stock', 'candidate'):
        with tempfile.TemporaryDirectory(prefix='health-cli-') as temporary:
            root = Path(temporary) / 'root'
            shutil.copytree(args.rootfs, root, symlinks=True)
            for directory in ('out', 'run/ubus', 'lock', 'state'):
                (root / 'tmp' / directory).mkdir(parents=True, exist_ok=True)
            if side == 'candidate':
                for component in candidates:
                    shutil.copy2(args.bins / (component + '-rs'), root / 'sbin' / component)
            command = ['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child', sys.executable, str(Path(__file__).resolve()), '--inner', str(root), str(args.rounds), side]
            with (args.output / (side + '.log')).open('wb') as log:
                subprocess.run(command, stdout=log, stderr=log, timeout=300, check=True)
            observed[side] = json.loads((root / 'tmp/out/observations.json').read_text())
    assert all(len(rows) == args.rounds * len(CASES) * 6 for rows in observed.values())
    sentinels = {
        'fw4-network': b'wan\n', 'fw4-device': b'wan\n',
        'fw4-zone': b'eth1\neth2\n', 'fw4-zone-device': b'eth1\n',
        'fw4-check': b'Ruleset passes nftables check.\n',
        'fw4-includes': b'include-sentinel\n', 'uci-get': b'hello\n',
    }
    for rows in observed.values():
        for row in rows:
            if row['closed'] == 'none' and row['case'] in sentinels:
                assert bytes.fromhex(row['stdout_hex']) == sentinels[row['case']], row
            if row['closed'] == 'none' and row['case'] in ('fw4-print', 'fw4-print-no-bus'):
                assert b'table inet fw4' in bytes.fromhex(row['stdout_hex']), row
    rows = []
    for stock_row, candidate in zip(observed['stock'], observed['candidate'], strict=True):
        key = ('case', 'repeat', 'closed', 'sigpipe')
        assert all(stock_row[k] == candidate[k] for k in key)
        different = [k for k in ('shell_status', 'stdout_hex', 'stderr_compared_hex') if stock_row[k] != candidate[k]]
        rows.append({**{k: stock_row[k] for k in key}, 'passed': not different, 'different': different,
                     'stock': stock_row, 'candidate': candidate})
    result = {'stock_sha256': stock, 'candidate_sha256': candidates, 'rounds': args.rounds,
              'comparison': 'exact stdout and operational stderr bytes + shell status; raw wait/stderr retained; restart-abort excludes only the existing ucode interpreter traceback',
              'passed': all(row['passed'] for row in rows), 'rows': rows}
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    failed = sorted(set(row['case'] for row in rows if not row['passed']))
    print(json.dumps({'rows': len(rows), 'failed_cases': failed, 'passed': result['passed']}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
