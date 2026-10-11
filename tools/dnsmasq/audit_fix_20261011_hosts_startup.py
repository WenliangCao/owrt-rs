#!/usr/bin/env python3
"""Probe restored-lease helper ordering around ordinary-hosts startup publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    from m2_rootfs import image_elf_command, STOCK_SHA256
    from audit_20261011_dhcp import dns_answer
    stock = args.image_root / 'usr/sbin/dnsmasq'
    assert sha(stock) == STOCK_SHA256
    args.out.mkdir(parents=True, exist_ok=False)
    commands = {'c': image_elf_command(args.image_root, stock),
                'rust': image_elf_command(args.image_root, args.rust)}
    report = {'script_sha256': sha(__file__), 'c_sha256': sha(stock),
              'rust_sha256': sha(args.rust), 'cases': [], 'passed': False}
    for kind in ['normal-resolv', 'large-resolv', 'held-fifo']:
        rows = {}
        for side, command in commands.items():
            folder = args.out / (kind + '-' + side)
            folder.mkdir()
            events = folder / 'helper.jsonl'
            hook = folder / 'hook.py'
            hook.write_text('#!/usr/bin/python3\nimport os,sys,json,time\n'
                + f'with open({str(events)!r},"a") as f: '
                + 'f.write(json.dumps({"argv":sys.argv[1:],"env":dict(os.environ),'
                  '"monotonic_ns":time.monotonic_ns()},sort_keys=True)+"\\n")\n')
            hook.chmod(0o755)
            hosts = folder / 'hosts'
            hosts.write_text('127.0.0.30 authoritative-one.test\n127.0.0.31 authoritative-two.test\n')
            leases = folder / 'leases'
            initial = ('0 02:00:00:00:00:01 127.0.0.30 restored-one *\n'
                       '0 02:00:00:00:00:02 127.0.0.31 restored-two *\n')
            leases.write_text(initial)
            resolver = folder / 'resolv.conf'
            writer_state = {}
            thread = None
            if kind == 'held-fifo':
                os.mkfifo(resolver)
                def writer():
                    with resolver.open('wb', buffering=0) as stream:
                        writer_state['opened_monotonic_ns'] = time.monotonic_ns()
                        stream.write(b'nameserver 127.0.0.1\n')
                        time.sleep(.5)
                        # Closing a FIFO writer can trigger C's inotify reload
                        # before EVENT_INIT. Make subsequent opens finite too.
                        replacement = resolver.with_suffix('.ready')
                        replacement.write_bytes(b'nameserver 127.0.0.1\n')
                        replacement.replace(resolver)
                        writer_state['replaced_monotonic_ns'] = time.monotonic_ns()
                        writer_state['closing_monotonic_ns'] = time.monotonic_ns()
                thread = threading.Thread(target=writer, daemon=True)
                thread.start()
            else:
                resolver.write_bytes((b'#' + b'x' * 126 + b'\n') * (8192 if kind == 'large-resolv' else 0)
                                     + b'nameserver 127.0.0.1\n')
            argv = command + ['-C', '/dev/null', '-k', '--user=root', '--group=root',
                '--pid-file=', '--no-hosts', '--bind-interfaces', '--listen-address=127.0.0.1',
                '--port=15353', '--no-ping', '--dhcp-authoritative', '--domain=test',
                '--dhcp-range=127.0.0.30,127.0.0.31,255.0.0.0,infinite',
                '--addn-hosts=' + str(hosts), '--resolv-file=' + str(resolver),
                '--dhcp-leasefile=' + str(leases), '--dhcp-script=' + str(hook),
                '--log-facility=-', '--log-dhcp']
            log_path = folder / 'daemon.log'
            row = {'argv': argv, 'initial_leases': initial, 'hosts': hosts.read_text(),
                   'writer': writer_state}
            with log_path.open('wb') as log:
                proc = subprocess.Popen(argv, stdout=log, stderr=log,
                    env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
                try:
                    start = time.monotonic()
                    previous = None
                    stable_since = start
                    while time.monotonic() - start < 1.5 or time.monotonic() - stable_since < .4:
                        current = events.read_text() if events.exists() else ''
                        if current != previous:
                            previous, stable_since = current, time.monotonic()
                        if proc.poll() is not None:
                            raise AssertionError(log_path.read_text())
                        if time.monotonic() - start > 8:
                            raise AssertionError('helper callbacks failed to settle')
                        time.sleep(.01)
                    row['callbacks_before_stop'] = [json.loads(line) for line in events.read_text().splitlines()]
                    closed = writer_state.get('closing_monotonic_ns')
                    row['callbacks_before_resolver_close'] = (
                        sum(event['monotonic_ns'] < closed for event in row['callbacks_before_stop'])
                        if closed is not None else None)
                    row['leases_before_stop'] = leases.read_text()
                    row['dns'] = {name: dns_answer(name, 1) for name in ['authoritative-one.test', 'authoritative-two.test']}
                    row['alive_before_stop'] = proc.poll() is None
                    # Explicit musl invocation makes libc.so the C process's
                    # /proc/exe; the target C ELF hash is recorded separately.
                    row['proc_exe_sha256'] = sha(Path(f'/proc/{proc.pid}/exe'))
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait()
                    row['exit'] = proc.returncode
                    if thread:
                        thread.join(timeout=1)
                        if thread.is_alive():
                            raise AssertionError('FIFO producer remained blocked')
            row['log'] = log_path.read_text()
            (folder / 'observed.json').write_text(json.dumps(row, indent=2) + '\n')
            rows[side] = row
        def semantic(row):
            events = [{k: v for k, v in r.items() if k != 'monotonic_ns'} for r in row['callbacks_before_stop']]
            # Infinite leases remove expiry-clock ambiguity. Preserve all env.
            return {'callbacks': events, 'leases': sorted(row['leases_before_stop'].splitlines()), 'dns': row['dns'],
                    'callbacks_before_resolver_close': row['callbacks_before_resolver_close'],
                    'alive': row['alive_before_stop'], 'exit': row['exit']}
        report['cases'].append({'id': kind, 'matched': semantic(rows['c']) == semantic(rows['rust']),
                                'observed': rows})
        (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    report['passed'] = all(row['matched'] for row in report['cases'])
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': [{
        'id': row['id'], 'matched': row['matched'],
        'callbacks': {side: [r['argv'] for r in value['callbacks_before_stop']]
                      for side, value in row['observed'].items()}}
        for row in report['cases']]}, indent=2))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
