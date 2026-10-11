#!/usr/bin/env python3
"""Configured-record diagnostics; retain full dump order and scoped differences."""
import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

CASES = [
    ('orphan-cname', ['--cname=alias.test,missing.test']),
    ('resolved-cname', ['--host-record=target.test,192.0.2.42', '--cname=alias.test,target.test']),
    ('chain-cname', ['--host-record=target.test,192.0.2.42', '--cname=middle.test,target.test', '--cname=alias.test,middle.test']),
    ('configured-dns', ['--host-record=target.test,192.0.2.42,2001:db8::42', '--address=/suffix.test/192.0.2.43', '--mx-host=mx.test,target.test,10', '--txt-record=txt.test,hello']),
    ('literal-address', ['--host-record=target.test,::192.0.2.42']),
]
SEPARATOR = '------------------------------ ---------------------------------------- ---------- ------------------------ ------------'


def dump_rows(log):
    """Only remove the process-specific syslog prefix; keep row bytes/order."""
    messages = [re.sub(r'^dnsmasq\[\d+\]: ', '', line) for line in log.splitlines()]
    assert messages.count(SEPARATOR) == 1, 'exactly one completed dump required'
    start = messages.index(SEPARATOR) + 1
    rows = []
    for line in messages[start:]:
        if line.startswith('exiting on receipt of '):
            break
        assert len(line) >= 107 and line[30] == line[71] == line[82] == ' ', repr(line)
        rows.append(dict(raw=line, name=line[:30].rstrip(), address=line[31:71].rstrip(),
                         flags=line[72:82], expires=line[83:107], source=line[107:]))
    return rows


def declared_rows(flags):
    names, count = set(), 0
    for flag in flags:
        if flag.startswith('--cname='):
            parts = flag.split('=', 1)[1].split(',')
            names.update(parts[:-1])
            count += len(parts) - 1
        elif flag.startswith('--host-record='):
            hosts, addresses = [], []
            for token in flag.split('=', 1)[1].split(','):
                try:
                    addresses.append(ipaddress.ip_address(token))
                except ValueError:
                    hosts.append(token)
            names.update(hosts)
            count += len(hosts) * len(addresses)
    return names, count


def comparison(flags, observations):
    names, count = declared_rows(flags)
    rows = {side: dump_rows(obs['log']) for side, obs in observations.items()}
    explicit = {side: [row for row in value if row['name'] in names] for side, value in rows.items()}
    others = {side: [row for row in value if row['name'] not in names] for side, value in rows.items()}
    raw = {side: [row['raw'] for row in value] for side, value in rows.items()}
    selected = {side: [row['raw'] for row in value] for side, value in explicit.items()}
    errors = []
    if not all(obs['alive_after_dump'] and obs['exit'] == 0 for obs in observations.values()):
        errors.append('daemon did not survive dump and exit normally')
    if any(len(value) != count for value in explicit.values()):
        errors.append('declared record row count differs')
    # Rows are preserved in their original order. Only this explicitly scoped
    # field/content gate uses a multiset; C hash iteration is not replicated.
    if Counter(selected['c']) != Counter(selected['rust']):
        errors.append('declared record row text or multiplicity differs')
    if any(row['flags'][0] != '!' or row['address'] for value in others.values() for row in value):
        errors.append('unexpected undeclared non-placeholder row')
    differences = []
    if others['c'] != others['rust']:
        differences.append(dict(kind='internal-nonterminal-rows', c=others['c'], rust=others['rust']))
    if selected['c'] != selected['rust'] and Counter(selected['c']) == Counter(selected['rust']):
        differences.append(dict(kind='declared-row-order', c=selected['c'], rust=selected['rust']))
    if raw['c'] != raw['rust']:
        differences.append(dict(kind='full-row-sequence', c=raw['c'], rust=raw['rust']))
    return dict(r4_passed=not errors, errors=errors, expected_declared_rows=count,
                all_rows_equal=raw['c'] == raw['rust'],
                declared_sequence_equal=selected['c'] == selected['rust'],
                rows=rows, declared_rows=explicit, other_rows=others,
                scope_difference=differences)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'image', 'rust', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-revision', help='frozen product revision, if source is an export')
    parser.add_argument('--require-match', action='store_true',
                        help='require R4 declared row content/count match; full table and ordering differences remain explicit')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    from m2_rootfs import prepare, command, sha256
    args.out.mkdir(exist_ok=False)
    root = prepare(args.image, None, args.out, args.rust)
    base = ['-C', '/dev/null', '-k', '--user=root', '--group=root', '--pid-file=',
            '--no-hosts', '--no-resolv', '--port=15353', '--listen-address=127.0.0.1',
            '--bind-interfaces', '--log-facility=-', '--log-queries']
    rows = []
    for name, flags in CASES:
        observations = {}
        for side in ('c', 'rust'):
            log = args.out / f'{name}-{side}.log'
            with log.open('wb') as output:
                argv = command(root, side, *base, *flags)
                process = subprocess.Popen(argv, stdout=output, stderr=output)
                try:
                    time.sleep(.12)
                    process.send_signal(signal.SIGUSR1)
                    time.sleep(.12)
                    alive = process.poll() is None
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=3)
            observations[side] = dict(argv=argv, alive_after_dump=alive,
                                      exit=process.returncode, log=log.read_text())
        rows.append(dict(case=name, flags=flags, result=observations,
                         comparison=comparison(flags, observations)))
    result = dict(source_revision=args.source_revision,
                  sha256=dict(c=sha256(root / 'usr/sbin/dnsmasq'), rust=sha256(args.rust), tool=sha256(Path(__file__))),
                  scope='R4 explicit host-record flags and configured CNAME Source; internal nonterminal/hash ordering differences retained, not qualified',
                  rows=rows, r4_passed=all(row['comparison']['r4_passed'] for row in rows),
                  all_rows_equal=all(row['comparison']['all_rows_equal'] for row in rows))
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return int(args.require_match and not result['r4_passed'])


if __name__ == '__main__':
    raise SystemExit(main())
