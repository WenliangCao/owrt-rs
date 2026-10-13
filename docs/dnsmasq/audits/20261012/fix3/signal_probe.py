#!/usr/bin/env python3
"""Exact-image signal repair confirmation, including lease write failure recovery."""
import argparse
import json
import os
from pathlib import Path
import signal
import sys

p = argparse.ArgumentParser()
for name in ('source', 'image', 'root', 'out'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
a.out.mkdir(exist_ok=False)
sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
import audit_20261011_runtime_signals as probe
from m2_rootfs import STOCK_SHA256, sha256
assert sha256(a.image / 'usr/sbin/dnsmasq') == STOCK_SHA256
loader = next((a.image / 'lib').glob('ld-musl-*.so.1'))
c = a.image / 'usr/sbin/dnsmasq'
implementations = [
    ('c', [str(loader), '--library-path', f'{a.image}/lib:{a.image}/usr/lib', str(c)], c),
    ('fix', [str(a.root / 'private/release-fix/dnsmasq-rs')], a.root / 'private/release-fix/dnsmasq-rs'),
]
rows = [probe.run_case(label, cmd, binary, a.out, sig)
        for sig in (signal.SIGHUP, signal.SIGUSR2, signal.SIGUSR1, signal.SIGALRM)
        for label, cmd, binary in implementations]
dumps = [probe.run_dump(label, cmd, binary, a.out) for label, cmd, binary in implementations]
maintenance = [probe.run_alarm_maintenance(label, cmd, binary, a.out)
               for label, cmd, binary in implementations]
result = dict(cases=rows, cache_dumps=dumps, alarm_maintenance=maintenance,
              main_signal_controls=[probe.run_case('main', [str(a.root / 'private/release-main/dnsmasq-rs')],
                                    a.root / 'private/release-main/dnsmasq-rs', a.out, sig)
                                    for sig in (signal.SIGUSR1, signal.SIGALRM)])
result['passed'] = (
    all(row['dns_after'] and row['exit_status_after_signal'] is None for row in rows)
    and all(row['daemon_alive'] and row['upstream_queries'] == 3 for row in dumps)
    and dumps[0]['dump'] == dumps[1]['dump']
    and all(row['ack'] == 5 and row['lease_absent_before_alarm'] and row['lease_persisted_after_alarm']
            and row['lease_dump_seen'] and row['daemon_alive'] and row['dns_after'] for row in maintenance))
(a.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'passed': result['passed']}))
raise SystemExit(not result['passed'])
