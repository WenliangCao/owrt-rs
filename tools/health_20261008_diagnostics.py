#!/usr/bin/env python3
"""One-shot diagnostic regression, with explicit Rust-only CLI contracts.

Unlike the fw4/uci oracle, Rust-only options have no byte-equivalent C command.
For those cases compare normal output to r2 byte for byte, then require closed
streams to retain the normal status and the other stream's exact bytes. Stock
C diagnostics are recorded separately, never presented as equivalent help text.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from health_20261008_cli import observe, digest, EXPECTED_STOCK
from r92_compat_probe import Fixture

PATHS = {'ubusd': '/sbin/ubusd', 'httpd': '/usr/sbin/uhttpd', 'logd': '/sbin/logd',
         'netifd': '/sbin/netifd', 'rpcd': '/sbin/rpcd', 'reload-config': '/sbin/reload_config'}
CASES = [
    ('ubusd-usage', 'ubusd', ['-h']),
    ('ubusd-version', 'ubusd', []),
    ('httpd-help', 'httpd', ['--help']),
    ('httpd-missing-argument', 'httpd', ['-h']),
    ('logd-help', 'logd', ['--help']),
    ('logd-unknown-argument', 'logd', ['--unknown']),
    ('netifd-version', 'netifd', ['--version']),
    ('netifd-wireless', 'netifd', ['--dump-wireless', '/tmp/empty-wireless']),
    ('netifd-missing-level', 'netifd', ['-l']),
    ('netifd-unknown-argument', 'netifd', ['--unknown']),
    ('rpcd-bench-usage', 'rpcd', ['--iwinfo-bench']),
    ('rpcd-bench-no-device', 'rpcd', ['--iwinfo-bench', 'health-missing']),
    ('rpcd-invalid-timeout', 'rpcd', ['-t', '0']),
    ('reload-help', 'reload-config', ['--help']),
    ('reload-invalid-timeout', 'reload-config', ['--timeout-ms', '0']),
]
C_CASES = [('ubusd-usage', 'ubusd', ['-h']), ('httpd-usage', 'httpd', ['-h']),
           ('netifd-usage', 'netifd', ['-l']), ('rpcd-timeout', 'rpcd', ['-t', '0'])]


def inner(root, side, rounds):
    fixture = Fixture(root, 'original', 'fw4')
    try:
        (root / 'tmp/empty-wireless').mkdir()
        # Synthetic fixtures keep diagnostic output deterministic and private.
        (root / 'etc/config/wireless').write_text('')
        cases = C_CASES if side == 'stock' else CASES
        rows = []
        for repeat in range(rounds):
            for name, component, arguments in cases:
                command = [PATHS[component], *arguments]
                if name == 'ubusd-version':
                    command = ['/bin/busybox', 'env', 'UBUSD_RS_VERSION=1', *command]
                for disposition in ('ignore', 'default'):
                    for closed in ('none', 'stdout', 'stderr'):
                        row = observe(root, command, closed, disposition)
                        row.update(case=name, repeat=repeat + 1, closed=closed, sigpipe=disposition)
                        rows.append(row)
        (root / 'tmp/out/observations.json').write_text(json.dumps(rows, indent=2) + '\n')
    finally:
        fixture.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inner':
        inner(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('baseline_bins', type=Path)
    parser.add_argument('candidate_bins', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--rounds', type=int, default=4)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    if os.geteuid() != 0 or sys.platform != 'linux':
        parser.error('run as root on Linux')
    assert {path: digest(args.rootfs / path) for path in EXPECTED_STOCK} == EXPECTED_STOCK
    args.output.mkdir(parents=True, exist_ok=False)
    observed, identities = {}, {}
    for side in ('stock', 'baseline', 'candidate'):
        with tempfile.TemporaryDirectory(prefix='health-diagnostic-') as temporary:
            root = Path(temporary) / 'root'
            shutil.copytree(args.rootfs, root, symlinks=True)
            for directory in ('out', 'run/ubus', 'lock', 'state'):
                (root / 'tmp' / directory).mkdir(parents=True, exist_ok=True)
            identities[side] = {}
            for component, target in PATHS.items():
                if side != 'stock':
                    bins = args.baseline_bins if side == 'baseline' else args.candidate_bins
                    shutil.copy2(bins / (component + '-rs'), root / target[1:])
                identities[side][component] = digest(root / target[1:])
            with (args.output / (side + '.log')).open('wb') as log:
                subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child', sys.executable,
                                str(Path(__file__).resolve()), '--inner', str(root), side, str(args.rounds)],
                               stdout=log, stderr=log, timeout=180, check=True)
            observed[side] = json.loads((root / 'tmp/out/observations.json').read_text())
    for side, rows in observed.items():
        assert len(rows) == args.rounds * len(C_CASES if side == 'stock' else CASES) * 6
    baseline = {(r['case'], r['repeat'], r['sigpipe']): r for r in observed['baseline'] if r['closed'] == 'none'}
    rows = []
    for row in observed['candidate']:
        reference = baseline[row['case'], row['repeat'], row['sigpipe']]
        fields = ['shell_status'] + [s + '_hex' for s in ('stdout', 'stderr') if s != row['closed']]
        different = [k for k in fields if row[k] != reference[k]]
        # Every case must actually write something with open streams.
        sentinel = bool(reference['stdout_hex'] or reference['stderr_hex'])
        rows.append({'case': row['case'], 'repeat': row['repeat'], 'sigpipe': row['sigpipe'], 'closed': row['closed'],
                     'passed': not different and sentinel, 'different': different, 'output_sentinel': sentinel})
    result = {'sha256': identities, 'rounds': args.rounds, 'passed': all(r['passed'] for r in rows),
              'contract': 'r2 normal bytes/status preserved; closed streams ignored; no claim of C help text parity',
              'comparisons': rows, 'observations': observed}
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'rows': len(rows), 'passed': result['passed'],
                      'failed_cases': sorted({r['case'] for r in rows if not r['passed']})}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
