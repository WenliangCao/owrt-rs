#!/usr/bin/env python3
"""Fresh final-SDK repair checks using retained transport drivers.

Must run in run_isolated.sh. Inputs/outputs are explicitly hashed. These are
fresh reruns of old reproductions, separate from boundaries.py's new cases.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
for key in ['source', 'image', 'fix', 'main', 'out']:
    p.add_argument('--' + key, type=Path, required=True)
a = p.parse_args()
assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
assert 'private' in a.out.resolve().parts
a.out.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
import audit_20261011_runtime_signals as signals
from m2_rootfs import image_elf_command, sha256

paths = {'c': a.image / 'usr/sbin/dnsmasq', 'main': a.main, 'fix': a.fix}
commands = {side: image_elf_command(a.image, path) for side, path in paths.items()}
report = dict(tool_sha256=sha256(__file__), binary_sha256={side: sha256(p) for side, p in paths.items()}, jobs=[])
jobs = [
    ('helper', a.source / 'tools/dnsmasq/audit_fix_20261011_dhcp_helper.py',
     ['--source', str(a.source), '--image-root', str(a.image), '--rust', str(a.fix)]),
    ('tftp', a.source / 'docs/dnsmasq/audits/20261011/independent/config_signals_tftp_probe.py',
     ['--image', str(a.image), '--rust', str(a.fix)]),
    ('dump-rows', a.source / 'docs/dnsmasq/audits/20261011/fix2/config/dump_rows.py',
     ['--source', str(a.source), '--image', str(a.image), '--rust', str(a.fix), '--require-match']),
]
for name, script, arguments in jobs:
    argv = ['python3', str(script), *arguments, '--out', str(a.out / name)]
    with (a.out / (name + '.log')).open('wb') as log:
        result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    result_path = a.out / name / 'result.json'
    report['jobs'].append(dict(name=name, argv=argv, exit=result.returncode,
        tool_sha256=sha256(script), result_sha256=sha256(result_path), result=json.loads(result_path.read_text())))
    print(name, result.returncode, flush=True)

out = a.out / 'signals'
out.mkdir()
report['signals'] = [signals.run_case(side, command, paths[side], out, sig)
    for sig in (signal.SIGUSR1, signal.SIGALRM) for side, command in commands.items()]
report['dump'] = [signals.run_dump(side, commands[side], paths[side], out) for side in ('c', 'fix')]
report['maintenance'] = [signals.run_alarm_maintenance(side, commands[side], paths[side], out) for side in ('c', 'fix')]
report['passed'] = (all(row['exit'] == 0 for row in report['jobs'])
    and all(row['dns_after'] and row['exit_status_after_signal'] is None for row in report['signals'] if row['implementation'] != 'main')
    and report['dump'][0]['dump'] == report['dump'][1]['dump']
    and all(row['ack'] == 5 and row['lease_absent_before_alarm'] and row['lease_persisted_after_alarm']
        and row['lease_dump_seen'] and row['daemon_alive'] and row['dns_after'] for row in report['maintenance']))
(a.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'passed': report['passed']}))
