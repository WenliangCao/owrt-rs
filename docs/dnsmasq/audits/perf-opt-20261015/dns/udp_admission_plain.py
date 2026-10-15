#!/usr/bin/env python3
"""One fixed quiet native screen, not whole-daemon acceptance."""
import hashlib
import json
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time

ROOT = Path(sys.argv[1])
OUT = ROOT / 'plain1'
SCENES = ['hit', 'hit-upper', 'miss', 'host', 'malformed']
OPERATIONS = 2000000
EXPECTED = {'hit': 3784130000, 'hit-upper': 3289090000,
            'miss': 2000000, 'host': 5552000000, 'malformed': 952000000}
HASHES = {
    'baseline': '524e9a108553ecf457943b8cdc4a15852d9b6c5f6f9d10cc0c77e15adc66decb',
    'candidate': '9feb67560b1a171ba332d7d4667ac07408a917ae6751400975e652b0f1899373',
}

def verify():
    for side, expected in HASHES.items():
        assert hashlib.sha256((ROOT / (side + '-probe')).read_bytes()).hexdigest() == expected

def cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime

verify()
OUT.mkdir()  # Never overwrite an earlier attempt.
report = {'scope': __doc__, 'reservation': 'udp-admission-plain1',
          'hashes': HASHES, 'operations': OPERATIONS, 'declared_windows': 50, 'runs': []}
for scene in SCENES:
    for pair in range(1, 6):
        order = ['baseline', 'candidate'] if pair % 2 else ['candidate', 'baseline']
        for side in order:
            prefix = OUT / f'{scene}-{pair}-{side}'
            with prefix.with_suffix('.stdout').open('wb') as stdout, prefix.with_suffix('.stderr').open('wb') as stderr:
                start_cpu, start_wall = cpu(), time.monotonic_ns()
                p = subprocess.run(['taskset', '-c', '2', str(ROOT / (side + '-probe')), scene, str(OPERATIONS)],
                                   stdout=stdout, stderr=stderr, timeout=60)
                elapsed_cpu = round((cpu() - start_cpu) * 1e9)
                elapsed_wall = time.monotonic_ns() - start_wall
            row = {'scene': scene, 'pair': pair, 'side': side, 'cpu_ns': elapsed_cpu,
                   'wall_ns': elapsed_wall, 'returncode': p.returncode}
            report['runs'].append(row)
            (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            assert p.returncode == 0
            actual = json.loads(prefix.with_suffix('.stdout').read_text())
            assert actual['scene'] == scene and actual['operations'] == OPERATIONS
            assert actual['checksum'] == EXPECTED[scene]
            assert actual['allocation_reallocation_requested_live'] == [0, 0, 0, 0]
            row['checksum'] = actual['checksum']
verify()
report['summaries'] = []
for scene in SCENES:
    samples = {side: [r['cpu_ns'] for r in report['runs'] if r['scene'] == scene and r['side'] == side] for side in HASHES}
    med = {s: statistics.median(v) for s, v in samples.items()}
    delta = (med['candidate'] / med['baseline'] - 1) * 100
    width = max((max(v) - min(v)) / statistics.median(v) * 100 for v in samples.values())
    improving = sum(c < b for b, c in zip(samples['baseline'], samples['candidate']))
    decision = 'improvement' if delta < -width and improving >= 4 else 'regression' if delta > width and improving <= 1 else 'indistinguishable'
    report['summaries'].append({'scene': scene, 'cpu_ns': samples, 'median_cpu_ns': med,
                                'change_percent': delta, 'W_percent': width, 'improving_pairs': improving, 'decision': decision})
report['complete'] = True
(OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report['summaries']))
