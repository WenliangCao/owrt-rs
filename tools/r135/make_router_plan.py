#!/usr/bin/env python3
"""Freeze four Latin-order targeted router windows after Oracle screening."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'private/r135/router-plan-01'
ORDERS = [('c', 'r134', 'split', 'drain'), ('r134', 'drain', 'c', 'split'),
          ('drain', 'split', 'r134', 'c'), ('split', 'c', 'drain', 'r134')]


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    inputs = ['tools/r95_device_smoke.py', 'tools/benchmark/isolated.sh',
              'private/r95/guard', 'private/r96/recovery-full/recovery-gate.json',
              'private/r135/owrt-benchmark', 'private/r135/build-01/s0b1k1/ubusd-rs',
              'private/r135/build-01/s1b0k1/ubusd-rs', 'private/r134/bins-ubusd/ubusd-rs']
    steps = []
    for i, order in enumerate(ORDERS):
        script = OUT / f'window-{i}.sh'
        text = (ROOT / 'tools/r135/router_probe.sh.in').read_text()
        script.write_text(text.replace('@ORDER@', ' '.join(order)).replace('@AFFINITIES@',
                          'split pair_allowed' if i % 2 == 0 else 'pair_allowed split'))
        path = str(script.relative_to(ROOT))
        inputs.append(path)
        dest = f'private/r135/router-probe-01/window-{i}'
        argv = ['tools/r95_device_smoke.py', 'ubusd', inputs[5], dest,
                '--recovery-gate', inputs[3], '--guard', inputs[2], '--benchmark', inputs[4],
                '--before-candidate', inputs[7], '--event-benchmark', inputs[6],
                '--workload-script', path, '--iterations', '10000', '--pilot']
        steps.append(dict(name=f'window-{i}', argv=argv, driver_result=f'{dest}/result.json'))
    plan = dict(scope='Four-window targeted diagnostic; no replacement for frozen R134 results or formal promotion',
                output='private/r135/router-probe-01', orders=ORDERS, steps=steps,
                input_sha256={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in inputs})
    (OUT / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')


if __name__ == '__main__':
    main()
