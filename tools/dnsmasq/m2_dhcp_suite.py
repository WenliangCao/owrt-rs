#!/usr/bin/env python3
"""Run the frozen M2 DHCP plan in fresh image/network fixtures for each side.

Failure reruns use identical plan, binaries and tools with only evidence paths
changed. The first pair and all reruns remain in the canonical private directory.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image-root', 'runtime-root', 'rust-binary', 'plan', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--profile', action='append')
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=True)
    plan = json.loads(args.plan.read_text())
    scripts = Path(__file__).resolve().parent
    records = []
    def run(implementation, profile, attempt):
        name = f'{args.label}-{profile}-{implementation}-{attempt}'
        output = args.out / name
        argv = ['sh', str(scripts / 'run_isolated.sh'), sys.executable, str(scripts / 'actual_config_network.py'),
                '--source-root', str(args.runtime_root), '--router-cidr', plan['router_cidr'],
                '--output', str(args.out / (name + '-network')), '--', sys.executable,
                str(scripts / 'm2_dhcp_scenarios.py'), 'run', '--image-root', str(args.image_root),
                '--runtime-root', str(args.runtime_root), '--rust-binary', str(args.rust_binary),
                '--plan', str(args.plan), '--implementation', implementation, '--profile', profile, '--out', str(output)]
        with (args.out / (name + '.log')).open('wb') as log:
            result = subprocess.run(argv, stdout=log, stderr=log)
        records.append({'argv': argv, 'exit': result.returncode})
        (args.out / (args.label + '-commands.json')).write_text(json.dumps(records, indent=2) + '\n')
        return result.returncode, output / 'result.json'
    failures = 0
    for profile in args.profile or plan['profiles']:
        outputs = {}
        for implementation in ('c', 'rust'):
            code, result = run(implementation, profile, 1)
            if code:
                run(implementation, profile, 2)
                failures += 1
                break
            outputs[implementation] = result
        if len(outputs) == 2:
            argv = [sys.executable, str(scripts / 'm2_dhcp_scenarios.py'), 'compare', '--c-result', str(outputs['c']),
                    '--rust-result', str(outputs['rust']), '--out', str(args.out / f'{args.label}-{profile}-comparison.json')]
            result = subprocess.run(argv)
            if result.returncode:
                failures += 1
                # Preserve a full unchanged pair when the first semantic comparison is red.
                for implementation in ('c', 'rust'):
                    run(implementation, profile, 2)
        if failures:
            break
    print(json.dumps({'failed_profiles': failures, 'commands': len(records)}))
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
