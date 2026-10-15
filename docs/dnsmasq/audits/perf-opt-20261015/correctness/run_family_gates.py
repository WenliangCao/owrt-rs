#!/usr/bin/env python3
"""Run the unchanged canonical family gates at explicit scheduling boundaries.

The pause file delays only the next family; an executing family is never stopped.
No argument, expected value, inventory or comparator is rewritten. Every family
gets a fresh original-runner output; final success requires all 44 and 67 jobs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'elf', 'link-map', 'base-identity', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    tools = source / 'tools/dnsmasq'
    registry_path = tools / 'm5_final_families.draft.json'
    registry = json.loads(registry_path.read_text())
    families = registry['families']
    assert len(families) == 44
    omitted = 'm5_dns_endpoints-local-archive-gate'
    expected_jobs = {family['id'] + '-' + step['id'] for family in families for step in family['steps']} - {omitted}
    assert len(expected_jobs) == 67
    identities = {str(path): sha(path) for path in
                  (args.elf, args.link_map, args.base_identity, registry_path, tools / 'audit_20261011_families.py')}
    report = {'source': str(source), 'commit': args.commit, 'elf_sha256': sha(args.elf),
              'identities': identities, 'expected_families': [f['id'] for f in families],
              'expected_jobs': sorted(expected_jobs), 'passed': False, 'families': [], 'pauses': []}
    save(out / 'result.json', report)
    completed = set()
    for family in families:
        while (out / 'PAUSE').exists():
            started = time.time()
            save(out / 'state.json', {'state': 'paused-before-family', 'next_family': family['id'], 'epoch': started})
            while (out / 'PAUSE').exists():
                time.sleep(1)
            report['pauses'].append({'before_family': family['id'], 'start_epoch': started, 'end_epoch': time.time()})
            save(out / 'result.json', report)
        assert all(sha(Path(name)) == digest for name, digest in identities.items())
        folder = out / family['id']
        argv = ['sudo', '-n', 'python3', str(tools / 'audit_20261011_families.py'),
                '--source', str(source), '--elf', str(args.elf), '--link-map', str(args.link_map),
                '--commit', args.commit, '--base-identity', str(args.base_identity),
                '--family', family['id'], '--out', str(folder)]
        save(out / 'state.json', {'state': 'running-family', 'family': family['id'], 'argv': argv, 'epoch': time.time()})
        with (out / (family['id'] + '.log')).open('w') as log:
            result = subprocess.run(argv, stdout=log, stderr=log)
        value = json.loads((folder / 'result.json').read_text())
        required = {family['id'] + '-' + step['id'] for step in family['steps']} - {omitted}
        actual = {job['id'] for job in value['commands']}
        passed = (result.returncode == 0 and value['passed'] and value['selected_families'] == [family['id']]
                  and value['source_commit'] == args.commit and value['elf_sha256'] == report['elf_sha256']
                  and actual == required and len(value['commands']) == len(required)
                  and value['c_sha256'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
                  and all(job['passed'] for job in value['commands']))
        record = {'family': family['id'], 'exit': result.returncode, 'passed': passed,
                  'commands': len(value['commands']), 'result_sha256': sha(folder / 'result.json'), 'argv': argv}
        report['families'].append(record)
        if passed:
            assert not (completed & actual)
            completed |= actual
        save(out / 'result.json', report)
        print(json.dumps(record), flush=True)
        if not passed:
            save(out / 'state.json', {'state': 'failed-family', 'family': family['id'], 'epoch': time.time()})
            return 1
    assert len(report['families']) == 44 and completed == expected_jobs
    assert all(sha(Path(name)) == digest for name, digest in identities.items())
    report['passed'] = True
    report['completed_jobs'] = len(completed)
    save(out / 'result.json', report)
    save(out / 'state.json', {'state': 'complete', 'families': 44, 'jobs': 67, 'epoch': time.time()})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
