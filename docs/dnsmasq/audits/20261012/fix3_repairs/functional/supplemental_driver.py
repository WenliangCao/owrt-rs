#!/usr/bin/env python3
"""Append two original hosts/TCP reproductions without mutating the source freeze.

The main 45-command plan must finish successfully before run. This controller is
separately Git/hash-bound and executes from private/functional-tools; its source
and workload tools remain the already archived, immutable source directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--primary-plan', type=Path)
    parser.add_argument('--tool-commit')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        assert args.primary_plan and args.tool_commit and args.out
        assert not args.plan.exists() and not args.out.exists()
        primary = read(args.primary_plan)
        source, output = Path(primary['source']), args.out
        tools = source / 'tools/dnsmasq'
        first = source / 'docs/dnsmasq/audits/20261011/independent/dns_hosts_probe.py'
        second = tools / 'audit_fix_20261011_hosts.py'
        image = next(Path(path).parents[2] for path in primary['assets']
                     if path.endswith('/rootfs-files/usr/sbin/dnsmasq'))
        jobs = []
        for name, script in (('hosts-original-TCP', first), ('hosts-diagnostics-TCP', second)):
            folder = output / name
            jobs.append({'id': name, 'argv': ['sh', str(tools / 'run_isolated.sh'), sys.executable,
                         str(script), '--image-root', str(image), '--rust', primary['rust'], '--out', str(folder)],
                         'result': str(folder / 'result.json'), 'timeout_seconds': 1800})
        assets = {str(path): sha(path) for path in (first, second, tools / 'run_isolated.sh', Path(__file__).resolve())}
        save(args.plan, {'schema': 'dnsmasq-fix3-hosts-supplement-v1', 'primary_plan': str(args.primary_plan),
             'primary_plan_sha256': sha(args.primary_plan), 'primary_state': str(Path(primary['output']) / 'state.json'),
             'source': str(source), 'source_commit': primary['source_commit'], 'rust': primary['rust'],
             'rust_sha256': primary['rust_sha256'], 'output': str(output), 'tool_commit': args.tool_commit,
             'assets': assets, 'jobs': jobs})
        print(json.dumps({'prepared': True, 'commands': 2, 'plan_sha256': sha(args.plan)}))
        return
    assert os.geteuid() == 0 and not sys.flags.optimize
    plan = read(args.plan)
    source, output = Path(plan['source']), Path(plan['output'])
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import m5_final_validation as final
    from m2_rootfs import STOCK_SHA256
    primary_state = read(plan['primary_state'])
    assert primary_state['passed'] and primary_state['plan_sha256'] == plan['primary_plan_sha256']
    assert len(primary_state['commands']) == 45 and all(row['passed'] for row in primary_state['commands'])
    def identity():
        assert sha(plan['primary_plan']) == plan['primary_plan_sha256']
        assert sha(plan['rust']) == plan['rust_sha256']
        for path, digest in plan['assets'].items():
            assert sha(path) == digest, path
    identity()
    output.mkdir(parents=True, exist_ok=False)
    state = {'passed': False, 'plan_sha256': sha(args.plan), 'source_commit': plan['source_commit'],
             'elf_sha256': plan['rust_sha256'], 'primary_state_sha256': sha(plan['primary_state']), 'commands': []}
    save(output / 'state.json', state)
    for job in plan['jobs']:
        record = dict(job, passed=False, started=time.time())
        state['commands'].append(record); save(output / 'state.json', state)
        print('START', job['id'], flush=True)
        with (output / (job['id'] + '.log')).open('wb') as log:
            process = subprocess.Popen(job['argv'], cwd=source, stdout=log, stderr=log, start_new_session=True)
            descendants = {}
            try:
                while process.poll() is None:
                    final.remember_job_processes(process, descendants)
                    if time.time() - record['started'] > job['timeout_seconds']:
                        raise TimeoutError(job['id'])
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                final.stop_job_processes(process, descendants)
        record['returncode'] = process.returncode
        try:
            assert process.returncode == 0
            result = read(job['result'])
            assert result['rust_sha256'] == plan['rust_sha256'] and result['c_sha256'] == STOCK_SHA256
            if job['id'] == 'hosts-original-TCP':
                assert len(result['rows']) == 4
                for row in result['rows']:
                    assert row['c']['alive'] and row['rust']['alive']
                    assert {k: v for k, v in row['c'].items() if k != 'dump'} == {k: v for k, v in row['rust'].items() if k != 'dump'}
                    if row['mode'] in ('addn-hosts', 'hostsdir'):
                        diagnostics = {side: re.findall(r'bad (?:name|address) at [^\n]+', row[side]['dump']) for side in ('c', 'rust')}
                        assert diagnostics['c'] and diagnostics['c'] == diagnostics['rust']
                        assert any(value.startswith('bad name at ') and value.endswith(' line 6') for value in diagnostics['c'])
            else:
                assert result['passed'] and len(result['cases']) == 8
            record.update(passed=True, result_sha256=sha(job['result']))
        except Exception as error:
            record['error'] = repr(error)
        record['elapsed_seconds'] = time.time() - record['started']
        save(output / 'state.json', state)
        print('PASS' if record['passed'] else 'FAIL', job['id'], record.get('error'), flush=True)
        if not record['passed']:
            raise SystemExit(1)
    identity()
    state['passed'] = True; save(output / 'state.json', state)
    print('SUPPLEMENT PASS', flush=True)


if __name__ == '__main__':
    main()
