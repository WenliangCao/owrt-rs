#!/usr/bin/env python3
"""Continue the frozen functional plan after classifying its known parser baseline.

No old plan, state, result or archived source is overwritten. Eight passed runs
are rebound by SHA. The original strict DNS script's exit 1 remains visible; its
two forward-pointer results must exactly equal the previously frozen baseline,
while every other response and all health checks must pass. Remaining 36 primary
and two previously frozen supplemental commands execute once, in original order.
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
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def assess_original(primary, state):
    assert not state['passed'] and len(state['commands']) == 9
    assert len(primary['jobs']) == 45
    for job, record in zip(primary['jobs'][:9], state['commands']):
        assert all(record[key] == value for key, value in job.items())
    reused = state['commands'][:8]
    for record in reused:
        assert record['passed'] and record['returncode'] == 0
        assert sha(record['result']) == record['result_sha256']
    failed = state['commands'][8]
    assert failed['id'] == 'A10-and-original-DNS' and not failed['passed'] and failed['returncode'] == 1
    result = read(failed['result'])
    historical_path = Path(primary['source']) / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional/historical-differences.json'
    historical = read(historical_path)
    profiles = result['profiles']
    assert set(profiles) == {'local', 'forward', 'filter', 'rebind'}
    checks, equal_count = [], 0
    for name, profile in profiles.items():
        assert len(profile['cases']) == (116 if name == 'local' else 84)
        for side in ('c', 'rust'):
            health = profile['processes'][side]
            assert health['ready'] and health['alive_after_cases'] and health['exit'] == 0
            assert health['health_after']['status'] == 'reply'
        assert profile['processes']['c']['health_after'] == profile['processes']['rust']['health_after']
        for row in profile['cases']:
            observed = {side: {key: value for key, value in row[side].items() if key != 'upstream'}
                        for side in ('c', 'rust')}
            if name == 'local' and row['name'] == 'forward-pointer':
                old = next(item for item in historical['records']
                           if item['profile'] == 'malformed' and item['case'] == 'forward-pointer-' + row['protocol'])
                matched = {'query_exact': row['query_hex'] == old['query'],
                           'C_response_exact': observed['c'] == old['C']['response'],
                           'Rust_response_exact': observed['rust'] == old['previous']['response'],
                           'upstream_empty': not row['c']['upstream'] and not row['rust']['upstream']}
                assert all(matched.values()) and not row['same_client_result']
                checks.append({'protocol': row['protocol'], **matched})
            else:
                assert observed['c'] == observed['rust'] and row['same_client_result'], (name, row['name'], row['protocol'])
                equal_count += 1
    assert len(checks) == 2 and {row['protocol'] for row in checks} == {'udp', 'tcp'} and equal_count == 366
    return {'id': failed['id'], 'result': failed['result'], 'result_sha256': sha(failed['result']),
            'original_returncode': 1, 'original_passed': False, 'accepted': True,
            'reason': 'same two forward-pointer baseline differences already declared in the frozen matrix plan',
            'historical_fixture': str(historical_path), 'historical_fixture_sha256': sha(historical_path),
            'prior_raw_matrix_sha256': historical['sha256'], 'exact_baseline_checks': checks,
            'other_responses_equal': equal_count, 'total_responses': 368,
            'all_C_Rust_profile_health_equal': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--plan', type=Path, required=True)
    for name in ('primary-plan', 'primary-state', 'supplement-plan', 'out'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--tool-commit')
    args = parser.parse_args()
    if args.action == 'prepare':
        assert all((args.primary_plan, args.primary_state, args.supplement_plan, args.out, args.tool_commit))
        assert not args.plan.exists() and not args.out.exists()
        primary, state, supplement = read(args.primary_plan), read(args.primary_state), read(args.supplement_plan)
        assert state['plan_sha256'] == sha(args.primary_plan)
        assert supplement['primary_plan_sha256'] == sha(args.primary_plan)
        assert supplement['source_commit'] == primary['source_commit'] and supplement['rust_sha256'] == primary['rust_sha256']
        assessment = assess_original(primary, state)
        jobs = [dict(job) for job in primary['jobs'][9:]]
        jobs += [dict(job, supplemental_check=job['id']) for job in supplement['jobs']]
        assert len(jobs) == 38 and len({job['id'] for job in jobs}) == 38
        assert all(not Path(job['result']).exists() for job in jobs)
        assets = {**primary['assets'], **supplement['assets']}
        for path in (args.primary_plan, args.primary_state, args.supplement_plan, Path(__file__).resolve()):
            assets[str(path)] = sha(path)
        assets[assessment['result']] = assessment['result_sha256']
        for record in state['commands'][:8]:
            assets[record['result']] = record['result_sha256']
        save(args.plan, {'schema': 'dnsmasq-fix3-functional-continuation-v1', 'tool_commit': args.tool_commit,
             'primary_plan': str(args.primary_plan), 'primary_plan_sha256': sha(args.primary_plan),
             'primary_state': str(args.primary_state), 'primary_state_sha256': sha(args.primary_state),
             'supplement_plan': str(args.supplement_plan), 'supplement_plan_sha256': sha(args.supplement_plan),
             'source': primary['source'], 'source_commit': primary['source_commit'],
             'rust': primary['rust'], 'rust_sha256': primary['rust_sha256'], 'source_files': primary['source_files'],
             'selected_families': primary['selected_families'], 'output': str(args.out), 'assets': assets,
             'reused_commands': state['commands'][:8], 'strict_script_assessment': assessment, 'jobs': jobs,
             'expected_total': 47, 'expected_new_commands': 38})
        print(json.dumps({'prepared': True, 'new_commands': 38, 'total_dispositions': 47, 'plan_sha256': sha(args.plan)}))
        return
    assert os.geteuid() == 0 and not sys.flags.optimize
    plan = read(args.plan)
    source, output = Path(plan['source']), Path(plan['output'])
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    sys.path.insert(0, str(source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'))
    import m5_final_validation as final
    import build_package as package
    from m2_rootfs import STOCK_SHA256
    from result_checks import check_acl, check_n2
    def identity():
        assert package.inputs(source) == plan['source_files']
        for path, digest in plan['assets'].items():
            assert sha(path) == digest, path
        assert assess_original(read(plan['primary_plan']), read(plan['primary_state'])) == plan['strict_script_assessment']
    identity()
    output.mkdir(parents=True, exist_ok=False)
    state = {'passed': False, 'plan_sha256': sha(args.plan), 'source_commit': plan['source_commit'],
             'elf_sha256': plan['rust_sha256'], 'reused_commands': plan['reused_commands'],
             'strict_script_assessment': plan['strict_script_assessment'], 'commands': [], 'families': {}}
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
            assert process.returncode == 0, f'exit {process.returncode}'
            result = read(job['result'])
            check = job.get('custom_check')
            if check in ('acl', 'n2'):
                record['strict_result'] = {'acl': check_acl, 'n2': check_n2}[check](result)
                assert record['strict_result']['passed'], record['strict_result']
            if 'family' in job:
                final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
            if 'supplemental_check' in job:
                assert result['rust_sha256'] == plan['rust_sha256'] and result['c_sha256'] == STOCK_SHA256
                if job['supplemental_check'] == 'hosts-original-TCP':
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
    for family in plan['selected_families']:
        expected = [job for job in plan['jobs'] if job.get('family') == family]
        actual = [job for job in state['commands'] if job.get('family') == family]
        assert len(expected) == len(actual) and all(job['passed'] for job in actual)
        state['families'][family] = {'passed': True, 'commands': len(actual)}
    assert len(state['commands']) == 38
    state.update(passed=True, total_dispositions=47, executed_zero_exit_commands=46,
                 original_strict_script_nonzero_exit=1,
                 completion_note='46 commands exit 0; one original strict script exit 1 independently verified as exactly two predeclared baseline parser differences, with its other 366 responses equal')
    save(output / 'state.json', state)
    print('CONTINUATION PASS; ORIGINAL STRICT EXIT 1 RETAINED', flush=True)


if __name__ == '__main__':
    main()
