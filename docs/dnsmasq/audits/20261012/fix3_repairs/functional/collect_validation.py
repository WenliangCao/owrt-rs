#!/usr/bin/env python3
"""Derive functional receipts from retained plans/results; never rerun workloads."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    private = args.root / 'private'
    primary_path = private / 'functional-plan.json'
    primary_state_path = private / 'functional/state.json'
    continuation_path = private / 'functional-continuation-plan.json'
    continuation_state_path = private / 'functional-continuation/state.json'
    supplement_path = private / 'functional-supplement-plan.json'
    primary, primary_state = read(primary_path), read(primary_state_path)
    continuation, state = read(continuation_path), read(continuation_state_path)
    supplement = read(supplement_path)
    assert state['passed'] and state['total_dispositions'] == 47
    assert state['plan_sha256'] == sha(continuation_path)
    assert not primary_state['passed'] and primary_state['commands'][8]['returncode'] == 1
    assert continuation['primary_plan_sha256'] == sha(primary_path)
    assert continuation['primary_state_sha256'] == sha(primary_state_path)
    assert continuation['supplement_plan_sha256'] == sha(supplement_path)
    assert state['strict_script_assessment'] == continuation['strict_script_assessment']
    assert len(state['reused_commands']) == 8 and len(state['commands']) == 38
    assert state['reused_commands'] == primary_state['commands'][:8]
    assessment = state['strict_script_assessment']
    assert assessment['accepted'] and assessment['original_returncode'] == 1 and not assessment['original_passed']
    assert assessment['other_responses_equal'] == 366 and assessment['total_responses'] == 368
    assert assessment['all_C_Rust_profile_health_equal']
    for check in assessment['exact_baseline_checks']:
        assert all(value for key, value in check.items() if key != 'protocol')
    for path, expected in continuation['assets'].items():
        assert sha(path) == expected, path
    source = Path(primary['source'])
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import build_package as package
    import m5_final_validation as final
    assert package.inputs(source) == primary['source_files']
    expected = primary['jobs'] + supplement['jobs']
    actual = state['reused_commands'] + [primary_state['commands'][8]] + state['commands']
    assert len(actual) == len(expected) == 47
    files = {}
    def bind(path):
        path = Path(path)
        value = {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}
        files[str(path)] = value
        return value
    commands = []
    for index, (job, record) in enumerate(zip(expected, actual)):
        assert all(record[key] == value for key, value in job.items()), job['id']
        expected_digest = assessment['result_sha256'] if index == 8 else record['result_sha256']
        assert sha(record['result']) == expected_digest
        if index != 8:
            assert record['passed'] and record['returncode'] == 0
        if 'family' in job:
            final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
        log_parent = private / ('functional' if index < 9 else 'functional-continuation')
        commands.append({'id': record['id'], 'family': record.get('family'), 'argv': record['argv'],
             'result': bind(record['result']), 'log': bind(log_parent / (record['id'] + '.log')),
             'actual_returncode': record['returncode'], 'original_controller_passed': record['passed'],
             'accepted': True, 'acceptance': 'predeclared baseline verified independently' if index == 8 else 'original assertions passed',
             'started': record['started'], 'elapsed_seconds': record['elapsed_seconds'],
             **({'strict_result': record['strict_result']} if 'strict_result' in record else {})})
    assert sum(command['actual_returncode'] == 0 for command in commands) == 46
    expected_families = set(primary['selected_families'])
    assert set(state['families']) == expected_families and len(expected_families) == 13
    assert sum(value['commands'] for value in state['families'].values()) == 34
    for family, value in state['families'].items():
        assert value['passed'] and value['commands'] == sum(command['family'] == family for command in commands)
    retained = {key: bind(path) for key, path in {
        'primary_plan': primary_path, 'primary_failed_state': primary_state_path,
        'continuation_plan': continuation_path, 'continuation_state': continuation_state_path,
        'supplement_plan': supplement_path,
        'primary_invocation': private / 'functional-invocation.json',
        'continuation_invocation': private / 'functional-continuation-invocation.json',
        'primary_log': private / 'functional-driver.log',
        'continuation_log': private / 'functional-continuation-driver.log',
        'primary_controller': source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional/validation_driver.py',
        'continuation_controller': private / 'functional-tools/continuation_driver.py',
        'supplement_controller': private / 'functional-tools/supplemental_driver.py',
        'collector': Path(__file__).resolve(),
    }.items()}
    endpoint_archives = {}
    endpoint_root = private / 'functional/families/m5_dns_endpoints'
    for name in ('syntax', 'service'):
        archive_receipts = {suffix: bind(endpoint_root / (name + suffix)) for suffix in
            ('.tar.gz', '.manifest.json', '.pack.json', '.local-verification.json', '.prune.json', '.restore.json')}
        local = read(endpoint_root / (name + '.local-verification.json'))
        manifest = read(endpoint_root / (name + '.manifest.json'))
        assert local['verified'] and local['local_full_metadata_verified']
        assert local['archive_sha256'] == archive_receipts['.tar.gz']['sha256'] == manifest['archive_sha256']
        assert local['manifest_sha256'] == archive_receipts['.manifest.json']['sha256']
        assert sha(endpoint_root / name / 'result.json') == manifest['entries']['result.json']['sha256']
        endpoint_archives[name] = {'files': archive_receipts, 'entries': len(manifest['entries']),
                                  'local_full_metadata_verified': True, 'original_result_bytes_retained': True}
    parity = read(private / 'functional/TCP-UDP-parity/result.json')
    assert parity['passed'] and parity['case_count'] == 1736 and not parity['failures']
    parity_cases = [case for profile in parity['profiles'] for case in profile['cases'].values()]
    matrix = next(row['strict_result'] for row in state['reused_commands'] if row['id'] == 'review3-matrix')
    n1 = next(row['strict_result'] for row in state['reused_commands'] if row['id'] == 'N1-filter-cname')
    stale = next(row['strict_result'] for row in state['reused_commands'] if row['id'] == 'F08-stale-observation')
    summary = {'schema': 'dnsmasq-fix3-functional-receipt-v1', 'passed_with_declared_baselines': True,
        'source_commit': primary['source_commit'], 'elf': bind(primary['rust']),
        'total_dispositions': 47, 'zero_exit_commands': 46, 'strict_script_exit_1': 1,
        'family_commands': 34, 'complete_families': state['families'], 'directed_commands': 13,
        'retained': retained, 'endpoint_archives': endpoint_archives, 'source_files': primary['source_files'], 'commands': commands,
        'strict_script_assessment': assessment,
        'directed_summary': {'N1': n1, 'review3_matrix': matrix,
            'persistent_TCP_UDP_parity': {'profiles': len(parity['profiles']), 'paired_cases': len(parity_cases),
                 'all_assertions_passed': True,
                 'C_internal_routing_cases_following_common_UDP': sum(case['declared_common_UDP_semantics'] for case in parity_cases),
                 'C_matched_transport_size_differences': sum(case['checks']['transport_size_difference'] for case in parity_cases)},
            'F08_stale_observation': stale},
        'limits': ['F08 stale EDE difference remains and is not declared equivalent',
             'Two inherited forward-pointer differences retain the exact prior results',
             'Nine C-internal routing differences deliberately follow shared UDP semantics',
             'Ordinary RR TTL aging and compression normalized only for declared semantic checks; full raw packets retained',
             'No performance conclusion from functional runs; SDK payload identity differs from release measurements']}
    args.out.mkdir(parents=True, exist_ok=False)
    for name, value in (('validation.json', summary), ('validation-raw-index.json', {'schema': 'dnsmasq-fix3-functional-raw-index-v1', 'files': list(files.values())})):
        (args.out / name).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({'passed_with_declared_baselines': True, 'commands': 47,
                      'validation_sha256': sha(args.out / 'validation.json'),
                      'raw_index_sha256': sha(args.out / 'validation-raw-index.json')}))


if __name__ == '__main__':
    main()
