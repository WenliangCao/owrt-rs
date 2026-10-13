#!/usr/bin/env python3
"""Derive the fresh types-artifact functional receipt; no workload reruns."""
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
    plan_path = private / 'functional-types-v2-plan.json'
    state_path = private / 'functional-types-v2/state.json'
    plan, state = read(plan_path), read(state_path)
    output, source = Path(plan['output']), Path(plan['source'])
    assert state['passed'] and state['plan_sha256'] == sha(plan_path)
    assert len(plan['jobs']) == len(state['commands']) == 49
    for path, expected in plan['assets'].items():
        assert sha(path) == expected, path
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import build_package as package
    import m5_final_validation as final
    assert package.inputs(source) == plan['source_files']
    files = {}
    def bind(path):
        path = Path(path)
        value = {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}
        files[str(path)] = value
        return value
    commands = []
    for job, record in zip(plan['jobs'], state['commands']):
        assert all(record[key] == value for key, value in job.items()), job['id']
        assert record['passed'] and record['returncode'] == 0
        assert sha(record['result']) == record['result_sha256']
        if 'family' in job:
            final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
        row = {'id': record['id'], 'family': record.get('family'), 'argv': record['argv'],
               'result': bind(record['result']), 'log': bind(output / (record['id'] + '.log')),
               'actual_returncode': record['returncode'], 'assertions_passed': True,
               'started': record['started'], 'elapsed_seconds': record['elapsed_seconds']}
        for key in ('strict_result', 'native_probe_identity', 'native_adapter_identity', 'native_adapter_receipt', 'probe_scope'):
            if key in record:
                row[key] = record[key]
        commands.append(row)
    assert len(state['families']) == 14 and sum(row['commands'] for row in state['families'].values()) == 35
    for family, value in state['families'].items():
        assert value['passed'] and value['commands'] == sum(row['family'] == family for row in commands)
    endpoint_root = output / 'families/m5_dns_endpoints'
    endpoint_archives = {}
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
    native = state['commands'][0]
    assert native['id'] == 'config-state-probe'
    native_dir = Path(native['result']).parent
    native_files = {str(path.relative_to(native_dir)): bind(path) for path in sorted(native_dir.rglob('*'))
                    if path.is_file() and 'cargo-target' not in path.relative_to(native_dir).parts}
    for value in native['native_probe_identity'].values():
        assert sha(value['path']) == value['sha256']
    assert sha(native['native_adapter_receipt']['path']) == native['native_adapter_receipt']['sha256']
    failed_plan_path = private / 'functional-types-plan.json'
    failed_state_path = private / 'functional-types/state.json'
    failed = read(failed_state_path)
    assert not failed['passed'] and len(failed['commands']) == 1
    assert failed['commands'][0]['id'] == 'config-state-probe' and failed['commands'][0]['returncode'] == 1
    assert not (private / 'functional-types/config-state-probe/result.json').exists()
    retained = {name: bind(path) for name, path in {
        'plan': plan_path, 'state': state_path, 'invocation': private / 'functional-types-v2-invocation.json',
        'controller_log': private / 'functional-types-v2-driver.log',
        'controller': private / 'types-functional-tools/types_validation_driver.py',
        'config_adapter': private / 'types-functional-tools/config_state_adapter.py',
        'collector': Path(__file__).resolve(),
        'initial_harness_plan': failed_plan_path, 'initial_harness_failed_state': failed_state_path,
        'initial_harness_invocation': private / 'functional-types-invocation.json',
        'initial_harness_log': private / 'functional-types/config-state-probe.log',
        'previous_functional_state': private / 'functional-continuation/state.json',
        'previous_original_strict_failed_state': private / 'functional/state.json',
        'previous_performance_plan': private / 'performance-paired-01/plan.json',
        'previous_performance_run': private / 'performance-paired-01/run.json',
        'previous_performance_summary': private / 'performance-paired-01/summary.json',
    }.items()}
    parity = read(output / 'TCP-UDP-parity/result.json')
    assert parity['passed'] and parity['case_count'] == 1736 and not parity['failures']
    pairs = [case for profile in parity['profiles'] for case in profile['cases'].values()]
    checks = {row['id']: row['strict_result'] for row in state['commands'] if 'strict_result' in row}
    report = {'schema': 'dnsmasq-fix3-types-functional-receipt-v1', 'passed_with_declared_baselines': True,
        'source_commit': plan['source_commit'], 'tool_commit': plan['tool_commit'], 'SDK_elf': bind(plan['rust']),
        'fresh_commands': 49, 'zero_exit_commands': 49, 'SDK_daemon_family_commands': 48,
        'native_state_probe_commands': 1, 'native_state_cases': 19,
        'complete_families': state['families'], 'family_commands': 35, 'directed_commands': 14,
        'retained': retained, 'endpoint_archives': endpoint_archives,
        'native_state_files': native_files, 'source_files': plan['source_files'], 'commands': commands,
        'directed_summary': {'N1': checks['N1-filter-cname'], 'review3_matrix': checks['review3-matrix'],
            'original_DNS_baseline': checks['A10-and-original-DNS'],
            'persistent_TCP_UDP_parity': {'profiles': len(parity['profiles']), 'paired_cases': len(pairs),
                'all_assertions_passed': True,
                'C_internal_routing_cases_following_common_UDP': sum(case['declared_common_UDP_semantics'] for case in pairs),
                'C_matched_transport_size_differences': sum(case['checks']['transport_size_difference'] for case in pairs)},
            'F08_stale_observation': checks['F08-stale-observation']},
        'initial_harness_failure': {'executed_state_cases': 0, 'executed_daemon_commands': 0,
            'cause': 'obsolete standalone rustc harness omitted complete crate dependencies; imports/build adapter fixed without changing frozen source or SDK'},
        'limits': ['No earlier functional pass reused; the first types compile failure and earlier unfavorable performance remain retained',
            'Native GNU/dev state helper is not the SDK daemon or performance executable',
            'F08 stale EDE, exact two forward-pointer baseline cases and eight ACL refusal representations remain explicit',
            'Nine C-internal routing cases deliberately follow shared UDP behavior; no general exception for C differences',
            'Ordinary RR TTL aging/compression normalized only in declared semantic checks; raw packet evidence retained']}
    args.out.mkdir(parents=True, exist_ok=False)
    for name, value in (('validation-types.json', report), ('validation-types-raw-index.json',
                        {'schema': 'dnsmasq-fix3-types-functional-raw-index-v1', 'files': list(files.values())})):
        (args.out / name).write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({'passed_with_declared_baselines': True, 'fresh_commands': 49,
         'validation_sha256': sha(args.out / 'validation-types.json'),
         'raw_index_sha256': sha(args.out / 'validation-types-raw-index.json')}))


if __name__ == '__main__':
    main()
