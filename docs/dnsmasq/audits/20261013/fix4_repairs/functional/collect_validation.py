#!/usr/bin/env python3
"""Verify every fresh job and retain raw-evidence hashes for the final SDK run."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def receipt(path):
    path = Path(path)
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = read(args.plan)
    source, output = Path(plan['source']), Path(plan['output'])
    state_path = output / 'state.json'
    state = read(state_path)
    assert state['passed'] and state['plan_sha256'] == sha(args.plan)
    assert len(plan['jobs']) == len(state['commands']) == 49
    for path, expected in plan['assets'].items():
        assert sha(path) == expected, path
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import build_package as package
    import m5_final_validation as final
    sys.path.insert(0, str(source / 'docs/dnsmasq/audits/20261013/fix4_repairs/functional'))
    from validate_final import exact_n1
    assert package.inputs(source) == plan['source_files']
    commands = []
    for job, record in zip(plan['jobs'], state['commands']):
        assert all(record[key] == value for key, value in job.items()), job['id']
        assert record['passed'] and record['returncode'] == 0
        assert sha(record['result']) == record['result_sha256']
        if 'family' in job:
            final.check_result(Path(job['result']), job['checks'], job.get('inventory'))
        commands.append({**{key: record[key] for key in ('id', 'argv', 'returncode', 'started', 'elapsed_seconds')},
                         'family': record.get('family'), 'result': receipt(record['result']),
                         'log': receipt(output / (record['id'] + '.log')),
                         'strict_result': record.get('strict_result')})
    assert len(state['families']) == 14
    assert sum(row['commands'] for row in state['families'].values()) == 35
    assert all(row['passed'] for row in state['families'].values())
    n1 = exact_n1(read(output / 'N1-filter-cname/result.json'))
    assert n1['passed']
    parity = read(output / 'TCP-UDP-parity/result.json')
    assert parity['passed'] and parity['case_count'] == 1736 and not parity['failures']
    endpoint_root = output / 'families/m5_dns_endpoints'
    endpoint_archives = {}
    for name in ('syntax', 'service'):
        receipts = {suffix: receipt(endpoint_root / (name + suffix)) for suffix in
                    ('.tar.gz', '.manifest.json', '.pack.json', '.local-verification.json', '.prune.json', '.restore.json')}
        local = read(endpoint_root / (name + '.local-verification.json'))
        manifest = read(endpoint_root / (name + '.manifest.json'))
        assert local['verified'] and local['local_full_metadata_verified']
        assert local['archive_sha256'] == receipts['.tar.gz']['sha256'] == manifest['archive_sha256']
        assert local['manifest_sha256'] == receipts['.manifest.json']['sha256']
        assert sha(endpoint_root / name / 'result.json') == manifest['entries']['result.json']['sha256']
        endpoint_archives[name] = {'files': receipts, 'entries': len(manifest['entries']),
                                   'local_full_metadata_verified': True, 'original_result_bytes_retained': True}
    index = [receipt(path) for path in sorted(output.rglob('*')) if path.is_file()]
    report = {'schema': 'dnsmasq-fix4-functional-v1', 'passed_with_declared_baselines': True,
              'source_commit': plan['source_commit'], 'SDK_elf': receipt(plan['rust']),
              'source_files': plan['source_files'], 'fresh_commands': 49,
              'SDK_daemon_family_commands': 48, 'native_state_probe_commands': 1,
              'complete_families': state['families'], 'family_commands': 35,
              'endpoint_archives': endpoint_archives,
              'plan': receipt(args.plan), 'state': receipt(state_path), 'commands': commands,
              'N1': n1, 'TCP_UDP_parity_cases': parity['case_count'],
              'limits': ['Exact N1 compares packet hex and TTL without normalization',
                         'Other inherited checks retain only their predeclared historical differences',
                         'Nine C-internal routing cases use shared C UDP semantics, not equivalence to C TCP',
                         'F08 stale EDE, two forward-pointer cases and eight ACL refusal representations remain explicit',
                         'Native configuration probes are not SDK daemon artifacts',
                         'No deployment or physical-router qualification'],
              'collector': receipt(__file__)}
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    (args.out / 'raw-index.json').write_text(json.dumps({'schema': 'dnsmasq-fix4-functional-raw-index-v1', 'files': index}, indent=2) + '\n')
    print(json.dumps({'passed': True, 'fresh_commands': 49, 'raw_files': len(index),
                      'validation': receipt(args.out / 'validation.json')}))


if __name__ == '__main__':
    main()
