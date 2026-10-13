#!/usr/bin/env python3
"""Compare independent exact-image boundary runs without normalizing DNS TTLs."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def response(row):
    return {key: value for key, value in row.items() if key != 'upstream'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('main_result', type=Path)
    parser.add_argument('final_result', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    before, after = [json.loads(path.read_text()) for path in (args.main_result, args.final_result)]
    assert before['c_sha256'] == after['c_sha256']
    assert before['tool_sha256'] == after['tool_sha256']
    report = {
        'schema': 'dnsmasq-fix4-independent-boundaries-v1',
        'method': 'Full client response dictionaries, including packet bytes and TTL; upstream count compared separately. No normalization.',
        'artifacts': {'c': after['c_sha256'], 'main': before['rust_sha256'], 'final_sdk': after['rust_sha256']},
        'tool_sha256': after['tool_sha256'],
        'inputs': {label: {'path': str(path), 'sha256': digest(path), 'timestamp': data['timestamp']}
                   for label, path, data in [('main', args.main_result, before), ('final', args.final_result, after)]},
        'profiles': {}, 'changes': [], 'remaining_C_differences': [],
    }
    for name, old in before['profiles'].items():
        new = after['profiles'][name]
        assert old['config'] == new['config']
        assert len(old['cases']) == len(new['cases'])
        health = {}
        for revision, profile in [('main', old), ('final', new)]:
            for side, state in profile['processes'].items():
                health[f'{revision}/{side}'] = {key: state[key] for key in ('ready', 'alive_after_cases', 'exit')}
                assert state['ready'] and state['alive_after_cases'] and state['exit'] == 0
                assert state['health_after']['status'] == 'reply'
        profile_result = {'cases': len(new['cases']), 'config': new['config'], 'health': health,
                          'C_repeated_identically': 0, 'final_matches_C': 0,
                          'all_upstream_counts_equal': True}
        for x, y in zip(old['cases'], new['cases']):
            assert (x['name'], x['protocol'], x['query_hex']) == (y['name'], y['protocol'], y['query_hex'])
            old_c, new_c = response(x['c']), response(y['c'])
            main_r, final_r = response(x['rust']), response(y['rust'])
            assert old_c == new_c
            profile_result['C_repeated_identically'] += 1
            counts = [len(row[side]['upstream']) for row in (x, y) for side in ('c', 'rust')]
            assert len(set(counts)) == 1
            record = {'profile': name, 'case': y['name'], 'transport': y['protocol'],
                      'query_hex': y['query_hex'], 'C': new_c, 'main': main_r, 'final': final_r,
                      'upstream_count': counts[0]}
            if main_r != final_r:
                report['changes'].append(record)
            if final_r != new_c:
                report['remaining_C_differences'].append(record)
            else:
                profile_result['final_matches_C'] += 1
        report['profiles'][name] = profile_result
    report['case_count'] = sum(p['cases'] for p in report['profiles'].values())
    report['changed_cases_all_align_with_C'] = all(r['final'] == r['C'] for r in report['changes'])
    report['remaining_differences_all_present_on_main'] = all(r['final'] == r['main'] for r in report['remaining_C_differences'])
    report['collector_sha256'] = digest(Path(__file__))
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
