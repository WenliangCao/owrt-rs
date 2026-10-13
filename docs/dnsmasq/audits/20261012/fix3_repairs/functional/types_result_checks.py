"""Known original-DNS parser baseline checker for a fresh artifact run.

Same exact two cases and health/other-response assertions used by the previous
continuation, applied directly to new raw results. Never reuse a prior pass.
"""
import json
from pathlib import Path


def check_original_dns(result):
    historical = json.loads(Path(__file__).with_name('historical-differences.json').read_text())
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
    return {'passed': True, 'freshly_executed_responses': 368, 'C_equal_responses': equal_count,
            'predeclared_exact_baseline_checks': checks, 'all_profile_health_equal': True,
            'limit': 'Two inherited forward-pointer parser differences are retained, not claimed equivalent to C'}
