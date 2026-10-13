"""Strict assertions around the original review probes, which only record data."""
import json
from pathlib import Path
from wire_compare import canonical, common_udp_case, parity_checks


def check_matrix(result):
    failures, exceptions, counts = [], [], {}
    historical = json.loads(Path(__file__).with_name('historical-differences.json').read_text())
    old = {(row['profile'], row['case']): row for row in historical['records']}
    assert len(result['profiles']) == 29
    for profile in result['profiles']:
        name = profile['name']
        counts[name] = len(profile['cases'])
        assert len(profile['cases']) == (116 if name == 'malformed' else 62)
        for label, case in profile['cases'].items():
            current = canonical(case['fix']['response'])
            expected_side = case['c']
            query = label.rsplit('-', 1)[0]
            common = common_udp_case(name, query)
            inherited_parser = name == 'malformed' and label.startswith('forward-pointer-')
            if inherited_parser:
                expected_side = old[(name, label)]['previous']
            elif common and label.endswith('-tcp'):
                expected_side = profile['cases'][query + '-udp']['c']
            expected = canonical(expected_side['response'])
            if current != expected:
                failures.append({'profile': name, 'case': label, 'kind': 'answer'})
            if 'upstream' in expected_side and case['fix']['upstream'] != expected_side['upstream']:
                failures.append({'profile': name, 'case': label, 'kind': 'upstream-count'})
            if common or inherited_parser:
                exceptions.append({'profile': name, 'case': label,
                    'reason': 'declared common UDP semantics' if common else 'unchanged forward-pointer parser difference'})
            if label.endswith('-udp') and name != 'malformed':
                tcp = profile['cases'][query + '-tcp']
                checks = parity_checks(case['c']['response'], tcp['c']['response'],
                    case['fix']['response'], tcp['fix']['response'], common_udp=common)
                if not checks['transport_equal_or_C_truncation']:
                    failures.append({'profile': name, 'case': query, 'kind': 'transport-parity'})
        for side in ('c', 'fix'):
            health = profile['sides'][side]
            if name == 'malformed':
                if not health['alive']:
                    failures.append({'profile': name, 'side': side, 'kind': 'health'})
            elif not health['ready'] or health['exit'] != 0:
                failures.append({'profile': name, 'side': side, 'kind': 'health'})
    return {'passed': not failures, 'failures': failures, 'case_counts': counts,
            'declared_differences': exceptions}


def check_n1(result):
    assert len(result['runs']) == 72
    failures = []
    for row in result['runs']:
        c, rust = row['sides']['c'], row['sides']['fix']
        checks = {'both_reply': c['response']['status'] == rust['response']['status'] == 'reply',
                  'response': canonical(c['response']) == canonical(rust['response']),
                  'upstream-count': len(c['upstream']) == len(rust['upstream']),
                  'healthy': all(r['alive'] and r['exit'] == 0 for r in (c, rust))}
        if row['warmth'] != 'cold':
            checks['warm-response'] = canonical(c['warm_response']) == canonical(rust['warm_response'])
            checks['warm-upstream-count'] = len(c['warm_upstream']) == len(rust['warm_upstream'])
        failed = [key for key, value in checks.items() if not value]
        if failed:
            failures.append({'case': row['name'], 'checks': failed})
    return {'passed': not failures, 'cases': 72, 'failures': failures}


def check_n2(result):
    assert len(result['rows']) == 9
    failures = []
    for mode, debug in (('0o600', False), ('0o644', False), ('0o600', True)):
        rows = {row['side']: row for row in result['rows'] if row['mode'] == mode and row['debug'] == debug}
        c, rust = rows['c'], rows['fix']
        for field in ('startup', 'after_hup', 'permission_restored_hup', 'uid', 'exit'):
            if c[field] != rust[field]:
                failures.append({'mode': mode, 'debug': debug, 'field': field})
    return {'passed': not failures, 'failures': failures,
            'decision': 'intentional C permission boundary; no root-only hosts compatibility restoration'}


def observe_stale(result):
    """All rows are replayed, without turning the known F08 EDE gap into a pass."""
    assert len(result['cases']) == 8
    observations = []
    for debug in (False, True):
        for stale in (False, True):
            sides = {row['side']: row for row in result['cases'] if row['debug'] == debug and row['stale'] == stale}
            c, rust = sides['c'], sides['rust']
            observations.append({'debug': debug, 'stale': stale,
                'answer_equal': canonical({'status': 'reply', 'hex': c['tcp_after']}) == canonical({'status': 'reply', 'hex': rust['tcp_after']}),
                'healthy_ACK': all(row['alive'] and row['ack'] == 5 for row in (c, rust)),
                'C_wire': c['tcp_after'], 'Rust_wire': rust['tcp_after']})
    return {'executed': True, 'passed': all(row['healthy_ACK'] for row in observations),
            'observations': observations, 'equivalence_claim': all(row['answer_equal'] for row in observations)}
