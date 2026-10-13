#!/usr/bin/env python3
"""Summarize N1 without waiving flags, TTL, sections, or packet loss."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--result', type=Path, required=True)
p.add_argument('--origin', required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
sys.path.insert(0, str(a.source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'))
from wire_compare import canonical


def with_ttls(response):
    result = canonical(response)
    if response['status'] != 'reply' or 'parse_error' in result:
        return result
    data = bytes.fromhex(response['hex'])
    header = struct.unpack_from('!6H', data)

    def skip_name(offset):
        while data[offset]:
            size = data[offset]
            if size & 192 == 192:
                return offset + 2
            if size > 63:
                raise ValueError('bad name')
            offset += size + 1
        return offset + 1

    offset = 12
    for _ in range(header[2]):
        offset = skip_name(offset) + 4
    result['all_ttls'] = []
    for count in header[3:]:
        section = []
        for _ in range(count):
            offset = skip_name(offset)
            _, _, ttl, size = struct.unpack_from('!HHIH', data, offset)
            section.append(ttl)
            offset += 10 + size
        result['all_ttls'].append(section)
    return result


raw = a.result.read_bytes()
result = json.loads(raw)
summary = {'origin': a.origin, 'raw_sha256': hashlib.sha256(raw).hexdigest(),
           'identities': result['identities'], 'total_runs': len(result['runs']),
           'comparison': 'TTL-aware full semantics; separately reports byte-for-byte packet equality.',
           'checks': {}, 'runs': []}
for run in result['runs']:
    c, main, fix = [run['sides'][side] for side in ('c', 'main', 'fix')]
    checks = {'main_wire_equals_c': main['response'] == c['response'],
              'fix_wire_equals_c': fix['response'] == c['response'],
              'main_ttl_semantics_equals_c': with_ttls(main['response']) == with_ttls(c['response']),
              'fix_ttl_semantics_equals_c': with_ttls(fix['response']) == with_ttls(c['response']),
              'fix_upstream_count_equals_c': len(fix['upstream']) == len(c['upstream']),
              'all_alive': all(v['alive'] for v in run['sides'].values()),
              'all_clean_exit': all(v['exit'] == 0 for v in run['sides'].values()),
              'all_health_reply': all(v['health_after_connection_close']['status'] == 'reply'
                                      for v in run['sides'].values())}
    if 'warm_response' in c:
        checks['fix_warm_wire_equals_c'] = fix['warm_response'] == c['warm_response']
        checks['fix_warm_ttl_semantics_equals_c'] = with_ttls(fix['warm_response']) == with_ttls(c['warm_response'])
        checks['fix_warm_upstream_count_equals_c'] = len(fix['warm_upstream']) == len(c['warm_upstream'])
    for key, value in checks.items():
        counts = summary['checks'].setdefault(key, {'passed': 0, 'total': 0})
        counts['passed'] += value
        counts['total'] += 1
    summary['runs'].append({'name': run['name'], 'query': run['query'], 'checks': checks,
        'responses': {side: v['response'] for side, v in run['sides'].items()},
        'upstream_counts': {side: len(v['upstream']) for side, v in run['sides'].items()},
        'warm_responses': {side: v.get('warm_response') for side, v in run['sides'].items()}})
a.out.write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary['checks'], indent=2))
