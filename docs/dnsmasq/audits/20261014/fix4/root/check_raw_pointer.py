#!/usr/bin/env python3
"""Independently decode the blocking raw-pointer controls, preserving TTLs."""
import hashlib
import importlib.util
import json
from pathlib import Path

here = Path(__file__).resolve().parent
source = here.parent / 'dns/raw-pointer-controls.json'
decoder = here.parent / 'dhcp_config/negative_final.py'
spec = importlib.util.spec_from_file_location('independent_dns_decoder', decoder)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
data = json.loads(source.read_text())
checks = []
for group in data['groups']:
    if group['host_anchor'] or not group['upstream_ns']:
        continue
    for row in group['cases']:
        sides = row['sides']
        c, main = [module.decode(bytes.fromhex(sides[side]['response']['hex'])) for side in ('c', 'main')]
        assert c == main, row['label']
        assert c['header'] == [0x1234, 0x8580, 1, 2, 0, 0]
        assert [rr['type'] for rr in c['records']] == [5, 2]
        assert [rr['ttl'] for rr in c['records']] == [300, 60]
        assert len(sides['c']['upstream']) == 0 and len(sides['main']['upstream']) == 1
        assert len(sides['fix']['upstream']) == 0
        assert all(side['alive'] and side['exit'] == 0 for side in sides.values())
        record = dict(label=row['label'], c_main_full_semantics_equal=True,
                      ttl=[300, 60], c_main_fix_upstream=[0, 1, 0],
                      branch_status=sides['fix']['response']['status'])
        if row['profile'] == 'raw-ns-target-pointer':
            packet = bytes.fromhex(sides['c']['response']['hex'])
            assert packet[-2:] == b'\xc0\x2b'
            assert packet[43:59] == b'\x06target\x07example\0'
            assert c['records'][1]['data'] == ['target'.encode().hex(), 'example'.encode().hex()]
            assert record['branch_status'] == ('timeout' if row['protocol'] == 'udp' else 'eof')
            record['C_pointer_43_names_target'] = True
        else:
            assert row['profile'] == 'raw-ns-pointer'
            fix = module.decode(bytes.fromhex(sides['fix']['response']['hex']))
            assert c['records'][1]['data'] == ['alias'.encode().hex(), 'example'.encode().hex()]
            assert fix['records'][1]['data'] == ['target'.encode().hex(), 'example'.encode().hex()]
            fix['records'][1]['data'] = c['records'][1]['data']
            assert fix == c
            record['branch_only_decoded_difference'] = 'NS target: alias.example -> target.example'
        checks.append(record)
assert len(checks) == 8
result = dict(passed=True, cases=checks, response_comparison='All decoded fields including TTL; compression only normalized.',
              inputs={'raw_pointer_controls': sha(source), 'independent_decoder': sha(decoder), 'checker': sha(Path(__file__))})
(here / 'raw-pointer-independent.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'passed': True, 'cases': len(checks)}))
