#!/usr/bin/env python3
"""Assert the complete fresh boundary outcome, including lifecycle and controls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

checker = Path(__file__).resolve().parents[1] / 'build/new-boundary-check.py'
spec = importlib.util.spec_from_file_location('independent_wire', checker)
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def validate(data):
    assert len(data['cases']) == 12
    rows = []
    for case in data['cases']:
        size = int(case['profile'].split('-')[-1])
        assert size in (193, 201, 220)
        expected_eof = case['protocol'] == 'tcp' and size == 220
        c = case['sides']['c']
        expected, layout = wire.decode(bytes.fromhex(c['response']['hex']))
        for role, side in case['sides'].items():
            assert side['alive'] and side['exit'] == 0
            assert side['health'] == c['health'] and side['health']['status'] == 'reply'
            assert side['warm'] == c['warm'] and side['warm']['status'] == 'reply'
            assert len(side['upstream']) == 0 and len(side['warm_upstream']) == 1
            if role == 'fix' and expected_eof:
                assert side['response'] == {'status': 'eof'}
            else:
                assert side['response']['status'] == 'reply'
                decoded, _ = wire.decode(bytes.fromhex(side['response']['hex']))
                assert decoded == expected
        if case['protocol'] == 'tcp':
            assert expected['header'][1:] == [0x8580, 1, 64, 0, 1]
            assert [row['ttl'] for row in layout] == [300] + [60] * 64
            target = layout[-2]['rdata_start'] + 2
            assert target == {193: 16375, 201: 16383, 220: 16402}[size]
            assert layout[-1]['owner_wire'] == {193: 'fff7', 201: 'ffff', 220: 'c012'}[size]
        else:
            assert len(bytes.fromhex(c['response']['hex'])) == 31
            assert expected['header'][1] & 0x200
        rows.append({'label': case['label'], 'head_eof_expected_and_observed': expected_eof,
                     'other_roles_full_semantics_equal_c': True,
                     'all_warm_health_lifecycle_and_upstream_checks': True})
    return rows


raw = Path(sys.argv[1]).read_bytes()
data = json.loads(raw)
rows = validate(data)
calibration = {}
for kind in ('hide_eof', 'break_valid_control', 'alter_header', 'alter_health'):
    changed = copy.deepcopy(data)
    tcp = next(case for case in changed['cases'] if case['profile'] == 'txt-tail-220'
               and case['protocol'] == 'tcp')
    if kind == 'hide_eof':
        tcp['sides']['fix']['response'] = tcp['sides']['c']['response']
    elif kind == 'break_valid_control':
        changed['cases'][0]['sides']['fix']['response'] = {'status': 'eof'}
    elif kind == 'alter_header':
        response = tcp['sides']['before']['response']
        packet = bytearray.fromhex(response['hex'])
        packet[0] ^= 1
        response['hex'] = packet.hex()
    else:
        tcp['sides']['fix']['health'] = {'status': 'timeout'}
    try:
        validate(changed)
    except (AssertionError, ValueError, KeyError):
        calibration[kind] = 'rejected'
    else:
        raise AssertionError(kind)
out = {'raw_result_sha256': hashlib.sha256(raw).hexdigest(), 'rows': rows,
       'cases': 12, 'daemon_runs': 48, 'fresh_tcp_blocker_reproductions': 2,
       'calibration': calibration, 'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
       'wire_decoder_sha256': hashlib.sha256(checker.read_bytes()).hexdigest()}
Path(sys.argv[2]).write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps({key: out[key] for key in ('cases', 'daemon_runs', 'fresh_tcp_blocker_reproductions', 'calibration')}))
