#!/usr/bin/env python3
"""Full wire comparison plus configuration-derived expectations; no canonical fields."""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path


def sha(value):
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    decoder_path = args.source / 'docs/dnsmasq/audits/20261014/fix6/build/new-boundary-check.py'
    spec = importlib.util.spec_from_file_location('wire', decoder_path)
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    expected_sha = {
        'c': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
        'main': 'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863',
        'before': 'a52bfb0b7725fc8d8179645b13133fbd12e2c73e1419d5e9c135115887eadd66',
        'fix': sha((args.root / 'private/release/dnsmasq-rs').read_bytes()),
    }
    label = lambda text: [v.encode().hex() for v in text.split('.')]
    target, example, alias = map(label, ('target.example', 'example', 'alias.example'))

    def validate(case, direct=False):
        family, size = case['profile'].split('-')
        size = int(size)
        c = case['sides']['c']
        parsed, layout = wire.decode(bytes.fromhex(c['response']['hex']))
        assert c['response']['status'] == 'reply'
        expected_eof = case['protocol'] == 'tcp' and size == 220 and not direct
        sides = {}
        for role, side in case['sides'].items():
            assert side['alive'] and side['exit'] == 0, (case['label'], role, 'lifecycle')
            assert side['warm'] == c['warm'] and side['warm']['status'] == 'reply'
            assert side['health'] == c['health'] and side['health']['status'] == 'reply'
            assert not side['upstream'] and len(side['warm_upstream']) == 1
            response = side['response']
            if role == 'before' and expected_eof:
                assert response == {'status': 'eof'}, (case['label'], role, response['status'])
                sides[role] = {'status': 'eof'}
                continue
            assert response['status'] == 'reply', (case['label'], role, response['status'])
            packet = bytes.fromhex(response['hex'])
            semantic, actual_layout = wire.decode(packet)
            assert semantic == parsed, (case['label'], role, 'full-fields')
            sides[role] = {'status': 'reply', 'bytes': len(packet), 'sha256': sha(packet),
                           'all_fields_equal_c': True,
                           'tail_layout': actual_layout[-3:]}
        if case['protocol'] == 'tcp':
            records = []
            for line in case['config'].splitlines():
                if line.startswith('txt-record='):
                    data = line.split(',')[1].encode()
                    records.append([target, 16, 1, 60, (bytes([len(data)]) + data).hex()])
                elif line.startswith('dns-rr='):
                    records.append([target, int(line.split(',')[1]), 1, 60, line.split(',')[2]])
            records.reverse()
            records += [[target, 1, 1, 60, 'c000024d'], [target, 15, 1, 60, [10, example]]]
            if not direct:
                records.insert(0, [alias, 5, 1, 300, target])
            additional = [[example, 1, 1, 60, 'c0000214']]
            if family == 'dual':
                additional.append([example, 28, 1, 60, ipaddress.ip_address('2001:db8::20').packed.hex()])
            assert parsed['sections'] == [records, [], additional], case['label']
            assert parsed['header'][1:] == [0x8580, 1, len(records), 0, len(additional)]
            assert parsed['questions'] == [[target if direct else alias, 255, 1]]
            mx = next(r for r in layout if r['kind'] == 15)
            mx_target = mx['rdata_start'] + 2
            assert mx_target == ({193: 16375, 201: 16383, 220: 16402}[size] - (27 if direct else 0))
            assert [r['owner_wire'] for r in layout if r['section'] == 'additional'] == [
                (0xc000 | mx_target).to_bytes(2, 'big').hex()] * len(additional)
        else:
            assert parsed['header'][1] & 0x200
            assert all(not records for records in parsed['sections'])
            mx_target = None
        return {'label': case['label'], 'direct': direct, 'profile': case['profile'],
                'protocol': case['protocol'], 'config_sha256': sha(case['config'].encode()),
                'before_eof_expected_and_observed': expected_eof,
                'mx_target': mx_target, 'c_header': parsed['header'],
                'semantics_sha256': sha(json.dumps(parsed, sort_keys=True).encode()),
                'all_warm_health_upstream_lifecycle_checks': True, 'sides': sides}

    report = {'checker_sha256': sha(Path(__file__).read_bytes()),
              'decoder_sha256': sha(decoder_path.read_bytes()), 'identities': expected_sha,
              'comparison': 'All header fields, ordered questions/sections, owner/type/class/TTL/RDATA; only compression normalized.',
              'groups': [], 'calibration': {}}
    data_by_group = {}
    for group, count in [('alias', 36), ('direct', 12)]:
        path = args.root / 'private/boundary' / group / 'result.json'
        raw = path.read_bytes()
        data = json.loads(raw)
        assert len(data['cases']) == count
        assert {key: data['identities'][key] for key in expected_sha} == expected_sha
        rows = [validate(case, group == 'direct') for case in data['cases']]
        report['groups'].append({'name': group, 'raw_private_path': str(path),
                                 'raw_sha256': sha(raw), 'cases': rows})
        data_by_group[group] = data
    old_path = args.root.parent / 'dnsmasq-audit-fix6-20261014/private/root-boundary-recheck/dns/result.json'
    old_bytes = old_path.read_bytes()
    old = json.loads(old_bytes)
    assert len(old['cases']) == 12
    for case in old['cases']:
        current = next(row for row in data_by_group['alias']['cases']
                       if row['profile'] == 'txt-' + case['profile'].split('-')[-1]
                       and (row['protocol'], row['debug']) == (case['protocol'], case['debug']))
        for key in ('config', 'query', 'warm_query'):
            assert current[key] == case[key], (case['label'], key)
    report['original_fix6_fixture_match'] = {
        'raw_private_path': str(old_path), 'raw_sha256': sha(old_bytes), 'cases': 12,
        'config_query_and_warm_query_byte_identical': True,
        'scope': 'Input comparison only; FIX6 runs are not counted as fresh FIX7 executions.'}
    fixture = next(case for case in data_by_group['alias']['cases']
                   if case['profile'] == 'txt-220' and case['protocol'] == 'tcp')
    for mutation in ('head_eof', 'hide_before_eof', 'ttl', 'additional_owner', 'health'):
        changed = copy.deepcopy(fixture)
        side = changed['sides']['fix']
        if mutation == 'head_eof':
            side['response'] = {'status': 'eof'}
        elif mutation == 'hide_before_eof':
            changed['sides']['before']['response'] = side['response']
        elif mutation == 'health':
            side['health'] = {'status': 'timeout'}
        else:
            packet = bytearray.fromhex(side['response']['hex'])
            _, layout = wire.decode(packet)
            if mutation == 'ttl':
                packet[layout[0]['fixed'] + 7] ^= 1
            else:
                packet[layout[-1]['start'] + 1] ^= 1
            side['response']['hex'] = packet.hex()
        try:
            validate(changed)
        except (AssertionError, ValueError, IndexError):
            report['calibration'][mutation] = 'rejected'
        else:
            raise AssertionError('missed mutation: ' + mutation)
    report['cases'], report['daemon_runs'] = 48, 192
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('cases', 'daemon_runs', 'calibration')}))


if __name__ == '__main__':
    main()
