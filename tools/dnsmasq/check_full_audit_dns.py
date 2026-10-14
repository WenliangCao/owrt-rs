#!/usr/bin/env python3
"""Check retained full-audit DNS wires without trusting stored equality flags."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct

from audit_20261011_dns import local_cases

C_SHA = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
RUST_SHA = 'e0ec75310a545d4f31822bb299f10674a6f12d639cc4cbd528e0e737b25c6bd0'
PROFILES = {'local': 116, 'forward': 84, 'filter': 84, 'rebind': 84}


def dns_name(packet, offset, seen=()):
    """Decode a name with an explicit compression-loop and bounds check."""
    labels = []
    while True:
        if offset in seen or offset >= len(packet):
            raise ValueError('name compression cycle or out-of-bounds offset')
        seen += (offset,)
        size = packet[offset]
        offset += 1
        if size == 0:
            return b'.'.join(labels), offset
        if size & 0xc0 == 0xc0:
            if offset >= len(packet):
                raise ValueError('truncated compression pointer')
            suffix, _ = dns_name(packet, ((size & 63) << 8) | packet[offset], seen)
            return b'.'.join(labels + [suffix]), offset + 1
        if size & 0xc0 or offset + size > len(packet):
            raise ValueError('invalid label')
        labels.append(packet[offset:offset + size])
        offset += size


def check(data, expected_rust_sha=RUST_SHA):
    assert data['c_sha256'] == C_SHA and data['rust_sha256'] == expected_rust_sha
    assert set(data['profiles']) == set(PROFILES)
    totals = {}
    differences = []
    local = {(label, proto): packet.hex() for label, packet in local_cases()
             for proto in ('udp', 'tcp')}
    for label, count in PROFILES.items():
        profile = data['profiles'][label]
        rows = profile['cases']
        assert len(rows) == count
        assert len({(row['name'], row['protocol'], row['query_hex']) for row in rows}) == count
        if label == 'local':
            assert {(row['name'], row['protocol']): row['query_hex'] for row in rows} == local
        for side in ('c', 'rust'):
            process = profile['processes'][side]
            assert process['ready'] and process['alive_after_cases'] and process['exit'] == 0
            assert process['health_after']['status'] == 'reply'
            assert bytes.fromhex(process['health_after']['hex'])[-4:] == bytes([192, 0, 2, 42])
        upstream_count = 0
        for row in rows:
            left, right = row['c'], row['rust']
            for outcome in (left, right):
                if outcome['status'] == 'reply':
                    wire = bytes.fromhex(outcome['hex'])
                    assert outcome['length'] == len(wire)
                    assert outcome['header'] == list(struct.unpack('!6H', wire[:12]))
            c_upstream, rust_upstream = left['upstream'], right['upstream']
            assert [x['protocol'] for x in c_upstream] == [x['protocol'] for x in rust_upstream]
            upstream_count += len(c_upstream)
            left = {k: v for k, v in left.items() if k != 'upstream'}
            right = {k: v for k, v in right.items() if k != 'upstream'}
            if left != right:
                assert label == 'local' and row['name'] == 'forward-pointer'
                c_wire, rust_wire = bytes.fromhex(left['hex']), bytes.fromhex(right['hex'])
                try:
                    dns_name(c_wire, 12)
                except ValueError:
                    pass
                else:
                    raise AssertionError('expected independently verified C compression cycle')
                host, end = dns_name(rust_wire, 12)
                assert host == b'host.audit.test' and rust_wire[end:end + 4] == b'\0\1\0\1'
                owner, end = dns_name(rust_wire, end + 4)
                assert owner == host
                assert struct.unpack('!HHIH', rust_wire[end:end + 10]) == (1, 1, 60, 4)
                assert rust_wire[end + 10:] == bytes([192, 0, 2, 42])
                differences.append({'profile': label, 'case': row['name'], 'protocol': row['protocol'],
                                    'classification': 'C compression cycle; Rust valid expanded answer'})
        totals[label] = {'paired_cases': count, 'upstream_requests_each_side': upstream_count}
    assert len(differences) == 2
    return {'paired_cases': sum(PROFILES.values()), 'exact_client_matches': sum(PROFILES.values()) - 2,
            'profiles': totals, 'differences': differences, 'daemon_lifecycles': 8}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rust-sha256', default=RUST_SHA,
                        help='Expected tested ELF SHA-256; defaults to the original audit baseline')
    args = parser.parse_args()
    if len(args.rust_sha256) != 64 or any(c not in '0123456789abcdef' for c in args.rust_sha256):
        parser.error('--rust-sha256 must be a lowercase SHA-256 digest')
    data = json.loads(args.input.read_text())
    result = check(data, args.rust_sha256)
    controls = []
    for kind in ('missing-case', 'changed-wire', 'failed-health', 'forged-comparison', 'wrong-rust-identity'):
        wrong = copy.deepcopy(data)
        rows = wrong['profiles']['local']['cases']
        if kind == 'missing-case':
            rows.pop()
        elif kind == 'failed-health':
            wrong['profiles']['local']['processes']['rust']['alive_after_cases'] = False
        elif kind == 'wrong-rust-identity':
            digest = wrong['rust_sha256']
            wrong['rust_sha256'] = ('1' if digest[0] == '0' else '0') + digest[1:]
        else:
            rows[0]['rust']['hex'] = rows[0]['rust']['hex'][:-2] + 'ff'
            if kind == 'forged-comparison':
                rows[0]['same_client_result'] = True
        try:
            check(wrong, args.rust_sha256)
        except (AssertionError, ValueError):
            controls.append({'control': kind, 'rejected': True})
        else:
            raise AssertionError('negative control accepted: ' + kind)
    result.update(input_sha256=hashlib.sha256(args.input.read_bytes()).hexdigest(),
                  expected_rust_sha256=args.rust_sha256,
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  negative_controls=controls)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
