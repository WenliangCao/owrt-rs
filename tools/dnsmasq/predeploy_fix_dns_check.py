#!/usr/bin/env python3
"""Independently verify the repaired predeployment DNS packet sequences."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(packet):
    def name(offset):
        labels, seen, resume = [], set(), None
        while True:
            assert offset < len(packet) and offset not in seen
            seen.add(offset)
            length = packet[offset]
            offset += 1
            if length == 0:
                return '.'.join(labels).lower(), resume or offset
            if length & 192 == 192:
                assert offset < len(packet)
                resume = resume or offset + 1
                offset = ((length & 63) << 8) | packet[offset]
            else:
                assert length <= 63 and offset + length <= len(packet)
                labels.append(packet[offset:offset + length].decode('ascii'))
                offset += length

    assert len(packet) >= 12
    ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    result = dict(id=ident, flags=flags, questions=[], records=[])
    offset = 12
    for _ in range(qd):
        owner, offset = name(offset)
        kind, cls = struct.unpack_from('!HH', packet, offset)
        offset += 4
        result['questions'].append([owner, kind, cls])
    for section, count in [('answer', an), ('authority', ns), ('additional', ar)]:
        for _ in range(count):
            owner, offset = name(offset)
            kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
            offset += 10
            end = offset + length
            assert end <= len(packet)
            if kind in (1, 28):
                assert length == (4 if kind == 1 else 16)
                data = str(ipaddress.ip_address(packet[offset:end]))
            elif kind in (2, 5, 12):
                data, consumed = name(offset)
                assert consumed == end
            else:
                data = packet[offset:end].hex()
            result['records'].append(dict(section=section, name=owner, type=kind,
                                          **{'class': cls}, ttl=ttl, data=data))
            offset = end
    assert offset == len(packet), 'unconsumed wire bytes'
    return result


def check(c_dir, rust_dir):
    decoded, traces, raw_hashes = {}, {}, {}
    for side, folder in [('c', c_dir), ('rust', rust_dir)]:
        trace = json.loads((folder / 'result.json').read_text())
        assert trace['config_sha256'] == '273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe'
        assert trace['errors'] == [] and trace['process_exits'] == [0, 0]
        traces[side], decoded[side], raw_hashes[side] = trace, {}, {}
        for case in trace['cases']:
            assert case['daemon_alive']
            rows = []
            for index, client in enumerate(case['clients']):
                request = folder / case['label'] / f'{index}.request'
                reply = folder / case['label'] / f'{index}.reply'
                sent, received = decode(request.read_bytes()), decode(reply.read_bytes())
                assert sent['questions'] == [[client['host'], client['type'], 1]]
                assert received == client['response']
                assert received['id'] == sent['id'] and received['questions'] == sent['questions']
                rows.append(received)
                raw_hashes[side][str(request.relative_to(folder))] = digest(request)
                raw_hashes[side][str(reply.relative_to(folder))] = digest(reply)
            decoded[side][case['label']] = rows
    assert decoded['c'] == decoded['rust'], 'independent full packet semantics differ'
    for side, rows in decoded.items():
        outage = rows['local-chain-outage'][1]
        assert outage['flags'] & 15 == 0 and outage['records'] == []
        for transport in ('udp', 'tcp'):
            initial = rows['direct-terminal-before-' + transport][0]
            address = rows['direct-terminal-a-' + transport][0]
            nodata = rows['direct-terminal-' + transport][0]
            assert initial['flags'] & 15 == 3
            assert address['flags'] & 15 == 0
            assert [(r['type'], r['data']) for r in address['records']] == [(1, '8.8.4.4')]
            assert nodata['flags'] & 15 == 0 and nodata['records'] == []
    requests = {side: [row['type'] for row in trace['upstream']
                       if row['stage'] == 'local-chain-outage'] for side, trace in traces.items()}
    assert requests == {'c': [1], 'rust': [1]}, requests
    return {'independent_decoder': True, 'b01_fixed': True, 'b02_fixed': True,
            'decoded_responses': sum(len(rows) for cases in decoded.values() for rows in cases.values()),
            'outage_upstream_types': requests,
            'binary_sha256': {side: trace['binary_sha256'] for side, trace in traces.items()},
            'raw_directories': {'c': str(c_dir), 'rust': str(rust_dir)},
            'result_sha256': {side: digest(folder / 'result.json')
                              for side, folder in [('c', c_dir), ('rust', rust_dir)]},
            'raw_packet_sha256': raw_hashes}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-dir', type=Path, required=True)
    parser.add_argument('--rust-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.c_dir, args.rust_dir)
    result['checker_sha256'] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('decoded_responses', 'b01_fixed', 'b02_fixed')}))
