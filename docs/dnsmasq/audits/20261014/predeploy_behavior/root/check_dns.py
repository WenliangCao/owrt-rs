#!/usr/bin/env python3
"""Independently decode focused audit wire; no product/probe decoder imports."""
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
    raw = {side: json.loads((folder / 'result.json').read_text())
           for side, folder in [('c', c_dir), ('rust', rust_dir)]}
    decoded_count, observations = 0, {}
    for side, folder in [('c', c_dir), ('rust', rust_dir)]:
        trace = raw[side]
        assert trace['config_sha256'] == '273642923b52722c6b423c22d1586972e7475d78142c2f14185a940230ad9afe'
        assert trace['errors'] == [] and trace['process_exits'] == [0, 0]
        observations[side] = {}
        for case in trace['cases']:
            assert case['daemon_alive']
            rows = []
            for index, client in enumerate(case['clients']):
                request = folder / case['label'] / f'{index}.request'
                reply = folder / case['label'] / f'{index}.reply'
                sent = decode(request.read_bytes())
                assert sent['questions'] == [[client['host'], client['type'], 1]]
                row = {'type': client['type'], 'request_sha256': digest(request)}
                if 'response' in client:
                    received = decode(reply.read_bytes())
                    assert received == client['response'], (side, case['label'], index)
                    assert received['id'] == sent['id']
                    assert received['questions'] == sent['questions']
                    row.update(rcode=received['flags'] & 15, records=len(received['records']),
                               reply_sha256=digest(reply))
                    decoded_count += 1
                else:
                    assert not reply.exists()
                    row['error'] = client['error']
                rows.append(row)
            observations[side][case['label']] = rows
    c = next(x for x in raw['c']['cases'] if x['label'] == 'local-chain-outage')['clients']
    rust = next(x for x in raw['rust']['cases'] if x['label'] == 'local-chain-outage')['clients']
    assert c[0]['response'] == rust[0]['response'], 'warm response must match exactly'
    assert c[1]['response']['flags'] & 15 == 0 and c[1]['response']['records'] == []
    assert rust[1]['error'].startswith('TimeoutError:')
    requests = {side: [row['type'] for row in trace['upstream']
                      if row['stage'] == 'local-chain-outage'] for side, trace in raw.items()}
    assert requests == {'c': [1], 'rust': [1, 28]}, requests
    return {'independent_decoder': True, 'decoded_responses': decoded_count,
            'result_sha256': {side: digest(folder / 'result.json')
                              for side, folder in [('c', c_dir), ('rust', rust_dir)]},
            'raw_directories': {'c': str(c_dir), 'rust': str(rust_dir)},
            'b01_outage_confirmed': True, 'outage_upstream_types': requests,
            'observations': observations}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-dir', type=Path, required=True)
    parser.add_argument('--rust-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.c_dir, args.rust_dir)
    result['checker_sha256'] = digest(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'decoded_responses': result['decoded_responses'], 'b01_outage_confirmed': True}))
