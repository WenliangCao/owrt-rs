#!/usr/bin/env python3
"""Strict FIX5 receipt from retained synthetic frames; never discard RR TTLs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def decode(response):
    if response['status'] != 'reply':
        return {'transport': response}
    packet = bytes.fromhex(response['hex'])

    def name(pos):
        labels, seen, end = [], set(), None
        while True:
            if pos >= len(packet) or pos in seen:
                raise ValueError(f'name bounds/cycle at {pos}')
            seen.add(pos)
            length = packet[pos]
            if length & 192 == 192:
                if pos + 1 >= len(packet):
                    raise ValueError('short pointer')
                end = end if end is not None else pos + 2
                pos = ((length & 63) << 8) | packet[pos + 1]
            elif length == 0:
                return labels, end if end is not None else pos + 1
            elif length <= 63 and pos + 1 + length <= len(packet):
                labels.append(packet[pos + 1:pos + 1 + length].hex())
                pos += 1 + length
            else:
                raise ValueError(f'invalid label {length:02x} at {pos}')

    try:
        header = list(struct.unpack_from('!6H', packet))
        result = {'header': header, 'questions': [], 'sections': []}
        pos = 12
        for _ in range(header[2]):
            owner, pos = name(pos)
            kind, cls = struct.unpack_from('!HH', packet, pos)
            pos += 4
            result['questions'].append([owner, kind, cls])
        for count in header[3:]:
            section = []
            for _ in range(count):
                owner, pos = name(pos)
                kind, cls, ttl, size = struct.unpack_from('!HHIH', packet, pos)
                pos += 10
                end = pos + size
                if end > len(packet):
                    raise ValueError('RDATA beyond frame')
                data = packet[pos:end].hex()
                if kind in (2, 3, 4, 5, 7, 8, 9, 12, 30, 39):
                    data, consumed = name(pos)
                    if consumed != end:
                        raise ValueError('name RDLENGTH')
                elif kind in (6, 14, 17):
                    first, consumed = name(pos)
                    second, consumed = name(consumed)
                    data = [first, second, packet[consumed:end].hex()]
                    if consumed + (20 if kind == 6 else 0) != end:
                        raise ValueError('two-name RDLENGTH')
                elif kind in (15, 18, 21, 36, 33):
                    prefix = 6 if kind == 33 else 2
                    target, consumed = name(pos + prefix)
                    data = [packet[pos:pos + prefix].hex(), target]
                    if consumed != end:
                        raise ValueError('prefixed-name RDLENGTH')
                section.append([owner, kind, cls, ttl, data])
                pos = end
            result['sections'].append(section)
        if pos != len(packet):
            raise ValueError('unconsumed packet bytes')
        return result
    except (ValueError, IndexError, struct.error) as error:
        return {'parse_error': str(error), 'hex': response['hex']}


def collect(path, origin):
    raw = path.read_bytes()
    data = json.loads(raw)
    result = {'origin': origin, 'sha256': hashlib.sha256(raw).hexdigest(),
              'identities': data['identities'], 'comparison': 'All header/question/ordered section/RDATA/TTL fields; normalize only name compression. Malformed replies require exact raw equality.',
              'counts': {}, 'cases': []}
    for row in data.get('cases', data.get('runs', [])):
        sides = row['sides']
        decoded = {k: decode(v['response']) for k, v in sides.items()}
        checks = {}
        for key in sides:
            if key == 'c':
                continue
            checks[key + '_strict_equals_c'] = decoded[key] == decoded['c']
            checks[key + '_upstream_count_equals_c'] = len(sides[key]['upstream']) == len(sides['c']['upstream'])
        if 'before' in sides:
            checks['before_strict_equals_fix'] = decoded['before'] == decoded['fix']
        warm_key = 'warm' if 'warm' in sides['c'] else 'warm_response'
        if warm_key in sides['c']:
            checks['warm_all_strict_equal'] = all(decode(v[warm_key]) == decode(sides['c'][warm_key]) for v in sides.values())
        checks['all_alive'] = all(v['alive'] for v in sides.values())
        checks['all_exit_zero'] = all(v['exit'] == 0 for v in sides.values())
        health_key = 'health' if 'health' in sides['c'] else 'health_after_connection_close'
        checks['all_health_reply'] = all(v[health_key]['status'] == 'reply' for v in sides.values())
        for key, value in checks.items():
            count = result['counts'].setdefault(key, {'passed': 0, 'total': 0})
            count['passed'] += bool(value)
            count['total'] += 1
        item = {'label': row.get('label', row.get('name')), 'checks': checks,
                'upstream_counts': {k: len(v['upstream']) for k, v in sides.items()},
                'statuses': {k: v['response']['status'] for k, v in sides.items()},
                'parse_errors': {k: v['parse_error'] for k, v in decoded.items() if 'parse_error' in v}}
        if len(data.get('cases', data.get('runs', []))) <= 16:
            item.update(config=row['config'], query=row['query'], responses={k: v['response'] for k, v in sides.items()})
        result['cases'].append(item)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('groups', nargs='+')
    a = p.parse_args()
    result = {'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'groups': {}}
    for group in a.groups:
        result['groups'][group] = collect(a.root / group / 'result.json',
            '/home/ubuntu/dnsmasq-audit-fix5-20261014/private/' + group + '/result.json')
    a.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v['counts'] for k, v in result['groups'].items()}, indent=2))


if __name__ == '__main__':
    main()
