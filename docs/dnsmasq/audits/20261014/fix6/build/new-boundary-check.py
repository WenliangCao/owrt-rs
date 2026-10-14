#!/usr/bin/env python3
"""Independently decode boundary audit raw packets; preserve TTL and section order."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def name(packet, start):
    cursor, end, labels, visited = start, None, [], set()
    while True:
        assert cursor < len(packet) and cursor not in visited
        visited.add(cursor)
        size = packet[cursor]
        if size & 0xc0 == 0xc0:
            assert cursor + 1 < len(packet)
            pointer = ((size & 0x3f) << 8) | packet[cursor + 1]
            assert pointer < cursor, (pointer, cursor)
            if end is None:
                end = cursor + 2
            cursor = pointer
        elif size == 0:
            if end is None:
                end = cursor + 1
            assert sum(len(label) + 1 for label in labels) + 1 <= 255
            return [label.hex() for label in labels], end
        else:
            assert size < 64 and cursor + 1 + size <= len(packet)
            labels.append(packet[cursor + 1:cursor + 1 + size])
            cursor += 1 + size


def decode(packet):
    assert len(packet) >= 12
    header = list(struct.unpack_from('!6H', packet))
    cursor, questions, sections, layout = 12, [], [], []
    for _ in range(header[2]):
        owner, cursor = name(packet, cursor)
        kind, klass = struct.unpack_from('!HH', packet, cursor)
        cursor += 4
        questions.append([owner, kind, klass])
    for section, count in zip(('answer', 'authority', 'additional'), header[3:]):
        records = []
        for _ in range(count):
            start = cursor
            owner, fixed = name(packet, cursor)
            kind, klass, ttl, size = struct.unpack_from('!HHIH', packet, fixed)
            data_start, end = fixed + 10, fixed + 10 + size
            assert end <= len(packet)
            raw = packet[data_start:end]
            if kind == 5:
                data, actual_end = name(packet, data_start)
                assert actual_end == end
            elif kind == 15:
                preference = struct.unpack_from('!H', packet, data_start)[0]
                target, actual_end = name(packet, data_start + 2)
                assert actual_end == end
                data = [preference, target]
            else:
                if kind == 1:
                    assert len(raw) == 4
                if kind == 16:
                    position = 0
                    while position < len(raw):
                        position += raw[position] + 1
                        assert position <= len(raw)
                    assert position == len(raw)
                data = raw.hex()
            records.append([owner, kind, klass, ttl, data])
            layout.append({'section': section, 'start': start, 'fixed': fixed,
                           'rdata_start': data_start, 'end': end, 'kind': kind,
                           'owner_wire': packet[start:fixed].hex(), 'ttl': ttl,
                           'owner': owner})
            cursor = end
        sections.append(records)
    assert cursor == len(packet), (cursor, len(packet))
    return {'header': header, 'questions': questions, 'sections': sections}, layout


def inspect(path):
    raw = Path(path).read_bytes()
    source = json.loads(raw)
    rows = []
    for case in source['cases']:
        canonical, sides = {}, {}
        for role, side in case['sides'].items():
            wire = side['response']
            row = {'status': wire['status'], 'final_upstream_count': len(side['upstream']),
                   'warm_upstream_count': len(side['warm_upstream']), 'alive': side['alive'],
                   'exit': side['exit'], 'health': side['health']['status']}
            warm, _ = decode(bytes.fromhex(side['warm']['hex']))
            row['warm_semantics_sha256'] = sha(json.dumps(warm, sort_keys=True).encode())
            if wire['status'] == 'reply':
                packet = bytes.fromhex(wire['hex'])
                semantic, layout = decode(packet)
                canonical[role] = semantic
                row.update(length=len(packet), raw_sha256=sha(packet), header=semantic['header'],
                           semantics_sha256=sha(json.dumps(semantic, sort_keys=True).encode()),
                           ttl=[record['ttl'] for record in layout],
                           layout_edges=layout[:1] + layout[-3:], tail_records=[section[-2:] for section in semantic['sections']])
            sides[role] = row
        if case['protocol'] == 'tcp':
            expected_raw = [[['746172676574', '6578616d706c65'], int(line.split(',')[1]), 1, 60,
                             line.split(',')[2]]
                            for line in case['config'].splitlines() if line.startswith('dns-rr=')]
            expected_raw += [[['746172676574', '6578616d706c65'], 16, 1, 60,
                              (bytes([len(line.split(',')[1])]) + line.split(',')[1].encode()).hex()]
                             for line in case['config'].splitlines() if line.startswith('txt-record=')]
            expected_raw.reverse()
            expected_answer = expected_raw + [
                [['746172676574', '6578616d706c65'], 1, 1, 60, 'c000024d'],
                [['746172676574', '6578616d706c65'], 15, 1, 60, [10, ['6578616d706c65']]]]
            if canonical['c']['questions'][0][0] == ['616c696173', '6578616d706c65']:
                expected_answer.insert(0, [['616c696173', '6578616d706c65'], 5, 1, 300,
                                           ['746172676574', '6578616d706c65']])
            assert canonical['c']['sections'] == [expected_answer, [], [
                [['6578616d706c65'], 1, 1, 60, 'c0000214']]]
            assert canonical['c']['header'][1] == 0x8580

        checks = {role + '_all_fields_equal_c': canonical.get(role) == canonical['c']
                  for role in ('main', 'before', 'fix')}
        rows.append({'label': case['label'], 'protocol': case['protocol'],
                     'config_sha256': sha(case['config'].encode()),
                     'strict_checks': checks, 'sides': sides})
    return {'input': str(path), 'input_sha256': sha(raw), 'identities': source['identities'],
            'comparison': 'New independent decoder; all DNS header bits/id/counts, questions, ordered sections, owners, types, classes, TTLs and RDATA preserved; only name compression normalized.',
            'cases': rows}


if __name__ == '__main__':
    result = {'checks': [inspect(path) for path in sys.argv[1:-1]],
              'checker_sha256': sha(Path(__file__).read_bytes())}
    Path(sys.argv[-1]).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([[{'label': row['label'], **row['strict_checks']} for row in check['cases']]
                      for check in result['checks']], indent=2))
