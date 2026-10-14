#!/usr/bin/env python3
"""Corrupt observed DNS fields to verify FIX6's strict decoder rejects them."""
import argparse
import copy
import json
from pathlib import Path
import struct

from negative_final import sha, strict_pair


def records(packet):
    def end_name(start):
        while packet[start]:
            if packet[start] & 0xc0 == 0xc0:
                return start + 2
            start += packet[start] + 1
        return start + 1

    header = struct.unpack_from('!6H', packet)
    pos = 12
    for _ in range(header[2]):
        pos = end_name(pos) + 4
    for section, count in zip(('answer', 'authority', 'additional'), header[3:]):
        for _ in range(count):
            start, fixed = pos, end_name(pos)
            kind, cls, ttl, size = struct.unpack_from('!HHIH', packet, fixed)
            data = fixed + 10
            yield dict(section=section, start=start, fixed=fixed, type=kind, ttl=ttl, data=data, end=data + size)
            pos = data + size


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--observed', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    observed = json.loads(a.observed.read_text())
    # This exact self-pair removes clock variation from corruption calibration.
    baseline = strict_pair(observed, copy.deepcopy(observed))
    index = next(i for i, e in enumerate(observed['events'])
                 if any(rr['type'] == 1 for rr in records(bytes.fromhex(e['packet'])))
                 and any(rr['type'] == 6 for rr in records(bytes.fromhex(e['packet']))))
    packet = bytearray.fromhex(observed['events'][index]['packet'])
    address = next(rr for rr in records(packet) if rr['type'] == 1)
    soa = next(rr for rr in records(packet) if rr['type'] == 6)
    checks = []
    for mutation in ('rcode', 'question', 'owner-pointer', 'answer-ttl', 'soa-ttl', 'soa-rdata', 'section-count', 'upstream'):
        changed = copy.deepcopy(observed)
        raw = bytearray(packet)
        if mutation == 'rcode':
            raw[3] ^= 1
        elif mutation == 'question':
            raw[13] ^= 1
        elif mutation == 'owner-pointer':
            raw[address['start']:address['start'] + 2] = b'\xc0\xff'
        elif mutation == 'answer-ttl':
            struct.pack_into('!I', raw, address['fixed'] + 4, address['ttl'] + 1)
        elif mutation == 'soa-ttl':
            struct.pack_into('!I', raw, soa['fixed'] + 4, soa['ttl'] - 2)
        elif mutation == 'soa-rdata':
            raw[soa['end'] - 1] ^= 1
        elif mutation == 'section-count':
            struct.pack_into('!H', raw, 10, struct.unpack_from('!H', raw, 10)[0] + 1)
        else:
            changed['events'][index]['upstream'].append(dict(transport='udp', host='unexpected.test', type=1, **{'class': 1}, enabled=True))
        changed['events'][index]['packet'] = raw.hex()
        try:
            strict_pair(observed, changed)
        except (AssertionError, IndexError, struct.error) as error:
            checks.append(dict(mutation=mutation, rejected=True, error_type=type(error).__name__))
        else:
            raise AssertionError('checker accepted ' + mutation)
    a.out.write_text(json.dumps(dict(status='passed', script_sha256=sha(__file__), checker_sha256=sha(Path(__file__).with_name('negative_final.py')),
        observed_path=str(a.observed), observed_sha256=sha(a.observed), self_pair=baseline,
        event=observed['events'][index]['label'], corruptions=checks), indent=2) + '\n')


if __name__ == '__main__':
    main()
