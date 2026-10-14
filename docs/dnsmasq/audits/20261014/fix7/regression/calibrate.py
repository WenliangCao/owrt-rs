#!/usr/bin/env python3
"""Negative-control calibration of the full-field decoder used by FIX7."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    path = args.source / 'docs/dnsmasq/audits/20261014/fix5/dns/collect.py'
    spec = importlib.util.spec_from_file_location('decoder', path)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    raw = json.loads(args.result.read_text())
    response = raw['cases'][0]['sides']['c']['response']
    original = decoder.decode(response)
    packet = bytes.fromhex(response['hex'])
    assert len(packet) == 154
    assert packet[31:33] == bytes.fromhex('c00c')
    controls = {}
    # First RR: owner 31..32, TYPE 33..34, CLASS 35..36, TTL 37..40,
    # RDLENGTH 41..42, uncompressed target RDATA begins at 43.
    for name, offset in [('header-flags', 3), ('question-type', 28),
                         ('rr-type', 34), ('rr-class', 36), ('rr-ttl', 40),
                         ('rdata-label', 44)]:
        changed = bytearray(packet)
        changed[offset] ^= 1
        mutated = copy.deepcopy(response)
        mutated['hex'] = changed.hex()
        value = decoder.decode(mutated)
        controls[name] = {'detected': value != original, 'parse_error': value.get('parse_error')}
        assert value != original, name
    changed = bytearray(packet)
    # Turn the last c062 RDATA into a self-referential pointer (offset 152).
    changed[-2:] = struct.pack('!H', 0xc000 | 152)
    mutated = {**response, 'hex': changed.hex()}
    value = decoder.decode(mutated)
    assert 'parse_error' in value and value != original
    controls['name-cycle'] = {'detected': True, 'parse_error': value['parse_error']}
    assert decoder.decode({'status': 'eof'}) != original
    controls['transport-eof'] = {'detected': True}
    output = {'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'decoder_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'input_sha256': hashlib.sha256(args.result.read_bytes()).hexdigest(),
              'controls': controls, 'ttl_tolerance_seconds': 0}
    args.out.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output))


if __name__ == '__main__':
    main()
