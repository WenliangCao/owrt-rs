#!/usr/bin/env python3
"""Requalify archived b99e observations; never overwrite the original raw run."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[6] / 'tools/dnsmasq'))
from f10_contract_check import check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--actual', type=Path, required=True)
    parser.add_argument('--allow-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    read = lambda path: json.loads(path.read_text())
    result = check(read(args.reference), read(args.actual), read(args.allow_manifest))
    result['inputs'] = {name: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in (('reference', args.reference), ('actual', args.actual), ('allow_manifest', args.allow_manifest))}
    result['scope'] = 'Offline requalification of the retained b99e run; no new runtime claim.'
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    return int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
