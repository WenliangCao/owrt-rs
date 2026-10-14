#!/usr/bin/env python3
"""Apply the FIX5 full-field decoder to fresh FIX6 observations.

Importing the frozen checker deliberately preserves comparison policy.
Original frames remain private; the receipt binds their hashes and identities.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('groups', nargs='+')
    args = parser.parse_args()
    checker = Path(__file__).resolve().parents[2] / 'fix5/dns/collect.py'
    spec = importlib.util.spec_from_file_location('fix5_full_field_decoder', checker)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = {'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'decoder_sha256': hashlib.sha256(checker.read_bytes()).hexdigest(),
                'groups': {}}
    for name in args.groups:
        result = module.collect(args.root / name / 'result.json',
            '/home/ubuntu/dnsmasq-audit-fix6-20261014/private/' + name + '/result.json')
        evidence['groups'][name] = result
        print(name, json.dumps(result['counts']))
    args.out.write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    main()
