#!/usr/bin/env python3
"""Offline negative controls for a saved M2 DNS differential trace.

This tool never starts a daemon or opens a socket. It proves that the saved
comparison detects a changed reply, missing work, and an omitted upstream
exchange. Inputs and the generated report must remain below private/.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from m2_dns_diff import compare


def load(path):
    return json.loads(Path(path).read_text())


def summary(result):
    return {key: value if key not in ('differences', 'failures') else len(value)
            for key, value in result.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-trace', type=Path, required=True)
    parser.add_argument('--rust-trace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if 'private' not in out.parts or out.exists():
        raise SystemExit('fresh output under private/ required')
    out.mkdir(parents=True)
    c_trace, rust_trace = load(args.c_trace), load(args.rust_trace)
    baseline = compare(c_trace, rust_trace)
    if baseline['differences'] or baseline['unexecuted']:
        raise SystemExit('saved traces are not a clean comparison baseline')

    cases = {'baseline': baseline}
    changed = copy.deepcopy(rust_trace)
    changed['rows'][0]['responses'][0] = '00'
    changed['rows'][0]['semantic'][0]['records'][0]['data'] = 'mutated-rdata'
    cases['changed_reply'] = compare(c_trace, changed)
    if len(cases['changed_reply']['differences']) != 1:
        raise SystemExit('changed reply was not detected')

    missing = copy.deepcopy(rust_trace)
    missing['rows'].pop()
    cases['missing_row'] = compare(c_trace, missing)
    if cases['missing_row']['unexecuted'] != 1:
        raise SystemExit('missing row was not detected')

    exchange = copy.deepcopy(rust_trace)
    exchange['rows'][0]['upstream'] = []
    cases['omitted_upstream_exchange'] = compare(c_trace, exchange)
    if not cases['omitted_upstream_exchange']['differences']:
        raise SystemExit('omitted upstream exchange was not detected')

    report = {'service_executions': 0,
              'inputs_sha256': {'c': hashlib.sha256(args.c_trace.read_bytes()).hexdigest(),
                                'rust': hashlib.sha256(args.rust_trace.read_bytes()).hexdigest()},
              'cases': {name: summary(result) for name, result in cases.items()}}
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
