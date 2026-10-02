#!/usr/bin/env python3
"""C/Rust upstream timeout, RCODE, recovery, strict-order and all-servers gate."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket

from m2_dns_diff import PROFILES
from m2_rootfs import prepare, sha256
from m3_soak import SoakProduct


def run_side(args, side, out):
    out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, out / 'rootfs-stage', args.rust)
    product = SoakProduct(root, side, out / 'service', clients=1)
    try:
        product.start()
        rows = PROFILES[args.profile](product)
        trace = product.close()
        trace.update({'rows': rows, 'side': side, 'profile': args.profile,
                      'root_identity': json.loads((out / 'rootfs-stage/rootfs-identity.json').read_text()),
                      'binary_sha256': sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))})
        (out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
        return trace
    except BaseException:
        product.close()
        raise


def normalized(trace):
    rows = []
    for row in trace['rows']:
        value = {key: copy.deepcopy(row[key]) for key in
                 ('label', 'semantic', 'transport', 'client', 'upstream', 'expect_reply', 'expected_upstream')}
        for answer in value['semantic']:
            for record in answer['records']:
                record.pop('ttl', None)
        rows.append(value)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--profile', choices=('failure-recovery', 'strict-order', 'all-servers'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise SystemExit('run through run_isolated.sh')
    if sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        raise SystemExit('loopback-only namespace required')
    args.out.mkdir(parents=True, exist_ok=False)
    traces = {side: run_side(args, side, args.out / side) for side in ('c', 'rust')}
    left, right = normalized(traces['c']), normalized(traces['rust'])
    differences = [{'row': i, 'c': c, 'rust': r} for i, (c, r) in enumerate(zip(left, right)) if c != r]
    result = {'profile': args.profile, 'planned': len(left), 'compared': min(len(left), len(right)),
              'differences': differences, 'unexecuted': abs(len(left) - len(right)),
              'c_sha256': traces['c']['binary_sha256'], 'rust_sha256': traces['rust']['binary_sha256'],
              'negative_controls': ['missing-row', 'changed-upstream-rcode']}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'profile': args.profile, 'difference_count': len(differences),
                      'unexecuted': result['unexecuted']}))
    return int(bool(differences or result['unexecuted']))


if __name__ == '__main__':
    raise SystemExit(main())
