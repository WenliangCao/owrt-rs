#!/usr/bin/env python3
"""M2 exact-image C/Rust DNS functional differential.

The command must run through ``run_isolated.sh``. It copies the verified image
rootfs, starts both implementations in separate fresh chroots, and compares
the raw/semantic DNS replies plus upstream transport and cache observations.
It is a functional gate; timings are retained only to prove bounded timeout
recovery and are never used as a performance result.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import time

from dns_service_probe import query
from m2_dns_support import Product, normalized_row
from m2_rootfs import prepare


ROOT = Path(__file__).resolve().parents[2]
IMAGE_SHA = '144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720'
STOCK_SHA = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
MIX_SEED = 29302026


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def profile_basic(product):
    rows = []
    rows.append(product.ask('a-fill', 'a.m2.test', expected_upstream=1))
    rows.append(product.ask('a-hit', 'a.m2.test', expected_upstream=0))
    rows.append(product.ask('aaaa-fill', 'aaaa.m2.test', 28, expected_upstream=1))
    rows.append(product.ask('ptr-fill', 'ptr.m2.test', 12, expected_upstream=1))
    rows.append(product.ask('alias-fill', 'alias.m2.test', expected_upstream=1))
    rows.append(product.ask('alias-hit', 'alias.m2.test', expected_upstream=0))
    rows.append(product.ask('nx-fill', 'nx.m2.test', expected_upstream=1))
    rows.append(product.ask('nx-hit', 'nx.m2.test', expected_upstream=0))
    rows.append(product.ask('nodata-fill', 'nodata.m2.test', expected_upstream=1))
    rows.append(product.ask('nodata-hit', 'nodata.m2.test', expected_upstream=0))
    rows.append(product.ask('local-host-record', 'desktop.home.test', expected_upstream=0))
    return rows


def profile_expiry(product):
    rows = []
    rows.append(product.ask('positive-before-expiry', 'expiry-positive.m2.test', expected_upstream=1))
    rows.append(product.ask('positive-hit', 'expiry-positive.m2.test', expected_upstream=0))
    time.sleep(3.3)
    product.servers[0].configure(generation=2)
    rows.append(product.ask('positive-after-expiry', 'expiry-positive.m2.test', expected_upstream=1))
    rows.append(product.ask('negative-before-expiry', 'expiry-negative.m2.test', expected_upstream=1))
    rows.append(product.ask('negative-hit', 'expiry-negative.m2.test', expected_upstream=0))
    time.sleep(3.3)
    product.servers[0].configure(generation=2)
    rows.append(product.ask('negative-after-expiry', 'expiry-negative.m2.test', expected_upstream=1))
    return rows


def profile_tcp(product):
    rows = []
    rows.append(product.ask('udp-seed-fill', 'udp-seed.m2.test', expected_upstream=1))
    stream = product.connection('tcp-main', client=0)
    rows.append(product.ask('udp-seed-tcp-hit', 'udp-seed.m2.test', connection='tcp-main', expected_upstream=0))
    rows.append(product.ask('tcp-a-fill', 'tcp-a.m2.test', connection='tcp-main', expected_upstream=1))
    rows.append(product.ask('tcp-a-hit', 'tcp-a.m2.test', connection='tcp-main', expected_upstream=0))
    rows.append(product.pipeline('tcp-pipeline', [('tcp-b.m2.test', 1), ('tcp-c.m2.test', 28)], 'tcp-main'))
    rows.append(product.ask('tcp-upstream', 'truncated.m2.test', connection='tcp-main', fragmented=True, expected_upstream=1))
    rows.append(product.ask('tcp-negative', 'nx.tcp.m2.test', connection='tcp-main', expected_upstream=1))
    rows.append(product.ask('tcp-learned-fill', 'tcp-learned.m2.test', connection='tcp-main', expected_upstream=1))
    product.close_connection('tcp-main')
    rows.append(product.ask('tcp-learned-udp-hit', 'tcp-learned.m2.test', expected_upstream=0))
    fresh = product.connection('tcp-fresh', client=1)
    rows.append(product.ask('tcp-fresh-cache', 'tcp-a.m2.test', connection='tcp-fresh', expected_upstream=0))
    product.close_connection('tcp-fresh')
    return rows


def profile_failure(product):
    rows = []
    product.servers[0].configure('silent')
    product.servers[1].configure('answer', generation=2)
    rows.append(product.ask('primary-timeout-no-reply', 'failover.m2.test', expect_reply=False, expected_upstream=1))
    product.servers[0].configure('answer', generation=3)
    product.servers[1].configure('silent')
    rows.append(product.ask('primary-recovered', 'recovered.m2.test', expected_upstream=1))
    product.servers[0].configure('servfail')
    product.servers[1].configure('answer', generation=4)
    rows.append(product.ask('servfail-secondary-answer', 'servfail.m2.test', expected_upstream=2))
    product.servers[0].configure('refused')
    product.servers[1].configure('answer', generation=5)
    rows.append(product.ask('refused-secondary-answer', 'refused.m2.test', expected_upstream=2))
    product.servers[0].configure('answer', generation=6)
    product.servers[1].configure('answer', generation=6)
    return rows


def profile_mix(product):
    # The deterministic sequence is deliberately synthetic. Its 80/20 split
    # follows the single observed metrics snapshot, while QTYPE/transport and
    # answer classes are explicit representative assumptions from plan.json.
    rows = []
    # Expiry is qualified separately with a short-TTL profile. Mixed traffic
    # retains raw TTLs for C/Rust comparison without treating wall-clock
    # scheduling as a performance or expiry assertion.
    product.validate_ttl = False
    names = []
    for index in range(700):
        names.append((f'mix-a-{index if index < 600 else index - 600}.m2.test', 1, 'udp'))
    for index in range(250):
        names.append((f'mix-aaaa-{index if index < 150 else index - 150}.m2.test', 28, 'udp'))
    for index in range(50):
        names.append((f'mix-ptr-{index % 10}.m2.test', 12, 'tcp'))
    # Stable stride interleaving avoids grouping all record types and makes
    # repeat/cache behavior deterministic under the fixed seed.
    order = sorted(range(len(names)), key=lambda index: ((index * 7919 + MIX_SEED) % len(names), index))
    stream = product.connection('mix-tcp', client=19)
    seen = set()
    for sequence, index in enumerate(order):
        host, kind, transport = names[index]
        key = (host, kind)
        repeat = key in seen
        seen.add(key)
        if transport == 'tcp':
            label = f'mix-{sequence:04d}-tcp'
            rows.append(product.ask(label, host, kind, connection='mix-tcp', expected_upstream=0 if repeat else 1))
        else:
            label = f'mix-{sequence:04d}-udp'
            rows.append(product.ask(label, host, kind, expected_upstream=0 if repeat else 1))
    product.close_connection('mix-tcp')
    return rows


PROFILES = {
    'udp-cache': profile_basic,
    'expiry': profile_expiry,
    'tcp': profile_tcp,
    'failure-recovery': profile_failure,
    'representative-mix': profile_mix,
}


def run_side(args, side, profile, out):
    root = prepare(args.image_root, args.runtime_root, out, args.rust)
    product = Product(root, side, out / 'service', servers=2 if profile == 'failure-recovery' else 1)
    try:
        product.start()
        rows = PROFILES[profile](product)
        trace = product.close()
        trace['rows'] = rows
        trace['side'] = side
        trace['profile'] = profile
        trace['root_identity'] = json.loads((out / 'rootfs-identity.json').read_text())
        (out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
        return trace
    except BaseException:
        product.close()
        raise


def normalized_trace(trace):
    return {'profile': trace['profile'], 'rows': [normalized_row(row) for row in trace['rows']]}


def compare(c_trace, rust_trace):
    left, right = normalized_trace(c_trace), normalized_trace(rust_trace)
    differences = []
    for index, (c_row, rust_row) in enumerate(zip(left['rows'], right['rows'])):
        if c_row != rust_row:
            differences.append({'row': index, 'c': c_row, 'rust': rust_row})
    return {'planned': len(left['rows']), 'compared': min(len(left['rows']), len(right['rows'])),
            'unexecuted': abs(len(left['rows']) - len(right['rows'])), 'differences': differences}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--runtime-root', type=Path)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--profile', choices=sorted(PROFILES), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise SystemExit('run through tools/dnsmasq/run_isolated.sh as root')
    if sorted(name for _, name in __import__('socket').if_nameindex()) != ['lo']:
        raise SystemExit('isolated loopback-only namespace required')
    if digest(args.image_root / 'usr/sbin/dnsmasq') != STOCK_SHA:
        raise SystemExit('exact image dnsmasq SHA-256 mismatch')
    out = args.out.resolve()
    if 'private' not in out.parts or out.exists():
        raise SystemExit('fresh output under private/ required')
    out.mkdir(parents=True)
    c_trace = run_side(args, 'c', args.profile, out / 'c')
    rust_trace = run_side(args, 'rust', args.profile, out / 'rust')
    report = compare(c_trace, rust_trace)
    report.update({'profile': args.profile, 'seed': MIX_SEED if args.profile == 'representative-mix' else None,
                   'c_sha256': digest((out / 'c/rootfs/usr/sbin/dnsmasq')), 'rust_sha256': digest((out / 'rust/rootfs/usr/sbin/dnsmasq-rs')),
                   'image_sha256': IMAGE_SHA, 'failures': []})
    if report['unexecuted']:
        report['failures'].append('row-count mismatch')
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value if key != 'differences' else len(value) for key, value in report.items()}))
    return int(bool(report['differences'] or report['failures'] or report['unexecuted']))


if __name__ == '__main__':
    raise SystemExit(main())
