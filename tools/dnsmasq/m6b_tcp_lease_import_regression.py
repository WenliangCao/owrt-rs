#!/usr/bin/env python3
"""Image C/product regression for lease publication across a held TCP import.

Use the existing fixed interleaving schedule with feature-off products. This
checks wire behavior; the separate resource gate retains all internal balances.
"""
import argparse
import copy
import json
from pathlib import Path
import re

import m5_dns_cache as driver
import m6b_tcp_accept_snapshot as accept
import m6b_tcp_interleaved as interleaved

PROFILE = 'lease-held-import'
CASE = interleaved.CASES[PROFILE]['case']
TOOLS = list(dict.fromkeys(['m6b_tcp_lease_import_regression.py',
                           'm6b_tcp_accept_snapshot.py', *interleaved.TOOLS]))


def tool_files():
    return {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}


def validate_identity(trace, root, expected):
    if (trace['case'] != CASE or trace['config'] != interleaved.CASES[PROFILE]['config']
            or trace['identity']['sha256'] != expected
            or trace['identity']['root'] != root['root']):
        raise ValueError('actual regression profile/process/root binding differs')


def run(args):
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('frozen feature-off product ELF differs')
    frozen = tool_files()
    spec = copy.deepcopy(interleaved.CASES[PROFILE])
    spec.update(metrics=True, diagnostic=False,
                samples_after_drain_seconds=interleaved.DRAIN_SECONDS)
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = [spec]
    driver.schedule = interleaved.schedule
    args.only = '^' + re.escape(CASE) + '$'
    status = driver.run(args)
    for name, data in frozen.items():
        (args.out / 'drivers' / name).write_bytes(data)
    files = ['result.json', 'rootfs-identity.json', CASE + '/trace.json',
             CASE + '/interleaved-markers.json', CASE + '/upstream-wire-events.json']
    interleaved.write(args.out / 'regression-run-receipt.json', {
        'source_commit': args.source_commit, 'product_sha256': args.expected_rust_sha,
        'side': args.side, 'diagnostic': False,
        'completed_without_fixture_errors': status == 0,
        'tools_unchanged': tool_files() == frozen,
        'tools': {name: driver.sha256(args.out / 'drivers' / name) for name in TOOLS},
        'files': {name: driver.sha256(args.out / name) for name in files},
    })
    return status or int(tool_files() != frozen)


def read_run(args, side):
    folder = getattr(args, side)
    receipt = json.loads((folder / 'regression-run-receipt.json').read_text())
    if (receipt['source_commit'] != args.source_commit
            or receipt['product_sha256'] != args.expected_rust_sha or receipt['side'] != side
            or receipt['diagnostic'] is not False
            or receipt['completed_without_fixture_errors'] is not True
            or receipt['tools_unchanged'] is not True):
        raise ValueError('actual feature-off regression run failed or changed')
    for name, digest in receipt['files'].items():
        if driver.sha256(folder / name) != digest:
            raise ValueError('regression raw file differs: ' + name)
    for name in TOOLS:
        if driver.sha256(folder / 'drivers' / name) != receipt['tools'][name]:
            raise ValueError('actual regression driver differs')
    result = json.loads((folder / 'result.json').read_text())
    if (result['side'] != side or result['c_sha256'] != driver.STOCK_SHA256
            or result['rust_sha256'] != args.expected_rust_sha or result['failures']
            or result['executed_cases'] != [CASE] or len(result['scenarios']) != 1):
        raise ValueError('actual product regression inventory or identity differs')
    trace = result['scenarios'][0]
    work = folder / CASE
    expected = driver.STOCK_SHA256 if side == 'c' else args.expected_rust_sha
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    if root['rust_sha256'] != args.expected_rust_sha:
        raise ValueError('copied product ELF/root binding differs')
    validate_identity(trace, root, expected)
    if (trace != json.loads((work / 'trace.json').read_text()) or trace.get('failure')
            or trace['exit'] != 0 or trace['upstream_errors'] or trace['identity']['sha256'] != expected):
        raise ValueError('actual regression trace failed or differs')
    for row in trace['observations']:
        if 'query' in row and 'reply' in row:
            query = (work / (row['label'] + '.query')).read_bytes()
            reply = (work / (row['label'] + '.reply')).read_bytes()
            if (query[:2] != reply[:2] or driver.normalized(query) != row['query']
                    or driver.normalized(reply) != row['reply']):
                raise ValueError('actual transaction wire differs')
    markers = json.loads((work / 'interleaved-markers.json').read_text())
    if (markers['profile'] != PROFILE or markers['capacity'] != 150
            or markers['clients'] != 2 or len(markers['batches']) != 10):
        raise ValueError('complete fixed lease interleaving schedule missing')
    upstream = json.loads((work / 'upstream-wire-events.json').read_text())
    interleaved.validate_actions(PROFILE, trace['observations'], work, upstream, trace['upstream'])
    provenance = accept.root_provenance(root)
    return receipt, trace, upstream, provenance


def compare(args):
    if args.out.exists():
        raise ValueError('fresh regression comparison output required')
    c, rust = read_run(args, 'c'), read_run(args, 'rust')
    upstream = lambda rows: [{key: row[key] for key in ['transport', 'release', 'query', 'reply']}
                             for row in rows]
    if (c[0]['tools'] != rust[0]['tools'] or c[3] != rust[3]
            or interleaved.answer_semantics(c[1]['observations'])
            != interleaved.answer_semantics(rust[1]['observations'])
            or upstream(c[2]) != upstream(rust[2])):
        raise ValueError('image C/product lease-import wire or order differs')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    interleaved.write(args.out, {
        'source_commit': args.source_commit, 'product_sha256': args.expected_rust_sha,
        'passed': True, 'profile': PROFILE, 'measured_batches': 10,
        'c_receipt_sha256': driver.sha256(args.c / 'regression-run-receipt.json'),
        'rust_receipt_sha256': driver.sha256(args.rust / 'regression-run-receipt.json'),
        'scope': 'feature-off product held TCP/DHCP wire regression; resource/CPU qualification separate',
    })
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    invoke = sub.add_parser('run')
    invoke.add_argument('--image-root', type=Path, required=True)
    invoke.add_argument('--rust', type=Path, required=True)
    invoke.add_argument('--side', choices=['c', 'rust'], required=True)
    invoke.add_argument('--out', type=Path, required=True)
    pair = sub.add_parser('compare')
    for name in ['c', 'rust', 'out']:
        pair.add_argument('--' + name, type=Path, required=True)
    for command in [invoke, pair]:
        command.add_argument('--source-commit', required=True)
        command.add_argument('--expected-rust-sha', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit) or not re.fullmatch('[0-9a-f]{64}', args.expected_rust_sha):
        parser.error('full frozen source/product identities required')
    return run(args) if args.action == 'run' else compare(args)


if __name__ == '__main__':
    raise SystemExit(main())
