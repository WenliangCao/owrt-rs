#!/usr/bin/env python3
"""Supplemental S1 gate: actual accept before the first DNS query.

Uses the M5 exact-image cache driver and public image UBus metrics. These two
ordinary caller scenarios supplement the full family; they do not replace
its 536-case/512-required qualification. Never substitutes native C.
"""
import argparse
import copy
import json
import re
import socket
import subprocess
import time
from pathlib import Path

import m5_dns_cache as driver


CASES = [
    {'case': 'm6b-accept-before-parent-learn', 'config': '', 'metrics': True, 'mode': 'learn'},
    {'case': 'm6b-accept-before-parent-replace', 'config': '', 'metrics': True, 'mode': 'replace'},
]
METRICS = ['tcp_connections', 'dns_cache_inserted', 'dns_cache_live_freed',
           'dns_queries_forwarded', 'dns_local_answered', 'dns_stale_answered']


def schedule(spec, port, upstream, folder, root):
    rows = []
    host = spec['case'] + '.cache.test'
    upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336407'}]}

    def metrics(label):
        argv = driver.command(root, '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}')
        run = subprocess.run(argv, capture_output=True, timeout=2)
        (folder / (label + '.metrics.stdout')).write_bytes(run.stdout)
        (folder / (label + '.metrics.stderr')).write_bytes(run.stderr)
        if run.returncode:
            raise AssertionError('image UBus metric call failed')
        value = json.loads(run.stdout)
        return {name: value[name] for name in METRICS}

    def wait_clients(count, label):
        deadline = time.monotonic() + 3
        samples = []
        while True:
            receipt = label + '-' + f'{len(samples):03}'
            value = metrics(receipt)
            samples.append({'receipt': receipt, 'metrics': value, 'monotonic_ns': time.monotonic_ns()})
            (folder / (label + '.metric-samples.json')).write_text(json.dumps(samples, indent=2) + '\n')
            if value['tcp_connections'] == count:
                return value
            if time.monotonic() >= deadline:
                raise AssertionError(('TCP accept/drain metric deadline', count, value))
            time.sleep(.005)

    def packet(label, tcp=False, connection=None):
        query = driver.query(host, 0x7400 + len(rows))
        before, wall_before = time.monotonic_ns(), time.time_ns()
        reply = driver.exchange(port, query, tcp=tcp, connection=connection)
        after, wall_after = time.monotonic_ns(), time.time_ns()
        (folder / (label + '.query')).write_bytes(query)
        if reply is not None:
            (folder / (label + '.reply')).write_bytes(reply)
        rows.append({'label': label, 'query': driver.normalized(query), 'reply': driver.normalized(reply),
                     'metrics': metrics(label), 'sent_monotonic_ns': before, 'completed_monotonic_ns': after,
                     'sent_realtime_ns': wall_before, 'completed_realtime_ns': wall_after})

    if spec['mode'] == 'replace':
        packet('seed-before-accept')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.bind((driver.CLIENT, 0))
        connection.connect((driver.LISTEN, port))
        # A completed connect or sleep is not an accept witness. No DNS is
        # sent on this connection until the actual parent metric confirms it.
        value = wait_clients(1, 'accept-before-first-query')
        accepted = time.monotonic_ns()
        rows.append({'label': 'accept-before-first-query', 'metrics': value,
                     'sent_monotonic_ns': accepted, 'completed_monotonic_ns': accepted})
        if spec['mode'] == 'replace':
            upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336408'}]}
            driver.process_hup(folder)
        packet('parent-mutation')
        packet('child-first-query', tcp=True, connection=connection)
        packet('parent-after-child')
    wait_clients(0, 'drained-first-connection')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.bind((driver.CLIENT, 0))
        connection.connect((driver.LISTEN, port))
        wait_clients(1, 'accept-next-view')
        packet('next-view', tcp=True, connection=connection)
    wait_clients(0, 'drained-next-connection')
    return rows


def valid_row(row, elf):
    labels = {v['label']: v for v in row.get('observations', [])}
    case = row.get('case')
    if case not in {c['case'] for c in CASES} or row.get('identity', {}).get('sha256') != elf:
        return False
    if row.get('failure') or row.get('exit') != 0 or row.get('upstream_errors'):
        return False
    expected = ['accept-before-first-query', 'parent-mutation', 'child-first-query', 'parent-after-child', 'next-view']
    if case.endswith('replace'):
        expected.insert(0, 'seed-before-accept')
    if [r['label'] for r in row['observations']] != expected:
        return False
    accepted, mutated, first = [labels[name] for name in ['accept-before-first-query', 'parent-mutation', 'child-first-query']]
    if accepted.get('metrics', {}).get('tcp_connections') != 1:
        return False
    if not accepted.get('completed_monotonic_ns', 0) < mutated.get('sent_monotonic_ns', 0) <= mutated.get('completed_monotonic_ns', 0) < first.get('sent_monotonic_ns', 0):
        return False
    for observation in row['observations']:
        if observation['label'] == 'accept-before-first-query':
            continue
        answers = [r for r in observation.get('reply', {}).get('records', []) if r['section'] == 'answer']
        wanted = '198.51.100.7' if case.endswith('learn') or observation['label'] in ['seed-before-accept', 'child-first-query'] else '198.51.100.8'
        if len(answers) != 1 or answers[0]['data'] != wanted or answers[0]['type'] != 1:
            return False
    transports = [e['transport'] for e in row.get('upstream', [])]
    return transports == (['udp', 'tcp'] if case.endswith('learn') else ['udp', 'udp'])


def raw_valid(folder, row):
    work = folder / row['case']
    root_identity = json.loads((folder / 'rootfs-identity.json').read_text())
    if row['identity']['root'] != root_identity['root']:
        return False
    for observation in row['observations']:
        label = observation['label']
        if label == 'accept-before-first-query':
            samples = json.loads((work / (label + '.metric-samples.json')).read_text())
            sample = samples[-1]
            raw = json.loads((work / (sample['receipt'] + '.metrics.stdout')).read_bytes())
            if (sample['metrics'] != observation['metrics']
                    or any(raw[key] != observation['metrics'][key] for key in METRICS)
                    or sample['monotonic_ns'] > observation['completed_monotonic_ns']):
                return False
        else:
            if any(driver.normalized((work / (label + '.' + kind)).read_bytes()) != observation[kind]
                   for kind in ['query', 'reply']):
                return False
            raw = json.loads((work / (label + '.metrics.stdout')).read_bytes())
            if any(raw[key] != observation['metrics'][key] for key in METRICS):
                return False
    return True


def run(args):
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('candidate ELF identity differs')
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = copy.deepcopy(CASES)
    driver.schedule = schedule
    args.only = '^m6b-accept-before-parent-'
    status = driver.run(args)
    out = args.out.resolve()
    saved = out / 'drivers/m6b_tcp_accept_snapshot.py'
    saved.write_bytes(Path(__file__).read_bytes())
    report = json.loads((out / 'result.json').read_text())
    elf = driver.STOCK_SHA256 if args.side == 'c' else args.expected_rust_sha
    errors = [row['case'] for row in report['scenarios'] if not valid_row(row, elf) or not raw_valid(out, row)]
    supplement = {'scope': __doc__, 'side': args.side, 'candidate_sha256': args.expected_rust_sha,
                  'driver_sha256': driver.sha256(saved), 'errors': errors,
                  'passed': status == 0 and not errors and len(report['scenarios']) == len(CASES)}
    (out / 'supplement.json').write_text(json.dumps(supplement, indent=2) + '\n')
    return int(not supplement['passed'])


def compare(args):
    reports = {}
    supplements = {}
    for side, folder in [('c', args.c), ('rust', args.rust)]:
        reports[side], rows = driver.comparison_rows(folder, side)
        supplements[side] = json.loads((folder / 'supplement.json').read_text())
        if not supplements[side]['passed'] or supplements[side]['driver_sha256'] != driver.sha256(__file__):
            raise ValueError('invalid or different supplemental gate')
        if any(not raw_valid(folder, row) for row in rows.values()):
            raise ValueError('supplemental raw receipts differ')
        reports[side]['rows'] = rows
    expected_elf = supplements['rust']['candidate_sha256']
    passed, controls = [], []
    for case in CASES:
        label = case['case']
        c, rust = [reports[side]['rows'][label] for side in ['c', 'rust']]
        check = lambda left, right: valid_row(left, driver.STOCK_SHA256) and valid_row(right, expected_elf) and driver.case_equal(left, right)
        if not check(c, rust):
            raise ValueError('C/R supplemental caller differs: ' + label)
        passed.append(label)
        for mode in ['missing-accept', 'unaccepted', 'early-first-query', 'wrong-answer', 'missing-upstream', 'wrong-elf']:
            bad = copy.deepcopy(rust)
            by_label = {v['label']: v for v in bad['observations']}
            if mode == 'missing-accept':
                bad['observations'].remove(by_label['accept-before-first-query'])
            elif mode == 'unaccepted':
                by_label['accept-before-first-query']['metrics']['tcp_connections'] = 0
            elif mode == 'early-first-query':
                by_label['child-first-query']['sent_monotonic_ns'] = by_label['accept-before-first-query']['completed_monotonic_ns'] - 1
            elif mode == 'wrong-answer':
                by_label['child-first-query']['reply']['records'][0]['data'] = '203.0.113.99'
            elif mode == 'missing-upstream':
                bad['upstream'].pop()
            else:
                bad['identity']['sha256'] = '0' * 64
            controls.append({'case': label, 'control': mode, 'rejected': not check(c, bad)})
    result = {'scope': __doc__, 'passed_cases': passed, 'negative_controls': controls,
              'passed': len(passed) == len(CASES) and all(c['rejected'] for c in controls),
              'candidate_sha256': expected_elf, 'c_sha256': driver.STOCK_SHA256}
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return int(not result['passed'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    invoke = sub.add_parser('run')
    invoke.add_argument('--image-root', type=Path, required=True)
    invoke.add_argument('--rust', type=Path, required=True)
    invoke.add_argument('--expected-rust-sha', required=True)
    invoke.add_argument('--side', choices=['c', 'rust'], required=True)
    invoke.add_argument('--out', type=Path, required=True)
    pair = sub.add_parser('compare')
    for name in ['c', 'rust', 'out']:
        pair.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'run' and not re.fullmatch('[0-9a-f]{64}', args.expected_rust_sha):
        parser.error('full frozen candidate SHA required')
    return run(args) if args.action == 'run' else compare(args)


if __name__ == '__main__':
    raise SystemExit(main())
