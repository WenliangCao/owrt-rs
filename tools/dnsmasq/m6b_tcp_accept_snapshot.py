#!/usr/bin/env python3
"""Supplemental S1/S6 gates: actual accept and failed parent import prefix.

Uses the M5 exact-image cache driver and public image UBus metrics. These
ordinary caller scenarios supplement the full family; they do not replace
its 536-case/512-required qualification. Never substitutes native C.
"""
import argparse
import copy
import json
import re
import socket
import struct
import subprocess
import time
from pathlib import Path

import m5_dns_cache as driver


CASES = [
    {'case': 'm6b-accept-before-parent-learn', 'config': '', 'metrics': True, 'mode': 'learn'},
    {'case': 'm6b-accept-before-parent-replace', 'config': '', 'metrics': True, 'mode': 'replace'},
    {'case': 'm6b-parent-import-failed-prefix', 'config': 'addn-hosts=/m2/caller.hosts',
     'initial_hosts': '', 'metrics': True, 'mode': 'failed-prefix'},
    {'case': 'm6b-child-eviction-parent-counters', 'config': '', 'capacity': 1,
     'metrics': True, 'mode': 'eviction'},
    {'case': 'm6b-cross-connection-progress', 'config': '', 'metrics': True, 'mode': 'cross'},
]
METRICS = ['tcp_connections', 'dns_cache_inserted', 'dns_cache_live_freed',
           'dns_queries_forwarded', 'dns_local_answered', 'dns_stale_answered']
TOOLS = ['m6b_tcp_accept_snapshot.py', 'm5_dns_cache.py', 'm5_dns_cache.json',
         'm2_rootfs.py', 'm2_rootfs_image.py', 'dns_service_probe.py', 'run_isolated.sh']


def root_provenance(root):
    filesystem = root.get('filesystem', {})
    if (root.get('c_sha256') != driver.STOCK_SHA256 or filesystem.get('kind') != 'overlay'
            or filesystem.get('lower_read_only') is not True
            or not re.fullmatch('[0-9a-f]{64}', filesystem.get('base_manifest_sha256', ''))
            or not root.get('image_files')):
        raise ValueError('exact-image immutable rootfs provenance missing')
    for key in ['image_sha256', 'image_provenance_sha256']:
        if key not in root or root[key] is not None and not re.fullmatch('[0-9a-f]{64}', root[key]):
            raise ValueError('image provenance identity differs')
    return {key: root[key] for key in ['c_sha256', 'image_sha256', 'image_provenance_sha256', 'image_files']} | {
        'base_manifest_sha256': filesystem['base_manifest_sha256']}


def frozen_tools():
    return {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}




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

    def packet(label, tcp=False, connection=None, target=None):
        query = driver.query(target or host, 0x7400 + len(rows))
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
    if spec['mode'] == 'eviction':
        target = 'parent.eviction.cache.test'
        upstream.plan[target] = {'ttl': 600, 'answers': [{'data': 'c6336407'}]}
        packet('seed-before-accept', target=target)
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
        if spec['mode'] == 'cross':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as second:
                second.settimeout(2)
                second.bind((driver.CLIENT, 0))
                second.connect((driver.LISTEN, port))
                wait_clients(2, 'accept-second')
                upstream.plan[host] = {'ttl': 600, 'hold': True, 'answers': [{'data': 'c6336415'}]}
                wire = driver.query(host, 0x7f01)
                started, wall_started = time.monotonic_ns(), time.time_ns()
                connection.sendall(struct.pack('!H', len(wire)) + wire)
                deadline = time.monotonic() + 2
                while not upstream.held:
                    if time.monotonic() >= deadline:
                        raise AssertionError('first TCP exchange not held')
                    time.sleep(.005)
                upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336416'}]}
                packet('second-completes-first', tcp=True, connection=second)
                packet('parent-pipe-barrier-b', target='health.cache.test')
                packet('parent-sees-second')
                upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336415'}]}
                upstream.release(host)
                reply = driver.exact_read(connection, struct.unpack('!H', driver.exact_read(connection, 2))[0])
                (folder / 'first-completes-later.query').write_bytes(wire)
                (folder / 'first-completes-later.reply').write_bytes(reply)
                rows.append({'label': 'first-completes-later', 'query': driver.normalized(wire), 'reply': driver.normalized(reply),
                             'metrics': metrics('first-completes-later'), 'sent_monotonic_ns': started,
                             'completed_monotonic_ns': time.monotonic_ns(), 'sent_realtime_ns': wall_started,
                             'completed_realtime_ns': time.time_ns()})
                packet('parent-pipe-barrier-a', target='health.cache.test')
                packet('parent-sees-first')
                packet('first-private-repeat', tcp=True, connection=connection)
                packet('second-private-repeat', tcp=True, connection=second)
        elif spec['mode'] == 'failed-prefix':
            target = 'target.failed-prefix.cache.test'
            (root / 'm2/caller.hosts').write_text('198.51.100.9 ' + host + '\n')
            driver.process_hup(folder)
            packet('parent-local-after-hup')
            upstream.plan[target] = {'ttl': 600, 'answers': [{'data': 'c6336407'}]}
            packet('parent-mutation', target=target)
            upstream.plan[host] = {'ttl': 600, 'answers': [
                {'kind': 5, 'data': driver.name(target).hex()},
                {'kind': 1, 'owner': target, 'data': 'c6336408'}]}
            packet('child-first-query', tcp=True, connection=connection)
            # C exports before writing the downstream reply. Parent pipe
            # servicing precedes the following ordinary DNS health answer.
            packet('parent-pipe-barrier', target='health.cache.test')
            packet('parent-local-preserved')
            upstream.plan[target] = {'ttl': 600, 'answers': [{'data': 'c633640a'}]}
            packet('parent-removed-prefix-misses', target=target)
            packet('child-private-repeat', tcp=True, connection=connection)
        elif spec['mode'] == 'eviction':
            upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336408'}]}
            packet('child-first-query', tcp=True, connection=connection)
            packet('parent-pipe-barrier', target='health.cache.test')
            packet('parent-after-child')
            packet('child-private-repeat', tcp=True, connection=connection)
        else:
            if spec['mode'] == 'replace':
                upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336408'}]}
                driver.process_hup(folder)
            packet('parent-mutation')
            packet('child-first-query', tcp=True, connection=connection)
            packet('parent-after-child')
    wait_clients(0, 'drained-first-connection')
    if spec['mode'] in ['failed-prefix', 'cross']:
        return rows
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
    prefix = case == 'm6b-parent-import-failed-prefix'
    eviction = case == 'm6b-child-eviction-parent-counters'
    cross = case == 'm6b-cross-connection-progress'
    if prefix:
        expected = ['accept-before-first-query', 'parent-local-after-hup', 'parent-mutation', 'child-first-query',
                    'parent-pipe-barrier', 'parent-local-preserved', 'parent-removed-prefix-misses', 'child-private-repeat']
    if case.endswith('replace'):
        expected.insert(0, 'seed-before-accept')
    if eviction:
        expected = ['seed-before-accept', 'accept-before-first-query', 'child-first-query',
                    'parent-pipe-barrier', 'parent-after-child', 'child-private-repeat', 'next-view']
    if cross:
        expected = ['accept-before-first-query', 'second-completes-first', 'parent-pipe-barrier-b', 'parent-sees-second',
                    'first-completes-later', 'parent-pipe-barrier-a', 'parent-sees-first', 'first-private-repeat', 'second-private-repeat']
    if [r['label'] for r in row['observations']] != expected:
        return False
    accepted = labels['accept-before-first-query']
    if accepted.get('metrics', {}).get('tcp_connections') != 1:
        return False
    if 'seed-before-accept' in labels and not labels['seed-before-accept']['completed_monotonic_ns'] < accepted['sent_monotonic_ns']:
        return False
    if eviction and not accepted['completed_monotonic_ns'] < labels['child-first-query']['sent_monotonic_ns']:
        return False
    if not eviction and not cross:
        mutated, first = [labels[name] for name in ['parent-mutation', 'child-first-query']]
        if not accepted.get('completed_monotonic_ns', 0) < mutated.get('sent_monotonic_ns', 0) <= mutated.get('completed_monotonic_ns', 0) < first.get('sent_monotonic_ns', 0):
            return False
    if cross and not accepted['completed_monotonic_ns'] < labels['first-completes-later']['sent_monotonic_ns'] < labels['second-completes-first']['sent_monotonic_ns'] < labels['second-completes-first']['completed_monotonic_ns'] < labels['first-completes-later']['completed_monotonic_ns']:
        return False
    for observation in row['observations']:
        if observation['label'] == 'accept-before-first-query':
            continue
        answers = [r for r in observation.get('reply', {}).get('records', []) if r['section'] == 'answer']
        if cross or eviction:
            if 'pipe-barrier' in observation['label']:
                wanted = '198.51.100.99'
            elif eviction:
                wanted = '198.51.100.7' if observation['label'] == 'seed-before-accept' else '198.51.100.8'
            else:
                wanted = '198.51.100.22' if observation['label'] in ['second-completes-first', 'parent-sees-second', 'second-private-repeat'] else '198.51.100.21'
            if len(answers) != 1 or answers[0]['type'] != 1 or answers[0]['data'] != wanted:
                return False
            continue
        if prefix:
            target = 'target.failed-prefix.cache.test'
            wanted = {
                'parent-local-after-hup': [(1, '198.51.100.9')],
                'parent-mutation': [(1, '198.51.100.7')],
                'child-first-query': [(5, target), (1, '198.51.100.8')],
                'parent-pipe-barrier': [(1, '198.51.100.99')],
                'parent-local-preserved': [(1, '198.51.100.9')],
                'parent-removed-prefix-misses': [(1, '198.51.100.10')],
                'child-private-repeat': [(5, target), (1, '198.51.100.8')],
            }[observation['label']]
            if [(r['type'], r['data']) for r in answers] != wanted:
                return False
            continue
        wanted = '198.51.100.7' if case.endswith('learn') or observation['label'] in ['seed-before-accept', 'child-first-query'] else '198.51.100.8'
        if len(answers) != 1 or answers[0]['data'] != wanted or answers[0]['type'] != 1:
            return False
    transports = [e['transport'] for e in row.get('upstream', [])]
    if eviction:
        before, after = [labels[name]['metrics'] for name in ['seed-before-accept', 'parent-pipe-barrier']]
        return (transports == ['udp', 'tcp']
                and [before.get(k) for k in ['dns_cache_inserted', 'dns_cache_live_freed', 'dns_queries_forwarded']] == [1, 0, 1]
                and [after.get(k) for k in ['dns_cache_inserted', 'dns_cache_live_freed', 'dns_queries_forwarded']] == [2, 1, 1])
    if cross:
        return (transports == ['tcp', 'tcp']
                and labels['parent-pipe-barrier-b']['metrics'].get('dns_cache_inserted') == 1
                and labels['parent-pipe-barrier-a']['metrics'].get('dns_cache_inserted') == 2
                and all(labels[name]['metrics'].get('dns_cache_live_freed') == 0 for name in ['parent-pipe-barrier-b', 'parent-pipe-barrier-a']))
    if prefix:
        counters = labels['parent-pipe-barrier'].get('metrics', {})
        refreshed = labels['parent-removed-prefix-misses'].get('metrics', {})
        return (transports == ['udp', 'tcp', 'udp']
                and counters.get('dns_cache_inserted') == 1 and counters.get('dns_cache_live_freed') == 0
                and refreshed.get('dns_cache_inserted') == 2 and refreshed.get('dns_cache_live_freed') == 0)
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
    if row['case'] == 'm6b-cross-connection-progress':
        samples = json.loads((work / 'accept-second.metric-samples.json').read_text())
        sample = samples[-1]
        raw = json.loads((work / (sample['receipt'] + '.metrics.stdout')).read_bytes())
        first = next(value for value in row['observations'] if value['label'] == 'first-completes-later')
        if (sample['metrics'].get('tcp_connections') != 2
                or any(raw[key] != sample['metrics'][key] for key in METRICS)
                or sample['monotonic_ns'] >= first['sent_monotonic_ns']):
            return False
    return True


def run(args):
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('full frozen source binding required')
    frozen = frozen_tools()
    hashes = {name: driver.sha256(Path(__file__).with_name(name)) for name in TOOLS}
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('candidate ELF identity differs')
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = copy.deepcopy(CASES)
    driver.schedule = schedule
    args.only = '^m6b-'
    status = driver.run(args)
    out = args.out.resolve()
    saved = out / 'drivers/m6b_tcp_accept_snapshot.py'
    for name, data in frozen.items():
        (out / 'drivers' / name).write_bytes(data)
    unchanged = frozen == frozen_tools()
    report = json.loads((out / 'result.json').read_text())
    elf = driver.STOCK_SHA256 if args.side == 'c' else args.expected_rust_sha
    errors = [row['case'] for row in report['scenarios'] if not valid_row(row, elf) or not raw_valid(out, row)]
    root = json.loads((out / 'rootfs-identity.json').read_text())
    supplement = {'scope': __doc__, 'side': args.side, 'candidate_sha256': args.expected_rust_sha,
                  'source_commit': args.source_commit, 'profile_plan': CASES, 'tools': hashes,
                  'tools_unchanged': unchanged, 'root_provenance': root_provenance(root),
                  'source_binding_scope': 'caller-declared freeze; source-to-ELF build proof remains external',
                  'driver_sha256': driver.sha256(saved), 'errors': errors,
                  'passed': status == 0 and unchanged and not errors and len(report['scenarios']) == len(CASES)}
    (out / 'supplement.json').write_text(json.dumps(supplement, indent=2) + '\n')
    return int(not supplement['passed'])


def validate_run(folder, side, wanted, source_commit):
    if not re.fullmatch('[0-9a-f]{64}', wanted) or not re.fullmatch('[0-9a-f]{40}', source_commit):
        raise ValueError('explicit frozen candidate and source required')
    report, rows = driver.comparison_rows(folder, side)
    supplement = json.loads((folder / 'supplement.json').read_text())
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    if (supplement.get('side') != side or supplement.get('candidate_sha256') != wanted
            or supplement.get('source_commit') != source_commit or supplement.get('profile_plan') != CASES
            or supplement.get('passed') is not True or supplement.get('tools_unchanged') is not True
            or report.get('rust_sha256') != wanted or root.get('rust_sha256') != wanted
            or report.get('c_sha256') != driver.STOCK_SHA256):
        raise ValueError('supplement is not this complete frozen candidate/source')
    for name in TOOLS:
        digest = driver.sha256(Path(__file__).with_name(name))
        if supplement['tools'].get(name) != digest or driver.sha256(folder / 'drivers' / name) != digest:
            raise ValueError('supplement tool/dependency identity differs')
    if supplement.get('driver_sha256') != driver.sha256(Path(__file__)):
        raise ValueError('supplement runner differs')
    expected = [case['case'] for case in CASES]
    if (list(rows) != expected or [row['case'] for row in report['scenarios']] != expected
            or report.get('syntax') or report.get('executed_cases') != expected or report.get('failures')):
        raise ValueError('complete five-case execution required')
    elf = driver.STOCK_SHA256 if side == 'c' else wanted
    for case in CASES:
        row = rows[case['case']]
        if row.get('config') != case['config'] or not valid_row(row, elf) or not raw_valid(folder, row):
            raise ValueError('supplemental caller/raw/config differs')
    provenance = root_provenance(root)
    if supplement.get('root_provenance') != provenance:
        raise ValueError('supplement root provenance changed')
    return report, rows, provenance


def compare(args):
    if args.out.exists():
        raise ValueError('fresh comparison output required')
    reports, provenance = {}, {}
    for side, folder in [('c', args.c), ('rust', args.rust)]:
        report, rows, provenance[side] = validate_run(folder, side, args.expected_rust_sha, args.source_commit)
        reports[side] = dict(report, rows=rows)
    if provenance['c'] != provenance['rust']:
        raise ValueError('C/R image provenance differs')
    expected_elf = args.expected_rust_sha
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
            first_label = 'first-completes-later' if label == 'm6b-cross-connection-progress' else 'child-first-query'
            if mode == 'missing-accept':
                bad['observations'].remove(by_label['accept-before-first-query'])
            elif mode == 'unaccepted':
                by_label['accept-before-first-query']['metrics']['tcp_connections'] = 0
            elif mode == 'early-first-query':
                by_label[first_label]['sent_monotonic_ns'] = by_label['accept-before-first-query']['completed_monotonic_ns'] - 1
            elif mode == 'wrong-answer':
                by_label[first_label]['reply']['records'][0]['data'] = '203.0.113.99'
            elif mode == 'missing-upstream':
                bad['upstream'].pop()
            else:
                bad['identity']['sha256'] = '0' * 64
            controls.append({'case': label, 'control': mode, 'rejected': not check(c, bad)})
    result = {'scope': __doc__, 'passed_cases': passed, 'negative_controls': controls,
              'passed': len(passed) == len(CASES) and all(c['rejected'] for c in controls),
              'candidate_sha256': expected_elf, 'source_commit': args.source_commit,
              'root_provenance': provenance['c'], 'c_sha256': driver.STOCK_SHA256}
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(result, indent=2))
    return int(not result['passed'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    invoke = sub.add_parser('run')
    invoke.add_argument('--image-root', type=Path, required=True)
    invoke.add_argument('--rust', type=Path, required=True)
    invoke.add_argument('--expected-rust-sha', required=True)
    invoke.add_argument('--source-commit', required=True)
    invoke.add_argument('--side', choices=['c', 'rust'], required=True)
    invoke.add_argument('--out', type=Path, required=True)
    pair = sub.add_parser('compare')
    for name in ['c', 'rust', 'out']:
        pair.add_argument('--' + name, type=Path, required=True)
    pair.add_argument('--expected-rust-sha', required=True)
    pair.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    if args.action == 'run' and not re.fullmatch('[0-9a-f]{64}', args.expected_rust_sha):
        parser.error('full frozen candidate SHA required')
    return run(args) if args.action == 'run' else compare(args)


if __name__ == '__main__':
    raise SystemExit(main())
