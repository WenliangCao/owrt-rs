#!/usr/bin/env python3
"""Exact-image EVENT_NEWROUTE caller supplement, never a performance window.

Freeze before execution: one held UDP query, one kernel-created connected
route, exactly one identical resend, original source port, one client answer,
one forward action and stable idle FD restoration; repeat with no-poll.
Absence of a resend is recorded, then the original held packet is answered
to permit clean drain. That cleanup answer cannot satisfy the resend gate.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

import m5_dns_cache as driver


CASES = [
    {'case': 'm6b-route-resend-poll', 'capacity': 0, 'metrics': True, 'config': ''},
    {'case': 'm6b-route-resend-no-poll', 'capacity': 0, 'metrics': True, 'config': 'no-poll'},
]
PLAN = {'profiles': CASES, 'scope': __doc__, 'kernel_route': '198.18.252.1/24 on private dummy m6broute',
        'upstream_hold_seconds': 0.2, 'resend_wait_seconds': 2, 'extra_reply_wait_seconds': 0.2,
        'idle_stable_observations': 3, 'idle_interval_seconds': 0.02, 'idle_deadline_seconds': 2,
        'dns_clients': 1, 'client_retries': 0, 'expected_upstream_packets': 2,
        'expected_forward_actions': 1, 'performance_qualification': False}
TOOLS = ['m6b_route_resend.py', 'm5_dns_cache.py', 'm5_dns_cache.json',
         'm2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh']


class TrackedUpstream(driver.Upstream):
    def __init__(self):
        self.received = []
        super().__init__()

    def answer(self, packet, transport, force=False):
        if not force:
            # Called by the inherited selector immediately after the actual
            # recv. Forced cleanup reply construction is not a received query.
            self.received.append({'sequence': len(self.received), 'transport': transport,
                                  'received_monotonic_ns': time.monotonic_ns(), 'wire': packet.hex()})
        return super().answer(packet, transport, force)


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def route_records(wire, peer):
    records, offset = [], 0
    while offset + 16 <= len(wire):
        length, kind, flags, seq, pid = struct.unpack_from('=IHHII', wire, offset)
        if length < 16 or offset + length > len(wire):
            raise ValueError('clipped netlink record')
        message = wire[offset:offset + length]
        qualifies = (peer[0] == 0 and pid == 0 and kind == 24 and length >= 28
                     and message[23] == 1 and message[22] == 253 and message[20] in [254, 255])
        attributes, at = [], 28
        if kind in [24, 25] and length >= 28:
            while at + 4 <= length:
                size, attr = struct.unpack_from('=HH', message, at)
                if size < 4 or at + size > length:
                    raise ValueError('clipped route attribute')
                attributes.append({'kind': attr, 'data': message[at + 4:at + size].hex()})
                at += (size + 3) & ~3
            if at != length:
                raise ValueError('unparsed route attribute tail')
        records.append({'length': length, 'kind': kind, 'flags': flags, 'sequence': seq,
                        'pid': pid, 'route': list(message[16:28]) if length >= 28 else [],
                        'attributes': attributes, 'qualifies': qualifies})
        offset += (length + 3) & ~3
    if offset != len(wire):
        raise ValueError('unparsed netlink tail')
    return records


def controlled_route(record):
    return (record['qualifies'] and record['route'][:2] == [2, 24]
            and any(attr == {'kind': 1, 'data': 'c612fc00'} for attr in record['attributes']))


def netlink_drain(endpoint, folder, label):
    rows, deadline = [], time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            wire, peer = endpoint.recvfrom(65535)
        except socket.timeout:
            break
        filename = f'{label}-{len(rows):03}.netlink'
        (folder / filename).write_bytes(wire)
        rows.append({'file': filename, 'peer': list(peer), 'observed_monotonic_ns': time.monotonic_ns(),
                     'records': route_records(wire, peer)})
        save_json(folder / (label + '.netlink.json'), rows)
    save_json(folder / (label + '.netlink.json'), rows)
    return rows


def metric(root, folder, label):
    argv = driver.command(root, '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}')
    result = subprocess.run(argv, capture_output=True, timeout=2)
    (folder / (label + '.metrics.stdout')).write_bytes(result.stdout)
    (folder / (label + '.metrics.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise AssertionError('exact-image UBus metric call failed')
    value = json.loads(result.stdout)
    return {'dns_queries_forwarded': value['dns_queries_forwarded'], 'tcp_connections': value['tcp_connections']}


def fd_set(pid):
    return {p.name: os.readlink(p) for p in (Path('/proc') / str(pid) / 'fd').iterdir()}


def stable_fds(pid, folder, label, expected=None):
    observations, deadline, stable, previous = [], time.monotonic() + 2, 0, None
    while True:
        try:
            current = fd_set(pid)
        except FileNotFoundError:
            current = None  # A transient interface-file FD may disappear.
        observations.append({'monotonic_ns': time.monotonic_ns(), 'fds': current})
        save_json(folder / (label + '.fds.json'), observations)
        matched = current is not None and current == (previous if expected is None else expected)
        stable = stable + 1 if matched else 1 if current is not None and expected is None else 0
        if stable == 3:
            return current
        if time.monotonic() >= deadline:
            raise AssertionError('idle FD identities did not stabilize/return')
        previous = current
        time.sleep(.02)


def held_packets(upstream, folder):
    rows = []
    for index, (transport, _, peer, packet) in enumerate(list(upstream.held)):
        filename = f'upstream-{index:03}.query'
        (folder / filename).write_bytes(packet)
        received = upstream.received[index]
        if received['wire'] != packet.hex() or received['transport'] != transport:
            raise AssertionError('received query/held inventory differs')
        rows.append({'file': filename, 'transport': transport, 'source': list(peer),
                     'received_monotonic_ns': received['received_monotonic_ns'],
                     'query': driver.normalized(packet)})
    save_json(folder / 'held-upstream.json', rows)
    return rows


def correct_answer(query, reply):
    parsed = driver.normalized(reply)
    if reply[:2] != query[:2] or parsed.get('questions') != driver.normalized(query)['questions']:
        return False
    if parsed.get('flags') != 0x8180:
        return False
    records = parsed.get('records', [])
    return records == [
        {'section': 'answer', 'name': 'route.resend.test', 'type': 1, 'class': 1,
         'ttl': 600, 'data': '198.51.100.7'},
        {'section': 'additional', 'name': '', 'type': 41, 'class': 1232, 'ttl': 0, 'data': ''},
    ]


def schedule(spec, port, upstream, folder, root):
    pid = int((folder / 'pid').read_text())
    witness = {'case': spec['case'], 'plan': PLAN, 'resend_observed': False, 'cleanup_answer': False}
    link_created = False
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as route, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        route.bind((0, 0x40 | 0x400)); route.settimeout(.2)
        client.bind((driver.CLIENT, 0)); client.settimeout(2)
        client.connect((driver.LISTEN, port))
        witness['dns_destination'] = list(client.getpeername())
        try:
            subprocess.run(['ip', 'link', 'add', 'm6broute', 'type', 'dummy'], check=True)
            link_created = True
            ipv6 = Path('/proc/sys/net/ipv6/conf/m6broute/disable_ipv6')
            if ipv6.exists():
                ipv6.write_text('1\n')
                if ipv6.read_text().strip() != '1':
                    raise AssertionError('new dummy IPv6 could not be disabled')
                witness['dummy_ipv6'] = 'disabled'
            else:
                witness['dummy_ipv6'] = 'not-present'
            subprocess.run(['ip', 'link', 'set', 'm6broute', 'up'], check=True)
            witness['bootstrap_netlink'] = netlink_drain(route, folder, 'bootstrap')
            # A real health reply after link setup is a daemon turn barrier,
            # before saved UDP state exists. No health traffic follows hold.
            health = driver.query('health.cache.test', 0x6e00)
            reply = driver.exchange(port, health)
            if reply is None or driver.normalized(reply)['records'][0]['data'] != '198.51.100.99':
                raise AssertionError('daemon setup barrier failed')
            witness['idle_fds'] = stable_fds(pid, folder, 'before')
            witness['before_metrics'] = metric(root, folder, 'before')
            host = 'route.resend.test'
            upstream.plan[host] = {'hold': True, 'ttl': 600, 'answers': [{'data': 'c6336407'}]}
            query = driver.query(host, 0x6e01)
            (folder / 'client.query').write_bytes(query)
            client.send(query)
            deadline = time.monotonic() + 2
            while not upstream.held:
                if time.monotonic() >= deadline:
                    raise AssertionError('first query did not reach controlled upstream')
                time.sleep(.005)
            time.sleep(.2)
            first = held_packets(upstream, folder)
            if len(first) != 1:
                raise AssertionError('query retried before route; invalid caller fixture')
            witness['before_trigger'] = first
            witness['trigger_monotonic_ns'] = time.monotonic_ns()
            save_json(folder / 'caller-witness.json', witness)
            subprocess.run(['ip', 'addr', 'add', '198.18.252.1/24', 'dev', 'm6broute'], check=True)
            witness['trigger_netlink'] = netlink_drain(route, folder, 'trigger')
            if not any(controlled_route(record) for row in witness['trigger_netlink'] for record in row['records']):
                raise AssertionError('no qualifying kernel connected-route witness')
            deadline = time.monotonic() + 2
            while len(upstream.held) < 2 and time.monotonic() < deadline:
                time.sleep(.005)
            witness['held_packets'] = held_packets(upstream, folder)
            witness['resend_observed'] = len(witness['held_packets']) == 2
            save_json(folder / 'caller-witness.json', witness)
            if not upstream.held:
                raise AssertionError('controlled held query vanished')
            # Missing resend is a retained defect, not a method failure. Reply
            # to its original packet only to release the pending transaction.
            witness['cleanup_answer'] = not witness['resend_observed']
            transport, endpoint, peer, packet = upstream.held[-1]
            if transport != 'udp':
                raise AssertionError('unexpected non-UDP caller')
            answer = upstream.answer(packet, transport, force=True)
            (folder / 'upstream.reply').write_bytes(answer)
            endpoint.sendto(answer, peer)
            upstream.held.clear()
            reply, source = client.recvfrom(65535)
            (folder / 'client.reply').write_bytes(reply)
            witness['reply_monotonic_ns'] = time.monotonic_ns()
            witness['reply_source'] = list(source)
            witness['correct_answer'] = correct_answer(query, reply)
            if not witness['correct_answer']:
                raise AssertionError('client answer is incorrect')
            client.settimeout(.2)
            try:
                extra, _ = client.recvfrom(65535)
                (folder / 'client.extra-reply').write_bytes(extra)
                raise AssertionError('more than one client reply')
            except socket.timeout:
                witness['one_client_reply'] = True
            witness['after_metrics'] = metric(root, folder, 'after')
            witness['final_fds'] = stable_fds(pid, folder, 'after', witness['idle_fds'])
            witness['completed'] = True
            save_json(folder / 'caller-witness.json', witness)
            return [{'label': 'caller', 'query': driver.normalized(query), 'reply': driver.normalized(reply),
                     'resend_observed': witness['resend_observed'], 'cleanup_answer': witness['cleanup_answer']}]
        finally:
            save_json(folder / 'upstream-receipts.json', upstream.received)
            save_json(folder / 'caller-witness.json', witness)
            if link_created:
                subprocess.run(['ip', 'link', 'del', 'm6broute'], check=True)


def validate_case(folder, row, expected_sha):
    """Recompute claims from raw wire/counters/fd identity, not report flags."""
    if row.get('failure') or row.get('exit') != 0 or row.get('upstream_errors'):
        raise ValueError('caller execution incomplete')
    if row.get('identity', {}).get('sha256') != expected_sha:
        raise ValueError('actual running ELF differs')
    witness = json.loads((folder / 'caller-witness.json').read_text())
    if witness.get('plan') != PLAN or witness.get('case') != row['case'] or not witness.get('completed'):
        raise ValueError('unfrozen or incomplete caller')
    queries = witness['held_packets']
    if not queries or len(queries) > 2 or len(witness['before_trigger']) != 1:
        raise ValueError('invalid hold schedule')
    packets = [(folder / query['file']).read_bytes() for query in queries]
    if any(query['transport'] != 'udp' or driver.normalized(packet) != query['query']
           for query, packet in zip(queries, packets)):
        raise ValueError('saved upstream wire differs')
    events = row.get('upstream', [])
    if (len(events) != len(packets)
            or any(event.get('host') != 'route.resend.test' or event.get('transport') != 'udp'
                   or event.get('wire') != packet.hex() or event.get('query') != driver.normalized(packet)
                   for event, packet in zip(events, packets))):
        raise ValueError('complete actual upstream inventory differs')
    received = json.loads((folder / 'upstream-receipts.json').read_text())
    if (len(received) != len(packets)
            or any(item['sequence'] != index or item['transport'] != 'udp' or item['wire'] != packet.hex()
                   or item['received_monotonic_ns'] != queries[index]['received_monotonic_ns']
                   for index, (item, packet) in enumerate(zip(received, packets)))):
        raise ValueError('actual receive receipts differ')
    if witness['before_trigger'][0] != queries[0] or received[0]['received_monotonic_ns'] >= witness['trigger_monotonic_ns']:
        raise ValueError('first held packet did not precede route')
    if len(received) == 2 and received[1]['received_monotonic_ns'] < witness['trigger_monotonic_ns']:
        raise ValueError('second packet preceded route')
    if witness.get('dummy_ipv6') not in ['disabled', 'not-present']:
        raise ValueError('new dummy DAD contamination not excluded')
    raw_routes = []
    for record in witness['trigger_netlink']:
        parsed = route_records((folder / record['file']).read_bytes(), record['peer'])
        if parsed != record['records']:
            raise ValueError('netlink raw/report differs')
        raw_routes += parsed
    if not any(controlled_route(record) for record in raw_routes):
        raise ValueError('no actual qualifying kernel route')
    query, reply = (folder / 'client.query').read_bytes(), (folder / 'client.reply').read_bytes()
    if (driver.normalized(query)['questions'] != [['route.resend.test', 1, 1]]
            or any(driver.normalized(packet)['questions'] != driver.normalized(query)['questions'] for packet in packets)):
        raise ValueError('controlled held question differs')
    if not correct_answer(query, reply) or not witness.get('one_client_reply') or (folder / 'client.extra-reply').exists():
        raise ValueError('client completion differs')
    if witness.get('reply_source') != witness.get('dns_destination') or not witness.get('reply_source'):
        raise ValueError('client answer came from a different endpoint')
    if not witness['trigger_monotonic_ns'] <= witness['reply_monotonic_ns']:
        raise ValueError('response preceded route')
    before, after = [json.loads((folder / f'{label}.metrics.stdout').read_bytes()) for label in ['before', 'after']]
    if any(value['tcp_connections'] != 0 for value in [before, after]):
        raise ValueError('unexpected TCP clients')
    if after['dns_queries_forwarded'] - before['dns_queries_forwarded'] != 1:
        raise ValueError('resend created an extra forward action')
    for label in ['before', 'after']:
        samples = json.loads((folder / (label + '.fds.json')).read_text())
        tail = samples[-3:]
        if len(tail) != 3 or any(item['fds'] != witness['idle_fds'] for item in tail):
            raise ValueError('stable original FD identities absent')
        if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
            raise ValueError('FD observations were not separated')
    observed = (len(packets) == 2 and packets[0] == packets[1]
                and queries[0]['source'] == queries[1]['source'])
    if witness['resend_observed'] != (len(packets) == 2) or witness['cleanup_answer'] != (len(packets) != 2):
        raise ValueError('cleanup masquerades as resend')
    return {'resend_contract_passed': observed, 'upstream_packets': len(packets),
            'same_wire': len(packets) == 2 and packets[0] == packets[1],
            'same_source_port': len(packets) == 2 and queries[0]['source'] == queries[1]['source'],
            'correct_client_answer': True, 'client_query': driver.normalized(query),
            'client_reply': driver.normalized(reply), 'forward_actions': 1, 'stable_idle_fds': True}


def validate_run(folder, side, expected_rust_sha):
    report = json.loads((folder / 'result.json').read_text())
    receipt = json.loads((folder / 'route-receipt.json').read_text())
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    if (report['side'] != side or report['c_sha256'] != driver.STOCK_SHA256 or receipt['plan'] != PLAN
            or report.get('rust_sha256') != expected_rust_sha or root.get('rust_sha256') != expected_rust_sha
            or root.get('c_sha256') != driver.STOCK_SHA256 or not receipt.get('tools_unchanged')):
        raise ValueError('reference/side/plan identity differs')
    for name in TOOLS:
        wanted = driver.sha256(Path(__file__).with_name(name))
        if receipt['tools'].get(name) != wanted or driver.sha256(folder / 'drivers' / name) != wanted:
            raise ValueError('frozen caller/dependency identity differs')
    expected = driver.STOCK_SHA256 if side == 'c' else report['rust_sha256']
    results = {}
    for row in report['scenarios']:
        if row['case'] in results or row['identity']['root'] != root['root']:
            raise ValueError('duplicate or wrong rootfs caller')
        results[row['case']] = validate_case(folder / row['case'], row, expected)
    if set(results) != {case['case'] for case in CASES} or report['failures']:
        raise ValueError('incomplete frozen caller set')
    return results


def run(args):
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('candidate SHA differs')
    frozen = {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}
    tools = {name: hashlib.sha256(data).hexdigest() for name, data in frozen.items()}
    driver.SYNTAX.clear(); driver.SCENARIOS[:] = copy.deepcopy(CASES); driver.schedule = schedule
    driver.Upstream = TrackedUpstream
    args.only = '^m6b-route-resend-'
    status = driver.run(args)
    out = args.out.resolve()
    for name in TOOLS:
        (out / 'drivers' / name).write_bytes(frozen[name])
    unchanged = all(driver.sha256(Path(__file__).with_name(name)) == tools[name] for name in TOOLS)
    save_json(out / 'route-receipt.json', {'plan': PLAN, 'tools': tools, 'run_status': status,
                                         'tools_unchanged': unchanged, 'scope': __doc__, 'performance_qualification': False})
    if not unchanged:
        raise ValueError('frozen tools changed during execution')
    if status:
        return status
    results = validate_run(out, args.side, args.expected_rust_sha)
    save_json(out / 'route-validation.json', results)
    passed = all(row['resend_contract_passed'] for row in results.values())
    print(json.dumps({'side': args.side, 'caller_contract_passed': passed, 'results': results}, indent=2))
    return int(not passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    plan = sub.add_parser('plan'); plan.add_argument('--out', type=Path, required=True)
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--side', choices=['c', 'rust'], required=True)
    execute.add_argument('--expected-rust-sha', required=True)
    compare = sub.add_parser('compare')
    for name in ['c', 'rust', 'out']:
        compare.add_argument('--' + name, type=Path, required=True)
    compare.add_argument('--expected-rust-sha', required=True)
    args = parser.parse_args()
    if args.action == 'plan':
        with args.out.open('x') as stream:
            json.dump(PLAN, stream, indent=2); stream.write('\n')
        return 0
    if args.action == 'run':
        return run(args)
    left, right = validate_run(args.c, 'c', args.expected_rust_sha), validate_run(args.rust, 'rust', args.expected_rust_sha)
    roots = [json.loads((folder / 'rootfs-identity.json').read_text()) for folder in [args.c, args.rust]]
    for key in ['image_sha256', 'image_provenance_sha256']:
        if roots[0].get(key) != roots[1].get(key):
            raise ValueError('C/R image provenance differs')
    if roots[0]['filesystem']['base_manifest_sha256'] != roots[1]['filesystem']['base_manifest_sha256']:
        raise ValueError('C/R immutable image base differs')
    c_valid = all(row['resend_contract_passed'] for row in left.values())
    different = [case for case in left if left[case] != right[case]]
    result = {'c_reference_contract_passed': c_valid, 'differences': different,
              'c': left, 'rust': right, 'caller_contract_passed': c_valid and not different,
              'performance_qualification': False}
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(result, indent=2))
    return int(not result['caller_contract_passed'])


if __name__ == '__main__':
    raise SystemExit(main())
