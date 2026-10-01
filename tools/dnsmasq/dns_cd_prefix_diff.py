#!/usr/bin/env python3
"""C-first ordinary CD insertion-prefix effects with real pending UDP replies.

No bogus-address policy, signatures or cache bypass options are involved.
Each case warms an owner through an independent CNAME while its first reply
is held, then observes target replacement, uncommitted visibility, empty-reply
cleanup and recovery. Optional pressure uses a three-record cache.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

from dns_service_probe import name, query, read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]


def cases():
    for kind, address in [(1, '127.0.0.1'), (28, '::1')]:
        for request_cd, reply_cd in [(False, False), (True, False), (False, True), (True, True)]:
            yield {'label': f'k{kind}-request{int(request_cd)}-reply{int(reply_cd)}',
                   'kind': kind, 'address': address, 'request_cd': request_cd, 'reply_cd': reply_cd,
                   'capacity': 8, 'pressure': False}
        yield {'label': f'k{kind}-pressure-request1-reply0', 'kind': kind, 'address': address,
               'request_cd': True, 'reply_cd': False, 'capacity': 3, 'pressure': True}


def request(host, kind, ident, cd=False):
    packet = bytearray(query(host, kind, ident))
    struct.pack_into('!H', packet, 2, 0x100 | (0x10 if cd else 0))
    return bytes(packet)


def answer(packet, kind, values=(), target=None, cd=False):
    host, end = read_name(packet, 12)
    records = []
    if target:
        records.append(rr(5, name(target), 120, name(host)))
    for value in values:
        address = f'192.0.2.{value}' if kind == 1 else f'2001:db8::{value:x}'
        records.append(rr(kind, ipaddress.ip_address(address).packed, 120, name(target or host)))
    return (packet[:2] + struct.pack('!5H', 0x8180 | (0x10 if cd else 0), 1, len(records), 0, 0)
            + packet[12:end + 4] + b''.join(records))


def run(args, binary, case, side, out):
    out.mkdir()
    fixture = Fixture(args, out)
    fixture.upstream.close()  # This gate synchronously controls every upstream reply.
    family = socket.AF_INET6 if ':' in case['address'] else socket.AF_INET
    upstream = socket.socket(family, socket.SOCK_DGRAM)
    upstream.bind((case['address'], 0))
    upstream.settimeout(2)
    clients = [socket.socket(family, socket.SOCK_DGRAM) for _ in range(3)]
    for client in clients:
        client.settimeout(2)
    rows, wires, events = [], [], []
    ident = 0x5100
    kind = case['kind']
    destination = (case['address'], 15353)

    def event(stage, **details):
        events.append({'stage': stage, 'ns': time.monotonic_ns(), **details})

    def send(client, host, cd=False, query_kind=None):
        nonlocal ident
        ident += 1
        packet = request(host, query_kind or kind, ident, cd)
        client.sendto(packet, destination)
        return packet

    def upstream_read(stage):
        packet, peer = upstream.recvfrom(65535)
        decoded = semantics(packet)
        decoded['id'] = 0
        event(stage, upstream_query=packet.hex())
        return packet, peer, decoded

    def finish(stage, client, packet, observed=()):
        response = client.recv(65535)
        assert response[:2] == packet[:2], ('response-id', stage)
        wires.append({'stage': stage, 'query': packet.hex(), 'reply': response.hex()})
        row = {'stage': stage, 'response': semantics(response), 'upstream': list(observed), 'metrics': fixture.metrics()}
        rows.append(row)
        return row

    def lookup(stage, host, values=(44,), target=None, cd=False, raw_cd=False, hold=False, query_kind=None):
        packet = send(clients[1], host, cd, query_kind)
        event(stage, client_query=packet.hex())
        ready, _, _ = select.select([clients[1], upstream], [], [], 2)
        assert ready, ('DNS-deadline', stage)
        if upstream in ready:
            sent, peer, decoded = upstream_read(stage)
            assert semantics(sent)['questions'][0][0] == host, ('unexpected-upstream-owner', stage)
            if hold:
                rows.append({'stage': stage, 'response': None, 'upstream': [decoded], 'metrics': fixture.metrics()})
                return packet, sent, peer, decoded
            response = answer(sent, kind, values, target, raw_cd)
            event(stage, upstream_reply=response.hex())
            upstream.sendto(response, peer)
            return finish(stage, clients[1], packet, [decoded])
        return finish(stage, clients[1], packet)

    try:
        fixture.start_bus()
        config = out / 'dnsmasq.conf'
        config.write_text('no-hosts\nno-resolv\nno-0x20-encode\nno-round-robin\n'
                          'listen-address=127.0.0.1,::1\nport=15353\n'
                          f'cache-size={case["capacity"]}\nserver={case["address"]}#{upstream.getsockname()[1]}\n'
                          f'enable-ubus={OBJECT}\n')
        command = [str(binary.resolve()), '-k', '-C', str(config)]
        if side == 'C':
            command += ['--user=root', '--group=root', '--log-facility=-', '--pid-file=' + str(out / 'pid')]
        fixture.daemon, _ = fixture.spawn(command, 'daemon')
        fixture.wait_registered()
        rows.append({'stage': 'initial', 'metrics': fixture.metrics()})
        held_client = send(clients[0], 'owner.test', case['request_cd'])
        event('held-query', client_query=held_client.hex())
        held, held_peer, held_decoded = upstream_read('held-query')
        lookup('warm-through-alias', 'alias.test', (11,), 'owner.test')
        if case['pressure']:
            lookup('fill-capacity', 'filler.test', (55,))
        for stage, host in [('old-owner-hit', 'owner.test'), ('old-alias-hit', 'alias.test')]:
            row = lookup(stage, host)
            assert not row['upstream'], ('warm-cache-control', stage)
        replacement = answer(held, kind, (21, 22) if case['pressure'] else (21,), cd=case['reply_cd'])
        event('held-completion', upstream_reply=replacement.hex())
        upstream.sendto(replacement, held_peer)
        finish('held-completion', clients[0], held_client, [held_decoded])
        lookup('alias-cname-before-next-start', 'alias.test', (31,), 'owner.test', query_kind=5)
        pending = lookup('direct-owner-probe', 'owner.test', hold=True)
        if case['pressure']:
            # Record whether LRU pressure survives the non-committing reply.
            # A miss remains unanswered until after the empty-reply reset.
            filler_request = send(clients[2], 'filler.test')
            ready, _, _ = select.select([clients[2], upstream], [], [], 2)
            assert ready, 'filler-probe-deadline'
            if upstream in ready:
                filler, filler_peer, decoded = upstream_read('filler-after-prefix')
                rows.append({'stage': 'filler-after-prefix', 'response': None, 'upstream': [decoded], 'metrics': fixture.metrics()})
                filler_pending = (filler_request, filler, filler_peer, decoded)
            else:
                finish('filler-after-prefix', clients[2], filler_request)
                filler_pending = None
        else:
            filler_pending = None
        # Empty NOERROR, no SOA and no neg-ttl: cache_start still cleans the
        # previous pending chain despite staging and committing no new record.
        # Use client 0 because client 1 may have a held direct-owner response.
        empty_request = send(clients[0], 'empty.test', True)
        empty, empty_peer, decoded = upstream_read('empty-cd-reset')
        empty_reply = answer(empty, kind)
        event('empty-cd-reset', upstream_reply=empty_reply.hex())
        upstream.sendto(empty_reply, empty_peer)
        finish('empty-cd-reset', clients[0], empty_request, [decoded])
        # Temporarily use the now-idle client 0 while direct-owner is pending.
        clients[0], clients[1] = clients[1], clients[0]
        lookup('alias-cname-after-empty-reset', 'alias.test', (), raw_cd=True, query_kind=5)
        lookup('alias-after-empty-reset', 'alias.test', (33,), 'owner.test')
        clients[0], clients[1] = clients[1], clients[0]
        if isinstance(pending, tuple):
            packet, sent, peer, decoded = pending
            response = answer(sent, kind, (44,))
            event('direct-owner-recovery', upstream_reply=response.hex())
            upstream.sendto(response, peer)
            finish('direct-owner-recovery', clients[1], packet, [decoded])
        # The no-CD control is already committed. Avoid a second unrelated
        # target replacement, whose CNAME cleanup depends on C hash collisions.
        if filler_pending:
            packet, sent, peer, decoded = filler_pending
            response = answer(sent, kind, (55,))
            event('filler-recovery', upstream_reply=response.hex())
            upstream.sendto(response, peer)
            finish('filler-recovery', clients[2], packet, [decoded])
        lookup('final-owner', 'owner.test', (44,))
        lookup('final-alias', 'alias.test', (44,), 'owner.test')
        assert not select.select([upstream, *clients], [], [], .01)[0], 'unexpected-extra-datagram'
        return rows
    finally:
        for client in clients:
            client.close()
        upstream.close()
        fixture.stop(fixture.daemon)
        fixture.stop(fixture.bus)
        (out / 'trace.json').write_text(json.dumps({'case': case, 'rows': rows, 'wires': wires, 'events': events,
                                                   'ubus': fixture.raw, 'checks': fixture.checks}, indent=2) + '\n')
        assert all(check['pass'] for check in fixture.checks), fixture.checks


def compare(expected, actual):
    if [row['stage'] for row in expected] != [row['stage'] for row in actual]:
        return [{'stages': [[row['stage'] for row in expected], [row['stage'] for row in actual]]}]
    differences = []
    for left, right in zip(expected, actual):
        c, rust = copy.deepcopy(left), copy.deepcopy(right)
        if c.get('response') and rust.get('response') and not c['upstream'] and not rust['upstream']:
            for a, b in zip(c['response']['records'], rust['response']['records']):
                if a['type'] != 41 and abs(a['ttl'] - b['ttl']) <= 1:
                    b['ttl'] = a['ttl']
        if c != rust:
            differences.append({'stage': c['stage'], 'c': c, 'rust': rust})
    return differences


def calibrate(rows, case):
    by_stage = {row['stage']: row for row in rows}
    expected = int(not case['request_cd'] and not case['reply_cd'])
    before = by_stage['old-alias-hit']['metrics']['dns_cache_inserted']
    after = by_stage['held-completion']['metrics']['dns_cache_inserted']
    assert after - before == expected * (2 if case['pressure'] else 1), ('CD-commit-control', case, before, after)
    assert not by_stage['old-owner-hit']['upstream'] and not by_stage['old-alias-hit']['upstream']
    assert not by_stage['alias-cname-before-next-start']['upstream']
    assert bool(by_stage['direct-owner-probe']['upstream']) == (not expected)
    assert bool(by_stage['alias-cname-after-empty-reset']['upstream']) == (not expected)
    assert by_stage['empty-cd-reset']['metrics']['dns_cache_inserted'] == after
    if case['pressure']:
        assert by_stage['held-completion']['metrics']['dns_cache_live_freed'] == 1
        assert len(by_stage['filler-after-prefix']['upstream']) == 1
    assert not by_stage['final-owner']['upstream'] and not by_stage['final-alias']['upstream']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--c-binary', type=Path)
    parser.add_argument('--c-identity', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    c = (args.c_binary or args.reference_build / 'dnsmasq/dnsmasq').resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / 'dnsmasq/dnsmasq', None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'private') and not out.exists()
    out.mkdir(parents=True)
    (out / 'tool.py').write_bytes(Path(__file__).read_bytes())
    plan = list(cases())
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    report = {'reference': reference, 'native_client_build': native, 'tool_sha256': digest(__file__),
              'rust_sha256': digest(args.rust) if args.rust else None, 'rounds': [], 'failures': [],
              'normalization': 'DNS compression, random upstream ID; cache-hit TTL at most one second'}
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'dns-cd-prefix', '/run'], check=True)
    Path(BUS).parent.mkdir()
    try:
        for case in plan:
            work = out / case['label']
            work.mkdir()
            try:
                expected = run(args, c, case, 'C', work / 'c')
                calibrate(expected, case)
                assert not compare(expected, copy.deepcopy(expected))
                changed = copy.deepcopy(expected)
                changed[0]['metrics']['dns_cache_inserted'] += 1
                assert len(compare(expected, changed)) == 1
                changed = copy.deepcopy(expected)
                changed[-1]['upstream'].append({'negative-control': 'extra-send'})
                assert len(compare(expected, changed)) == 1
                row = {'case': case, 'c_observations': len(expected), 'matched': None, 'differences': []}
                if args.rust:
                    actual = run(args, args.rust.resolve(), case, 'Rust', work / 'rust')
                    row['differences'] = compare(expected, actual)
                    row['matched'] = (None if any('stages' in difference for difference in row['differences'])
                                      else len(expected) - len(row['differences']))
                report['rounds'].append(row)
            except Exception as error:
                report['failures'].append({'case': case['label'], 'error': repr(error)})
            (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    finally:
        subprocess.run(['umount', '/run'], check=True)
    report['mismatches'] = sum(bool(row['differences']) for row in report['rounds'])
    print(json.dumps(report))
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return int(bool(report['failures'] or report['mismatches']))


if __name__ == '__main__':
    raise SystemExit(main())
