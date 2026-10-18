#!/usr/bin/env python3
"""Targeted final-SDK recovery check; one injected runtime ENOBUFS only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time
from odhcpd_baseline import Fixture, options, run


def ia_payload(reply, code):
    assert reply.get('decoded', {}).get('type') in (2, 7), reply
    return next(body for option, body in options(bytes.fromhex(reply['hex'])[4:])
                if option == code)


def mtu(reply):
    assert not reply.get('timeout'), reply
    value = next(option for option in reply['decoded']['options'] if option['type'] == 5)
    return struct.unpack('!I', bytes.fromhex(value['hex'])[4:8])[0]


def leases(fixture):
    result = fixture.bus('dhcp', 'ipv6leases')
    assert result['status'] == 0, result
    entries = json.loads(result['stdout'])['device']['br-lan']['leases']
    return sorted([{
        'duid': entry['duid'], 'iaid': entry['iaid'], 'assigned': entry['assigned'],
        'flags': entry['flags'],
        'addresses': sorted(address['address'] for address in
                            entry.get('ipv6-addr', entry.get('ipv6-prefix', []))),
    } for entry in entries], key=lambda entry: entry['iaid'])


def pd_routes():
    entries = json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all').stdout)
    return sorted((entry['dst'], entry.get('gateway'), entry.get('dev'), entry.get('metric'))
                  for entry in entries if entry.get('gateway') == 'fe80::2')


parser = argparse.ArgumentParser()
parser.add_argument('--rootfs', required=True)
parser.add_argument('--out', required=True)
parser.add_argument('--daemon', required=True)
parser.add_argument('--candidate-sha', required=True)
args = parser.parse_args()
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
assert hashlib.sha256(Path(args.daemon).read_bytes()).hexdigest() == args.candidate_sha
Path(args.out).mkdir()
fixture = Fixture(args)
try:
    fixture.setup()
    fixture.start_daemon()
    time.sleep(.3)
    na_offer = fixture.dhcp('na_offer', 1, [(3, struct.pack('!III', 1, 0, 0))])
    server = ia_payload(na_offer, 2)
    na = ia_payload(na_offer, 3)
    na_bound = fixture.dhcp('na_bound', 3, [(3, na)], server=server)
    assert any(code == 5 for code, _ in options(ia_payload(na_bound, 3)[12:]))
    pd_offer = fixture.dhcp('pd_offer', 1, [(25, struct.pack('!III', 2, 0, 0))])
    pd = ia_payload(pd_offer, 25)
    pd_bound = fixture.dhcp('pd_bound', 3, [(25, pd)], server=server)
    assert any(code == 26 for code, _ in options(ia_payload(pd_bound, 25)[12:]))
    time.sleep(.3)
    before_ra = fixture.request('before_rs', 'rs')
    before_leases = fixture.record('before_lease_identities', leases(fixture))
    before_routes = fixture.record('before_pd_routes', pd_routes())
    assert len(before_leases) == 2 and all('bound' in item['flags'] for item in before_leases)
    assert before_routes and mtu(before_ra) == 1500
    assert before_ra['decoded']['router_lifetime'] > 0
    daemon_pid = fixture.daemon.pid
    tracer = fixture.spawn('strace', [
        'strace', '-tt', '-e', 'trace=recvfrom,sendto',
        '-e', 'inject=recvfrom:error=ENOBUFS:when=3', '-p', str(daemon_pid)])
    trace_path = Path(args.out) / 'strace.log'
    for _ in range(100):
        if 'attached' in trace_path.read_text():
            break
        time.sleep(.01)
    else:
        raise RuntimeError('strace did not attach')
    run('ip', 'link', 'set', 'br-lan', 'mtu', '1499')
    for _ in range(100):
        if '(INJECTED)' in trace_path.read_text():
            break
        time.sleep(.01)
    else:
        raise RuntimeError('ENOBUFS was not injected')
    trace = trace_path.read_text()
    assert 'RTM_GETLINK' in trace and 'recvfrom(3,' in trace
    assert 'ENOBUFS' in trace and trace.count('(INJECTED)') == 1
    assert fixture.daemon.poll() is None
    # This event is deliberately consumed while retry is pending. Successful
    # resync must still advertise the new default-route state without a third event.
    run('ip', '-6', 'route', 'del', 'default', 'dev', 'wan0')
    during_ra = fixture.request('during_retry_rs', 'rs')
    during_info = fixture.dhcp('during_retry_information', 11, duid=None)
    assert during_info.get('decoded', {}).get('type') == 7
    during_leases = fixture.record('during_lease_identities', leases(fixture))
    during_routes = fixture.record('during_pd_routes', pd_routes())
    assert before_leases == during_leases and before_routes == during_routes
    assert mtu(during_ra) == 1500 and during_ra['decoded']['router_lifetime'] > 0
    deadline = time.monotonic() + 5
    observations = []
    while time.monotonic() < deadline:
        assert fixture.daemon.poll() is None
        current = fixture.request(f'recovery_rs_{len(observations)}', 'rs')
        observations.append({'mtu': mtu(current),
                             'router_lifetime': current['decoded']['router_lifetime']})
        if observations[-1] == {'mtu': 1499, 'router_lifetime': 0}:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('real MTU/default-route change never reached RA')
    na_renew = fixture.dhcp('na_renew_after_recovery', 5, [(3, na)], server=server)
    pd_renew = fixture.dhcp('pd_renew_after_recovery', 5, [(25, pd)], server=server)
    assert any(code == 5 for code, _ in options(ia_payload(na_renew, 3)[12:]))
    assert any(code == 26 for code, _ in options(ia_payload(pd_renew, 25)[12:]))
    after_leases = fixture.record('after_lease_identities', leases(fixture))
    after_routes = fixture.record('after_pd_routes', pd_routes())
    assert before_leases == after_leases and before_routes == after_routes
    trace = trace_path.read_text()
    assert trace.count('(INJECTED)') == 1
    assert fixture.daemon.poll() is None and fixture.daemon.pid == daemon_pid
    result = {'pid_preserved': daemon_pid, 'one_enobufs_injected': True,
              'original_bound_na_pd_retained': True, 'original_pd_routes_retained': True,
              'rs_and_dhcp_served_during_retry': True, 'na_pd_renew_succeeded': True,
              'before_mtu': 1500, 'during_mtu': mtu(during_ra), 'after_mtu': 1499,
              'before_router_lifetime': before_ra['decoded']['router_lifetime'],
              'during_router_lifetime': during_ra['decoded']['router_lifetime'],
              'after_router_lifetime': 0, 'observations': observations,
              'newroute_messages_during_trace': trace.count('nlmsg_type=RTM_NEWROUTE'),
              'delroute_messages_during_trace': trace.count('nlmsg_type=RTM_DELROUTE')}
    fixture.record('snapshot_recovery_result', result)
    print(json.dumps(result), flush=True)
finally:
    for process in reversed(fixture.children):
        if process.poll() is None:
            process.terminate()
    for process in reversed(fixture.children):
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
