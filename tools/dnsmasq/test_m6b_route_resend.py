#!/usr/bin/env python3
"""Offline negative controls for raw route caller evidence, not image tests."""
import copy
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

import m6b_route_resend as gate


def netlink(pid=0, kind=24, table=254, scope=253, route_type=1):
    header = struct.pack('=IHHII', 36, kind, 0, 0, pid)
    return (header + bytes([2, 24, 0, 0, table, 2, scope, route_type]) + b'\0' * 4
            + struct.pack('=HH', 8, 1) + socket.inet_aton('198.18.252.0'))


def raw_fixture(folder, resend=True):
    query = gate.driver.query('route.resend.test', 0x6e01)
    _, end = gate.driver.read_name(query, 12)
    reply = (query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 1)
             + query[12:end + 4] + gate.driver.rr(1, socket.inet_aton('198.51.100.7'), ttl=600)
             + gate.driver.rr(41, b'', owner=b'\0', ttl=0, cls=1232))
    (folder / 'client.query').write_bytes(query); (folder / 'client.reply').write_bytes(reply)
    source = ['127.0.0.1', 50001]
    packets = []
    for index in range(2 if resend else 1):
        name = f'upstream-{index:03}.query'
        (folder / name).write_bytes(query)
        packets.append({'file': name, 'transport': 'udp', 'source': source,
                        'received_monotonic_ns': 100 + index * 100, 'query': gate.driver.normalized(query)})
    wire = netlink(); (folder / 'trigger-000.netlink').write_bytes(wire)
    idle = {'0': '/dev/null', '3': 'socket:[1000]'}
    value = {'case': gate.CASES[0]['case'], 'plan': gate.PLAN, 'completed': True,
             'before_trigger': packets[:1], 'held_packets': packets, 'resend_observed': resend,
             'cleanup_answer': not resend, 'one_client_reply': True, 'trigger_monotonic_ns': 150,
             'reply_monotonic_ns': 300, 'idle_fds': idle, 'dummy_ipv6': 'disabled',
             'dns_destination': ['192.0.2.1', 53000], 'reply_source': ['192.0.2.1', 53000],
             'trigger_netlink': [{'file': 'trigger-000.netlink', 'peer': [0, 64],
                                 'records': gate.route_records(wire, (0, 64))}]}
    gate.save_json(folder / 'caller-witness.json', value)
    gate.save_json(folder / 'upstream-receipts.json', [
        {'sequence': index, 'transport': 'udp', 'wire': query.hex(), 'received_monotonic_ns': item['received_monotonic_ns']}
        for index, item in enumerate(packets)])
    for label, forwarded in [('before', 0), ('after', 1)]:
        gate.save_json(folder / (label + '.metrics.stdout'), {'tcp_connections': 0, 'dns_queries_forwarded': forwarded})
        gate.save_json(folder / (label + '.fds.json'), [{'monotonic_ns': n * 20_000_000, 'fds': idle} for n in range(3)])
    row = {'case': value['case'], 'exit': 0, 'upstream_errors': [], 'identity': {'sha256': 'x' * 64},
           'upstream': [{'host': 'route.resend.test', 'transport': 'udp', 'wire': query.hex(),
                         'query': gate.driver.normalized(query)} for _ in packets]}
    return value, row


class RouteWitnessTests(unittest.TestCase):
    def test_frozen_basic_profiles_and_no_poll(self):
        self.assertEqual(len(gate.CASES), 2)
        self.assertEqual([case['config'] for case in gate.CASES], ['', 'no-poll'])
        self.assertTrue(all(case['capacity'] == 0 and case['metrics'] for case in gate.CASES))
        self.assertEqual(gate.PLAN['client_retries'], 0)
        self.assertEqual(gate.PLAN['expected_upstream_packets'], 2)

    def test_kernel_route_predicate_rejects_manual_pid_and_other_events(self):
        record = gate.route_records(netlink(), (0, 64))[0]
        self.assertTrue(record['qualifies'])
        self.assertTrue(gate.controlled_route(record))
        record['attributes'][0]['data'] = 'c612fb00'
        self.assertFalse(gate.controlled_route(record), 'unrelated route cannot witness the trigger')
        for wire, peer in [(netlink(pid=900), (0, 64)), (netlink(), (900, 64)),
                           (netlink(kind=25), (0, 64)), (netlink(kind=20), (0, 64)),
                           (netlink(scope=0), (0, 64)), (netlink(route_type=2), (0, 64)),
                           (netlink(table=100), (0, 64))]:
            self.assertFalse(gate.route_records(wire, peer)[0]['qualifies'])
        self.assertTrue(gate.route_records(netlink(table=255), (0, 64))[0]['qualifies'])
        for clipped in [netlink()[:-1], netlink() + b'x']:
            with self.assertRaises(ValueError):
                gate.route_records(clipped, (0, 64))

    def test_raw_repeated_packet_same_source_validates(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); _, row = raw_fixture(folder)
            result = gate.validate_case(folder, row, 'x' * 64)
            self.assertTrue(result['resend_contract_passed'])
            self.assertEqual(result['forward_actions'], 1)

    def test_missing_resend_preserves_defect_and_cleanup_cannot_pass(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); witness, row = raw_fixture(folder, resend=False)
            self.assertFalse(gate.validate_case(folder, row, 'x' * 64)['resend_contract_passed'])
            witness['cleanup_answer'] = False
            gate.save_json(folder / 'caller-witness.json', witness)
            with self.assertRaisesRegex(ValueError, 'cleanup'):
                gate.validate_case(folder, row, 'x' * 64)

    def test_answer_rejects_changed_flags_owner_class_ttl_or_opt(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); raw_fixture(folder)
            query, reply = (folder / 'client.query').read_bytes(), (folder / 'client.reply').read_bytes()
            _, end = gate.driver.read_name(query, 12)
            rr_offset = end + 4
            variants = [reply[:2] + struct.pack('!H', flags) + reply[4:] for flags in [0x8100, 0x8580, 0x81a0]]
            # Compressed owner2, type2, class2, ttl4, rdlength2, then RDATA.
            variants += [reply[:rr_offset + 6] + struct.pack('!I', 1) + reply[rr_offset + 10:],
                         reply[:rr_offset + 4] + struct.pack('!H', 3) + reply[rr_offset + 6:],
                         reply[:rr_offset] + b'\xc0\x0d' + reply[rr_offset + 2:],
                         reply[:10] + b'\0\0' + reply[12:-11]]
            self.assertTrue(gate.correct_answer(query, reply))
            for bad in variants:
                self.assertFalse(gate.correct_answer(query, bad))

    def test_refuses_corrupted_evidence_or_nonidentical_resend(self):
        cases = ['route-wire', 'query-wire', 'new-port', 'new-id', 'third-send', 'missing-upstream',
                 'early-first', 'early-second', 'wrong-reply-source', 'dad-not-excluded', 'forward-counter',
                 'extra-reply', 'fd-return', 'fd-no-spacing', 'wrong-client-content',
                 'wrong-elf', 'missing-completion', 'response-before-trigger', 'unfrozen-plan']
        for kind in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                folder = Path(name); witness, row = raw_fixture(folder)
                expects_exception = kind not in ['new-port', 'new-id']
                if kind == 'route-wire':
                    (folder / 'trigger-000.netlink').write_bytes(netlink(pid=900))
                elif kind == 'query-wire':
                    (folder / 'upstream-001.query').write_bytes(b'bad')
                elif kind == 'new-port':
                    witness['held_packets'][1]['source'] = ['127.0.0.1', 50002]
                elif kind == 'new-id':
                    path = folder / 'upstream-001.query'
                    path.write_bytes(b'\x6e\x02' + path.read_bytes()[2:])
                    row['upstream'][1]['wire'] = path.read_bytes().hex()
                    receipts = json.loads((folder / 'upstream-receipts.json').read_text())
                    receipts[1]['wire'] = path.read_bytes().hex()
                    gate.save_json(folder / 'upstream-receipts.json', receipts)
                elif kind == 'third-send':
                    row['upstream'].append(copy.deepcopy(row['upstream'][1]))
                elif kind == 'missing-upstream':
                    row['upstream'] = []
                elif kind in ['early-first', 'early-second']:
                    index = 0 if kind == 'early-first' else 1
                    stamp = 250 if index == 0 else 99
                    witness['held_packets'][index]['received_monotonic_ns'] = stamp
                    receipts = json.loads((folder / 'upstream-receipts.json').read_text())
                    receipts[index]['received_monotonic_ns'] = stamp
                    gate.save_json(folder / 'upstream-receipts.json', receipts)
                elif kind == 'wrong-reply-source':
                    witness['reply_source'][1] += 1
                elif kind == 'dad-not-excluded':
                    witness['dummy_ipv6'] = 'active'
                elif kind == 'forward-counter':
                    gate.save_json(folder / 'after.metrics.stdout', {'tcp_connections': 0, 'dns_queries_forwarded': 2})
                elif kind == 'extra-reply':
                    (folder / 'client.extra-reply').write_bytes((folder / 'client.reply').read_bytes())
                elif kind == 'fd-return':
                    gate.save_json(folder / 'after.fds.json', [{'monotonic_ns': n * 20_000_000, 'fds': {}} for n in range(3)])
                elif kind == 'fd-no-spacing':
                    gate.save_json(folder / 'after.fds.json', [{'monotonic_ns': 0, 'fds': witness['idle_fds']} for _ in range(3)])
                elif kind == 'wrong-client-content':
                    path = folder / 'client.reply'; path.write_bytes(path.read_bytes().replace(socket.inet_aton('198.51.100.7'), socket.inet_aton('198.51.100.8')))
                elif kind == 'wrong-elf':
                    row['identity']['sha256'] = 'y' * 64
                elif kind == 'missing-completion':
                    witness['completed'] = False
                elif kind == 'response-before-trigger':
                    witness['reply_monotonic_ns'] = 99
                elif kind == 'unfrozen-plan':
                    witness['plan'] = copy.deepcopy(gate.PLAN); witness['plan']['expected_upstream_packets'] = 1
                gate.save_json(folder / 'caller-witness.json', witness)
                if expects_exception:
                    with self.assertRaises(ValueError):
                        gate.validate_case(folder, row, 'x' * 64)
                else:
                    self.assertFalse(gate.validate_case(folder, row, 'x' * 64)['resend_contract_passed'])

    def test_run_validation_binds_dependencies_process_root_and_complete_profiles(self):
        # Synthetic receipt tests exercise validator rejection only. They are
        # not actual C execution or running-process identity observations.
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); (folder / 'drivers').mkdir()
            tools = {}
            for filename in gate.TOOLS:
                source = Path(gate.__file__).with_name(filename)
                (folder / 'drivers' / filename).write_bytes(source.read_bytes())
                tools[filename] = gate.driver.sha256(source)
            rows = []
            for case in gate.CASES:
                target = folder / case['case']; target.mkdir()
                witness, row = raw_fixture(target)
                witness['case'] = case['case']; row['case'] = case['case']
                row['identity'] = {'root': '/synthetic/root', 'sha256': gate.driver.STOCK_SHA256}
                gate.save_json(target / 'caller-witness.json', witness); rows.append(row)
            report = {'side': 'c', 'c_sha256': gate.driver.STOCK_SHA256, 'rust_sha256': 'x' * 64,
                      'scenarios': rows, 'failures': []}
            gate.save_json(folder / 'result.json', report)
            gate.save_json(folder / 'rootfs-identity.json', {'root': '/synthetic/root', 'rust_sha256': 'x' * 64,
                                                            'c_sha256': gate.driver.STOCK_SHA256})
            gate.save_json(folder / 'route-receipt.json', {'plan': gate.PLAN, 'tools': tools, 'tools_unchanged': True})
            self.assertEqual(len(gate.validate_run(folder, 'c', 'x' * 64)), 2)
            with self.assertRaisesRegex(ValueError, 'identity'):
                gate.validate_run(folder, 'c', 'y' * 64)
            report['scenarios'][0]['identity']['root'] = '/different/root'
            gate.save_json(folder / 'result.json', report)
            with self.assertRaisesRegex(ValueError, 'rootfs'):
                gate.validate_run(folder, 'c', 'x' * 64)
            report['scenarios'][0]['identity']['root'] = '/synthetic/root'
            report['scenarios'].pop(); gate.save_json(folder / 'result.json', report)
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                gate.validate_run(folder, 'c', 'x' * 64)
            (folder / 'drivers/m2_rootfs.py').write_text('modified dependency')
            with self.assertRaisesRegex(ValueError, 'dependency'):
                gate.validate_run(folder, 'c', 'x' * 64)


def clear_fixture(folder, spec, unwanted_resend=False):
    wanted = spec['expected_upstream_packets'] == 2
    witness, row = raw_fixture(folder, resend=wanted or unwanted_resend)
    witness['case'] = spec['case']; witness['plan'] = gate.CLEAR_PLAN; row['case'] = spec['case']
    row['identity']['cmdline'] = '/usr/sbin/dnsmasq ' + ('-d' if spec.get('debug') else '-k') + ' -C /m2/cache.conf'
    for index, packet in enumerate(witness['held_packets']):
        packet['received_monotonic_ns'] = 1_000_000_000 if index == 0 else 5_000_000_000
    witness.update(trigger_monotonic_ns=4_000_000_000, reply_monotonic_ns=6_400_000_000,
        resend_wait_started_monotonic_ns=4_200_000_000, resend_wait_finished_monotonic_ns=6_200_000_000,
        before_metrics={'dns_queries_forwarded': 0, 'tcp_connections': 0},
        after_metrics={'dns_queries_forwarded': 1, 'tcp_connections': 0})
    gate.save_json(folder / 'upstream-receipts.json', [
        {'sequence': index, 'transport': 'udp', 'wire': (folder / packet['file']).read_bytes().hex(),
         'received_monotonic_ns': packet['received_monotonic_ns']}
        for index, packet in enumerate(witness['held_packets'])])
    before = {'InDatagrams': 10, 'InErrors': 0, 'RcvbufErrors': 0}
    delta = {'local-udp': 2, 'invalid-udp': 1, 'unmatched-upstream': 1,
             'hup': 0, 'bound-tcp': 0, 'debug-tcp': 0}[spec['action']]
    action = {'action': spec['action'], 'started_monotonic_ns': 2_000_000_000,
              'completed_monotonic_ns': 3_000_000_000, 'udp_before': before, 'udp_delta': delta,
              'client_source': [gate.driver.CLIENT, 52001], 'destination': witness['dns_destination']}
    gate.save_json(folder / 'action-udp-before.json', before)
    gate.save_json(folder / 'action-udp-samples.json', [
        {'monotonic_ns': 2_100_000_000 + index * 20_000_000, 'stats': dict(before, InDatagrams=10+delta)}
        for index in range(3)])
    query = gate.driver.query('health.cache.test', 0x6e02)
    _, end = gate.driver.read_name(query, 12)
    answer = (query[:2] + struct.pack('!5H', 0x8580, 1, 1, 0, 1) + query[12:end + 4]
        + gate.driver.rr(1, socket.inet_aton('198.51.100.99'), ttl=600)
        + gate.driver.rr(41, b'', owner=b'\0', ttl=0, cls=1232))
    if spec['action'] in ['local-udp', 'bound-tcp', 'debug-tcp']:
        (folder / 'action.query').write_bytes(query); (folder / 'action.reply').write_bytes(answer)
    elif spec['action'] == 'invalid-udp':
        (folder / 'action.query').write_bytes(b'\x00')
    elif spec['action'] == 'unmatched-upstream':
        packet = (folder / 'upstream-000.query').read_bytes()
        reply = (folder / 'client.reply').read_bytes()
        (folder / 'action.query').write_bytes(packet)
        (folder / 'action.upstream-packet').write_bytes((int.from_bytes(packet[:2], 'big') ^ 0x8000).to_bytes(2, 'big') + reply[2:])
        action['upstream_source'] = ['127.0.0.2', 50000]
        action['destination'] = witness['held_packets'][0]['source']
    elif spec['action'] == 'hup':
        action.update(hosts_before=spec['initial_hosts'],
            hosts_after='198.51.100.41 hup-one.route.test\n198.51.100.42 hup-two.route.test\n')
        (folder / 'action-hosts').write_text(action['hosts_after'])
        (folder / 'action-before.daemon.log').write_text('read /m2/caller.hosts - 1 names\n')
        (folder / 'action-after.daemon.log').write_text('read /m2/caller.hosts - 1 names\nread /m2/caller.hosts - 2 names\n')
    if spec['action'] == 'bound-tcp':
        snapshots = []
        for index in range(3):
            value = {'tcp_connections': 0, 'dns_queries_forwarded': 1}
            gate.save_json(folder / f'action-tcp-{index:03}.metrics.stdout', value)
            snapshots.append({'monotonic_ns': 2_100_000_000 + index*20_000_000, 'metrics': value})
        gate.save_json(folder / 'action-tcp-samples.json', snapshots)
    config = (f'port=53000\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={gate.driver.LISTEN}\n'
        'server=127.0.0.2#50000\ncache-size=0\nno-0x20-encode\n'
        'host-record=health.cache.test,198.51.100.99\nlocal-ttl=600\nuser=root\n'
        'pid-file=/m2/cache.pid\nlog-facility=/m2/cache.log\n' + spec['config'] + '\n'
        + ('enable-ubus=cache-metrics\n' if spec['metrics'] else ''))
    (folder / 'config').write_text(config)
    if spec['action'] == 'debug-tcp':
        for label in ['before', 'after']:
            (folder / (label + '.metrics.stdout')).unlink()
            witness.pop(label + '_metrics')
        for label, raw in [('before', b'startup\n'), ('after', b'startup\ndnsmasq[24]: forwarded route.resend.test to 127.0.0.2#50000\n')]:
            (folder / (label + '.forward.log')).write_bytes(raw)
            value = {'forward_actions': len(gate.forwarded_messages(raw)), 'messages': gate.forwarded_messages(raw)}
            gate.save_json(folder / (label + '.forward.json'), value); witness[label + '_forward_log'] = value
        held = dict(witness['idle_fds'], **{'4': 'socket:[1001]'})
        action.update(held_fds=held, server_eof=True, shutdown_write_monotonic_ns=2_150_000_000, eof_monotonic_ns=2_180_000_000)
        gate.save_json(folder / 'action-held-before.fds.json', [
            {'monotonic_ns': 2_010_000_000 + index * 20_000_000, 'fds': held} for index in range(3)])
        raw_tcp = ('sl local_address rem_address st queues timers retr uid timeout inode\n'
            '0: 010200C0:CF08 110200C0:CB21 01 00000000:00000000 00:00000000 00000000 0 0 4242\n')
        fds = dict(held, **{'5': 'socket:[4242]'})
        live = {'monotonic_ns': 2_140_000_000, 'fds': fds, 'raw_tcp': raw_tcp,
                'rows': gate.tcp_rows(raw_tcp, fds, action['client_source'], action['destination'])}
        gate.save_json(folder / 'action-debug-tcp-live.json', live)
        gate.save_json(folder / 'action-debug-tcp-live-samples.json', [
            dict(live, monotonic_ns=2_100_000_000 + index * 20_000_000) for index in range(3)])
        gate.save_json(folder / 'action-debug-tcp-samples.json', [
            {'monotonic_ns': 2_200_000_000 + index * 20_000_000, 'fds': held,
             'raw_tcp': 'sl local_address rem_address st queues timers retr uid timeout inode\n', 'rows': []}
            for index in range(3)])
        (folder / 'action-tcp-eof').write_bytes(b'')
    witness['action'] = action
    gate.save_json(folder / 'action-witness.json', action); gate.save_json(folder / 'caller-witness.json', witness)
    return witness, row


class RouteClearTests(unittest.TestCase):
    def test_clear_profiles_validate_all_six_without_weakening_basic(self):
        self.assertEqual(len(gate.CASES), 2)
        self.assertEqual(gate.PLAN['expected_upstream_packets'], 2)
        self.assertEqual(len(gate.CLEAR_CASES), 6)
        for spec in gate.CLEAR_CASES:
            with self.subTest(action=spec['action']), tempfile.TemporaryDirectory() as name:
                folder = Path(name); _, row = clear_fixture(folder, spec)
                result = gate.validate_clear_case(folder, row, 'x' * 64)
                self.assertTrue(result['caller_contract_passed'])
                self.assertEqual(result['upstream_packets'], spec['expected_upstream_packets'])
                with self.assertRaisesRegex(ValueError, 'unfrozen'):
                    gate.validate_case(folder, row, 'x' * 64)

    def test_only_debug_disables_ubus_and_keeps_frozen_real_counter_guards(self):
        debug = next(spec for spec in gate.CLEAR_CASES if spec['action'] == 'debug-tcp')
        self.assertFalse(debug['metrics']); self.assertEqual(debug['config'], 'log-queries')
        self.assertTrue(all(spec['metrics'] for spec in gate.CLEAR_CASES if spec is not debug))
        self.assertTrue(all(spec['metrics'] for spec in gate.CASES))
        self.assertEqual(gate.PLAN['expected_forward_actions'], 1)
        self.assertEqual(gate.CLEAR_PLAN['debug_tcp_observation']['expected_forward_actions'], 1)

    def test_debug_log_and_socket_eof_negatives_cannot_bypass_counters_or_fd_recovery(self):
        spec = next(row for row in gate.CLEAR_CASES if row['action'] == 'debug-tcp')
        for kind in ['reenable-ubus', 'no-log-queries', 'extra-forward', 'wrong-upstream', 'fake-log-count',
                     'not-append-only', 'eof-extra', 'no-eof', 'wrong-live-tuple', 'fake-live-state',
                     'live-fd-swap', 'live-no-spacing', 'closed-fd-leak', 'closed-no-spacing',
                     'early-eof', 'fake-debug-metrics', 'idle-fd-swap']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                folder = Path(name); witness, row = clear_fixture(folder, spec)
                action = witness['action']
                if kind in ['reenable-ubus', 'no-log-queries']:
                    path = folder / 'config'
                    path.write_text(path.read_text() + 'enable-ubus=cache-metrics\n' if kind == 'reenable-ubus'
                                    else path.read_text().replace('log-queries\n', ''))
                elif kind in ['extra-forward', 'wrong-upstream', 'not-append-only']:
                    path = folder / 'after.forward.log'; data = path.read_bytes()
                    if kind == 'extra-forward': data += b'dnsmasq[24]: forwarded route.resend.test to 127.0.0.2#50000\n'
                    elif kind == 'wrong-upstream': data = data.replace(b'#50000', b'#50001')
                    else: data = data.replace(b'startup\n', b'different start\n')
                    path.write_bytes(data)
                elif kind == 'fake-log-count': witness['after_forward_log']['forward_actions'] = 0
                elif kind == 'eof-extra': (folder / 'action-tcp-eof').write_bytes(b'x')
                elif kind == 'no-eof': action['server_eof'] = False
                elif kind == 'early-eof': action['eof_monotonic_ns'] = action['shutdown_write_monotonic_ns'] - 1
                elif kind == 'fake-debug-metrics': gate.save_json(folder / 'after.metrics.stdout', {'tcp_connections': 0, 'dns_queries_forwarded': 1})
                elif kind == 'idle-fd-swap':
                    samples = json.loads((folder / 'after.fds.json').read_text())
                    for item in samples: item['fds']['3'] = 'socket:[9999]'
                    gate.save_json(folder / 'after.fds.json', samples)
                elif kind.startswith('live') or kind in ['wrong-live-tuple', 'fake-live-state']:
                    live = json.loads((folder / 'action-debug-tcp-live.json').read_text())
                    samples = json.loads((folder / 'action-debug-tcp-live-samples.json').read_text())
                    if kind == 'wrong-live-tuple': live['raw_tcp'] = live['raw_tcp'].replace('110200C0:CB21', '110200C0:CB22')
                    elif kind == 'fake-live-state': live['rows'][0]['state'] = 6
                    elif kind == 'live-fd-swap': live['fds']['3'] = 'socket:[9999]'
                    else:
                        for item in samples: item['monotonic_ns'] = live['monotonic_ns']
                    gate.save_json(folder / 'action-debug-tcp-live.json', live)
                    gate.save_json(folder / 'action-debug-tcp-live-samples.json', samples)
                else:
                    samples = json.loads((folder / 'action-debug-tcp-samples.json').read_text())
                    for item in samples:
                        if kind == 'closed-fd-leak': item['fds']['5'] = 'socket:[4242]'
                        else: item['monotonic_ns'] = samples[0]['monotonic_ns']
                    gate.save_json(folder / 'action-debug-tcp-samples.json', samples)
                gate.save_json(folder / 'action-witness.json', action); gate.save_json(folder / 'caller-witness.json', witness)
                with self.assertRaises(ValueError): gate.validate_clear_case(folder, row, 'x' * 64)

    def test_unwanted_resend_is_defect_not_false_clear_pass(self):
        for spec in gate.CLEAR_CASES:
            if spec['expected_upstream_packets'] != 1: continue
            with self.subTest(action=spec['action']), tempfile.TemporaryDirectory() as name:
                folder = Path(name); _, row = clear_fixture(folder, spec, unwanted_resend=True)
                self.assertFalse(gate.validate_clear_case(folder, row, 'x' * 64)['caller_contract_passed'])

    def test_clear_negative_controls_reject_missing_consumption_and_wrong_witnesses(self):
        corruptions = ['no-consumption', 'extra-consumption', 'recv-errors', 'no-spacing', 'late-action', 'wrong-parent-counter', 'wrong-debug',
            'wrong-bind', 'invalid-replied', 'unmatched-id', 'wrong-upstream-source',
            'wrong-unmatched-destination', 'hup-not-completed', 'hup-preexisting-marker',
            'short-absence', 'wrong-tcp-counter', 'wrong-local-answer', 'third-upstream']
        for kind in corruptions:
            action_name = ('invalid-udp' if kind == 'invalid-replied' else 'unmatched-upstream' if kind.startswith('unmatched') or kind in ['wrong-upstream-source','wrong-unmatched-destination']
                else 'hup' if kind.startswith('hup-') else 'bound-tcp' if kind == 'wrong-tcp-counter' else 'local-udp')
            spec = next(row for row in gate.CLEAR_CASES if row['action'] == action_name)
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                folder = Path(name); witness, row = clear_fixture(folder, spec)
                action = witness['action']
                if kind in ['no-consumption', 'extra-consumption', 'recv-errors', 'no-spacing']:
                    samples = json.loads((folder / 'action-udp-samples.json').read_text())
                    for value in samples:
                        if kind == 'no-consumption': value['stats']['InDatagrams'] = 10
                        elif kind == 'extra-consumption': value['stats']['InDatagrams'] += 1
                        elif kind == 'recv-errors': value['stats']['RcvbufErrors'] += 1
                        else: value['monotonic_ns'] = samples[0]['monotonic_ns']
                    gate.save_json(folder / 'action-udp-samples.json', samples)
                elif kind == 'late-action': action['completed_monotonic_ns'] = 4_100_000_000
                elif kind == 'wrong-parent-counter': witness['before_metrics']['dns_queries_forwarded'] = 1
                elif kind == 'wrong-debug': row['identity']['cmdline'] = row['identity']['cmdline'].replace('-k', '-d')
                elif kind == 'wrong-bind':
                    path = folder / 'config'; path.write_text(path.read_text().replace('bind-interfaces\n', ''))
                elif kind == 'invalid-replied': (folder / 'action.reply').write_bytes(b'bad')
                elif kind == 'unmatched-id':
                    path = folder / 'action.upstream-packet'; path.write_bytes((folder / 'action.query').read_bytes()[:2] + path.read_bytes()[2:])
                elif kind == 'wrong-upstream-source': action['upstream_source'][1] += 1
                elif kind == 'wrong-unmatched-destination': action['destination'] = ['127.0.0.1', 59999]
                elif kind == 'hup-not-completed': (folder / 'action-after.daemon.log').write_text('no HUP here\n')
                elif kind == 'hup-preexisting-marker': (folder / 'action-before.daemon.log').write_text(gate.CLEAR_PLAN['hup_log_marker'])
                elif kind == 'short-absence': witness['resend_wait_finished_monotonic_ns'] = 4_250_000_000
                elif kind == 'wrong-tcp-counter':
                    gate.save_json(folder / 'action-tcp-000.metrics.stdout', {'tcp_connections': 0, 'dns_queries_forwarded': 2})
                elif kind == 'wrong-local-answer':
                    path = folder / 'action.reply'; path.write_bytes(path.read_bytes().replace(socket.inet_aton('198.51.100.99'), socket.inet_aton('198.51.100.98')))
                elif kind == 'third-upstream': row['upstream'].append(copy.deepcopy(row['upstream'][0]))
                gate.save_json(folder / 'action-witness.json', action); gate.save_json(folder / 'caller-witness.json', witness)
                with self.assertRaises(ValueError): gate.validate_clear_case(folder, row, 'x' * 64)


    def test_clear_run_requires_complete_frozen_set_and_batch_identity(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); (folder / 'drivers').mkdir()
            tools = {}
            for filename in gate.TOOLS:
                source = Path(gate.__file__).with_name(filename)
                (folder / 'drivers' / filename).write_bytes(source.read_bytes())
                tools[filename] = gate.driver.sha256(source)
            rows = []
            for spec in gate.CLEAR_CASES:
                target = folder / spec['case']; target.mkdir()
                _, row = clear_fixture(target, spec)
                row['identity'].update(root='/synthetic/root', sha256=gate.driver.STOCK_SHA256)
                rows.append(row)
            report = {'side': 'c', 'c_sha256': gate.driver.STOCK_SHA256, 'rust_sha256': 'x'*64,
                      'scenarios': rows, 'failures': []}
            gate.save_json(folder / 'result.json', report)
            gate.save_json(folder / 'rootfs-identity.json', {'root': '/synthetic/root', 'rust_sha256': 'x'*64,
                'c_sha256': gate.driver.STOCK_SHA256})
            gate.save_json(folder / 'route-receipt.json', {'plan': gate.CLEAR_PLAN, 'tools': tools, 'tools_unchanged': True})
            self.assertEqual(len(gate.validate_run(folder, 'c', 'x'*64, 'clears')), 6)
            with self.assertRaisesRegex(ValueError, 'identity'):
                gate.validate_run(folder, 'c', 'x'*64, 'basic')
            report['scenarios'].pop(); gate.save_json(folder / 'result.json', report)
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                gate.validate_run(folder, 'c', 'x'*64, 'clears')


if __name__ == '__main__':
    unittest.main()
