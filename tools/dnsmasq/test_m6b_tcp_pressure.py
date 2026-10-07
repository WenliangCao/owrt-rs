#!/usr/bin/env python3
"""Offline checks of fixed profiles and raw DNS resource witnesses."""
import socket
import json
import copy
import struct
from pathlib import Path
import tempfile
import unittest

import m6b_tcp_pressure as gate


def answer(wire, address='198.51.100.99', flags=0x8580):
    _, end = gate.driver.read_name(wire, 12)
    return wire[:2] + struct.pack('!5H', flags, 1, 1, 0, 0) + wire[12:end + 4] + gate.driver.rr(1, socket.inet_aton(address), ttl=600)


class ResourceWitnesses(unittest.TestCase):
    def test_controlled_eof_fixture_closes_old_and_fresh_before_fallback(self):
        peers = gate.EofServers(0, fallback_port=0, primary_address='127.0.0.1', fallback_address='127.0.0.1')
        ports = {role: endpoint.getsockname()[1] for endpoint, role in peers.listeners.items()}
        try:
            with socket.create_connection(('127.0.0.1', ports['primary']), timeout=2) as client:
                wire = gate.driver.query('first.pressure.test', 1)
                client.sendall(struct.pack('!H', len(wire)) + wire)
                reply = gate.driver.exact_read(client, struct.unpack('!H', gate.driver.exact_read(client, 2))[0])
                self.assertEqual(gate.driver.normalized(reply)['records'][0]['data'], '198.51.100.7')
                wire = gate.driver.query('second.pressure.test', 2)
                client.sendall(struct.pack('!H', len(wire)) + wire)
                self.assertEqual(client.recv(1), b'')
            with socket.create_connection(('127.0.0.1', ports['primary']), timeout=2) as client:
                client.sendall(struct.pack('!H', len(wire)) + wire)
                self.assertEqual(client.recv(1), b'')
            with socket.create_connection(('127.0.0.1', ports['fallback']), timeout=2) as client:
                client.sendall(struct.pack('!H', len(wire)) + wire)
                reply = gate.driver.exact_read(client, struct.unpack('!H', gate.driver.exact_read(client, 2))[0])
                self.assertEqual(gate.driver.normalized(reply)['records'][0]['data'], '198.51.100.8')
            self.assertEqual([(e['server'], e['connection']) for e in peers.events],
                             [('primary', 1), ('primary', 1), ('primary', 2), ('fallback', 1)])
        finally:
            peers.close()

    def test_plan_keeps_small_empty_large_and_ten_reconnect_batches(self):
        cases = {c['case']: c for c in gate.CASES}
        self.assertEqual(len(cases), len(gate.CASES))
        reconnect = [c for c in gate.CASES if c['mode'] == 'reconnect']
        self.assertEqual({c['capacity'] for c in reconnect}, {0, 150, 4096})
        self.assertTrue(all(c['batches'] == 10 and c['clients'] == 20 for c in reconnect))
        self.assertTrue(all(c['samples_after_drain_seconds'] == [0, 1, 5, 15, 60] for c in gate.CASES))

    def test_capture_rejects_wrong_content_id_and_error_reply(self):
        with tempfile.TemporaryDirectory() as folder:
            value = gate.Caller.__new__(gate.Caller)
            value.folder, value.rows = Path(folder), []
            wire = gate.driver.query('health.cache.test', 0x7432)
            value.capture('correct', wire, answer(wire))
            with self.assertRaises(AssertionError):
                value.capture('wrong-content', wire, answer(wire, '203.0.113.1'))
            with self.assertRaises(AssertionError):
                value.capture('wrong-id', wire, b'\0\0' + answer(wire)[2:])
            with self.assertRaises(AssertionError):
                value.capture('servfail', wire, answer(wire, flags=0x8582))
            self.assertEqual(len(value.rows), 1)

class RawQualificationTests(unittest.TestCase):
    # Fixture files below test rejection logic only; no daemon is executed.
    def test_all_grouped_profiles_bind_one_candidate(self):
        wanted = 'a'*64
        report = {'rust_sha256': wanted}
        receipt = {'candidate_sha256': wanted}
        root = {'rust_sha256': wanted, 'c_sha256': gate.driver.STOCK_SHA256}
        gate.bound_candidate(report, receipt, root, wanted)
        for record, key in [(report, 'rust_sha256'), (receipt, 'candidate_sha256'), (root, 'rust_sha256')]:
            old = record[key]; record[key] = 'b'*64
            with self.assertRaises(ValueError): gate.bound_candidate(report, receipt, root, wanted)
            record[key] = old

    def test_eof_raw_inventory_rejects_missing_fresh_primary_or_changed_retry(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            first = gate.driver.query('first.pressure.test', 1)
            second = gate.driver.query('second.pressure.test', 2)
            (folder / 'old-connection-seed.query').write_bytes(first)
            (folder / 'old-and-fresh-eof-fallback.query').write_bytes(second)
            rows = [{'server': role, 'connection': number, 'host': host,
                     'wire': wire.hex(), 'query': gate.driver.normalized(wire)} for role, number, host, wire in [
                ('primary', 1, 'first.pressure.test', first), ('primary', 1, 'second.pressure.test', second),
                ('primary', 2, 'second.pressure.test', second), ('fallback', 1, 'second.pressure.test', second)]]
            path = folder / 'upstream-eof-events.json'; path.write_text(json.dumps(rows))
            gate.eof_inventory(folder)
            path.write_text(json.dumps(rows[:2] + rows[3:]))
            with self.assertRaises(ValueError): gate.eof_inventory(folder)
            bad = copy.deepcopy(rows); bad[2]['wire'] = (b'\0\3' + second[2:]).hex()
            bad[2]['query'] = gate.driver.normalized(bytes.fromhex(bad[2]['wire']))
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): gate.eof_inventory(folder)

    def test_stable_fd_guard_uses_raw_targets_spacing_and_child_balance(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); wanted = {'0': '/dev/null', '7': 'socket:[123]'}
            rows = [{'monotonic_ns': 10_000_000 + index*20_000_000,
                     'snapshot': {'child_processes': 0, 'threads': 1,
                                  'members': [{'pid': 10, 'fds': wanted}]}} for index in range(3)]
            path = folder / 'drain.json'; path.write_text(json.dumps(rows))
            self.assertEqual(gate.stable_fd_receipt(folder, path.name, 10)[0], wanted)
            for kind in ['fd-target', 'short-spacing', 'child']:
                bad = copy.deepcopy(rows)
                if kind == 'fd-target': bad[-1]['snapshot']['members'][0]['fds']['7'] = 'socket:[999]'
                elif kind == 'short-spacing': bad[-1]['monotonic_ns'] = bad[-2]['monotonic_ns'] + 1
                else: bad[-1]['snapshot']['child_processes'] = 1
                path.write_text(json.dumps(bad))
                with self.subTest(kind=kind), self.assertRaises(ValueError): gate.stable_fd_receipt(folder, path.name, 10, wanted)

    def test_gauge_rechecks_actual_invocation_and_stdout(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); value = {'tcp_connections': 0}
            stdout = folder / 'closed-000.metrics.stdout'; stdout.write_text(json.dumps(value))
            stderr = folder / 'closed-000.metrics.stderr'; stderr.write_bytes(b'')
            call = {'argv': gate.driver.command(Path('/synthetic/root'), '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}'),
                    'returncode': 0, 'pid': 10, 'stdout_sha256': gate.driver.sha256(stdout),
                    'stderr_sha256': gate.driver.sha256(stderr)}
            (folder / 'closed-000.metrics.call.json').write_text(json.dumps(call))
            (folder / 'closed.gauge.json').write_text(json.dumps([{'monotonic_ns': 1, 'wanted': 0, 'value': value}]))
            gate.gauge_receipt(folder, 'closed.gauge.json', 10, '/synthetic/root', 0)
            stdout.write_text(json.dumps({'tcp_connections': 1}))
            with self.assertRaises(ValueError): gate.gauge_receipt(folder, 'closed.gauge.json', 10, '/synthetic/root', 0)


if __name__ == '__main__':
    unittest.main()
