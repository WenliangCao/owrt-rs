#!/usr/bin/env python3
"""Offline checks of fixed profiles and raw DNS resource witnesses."""
import socket
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

if __name__ == '__main__':
    unittest.main()
