#!/usr/bin/env python3
"""Small decoder/comparison negative controls; no daemon or network access."""
import copy
import socket
import struct
import unittest

from dns_service_probe import query, semantics
from tcp_upstream_parity import ENDPOINTS, compare, decode_packet, response


class ParityTests(unittest.TestCase):
    def test_ipv4_syn_including_refused_destination(self):
        ip = bytearray(20)
        ip[0], ip[9] = 0x45, 6
        ip[12:16], ip[16:20] = socket.inet_aton('127.0.0.1'), socket.inet_aton(ENDPOINTS['v4a'])
        tcp = struct.pack('!HHII', 39000, 53, 41, 0) + b'\x50\x02' + bytes(6)
        row = decode_packet(bytes(12) + b'\x08\x00' + ip + tcp)
        self.assertEqual((row['upstream'], row['direction'], row['flags'], row['sequence']),
                         ('v4a', 'to-upstream', 2, 41))

    def test_ipv6_syn_and_rst(self):
        ip = bytearray(40)
        ip[0], ip[6] = 0x60, 6
        ip[8:24] = socket.inet_pton(socket.AF_INET6, ENDPOINTS['v6b'])
        ip[24:40] = socket.inet_pton(socket.AF_INET6, '::1')
        tcp = struct.pack('!HHII', 53, 39000, 41, 0) + b'\x50\x14' + bytes(6)
        row = decode_packet(bytes(12) + b'\x86\xdd' + ip + tcp)
        self.assertEqual((row['upstream'], row['direction'], row['flags']), ('v6b', 'from-upstream', 20))

    def test_non_fixture_and_short_packets_ignored(self):
        self.assertIsNone(decode_packet(b''))
        self.assertIsNone(decode_packet(bytes(80)))

    def test_fixture_answers_keep_question_and_disable_cache(self):
        for kind, expected in ((1, '192.0.2.7'), (28, '2001:db8::7')):
            parsed = semantics(response(query('fixture.test', kind=kind, ident=43)))
            self.assertEqual(parsed['id'], 43)
            self.assertEqual(parsed['questions'], [['fixture.test', kind, 1]])
            self.assertEqual(parsed['records'][0]['data'], expected)
            self.assertEqual(parsed['records'][0]['ttl'], 0)

    def trace(self):
        return {'status': 'observed', 'daemon_alive_after_queries': True, 'rows': [{
            'label': 'first', 'transport': 'tcp', 'name': 'first.test', 'type': 1,
            'request': '0010', 'session': 'one', 'timeout_seconds': 15,
            'scheduled_udp_retries_seconds': [], 'status': 'reply', 'wire': '0001',
            'window_connect_order': ['v4a', 'v6b'], 'elapsed_seconds': 5.01,
            'reused_connection': False,
            'upstream_queries': [{'protocol': 'tcp', 'upstream': 'v6b'}],
        }]}

    def test_route_wire_reuse_and_latency_mutations_rejected(self):
        original = self.trace()
        before = copy.deepcopy(original)
        self.assertEqual(compare(original, copy.deepcopy(original)), [])
        self.assertEqual(original, before)
        for key, value in (('wire', '0002'), ('window_connect_order', ['v6b']),
                           ('reused_connection', True), ('elapsed_seconds', 10),
                           ('status', 'error'), ('request', '0020'), ('timeout_seconds', 2), ('transport', 'udp')):
            mutated = copy.deepcopy(original)
            mutated['rows'][0][key] = value
            self.assertTrue(compare(original, mutated), key)
        mutated = copy.deepcopy(original)
        mutated['rows'][0]['upstream_queries'][0]['upstream'] = 'v6a'
        self.assertTrue(compare(original, mutated))

    def test_late_cleanup_error_or_dead_daemon_never_pass(self):
        mutated = self.trace()
        mutated['harness_error'] = 'cleanup failed'
        self.assertTrue(compare(self.trace(), mutated))
        mutated = self.trace()
        mutated['daemon_alive_after_queries'] = False
        self.assertTrue(compare(self.trace(), mutated))
        self.assertTrue(compare(mutated, copy.deepcopy(mutated)))
        mutated = self.trace()
        mutated['cleanup_non_zombie_survivors'] = [{'pid': 42, 'state': 'S'}]
        self.assertTrue(compare(self.trace(), mutated))

    def test_harness_failure_or_missing_row_never_pass(self):
        self.assertTrue(compare(self.trace(), {'status': 'incomplete', 'rows': []}))
        self.assertTrue(compare(self.trace(), {'status': 'observed', 'daemon_alive_after_queries': True, 'rows': []}))


if __name__ == '__main__':
    unittest.main()
