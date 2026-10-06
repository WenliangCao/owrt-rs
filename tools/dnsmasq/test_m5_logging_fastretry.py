import copy
import socket
import sys
import unittest
from unittest.mock import patch

import m5_logging as logging


class FastRetryFixtureTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux loopback aliases required')
    def test_actual_udp_response_requires_first_retry(self):
        upstream = logging.QueryUpstream(retry_barrier=True)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(('127.0.0.1', 0)); client.settimeout(.05)
                packet = logging.query_packet('delay.forward.test', 1, 0x7601)
                client.sendto(packet, ('127.0.0.2', 15957))
                with self.assertRaises(socket.timeout): client.recv(65535)
                self.assertEqual(upstream.retry_requests, 1)
                client.sendto(packet, ('127.0.0.2', 15957)); client.settimeout(1)
                response = client.recv(65535)
                self.assertEqual(response[:2], packet[:2])
                self.assertTrue(upstream.retry_released.wait(1))
                self.assertEqual(upstream.retry_requests, 2)
                self.assertEqual(upstream.released_on_request, 2)
                first, retry = upstream.wire
                self.assertEqual(first['reply'], response.hex()); self.assertIsNone(retry['reply'])
                self.assertGreaterEqual(first['response_send_started_monotonic_ns'], retry['received_monotonic_ns'])
        finally: upstream.close()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux loopback aliases required')
    def test_missing_retry_is_bounded_and_never_gets_a_reply(self):
        with patch.object(logging, 'RETRY_BARRIER_SECONDS', .1):
            upstream = logging.QueryUpstream(retry_barrier=True)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(.3)
                    client.sendto(logging.query_packet('delay.forward.test'), ('127.0.0.2', 15957))
                    with self.assertRaises(socket.timeout): client.recv(65535)
                self.assertTrue(upstream.stopped.is_set())
                self.assertIsNone(upstream.wire[0]['reply'])
                self.assertIsNone(upstream.wire[0]['response_sent_monotonic_ns'])
            finally:
                with self.assertRaisesRegex(AssertionError, 'retry'): upstream.close()

    def witness(self):
        first = {'transport': 'udp', 'request': '7601', 'reply': '7601', 'client': ['127.0.0.1', 16505],
                 'send_count': 1, 'sent_monotonic_ns': 1_000_000_000, 'received_monotonic_ns': 1_060_000_000}
        cached = dict(first, transport='udp-cached', request='7100', reply='7100', client=['127.0.0.1', 16507],
                      sent_monotonic_ns=1_070_000_000, received_monotonic_ns=1_080_000_000)
        forward = {'transport': 'udp', 'request': '0102', 'reply': '0103', 'server': ['127.0.0.2', 15957],
                   'peer': ['127.0.0.1', 10000], 'received_monotonic_ns': 1_001_000_000,
                   'response_send_started_monotonic_ns': 1_052_000_000, 'response_sent_monotonic_ns': 1_053_000_000}
        retry = copy.deepcopy(forward)
        retry.update(reply=None, received_monotonic_ns=1_051_000_000, response_sent_monotonic_ns=None)
        return {'fast_retry_witness': {'client_queries': [first, cached], 'upstream': [forward, retry],
                'upstream_requests': 2, 'released_on_request': 2, 'deadline_seconds': 2.5}}

    def test_witness_rejects_missing_retry_client_resend_early_reply_and_wrong_wire(self):
        self.assertEqual(logging.fast_retry_witness_errors(self.witness()), [])
        for mutation in ['missing', 'client-resend', 'wire', 'peer', 'extra-response', 'early-reply', 'deadline', 'missing-clock']:
            with self.subTest(mutation=mutation):
                row = copy.deepcopy(self.witness()); witness = row['fast_retry_witness']
                first, retry = witness['upstream']
                if mutation == 'missing': witness['upstream'].pop()
                elif mutation == 'client-resend': witness['client_queries'][0]['send_count'] = 2
                elif mutation == 'wire': retry['request'] = 'ffff'
                elif mutation == 'peer': retry['peer'][1] += 1
                elif mutation == 'extra-response': retry['reply'] = first['reply']
                elif mutation == 'early-reply': first['response_send_started_monotonic_ns'] = 1_002_000_000
                elif mutation == 'deadline': witness['client_queries'][1]['received_monotonic_ns'] = 4_000_000_000
                else: retry.pop('received_monotonic_ns')
                self.assertTrue(logging.fast_retry_witness_errors(row))


if __name__ == '__main__': unittest.main()
