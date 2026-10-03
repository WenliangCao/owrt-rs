#!/usr/bin/env python3
"""Keep missing or late observations from passing the ICMP coexistence gate."""
import copy
import unittest

from test_icmp_service import UDP_QUERIES, coexistence_passed


class CoexistenceAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.result = {
            'probe': {'observed': True, 'observed_monotonic': 10},
            'udp': {'started_monotonic': 10.1, 'finished_monotonic': 10.2,
                    'seconds': .1, 'semantic': [{'answer': '192.0.2.7'}] * UDP_QUERIES},
            'tftp': {'started_monotonic': 10.2, 'finished_monotonic': 10.3,
                     'seconds': .1, 'semantic': {'bytes': 1537}},
            'dora': {'offer_monotonic': 13, 'semantic': ['offer', 'ack']},
            'capture_stopped': True,
        }

    def test_observed_probe_and_completed_services_pass(self):
        self.assertTrue(coexistence_passed(self.result, with_tftp=True))

    def test_missing_probe_or_unexecuted_service_never_passes(self):
        for key in ('probe', 'udp', 'tftp', 'dora'):
            with self.subTest(key=key):
                result = copy.deepcopy(self.result)
                del result[key]
                self.assertFalse(coexistence_passed(result, with_tftp=True))
        del self.result['tftp']
        self.assertTrue(coexistence_passed(self.result, with_tftp=False))
        self.result['udp']['semantic'].pop()
        self.assertFalse(coexistence_passed(self.result, with_tftp=False))

    def test_late_or_pre_probe_completion_does_not_count_as_progress(self):
        for start, end, seconds in ((9, 9.1, .1), (10.1, 11.1, 1), (12.9, 13, .1)):
            with self.subTest(start=start, end=end):
                result = copy.deepcopy(self.result)
                result['udp'].update(started_monotonic=start, finished_monotonic=end, seconds=seconds)
                self.assertFalse(coexistence_passed(result, with_tftp=True))

    def test_client_failure_or_live_capture_fails_even_with_all_semantics(self):
        self.result['error'] = 'DHCP receive failed'
        self.assertFalse(coexistence_passed(self.result, with_tftp=True))
        del self.result['error']
        self.result['capture_stopped'] = False
        self.assertFalse(coexistence_passed(self.result, with_tftp=True))


if __name__ == '__main__':
    unittest.main()
