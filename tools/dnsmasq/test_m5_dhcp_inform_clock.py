import copy
import unittest

import m5_dhcp_tags_options as family


def response(remaining, name=b'client'):
    header = bytearray(240); header[0] = 2
    header[236:240] = bytes.fromhex('63825363')
    return bytes(header) + bytes([53, 1, 5, 51, 4]) + remaining.to_bytes(4, 'big') + bytes([12, len(name)]) + name + b'\xff'


class InformClock(unittest.TestCase):
    event = {'kind': 8, 'ciaddr': '127.0.0.40'}

    def witness(self, before=1_000_980_000_000, after=1_000_990_000_000, expiry=1600):
        return family.inform_clock_witness(f'{expiry} 02:00:00:00:00:01 127.0.0.40 * *\n',
                                          self.event, before, after)

    def test_independent_clock_phases_normalize_only_the_validated_time(self):
        c = family.comparable_reply(response(600), self.event, self.witness())
        r = family.comparable_reply(response(599), self.event,
            self.witness(1_001_002_000_000, 1_001_003_000_000))
        self.assertEqual(c, r)
        changed = family.comparable_reply(response(599, b'changed'), self.event,
            self.witness(1_001_002_000_000, 1_001_003_000_000))
        self.assertNotEqual(c, changed)
        self.assertEqual(family.comparable_reply(response(599), self.event), response(599).hex())

    def test_boundary_accepts_only_clocks_in_the_observed_interval(self):
        clock = self.witness(1_000_999_000_000, 1_001_002_000_000)
        for remaining in [599, 600]:
            family.comparable_reply(response(remaining), self.event, clock)
        for remaining in [0, 598, 601, 0xffffffff]:
            with self.subTest(remaining=remaining), self.assertRaises(AssertionError):
                family.comparable_reply(response(remaining), self.event, clock)
        with self.assertRaises(AssertionError):
            family.comparable_reply(response(599), self.event, self.witness())

    def test_missing_ambiguous_and_changed_expiry_cannot_hide_a_wrong_reply(self):
        missing = family.inform_clock_witness('', self.event, 1_000_980_000_000, 1_000_990_000_000)
        with self.assertRaises(AssertionError): family.comparable_reply(response(600), self.event, missing)
        with self.assertRaises(AssertionError):
            family.inform_clock_witness('1600 aa 127.0.0.40 * *\n1601 bb 127.0.0.40 * *\n', self.event, 1, 2)
        with self.assertRaises(AssertionError):
            family.comparable_reply(response(600), self.event, self.witness(expiry=1599))
        bad = copy.deepcopy(self.witness()); bad['after_ns'] = bad['before_ns'] - 1
        with self.assertRaises(AssertionError): family.comparable_reply(response(600), self.event, bad)
        bad = copy.deepcopy(self.witness()); bad['lease_expiry'] = 1599
        with self.assertRaises(AssertionError): family.comparable_reply(response(599), self.event, bad)

    def test_infinite_lease_and_no_time_option_preserve_their_contracts(self):
        clock = self.witness(expiry=0)
        family.comparable_reply(response(0xffffffff), self.event, clock)
        with self.assertRaises(AssertionError): family.comparable_reply(response(600), self.event, clock)
        packet = bytes(240) + b'\x35\x01\x05\xff'
        self.assertEqual(family.comparable_reply(packet, self.event, clock), packet.hex())
