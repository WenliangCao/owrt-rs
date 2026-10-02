#!/usr/bin/env python3
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from m2_lifecycle import dhcp6_fqdn, dhcp6_ia_na, dhcp6_option, dhcp6_options


class Dhcp6EncodingTests(unittest.TestCase):
    def test_fqdn_is_a_client_fqdn_option_with_dns_wire_name(self):
        encoded = dhcp6_fqdn('m2-dhcp6')
        code, length = struct.unpack('!HH', encoded[:4])
        self.assertEqual(code, 39)
        self.assertEqual(length, len(encoded) - 4)
        self.assertEqual(encoded[4:], b'\0\x08m2-dhcp6\0')

    def test_ia_na_has_iaid_and_zero_server_timers(self):
        encoded = dhcp6_ia_na(0x4D320001)
        self.assertEqual(dhcp6_options(b'\0\0\0\0' + encoded)[0],
                         (3, struct.pack('!III', 0x4D320001, 0, 0)))

    def test_option_parser_stops_at_truncated_tail(self):
        packet = b'\x01\x00\x00\x01' + dhcp6_option(1, b'client') + b'\x00\x02\x00'
        self.assertEqual(dhcp6_options(packet), [(1, b'client')])


if __name__ == '__main__':
    unittest.main()
