#!/usr/bin/env python3
"""Fail-closed/content-comparison checks for the WAN6 oracle harness."""
import copy
import tempfile
import unittest
from pathlib import Path

from netifd_replay import differences, extract


class ComparisonTest(unittest.TestCase):
    def test_kernel_and_ubus_mutations_fail(self):
        original = {'addresses': [{'local': '2001:db8::1', 'flags': ['noprefixroute']}],
                    'routes': [{'dst': 'default', 'gateway': 'fe80::1', 'expires': 900}],
                    'sysctl': {'wan': {'accept_ra': '0'}},
                    'rules': [{'priority': 4200000000, 'action': 'unreachable'}],
                    'wan6': {'updated': ['addresses'], 'valid': 7200}}
        for field, replacement in (
            ('addresses', [{'local': '2001:db8::2', 'flags': ['noprefixroute']}]),
            ('addresses', [{'local': '2001:db8::1', 'flags': []}]),
            ('routes', []),
            ('rules', [{'priority': 4200000000, 'action': 'blackhole'}]),
            ('sysctl', {'wan': {'accept_ra': '1'}}),
            ('wan6', {'updated': [], 'valid': 7200}),
        ):
            with self.subTest(field=field, replacement=replacement):
                changed = copy.deepcopy(original)
                changed[field] = replacement
                self.assertTrue(differences(original, changed))
        self.assertEqual(differences(original, original), [])

    def test_lifetime_tolerance_is_bounded_and_preserves_deprecation(self):
        self.assertEqual(differences({'valid': 7200}, {'valid': 7198}), [])
        self.assertTrue(differences({'valid': 7200}, {'valid': 7197}))
        self.assertTrue(differences({'preferred': 1}, {'preferred': 0}))
        self.assertTrue(differences({'valid': 7200}, {'valid': 'forever'}))

    def test_prefix_assignment_order_is_compared(self):
        a = ['2001:db8::/64', 'fd00::/60']
        self.assertTrue(differences(a, list(reversed(a))))

    def test_empty_capture_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture'
            path.write_text('')
            with self.assertRaises(ValueError):
                extract(path)


if __name__ == '__main__':
    unittest.main()
