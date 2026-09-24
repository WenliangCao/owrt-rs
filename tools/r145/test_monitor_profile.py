"""Regression coverage for the pinned perf control protocol; no perf required."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import monitor_profile as profile


class PerfControlTests(unittest.TestCase):
    def test_two_nul_terminated_acks_are_consumed_separately(self):
        cr, cw = os.pipe()
        ar, aw = os.pipe()
        try:
            os.write(aw, b'ack\n\0ack\n\0')
            for command in ('enable', 'disable'):
                result = profile.control(cw, ar, command)
                self.assertEqual(os.read(cr, 64), command.encode() + b'\n')
                self.assertEqual(result['ack_hex'], '61636b0a00')
                self.assertLessEqual(result['requested_monotonic_ns'], result['ack_monotonic_ns'])
        finally:
            for fd in (cr, cw, ar, aw):
                os.close(fd)

    def test_fragmented_ack(self):
        with patch.object(profile.os, 'write'), \
                patch.object(profile.select, 'select', return_value=([12], [], [])), \
                patch.object(profile.os, 'read', side_effect=[b'a', b'ck\n', b'\0']) as read:
            self.assertEqual(profile.control(11, 12, 'enable')['ack_hex'], '61636b0a00')
            self.assertEqual([call.args[1] for call in read.call_args_list], [5, 4, 1])

    def test_invalid_or_incomplete_ack_is_rejected(self):
        for chunks, message in (([b'no!\n\0'], 'unexpected'), ([b'ack\n', b''], 'closed')):
            with self.subTest(chunks=chunks), patch.object(profile.os, 'write'), \
                    patch.object(profile.select, 'select', return_value=([12], [], [])), \
                    patch.object(profile.os, 'read', side_effect=chunks):
                with self.assertRaisesRegex(RuntimeError, message):
                    profile.control(11, 12, 'enable')

    def test_timeout_is_rejected(self):
        with patch.object(profile.os, 'write'), \
                patch.object(profile.select, 'select', return_value=([], [], [])):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                profile.control(11, 12, 'enable')


if __name__ == '__main__':
    unittest.main()
