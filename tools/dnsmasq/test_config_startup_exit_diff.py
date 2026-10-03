#!/usr/bin/env python3
"""Offline checks for exit-status comparison and subprocess cleanup."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

import config_startup_exit_diff as startup


class StartupExitTests(unittest.TestCase):
    def rows(self):
        return [{'case': name, 'side': side, 'exit': code, 'timed_out': False}
                for name, _, _, code in startup.CASES for side in ('c', 'rust')]

    def test_negative_controls_detect_wrong_status_and_missing_execution(self):
        rows = self.rows()
        self.assertEqual(startup.compare(rows), [])
        self.assertTrue(all(startup.negative_controls(rows).values()))

    def test_equal_wrong_status_does_not_validate_broken_permission_fixture(self):
        rows = self.rows()
        for row in rows:
            if row['case'] == 'permission-denied':
                row['exit'] = 0
        self.assertTrue(any('C fixture' in failure for failure in startup.compare(rows)))

    def test_timeout_kills_and_reaps_process_and_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / 'timeout'
            command = [sys.executable, '-u', '-c',
                       'import time; print("before timeout", flush=True); time.sleep(30)']
            result = startup.run_command(command, None, prefix, timeout=0.5)
            self.assertTrue(result['timed_out'])
            self.assertLess(result['exit'], 0)
            self.assertEqual(prefix.with_suffix('.stdout').read_bytes(), b'before timeout\n')
            with self.assertRaises(ProcessLookupError):
                os.kill(result['pid'], 0)


if __name__ == '__main__':
    unittest.main()
