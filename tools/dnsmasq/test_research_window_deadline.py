"""Reproduce the declared 95-second window exceeding the old watchdog."""
import unittest

from perf_opt_device_run import case_deadline_seconds


class WindowDeadlineTest(unittest.TestCase):
    def test_long_window_cannot_finish_with_old_deadline(self):
        scene = ('hit', 'udp', 'hit', 200, 5, 95, 150)
        earliest_finish = scene[4] + scene[5] + 1  # Mandatory drain; excludes setup.
        self.assertGreater(earliest_finish, 100)
        self.assertEqual(case_deadline_seconds(scene), 140)
        self.assertLess(earliest_finish, case_deadline_seconds(scene))

    def test_original_windows_keep_original_deadline(self):
        for mode in ('udp', 'tcp', 'dhcp'):
            for measured in (20, 45):
                self.assertEqual(case_deadline_seconds(('case', mode, 'hit', 200, 5, measured, 150)), 100)
        for mode in ('life-startup', 'life-config', 'life-hup'):
            self.assertEqual(case_deadline_seconds(('case', mode, 7, 6, 20, 1000, 150)), 100)


if __name__ == '__main__':
    unittest.main()
