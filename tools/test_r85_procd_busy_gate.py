#!/usr/bin/env python3
"""Final-line counts must not conceal duplicates or reset pid tags."""
import unittest

from r85_procd_busy_gate import check_final_logs


class FinalLogs(unittest.TestCase):
    def setUp(self):
        self.before = {"burst": {"instances": {f"i{i}": {"pid": 100 + i} for i in range(32)}}}
        self.lines = [f"daemon.info sh[{100 + i}]: r85-tail-{i}" for i in range(32)]

    def test_arrival_order_is_not_part_of_the_contract(self):
        check_final_logs(self.before, "\n".join(reversed(self.lines)))

    def test_count_of_32_does_not_hide_a_lost_line(self):
        self.lines[-1] = self.lines[0]
        with self.assertRaisesRegex(AssertionError, "final log line"):
            check_final_logs(self.before, "\n".join(self.lines))

    def test_pid_must_be_the_exited_child_not_zero_or_a_replacement(self):
        for pid in (0, 9999):
            self.lines[-1] = f"daemon.info sh[{pid}]: r85-tail-31"
            with self.assertRaisesRegex(AssertionError, "final log line"):
                check_final_logs(self.before, "\n".join(self.lines))


if __name__ == "__main__":
    unittest.main()
