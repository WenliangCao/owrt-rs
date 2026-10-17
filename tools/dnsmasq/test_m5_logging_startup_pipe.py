import unittest

import m5_logging as logging


class StartupPipeTargetTests(unittest.TestCase):
    def syscall(self, selector, number, args=(0,) * 6, result=0, root_path=False):
        selected = selector.enter(number, args, root_path)
        pipe_return = selector.exit(result)
        return selected, pipe_return

    def test_both_daemons_ignore_signal_pipes_before_the_daemonization_boundary(self):
        for initial_pipe_count in [0, 1, 2, 4]:
            with self.subTest(initial_pipe_count=initial_pipe_count):
                selector = logging.StartupPipeSelector()
                for index in range(initial_pipe_count):
                    self.assertEqual(self.syscall(selector, 59, (100 + index, 0, 0, 0, 0, 0)), (False, False))
                self.assertEqual(self.syscall(selector, 49, root_path=True), (False, False))
                self.assertEqual(self.syscall(selector, 59, (200, 0x80000, 0, 0, 0, 0)), (True, True))
                selector.bind_fds(8, 9)
                self.assertEqual(selector.writer, 9)
                self.assertEqual(selector.pointer, 200)
                self.assertEqual(selector.events[-1], {'kind': 'startup-pipe-fds', 'reader': 8, 'writer': 9})

    def test_other_or_failed_chdir_does_not_select_a_pipe(self):
        for root_path, result in [(False, 0), (True, -2), (True, -13)]:
            selector = logging.StartupPipeSelector()
            self.syscall(selector, 49, root_path=root_path, result=result)
            self.assertEqual(self.syscall(selector, 59), (False, False))
            self.assertIsNone(selector.writer)

    def test_first_fork_closes_the_boundary_even_if_no_pipe_was_seen(self):
        selector = logging.StartupPipeSelector()
        self.syscall(selector, 49, root_path=True)
        self.syscall(selector, 220)
        self.assertEqual(self.syscall(selector, 59), (False, False))

    def test_only_selected_successful_pipe_produces_descriptors(self):
        selector = logging.StartupPipeSelector()
        self.syscall(selector, 49, root_path=True)
        self.assertEqual(self.syscall(selector, 59, (200, 0, 0, 0, 0, 0), result=-24), (True, False))
        self.assertIsNone(selector.writer)
        self.assertEqual(self.syscall(selector, 59, (300, 0, 0, 0, 0, 0)), (False, False))

    def test_writer_survives_two_forks_but_later_helper_pipes_are_not_selected(self):
        selector = logging.StartupPipeSelector()
        self.syscall(selector, 49, root_path=True)
        self.syscall(selector, 59, (200, 0, 0, 0, 0, 0))
        selector.bind_fds(8, 9)
        self.syscall(selector, 220)
        self.syscall(selector, 220)
        self.assertEqual(self.syscall(selector, 59, (300, 0, 0, 0, 0, 0)), (False, False))
        self.assertEqual(selector.writer, 9)

    def test_keepcaps_fault_ignores_auxv_get_and_disable(self):
        # Actual failed-run PR_GET_AUXV, plus the other keepcaps operation/value.
        for args in [(0x41555856, 281474688573008, 512, 0, 0, 1685382482),
                     (7, 0, 0, 0, 0, 0), (8, 0, 0, 0, 0, 0)]:
            with self.subTest(args=args):
                self.assertFalse(logging.keepcaps_enable(args))

    def test_keepcaps_fault_selects_enable_without_constraining_tail_registers(self):
        for tail in [(0, 0, 0, 4294967288), (1, 2, 3, 0xffffffffffffffff)]:
            self.assertTrue(logging.keepcaps_enable((8, 1, *tail)))
        case = next(row for row in logging.cases() if row['id'] == 'credential-fault-keepcaps')
        self.assertEqual((case['fault_number'], case['fault_errno'], case['exit']), (167, 1, 5))

    def test_fault_expectations_remain_exact(self):
        cases = {row['id']: row for row in logging.cases()}
        for name in ['startup-fault-error-pipe', 'startup-fault-error-pipe-flags']:
            self.assertEqual(cases[name]['exit'], 5)
        self.assertEqual(cases['startup-fault-error-pipe']['fault_errno'], 24)
        self.assertEqual(cases['startup-fault-error-pipe-flags']['fault_errno'], 5)
        self.assertEqual(cases['startup-error-frame-interrupt']['exit'], 3)
        self.assertEqual(cases['startup-error-frame-interrupt']['fault_errno'], 4)
        self.assertEqual(cases['startup-error-frame-interrupt']['fault_follow_depth'], 2)


if __name__ == '__main__':
    unittest.main()
