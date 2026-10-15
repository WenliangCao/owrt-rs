import unittest

from loop_hit_syscalls import aggregate, arguments, parameter_counts, parse


class TraceTests(unittest.TestCase):
    def test_fork_resume_boundary_and_inflight_are_not_double_counted(self):
        rows = [
            '10 1.000000 clone(child_stack=NULL, flags=SIGCHLD) = 11\n',
            '11 1.000010 read(5<TCP:[127.0.0.1:15353->127.0.0.1:42]>,  <unfinished ...>\n',
            '10 1.000020 ppoll([{fd=3, events=POLLIN}], 1, NULL, NULL, 8 <unfinished ...>\n',
            '11 1.000030 <... read resumed>""..., 2) = 2\n',
            '11 1.000040 write(5<TCP:[127.0.0.1:15353->127.0.0.1:42]>, ""..., 42) = 42\n',
            '11 1.000050 exit_group(0) = ?\n',
            '11 1.000060 +++ exited with 0 +++\n',
            '10 1.000070 <... ppoll resumed>) = -1 EINTR (Interrupted system call)\n',
            '10 1.000080 ppoll([{fd=3, events=POLLIN}], 1, NULL, NULL, 8 <detached ...>\n',
        ]
        parsed = parse(rows, 10)
        self.assertEqual(parsed['parents'], {11: 10})
        self.assertEqual(parsed['incomplete_entries'], {10: 'ppoll'})
        self.assertEqual(parsed['unparsed_lines'], [])
        tree = aggregate(parsed['calls'], [10, 11], 5)
        self.assertEqual((tree['ppoll']['entered'], tree['ppoll']['completed']), (2, 1))
        self.assertEqual(tree['read']['entered'], 1)
        self.assertEqual(tree['read']['parameters']['requested_bytes=2'], 1)
        self.assertEqual(tree['read']['entered_per_completed_client_query'], .2)
        self.assertEqual(tree['ppoll']['errors']['EINTR'], 1)

    def test_ancillary_flags_and_nested_vectors(self):
        body = ('recvmsg(6<UDP:[127.0.0.1:15353]>, {msg_name={sa_family=AF_INET}, '
                'msg_iov=[{iov_base=""..., iov_len=65535}], '
                'msg_control=[{cmsg_type=IP_PKTINFO, cmsg_data={ipi_ifindex=1}}], '
                'msg_controllen=32, msg_flags=0}, MSG_DONTWAIT) = -1 EAGAIN (Resource temporarily unavailable)')
        self.assertEqual(len(arguments(body)), 3)
        params = parameter_counts('recvmsg', body)
        self.assertIn('flags=MSG_DONTWAIT', params)
        self.assertIn('cmsg_type=IP_PKTINFO', params)
        self.assertIn('iov_len=65535', params)

    def test_unknown_pid_is_rejected_and_preexisting_call_is_marked(self):
        with self.assertRaises(AssertionError):
            parse(['11 1.000000 getpid() = 11\n'], 10)
        parsed = parse(['10 1.000000 <... ppoll resumed>) = 0 (Timeout)\n'], 10)
        self.assertEqual(parsed['calls'][10]['ppoll']['entered'], 0)
        self.assertEqual(parsed['calls'][10]['ppoll']['boundary_completions'], 1)


if __name__ == '__main__':
    unittest.main()
