import unittest

from r92_recovery_probe import netlink_socket_sample, owned_link_socket


def row(port=16, recv=9216, buffer=262140, drops=7448):
    return (f"UNCONN {recv} 0 0:{port} * sk=0 cb=0 groups=0x00000001\t"
            f" skmem:(r{recv},rb{buffer},t0,tb212992,f0,w0,o0,bl0,d{drops})")


class SocketSample(unittest.TestCase):
    def test_live_queue_changes_do_not_create_a_second_socket(self):
        sample = netlink_socket_sample(row() + "\n" + row(recv=6912), 16)
        self.assertEqual((sample['recv_min'], sample['recv_max']), (6912, 9216))
        self.assertEqual(sample['buffer_min'], 262140)
        self.assertEqual(sample['drops_max'], 7448)
        self.assertEqual(len(sample['readings']), 2)

    def test_ambiguity_and_incomplete_records_fail(self):
        for text in (row() + "\n" + row(port=17), row().replace('rb262140,', ''),
                     row().replace(',d7448', ''), ''):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                netlink_socket_sample(text, 16)

    def test_buffer_range_cannot_prove_growth_from_just_one_reading(self):
        sample = netlink_socket_sample(row(buffer=131070) + "\n" + row(), 16)
        self.assertEqual((sample['buffer_min'], sample['buffer_max']), (131070, 262140))
        self.assertFalse(sample['buffer_min'] > 131070)
        self.assertEqual(netlink_socket_sample(row(drops=0), 16)['drops_min'], 0)

    def test_proc_socket_must_belong_to_the_subject(self):
        table = ('sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n'
                 '0000 0 16 00000001 6912 0 0 2 7448 700\n'
                 '0000 0 17 00000000 0 0 0 2 0 701\n')
        self.assertEqual(owned_link_socket(table, {700, 701}), (16, 700))
        with self.assertRaises(AssertionError):
            owned_link_socket(table, {701})
        with self.assertRaises(AssertionError):
            owned_link_socket(table + '0000 0 18 00000001 0 0 0 2 0 702\n', {700, 702})


if __name__ == '__main__':
    unittest.main()
