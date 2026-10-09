#!/usr/bin/env python3
"""Offline membership selection/receipt negatives; no ptrace or daemon runs."""
import copy
import errno
import struct
import unittest

import m6b_netlink_membership_fault as fault


class MembershipReceipts(unittest.TestCase):
    def valid(self):
        return {'events': [
            {'syscall': 200, 'fd': 19, 'family': 16, 'groups': 0x550, 'injected': True,
             'actual_result': 19, 'result': -errno.EPERM,
             'entry_syscall': 200, 'skipped_syscall': -1, 'exit_syscall': -1,
             'entry_stop': 1, 'exit_stop': 2, 'entry_x0': 19, 'syscall_regset_bytes': 4},
            {'syscall': 200, 'fd': 19, 'family': 16, 'groups': 0, 'injected': False,
             'actual_result': 0, 'result': 0},
            {'syscall': 204, 'fd': 19, 'injected': False, 'actual_result': 0, 'result': 0,
             'address': {'family': 16, 'port': 2001, 'groups': 0}}]}

    def test_mask_selects_actual_route_address_membership_not_other_bind(self):
        parsed = fault.membership_address(struct.pack('=HHII', 16, 0, 0, 0x550))
        self.assertEqual(parsed['groups'], 0x550)
        self.assertIsNone(fault.membership_address(struct.pack('=HHII', 2, 0, 0, 0x550)))
        self.assertIsNone(fault.membership_address(bytes(11)))
        # Unicast getifaddrs bind is parsed but cannot match the membership mask.
        self.assertEqual(fault.membership_address(struct.pack('=HHII', 16, 0, 0, 0))['groups'], 0)

    def test_eperm_requires_real_fallback_and_kernel_socket_name(self):
        self.assertTrue(fault.check_trace(self.valid(), 'membership-eperm'))
        for label in ('no-fallback', 'wrong-fd', 'wrong-groups', 'not-skipped', 'wrong-errno', 'not-group-zero', 'no-auto-port', 'wrong-order', 'fake-name-return'):
            report = self.valid()
            if label == 'no-fallback': report['events'].pop(1)
            elif label == 'wrong-fd': report['events'][1]['fd'] = 20
            elif label == 'wrong-groups': report['events'][0]['groups'] = 0x440
            elif label == 'not-skipped': report['events'][0]['actual_result'] = 0
            elif label == 'wrong-errno': report['events'][0]['result'] = -errno.EINVAL
            elif label == 'not-group-zero': report['events'][2]['address']['groups'] = 0x550
            elif label == 'no-auto-port': report['events'][2]['address']['port'] = 0
            elif label == 'wrong-order': report['events'][0], report['events'][1] = report['events'][1], report['events'][0]
            else: report['events'][2]['actual_result'] = -errno.EIO
            with self.subTest(label=label), self.assertRaises(ValueError):
                fault.check_trace(report, 'membership-eperm')

    def test_health_cannot_hide_a_later_crash_or_forced_cleanup(self):
        self.assertTrue(fault.check_cleanup('membership-eperm', {'returncode': 0, 'forced': False}))
        self.assertTrue(fault.check_cleanup('membership-einval', {'returncode': 5, 'forced': False}))
        for case, result in [('membership-eperm', 5), ('membership-eperm', -11), ('membership-einval', 0)]:
            with self.subTest(case=case, result=result), self.assertRaises(ValueError):
                fault.check_cleanup(case, {'returncode': result, 'forced': False})
        with self.assertRaises(ValueError):
            fault.check_cleanup('membership-eperm', {'returncode': 0, 'forced': True})

    def test_skip_requires_actual_entry_write_readback_and_exit_registers(self):
        for field, value in [('entry_syscall', 201), ('skipped_syscall', 200),
                             ('exit_syscall', 200), ('entry_stop', 2), ('exit_stop', 1),
                             ('syscall_regset_bytes', 8), ('entry_x0', 20),
                             ('family', 2), ('fd', 0),
                             ('actual_result', -errno.ENOSYS), ('actual_result', 20),
                             ('actual_result', -errno.EPERM)]:
            report = self.valid(); report['events'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                fault.check_trace(report, 'membership-eperm')
        report = self.valid(); report['events'].append(copy.deepcopy(report['events'][0]))
        with self.assertRaises(ValueError): fault.check_trace(report, 'membership-eperm')
        for field in ['entry_syscall', 'skipped_syscall', 'exit_syscall', 'entry_x0']:
            report = self.valid(); del report['events'][0][field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                fault.check_trace(report, 'membership-eperm')

    def test_einval_must_not_fall_back_or_claim_eperm_result(self):
        report = self.valid(); report['events'] = report['events'][:1]
        report['events'][0]['result'] = -errno.EINVAL
        self.assertTrue(fault.check_trace(report, 'membership-einval'))
        report['events'].append(self.valid()['events'][1])
        with self.assertRaises(ValueError): fault.check_trace(report, 'membership-einval')
        with self.assertRaises(ValueError): fault.check_trace({'events': []}, 'membership-einval')


if __name__ == '__main__': unittest.main()
