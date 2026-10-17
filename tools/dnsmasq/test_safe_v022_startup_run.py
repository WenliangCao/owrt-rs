"""Synthetic startup evidence validation only; no process launch or network."""
import json
from pathlib import Path
import tempfile
import unittest

import safe_v022_startup_run as startup


ELF = 'a' * 64
CLOEXEC = 0o2000000
OPATH = 0o10000000


def write_fds(path, descriptors):
    path.write_text(''.join(f'fd={fd} target={target}\npos:\t0\nflags:\t{flags:08o}\n'
                            for fd, target, flags in descriptors))


def fixture(folder, mode='helper', role='candidate'):
    for name in ('elf.sha256', 'elf-after.sha256'):
        (folder / name).write_text(ELF + ' artifact\n')
    (folder / 'COMPLETE').write_text('complete\n')
    (folder / 'probe.exit').write_text('0\n')
    (folder / 'startup.stderr').write_bytes(b'')
    rows = []
    for index in range(10):
        owner = [(0, '/dev/null', 0), (1, '/dev/null', 1), (2, '/dev/null', 1),
                 (3, 'socket:[200]', CLOEXEC | 2)]
        helper = [(0, '/dev/null', 0), (1, '/dev/null', 1), (2, '/dev/null', 1),
                  (3, 'pipe:[300]', CLOEXEC), (4, 'pipe:[301]', CLOEXEC | 1)]
        trial = folder / 'trials' / f'run-{index:02d}'; trial.mkdir(parents=True)
        write_fds(trial / 'owner-fds.raw', owner)
        resources = [dict(uid=453, gid=453, cap_eff=0x3400, fd_count=len(owner))]
        if mode == 'helper':
            write_fds(trial / 'helper-fds.raw', helper)
            (trial / 'rootfs/fixture').mkdir(parents=True)
            (trial / 'rootfs/fixture/callback').write_bytes(b'old 02:00:00:de:00:01 127.0.0.10 startup\n' * 2)
            resources.append(dict(uid=0, gid=0, fd_count=len(helper)))
        start = 1_000_000_000 + index * 500_000_000
        rows.append(dict(kind='startup', index=index, mode=mode,
            proc_mode='absent' if mode == 'helper' else 'present',
            nofile_soft=1024, nofile_hard=4096, ok=True, cpu_complete=True,
            all_children_reaped=True, owner_reaped=True, owner_wait_status=0,
            forced_cleanup=False, bad_exits=0, period_overrun_ns=0,
            start_ns=start, ready_ns=start + 2_000_000, latency_ns=2_000_000,
            snapshot_ns=start + 3_000_000, finished_ns=start + 4_000_000,
            setup_user_usec=10 + index, setup_system_usec=20 + index,
            children_user_usec=110 + index, children_system_usec=220 + index,
            timed_tree_user_usec=100, timed_tree_system_usec=200,
            callback_valid=True if mode == 'helper' else None, callback_count=2 if mode == 'helper' else 0,
            callback_exact_once=False if mode == 'helper' else None, resources=resources))
    summary = dict(kind='summary', mode=mode, ok=True, completed=10, cpu_complete=True)
    for key in ('children_user_usec', 'children_system_usec', 'timed_tree_user_usec', 'timed_tree_system_usec'):
        summary[key] = sum(row[key] for row in rows)
    rows.append(summary)
    save_rows(folder, rows)
    return rows


def save_rows(folder, rows):
    (folder / 'startup.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))


class StartupValidationTests(unittest.TestCase):
    def test_sub_millisecond_cpu_cost_requests_review_independently_of_ready_floor(self):
        baseline = [2000, 2010, 1990, 2020, 2005, 2015, 2000, 2025, 2010, 2000]
        def rows(values, setup=20):
            return [dict(children_user_usec=value + setup, children_system_usec=0,
                         timed_tree_user_usec=value, timed_tree_system_usec=0) for value in values]
        clear = startup.cpu_comparison(rows(baseline), rows([value + 400 for value in baseline]), 'timed')
        self.assertTrue(clear['review_required'])
        self.assertEqual(clear['median_ordinal_difference_us'], 400)
        self.assertEqual(clear['ten_start_total_us']['candidate'] - clear['ten_start_total_us']['k'], 4000)
        for deltas in ([3] * 10, [20] * 10, [400] * 8 + [-1, -1]):
            measured = startup.cpu_comparison(rows(baseline), rows([a + b for a, b in zip(baseline, deltas)]), 'timed')
            self.assertFalse(measured['review_required'])
        self.assertTrue(startup.cpu_comparison(rows(baseline), rows(baseline, setup=420), 'whole')['review_required'])
        self.assertFalse(startup.cpu_comparison(rows(baseline), rows(baseline, setup=420), 'timed')['review_required'])

    def test_callback_contents_and_final_count_are_not_normalized_away(self):
        for defect in ('raw-count', 'reported-count', 'wrong-callback'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); rows = fixture(folder)
                path = folder / 'trials/run-00/rootfs/fixture/callback'
                if defect == 'raw-count':
                    path.write_bytes(path.read_bytes() * 2)
                elif defect == 'reported-count':
                    rows[0]['callback_count'] = 3; save_rows(folder, rows)
                else:
                    path.write_bytes(path.read_bytes().replace(b'old ', b'new '))
                with self.assertRaisesRegex(ValueError, 'raw callback'):
                    startup.validate(folder, 'helper', 'candidate', ELF)

    def test_ten_starts_and_all_fd_records_pass_for_four_cells(self):
        for mode in ('helper', 'resolver'):
            for role in ('k', 'candidate'):
                with self.subTest(mode=mode, role=role), tempfile.TemporaryDirectory() as temporary:
                    folder = Path(temporary); fixture(folder, mode, role)
                    result = startup.validate(folder, mode, role, ELF)
                    self.assertEqual(len(result['starts']), 10)
                    self.assertEqual(result['summary']['timed_tree_user_usec'], 1000)
                    self.assertEqual(len(result['fd_inventory'][0]['owner']), 4)
                    self.assertFalse(any(fd['opath'] for fd in result['fd_inventory'][0]['owner']))
                    if mode == 'helper':
                        self.assertEqual(len(result['fd_inventory'][0]['helper']), 5)

    def test_any_owner_opath_is_rejected_for_both_fork_roles(self):
        for mode in ('helper', 'resolver'):
            for role in ('k', 'candidate'):
                for flags in (OPATH, OPATH | CLOEXEC):
                    with self.subTest(mode=mode, role=role, flags=flags), tempfile.TemporaryDirectory() as temporary:
                        folder = Path(temporary); rows = fixture(folder, mode, role)
                        path = folder / 'trials/run-00/owner-fds.raw'
                        owner = [(row['fd'], row['target'], row['flags']) for row in startup.fd_inventory(path)]
                        owner.append((4, '/usr/sbin/dnsmasq', flags))
                        write_fds(path, owner)
                        rows[0]['resources'][0]['fd_count'] += 1; save_rows(folder, rows)
                        with self.assertRaisesRegex(ValueError, 'owner retained image FD'):
                            startup.validate(folder, mode, role, ELF)

    def test_helper_extra_fds_wrong_direction_and_missing_cloexec_are_rejected(self):
        for role in ('k', 'candidate'):
            for defect in ('socket', 'duplicated-pipes', 'direction', 'cloexec'):
                with self.subTest(role=role, defect=defect), tempfile.TemporaryDirectory() as temporary:
                    folder = Path(temporary); rows = fixture(folder, role=role)
                    path = folder / 'trials/run-00/helper-fds.raw'
                    descriptors = [(row['fd'], row['target'], row['flags']) for row in startup.fd_inventory(path)]
                    if defect == 'socket':
                        descriptors.append((7, 'socket:[999]', CLOEXEC | 2))
                    elif defect == 'duplicated-pipes':
                        descriptors += [(5, 'pipe:[300]', CLOEXEC), (6, 'pipe:[301]', CLOEXEC | 1)]
                    elif defect == 'direction':
                        descriptors[4] = (4, 'pipe:[301]', CLOEXEC)
                    else:
                        descriptors[3] = (3, 'pipe:[300]', 0)
                    rows[0]['resources'][1]['fd_count'] = len(descriptors)
                    save_rows(folder, rows)
                    write_fds(path, descriptors)
                    with self.assertRaisesRegex(ValueError, 'helper inherited|pipe directions|missing CLOEXEC'):
                        startup.validate(folder, 'helper', role, ELF)

    def test_microsecond_terminal_sum_and_setup_subtraction_are_rejected(self):
        for defect in ('children_user_usec', 'children_system_usec', 'timed_tree_user_usec', 'timed_tree_system_usec', 'setup'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); rows = fixture(folder)
                if defect == 'setup':
                    rows[0]['setup_user_usec'] += 1
                else:
                    rows[-1][defect] += 1
                save_rows(folder, rows)
                with self.assertRaisesRegex(ValueError, 'CPU sum differs|CPU accounting differs'):
                    startup.validate(folder, 'helper', 'candidate', ELF)

    def test_unreaped_child_forced_cleanup_and_wrong_proc_boundary_are_rejected(self):
        for key, value in [('all_children_reaped', False), ('owner_reaped', False),
                           ('owner_wait_status', 15), ('forced_cleanup', True),
                           ('proc_mode', 'present')]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary); rows = fixture(folder); rows[0][key] = value
                save_rows(folder, rows)
                with self.assertRaisesRegex(ValueError, 'startup/reaping|startup boundary'):
                    startup.validate(folder, 'helper', 'candidate', ELF)

    def test_labels_are_four_unique_blocks_with_frozen_order(self):
        self.assertEqual(startup.labels('v022'), [
            'v022-startup-helper-k', 'v022-startup-helper-candidate',
            'v022-startup-resolver-candidate', 'v022-startup-resolver-k'])


if __name__ == '__main__':
    unittest.main()
