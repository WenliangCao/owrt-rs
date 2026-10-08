#!/usr/bin/env python3
"""Pure collector checks for exclusive roots that retain parent history."""
import copy
import unittest
from unittest.mock import patch

import m6b_tcp_internal as internal
import m6b_tcp_interleaved as gate


def idle(epoch, elapsed, nominal=-1):
    row = {key: 0 for key in set(internal.DRAIN_FIELDS + internal.BALANCE_FIELDS)}
    row.update(diagnostic_only=True, product_qualification=False, extra_trace_fd=1,
               missing_hooks=0, balance_errors=0, alloc_failed=0,
               elapsed_ns=elapsed, drain_epoch=epoch, nominal_drain_second=nominal,
               actual_drain_ns=max(0, nominal) * 1_000_000_000,
               full_drained=True, content_versions=3, index_versions=64,
               live_objects=100, live_requested_including_diagnostic=2000,
               observer_registry_requested=100)
    return row


def complete(mode):
    rows = [idle(0, 1_000_000_000)]
    batches = []
    held_count, count = (2 if mode == 'staggered-conflicts' else 1), gate.CLIENTS[mode]
    for number in range(11):
        parent = {'trace_index': len(rows) - 1, 'row': copy.deepcopy(rows[-1])}
        points = {}
        for phase, clients, pending in [('held', held_count, 1), ('active', count, 0)]:
            wanted = dict(clients=clients, G=clients, dns_work=clients, views=clients,
                          tcp_pending=pending, udp_pending=0)
            row = idle(number, (len(rows) + 1) * 1_000_000_000)
            exclusive = gate.EXCLUSIVE_CONTENT[mode]
            if mode == 'lease-held-import' and number == 0 and phase == 'held':
                exclusive = 0
            row.update(wanted, full_drained=False, old_pinned_content=exclusive,
                       content_versions=3 + exclusive)
            if mode == 'lease-held-import' and number == 0 and phase == 'active':
                row.update(old_pinned_content=0, private_content=1)
            points[phase] = {'trace_index': len(rows), 'row': copy.deepcopy(row), 'wanted': wanted}
            rows.append(row)
        row = idle(number + 1, (len(rows) + 1) * 1_000_000_000, 0 if number == 10 else -1)
        points['drained'] = {'trace_index': len(rows), 'row': copy.deepcopy(row)}
        rows.append(row)
        batches.append(dict(label='warm' if number == 0 else f'b{number - 1:02}', parent=parent, **points))
    origin = rows[-1]['elapsed_ns']
    for second in [1, 5, 15, 60]:
        rows.append(idle(11, origin + second * 1_000_000_000, second))
    markers = dict(profile=mode, capacity=150, clients=count, warm_batch=batches[0],
                   baseline=copy.deepcopy(batches[0]['drained']), batches=batches[1:],
                   final={'trace_index': len(rows) - 1, 'row': copy.deepcopy(rows[-1])})
    return rows, markers


class ExclusiveContentRoots(unittest.TestCase):
    def test_parent_history_does_not_hide_actual_exclusive_roots(self):
        for mode in gate.CASES:
            with self.subTest(mode=mode):
                rows, markers = complete(mode)
                self.assertEqual(len(gate.validate_trace(rows, markers)), 10)
                self.assertEqual(markers['batches'][0]['active']['row']['private_content'], 0)

    def test_history_split_does_not_change_current_ownership(self):
        rows, markers = complete('staggered-conflicts')
        parent, active = markers['batches'][0]['parent']['row'], markers['batches'][0]['active']['row']
        active.update(old_pinned_content=1, private_content=1)
        gate.active_content_contract('staggered-conflicts', active, parent)

    def test_lease_warm_clone_and_later_sole_owner_keep_one_exclusive_root(self):
        rows, markers = complete('lease-held-import')
        batch = markers['batches'][0]
        for old, private in [(0, 1), (1, 0)]:
            row = copy.deepcopy(batch['active']['row'])
            row.update(old_pinned_content=old, private_content=private)
            gate.active_content_contract('lease-held-import', row, batch['parent']['row'])

    def test_reload_requires_all_three_old_blocks_even_with_two_clients(self):
        rows, markers = complete('reload-held-import')
        batch = markers['batches'][0]
        self.assertEqual(batch['active']['row']['content_versions'], 6)
        row = copy.deepcopy(batch['active']['row'])
        row.update(content_versions=4, old_pinned_content=1)
        with self.assertRaises(ValueError):
            gate.active_content_contract('reload-held-import', row, batch['parent']['row'])

    def test_missing_shared_extra_and_negative_roots_are_rejected(self):
        for mode in gate.CASES:
            rows, markers = complete(mode)
            batch = markers['batches'][0]
            for fault in ['missing', 'shared', 'extra', 'negative']:
                with self.subTest(mode=mode, fault=fault):
                    row = copy.deepcopy(batch['active']['row'])
                    if fault == 'missing':
                        row['old_pinned_content'] -= 1
                    elif fault == 'shared':
                        row['content_versions'] -= 1
                    elif fault == 'extra':
                        row['content_versions'] += 1
                    else:
                        row.update(private_content=-1, old_pinned_content=row['old_pinned_content'] + 1)
                    with self.assertRaises(ValueError):
                        gate.active_content_contract(mode, row, batch['parent']['row'])

    def test_parent_with_a_retained_view_is_rejected(self):
        rows, markers = complete('staggered-conflicts')
        batch = markers['batches'][0]
        batch['parent']['row']['views'] = 1
        with self.assertRaises(ValueError):
            gate.active_content_contract('staggered-conflicts', batch['active']['row'], batch['parent']['row'])

    def test_parent_marker_must_match_original_trace(self):
        for fault in ['row', 'order']:
            rows, markers = complete('staggered-conflicts')
            parent = markers['batches'][0]['parent']
            if fault == 'row':
                parent['row']['content_versions'] += 1
            else:
                parent['trace_index'] = markers['batches'][0]['active']['trace_index']
            with self.assertRaises(ValueError):
                gate.validate_trace(rows, markers)

    def test_original_six_controls_and_strict_balance_remain(self):
        for mode in gate.CASES:
            rows, markers = complete(mode)
            controls = gate.rejection_controls(rows, markers)
            self.assertEqual(len(controls), 6)
            self.assertTrue(all(row['rejected'] for row in controls))

    def test_each_balance_field_and_both_retained_root_labels_are_rejected(self):
        for key in dict.fromkeys([*internal.BALANCE_FIELDS, 'old_pinned_content', 'private_content']):
            rows, markers = complete('reload-held-import')
            point = markers['batches'][-1]['drained']
            rows[point['trace_index']][key] += 1
            point['row'] = copy.deepcopy(rows[point['trace_index']])
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate_trace(rows, markers)


class PhaseWitness(unittest.TestCase):
    def test_previous_held_or_active_row_is_not_selected(self):
        for phase in ['held', 'active']:
            rows, markers = complete('reload-held-import')
            old = copy.deepcopy(markers['batches'][0][phase]['row'])
            old.update(content_versions=3, old_pinned_content=0)
            new = markers['batches'][0][phase]['row']
            with patch.object(gate.internal, 'trace_rows', side_effect=[[old], [old, new]]):
                point = gate.fresh_witness('unused', markers['batches'][0][phase]['wanted'])
            self.assertEqual(point['trace_index'], 1)
            self.assertEqual(point['row']['content_versions'], 6)

    def test_missing_new_phase_row_does_not_reuse_previous_positive(self):
        rows, markers = complete('staggered-conflicts')
        point = markers['batches'][0]['active']
        with patch.object(gate.internal, 'trace_rows', return_value=[point['row']]), \
                patch.object(gate.time, 'monotonic', side_effect=[0, 6]):
            with self.assertRaises(AssertionError):
                gate.fresh_witness('unused', point['wanted'])


if __name__ == '__main__':
    unittest.main()
