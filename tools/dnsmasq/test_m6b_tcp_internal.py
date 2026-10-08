#!/usr/bin/env python3
"""Pure collector controls; no daemon, namespace, socket or Rust execution."""
import copy
import unittest
from unittest.mock import patch

import m6b_tcp_internal as gate


def idle(epoch, elapsed, nominal=-1):
    row = {key: 0 for key in set(gate.DRAIN_FIELDS + gate.BALANCE_FIELDS)}
    row.update(diagnostic_only=True, product_qualification=False, extra_trace_fd=1,
               missing_hooks=0, balance_errors=0, alloc_failed=0,
               elapsed_ns=elapsed, drain_epoch=epoch, nominal_drain_second=nominal,
               actual_drain_ns=nominal * 1_000_000_000 if nominal >= 0 else -1,
               full_drained=True, content_versions=1, index_versions=64,
               registry_len=65, registry_capacity=112, live_objects=100,
               live_requested_including_diagnostic=2000, observer_registry_requested=100)
    return row


def active(epoch, elapsed):
    row = idle(epoch, elapsed)
    row.update(full_drained=False, clients=20, G=20, dns_work=20, views=20,
               private_content=20, content_versions=21, old_pinned_content=0)
    return row


def complete():
    rows = [active(0, 1_000_000_000), idle(1, 2_000_000_000)]
    warm = {'label': 'warm', 'active_trace_index': 0, 'active': copy.deepcopy(rows[0]),
            'drain_trace_index': 1, 'drained': copy.deepcopy(rows[1])}
    markers = {'profile': 'reconnect', 'capacity': 1, 'clients': 20,
               'prefill_names': [f'r{n:06}.internal.test' for n in range(32)],
               'warm_batch': warm, 'baseline': {'trace_index': 1, 'row': copy.deepcopy(rows[1])},
               'batches': []}
    for number in range(10):
        ai = len(rows)
        rows.append(active(number + 1, (ai + 1) * 1_000_000_000))
        di = len(rows)
        rows.append(idle(number + 2, (di + 1) * 1_000_000_000, 0 if number == 9 else -1))
        markers['batches'].append({'label': f'b{number:02}', 'active_trace_index': ai,
                                  'active': copy.deepcopy(rows[ai]), 'drain_trace_index': di,
                                  'drained': copy.deepcopy(rows[di])})
    origin = rows[-1]['elapsed_ns']
    for second in [1, 5, 15, 60]:
        rows.append(idle(11, origin + second * 1_000_000_000, second))
    markers['final'] = {'trace_index': len(rows) - 1, 'row': copy.deepcopy(rows[-1])}
    return rows, markers


class SingleBlockOwners(unittest.TestCase):
    def test_one_block_has_twenty_private_roots_and_no_old_owner_after_all_children_write(self):
        rows, markers = complete()
        self.assertTrue(gate.active_owner_contract(rows[0], 1))
        self.assertEqual(len(gate.validate(rows, markers)), 10)
        with patch.object(gate, 'trace_rows', return_value=rows[:1]):
            index, observed = gate.active_trace(None, 0, 1)
        self.assertEqual(index, 0)
        self.assertEqual(observed, rows[0])

    def test_single_block_contract_rejects_lost_private_owner_and_extra_live_root(self):
        for key, value in [('private_content', 19), ('content_versions', 20),
                           ('content_versions', 22), ('old_pinned_content', 1), ('views', 19)]:
            rows, markers = complete()
            last = markers['batches'][-1]
            target = rows[last['active_trace_index']]
            target[key] = value
            last['active'] = copy.deepcopy(target)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                gate.validate(rows, markers)

    def test_warm_batch_requires_the_same_actual_owner_contract(self):
        rows, markers = complete()
        rows[0]['private_content'] = 19
        markers['warm_batch']['active'] = copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)

    def test_all_drained_owner_root_requested_and_object_balances_stay_strict(self):
        keys = ['clients', 'G', 'dns_work', 'views', 'tcp_pending', 'tcp_accept_pending',
                'udp_pending', 'typed_transfer_inflight', 'old_pinned_content', 'old_pinned_index',
                'private_content', 'private_index', 'content_versions', 'index_versions',
                'live_requested_including_diagnostic', 'live_objects', 'registry_capacity']
        for key in keys:
            rows, markers = complete()
            last = markers['batches'][-1]
            target = rows[last['drain_trace_index']]
            target[key] += 1
            last['drained'] = copy.deepcopy(target)
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate(rows, markers)

    def test_cannot_drop_a_batch_or_shorten_final_sixty_second_observation(self):
        rows, markers = complete()
        markers['batches'].pop()
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)
        rows, markers = complete()
        rows[-1]['actual_drain_ns'] = 59_000_000_000
        markers['final']['row'] = copy.deepcopy(rows[-1])
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)

    def test_the_actual_collector_negative_controls_reject_all_twelve_mutations(self):
        rows, markers = complete()
        controls = gate.rejection_controls(rows, markers)
        self.assertEqual(len(controls), 12)
        self.assertTrue(all(row['rejected'] for row in controls))
        self.assertEqual([row['control'] for row in controls[-2:]],
                         ['missing-private-owner', 'extra-content-root'])

    def test_empty_and_multiblock_contracts_are_not_weakened_by_capacity_one(self):
        row = active(0, 1)
        self.assertFalse(gate.active_owner_contract(row, 0))
        row.update(content_versions=0, private_content=0, old_pinned_content=0)
        self.assertTrue(gate.active_owner_contract(row, 0))
        self.assertFalse(gate.active_owner_contract(row, 150))
        row.update(content_versions=23, private_content=20, old_pinned_content=1)
        self.assertTrue(gate.active_owner_contract(row, 150))


if __name__ == '__main__':
    unittest.main()
