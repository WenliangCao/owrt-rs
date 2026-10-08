#!/usr/bin/env python3
"""Pure collector controls; no daemon, namespace, socket or Rust execution."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import m6b_tcp_internal as gate


def warm_receipt(clients):
    states = [{'pid': 123, 'starttime': 42, 'state': state, 'monotonic_ns': n}
              for n, state in enumerate(['S', 'T', 'S'])]
    return {'phase': 'structural-warm-only', 'completed': True, 'resume_attempted': True,
            'closed_clients': clients, 'client_fds': list(range(10, 10 + clients)),
            'identity': {'pid': 123}, 'before': states[0], 'stopped': states[1], 'resumed': states[2]}


def idle(epoch, elapsed, nominal=-1):
    row = {key: 0 for key in set(gate.DRAIN_FIELDS + gate.BALANCE_FIELDS)}
    row.update(diagnostic_only=True, product_qualification=False, extra_trace_fd=1,
               missing_hooks=0, balance_errors=0, alloc_failed=0,
               elapsed_ns=elapsed, drain_epoch=epoch, nominal_drain_second=nominal,
               actual_drain_ns=nominal * 1_000_000_000 if nominal >= 0 else -1,
               full_drained=True, content_versions=1, index_versions=64,
               registry_len=65, registry_capacity=112, ready_fd_bytes=256,
               registry_capacity_semantics=gate.REGISTRY_CAPACITY_SEMANTICS, live_objects=100,
               live_requested_including_diagnostic=2000, observer_registry_requested=100)
    return row


def active(epoch, elapsed):
    row = idle(epoch, elapsed)
    row.update(full_drained=False, clients=20, G=20, dns_work=20, views=20,
               private_content=20, content_versions=21, old_pinned_content=0)
    return row


def complete():
    rows = [active(0, 1_000_000_000), idle(1, 2_000_000_000)]
    warm = {'label': 'warm', 'ready_close': warm_receipt(20), 'active_trace_index': 0, 'active': copy.deepcopy(rows[0]),
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


def complete_limit():
    rows = []
    batches = []
    for number in range(11):
        ai = len(rows)
        for second in [1, 2]:
            row = active(number, (ai + second) * 1_000_000_000)
            row.update(clients=30, G=30, dns_work=30, views=30,
                       old_pinned_content=1, private_content=30, content_versions=32)
            rows.append(row)
        di = len(rows)
        rows.append(idle(number + 1, (di + 1) * 1_000_000_000, 0 if number == 10 else -1))
        batches.append({'label': 'warm' if number == 0 else f'b{number - 1:02}',
                        'active_trace_index': ai, 'active': copy.deepcopy(rows[ai]),
                        'drain_trace_index': di, 'drained': copy.deepcopy(rows[di]),
                        'limit': {'started_monotonic_ns': ai * 1_000_000_000,
                                  'completed_monotonic_ns': ai * 1_000_000_000 + gate.LIMIT_HOLD_NS,
                                  'first_trace_index': ai, 'first': copy.deepcopy(rows[ai]),
                                  'last_trace_index': ai + 1, 'last': copy.deepcopy(rows[ai + 1])}})
    batches[0]['ready_close'] = warm_receipt(29)
    markers = {'profile': 'limit30', 'capacity': 150, 'clients': 30,
               'prefill_names': [f'r{n:06}.internal.test' for n in range(150)],
               'warm_batch': batches[0], 'batches': batches[1:],
               'baseline': {'trace_index': 2, 'row': copy.deepcopy(rows[2])}}
    origin = rows[-1]['elapsed_ns']
    for second in [1, 5, 15, 60]:
        rows.append(idle(11, origin + second * 1_000_000_000, second))
    markers['final'] = {'trace_index': len(rows) - 1, 'row': copy.deepcopy(rows[-1])}
    return rows, markers


def limit_observations(folder):
    (folder / 'config').write_text('cache-size=150\nmax-tcp-connections=30\n')
    row = {'config': 'max-tcp-connections=30', 'observations': []}
    for prefix in ['warm', *[f'b{number:02}' for number in range(10)]]:
        wire = b'original-request-' + prefix.encode()
        (folder / (prefix + '-over-limit.query')).write_bytes(wire)
        (folder / (prefix + '-over-limit-recovered.query')).write_bytes(wire)
        row['observations'].append({'label': prefix + '-over-limit-held', 'no_reply': True,
                                    'metrics': {'tcp_connections': 30}})
        for suffix in ['-parent-at-limit', '-existing-at-limit', '-over-limit-recovered']:
            row['observations'].append({'label': prefix + suffix, 'query': {}, 'reply': {}})
    return row


class StructuralWarm(unittest.TestCase):
    def test_missing_pause_generation_or_ready_high_water_is_rejected(self):
        for fault in ['missing', 'generation', 'resume', 'ready']:
            rows, markers = complete()
            warm = markers['warm_batch']
            if fault == 'missing':
                del warm['ready_close']
            elif fault == 'generation':
                warm['ready_close']['stopped']['starttime'] += 1
            elif fault == 'resume':
                warm['ready_close']['resumed']['state'] = 'T'
            else:
                warm['drained']['ready_fd_bytes'] = 128
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                gate.validate_warm_ready(warm, 20, 'reconnect')

    def test_measured_batches_cannot_pause_the_daemon(self):
        rows, markers = complete()
        markers['batches'][0]['ready_close'] = warm_receipt(20)
        with self.assertRaisesRegex(ValueError, 'restricted to structural warm'):
            gate.validate(rows, markers)

    def test_close_failure_still_resumes_the_owned_pidfd(self):
        states = [{'pid': 123, 'starttime': 42, 'state': state, 'monotonic_ns': n}
                  for n, state in enumerate(['S', 'S', 'T', 'S'])]
        with tempfile.TemporaryDirectory() as name:
            fixture = SimpleNamespace(pid=123, folder=Path(name), root=Path('/synthetic/root'),
                                      spec={'profile': 'reconnect', 'diagnostic_sha256': 'same-elf'},
                                      close=Mock(), event=Mock())
            fixture.clients = [Mock() for _ in range(20)]
            for number, client in enumerate(fixture.clients):
                client.fileno.return_value = number + 10
            fixture.close.side_effect = RuntimeError('close failed')
            with patch.object(gate, 'process_state', side_effect=states), \
                    patch.object(gate.os, 'pidfd_open', return_value=99, create=True), \
                    patch.object(gate.os, 'close') as close_fd, \
                    patch.object(gate.signal, 'pidfd_send_signal', create=True) as send, \
                    patch.object(gate.driver, 'process_identity', return_value={'sha256': 'same-elf'}):
                with self.assertRaisesRegex(RuntimeError, 'close failed'):
                    gate.warm_ready_close(fixture)
                self.assertEqual([call.args for call in send.call_args_list],
                                 [(99, gate.signal.SIGSTOP), (99, gate.signal.SIGCONT)])
                close_fd.assert_called_once_with(99)
            receipt = json.loads((Path(name) / 'warm-ready-close.json').read_text())
            self.assertTrue(receipt['resume_attempted'])
            self.assertFalse(receipt['completed'])


class ExactConnectionCounts(unittest.TestCase):
    def test_exact_totals_include_twenty_warm_connections_and_partial_last_batch(self):
        for count, batches, tail in [(1024, 51, 4), (4096, 204, 16)]:
            sizes = gate.connection_batch_sizes(count)
            with self.subTest(count=count):
                self.assertEqual(sum(sizes) + 20, count)
                self.assertEqual(len(sizes), batches)
                self.assertEqual(sizes[-1], tail)
                self.assertTrue(all(size == 20 for size in sizes[:-1]))
                self.assertLessEqual(max(sizes), 20)

    def test_other_counts_are_rejected_and_default_case_identity_is_unchanged(self):
        for count in [0, 20, 200, 1023, 1025, 4095, 4097]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                gate.connection_batch_sizes(count)
        self.assertEqual(gate.case_name(4096, 'reconnect'), 'm6b-internal-reconnect-4096')
        self.assertEqual(gate.case_name(4096, 'reconnect', 1024),
                         'm6b-internal-reconnect-4096-connections-1024')

    def test_partial_batch_owner_contract_uses_actual_four_or_sixteen_views(self):
        for count in [4, 16]:
            row = active(0, 1)
            row.update(clients=count, G=count, dns_work=count, views=count,
                       private_content=count, content_versions=65 + count, old_pinned_content=1)
            self.assertTrue(gate.active_owner_contract(row, 4096, count))
            self.assertFalse(gate.active_owner_contract(row, 4096, 20))


class ConfiguredLimitOwners(unittest.TestCase):
    def test_thirty_actual_views_hold_in_warm_and_all_ten_batches(self):
        rows, markers = complete_limit()
        self.assertEqual(len(gate.validate(rows, markers)), 10)
        self.assertTrue(gate.active_owner_contract(rows[0], 150, 30))
        self.assertFalse(gate.active_owner_contract(rows[0], 150))
        self.assertEqual(gate.profile_clients('reconnect'), 20)
        controls = gate.rejection_controls(rows, markers)
        self.assertEqual(len(controls), 12)
        self.assertTrue(all(row['rejected'] for row in controls))
        self.assertEqual([row['control'] for row in controls[-2:]],
                         ['missing-limit-view', 'shortened-limit-hold'])

    def test_cannot_expand_limit_profile_to_another_capacity(self):
        rows, markers = complete_limit()
        markers['capacity'] = 4096
        markers['prefill_names'] = [f'r{n:06}.internal.test' for n in range(4096)]
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)

    def test_missing_view_or_slot_is_rejected_even_with_matching_raw_markers(self):
        for number in [0, 10]:
            for key in ['clients', 'G', 'dns_work', 'views']:
                rows, markers = complete_limit()
                batch = ([markers['warm_batch'], *markers['batches']])[number]
                target = rows[batch['active_trace_index']]
                target[key] = 29
                batch['active'] = copy.deepcopy(target)
                batch['limit']['first'] = copy.deepcopy(target)
                with self.subTest(batch=number, key=key), self.assertRaises(ValueError):
                    gate.validate(rows, markers)

    def test_short_hold_missing_warm_or_collapsed_trace_pair_is_rejected(self):
        for kind in ['short-hold', 'short-spacing', 'missing-warm-hold', 'same-row']:
            rows, markers = complete_limit()
            batch = markers['warm_batch']
            hold = batch['limit']
            if kind == 'short-hold':
                hold['completed_monotonic_ns'] -= 1
            elif kind == 'short-spacing':
                rows[hold['last_trace_index']]['elapsed_ns'] = hold['first']['elapsed_ns'] + 899_999_999
                hold['last'] = copy.deepcopy(rows[hold['last_trace_index']])
            elif kind == 'missing-warm-hold':
                del batch['limit']
            else:
                hold['last_trace_index'] = hold['first_trace_index']
                hold['last'] = copy.deepcopy(hold['first'])
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.validate(rows, markers)

    def test_all_admission_progress_and_recovery_observations_join_the_gauge(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            row = limit_observations(folder)
            with patch.object(gate.pressure, 'gauge_receipt', return_value=[{'value': {'tcp_connections': 30}}]) as gauge:
                gate.limit_observations(folder, row, 123, '/synthetic/root')
            self.assertEqual(gauge.call_count, 11)
            self.assertEqual(gauge.call_args_list[0].args,
                             (folder, 'warm-over-limit-gauge.gauge.json', 123, '/synthetic/root', 30))

    def test_missing_reordered_or_forged_admission_and_recovery_is_rejected(self):
        for kind in ['config', 'raw-config', 'raw-capacity', 'duplicate', 'missing',
                     'order', 'reply-present', 'gauge', 'missing-answer', 'different-request']:
            with tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                row = limit_observations(folder)
                if kind == 'config':
                    row['config'] = ''
                elif kind == 'raw-config':
                    (folder / 'config').write_text('cache-size=150\nmax-tcp-connections=20\n')
                elif kind == 'raw-capacity':
                    (folder / 'config').write_text('cache-size=4096\nmax-tcp-connections=30\n')
                elif kind == 'duplicate':
                    row['observations'].append(copy.deepcopy(row['observations'][0]))
                elif kind == 'missing':
                    row['observations'].pop()
                elif kind == 'order':
                    row['observations'][0], row['observations'][3] = row['observations'][3], row['observations'][0]
                elif kind == 'reply-present':
                    row['observations'][0]['no_reply'] = False
                elif kind == 'gauge':
                    row['observations'][0]['metrics']['tcp_connections'] = 29
                elif kind == 'missing-answer':
                    del row['observations'][1]['reply']
                else:
                    (folder / 'warm-over-limit-recovered.query').write_bytes(b'another-request')
                with self.subTest(kind=kind), patch.object(gate.pressure, 'gauge_receipt', return_value=[{'value': {'tcp_connections': 30}}]), self.assertRaises(ValueError):
                    gate.limit_observations(folder, row, 123, '/synthetic/root')


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
                'live_requested_including_diagnostic', 'observer_registry_requested', 'live_objects',
                'poll_fd_bytes', 'ready_fd_bytes']
        for key in keys:
            rows, markers = complete()
            last = markers['batches'][-1]
            target = rows[last['drain_trace_index']]
            target[key] += 1
            last['drained'] = copy.deepcopy(target)
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate(rows, markers)

    def test_effective_registry_capacity_changes_do_not_claim_allocated_growth(self):
        rows, markers = complete()
        for number, batch in enumerate(markers['batches']):
            target = rows[batch['drain_trace_index']]
            target['registry_capacity'] = 100 + number
            batch['drained'] = copy.deepcopy(target)
        rows[-1]['registry_capacity'] = 107
        markers['final']['row'] = copy.deepcopy(rows[-1])
        self.assertEqual(len(gate.validate(rows, markers)), 10)

    def test_true_observer_allocated_growth_rejects_even_if_product_live_is_unchanged(self):
        rows, markers = complete()
        last = markers['batches'][-1]
        target = rows[last['drain_trace_index']]
        before = gate.product_live(target)
        target['observer_registry_requested'] += 128
        target['live_requested_including_diagnostic'] += 128
        last['drained'] = copy.deepcopy(target)
        self.assertEqual(gate.product_live(target), before)
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)

    def test_product_one_byte_delta_cannot_be_hidden_by_observer_reclassification(self):
        rows, markers = complete()
        last = markers['batches'][-1]
        target = rows[last['drain_trace_index']]
        target['live_requested_including_diagnostic'] += 1
        target['observer_registry_requested'] += 1
        last['drained'] = copy.deepcopy(target)
        with self.assertRaises(ValueError):
            gate.validate(rows, markers)

    def test_old_trace_without_capacity_semantics_is_not_reinterpreted(self):
        rows, markers = complete()
        for row in rows:
            del row['registry_capacity_semantics']
        with self.assertRaises(ValueError):
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
