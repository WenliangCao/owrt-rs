#!/usr/bin/env python3
"""S8 phase witnesses and unchanged DNS/root/object release checks."""
import copy
import unittest
from unittest.mock import patch

import m6b_tcp_internal as internal
import m6b_tcp_interleaved as interleaved
import m6b_tcp_log_lifetime as gate
from test_m6b_tcp_interleaved import idle


def active(elapsed):
    row = idle(0, elapsed)
    row.update(clients=1, G=1, dns_work=1, views=1, full_drained=False,
               private_content=1, content_versions=4)
    return row


def complete(profile):
    rows, items = [], []
    count = 11 if profile == 'recover' else 2
    for number in range(count):
        item = {'label': 'warm' if number == 0 else f'b{number - 1:02}' if profile == 'recover' else 'term',
                'fill': dict(path=gate.SINK, capacity=4096, filler_bytes=4096,
                             byte_hex='42', filled_until_eagain=True)}
        item['active'] = {'trace_index': len(rows), 'row': active((len(rows) + 1) * 1_000_000_000)}
        rows.append(copy.deepcopy(item['active']['row']))
        only = idle(number, (len(rows) + 1) * 1_000_000_000)
        only.update(clients=1, G=1, full_drained=False, log_payload_capacity=128,
                    log_queue_capacity=64, live_requested_including_diagnostic=2400)
        item['log_only'] = {'trace_index': len(rows), 'row': copy.deepcopy(only)}
        rows.append(only)
        if profile == 'term' and number == 1:
            item['drained'] = None
        else:
            row = idle(number + 1, (len(rows) + 1) * 1_000_000_000,
                       0 if profile == 'recover' and number == 10 else -1)
            item['drained'] = {'trace_index': len(rows), 'row': copy.deepcopy(row)}
            rows.append(row)
        items.append(item)
    markers = dict(profile=profile, capacity=150, prefill_names=gate.PREFILL,
                   warm_batch=items[0], baseline=copy.deepcopy(items[0]['drained']),
                   batches=items[1:] if profile == 'recover' else [],
                   term=items[-1] if profile == 'term' else None, final=None)
    if profile == 'recover':
        origin = rows[-1]['elapsed_ns']
        for second in [1, 5, 15, 60]:
            rows.append(idle(11, origin + second * 1_000_000_000, second))
        markers['final'] = {'trace_index': len(rows) - 1, 'row': copy.deepcopy(rows[-1])}
    return rows, markers


class SuccessfulDnsWitness(unittest.TestCase):
    def test_s8_uses_one_fifo_facility_without_the_default_file_facility(self):
        config = gate.driver.scenario_config({'config': 'log-queries', 'log_facility': gate.SINK,
                                             'capacity': 150, 'metrics': True}, 5300, 5400)
        self.assertEqual([line for line in config.splitlines() if line.startswith('log-facility=')],
                         ['log-facility=' + gate.SINK])
        self.assertIn('log-queries', config.splitlines())
        self.assertIn('enable-ubus=cache-metrics', config.splitlines())

    def test_default_family_configuration_is_byte_for_byte_unchanged(self):
        for spec in gate.driver.SCENARIOS:
            config = (f'port={0 if spec.get("dns_off") else 5300}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={gate.driver.LISTEN}\n'
                      f'server=127.0.0.2#5400\ncache-size={spec.get("capacity",100)}\nno-0x20-encode\n'
                      'host-record=health.cache.test,198.51.100.99\nlocal-ttl=600\nuser=root\n'
                      'pid-file=/m2/cache.pid\nlog-facility=/m2/cache.log\n'+spec['config'].replace('@UPSTREAM@','5400')+'\n'
                      +('enable-ubus=cache-metrics\n' if spec.get('metrics') else ''))
            with self.subTest(case=spec['case']):
                self.assertEqual(gate.driver.scenario_config(spec, 5300, 5400), config)

    def test_acceptance_sample_cannot_replace_a_completed_query_sample(self):
        early, completed = active(1), active(2)
        early.update(private_content=0, content_versions=3)
        with patch.object(internal, 'trace_rows', side_effect=[[early], [early, completed]]):
            point = gate.successful_dns_witness('unused')
        self.assertEqual(point['trace_index'], 1)
        self.assertEqual(point['row']['private_content'], 1)

    def test_actual_missing_private_root_after_success_is_rejected(self):
        before, missing = active(1), active(2)
        missing.update(private_content=0, content_versions=3)
        with patch.object(internal, 'trace_rows', side_effect=[[before], [before, missing]]):
            with self.assertRaises(AssertionError):
                gate.successful_dns_witness('unused')

    def test_previous_positive_sample_is_not_reused_without_a_new_sample(self):
        with patch.object(internal, 'trace_rows', return_value=[active(1)]), \
                patch.object(interleaved.time, 'monotonic', side_effect=[0, 6]):
            with self.assertRaises(AssertionError):
                gate.successful_dns_witness('unused')


class OwnerRelease(unittest.TestCase):
    def test_recovery_and_term_keep_all_original_six_negative_controls(self):
        for profile in ['recover', 'term']:
            rows, markers = complete(profile)
            self.assertEqual(len(gate.validate_trace(rows, markers)), 11 if profile == 'recover' else 2)
            controls = gate.rejection_controls(rows, markers)
            self.assertEqual(len(controls), 6)
            self.assertTrue(all(row['rejected'] for row in controls))

    def test_each_dns_owner_and_root_is_zero_before_log_only(self):
        for key in gate.ZERO_DNS:
            for profile in ['recover', 'term']:
                rows, markers = complete(profile)
                item = markers['batches'][-1] if profile == 'recover' else markers['term']
                point = item['log_only']
                rows[point['trace_index']][key] += 1
                point['row'] = copy.deepcopy(rows[point['trace_index']])
                with self.subTest(profile=profile, key=key), self.assertRaises(ValueError):
                    gate.validate_trace(rows, markers)

    def test_every_recovery_balance_field_remains_exact(self):
        for key in internal.BALANCE_FIELDS:
            rows, markers = complete('recover')
            point = markers['batches'][-1]['drained']
            rows[point['trace_index']][key] += 1
            point['row'] = copy.deepcopy(rows[point['trace_index']])
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate_trace(rows, markers)

    def test_collector_still_rejects_a_successful_phase_without_private_content(self):
        for profile in ['recover', 'term']:
            rows, markers = complete(profile)
            point = markers['warm_batch']['active']
            rows[point['trace_index']].update(private_content=0, old_pinned_content=1)
            point['row'] = copy.deepcopy(rows[point['trace_index']])
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                gate.validate_trace(rows, markers)


if __name__ == '__main__':
    unittest.main()
