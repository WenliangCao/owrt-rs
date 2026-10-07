#!/usr/bin/env python3
"""Offline checks of the supplemental accept-before-query witness guard."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest

import m6b_tcp_accept_snapshot as gate


def row(mode):
    label = 'm6b-accept-before-parent-' + mode
    labels = ['accept-before-first-query', 'parent-mutation', 'child-first-query', 'parent-after-child', 'next-view']
    if mode == 'replace':
        labels.insert(0, 'seed-before-accept')
    observations = []
    for index, name in enumerate(labels):
        observation = {'label': name, 'sent_monotonic_ns': 100 + index * 10,
                       'completed_monotonic_ns': 101 + index * 10, 'metrics': {'tcp_connections': 1}}
        if name != 'accept-before-first-query':
            address = '198.51.100.7' if mode == 'learn' or name in ['seed-before-accept', 'child-first-query'] else '198.51.100.8'
            observation['reply'] = {'records': [{'section': 'answer', 'type': 1, 'data': address}]}
        observations.append(observation)
    return {'case': label, 'identity': {'sha256': gate.driver.STOCK_SHA256},
            'exit': 0, 'upstream_errors': [], 'observations': observations,
            'upstream': [{'transport': mode} for mode in (['udp', 'tcp'] if mode == 'learn' else ['udp', 'udp'])]}


class AcceptSnapshotGuard(unittest.TestCase):
    def test_child_eviction_parent_counter_is_counted_once(self):
        value = row('learn')
        value['case'] = 'm6b-child-eviction-parent-counters'
        labels = ['seed-before-accept', 'accept-before-first-query', 'child-first-query',
                  'parent-pipe-barrier', 'parent-after-child', 'child-private-repeat', 'next-view']
        value['observations'] = []
        for n, label in enumerate(labels):
            observation = {'label': label, 'sent_monotonic_ns': 100 + n * 10, 'completed_monotonic_ns': 101 + n * 10,
                           'metrics': {'tcp_connections': 1, 'dns_cache_inserted': 1 if n == 0 else 2,
                                       'dns_cache_live_freed': 0 if n == 0 else 1, 'dns_queries_forwarded': 1}}
            if label != 'accept-before-first-query':
                address = '198.51.100.7' if n == 0 else '198.51.100.99' if 'barrier' in label else '198.51.100.8'
                observation['reply'] = {'records': [{'section': 'answer', 'type': 1, 'data': address}]}
            value['observations'].append(observation)
        self.assertTrue(gate.valid_row(value, gate.driver.STOCK_SHA256))
        for key, wrong in [('dns_cache_inserted', 3), ('dns_cache_live_freed', 2), ('dns_queries_forwarded', 2)]:
            bad = copy.deepcopy(value)
            bad['observations'][3]['metrics'][key] = wrong
            self.assertFalse(gate.valid_row(bad, gate.driver.STOCK_SHA256))

    def test_later_connection_completes_before_held_earlier_connection(self):
        value = row('learn')
        value['case'] = 'm6b-cross-connection-progress'
        labels = ['accept-before-first-query', 'second-completes-first', 'parent-pipe-barrier-b', 'parent-sees-second',
                  'first-completes-later', 'parent-pipe-barrier-a', 'parent-sees-first', 'first-private-repeat', 'second-private-repeat']
        value['upstream'] = [{'transport': 'tcp'}, {'transport': 'tcp'}]
        value['observations'] = []
        for n, label in enumerate(labels):
            before, after = (100, 101) if n == 0 else (150, 231) if n == 4 else (190 + n * 10, 191 + n * 10)
            observation = {'label': label, 'sent_monotonic_ns': before, 'completed_monotonic_ns': after,
                           'metrics': {'tcp_connections': 1 if n == 0 else 2,
                                       'dns_cache_inserted': 1 if n < 5 else 2, 'dns_cache_live_freed': 0}}
            if n:
                address = '198.51.100.99' if 'barrier' in label else '198.51.100.22' if label in ['second-completes-first', 'parent-sees-second', 'second-private-repeat'] else '198.51.100.21'
                observation['reply'] = {'records': [{'section': 'answer', 'type': 1, 'data': address}]}
            value['observations'].append(observation)
        self.assertTrue(gate.valid_row(value, gate.driver.STOCK_SHA256))
        bad = copy.deepcopy(value)
        bad['observations'][1]['completed_monotonic_ns'] = 240
        self.assertFalse(gate.valid_row(bad, gate.driver.STOCK_SHA256), 'global accept ordering stalls second')

    def test_failed_parent_prefix_requires_removal_without_commit_and_child_privacy(self):
        target = 'target.failed-prefix.cache.test'
        answers = [None, [(1, '198.51.100.9')], [(1, '198.51.100.7')],
                   [(5, target), (1, '198.51.100.8')], [(1, '198.51.100.99')],
                   [(1, '198.51.100.9')], [(1, '198.51.100.10')], [(5, target), (1, '198.51.100.8')]]
        labels = ['accept-before-first-query', 'parent-local-after-hup', 'parent-mutation', 'child-first-query',
                  'parent-pipe-barrier', 'parent-local-preserved', 'parent-removed-prefix-misses', 'child-private-repeat']
        value = {'case': 'm6b-parent-import-failed-prefix', 'identity': {'sha256': gate.driver.STOCK_SHA256},
                 'exit': 0, 'upstream_errors': [], 'upstream': [{'transport': t} for t in ['udp', 'tcp', 'udp']],
                 'observations': [{'label': label, 'sent_monotonic_ns': 100 + n * 10,
                                   'completed_monotonic_ns': 101 + n * 10,
                                   'metrics': {'tcp_connections': 1, 'dns_cache_inserted': 2 if n >= 6 else 1,
                                               'dns_cache_live_freed': 0},
                                   **({'reply': {'records': [{'section': 'answer', 'type': t, 'data': d}
                                                            for t, d in answers[n]]}} if answers[n] else {})}
                                  for n, label in enumerate(labels)]}
        self.assertTrue(gate.valid_row(value, gate.driver.STOCK_SHA256))
        for index, field, wrong in [(4, 'dns_cache_inserted', 2), (6, 'dns_cache_inserted', 1), (4, 'dns_cache_live_freed', 1)]:
            bad = copy.deepcopy(value)
            bad['observations'][index]['metrics'][field] = wrong
            self.assertFalse(gate.valid_row(bad, gate.driver.STOCK_SHA256))
        bad = copy.deepcopy(value)
        bad['observations'][6]['reply']['records'][0]['data'] = '198.51.100.7'
        self.assertFalse(gate.valid_row(bad, gate.driver.STOCK_SHA256), 'rollback wrongly preserved old target')

    def test_accept_and_upstream_witnesses_are_required_for_both_modes(self):
        for mode in ['learn', 'replace']:
            with self.subTest(mode=mode):
                value = row(mode)
                self.assertTrue(gate.valid_row(value, gate.driver.STOCK_SHA256))
                for mutation in ['missing-accept', 'unaccepted', 'query-before-mutation', 'wrong-content', 'wrong-upstream', 'wrong-elf']:
                    bad = copy.deepcopy(value)
                    rows = {r['label']: r for r in bad['observations']}
                    if mutation == 'missing-accept':
                        bad['observations'].remove(rows['accept-before-first-query'])
                    elif mutation == 'unaccepted':
                        rows['accept-before-first-query']['metrics']['tcp_connections'] = 0
                    elif mutation == 'query-before-mutation':
                        rows['child-first-query']['sent_monotonic_ns'] = 1
                    elif mutation == 'wrong-content':
                        rows['child-first-query']['reply']['records'][0]['data'] = '203.0.113.99'
                    elif mutation == 'wrong-upstream':
                        bad['upstream'].pop()
                    else:
                        bad['identity']['sha256'] = '0' * 64
                    self.assertFalse(gate.valid_row(bad, gate.driver.STOCK_SHA256), mutation)


class SupplementIdentityTests(unittest.TestCase):
    # Synthetic envelope checks only; never image execution or qualification.
    def test_compare_requires_fresh_output_before_reading_old_receipts(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / 'comparison.json'; out.write_text('preserve old failure')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                gate.compare(SimpleNamespace(out=out))
            self.assertEqual(out.read_text(), 'preserve old failure')

    def test_frozen_envelope_rejects_a_different_candidate_source_or_case_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name); (folder / 'drivers').mkdir()
            wanted, source = 'a'*64, 'b'*40
            tools = {}
            for filename in gate.TOOLS:
                data = Path(gate.__file__).with_name(filename).read_bytes()
                (folder / 'drivers' / filename).write_bytes(data)
                tools[filename] = gate.driver.sha256(folder / 'drivers' / filename)
            root = {'root': '/synthetic/root', 'c_sha256': gate.driver.STOCK_SHA256,
                    'rust_sha256': wanted, 'image_sha256': 'c'*64, 'image_provenance_sha256': 'd'*64,
                    'image_files': {'lib/test.so': 'e'*64},
                    'filesystem': {'kind': 'overlay', 'lower_read_only': True, 'base_manifest_sha256': 'f'*64}}
            (folder / 'rootfs-identity.json').write_text(json.dumps(root))
            rows = {case['case']: {'case': case['case'], 'config': case['config']} for case in gate.CASES}
            report = {'rust_sha256': wanted, 'c_sha256': gate.driver.STOCK_SHA256, 'syntax': [],
                      'scenarios': list(rows.values()), 'executed_cases': list(rows), 'failures': []}
            supplement = {'side': 'rust', 'candidate_sha256': wanted, 'source_commit': source,
                          'profile_plan': gate.CASES, 'passed': True, 'tools_unchanged': True, 'tools': tools,
                          'driver_sha256': tools['m6b_tcp_accept_snapshot.py'], 'root_provenance': gate.root_provenance(root)}
            (folder / 'supplement.json').write_text(json.dumps(supplement))
            with patch.object(gate.driver, 'comparison_rows', return_value=(report, rows)), \
                    patch.object(gate, 'valid_row', return_value=True), patch.object(gate, 'raw_valid', return_value=True):
                gate.validate_run(folder, 'rust', wanted, source)
                for sha, commit in [('0'*64, source), (wanted, '0'*40)]:
                    with self.assertRaises(ValueError): gate.validate_run(folder, 'rust', sha, commit)
                report['executed_cases'].pop()
                with self.assertRaisesRegex(ValueError, 'five-case'): gate.validate_run(folder, 'rust', wanted, source)


if __name__ == '__main__':
    unittest.main()
