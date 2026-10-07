#!/usr/bin/env python3
"""Offline checks of the supplemental accept-before-query witness guard."""
import copy
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


if __name__ == '__main__':
    unittest.main()
