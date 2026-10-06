import copy
import unittest

import m5_logging as logging


class QueryPhaseTests(unittest.TestCase):
    case = {'id': 'query-forward-ordinary', 'kind': 'run', 'query_sequence': [('a.forward.test', 1), ('a.forward.test', 1)]}

    def witness(self):
        epoch = 100
        phase = {'epoch': epoch, 'aligned_at': {'wall_ns': 100_200_000_000, 'monotonic_ns': 1_000_000_000}, 'intervals': []}
        order = [(name, kind, transport) for transport in ['udp', 'tcp'] for name, kind in self.case['query_sequence']]
        order.append(('ready.logging', 1, 'udp-after-tcp'))
        for index, (name, kind, transport) in enumerate(order):
            start = 2 * index + 1
            phase['intervals'].append({'name': name, 'type': kind, 'transport': transport,
                'started': {'wall_ns': 100_200_000_000 + start, 'monotonic_ns': 1_000_000_000 + start},
                'finished': {'wall_ns': 100_200_000_000 + start + 1, 'monotonic_ns': 1_000_000_000 + start + 1}})
        return {'query_phase': phase}

    def test_real_wall_alignment_is_bounded_and_records_both_clocks(self):
        phase = logging.align_query_phase()
        self.assertLessEqual(190_000_000, phase['aligned_at']['wall_ns'] % 1_000_000_000)
        self.assertGreaterEqual(210_000_000, phase['aligned_at']['wall_ns'] % 1_000_000_000)
        self.assertGreater(phase['aligned_at']['monotonic_ns'], 0)

    def test_phase_requires_complete_single_epoch_seed_and_read_intervals(self):
        self.assertEqual(logging.query_phase_errors(self.witness(), self.case), [])
        for mutation in ['missing', 'wrong-query', 'cross-second', 'bad-wall-order', 'bad-mono-order', 'missing-clock']:
            with self.subTest(mutation=mutation):
                row = copy.deepcopy(self.witness()); phase = row['query_phase']; intervals = phase['intervals']
                if mutation == 'missing': intervals.pop()
                elif mutation == 'wrong-query': intervals[0]['name'] = 'other.forward.test'
                elif mutation == 'cross-second': intervals[-1]['finished']['wall_ns'] = 101_000_000_000
                elif mutation == 'bad-wall-order': intervals[0]['finished']['wall_ns'] = 100_199_999_999
                elif mutation == 'bad-mono-order': intervals[0]['finished']['monotonic_ns'] = 999_999_999
                else: intervals[0]['started'].pop('wall_ns')
                self.assertTrue(logging.query_phase_errors(row, self.case))

    def test_valid_phase_does_not_normalize_different_ttls(self):
        row = {'ready': True, 'exit': 0, 'forced': False, 'syslog': [], 'files': {}, 'file_metadata': {},
               'dns': [{'response': {'records': [{'ttl': 120}]}}], 'stdout': '', 'stderr': ''}
        row.update(self.witness()); candidate = copy.deepcopy(row)
        candidate['dns'][0]['response']['records'][0]['ttl'] = 119
        failures = logging.compare(row, candidate, self.case)
        self.assertTrue(any(failure.get('field') == 'dns' for failure in failures))
        self.assertEqual(row['dns'][0]['response']['records'][0]['ttl'], 120)
        self.assertEqual(candidate['dns'][0]['response']['records'][0]['ttl'], 119)


if __name__ == '__main__': unittest.main()
