import unittest

from loop_owner_profile_analyze import EVENTS, attribute_samples, sample_read_metadata, stat_counts, task_tree
from perf_link_map_profile import Sample
from r121_symbolize import parse_proc_maps


class ProfileAnalysisTests(unittest.TestCase):
    def test_read_sample_weights_are_bound_to_raw_counter_deltas(self):
        samples = [Sample(42, 42, 'U', weight, 'cycles:uS', 0x1010, '[unknown]', '/exact')
                   for weight in (200005, 199998)]
        attributes = ('cycles:uS: { sample_period, sample_freq }: 200000, '
                      'sample_type: IP|TID|TIME|READ|IDENTIFIER, '
                      'read_format: TOTAL_TIME_ENABLED|TOTAL_TIME_RUNNING|ID|LOST, exclude_kernel: 1')
        raw = ''.join('PERF_RECORD_SAMPLE(IP, 0x2): 42/42: 0x1010 period: 200000 addr: 0\n'
                      f'...... time enabled {index:016x}\n...... time running {index:016x}\n'
                      f'..... id 0001, value {value:016x}, lost 0\n'
                      for index, value in enumerate((200005, 400003), 1))
        result = sample_read_metadata(raw, attributes, samples, 200000)
        self.assertEqual(result['observed_weight_range'], [199998, 200005])
        for broken, attrs in [(raw.replace('time running 0000000000000001', 'time running 0000000000000000'), attributes),
                              (raw.replace('lost 0', 'lost 1', 1), attributes),
                              (raw.replace('period: 200000', 'period: 10000', 1), attributes),
                              (raw, attributes.replace('exclude_kernel: 1', 'exclude_kernel: 0'))]:
            with self.assertRaises(ValueError):
                sample_read_metadata(broken, attrs, samples, 200000)

    def test_stat_preserves_scaling_and_rejects_missing_inheritance(self):
        verbose = ''.join(
            'perf_event_attr:\n  inherit 1\n  ' +
            ('exclude_kernel' if index % 2 == 0 else 'exclude_user') +
            f' 1\nsys_perf_event_open: pid 42  cpu -1  group_fd {-1 if index == 0 else 6}  flags 0x8 = {6 + index}\n'
            for index in range(4))
        text = ''.join(f'{event}: -1: 100 200 100\n{event}: 100 200 100\n'
                       f'200,,{event},100,50.00,,\n' for event in EVENTS)
        result = stat_counts(text, verbose, 42, 5000)
        self.assertFalse(result['all_unscaled'])
        self.assertEqual(result['events']['instructions:u']['raw_count'], 100)
        self.assertEqual(result['events']['instructions:u']['reported_count'], 200)
        self.assertEqual(result['events']['instructions:u']['scale_factor'], 2)
        for broken, log in ((text.replace('200,,instructions:u', '<not counted>,,instructions:u'), verbose),
                            (text.replace('50.00', '100.00'), verbose),
                            (text, verbose.replace('inherit 1', 'inherit 0', 1)),
                            (text, verbose.replace('group_fd 6', 'group_fd -1', 1))):
            with self.assertRaises(ValueError):
                stat_counts(broken, log, 42, 5000)

    def test_fork_samples_require_lineage_and_exit(self):
        mappings = parse_proc_maps('1000-2000 r-xp 00000000 08:01 123 /exact\n')
        sample = Sample(43, 43, 'U', 10000, 'instructions:u', 0x1010, '[unknown]', '/exact')
        text = ('0/0 0.000000000: PERF_RECORD_COMM: exact:42/42\n'
                '42/42 1.000000000: PERF_RECORD_FORK(43:43):(42:42)\n'
                '43/43 U 1.100000000: instructions:u: 1010 [unknown] (/exact)\n'
                '43/43 1.200000000: PERF_RECORD_EXIT(43:43):(42:42)\n')
        result = task_tree(text, 42, mappings, [sample])
        self.assertEqual(result['parents'], {42: None, 43: 42})
        for broken in (text.replace('(42:42)', '(99:99)', 1),
                       text[:text.index('43/43 1.200')],
                       text.replace('PERF_RECORD_COMM:', 'PERF_RECORD_COMM exec:')):
            with self.assertRaises(ValueError):
                task_tree(broken, 42, mappings, [sample])

    def test_aliases_and_gaps_are_not_guessed(self):
        class Image:
            loads = [(1, 0, 0, 0, 4096, 4096, 4096)]
        mappings = parse_proc_maps('1000-2000 r-xp 00000000 08:01 123 /exact\n')
        samples = [Sample(42, 42, 'U', 10000, 'instructions:u', ip, '[unknown]', '/exact')
                   for ip in (0x1010, 0x1100)]
        samples.append(Sample(42, 42, 'K', 10000, 'instructions:u', 0xffff0000, '[unknown]', '[unknown]'))
        images = {'/exact': (Image(), [(0, 0, 32, 'alias_a'), (0, 0, 32, 'alias_b')], {})}
        result = attribute_samples(samples, mappings, images)
        self.assertEqual({row['category'] for row in result['ranges']},
                         {'user_shared_or_overlapping', 'user_unattributed', 'non_user_pc_unattributed'})
        self.assertEqual(sum(row['period'] for row in result['ranges']), 30000)


if __name__ == '__main__':
    unittest.main()
