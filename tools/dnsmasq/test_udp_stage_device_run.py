import json
from pathlib import Path
import tempfile
import unittest

from udp_stage_device_run import GROUPS, MODES, schedule, stage_report


class StageGateTests(unittest.TestCase):
    def fixture(self, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        def counts(number):
            return dict(scheduled=number, sent=number, correct=number, timeout=0,
                        wrong=0, transport_error=0, scheduled_skipped=0)
        (folder / 'prewarm.json').write_text(json.dumps({'measurement': counts(1000), 'interrupted': False, 'output_failed': False}))
        (folder / 'client.json').write_text(json.dumps({'warmup': counts(1000), 'measurement': counts(4000),
                                                       'interrupted': False, 'output_failed': False}))
        sample = {'processes': [{'pid': 42, 'starttime_ticks': 100, 'thread_count': 1}], 'tree_truncated': False}
        for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl'):
            (folder / name).write_text(json.dumps(sample) + '\n')
        fields = ['0'] * 30
        fields[17], fields[19] = '1', '100'
        (folder / 'final.stat').write_text('42 (dnsmasq) ' + ' '.join(fields))
        for name in ('netns.txt', 'daemon.netns'):
            (folder / name).write_text('net:[1234]\n')
        if mode is not None:
            selected = MODES.index(mode)
            report = {'scope': 'excluded synthetic cumulative-path intervention, not oracle correctness or accepted performance',
                      'mode': selected, 'matched_queries': 6000, 'prewarm_threshold': 1000,
                      'cuts_by_mode': [5000 if index == selected and selected else 0 for index in range(4)]}
            (folder / 'udp-stage.json').write_text(json.dumps(report))
        return folder

    def test_frozen_order_is_five_separate_alternating_pairs_per_group(self):
        rows = schedule()
        self.assertEqual(len(rows), 50)
        self.assertEqual(len({row['label'] for row in rows}), 50)
        for index, (name, left, right) in enumerate(GROUPS):
            group = rows[index * 10:(index + 1) * 10]
            self.assertEqual({row['group'] for row in group}, {name})
            self.assertEqual([row['side'] for row in group], ['c', 'rust', 'rust', 'c', 'c', 'rust', 'rust', 'c', 'c', 'rust'])
            self.assertEqual([row['round'] for row in group], [1, 1, 2, 2, 3, 3, 4, 4, 5, 5])
            for row in group:
                self.assertEqual((row['artifact'], row['mode']), left if row['side'] == 'c' else right)

    def test_every_mode_and_originals_have_required_cohorts(self):
        for mode in (None,) + MODES:
            result = stage_report(self.fixture(mode), mode)
            self.assertEqual(result['correct_fixture_replies'], 6000)
            self.assertEqual(result['thread_samples'], 3)
            self.assertEqual(result['raw'] is None, mode is None)

    def test_wrong_mode_threshold_matching_or_cuts_is_rejected(self):
        for key, value in [('mode', 2), ('mode', True), ('matched_queries', 5000),
                           ('prewarm_threshold', 999), ('cuts_by_mode', [0, 5001, 0, 0]),
                           ('cuts_by_mode', [1, 5000, 0, 0]), ('cuts_by_mode', [0, 5000, 0])]:
            folder = self.fixture('receive')
            report = json.loads((folder / 'udp-stage.json').read_text())
            report[key] = value
            (folder / 'udp-stage.json').write_text(json.dumps(report))
            with self.assertRaises(AssertionError):
                stage_report(folder, 'receive')

    def test_prewarm_failure_is_rejected_even_with_correct_stage_counts(self):
        folder = self.fixture('receive')
        prewarm = json.loads((folder / 'prewarm.json').read_text())
        prewarm['measurement']['correct'] = 999
        prewarm['measurement']['wrong'] = 1
        (folder / 'prewarm.json').write_text(json.dumps(prewarm))
        with self.assertRaises(AssertionError):
            stage_report(folder, 'receive')

    def test_extra_thread_or_different_namespace_is_rejected(self):
        folder = self.fixture('full')
        sample = {'processes': [{'pid': 42, 'starttime_ticks': 100, 'thread_count': 2}], 'tree_truncated': False}
        (folder / 'resources.jsonl').write_text(json.dumps(sample) + '\n')
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')
        folder = self.fixture('full')
        (folder / 'daemon.netns').write_text('net:[9999]\n')
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')

    def test_full_cut_or_original_sidecar_is_rejected(self):
        folder = self.fixture('full')
        report = json.loads((folder / 'udp-stage.json').read_text())
        report['cuts_by_mode'][0] = 5000
        (folder / 'udp-stage.json').write_text(json.dumps(report))
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')
        with self.assertRaises(AssertionError):
            stage_report(folder, None)


if __name__ == '__main__':
    unittest.main()
