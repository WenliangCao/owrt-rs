"""Local controls for the next-version miss cohort validator; no device access."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from perf_opt_device_run import SCENES, validate


class MissCohortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.digest = 'a' * 64
        for name, body in [('COMPLETE', 'complete\n'), ('elf.sha256', self.digest + ' elf\n'),
                           ('live.sha256', self.digest + ' live\n')]:
            (self.folder / name).write_text(body)
        self.scene = next(scene for scene in SCENES if scene[0] == 'udp-miss')
        def counts(number):
            return dict(scheduled=number, sent=number, correct=number,
                        timeout=0, wrong=0, transport_error=0, scheduled_skipped=0,
                        correct_in_window=number, correct_after_window=0)
        self.load = dict(mode='udp', profile='miss', saturation_seconds=0,
                         interrupted=False, output_failed=False,
                         warmup=counts(1000), measurement=counts(4000))
        self.upstream = dict(delay_queue_dropped=0,
            total=dict(requests=5000, replies=5000, invalid_queries=0,
                       dropped_requests=0, disabled_requests=0),
            phases={name: dict(requests=number, replies=number) for name, number in
                    [('setup_warmup', 1000), ('steady', 4000), ('saturation', 0),
                     ('fault', 0), ('recovery', 0)]})

    def errors(self):
        (self.folder / 'client.json').write_text(json.dumps(self.load))
        (self.folder / 'upstream.json').write_text(json.dumps(self.upstream))
        return validate(self.folder, self.scene, self.digest)

    def boundary_counts(self, before_start=0, after_start=0, before_end=0, after_end=0):
        # Same initiated request cohorts; only upstream processing timestamps move.
        phases = self.upstream['phases']
        for name, count in [('setup_warmup', 1000 + before_start - after_start),
                            ('steady', 4000 - before_start + after_start + before_end - after_end),
                            ('saturation', after_end - before_end)]:
            phases[name] = dict(requests=count, replies=count)

    def test_exact_in_window_control(self):
        self.assertEqual(self.errors(), [])

    def test_measurement_request_processed_after_end_is_not_lost(self):
        self.boundary_counts(after_end=1)
        self.load['measurement'].update(correct_in_window=3999, correct_after_window=1)
        self.assertEqual(self.errors(), [])

    def test_warmup_request_processed_after_start_stays_in_total(self):
        self.boundary_counts(after_start=1)
        self.assertEqual(self.errors(), [])

    def test_both_boundaries_can_cross_without_count_tolerance(self):
        self.boundary_counts(after_start=2, after_end=3)
        self.load['measurement'].update(correct_in_window=3997, correct_after_window=3)
        self.assertEqual(self.errors(), [])

    def test_reply_only_crosses_end(self):
        self.load['measurement'].update(correct_in_window=3999, correct_after_window=1)
        self.assertEqual(self.errors(), [])

    def test_tcp_miss_uses_the_same_cohort_rule(self):
        self.scene = next(scene for scene in SCENES if scene[0] == 'tcp-miss')
        self.load['mode'] = 'tcp'
        self.boundary_counts(after_end=1)
        self.assertEqual(self.errors(), [])

    def test_missing_or_extra_upstream_forward_rejected(self):
        for count in [4999, 5001]:
            with self.subTest(count=count):
                self.upstream['total'].update(requests=count, replies=count)
                self.assertIn('upstream miss cohort count', self.errors())

    def test_client_skip_wrong_timeout_and_transport_error_rejected(self):
        original = copy.deepcopy(self.load)
        for key in ['scheduled_skipped', 'wrong', 'timeout', 'transport_error']:
            with self.subTest(counter=key):
                self.load = copy.deepcopy(original)
                self.load['measurement'][key] = 1
                self.load['measurement']['correct'] = 3999
                self.assertIn('measurement error counters', self.errors())
                self.assertIn('measurement completion count', self.errors())

    def test_upstream_error_and_unanswered_request_rejected(self):
        original = copy.deepcopy(self.upstream)
        for key in ['invalid_queries', 'dropped_requests', 'disabled_requests']:
            with self.subTest(counter=key):
                self.upstream = copy.deepcopy(original)
                self.upstream['total'][key] = 1
                self.assertIn('upstream completeness', self.errors())
        self.upstream = copy.deepcopy(original)
        self.upstream['total']['replies'] = 4999
        self.assertIn('upstream completeness', self.errors())

    def test_fault_recovery_or_unexpected_prewarm_rejected(self):
        for phase in ['fault', 'recovery']:
            with self.subTest(phase=phase):
                self.upstream['phases'][phase]['requests'] = 1
                self.assertIn('upstream miss cohort count', self.errors())
                self.upstream['phases'][phase]['requests'] = 0
        (self.folder / 'prewarm.json').write_text('{}')
        self.assertIn('upstream miss cohort count', self.errors())

    def test_actual_saturation_retains_old_phase_rule(self):
        self.load['saturation_seconds'] = 1
        self.boundary_counts(after_end=1)
        self.assertIn('upstream hit/miss count', self.errors())

    def test_hit_and_mixed_retain_exact_steady_checks(self):
        for profile, expected in [('hit', 0), ('mixed', 800)]:
            with self.subTest(profile=profile):
                self.scene = next(s for s in SCENES if s[0] == 'udp-' + profile)
                self.load['profile'] = profile
                self.upstream['phases']['steady']['requests'] = expected
                self.assertEqual(self.errors(), [])
                self.upstream['phases']['steady']['requests'] = expected + 1
                self.assertIn('upstream hit/miss count', self.errors())


if __name__ == '__main__':
    unittest.main()
