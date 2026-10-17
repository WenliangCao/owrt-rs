"""Reject missing/extra forwards even when fixed mixed totals cancel out."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from perf_opt_device_run import SCENES, validate


def counters(number):
    return dict(scheduled=number, sent=number, correct=number, timeout=0,
                wrong=0, transport_error=0, scheduled_skipped=0)


class MixedCohortTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.digest = 'a' * 64
        for name in ('COMPLETE', 'elf.sha256', 'live.sha256'):
            (self.folder / name).write_text(self.digest + '\n')
        self.scene = next(s for s in SCENES if s[0] == 'udp-mixed')
        common = dict(mode='udp', clients=32, rate=200, seed=0x293001,
                      qtype='aaaa30', name_prefix='m6a.test', saturation_seconds=0,
                      interrupted=False, output_failed=False)
        self.prewarm = dict(common, profile='hit', warmup_seconds=0, measurement_seconds=5,
                            warmup=counters(0), measurement=counters(1000),
                            warmup_start_ns=1_000_000_000, run_end_ns=6_000_000_000)
        self.load = dict(common, profile='mixed', warmup_seconds=5, measurement_seconds=20,
                         warmup=counters(1000), measurement=counters(4000),
                         warmup_start_ns=7_000_000_000, run_end_ns=32_000_000_000)
        self.up = dict(delay_queue_dropped=0, delay_us=1000, ttl=120,
                       total=dict(requests=1800, replies=1800, invalid_queries=0,
                                  dropped_requests=0, disabled_requests=0,
                                  udp_requests=1800, tcp_requests=0),
                       phases={name: dict(requests=count, replies=count) for name, count in
                               [('setup_warmup', 999), ('steady', 801), ('saturation', 0),
                                ('fault', 0), ('recovery', 0)]},
                       mixed_cohort=dict(schema=1, enabled=True, prefill_unique=800,
                                         warmup_miss_unique=200, measurement_miss_unique=800,
                                         duplicate_queries=0, unexpected_queries=0))

    def errors(self):
        for name, report in (('prewarm', self.prewarm), ('client', self.load), ('upstream', self.up)):
            (self.folder / (name + '.json')).write_text(json.dumps(report))
        return validate(self.folder, self.scene, self.digest)

    def test_exact_named_cohorts_survive_clock_boundary(self):
        self.assertEqual(self.errors(), [])
        self.up['phases']['steady'] = dict(requests=800, replies=800)
        self.up['phases']['saturation'] = dict(requests=1, replies=1)
        self.assertEqual(self.errors(), [])

    def test_original_window_without_cohort_stays_invalid(self):
        del self.up['mixed_cohort']
        self.assertIn('upstream hit/miss count', self.errors())

    def test_missing_miss_and_extra_hit_do_not_cancel(self):
        self.up['mixed_cohort'].update(measurement_miss_unique=799, duplicate_queries=1)
        self.assertIn('upstream mixed cohort count', self.errors())

    def test_wrong_type_or_name_rejected_with_unchanged_total(self):
        self.up['mixed_cohort'].update(measurement_miss_unique=799, unexpected_queries=1)
        self.assertIn('upstream mixed cohort count', self.errors())

    def test_each_cohort_and_audit_identity_is_required(self):
        original = copy.deepcopy(self.up)
        for key in ('prefill_unique', 'warmup_miss_unique', 'measurement_miss_unique', 'schema', 'enabled'):
            with self.subTest(key=key):
                self.up = copy.deepcopy(original)
                self.up['mixed_cohort'][key] = 0
                self.assertIn('upstream mixed cohort count', self.errors())

    def test_missing_extra_forward_or_unanswered_request_rejected(self):
        for requests, replies in ((1799, 1799), (1801, 1801), (1800, 1799)):
            with self.subTest(requests=requests, replies=replies):
                self.up['total'].update(requests=requests, replies=replies)
                self.assertTrue(self.errors())

    def test_client_errors_remain_fatal(self):
        for key in ('wrong', 'timeout', 'transport_error', 'scheduled_skipped'):
            with self.subTest(key=key):
                self.load['measurement'][key] = 1
                self.assertIn('measurement error counters', self.errors())
                self.load['measurement'][key] = 0

    def test_prewarm_errors_or_wrong_shape_rejected(self):
        original = copy.deepcopy(self.prewarm)
        for key, value in (('profile', 'miss'), ('seed', 7), ('qtype', 'a'), ('interrupted', True)):
            with self.subTest(key=key):
                self.prewarm = dict(original, **{key: value})
                self.assertIn('upstream mixed cohort count', self.errors())
        self.prewarm = copy.deepcopy(original)
        self.prewarm['measurement']['scheduled_skipped'] = 1
        self.assertIn('upstream mixed cohort count', self.errors())

    def test_saturation_ttl_expiry_and_phase_incompleteness_rejected(self):
        self.load['saturation_seconds'] = 1
        self.assertIn('upstream mixed cohort count', self.errors())
        self.load['saturation_seconds'] = 0
        self.load['run_end_ns'] = 121_000_000_000
        self.assertIn('upstream mixed cohort count', self.errors())
        self.load['run_end_ns'] = 32_000_000_000
        self.up['phases']['setup_warmup']['replies'] -= 1
        self.assertIn('upstream mixed cohort count', self.errors())


if __name__ == '__main__':
    unittest.main()
