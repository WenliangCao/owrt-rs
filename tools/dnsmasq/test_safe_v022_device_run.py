"""Local failure-boundary tests; no device, network, SDK or product execution."""
import contextlib
import io
import json
from pathlib import Path
import statistics
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import safe_v022_device_run as driver


REPO = Path(__file__).resolve().parents[2]
BUNDLE = REPO / 'private/device-v022-tool-recovery-20261017'
PLAN = REPO / 'private/device-v022-preparation/batch-plan-v2.json'


class DriverTests(unittest.TestCase):
    @unittest.skipUnless(BUNDLE.is_dir() and PLAN.is_file(), 'requires explicitly prepared local archive bundle')
    def test_default_dry_run_never_loads_remote_modules(self):
        argv = ['run', '--bundle', str(BUNDLE), '--plan', str(PLAN)]
        with patch.object(sys, 'argv', argv), patch.object(driver, 'bind_modules', side_effect=AssertionError('remote modules loaded')), contextlib.redirect_stdout(io.StringIO()) as output:
            driver.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['windows'], 148)
        self.assertFalse(result['remote_access'])

    @unittest.skipUnless(BUNDLE.is_dir() and PLAN.is_file(), 'requires explicitly prepared local archive bundle')
    def test_execute_without_qualification_is_rejected_before_remote(self):
        argv = ['run', '--bundle', str(BUNDLE), '--plan', str(PLAN), '--execute']
        with patch.object(sys, 'argv', argv), patch.object(driver, 'execute', side_effect=AssertionError('executed')), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                driver.main()
        self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(BUNDLE.is_dir() and PLAN.is_file(), 'requires explicitly prepared local archive bundle')
    def test_changed_schedule_rejected(self):
        plan = json.loads(PLAN.read_text())
        plan['schedule'][0]['scene'][5] += 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'plan.json'; path.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, 'plan differs'):
                driver.load_plan(path, BUNDLE)

    def test_health_failure_stops_owned_group_and_archives_before_raise(self):
        events = []; checks = iter([True, False]); boot = '00000000-0000-0000-0000-000000000001'
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            def ssh(command, **kwargs):
                self.assertNotIn('rm ', command)
                return SimpleNamespace(stdout=(boot + '\n').encode(), returncode=0)
            def archive(destination, label):
                events.append('archive')
                folder = destination / 'runs' / label; folder.mkdir(parents=True)
                (folder / 'partial').write_text('retained')
                return folder
            def write(path, value):
                path.write_text(json.dumps(value))
            run = SimpleNamespace(ROOT=driver.plan_tool.ROOT, ssh=ssh,
                production_identity=lambda: [101, 42], guard_check=lambda identity: next(checks),
                stop_owned=lambda reason: events.append('stop-owned'), archive_run=archive, write=write)
            process = SimpleNamespace(poll=iter([None, 0]).__next__, returncode=255)
            ctx = dict(run=run, out=out, identity=[101, 42], boot=boot, guard=(123, 5),
                failed=SimpleNamespace(is_set=lambda: False, wait=lambda seconds: False),
                archived=set(), research=SimpleNamespace(clear_exited_group=lambda: events.append('clear')))
            with patch.object(driver.subprocess, 'Popen', return_value=process):
                with self.assertRaisesRegex(RuntimeError, 'health/guard'):
                    driver.execute_owned_group(ctx, 'failed-r1-c', 'safe_v022_group.sh',
                        ['full', 'c', 'failed-r1-c', 'udp', 'hit', '200', '5', '45', '150'], 100)
            self.assertEqual(events, ['stop-owned', 'archive'])
            self.assertTrue((out / 'runs/failed-r1-c/partial').exists())
            self.assertTrue(json.loads((out / 'failed-r1-c.failure.json').read_text())['archived'])

    def dual_fixture(self, folder):
        counts = dict(scheduled=1000, sent=1000, correct=1000, timeout=0, wrong=0, transport_error=0, scheduled_skipped=0)
        for index, (prefix, qtype, code) in enumerate([('prewarm-a', 'a', 1), ('prewarm', 'aaaa', 28)]):
            report = dict(mode='udp', profile='hit', qtype=qtype, name_prefix='m6a.example',
                seed=0x293001, rate=200, warmup_seconds=0, measurement_seconds=5,
                interrupted=False, output_failed=False, measurement=counts,
                warmup_start_ns=(1 + 5 * index) * 10**9, run_end_ns=(6 + 5 * index) * 10**9)
            (folder / (prefix + '.json')).write_text(json.dumps(report))
            first = (0x293001 << 32) + 1
            (folder / (prefix + '.latencies.bin')).write_bytes(b''.join(
                struct.pack('<QQQHHBBBB', first + i, 100, 100, 0, code, 0, 1, 0, 0) for i in range(1000)))
        (folder / 'client.json').write_text(json.dumps(dict(qtype='aaaa30', name_prefix='m6a.example',
            seed=0x293001, warmup_start_ns=11 * 10**9, run_end_ns=111 * 10**9)))
        (folder / 'upstream.json').write_text(json.dumps(dict(ttl=120, total=dict(requests=800, replies=800),
            phases={name: dict(requests=800 if name == 'setup_warmup' else 0)
                    for name in ('setup_warmup', 'steady', 'saturation', 'fault', 'recovery')})))

    def test_dual_rejects_bad_family_stale_window_and_extra_forward(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary); self.dual_fixture(folder)
            self.assertEqual(driver.dual_errors(folder), [])
            for filename, mutate in [
                ('prewarm-a.json', lambda value: value.update(qtype='aaaa')),
                ('client.json', lambda value: value.update(run_end_ns=121 * 10**9)),
                ('upstream.json', lambda value: value['phases']['steady'].update(requests=1)),
            ]:
                original = (folder / filename).read_bytes()
                value = json.loads(original); mutate(value)
                (folder / filename).write_text(json.dumps(value))
                self.assertTrue(driver.dual_errors(folder), filename)
                (folder / filename).write_bytes(original)
            records = (folder / 'prewarm-a.latencies.bin').read_bytes()
            (folder / 'prewarm-a.latencies.bin').write_bytes(records[:32] + records[:32] + records[64:])
            self.assertTrue(driver.dual_errors(folder))

    def test_replacements_keep_original_pairs_and_chronology(self):
        rows = [dict(round=n, side=side, valid=True, execution_index=len(range(n)) * 2 + index)
                for n in (1, 2) for index, side in enumerate(('c', 'rust'))]
        rows[0]['valid'] = False
        rows += [dict(round=1, side=side, valid=True, attempt=1, execution_index=5 + index)
                 for index, side in enumerate(('c', 'rust'))]
        selected = driver.selected_pairs(rows)
        self.assertEqual([row.get('attempt', 0) for row in selected[0]], [1, 1])
        self.assertEqual(len(rows), 6)
        self.assertFalse(rows[0]['valid'])

    def assessment(self, deltas, stage='full118', group='full-udp-mixed'):
        # Isolate the additional CPU-clock gates from the unchanged legacy gate.
        analyze = SimpleNamespace(
            compare=lambda *args, **kwargs: dict(direction='within_variation_or_resolution', discernible=False, same_direction_pairs=0),
            spread=lambda values: dict(median=statistics.median(values), rounds=values))
        rows = []
        for number, delta in enumerate(deltas, 1):
            for side in ('c', 'rust'):
                measurement = dict(latency_ms=dict(p50=.1, p95=.2), cpu_us_per_operation=100,
                    cpu_ticks=50, tree_fd_peak=12, parent_fd_peak=12,
                    cpu_clock=dict(cpu_us_per_operation=100 + (delta if side == 'rust' else 0)),
                    clock_endpoint_resolution_us_per_op=.000001)
                rows.append(dict(round=number, side=side, valid=True, stage=stage,
                    scene=['udp-mixed', 'udp', 'mixed', 200, 5, 20, 150],
                    execution_index=len(rows) + 1, measurement=measurement))
        return driver.assess({'analyze': analyze}, group, rows, {'mixed-aa': 1.0}, {})

    def test_only_five_positive_small_deltas_trigger_fixed_extension(self):
        self.assertFalse(self.assessment([3, 3, 3, 3, -.1])['extend_mixed'])
        result = self.assessment([3, 3, 3, 3, 3])
        self.assertTrue(result['extend_mixed'])
        self.assertEqual(result['stop_reasons'], [])
        large = self.assessment([6, 6, 6, 6, 6])
        self.assertFalse(large['extend_mixed'])
        self.assertTrue(large['stop_reasons'])

    def test_four_us_noise_and_nine_pair_regression_require_review(self):
        noisy = self.assessment([4, -1], stage='calibration', group='mixed-aa')
        self.assertTrue(noisy['stop_reasons'])
        nine = self.assessment([3] * 9)
        self.assertEqual(nine['d2_d8_us'], [3, 3])
        self.assertEqual(nine['three_block_medians_us'], [3, 3, 3])
        self.assertIn('nine-pair CPU-clock regression', nine['stop_reasons'])


if __name__ == '__main__':
    unittest.main()
