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


class DriverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.plan = Path(temporary.name) / 'plan.json'
        if BUNDLE.is_dir():
            self.plan.write_text(json.dumps(driver.plan_tool.make_plan('test', BUNDLE)))

    @unittest.skipUnless(BUNDLE.is_dir(), 'requires explicitly prepared local archive bundle')
    def test_default_dry_run_never_loads_remote_modules(self):
        argv = ['run', '--bundle', str(BUNDLE), '--plan', str(self.plan)]
        with patch.object(sys, 'argv', argv), patch.object(driver, 'bind_modules', side_effect=AssertionError('remote modules loaded')), contextlib.redirect_stdout(io.StringIO()) as output:
            driver.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['windows'], 148)
        self.assertFalse(result['remote_access'])

    @unittest.skipUnless(BUNDLE.is_dir(), 'requires explicitly prepared local archive bundle')
    def test_execute_without_qualification_is_rejected_before_remote(self):
        argv = ['run', '--bundle', str(BUNDLE), '--plan', str(self.plan), '--execute']
        with patch.object(sys, 'argv', argv), patch.object(driver, 'execute', side_effect=AssertionError('executed')), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                driver.main()
        self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(BUNDLE.is_dir(), 'requires explicitly prepared local archive bundle')
    def test_changed_schedule_rejected(self):
        plan = json.loads(self.plan.read_text())
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

    def assessment(self, deltas, stage='full118', group='full-udp-mixed', short=False):
        # Isolate the additional CPU-clock gates from the unchanged legacy gate.
        analyze = SimpleNamespace(
            compare=lambda *args, **kwargs: dict(direction='within_variation_or_resolution', discernible=False,
                same_direction_pairs=0, precision_ok=True, relative_change_pct=0, W_pct=0),
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
        return driver.assess({'analyze': analyze, 'short': short}, group, rows, {'mixed-aa': 1.0}, {})

    def test_short_regression_keeps_all_three_pair_directions(self):
        self.assertFalse(self.assessment([-.5, .2, -.1], short=True)['stop_reasons'])
        self.assertIn('three-pair consistent CPU regression',
                      self.assessment([3, 3.2, 2.9], short=True)['stop_reasons'])
        with self.assertRaisesRegex(RuntimeError, 'three complete pairs'):
            self.assessment([3, 3], short=True)

    def test_short_schedule_has_only_four_three_pair_scenes_and_no_extension(self):
        with patch.object(driver.plan_tool, 'verify_bundle', return_value={}):
            plan = driver.plan_tool.make_plan('short', BUNDLE, short=True)
        self.assertEqual(len(plan['schedule']), 26)
        startup, traffic = plan['schedule'][:2], plan['schedule'][2:]
        self.assertEqual(sum(row['cpu_operations'] for row in startup), 10)
        self.assertTrue(all(row['scene'][1] == 'life-startup' and row['scene'][4] == 5 for row in startup))
        self.assertEqual({row['scene'][0] for row in traffic},
                         {'udp-hit', 'udp-miss', 'tcp-hit', 'dhcp-home6'})
        self.assertEqual({row['round'] for row in traffic}, {1, 2, 3})
        self.assertEqual(driver.extension_windows(plan), [])
        with patch.object(driver.plan_tool, 'verify_bundle', return_value={}):
            suffix = driver.plan_tool.make_plan('suffix', BUNDLE, short=True, after_group='full-udp-miss')
        self.assertEqual(len(suffix['schedule']), 12)
        self.assertEqual({row['scene'][0] for row in suffix['schedule']}, {'tcp-hit', 'dhcp-home6'})
        self.assertEqual(suffix['startup_supplement']['total_starts'], 0)

    def test_short_startup_requires_all_five_successful_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'COMPLETE').touch()
            (folder / 'elf.sha256').write_text('abc  dnsmasq\n')
            (folder / 'lifecycle.stderr').write_text('children_cpu_usec=25000 clk_tck=100\n')
            names = ['m6a_loadgen', 'm6a_upstream', 'device_perf_resource_probe', 'device_perf_lifecycle',
                     'safe_v022_full_case.sh', 'safe_v022_group.sh', 'research_cpu_clock_probe']
            (folder / 'tools.sha256').write_text(''.join('abc  /task/' + name + '\n' for name in names))
            values = [dict(index=i, ok=True, mode='startup', hosts=8, initial_leases=6, threads=1,
                           start_ns=i * 10000000, visible_ns=i * 10000000 + 2000000,
                           latency_ns=2000000, fds=8, rss_kib=2000) for i in range(5)]
            analyze = SimpleNamespace(json_lines=lambda p: [json.loads(v) for v in p.read_text().splitlines()],
                                      quantiles=lambda v: dict(p50=statistics.median(v), p95=max(v)))
            ctx = dict(short=True, run=SimpleNamespace(ROOT='/task'), analyze=analyze,
                       research=SimpleNamespace(tool_invalid=lambda *args: False))
            window = dict(scene=['startup-small', 'life-startup', 7, 6, 5, 1000, 150],
                          artifact='candidate', case_kind='full', cpu_operations=5)
            qualification = {'artifacts': {'candidate': {'sha256': 'abc'}},
                             'files': {name: {'sha256': 'abc'} for name in names}}
            for samples, valid in ((values, True), (values[:-1], False),
                                   ([dict(v, ok=False) if i == 2 else v for i, v in enumerate(values)], False)):
                (folder / 'lifecycle.jsonl').write_text(''.join(json.dumps(v) + '\n' for v in samples))
                self.assertEqual(driver.measure_window(ctx, window, folder, 0, qualification)['valid'], valid)

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
