import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import device_health_baseline as health
from device_health_baseline import complete_prefix, validate_baseline


def encode(rows):
    return b''.join((json.dumps(row) + '\n').encode() for row in rows)


class PrefixHealthTests(unittest.TestCase):
    def fixture(self):
        start = dict(event='start', production_pid=3086, production_starttime=2115, ipv4_default_initial=1)
        sample = dict(event='sample', elapsed_s=0, production_pid=3086, production_starttime=2115,
                      mem_available_kib=90000, ipv4_default=1, dns_ok=1, dns_rtt_ms=.5,
                      http_status=403, http_rtt_ms=50)
        prefix = [start, sample, {**sample, 'elapsed_s': 125}]
        tail = {**sample, 'elapsed_s': 126, 'http_status': 0, 'dns_ok': 0,
                'dns_rtt_ms': 699, 'http_rtt_ms': 43}
        final = prefix + [tail, dict(event='monitor_stopped', elapsed_s=126.044)]
        external = [dict(ip_version=version, exit=0, result='200 0.08') for version in (4, 6)]
        return prefix, final, external

    def verify(self, prefix, final, external, capture=None):
        return validate_baseline(encode(prefix), encode(final), external, [3086, 2115],
                                 encode(prefix) if capture is None else capture)

    def test_valid_pre_stop_prefix_and_cancelled_tail_preserve_scope(self):
        prefix, final, external = self.fixture()
        result = self.verify(prefix, final, external)
        self.assertEqual(result['elapsed_seconds'], 125)
        self.assertEqual(result['dns_p95_ms'], .5)
        self.assertEqual(result['dns_samples'], 2)
        self.assertEqual(result['http_samples'], 2)
        self.assertEqual(result['final_tail_samples'], 1)
        self.assertEqual(result['threshold_ms'], 200)
        partial = encode(final[len(prefix):])[:17]
        capture = encode(prefix) + partial
        self.assertEqual(complete_prefix(capture), encode(prefix))
        self.assertTrue(self.verify(prefix, final, external, capture)['valid'])
        with self.assertRaises(AssertionError):
            self.verify(prefix, final, external, capture[:-1] + b'X')

    def test_http_or_dns_failure_inside_prefix_cannot_be_filtered(self):
        for key, value in [('http_status', 0), ('http_status', 500), ('dns_ok', 0)]:
            prefix, final, external = self.fixture()
            prefix[1][key] = value
            with self.assertRaises(AssertionError):
                self.verify(prefix, final, external)

    def test_any_guard_stop_event_fails_including_after_boundary(self):
        for position in (1, 3):
            prefix, final, external = self.fixture()
            final.insert(position, dict(event='stop', reason='luci_http_failed'))
            with self.assertRaises(AssertionError):
                self.verify(prefix, final, external)

    def test_changed_prefix_or_insufficient_coverage_fails(self):
        prefix, final, external = self.fixture()
        altered = copy.deepcopy(final)
        altered[1]['http_rtt_ms'] = 51
        with self.assertRaises(AssertionError):
            self.verify(prefix, altered, external)
        prefix[-1]['elapsed_s'] = 119.999
        with self.assertRaises(AssertionError):
            self.verify(prefix, final, external)

    def test_tail_identity_memory_route_and_missing_shutdown_still_fail(self):
        for key, value in [('production_pid', 999), ('production_starttime', 999),
                           ('mem_available_kib', 65535), ('ipv4_default', 0)]:
            prefix, final, external = self.fixture()
            final[-2][key] = value
            with self.assertRaises(AssertionError):
                self.verify(prefix, final, external)
        prefix, final, external = self.fixture()
        with self.assertRaises(AssertionError):
            self.verify(prefix, final[:-1], external)

    def test_external_failure_or_threshold_above_original_limit_fails(self):
        prefix, final, external = self.fixture()
        external[0]['exit'] = 28
        with self.assertRaises(AssertionError):
            self.verify(prefix, final, external)
        prefix, final, external = self.fixture()
        prefix[-1]['dns_rtt_ms'] = 70.1
        with self.assertRaises(AssertionError):
            self.verify(prefix, final, external)

    def test_collector_saves_prefix_before_actual_stop_call(self):
        prefix, final, external = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'new-attempt'
            # The standalone producer remains frozen to its original controller;
            # the new full-run consumer must not silently widen that identity.
            frozen = subprocess.check_output(['git', 'show',
                'df511ea2:tools/dnsmasq/perf_opt_device_run.py'], cwd=Path(__file__).resolve().parents[2])
            self.assertEqual(hashlib.sha256(frozen).hexdigest(), health.CONTROLLER_SHA)
            frozen_path = Path(temporary) / 'perf_opt_device_run.py'
            frozen_path.write_bytes(frozen)
            spec = importlib.util.spec_from_file_location('frozen_baseline_run', frozen_path)
            frozen_run = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(frozen_run)
            stopped = False
            def ssh(command, **kwargs):
                if command.startswith('cat ') and command.endswith('.jsonl'):
                    return SimpleNamespace(stdout=encode(final if stopped else prefix), returncode=0)
                return SimpleNamespace(stdout=b'', returncode=0)
            def stop(identity):
                nonlocal stopped
                self.assertEqual((out / 'pre-stop-prefix.jsonl').read_bytes(), encode(prefix))
                self.assertEqual((out / 'pre-stop-capture.raw').read_bytes(), encode(prefix))
                self.assertTrue((out / 'stop-request.json').exists())
                stopped = True
            def external_health(destination, finished, failed):
                (destination / 'external-health.jsonl').write_bytes(encode(external))
            with patch.object(health, 'run', frozen_run), \
                 patch('sys.argv', ['health', '--out', str(out), '--label-prefix', 'test-health']), \
                 patch.object(health.run, 'ssh', side_effect=ssh), \
                 patch.object(health.run, 'production_identity', return_value=[3086, 2115]), \
                 patch.object(health.run, 'guard_start', return_value=(99, 1)), \
                 patch.object(health.run, 'guard_stop', side_effect=stop), \
                 patch.object(health.run, 'external_health', side_effect=external_health), \
                 patch.object(health.time, 'monotonic', side_effect=[0, 125, 125]):
                health.main()
            self.assertTrue(stopped)
            self.assertEqual((out / 'health-baseline.jsonl').read_bytes(), encode(final))
            summary = json.loads((out / 'summary.json').read_text())
            self.assertEqual(summary['http_samples'], 2)
            self.assertEqual(summary['final_tail_samples'], 1)


if __name__ == '__main__':
    unittest.main()
