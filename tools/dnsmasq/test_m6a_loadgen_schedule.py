"""Real delayed upstream controls for fixed-rate load generation, localhost only."""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'the existing upstream uses Linux ppoll')
class LoadgenScheduleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        source = Path(__file__).parent
        cls.upstream = cls.build / 'upstream'
        cls.loadgen = Path(os.environ.get('M6A_LOADGEN_TEST_BINARY', cls.build / 'loadgen'))
        builds = [(source / 'm6a_upstream.c', cls.upstream)]
        if 'M6A_LOADGEN_TEST_BINARY' not in os.environ:
            builds.append((source / 'm6a_loadgen.c', cls.loadgen))
        for src, out in builds:
            subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(src), '-o', str(out)], check=True, capture_output=True)

    def run_case(self, mode='udp', warmup=0, duration=.05, rate=100,
                 delay_us=60000, timeout_ms=300, disabled=False, saturation=0):
        artifacts = os.environ.get('M6A_LOADGEN_TEST_ARTIFACTS')
        root = Path(artifacts) if artifacts else self.build
        root.mkdir(parents=True, exist_ok=True)
        folder = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-' + mode + '-', dir=root))
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            udp.bind(('127.0.0.1', port))
        up = [str(self.upstream), '--port', str(port), '--delay-us', str(delay_us),
              '--ttl', '120', '--output', str(folder / 'upstream.json'),
              '--ready-file', str(folder / 'ready'), '--epoch-file', str(folder / 'epoch'),
              '--steady-seconds', str(duration - saturation)]
        if disabled:
            up.append('--disabled')
        command = [str(self.loadgen), '--mode', mode, '--host', '127.0.0.1', '--port', str(port),
                   '--clients', '2', '--warmup-seconds', str(warmup),
                   '--duration-seconds', str(duration), '--rate', str(rate), '--seed', '3',
                   '--profile', 'miss', '--qtype', 'aaaa30', '--cache-names', '800',
                   '--timeout-ms', str(timeout_ms), '--saturation-seconds', str(saturation),
                   '--epoch-file', str(folder / 'epoch'), '--output', str(folder / 'client')]
        (folder / 'commands.json').write_text(json.dumps([up, command], indent=2) + '\n')
        with (folder / 'upstream.stdout').open('wb') as out, (folder / 'upstream.stderr').open('wb') as err:
            server = subprocess.Popen(up, stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 2
            while not (folder / 'ready').exists():
                self.assertIsNone(server.poll(), 'upstream exited before readiness')
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.005)
            result = subprocess.run(command, capture_output=True, timeout=3)
            (folder / 'client.stdout').write_bytes(result.stdout)
            (folder / 'client.stderr').write_bytes(result.stderr)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
            server.wait(timeout=2)
        self.assertEqual(server.returncode, 0)
        data = json.loads((folder / 'client.json').read_text())
        upstream = json.loads((folder / 'upstream.json').read_text())
        rows = list(struct.iter_unpack('<QQQHHBBBB', (folder / 'client.latencies.bin').read_bytes()))
        lags = dict(struct.iter_unpack('<QQ', (folder / 'client.send-lag.bin').read_bytes()))
        self.assertEqual(len(rows), len(lags))
        self.assertEqual({row[0] for row in rows}, set(lags))
        self.assertFalse(data['interrupted'] or data['output_failed'])
        return data, upstream, rows, lags

    def assert_complete(self, data, upstream, warmup, measured):
        for phase, expected in [('warmup', warmup), ('measurement', measured)]:
            counts = data[phase]
            for key in ['scheduled', 'sent', 'correct']:
                self.assertEqual(counts[key], expected, (phase, key, counts))
            for key in ['scheduled_skipped', 'wrong', 'timeout', 'transport_error']:
                self.assertEqual(counts[key], 0, (phase, key, counts))
        self.assertEqual(upstream['total']['requests'], warmup + measured)
        self.assertEqual(upstream['total']['replies'], warmup + measured)

    def test_udp_busy_clients_keep_every_planned_request_after_window(self):
        data, upstream, rows, lags = self.run_case()
        self.assert_complete(data, upstream, 0, 5)
        self.assertEqual({row[0] & 0xffffffff for row in rows}, set(range(1, 6)))
        self.assertEqual(data['measurement']['correct_after_window'], 5)
        self.assertGreater(max(lags.values()), 20_000_000)

    def test_tcp_busy_clients_keep_every_planned_request_after_window(self):
        data, upstream, rows, lags = self.run_case(mode='tcp')
        self.assert_complete(data, upstream, 0, 5)
        self.assertEqual({row[0] & 0xffffffff for row in rows}, set(range(1, 6)))
        self.assertGreater(max(lags.values()), 20_000_000)

    def test_delayed_warmup_keeps_phase_and_planned_query_identity(self):
        data, upstream, rows, lags = self.run_case(warmup=.04, duration=.06)
        self.assert_complete(data, upstream, 4, 6)
        self.assertEqual({row[0] & 0xffffffff for row in rows}, set(range(5, 11)))
        self.assertTrue(all(row[6] == 1 and row[5] == 0 for row in rows))
        self.assertEqual({row[0] & 0xffffffff: row[4] for row in rows},
                         {seq: (1 if ((3 << 32) + seq) % 800 % 10 < 7 else 28)
                          for seq in range(5, 11)})
        self.assertGreater(max(lags.values()), 20_000_000)

    def test_response_timeouts_and_exhausted_dispatch_budget_remain_failures(self):
        data, upstream, rows, _ = self.run_case(disabled=True, timeout_ms=30, rate=200)
        counts = data['measurement']
        self.assertEqual(counts['scheduled'], 10)
        self.assertGreater(counts['timeout'], 0)
        self.assertGreater(counts['scheduled_skipped'], 0)
        self.assertEqual(counts['correct'], 0)
        self.assertEqual(counts['sent'] + counts['scheduled_skipped'], 10)
        self.assertEqual(upstream['total']['replies'], 0)
        self.assertTrue(all(row[5] == 1 for row in rows))
        self.assertLess(data['run_end_ns'] - data['measurement_end_ns'], 200_000_000)

    def test_closed_loop_and_explicit_saturation_keep_existing_path(self):
        for rate, saturation in [(0, 0), (100, .02)]:
            with self.subTest(rate=rate, saturation=saturation):
                data, _, rows, _ = self.run_case(duration=.06, rate=rate,
                                                saturation=saturation, delay_us=1000)
                counts = data['measurement']
                self.assertGreater(counts['sent'], 0)
                self.assertEqual(counts['correct'], counts['sent'])
                self.assertEqual(counts['scheduled_skipped'], 0)
                self.assertTrue(all(row[5] == 0 for row in rows))
                if saturation:
                    self.assertGreater(data['saturation']['sent'], 0)


if __name__ == '__main__':
    unittest.main()
