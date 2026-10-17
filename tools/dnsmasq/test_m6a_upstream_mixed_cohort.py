"""Exact fixed mixed-cohort accounting through the real UDP/TCP helper."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


BASE = 0x293001 << 32
WARM = [BASE + n for n in range(1, 1001) if (BASE + n) % 5 == 4]
MEASURED = [BASE + n for n in range(1001, 5001) if (BASE + n) % 5 == 4]


def kind(index):
    return 1 if index % 800 % 10 < 7 else 28


def miss(sequence):
    return f'u{sequence:012x}.m6a.test', kind(sequence)


class Upstream:
    def __init__(self, case, binary, folder, enabled=True):
        self.case, self.folder = case, folder
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0))
            self.port = tcp.getsockname()[1]
            udp.bind(('127.0.0.1', self.port))
        ready = folder / 'ready'
        os.mkfifo(ready)
        reader = os.open(ready, os.O_RDONLY | os.O_NONBLOCK)
        self.command = [str(binary), '--port', str(self.port), '--output', str(folder / 'result.json'),
                        '--ready-file', str(ready), '--epoch-file', str(folder / 'epoch')]
        if enabled:
            self.command.append('--audit-fixed-mixed-cohort')
        (folder / 'command.json').write_text(json.dumps(self.command) + '\n')
        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            case.assertTrue(select.select([reader], [], [], 5)[0], 'helper readiness timeout')
            case.assertTrue(json.loads(os.read(reader, 4096))['ready'])
        except BaseException:
            self.process.kill()
            self.process.communicate()
            raise
        finally:
            os.close(reader)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(2)
        self.udp.connect(('127.0.0.1', self.port))
        self.closed = False
        case.addCleanup(self.close)

    def query(self, name, qtype, tcp=False, labels=None, qclass=1, reply=True):
        if labels is None:
            labels = [part.encode() for part in name.split('.')]
        wire = b''.join(bytes([len(part)]) + part for part in labels) + b'\0'
        query = struct.pack('!6H', 7, 0x100, 1, 0, 0, 0) + wire + struct.pack('!HH', qtype, qclass)
        if tcp:
            with socket.create_connection(('127.0.0.1', self.port), timeout=2) as stream:
                stream.sendall(struct.pack('!H', len(query)) + query)
                def read_exact(n):
                    data = b''
                    while len(data) < n:
                        part = stream.recv(n - len(data))
                        self.case.assertTrue(part)
                        data += part
                    return data
                response = read_exact(struct.unpack('!H', read_exact(2))[0])
        else:
            self.udp.send(query)
            if not reply:
                return
            response = self.udp.recv(4096)
        self.case.assertEqual(response[:4], b'\0\7\x81\x80')
        self.case.assertEqual(response[12:len(query)], query[12:])
        return response

    def publish_epoch(self, when=1):
        # FIFO rendezvous ensures the helper reads this exact epoch before
        # processing later packets; no readiness or scheduling sleep loop.
        epoch = self.folder / 'epoch'
        os.mkfifo(epoch)
        with epoch.open('w') as output:
            output.write(str(when) + '\n')

    def close(self):
        if self.closed:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        stdout, stderr = self.process.communicate(timeout=3)
        self.udp.close()
        (self.folder / 'stdout').write_bytes(stdout)
        (self.folder / 'stderr').write_bytes(stderr)
        self.closed = True
        self.case.assertEqual((self.process.returncode, stdout, stderr), (0, b'', b''))

    def finish(self):
        self.close()
        return json.loads((self.folder / 'result.json').read_text())


@unittest.skipUnless(sys.platform.startswith('linux'), 'existing upstream requires Linux ppoll')
class MixedCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(os.environ.get('M6A_UPSTREAM_TEST_ARTIFACTS', cls.temporary.name))
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.binary = Path(os.environ.get('M6A_UPSTREAM_TEST_BINARY', Path(cls.temporary.name) / 'upstream'))
        if 'M6A_UPSTREAM_TEST_BINARY' not in os.environ:
            subprocess.run(['cc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(Path(__file__).with_name('m6a_upstream.c')), '-o', str(cls.binary)],
                           check=True, capture_output=True)

    def server(self, enabled=True):
        folder = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=self.root))
        return Upstream(self, self.binary, folder, enabled)

    def prefill(self, server, count=800):
        for index in range(count):
            server.query(f'q{index:04x}.m6a.test', kind(index))

    def assert_cohort(self, result, prefill=800, warmup=200, measurement=800, duplicates=0, unexpected=0):
        self.assertEqual(result['mixed_cohort'], dict(enabled=True, schema=1, prefill_unique=prefill,
                         warmup_miss_unique=warmup, measurement_miss_unique=measurement,
                         duplicate_queries=duplicates, unexpected_queries=unexpected))

    def test_complete_fixed_cohort(self):
        server = self.server()
        self.prefill(server)
        server.publish_epoch()
        for sequence in WARM + MEASURED:
            server.query(*miss(sequence))
        result = server.finish()
        self.assert_cohort(result)
        self.assertEqual(result['total']['requests'], 1800)
        self.assertEqual(result['total']['replies'], 1800)

    def test_last_warmup_miss_crosses_measurement_epoch(self):
        server = self.server()
        self.prefill(server)
        epoch = time.monotonic_ns() + 500_000_000
        server.publish_epoch(epoch)
        for sequence in WARM[:-1]:
            server.query(*miss(sequence))
        self.assertLess(time.monotonic_ns(), epoch, 'controlled warmup did not finish before boundary')
        # One scheduled boundary wait; no polling or performance observation.
        select.select([], [], [], max(0, (epoch - time.monotonic_ns()) / 1e9) + .01)
        for sequence in WARM[-1:] + MEASURED:
            server.query(*miss(sequence))
        result = server.finish()
        self.assert_cohort(result)
        self.assertEqual(result['phases']['setup_warmup']['requests'], 999)
        self.assertEqual(result['phases']['steady']['requests'], 801)

    def test_duplicate_prefill_cannot_replace_missing_measurement_miss(self):
        server = self.server()
        self.prefill(server)
        server.query('q0000.m6a.test', 1)
        server.publish_epoch()
        for sequence in WARM + MEASURED[:-1]:
            server.query(*miss(sequence))
        result = server.finish()
        self.assert_cohort(result, measurement=799, duplicates=1)
        self.assertEqual(result['total']['requests'], 1800)
        self.assertEqual(result['total']['replies'], 1800)

    def test_late_prefill_cannot_replace_missing_prefill(self):
        server = self.server()
        self.prefill(server, 799)
        server.publish_epoch(time.monotonic_ns() + 60_000_000_000)
        server.query('q031f.m6a.test', kind(799))
        for sequence in WARM + MEASURED:
            server.query(*miss(sequence))
        result = server.finish()
        self.assert_cohort(result, prefill=799, unexpected=1)
        self.assertEqual(result['total']['requests'], 1800)
        self.assertEqual(result['total']['replies'], 1800)

    def test_wrong_kind_range_encoding_transport_and_unpublished_epoch(self):
        server = self.server()
        bad = [('q0000.m6a.test', 28, {}), ('q0320.m6a.test', 1, {}),
               ('q000F.m6a.test', 1, {}), ('q00000.m6a.test', 1, {}),
               ('q0000.M6A.test', 1, {}), ('q0000.m6a.test', 1, {'labels': [b'q0000', b'm6a.test']}),
               (*miss(WARM[0]), {}), ('q0000.m6a.test', 1, {'tcp': True}),
               ('q0000.m6a.test', 1, {'qclass': 3, 'reply': False})]
        for name, qtype, extra in bad:
            server.query(name, qtype, **extra)
        server.query('q0001.m6a.test', 1)  # Successful response also drains the malformed request.
        server.publish_epoch()
        server.query(*miss(WARM[0]))
        server.query(*miss(WARM[0]))
        bad_after = [(miss(WARM[0])[0], 28 if kind(WARM[0]) == 1 else 1, {}),
                     (*miss(BASE), {}), (*miss(BASE + 5001), {}),
                     (f'u{BASE + 1:012x}.m6a.test', kind(BASE + 1), {}),
                     (f'u0{WARM[0]:012x}.m6a.test', kind(WARM[0]), {}),
                     (*miss(WARM[1]), {'tcp': True})]
        self.assertNotEqual((BASE + 1) % 5, 4)
        for name, qtype, extra in bad_after:
            server.query(name, qtype, **extra)
        result = server.finish()
        self.assert_cohort(result, prefill=1, warmup=1, measurement=0, duplicates=1,
                           unexpected=len(bad) + len(bad_after))
        self.assertEqual(result['total']['invalid_queries'], 1)

    def test_disabled_flag_preserves_original_output_and_answers(self):
        answers = []
        for enabled in [False, True]:
            server = self.server(enabled)
            replies = [server.query('q0000.m6a.test', 1)]
            server.publish_epoch()
            replies.append(server.query(*miss(WARM[0])))
            result = server.finish()
            self.assertEqual('mixed_cohort' in result, enabled)
            if enabled:
                self.assert_cohort(result, prefill=1, warmup=1, measurement=0)
            else:
                self.assertEqual(set(result), {'schema', 'epoch_ns', 'disabled', 'total', 'delay_us', 'ttl',
                    'delay_queue_dropped', 'requests', 'disabled_requests', 'invalid_queries', 'phases'})
            answers.append(replies)
        self.assertEqual(*answers)

    def test_flag_requires_epoch_file(self):
        result = subprocess.run([str(self.binary), '--audit-fixed-mixed-cohort', '--output', 'unused',
                                 '--ready-file', 'unused'], capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
