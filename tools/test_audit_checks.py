#!/usr/bin/env python3
"""Negative tests for gates: dead baselines, incomplete runs and over-masking."""
import json
import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from audit_checks import (interfaces, kernel, lease, mask_session_ids, resources,
                          transcript36, transcript42, volatile_netifd_path)
import r19_lucirpc_check
import r27_httpd_fuzz
import r28_logd_fuzz

HERE = Path(__file__).resolve().parent


class EvidenceGates(unittest.TestCase):
    def test_multicast_configuration_is_compared(self):
        self.assertFalse(volatile_netifd_path('devices.eth0.multicast'))
        self.assertTrue(volatile_netifd_path('devices.eth0.statistics.multicast'))
        self.assertFalse(volatile_netifd_path('interface dump.lan.data.uptime'))
        self.assertTrue(volatile_netifd_path('interface dump.lan.uptime'))
        norm = lambda flag, counter: r19_lucirpc_check.normalize('netdev', json.dumps({
            'eth0': {'flags': {'multicast': flag}, 'statistics': {'multicast': counter}}
        }).encode())
        self.assertNotEqual(norm(True, 1), norm(False, 1))
        self.assertEqual(norm(True, 1), norm(True, 999))

    def test_md5_is_compared_while_session_ids_are_masked(self):
        norm = lambda md5, sid: mask_session_ids(json.dumps({'md5': md5, 'ubus_rpc_session': sid}))
        self.assertNotEqual(norm('1' * 32, 'a' * 32), norm('2' * 32, 'b' * 32))
        self.assertEqual(norm('1' * 32, 'a' * 32), norm('1' * 32, 'b' * 32))

    def test_non_utf8_log_bytes_remain_distinct(self):
        norm = lambda data: r28_logd_fuzz.norm_logread(data.decode(errors='surrogateescape'))
        self.assertNotEqual(norm(b'payload\xff'), norm(b'payload\xfe'))

    def test_http_body_differences_after_2000_bytes_are_compared(self):
        def normalized(tail):
            body = json.dumps({'payload': 'x' * 3000 + tail}).encode()
            return r27_httpd_fuzz.normalize(b'HTTP/1.1 200 OK\r\n\r\n' + body, True)
        self.assertNotEqual(normalized('a'), normalized('b'))

    def test_http_two_dead_servers_are_not_a_pass(self):
        with patch.object(r27_httpd_fuzz, 'cases', return_value=[{'id': 'probe'}]), \
             patch.object(r27_httpd_fuzz, 'run_side', return_value=({'probe': {'alive_after': False}}, '')), \
             patch.object(sys, 'argv', ['r27', '--rootfs', '/unused', '--candidate', '/unused']), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(r27_httpd_fuzz.main(), 1)
        self.assertIn('survival_failures=2', output.getvalue())

    def test_both_dead_empty_and_no_lease_are_rejected(self):
        for text in ('', '{}', 'Failed to connect to ubus', '{"interface":[]}'):
            with self.assertRaises(ValueError):
                interfaces(text)
        for text in ('', '--- ip addr\n', 'Failed to connect to ubus'):
            with self.assertRaises(ValueError):
                kernel(text)
        for text in ('{}', '{"up":false}', '{"up":true,"ipv4-address":[]}'):
            with self.assertRaises(ValueError):
                lease(text)

    def test_cycles_fail_on_skipped_work_leaks_and_failed_calls(self):
        text = ('before rss_kb=1000 fds=10 threads=1\ncycles: 200\nfailed calls: 0\n'
                'after rss_kb=1010 fds=10 threads=1\nalive: yes\n')
        resources(text, 200)
        for old, new in [('cycles: 200', 'cycles: 0'), ('failed calls: 0', 'failed calls: 1'),
                         ('alive: yes', 'alive: no'), ('after rss_kb=1010', 'after rss_kb=3000'),
                         ('after rss_kb=1010 fds=10', 'after rss_kb=1010 fds=11'),
                         ('threads=1\nalive', 'threads=2\nalive')]:
            with self.subTest(injection=new), self.assertRaises(ValueError):
                resources(text.replace(old, new), 200)

    def test_dead_or_truncated_ubusd_transcripts_are_rejected(self):
        with self.assertRaises(ValueError):
            transcript36('daemon_alive: no\n')
        with self.assertRaises(ValueError):
            transcript42('survived: no\n')
        with self.assertRaises(ValueError):
            transcript42('survived: yes\nfinal objects unchanged: yes\nfinal serving: 0\nfinal fd bounded: yes\n')

    def run_embedded(self, script, args):
        code = re.findall(r"<<'PY'[^\n]*\n(.*?)\nPY", (HERE / script).read_text(), re.S)[0]
        return subprocess.run([sys.executable, '-', *map(str, args)], input=code, text=True,
                              capture_output=True, env={**os.environ, 'PYTHONPATH': str(HERE)})

    def test_r55_compares_return_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = [Path(directory) / name for name in ('c', 'rs')]
            fixture = '===== method\n--- call\n--- status\n0\n--- interface dump\n{"interface":[]}\n'
            a.write_text(fixture)
            b.write_text(fixture)
            self.assertEqual(self.run_embedded('r55_writemethods_diff.sh', [a, b]).returncode, 0)
            b.write_text(fixture.replace('status\n0', 'status\n6'))
            self.assertEqual(self.run_embedded('r55_writemethods_diff.sh', [a, b]).returncode, 1)

    def test_r59_rejects_two_missing_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'c.status').write_text('FAILED\n')
            (p / 'c.validate').write_text('FAILED\n')
            (p / 'rs.raw').write_text('{}\n')
            result = self.run_embedded('r59_wireless_diff.sh', [p / 'c', p / 'rs', 'A'])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('invalid/missing reply', result.stderr)

    def test_r09_zero_cases_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'tests').mkdir()
            result = subprocess.run([sys.executable, str(HERE / 'r09_fw4_check.py'), directory, '/bin/false'],
                                    capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_abi_without_sdk_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['sh', str(HERE / 'check_abi.sh')], capture_output=True,
                                    env={**os.environ, 'SDK': directory})
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
