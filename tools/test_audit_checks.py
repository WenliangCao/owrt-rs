#!/usr/bin/env python3
"""Negative tests for gates: dead baselines, incomplete runs and over-masking."""
import json
import contextlib
import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from audit_checks import (interfaces, kernel, lease, mask_session_ids, resources,
                          output_archive, transcript36, transcript41, transcript42, volatile_netifd_path)
import r16_uci_check
import r19_lucirpc_check
import r24_uci_fuzz
import r27_httpd_fuzz
import r28_logd_fuzz

HERE = Path(__file__).resolve().parent


class EvidenceGates(unittest.TestCase):
    def test_uci_missing_outputs_are_not_empty_successes(self):
        step = {f'call.{ext}': b'0\n' if ext == 'rc' else b'' for ext in ('rc', 'out', 'err')}
        self.assertTrue(r16_uci_check.same_step(step, step, 'call'))
        self.assertFalse(r16_uci_check.same_step({}, {}, 'call'))
        for ext in ('rc', 'out', 'err'):
            incomplete = step.copy()
            del incomplete[f'call.{ext}']
            self.assertFalse(r16_uci_check.same_step(incomplete, step, 'call'))
            self.assertFalse(r16_uci_check.same_step(step, incomplete, 'call'))
            self.assertFalse(r16_uci_check.same_step(incomplete, incomplete, 'call'))
        case = {f'fz0000.{j}.{side}.{ext}': b'0\n' if ext == 'rc' else b''
                for j in range(7) for side in ('original', 'candidate') for ext in ('rc', 'out', 'err')}
        self.assertEqual(r24_uci_fuzz.compare_case(case, 'fz0000'), [])
        for side in ('original', 'candidate'):
            incomplete = case.copy()
            del incomplete[f'fz0000.3.{side}.out']
            self.assertTrue(r24_uci_fuzz.compare_case(incomplete, 'fz0000'))
        self.assertTrue(r24_uci_fuzz.compare_case({}, 'fz0000'))
        case['fz0000.2.candidate.rc'] = b'1\n'
        self.assertTrue(r24_uci_fuzz.compare_case(case, 'fz0000'))

    def test_output_archive_preserves_empty_raw_bytes_and_rejects_ambiguous_entries(self):
        def archive(entries):
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as tar:
                for name, data in entries:
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    tar.addfile(entry, io.BytesIO(data))
            return raw.getvalue()
        result = output_archive(archive([('./case.out', b'\xff\x00'), ('./case.err', b'')]))
        self.assertEqual(result, {'case.out': b'\xff\x00', 'case.err': b''})
        for entries in [[('case.out', b'a'), ('./case.out', b'b')],
                        [('../case.out', b'x')], [('nested/case.out', b'x')]]:
            with self.assertRaises(ValueError):
                output_archive(archive(entries))

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

    def test_lucirpc_stats_mask_only_numeric_device_counters(self):
        norm = lambda value: r19_lucirpc_check.normalize('netdev', json.dumps(value).encode())
        base = {'eth0': {'stats': {'rx_bytes': 1, 'unknown': 7}, 'flags': {'multicast': True}}}
        changed = json.loads(json.dumps(base))
        changed['eth0']['stats']['rx_bytes'] = 999
        self.assertEqual(norm(base), norm(changed))
        for value in ('999', True, -1, None):
            changed['eth0']['stats']['rx_bytes'] = value
            self.assertNotEqual(norm(base), norm(changed))
        del changed['eth0']['stats']['rx_bytes']
        self.assertNotEqual(norm(base), norm(changed))
        changed = json.loads(json.dumps(base))
        changed['eth0']['stats']['unknown'] = 8
        self.assertNotEqual(norm(base), norm(changed))
        changed = json.loads(json.dumps(base))
        changed['eth0']['flags']['multicast'] = False
        self.assertNotEqual(norm(base), norm(changed))

    def test_lucirpc_missing_results_are_not_equal(self):
        pair = {f'netdev.{side}.{ext}': b'0\n' if ext == 'rc' else b''
                for side in ('o', 'c') for ext in ('rc', 'out', 'err')}
        self.assertTrue(r19_lucirpc_check.same_pair('netdev', pair))
        for side in ('o', 'c'):
            incomplete = pair.copy()
            del incomplete[f'netdev.{side}.out']
            self.assertFalse(r19_lucirpc_check.same_pair('netdev', incomplete))
        self.assertFalse(r19_lucirpc_check.same_pair('netdev', {}))

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

    def test_two_identical_ubusd_leaks_cannot_pass_the_gate(self):
        text = ''.join(f'--- {n}. case\n' for n in range(1, 17))
        text += ''.join(f'probe{n}_survived: yes\n' for n in range(6))
        text += ('daemon_alive: yes\nlist_rc: 0\nstill_serving: 0\nsession_create: {"sid":MASKED}\n'
                 'fd_delta_since_probe_start: 0\nfd_delta_after_20_clients: 0\n')
        transcript36(text)
        for label in ('since_probe_start', 'after_20_clients'):
            with self.subTest(label=label), self.assertRaises(ValueError):
                transcript36(text.replace(f'fd_delta_{label}: 0', f'fd_delta_{label}: 1'))

    def test_limits_require_real_probes_survival_and_complete_fixture(self):
        text = '--- 1. sizes\n'
        for n in (1048572, 1048576, 1048577, 1048580, 2097152):
            verdict = 'accepted_replied' if n <= 1048576 else 'dropped'
            text += f'size={n} verdict={verdict}\n  bus_alive_after=yes serving=yes\n'
        text += ('--- 2. short\nsize=3 verdict=dropped\n  serving=yes\n'
                 '--- 3. queue\nobjects=200\none_signature_bytes=9000\n'
                 'during: serving=yes call_rc=0\nduring: rss_growth_kib_bounded=yes\n'
                 'after: bus_alive=yes\nafter: serving=yes\nafter: rss_growth_kib_bounded=yes\n'
                 '--- 4. disconnects\nstill_serving=yes\nfd_bounded=yes\nrss_growth_kib_bounded=yes\n')
        transcript41(text)
        for old, new in [('size=3 verdict=dropped', 'size=3 verdict=too small'),
                         ('objects=200', 'objects=0'), ('call_rc=0', 'call_rc=1'),
                         ('after: bus_alive=yes', 'after: bus_alive=no'),
                         ('fd_bounded=yes', 'fd_bounded=no'),
                         ('size=1048576 verdict=accepted_replied', 'size=1048576 verdict=dropped')]:
            with self.subTest(injection=new), self.assertRaises(ValueError):
                transcript41(text.replace(old, new))
        for incomplete in ('', text[:text.index('--- 4.')]):
            with self.assertRaises(ValueError):
                transcript41(incomplete)

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
