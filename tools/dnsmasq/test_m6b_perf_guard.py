#!/usr/bin/env python3
"""Offline guard negative controls; synthetic samples are never qualification."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import m6b_perf_guard as guard
import m6a_window as window
import m6a_analyze as analyze
import m5_final_validation as final
from dns_service_probe import query

SHA = 'a' * 64


def write(path, value):
    path.write_text(json.dumps(value))


class GuardInputs(unittest.TestCase):
    def test_guard_rejects_s_even_when_elf_and_feature_identity_match(self):
        product = {'kind': 'release', 'features': '', 'opt_level': '3',
                   'artifacts': [{'path': 'dnsmasq-rs', 'sha256': SHA, 'bytes': 1234}]}
        guard.verify_release_build(product, SHA, 1234)
        variants = [dict(product, opt_level=level) for level in ['s', 'z', 3, None]]
        variants += [dict(product, features='m6b-diagnostics'), dict(product, kind='tests')]
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                guard.verify_release_build(variant, SHA, 1234)
        with self.assertRaises(ValueError): guard.verify_release_build(product, 'b'*64, 1234)
        with self.assertRaises(ValueError): guard.verify_release_build(product, SHA, 1235)

    def fixture(self, root):
        tools = root / 'tools'; tools.mkdir()
        native = {'tools_files': {}, 'native': {}}
        for name in ('m6a_loadgen', 'm6a_upstream'):
            source = tools / (name + '.c'); source.write_text('frozen fixture source ' + name)
            binary = root / name; binary.write_bytes(b'prebuilt fixture ' + name.encode())
            native['tools_files'][name + '.c'] = guard.sha256(source)
            native['native'][name] = {'path': str(binary), 'sha256': guard.sha256(binary)}
        manifest = root / 'native.json'; write(manifest, native)
        plan = {'schema': 1, 'frozen': True, 'basis': 'synthetic negative-control fixture',
                'thresholds': {'udp_p50_max_ns': 1_000_000, 'idle_cpu_max_seconds': 0.1, 'tcp_peak_pss_max_kib': 7000},
                'native_manifest': {'path': str(manifest), 'sha256': guard.sha256(manifest)}}
        path = root / 'plan.json'; write(path, plan)
        return tools, path, plan

    def test_no_default_or_null_threshold_can_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            tools, path, plan = self.fixture(Path(directory))
            guard.inputs(path, tools)
            for limits in ({}, {**plan['thresholds'], 'idle_cpu_max_seconds': None},
                           {**plan['thresholds'], 'tcp_peak_pss_max_kib': True},
                           {**plan['thresholds'], 'udp_p50_max_ns': 1_000_001}):
                altered = {**plan, 'thresholds': limits}; write(path, altered)
                with self.subTest(limits=limits), self.assertRaises(ValueError):
                    guard.inputs(path, tools)

    def test_native_source_and_elf_hashes_are_both_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tools, path, plan = self.fixture(root)
            _, _, assets = guard.inputs(path, tools)
            self.assertIn(str(path.resolve()), assets)
            original = (root / 'm6a_loadgen').read_bytes()
            (root / 'm6a_loadgen').write_bytes(b'changed native')
            with self.assertRaises(ValueError): guard.inputs(path, tools)
            # Rehashing a changed helper manifest cannot hide different source.
            (root / 'm6a_loadgen').write_bytes(original)
            source = tools / 'm6a_upstream.c'; source.write_text('different workload')
            with self.assertRaises(ValueError): guard.inputs(path, tools)

    def test_guard_command_uses_disjoint_affinity_and_never_traces(self):
        args = SimpleNamespace(elf=Path('/elf'), expected_elf_sha=SHA, image_root=Path('/image'))
        native = {name: {'path': '/' + name} for name in ('m6a_loadgen', 'm6a_upstream')}
        for profile in ('udp-hit', 'tcp-cache'):
            cmd = guard.window_command(args, native, profile, Path('/private/new'))
            self.assertEqual(cmd[cmd.index('--clients') + 1], '20')
            self.assertEqual(cmd[cmd.index('--idle-seconds') + 1], '60' if profile == 'udp-hit' else '0')
            self.assertEqual(cmd[cmd.index('--cpu-daemon') + 1], '0')
            self.assertEqual(cmd[cmd.index('--cpu-control') + 1], '3')
            self.assertNotIn('--wake-metrics', cmd); self.assertNotIn('--perf-record', cmd)
            self.assertNotIn('--strace-summary', cmd)
            self.assertEqual('--perf-guard-tcp-hold' in cmd, profile == 'tcp-cache')


class HeldTcpEvidence(unittest.TestCase):
    def test_twenty_correct_streams_are_sampled_while_live_and_always_closed(self):
        class Endpoint:
            def sendall(self, framed):
                reply = window.answer(framed[2:])
                self.pending = len(reply).to_bytes(2, 'big') + reply
            def recv(self, length):
                result, self.pending = self.pending[:length], self.pending[length:]
                return result
            def close(self):
                self.closed = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); endpoints = [Endpoint() for _ in range(20)]
            before = {'tree': {'fd_count': 10}}
            held = {'tree': {'fd_count': 30, 'child_processes': 0}}
            with patch.object(window, 'process_tree', return_value=before), \
                    patch.object(window.socket, 'create_connection', side_effect=endpoints), \
                    patch.object(window, 'snapshot', return_value=held), \
                    patch.object(window, 'wait_for_drain', return_value={'observations': []}):
                result = window.guard_tcp_hold(123, root)
            self.assertTrue(result['complete']); self.assertEqual(len(result['replies']), 20)
            self.assertTrue(all(item['correct'] for item in result['replies']))
            self.assertTrue(all(endpoint.closed for endpoint in endpoints))
            self.assertTrue((root / 'tcp-hold-drain.json').exists())


class GuardEvidence(unittest.TestCase):
    def fixture(self, path, profile):
        path.mkdir()
        counters = {'correct': 1000, 'sent': 1000, 'wrong': 0, 'timeout': 0, 'transport_error': 0}
        load = {'warmup': dict(counters), 'measurement': dict(counters),
                'measurement_start_ns': 1_000_000_000, 'measurement_end_ns': 11_000_000_000}
        write(path / 'load.json', load)
        resources = [{'measurement_elapsed_seconds': index, 'parent': {'affinity': [0]},
                      'tree': {'pss_kib': 6000 + index, 'thread_count': 1, 'child_processes': 0}}
                     for index in range(10)]
        write(path / 'resources.json', resources)
        result = {'measurement_valid': True, 'accepted': True,
                  'identity': {'expected_elf_sha256': SHA, 'implementation': 'r3', 'clients': 20,
                               'warmup_seconds': 2, 'duration_seconds': 10, 'rate': 10000,
                               'saturation_seconds': 0, 'scenario': 'hit' if profile == 'udp-hit' else 'tcp',
                               'tcp_profile': 'hit', 'wake_metrics': False, 'perf_record': False, 'strace_summary': False,
                               'perf_guard_tcp_hold': profile == 'tcp-cache',
                               'cpus': {'daemon': 0, 'upstream': 1, 'loadgen': 2, 'control': 3}},
                  'cleanup': {'returncode': 0, 'forced_kill': False},
                  'measurement': {'quality': {'sample_count_passed': True}, 'load': load, 'peaks': {'pss_kib': 6009},
                                  'idle_cpu': {'enabled': True, 'requested_seconds': 60, 'elapsed_seconds': 60.01,
                                               'cgroup_before': {'path': '/same', 'usage_usec': 100},
                                               'cgroup_after': {'path': '/same', 'usage_usec': 80100}, 'cpu_seconds': .08}},
                  'upstream': {'disabled_requests': 0, 'invalid_queries': 0}}
        host = 'q0000.m6a.test'; request = query(host, 1, 123); reply = window.answer(request)
        held_tree = {'fd_count': 30, 'child_processes': 0, 'thread_count': 1, 'pss_kib': 6100}
        result['tcp_hold_20'] = {'complete': True, 'clients': 20, 'before': {'tree': {'fd_count': 10}},
                                 'held': {'tree': held_tree}, 'replies': [
                                     {'correct': True, 'query': request.hex(), 'reply': reply.hex()} for _ in range(20)]}
        write(path / 'result.json', result)
        write(path / 'cache-proof.json', {'capacity': 4096, 'ttl': 3600, 'upstream_disabled': True,
                                         'filled_names': 4096, 'validated_names': 4096,
                                         'rows': [{'correct': True} for _ in range(4096)]})
        with (path / 'load.latencies.bin').open('wb') as stream:
            for index in range(1000):
                stream.write(analyze.LATENCY.pack(index, 500000, 2_000_000_000 + index * 1000,
                                                  index % 20, 1, 0, 1, 0, 0))
        sample = {'phase': 1, 'correct': True, 'query_hex': request.hex(), 'reply_hex': reply.hex()}
        (path / 'load.wire-samples.jsonl').write_text(''.join(json.dumps(sample) + '\n' for _ in range(10)))
        return result

    def test_valid_observations_use_binary_latency_cgroup_delta_and_held_pss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root / 'udp', 'udp-hit'); self.fixture(root / 'tcp', 'tcp-cache')
            udp = guard.assess_window(root / 'udp', 'udp-hit', SHA)
            tcp = guard.assess_window(root / 'tcp', 'tcp-cache', SHA)
            self.assertEqual(udp['p50_ns'], 500000); self.assertEqual(udp['idle_cpu_seconds'], .08)
            self.assertEqual(tcp['peak_pss_kib'], 6100)
            checks = guard.classify({'udp-hit': udp, 'tcp-cache': tcp},
                                    {'udp_p50_max_ns': 1_000_000, 'idle_cpu_max_seconds': .1, 'tcp_peak_pss_max_kib': 6000})
            self.assertFalse(checks['tcp_peak_pss_max_kib']['passed'])

    def test_missing_idle_or_short_idle_or_counter_mismatch_is_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'udp'; original = self.fixture(path, 'udp-hit')
            for mutation in ('missing', 'short', 'fake_cpu'):
                result = copy.deepcopy(original)
                if mutation == 'missing': result['measurement'].pop('idle_cpu')
                elif mutation == 'short': result['measurement']['idle_cpu']['elapsed_seconds'] = 10
                else: result['measurement']['idle_cpu']['cpu_seconds'] = 0
                write(path / 'result.json', result)
                with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                    guard.assess_window(path, 'udp-hit', SHA)

    def test_wrong_answers_missing_samples_and_19_connection_proof_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / 'tcp'; original = self.fixture(path, 'tcp-cache')
            for mutation in ('wrong', 'no_latency', 'nineteen'):
                result = copy.deepcopy(original)
                if mutation == 'wrong': result['measurement']['load']['measurement']['wrong'] = 1
                elif mutation == 'nineteen': result['tcp_hold_20']['held']['tree']['fd_count'] = 29
                write(path / 'result.json', result)
                data = (path / 'load.latencies.bin').read_bytes()
                if mutation == 'no_latency': (path / 'load.latencies.bin').write_bytes(b'')
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    guard.assess_window(path, 'tcp-cache', SHA)
                (path / 'load.latencies.bin').write_bytes(data)

    def test_phase_command_binds_threshold_hash_product_hash_and_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); plan = root / 'frozen.json'; plan.write_text('frozen fixture')
            spec = {'validation_mode': 'm6b', 'perf_guard_plan': str(plan), 'source_root': '/source',
                    'runtime_root': '/runtime', 'image_root': '/image', 'elf': '/elf', 'elf_sha256': SHA,
                    'source_commit': 'b' * 40, 'build_json': '/build.json'}
            jobs = final.commands(spec, 'perf-guard', root / 'output')
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]['checks']['plan_sha256'], guard.sha256(plan))
            self.assertEqual(jobs[0]['checks']['elf_sha256'], SHA)
            self.assertIn('--expected-plan-sha', jobs[0]['argv'])
            self.assertIn('--build-json', jobs[0]['argv'])

    def test_m6b_chain_and_summary_require_real_guard_without_changing_m5(self):
        self.assertIn('perf-guard', final.phase_prerequisites({'validation_mode': 'm6b'}, 'package'))
        completed = {name: {'passed': True} for name in final.M6B_PHASES if name != 'perf-guard'}
        self.assertEqual(final.completion_status({'validation_mode': 'm6b'}, completed)['missing_phases'], ['perf-guard'])
        self.assertNotIn('perf-guard', final.required_phases({}))
        self.assertEqual(len(final.required_phases({})), 8)


if __name__ == '__main__':
    unittest.main()
