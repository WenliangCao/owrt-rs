"""Generate the final batch's local fixtures before using Oracle."""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

import m5_final_validation as final
import m5_cli_final as cli
import m5_config_inputs as inputs
import m5_dhcp_files as dhcp_files
import m5_dns_cache as cache
import m5_listeners as listeners
import m5_dns_files as dns_files
import m6b_route_resend as route
import m6b_tcp_accept_snapshot as accept
import m6b_tcp_lease_import_regression as lease
import m6b_reload_same_wake as reload

HERE = Path(final.__file__).resolve().parent


class FinalBatch(unittest.TestCase):
    def test_listener_batch_keeps_all_original_cases_and_loopback_witnesses(self):
        cases = listeners.scenarios()
        plan = json.loads((HERE / 'm5_listeners.json').read_text())
        self.assertEqual(len(cases), 163)
        self.assertEqual([case['name'] for case in cases], plan['required_cases'])
        self.assertEqual(len({case['name'] for case in cases}), 163)
        for case in cases:
            labels = listeners.expected_labels(case)
            self.assertTrue(labels)
            self.assertEqual(len(labels), len(set(labels)), case['name'])
            self.assertEqual(labels, plan['required_observations'][case['name']])
        named = {case['name']: case for case in cases}
        for transport in ['udp', 'tcp']:
            label = 'lo-extra-' + transport
            self.assertTrue(listeners.expected_answer(named['interface-wildcard'], label))
            for name in ['listen-only-wildcard', 'interface-static', 'interface-dynamic']:
                self.assertFalse(listeners.expected_answer(named[name], label))

    def test_dns_file_dhcp_callers_have_the_declared_executable_helper(self):
        cases = [case for case in dns_files.scenarios() if case.get('dhcp_witness')]
        self.assertTrue(cases)
        for case in cases:
            self.assertTrue(case['files']['helper.sh'].startswith('#!/bin/sh\n'))
            self.assertIn('dhcp-script=/m2/files/helper.sh', case['config'].splitlines())
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); (root / 'm2/files').mkdir(parents=True)
                opened = {}
                try:
                    dns_files.put(root, 'helper.sh', case['files']['helper.sh'], opened)
                    path = root / 'm2/files/helper.sh'; path.chmod(0o755)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
                    self.assertEqual(path.read_bytes(), case['files']['helper.sh'].encode())
                finally:
                    for handle in opened.values():
                        if hasattr(handle, 'close'): handle.close()

    def test_all_44_families_68_steps_have_real_tools_and_witnesses(self):
        registry = json.loads((HERE / 'm5_final_families.draft.json').read_text())
        self.assertEqual(len(registry['families']), 44)
        spec = dict(source_root=str(HERE.parents[1]), image_root='/private/image',
            runtime_root='/private/runtime', elf='/private/final-elf', elf_sha256='a' * 64,
            source_commit='b' * 40, sdk='/private/sdk', family_registry=registry,
            bindings={name: '/private/' + name for name in ['link_map', 'reference_source',
                'ubus_reference_build', 'ubus_native_c_sha', 'ubus_image_runner', 'ubus_image_identity']})
        jobs = final.commands(spec, 'families', Path('/private/runs'))
        self.assertEqual(len(jobs), 68)
        self.assertEqual(len({job['id'] for job in jobs}), 68)
        for job in jobs:
            self.assertTrue(job['checks']); self.assertTrue(job['result'])
            for word in job['argv']:
                self.assertNotIn('{', word); self.assertNotIn('}', word)
                if Path(word).is_relative_to(HERE): self.assertTrue(Path(word).is_file(), word)
            inventory = job.get('inventory')
            if inventory: self.assertEqual(len(inventory['ids']), len(set(inventory['ids'])))

    def test_169_options_have_both_forms_and_real_cli_fixtures(self):
        rows = json.loads((HERE / 'm5_cli_final.json').read_text())['test_cases']
        self.assertEqual(len(rows), 338)
        options = {row['option'] for row in rows}; self.assertEqual(len(options), 169)
        self.assertEqual(len(cli.test_controls()), 7)
        for option in options:
            selected = [row for row in rows if row['option'] == option]
            self.assertEqual(len(selected), 2)
            self.assertEqual({row['form'] for row in selected}, {'cli', 'file'})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'm2').mkdir(); folder = cli.fixtures(root)
            required = {path.name for path in folder.iterdir()}
            for name in ['config-script', 'lease-script']:
                self.assertEqual(stat.S_IMODE((folder / name).stat().st_mode), 0o755)
            for row in rows:
                for text in [row['directive'], *row.get('dependencies', [])]:
                    if '=/m2/cli/' in text:
                        name = text.split('=/m2/cli/', 1)[1].split(',', 1)[0]
                        self.assertIn(name, required | {'leases', 'pid', 'log', 'dump'}, row['case'])

    def test_config_input_and_dhcp_file_fixtures_have_declared_paths_and_modes(self):
        cases = json.loads((HERE / 'm5_config_inputs.json').read_text())['scenarios']
        previous = os.umask(0o022)
        try:
            for case in cases:
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); (root / 'm2').mkdir(); (root / 'etc').mkdir()
                    folder = inputs.install(root, case)
                    for name, item in case.get('files', {}).items():
                        item = {'text': item} if isinstance(item, str) else item
                        self.assertEqual((folder / name).read_bytes(), item['text'].encode())
                        self.assertEqual(stat.S_IMODE((folder / name).stat().st_mode), item.get('mode', 0o644))
                    for name, target in case.get('symlinks', {}).items():
                        self.assertEqual(str((folder / name).readlink()), target)
            for case in dhcp_files.scenarios():
                # macOS rejects raw-byte Linux names. Check their exact byte
                # representation locally; the final image gate creates them.
                raw_names = [name for name in case['files']
                             if any(0xdc80 <= ord(char) <= 0xdcff for char in name)]
                if raw_names and sys.platform == 'darwin':
                    for name in raw_names:
                        self.assertEqual(os.fsdecode(os.fsencode(name)), name)
                    continue
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); (root / 'm2').mkdir()
                    folder = dhcp_files.install(root, case)
                    for name, item in case['files'].items():
                        item = {'text': item} if isinstance(item, str) else item
                        path = folder / name
                        if 'mode' in item: self.assertEqual(stat.S_IMODE(path.stat().st_mode), item['mode'])
                        if item.get('fifo'): self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))
                        if 'symlink' in item: self.assertEqual(str(path.readlink()), item['symlink'])
        finally:
            os.umask(previous)

    def test_targeted_configs_and_reload_witness_paths(self):
        held = copy.deepcopy(lease.interleaved.CASES[lease.PROFILE])
        held.update(metrics=True, diagnostic=False,
                    samples_after_drain_seconds=lease.interleaved.DRAIN_SECONDS)
        cases = [*route.CASES, *route.CLEAR_CASES, *accept.CASES, held]
        self.assertEqual(len(cases), 14)
        for case in cases:
            lines = cache.scenario_config(case, 15353, 15953).splitlines()
            self.assertEqual(lines[:13], ['port=15353', 'no-resolv', 'no-hosts', 'bind-interfaces',
                'listen-address=' + cache.LISTEN, 'server=127.0.0.2#15953',
                'cache-size=' + str(case.get('capacity', 100)), 'no-0x20-encode',
                'host-record=health.cache.test,198.51.100.99', 'local-ttl=600',
                'user=root', 'pid-file=/m2/cache.pid', 'log-facility=/m2/cache.log'])
            expected = case['config'].replace('@UPSTREAM@', '15953').splitlines()
            self.assertEqual(lines[13:13 + len(expected)], expected)
            for directive in ['cache-size', 'pid-file', 'log-facility']:
                self.assertEqual(sum(line.startswith(directive + '=') for line in lines), 1)
            self.assertNotIn('@UPSTREAM@', '\n'.join(lines))
        scenarios = reload.scenarios(); self.assertEqual(len(scenarios), 6)
        for case in scenarios:
            self.assertIn(case['actions'][1]['reload_path'], case['files'])
            self.assertEqual(len(case['expected_addresses']), 3)
