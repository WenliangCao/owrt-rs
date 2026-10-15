"""Local metadata, synthetic ELF/maps and owned-process cleanup checks only."""
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import pgo_sdk_smoke as smoke


class SmokeGates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = json.loads((Path(__file__).resolve().parents[2] /
            'docs/dnsmasq/audits/perf-opt-20261015/dns/pgo-sdk-smoke-plan.json').read_text())
        self.tools = {'cargo': 'c' * 64, 'rustc': 'r' * 64}
        self.plan_sha = 'p' * 64
        for mode in ('control', 'generate'):
            out = self.root / mode
            out.mkdir()
            self.plan['outputs'][mode] = str(out)
            self.plan['invocation_receipts'][mode] = str(out / 'invocation.json')
            for filename in ('dnsmasq-rs', 'dnsmasq-prestrip', 'link.map'):
                (out / filename).write_bytes((mode + filename).encode())
        self.plan['expected_control_elf_sha256'] = smoke.sha(self.root / 'control/dnsmasq-rs')

    def build_receipt(self, mode, budget):
        out = self.root / mode
        value = {key: self.plan[key] for key in
                 ('source_commit', 'source_date_epoch', 'source_digest', 'builder_sha256', 'build_helper_sha256')}
        value.update(status='built-unqualified', source_unchanged=True, within_existing_budget=budget,
                     baseline_matches_expected=True,
                     toolchain={'map_wrapper_sha256': self.plan['map_cc_sha256']},
                     elf_layout={'type': 'ET_DYN', 'machine': 'AArch64', 'linkage': 'static-pie',
                                 'interpreter': None, 'needed': [], 'pie': True, 'bind_now': True,
                                 'gnu_relro': True, 'nx_stack': True, 'writable_executable_load': False},
                     artifacts=[{'path': 'dnsmasq-rs', 'sha256': smoke.sha(out / 'dnsmasq-rs')}],
                     link_map={'sha256': smoke.sha(out / 'link.map')},
                     prestrip={'sha256': smoke.sha(out / 'dnsmasq-prestrip')})
        (out / 'build.json').write_text(json.dumps(value))
        extra = '' if mode == 'control' else '-Cprofile-generate=' + self.plan['default_profile_directory']
        invocation = {'mode': mode, 'plan_sha256': self.plan_sha, 'wrapper_sha256': self.plan['wrapper_sha256'],
                      'cargo_sha256': self.tools['cargo'], 'rustc_sha256': self.tools['rustc'],
                      'recipe_rustflags': self.plan['recipe_rustflags'], 'added_rustflags': extra,
                      'effective_rustflags': self.plan['recipe_rustflags'] + (' ' + extra if extra else '')}
        Path(self.plan['invocation_receipts'][mode]).write_text(json.dumps(invocation))
        return value

    def check(self, mode):
        return smoke.check_build(self.plan, mode, self.plan_sha, self.tools)

    def test_control_requires_independent_exact_hash_and_budget(self):
        self.build_receipt('control', True)
        self.check('control')
        self.plan['expected_control_elf_sha256'] = '0' * 64
        with self.assertRaises(AssertionError):
            self.check('control')
        self.plan['expected_control_elf_sha256'] = smoke.sha(self.root / 'control/dnsmasq-rs')
        self.build_receipt('control', False)
        with self.assertRaises(AssertionError):
            self.check('control')

    def test_generate_budget_exception_does_not_relax_hardening(self):
        value = self.build_receipt('generate', False)
        self.check('generate')
        value['elf_layout']['gnu_relro'] = False
        (self.root / 'generate/build.json').write_text(json.dumps(value))
        with self.assertRaises(AssertionError):
            self.check('generate')

    def test_relro_coverage_and_stack_permissions_are_required(self):
        data = bytearray(64 + 2 * 56)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 0x3000, 0x3000, 4096)
        struct.pack_into('<IIQQQQQQ', data, 120, 0x6474e552, 4, 0x1000, 0x1000, 0, 0x1000, 0x1000, 1)
        maps = [{'start': 0x400000, 'end': 0x401000, 'offset': 0, 'permissions': 'r-xp', 'main': True, 'path': 'elf'},
                {'start': 0x401000, 'end': 0x402000, 'offset': 4096, 'permissions': 'r--p', 'main': True, 'path': 'elf'},
                {'start': 0x500000, 'end': 0x501000, 'offset': 0, 'permissions': 'rw-p', 'main': False, 'path': '[stack]'}]
        self.assertTrue(smoke.protections(data, maps, 4096)['relro_read_only'])
        for index, permissions in ((1, 'rw-p'), (2, 'rwxp')):
            wrong = copy.deepcopy(maps)
            wrong[index]['permissions'] = permissions
            with self.assertRaises(AssertionError):
                smoke.protections(data, wrong, 4096)
        with self.assertRaises(ValueError):
            smoke.protections(data, [maps[0], maps[2]], 4096)

    def test_exited_launcher_does_not_hide_live_descendant(self):
        code = ('import subprocess,sys\n'
                'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],'
                'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                'print(p.pid,flush=True)\n')
        process = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            output, error = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertGreater(int(output.strip()), 0)
            self.assertTrue(smoke.group_exists(process.pid))
            receipt = smoke.stop_group(process)
            self.assertTrue(receipt['term_sent'] and receipt['group_exited'])
            self.assertFalse(smoke.group_exists(process.pid))
        finally:
            smoke.stop_group(process)


if __name__ == '__main__':
    unittest.main()
