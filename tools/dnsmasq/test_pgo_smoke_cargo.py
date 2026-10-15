"""Exercise the real recipe/wrapper handoff using a capture-only Cargo stub."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / 'tools/dnsmasq/pgo_smoke_cargo.py'
RECIPE = ROOT / 'packaging/openwrt/owrt-dnsmasq/Makefile'
PLAN = ROOT / 'docs/dnsmasq/audits/perf-opt-20261015/dns/pgo-sdk-smoke-plan.json'


class Handoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'private'
        self.root.mkdir()
        (self.root / 'rules.mk').write_text('')
        (self.root / 'package.mk').write_text('define BuildPackage\ncheck:\n\t$(Build/Compile)\nendef\n')
        self.capture = self.root / 'captured.json'
        self.cargo = self.root / 'cargo-stub'
        self.cargo.write_text(f'#!{sys.executable}\nimport json,os,sys\nfrom pathlib import Path\n'
                             f'Path({str(self.capture)!r}).write_text(json.dumps({{"argv":sys.argv[1:],"flags":os.environ.get("RUSTFLAGS"),"rustc":os.environ.get("RUSTC")}}))\n')
        self.cargo.chmod(0o755)
        self.cc = self.root / 'sdk-cc'
        self.cc.write_text('#!/bin/sh\nexit 99\n')
        self.cc.chmod(0o755)
        self.plan = json.loads(PLAN.read_text())
        old_build = self.plan['build_slot']
        self.plan.update(build_slot=str(self.root / 'build'), cargo=str(self.cargo),
                         rustc=str(self.cargo), map_cc=str(self.cc), sdk_cc=str(self.cc),
                         default_profile_directory=str(self.root / 'profraw'))
        self.plan['recipe_rustflags'] = self.plan['recipe_rustflags'].replace(old_build, self.plan['build_slot'])
        for mode in ('control', 'generate'):
            output = self.root / mode
            output.mkdir()
            self.plan['outputs'][mode] = str(output)
            self.plan['invocation_receipts'][mode] = str(output / 'invocation.json')
        self.plan_path = self.root / 'plan.json'
        self.plan_path.write_text(json.dumps(self.plan))
        self.env = {'PATH': os.environ['PATH'], 'PGO_SMOKE_PLAN': str(self.plan_path),
                    'RUSTUP_TOOLCHAIN': '1.98.1', 'PERF_SDK_CC': str(self.cc)}

    def make(self, mode, extra=None):
        env = dict(self.env, PGO_SMOKE_MODE=mode,
                   PERF_LINK_MAP=str(Path(self.plan['outputs'][mode]) / 'link.map'),
                   RUSTFLAGS='external flags must be overwritten by the recipe')
        env.update(extra or {})
        return subprocess.run(['make', '--no-print-directory', '-f', str(RECIPE),
                               f'TOPDIR={self.root}', f'INCLUDE_DIR={self.root}',
                               f'PKG_BUILD_DIR={self.plan["build_slot"]}', f'V1_CARGO={WRAPPER}',
                               'V1_CARGO_HOME=/home/ubuntu/.cargo', 'V1_RUSTUP_HOME=/home/ubuntu/.rustup',
                               f'TARGET_CC_NOCACHE={self.cc}', 'TARGET_LINKER=bfd', 'check'],
                              cwd=RECIPE.parent, env=env, text=True, capture_output=True)

    def test_real_recipe_control_and_generate_handoff(self):
        for mode in ('control', 'generate'):
            with self.subTest(mode=mode):
                result = self.make(mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                actual = json.loads(self.capture.read_text())
                receipt = json.loads(Path(self.plan['invocation_receipts'][mode]).read_text())
                self.assertEqual(actual['argv'], receipt['argv'])
                self.assertEqual(actual['flags'], receipt['effective_rustflags'])
                self.assertEqual(actual['rustc'], receipt['rustc_environment'])
                self.assertEqual(receipt['recipe_rustflags'], self.plan['recipe_rustflags'])
                suffix = '' if mode == 'control' else ' -Cprofile-generate=' + self.plan['default_profile_directory']
                self.assertEqual(actual['flags'], self.plan['recipe_rustflags'] + suffix)
                self.capture.unlink()
                original = Path(self.plan['invocation_receipts'][mode]).read_bytes()
                self.assertNotEqual(self.make(mode).returncode, 0)
                self.assertFalse(self.capture.exists())
                self.assertEqual(Path(self.plan['invocation_receipts'][mode]).read_bytes(), original)

    def test_builder_metadata_and_clean_calls_are_passed_through(self):
        manifest = str(Path(self.plan['build_slot']) / 'dnsmasq/Cargo.toml')
        for argv in (['--version'], ['clean', '--manifest-path', manifest, '-p', 'dnsmasq-rs',
                                     '--release', '--target', 'aarch64-unknown-linux-musl']):
            result = subprocess.run([sys.executable, str(WRAPPER), *argv],
                                    env=dict(self.env, PGO_SMOKE_MODE='generate'), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(self.capture.read_text()), {'argv': argv, 'flags': None, 'rustc': self.plan['rustc']})
            self.assertFalse(Path(self.plan['invocation_receipts']['generate']).exists())

    def test_ambient_codegen_overrides_and_unknown_commands_never_execute_cargo(self):
        for extra in ({'CARGO_ENCODED_RUSTFLAGS': '-Clto=thin'},
                      {'CARGO_PROFILE_RELEASE_LTO': 'thin'}, {'RUSTC_WRAPPER': '/wrong'}):
            with self.subTest(extra=extra):
                self.assertNotEqual(self.make('generate', extra).returncode, 0)
                self.assertFalse(self.capture.exists())
        result = subprocess.run([sys.executable, str(WRAPPER), 'build', '--features', 'unexpected'],
                                env=dict(self.env, PGO_SMOKE_MODE='generate'), capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())

    def test_real_pinned_cargo_proxy_discovers_rustc_with_empty_path(self):
        direct = Path(subprocess.check_output(['rustup', 'which', '--toolchain', '1.98.1', 'cargo'],
                                             text=True).strip())
        compiler = Path(subprocess.check_output(['rustup', 'which', '--toolchain', '1.98.1', 'rustc'],
                                               text=True).strip())
        proxy = Path(shutil.which('cargo'))
        self.assertTrue(proxy.is_file())
        self.assertNotEqual(proxy.resolve(), direct.resolve())
        empty = self.root / 'empty-path'
        empty.mkdir()
        manifest = Path(self.plan['build_slot']) / 'dnsmasq/Cargo.toml'
        manifest.parent.mkdir(parents=True)
        (manifest.parent / 'src').mkdir()
        (manifest.parent / 'src/lib.rs').write_text('pub fn fixture() {}\n')
        manifest.write_text('[package]\nname="dnsmasq-rs"\nversion="0.1.0"\nedition="2021"\n')
        argv = ['clean', '--manifest-path', str(manifest), '-p', 'dnsmasq-rs',
                '--release', '--target', 'aarch64-unknown-linux-musl']
        env = dict(self.env, PATH=str(empty), PGO_SMOKE_MODE='control',
                   RUSTUP_HOME=str(compiler.parents[3]), CARGO_HOME=str(self.root / 'cargo-home'))
        broken = subprocess.run([str(direct), *argv], env=env, text=True, capture_output=True)
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn('rustc -vV', broken.stderr)
        self.assertIn('os error 2', broken.stderr)
        self.plan.update(cargo=str(proxy), rustc=str(compiler))
        self.plan_path.write_text(json.dumps(self.plan))
        fixed = subprocess.run([sys.executable, str(WRAPPER), *argv], env=env, text=True, capture_output=True)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        self.assertFalse(Path(self.plan['invocation_receipts']['control']).exists())
        self.assertFalse(list(manifest.parent.rglob('*.rlib')))
        print(json.dumps({'real_toolchain_regression': 'Cargo clean with empty PATH through the actual wrapper',
                          'direct_cargo_status': broken.returncode, 'direct_cargo_stderr': broken.stderr.strip(),
                          'rustup_proxy_status': fixed.returncode, 'rustup_proxy_stderr': fixed.stderr.strip()}))


if __name__ == '__main__':
    unittest.main()
