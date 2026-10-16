"""Fixed-flag/provenance checks and real pinned LLVM argument parsing."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pgo_sdk_smoke import sha

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / 'docs/dnsmasq/audits/perf-opt-20261015/dns/pgo-use-hot250-plan.json'


class Hot250(unittest.TestCase):
    def test_exact_single_flag_delta_and_no_other_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'private'
            root.mkdir()
            plan = json.loads(PLAN.read_text())
            capture = root / 'capture'
            cargo = root / 'cargo-stub'
            cargo.write_text(f'#!{sys.executable}\nimport os\nfrom pathlib import Path\n'
                             f'Path({str(capture)!r}).write_text(os.environ["RUSTFLAGS"])\n')
            cargo.chmod(0o755)
            plan.update(build_slot=str(root / 'build'), cargo=str(cargo), rustc=str(cargo),
                        merged_profile=str(root / 'training.profdata'), profile_receipt=str(root / 'training-profile.json'))
            plan['outputs']['use'] = str(root)
            plan['invocation_receipts']['use'] = str(root / 'invocation.json')
            Path(plan['merged_profile']).write_bytes(b'fixed original profile fixture')
            plan['merged_profile_sha256'] = sha(plan['merged_profile'])
            profile = {'status': 'training-complete', 'plan_sha256': plan['training_plan_sha256'],
                       'generate_elf_sha256': plan['generate_elf']['sha256'],
                       'merged_profile': {'path': plan['merged_profile'], 'sha256': plan['merged_profile_sha256']}}
            Path(plan['profile_receipt']).write_text(json.dumps(profile))
            plan['profile_receipt_sha256'] = sha(plan['profile_receipt'])
            path = root / 'plan.json'
            path.write_text(json.dumps(plan))
            env = {'PATH': os.environ['PATH'], 'PGO_SMOKE_PLAN': str(path), 'PGO_SMOKE_MODE': 'use',
                   'RUSTUP_TOOLCHAIN': '1.98.1', 'CARGO_HOME': '/home/ubuntu/.cargo',
                   'RUSTUP_HOME': '/home/ubuntu/.rustup', 'CARGO_BUILD_TARGET': 'aarch64-unknown-linux-musl',
                   'CARGO_PROFILE_RELEASE_PANIC': 'abort', 'DNSMASQ_STATIC_PIE_CC': plan['map_cc'],
                   'PERF_SDK_CC': plan['sdk_cc'], 'PERF_LINK_MAP': str(root / 'link.map'),
                   'RUSTFLAGS': plan['recipe_rustflags'],
                   'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': str(ROOT / 'packaging/openwrt/owrt-dnsmasq/static-pie-linker.py')}
            argv = [sys.executable, str(ROOT / 'tools/dnsmasq/pgo_hot250_cargo.py'), 'build', '--release', '--frozen',
                    '--manifest-path', str(root / 'build/dnsmasq/Cargo.toml'), '--bin', 'dnsmasq-rs',
                    '--target-dir', str(root / 'build/dnsmasq/target')]
            result = subprocess.run(argv, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = plan['recipe_rustflags'] + ' -Cprofile-use=' + plan['merged_profile'] + ' -Cllvm-args=-pgo-warn-missing-function'
            receipt = json.loads(Path(plan['invocation_receipts']['use']).read_text())
            self.assertEqual(receipt['base_use_rustflags'], expected)
            self.assertEqual(capture.read_text(), expected + ' -Cllvm-args=-hot-callsite-threshold=250')
            capture.unlink()
            Path(plan['invocation_receipts']['use']).unlink()
            plan['hot_callsite_threshold'] = 251
            path.write_text(json.dumps(plan))
            self.assertNotEqual(subprocess.run(argv, env=env, capture_output=True).returncode, 0)
            self.assertFalse(capture.exists())

    def test_pinned_rustc_passes_both_llvm_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'tiny.rs'
            source.write_text('pub fn f(x:u64)->u64 { x+1 }\n')
            for index, first, second, expected_error in (
                (0, '-pgo-warn-missing-function', '-hot-callsite-threshold=250', None),
                (1, '-pgo-warn-missing-function=not-a-bool', '-hot-callsite-threshold=250', 'pgo-warn-missing-function'),
                (2, '-pgo-warn-missing-function', '-hot-callsite-threshold=not-an-int', 'hot-callsite-threshold'),
            ):
                result = subprocess.run(['rustc', '+1.98.1', '--crate-type=lib', '-Copt-level=3',
                    '-Cllvm-args=' + first, '-Cllvm-args=' + second, '--emit=llvm-ir', str(source),
                    '-o', str(root / (str(index) + '.ll'))], text=True, capture_output=True)
                if expected_error is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)


if __name__ == '__main__':
    unittest.main()
