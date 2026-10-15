"""Local fixed-input and profile provenance gates; no training or SDK build."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import pgo_train as train
from perf_opt_device_run import SCENES

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / 'docs/dnsmasq/audits/perf-opt-20261015/dns/pgo-training-plan.json'


class TrainingGates(unittest.TestCase):
    def test_fixed_scenes_and_minimal_case_adaptation(self):
        plan = json.loads(PLAN.read_text())
        self.assertEqual(plan['scenes'], [list(scene) for scene in SCENES])
        self.assertEqual(plan['passes'], 1)
        self.assertEqual(sum(plan['expected_profiles_by_scene'].values()), 50)
        source = (ROOT / 'tools/dnsmasq/perf_opt_device_case.sh').read_text()
        actual = train.training_case(source, Path(plan['training_directory']), Path(plan['runtime_directory']))
        expected = source.replace('/tmp/dnsmasq-perf-20261015', plan['training_directory']).replace(
            'out=$root/runs/$label', 'out=' + plan['runtime_directory'] + '/$label').replace(
            '--name-prefix m6a.test', '--name-prefix pgo.test')
        self.assertEqual(actual, expected)
        self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), plan['training_case_sha256'])
        self.assertEqual(actual.count('--name-prefix pgo.test'), 2)

    def test_config_initial_daemon_and_every_exit_profile_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            profiles = folder / 'profiles'
            profiles.mkdir()
            rows = [{'pid': pid, 'ok': True} for pid in range(101, 121)]
            exits = [{'pid': pid, 'exited': True, 'exit_code': 0, 'wait_errno': 0, 'signal': 0, 'forced': False}
                     for pid in range(100, 121)]
            (folder / 'lifecycle.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            def store():
                (folder / 'lifecycle.stderr').write_text(''.join('pgo_child_exit ' + json.dumps(row) + '\n' for row in exits))
            store()
            for row in exits:
                (profiles / (str(row['pid']) + '.profraw')).write_bytes(b'fixture')
            scene = next(scene for scene in SCENES if scene[0] == 'config-small')
            self.assertEqual(len(train.profile_rows(folder, scene, profiles)[1]), 21)
            initial = exits.pop(0)
            store()
            with self.assertRaises(AssertionError):
                train.profile_rows(folder, scene, profiles)
            exits.insert(0, initial)
            exits[0]['exit_code'] = 7
            store()
            with self.assertRaises(AssertionError):
                train.profile_rows(folder, scene, profiles)
            exits[0]['exit_code'] = 0
            store()
            (profiles / '100.profraw').unlink()
            with self.assertRaises(AssertionError):
                train.profile_rows(folder, scene, profiles)

    def test_use_wrapper_rejects_modified_or_foreign_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'private'
            root.mkdir()
            plan = json.loads(PLAN.read_text())
            captured = root / 'capture'
            cargo = root / 'cargo'
            cargo.write_text(f'#!{sys.executable}\nimport os\nfrom pathlib import Path\n'
                             f'Path({str(captured)!r}).write_text(os.environ["RUSTFLAGS"])\n')
            cargo.chmod(0o755)
            plan.update(build_slot=str(root / 'build'), cargo=str(cargo), rustc=str(cargo),
                        merged_profile=str(root / 'profile.profdata'), profile_receipt=str(root / 'profile.json'))
            plan['outputs']['use'] = str(root)
            plan['invocation_receipts']['use'] = str(root / 'invocation.json')
            plan_path = root / 'plan.json'
            plan_path.write_text(json.dumps(plan))
            merged = Path(plan['merged_profile'])
            merged.write_bytes(b'fixed profile fixture')
            profile = {'status': 'training-complete', 'plan_sha256': train.sha(plan_path),
                       'generate_elf_sha256': plan['generate_elf']['sha256'],
                       'merged_profile': {'path': str(merged), 'sha256': train.sha(merged)}}
            Path(plan['profile_receipt']).write_text(json.dumps(profile))
            env = {'PATH': os.environ['PATH'], 'PGO_SMOKE_PLAN': str(plan_path), 'PGO_SMOKE_MODE': 'use',
                   'RUSTUP_TOOLCHAIN': '1.98.1', 'CARGO_HOME': '/home/ubuntu/.cargo',
                   'RUSTUP_HOME': '/home/ubuntu/.rustup', 'CARGO_BUILD_TARGET': 'aarch64-unknown-linux-musl',
                   'CARGO_PROFILE_RELEASE_PANIC': 'abort', 'DNSMASQ_STATIC_PIE_CC': plan['map_cc'],
                   'PERF_SDK_CC': plan['sdk_cc'], 'PERF_LINK_MAP': str(root / 'link.map'),
                   'RUSTFLAGS': plan['recipe_rustflags'],
                   'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': str(ROOT / 'packaging/openwrt/owrt-dnsmasq/static-pie-linker.py')}
            argv = [sys.executable, str(ROOT / 'tools/dnsmasq/pgo_train_cargo.py'), 'build', '--release', '--frozen',
                    '--manifest-path', str(root / 'build/dnsmasq/Cargo.toml'), '--bin', 'dnsmasq-rs',
                    '--target-dir', str(root / 'build/dnsmasq/target')]
            result = subprocess.run(argv, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(captured.read_text(), plan['recipe_rustflags'] + ' -Cprofile-use=' + str(merged) +
                             ' -Cllvm-args=-pgo-warn-missing-function')
            captured.unlink()
            Path(plan['invocation_receipts']['use']).unlink()
            merged.write_bytes(b'changed')
            self.assertNotEqual(subprocess.run(argv, env=env, capture_output=True).returncode, 0)
            self.assertFalse(captured.exists())
            merged.write_bytes(b'fixed profile fixture')
            profile['generate_elf_sha256'] = '0' * 64
            Path(plan['profile_receipt']).write_text(json.dumps(profile))
            self.assertNotEqual(subprocess.run(argv, env=env, capture_output=True).returncode, 0)
            self.assertFalse(captured.exists())


if __name__ == '__main__':
    unittest.main()
