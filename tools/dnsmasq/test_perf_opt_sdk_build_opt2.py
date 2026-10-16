#!/usr/bin/env python3
"""Reject receipts that cannot establish the isolated effective profile2."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import perf_opt_sdk_build_opt2 as builder


def commands():
    lines = []
    for kind in ('lib', 'bin'):
        flags = '-C opt-level=2 -Ccodegen-units=1 -C panic=abort -C strip=symbols'
        flags += ' -C lto' if kind == 'bin' else ' -C linker-plugin-lto'
        lines.append('     Running `/toolchain/rustc --crate-name dnsmasq_rs '
                     f'--crate-type {kind} --target aarch64-unknown-linux-musl {flags}`')
    return builder.release_rustc_commands('\n'.join(lines))


class Profile2ReceiptTests(unittest.TestCase):
    def test_separate_and_joined_flags_preserve_two_actual_invocations(self):
        result = commands()
        builder.verify_profile2_commands(result)
        self.assertEqual(len(result), 2)
        self.assertIn('-Ccodegen-units=1', result[0]['argv'])

    def test_missing_or_duplicate_invocations_are_rejected(self):
        valid = commands()
        for bad in ([], valid[:1], valid + valid[:1], [valid[0], valid[0]]):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                builder.verify_profile2_commands(bad)

    def test_wrong_or_conflicting_effective_codegen_is_rejected(self):
        valid = commands()
        for original, replacement in [('opt-level=2', 'opt-level=3'),
                                      ('codegen-units=1', 'codegen-units=16'),
                                      ('panic=abort', 'panic=unwind'),
                                      ('strip=symbols', 'strip=none'), ('lto', 'lto=thin')]:
            bad = copy.deepcopy(valid)
            bad[1]['codegen'].remove(original)
            bad[1]['codegen'].append(replacement)
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                builder.verify_profile2_commands(bad)
        bad = copy.deepcopy(valid)
        bad[1]['codegen'].append('opt-level=3')
        with self.assertRaises(AssertionError):
            builder.verify_profile2_commands(bad)
        bad = copy.deepcopy(valid)
        bad[0]['argv'][bad[0]['argv'].index('--target') + 1] = 'aarch64-apple-darwin'
        with self.assertRaises(AssertionError):
            builder.verify_profile2_commands(bad)

    def test_ambient_release_override_fails_before_source_or_sdk_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / 'private'
            for key in ('OPT_LEVEL', 'LTO', 'CODEGEN_UNITS', 'PANIC'):
                out = base / key
                argv = ['opt2-builder', '--source', str(base / 'source'), '--commit',
                        '8035114257c8706047d2038c2bb8126391331925', '--epoch', '1792119705',
                        '--sdk', str(base / 'sdk'), '--out', str(out), '--cargo', '/absent/cargo']
                with self.subTest(key=key), patch('sys.argv', argv), \
                        patch.dict(os.environ, {'CARGO_PROFILE_RELEASE_' + key: '3'}), \
                        patch.object(builder.audit, 'inputs') as inputs:
                    with self.assertRaisesRegex(AssertionError, 'ambient Cargo release profile overrides'):
                        builder.main()
                    inputs.assert_not_called()
                    self.assertEqual(json.loads((out / 'build.json').read_text())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
