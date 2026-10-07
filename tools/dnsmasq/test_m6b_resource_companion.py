"""Planned local identity controls; not executed during formal windows."""
import tempfile
import unittest
from pathlib import Path

import m6b_resource_companion as companion


class BindingControls(unittest.TestCase):
    def test_only_map_and_source_paths_normalize(self):
        common = '-Cpanic=abort -Clink-arg=-Wl,-z,now'
        left = {'source': '/frozen/product', 'rustflags': common +
                ' --remap-path-prefix=/frozen/product=/build -Clink-arg=-Wl,-Map=/out/product/link.map'}
        right = {'source': '/frozen/diag', 'rustflags': common +
                 ' --remap-path-prefix=/frozen/diag=/build -Clink-arg=-Wl,-Map=/out/diag/link.map'}
        self.assertEqual(companion.normalized_flags(left), companion.normalized_flags(right))
        comma = dict(right, rustflags=right['rustflags'].replace('-Map=', '-Map,'))
        self.assertEqual(companion.normalized_flags(left), companion.normalized_flags(comma))
        changed = dict(right, rustflags=right['rustflags'].replace('-z,now', '-z,lazy'))
        self.assertNotEqual(companion.normalized_flags(left), companion.normalized_flags(changed))

    def test_compile_inputs_ignore_docs_but_bind_source_cargo_and_config(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for name in ['dnsmasq', 'ubus']:
                crate = source / 'components' / name
                (crate / 'src').mkdir(parents=True)
                (crate / 'Cargo.toml').write_text(name)
                (crate / 'Cargo.lock').write_text('locked')
                (crate / 'src/lib.rs').write_text('pub fn frozen() {}')
            original = companion.compilation_files(source)
            (source / 'docs').mkdir(); (source / 'docs/unrelated.md').write_text('different export')
            self.assertEqual(original, companion.compilation_files(source))
            (source / 'components/dnsmasq/src/lib.rs').write_text('pub fn changed() {}')
            self.assertNotEqual(original, companion.compilation_files(source))
            (source / 'components/dnsmasq/src/lib.rs').write_text('pub fn frozen() {}')
            (source / 'components/dnsmasq/Cargo.lock').write_text('changed dependency')
            self.assertNotEqual(original, companion.compilation_files(source))
            (source / 'components/dnsmasq/Cargo.lock').write_text('locked')
            (source / '.cargo').mkdir(); (source / '.cargo/config.toml').write_text('[build]\nrustflags=[]')
            self.assertNotEqual(original, companion.compilation_files(source))


if __name__ == '__main__':
    unittest.main()
