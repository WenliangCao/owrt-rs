"""Real Git archives, subprocess receipts and filesystem identity negative controls."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import m5_final_validation as final
import m5_fixture_revision as revision


class FixtureRevisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.number = 0

    def fixture(self, changes=None, driver=None, registry_change=None, extra=None):
        self.number += 1
        base = self.base / str(self.number); source = base / 'source'; tools = source / 'tools/dnsmasq'
        tools.mkdir(parents=True)
        def write(root, name, data='fixture\n'):
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(data)
        for name in ['rust-toolchain.toml', 'manifests/release-25.12.5.json',
                     'packaging/openwrt/owrt-dnsmasq/Makefile', 'components/dnsmasq/Cargo.lock',
                     'components/dnsmasq/Cargo.toml', 'components/dnsmasq/src/lib.rs',
                     'components/ubus/Cargo.toml', 'components/ubus/src/lib.rs']:
            write(source, name)
        write(tools, 'build_package.py', '# frozen packaging fixture\n')
        write(tools, 'build_package.sh', '# frozen packaging fixture\n')
        write(tools, 'helper.py', 'QUALIFIED = True\n')
        write(tools, 'notes.py', '# unrelated old fixture documentation\n')
        for name, contents in (extra or {}).items(): write(tools, name, contents)
        driver = driver or 'import helper\n'
        write(tools, 'driver.py', driver + '''import argparse,json,pathlib
p=argparse.ArgumentParser();p.add_argument('out');p.add_argument('--cases');a=p.parse_args()
out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps({'qualified':helper.QUALIFIED,'cases':[{'id':case} for case in a.cases.split(',')]}))
''')
        registry = {'schema': 1, 'complete': True, 'families': [{'id': 'fixture', 'steps': [{
            'id': 'paired', 'argv': ['{python}', '{tools}/driver.py', '{out}/result.json', '--cases', 'a,b'],
            'result': '{out}/result.json', 'checks': {'qualified': True},
            'inventory': {'field': 'cases', 'key': 'id', 'ids': ['a', 'b']}}]}]}
        final.save(tools / 'm5_final_families.draft.json', registry)
        external = {}
        for name in ['image', 'runtime', 'ubus', 'reference']:
            root = base / name; write(root, 'fixture.txt'); external[name] = root
        sdk = base / 'sdk'
        sdk_files = ['.config', 'rules.mk', 'include/package.mk', 'include/package-pack.mk', 'include/feeds.mk',
                     'scripts/rstrip.sh', 'staging_dir/host/bin/apk', 'staging_dir/host/bin/sstrip',
                     'staging_dir/host/bin/patchelf', 'staging_dir/host/bin/.apk.bin', 'staging_dir/host/bin/.sstrip.bin',
                     'staging_dir/host/bin/.patchelf.bin', 'staging_dir/host/lib/runas.so', 'staging_dir/host/lib/ld-linux-x86-64.so.2']
        chain = f'staging_dir/toolchain-{final.build_package.ARCH}_gcc-14.3.0_musl/'
        for name in sdk_files + [chain + name for name in ['include/stdio.h', 'lib/libc.so', 'lib/crt1.o', 'bin/gcc']]: write(sdk, name)
        old_output = source / 'private/old'; old_output.mkdir(parents=True)
        elf = old_output / 'elf'; elf.write_bytes(b'fixed product fixture ELF')
        spec = {'source_root': str(source), 'output': str(old_output), 'source_commit': 'b' * 40,
                'elf': str(elf), 'elf_sha256': final.digest(elf), 'elf_bytes': elf.stat().st_size,
                'source_files': final.build_package.inputs(source), 'tools': final.file_map(tools),
                'image_root': str(external['image']), 'image_files': final.file_map(external['image']),
                'runtime_root': str(external['runtime']), 'runtime_files': final.file_map(external['runtime']),
                'sdk': str(sdk), 'sdk_files': final.build_package.sdk_inputs(sdk),
                'ubus_helpers': {'root': str(external['ubus']), 'files': final.file_map(external['ubus'])},
                'reference_source': {'root': str(external['reference']), 'files': final.file_map(external['reference'])},
                'assets': {}, 'family_registry': registry}
        manifest = old_output / 'identity.json'; final.save(manifest, spec); final.verify_identity(spec)
        attempt = old_output / 'attempt-1'
        command = final.commands(spec, 'families', attempt)[0]
        started = time.monotonic(); run = subprocess.run(command['argv'], capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        command.update(passed=True, returncode=0, elapsed_seconds=time.monotonic() - started,
                       result_sha256=final.digest(command['result']))
        record = {'phase': 'family:fixture', 'passed': True, 'failures': [], 'commands': [command],
                  'attempt': str(attempt), 'source_commit': spec['source_commit'], 'elf_sha256': spec['elf_sha256'],
                  'manifest_sha256': final.digest(manifest), 'receipt': str(attempt / 'family.result.json')}
        final.save(Path(record['receipt']), record); final.save(old_output / 'completed.json', {record['phase']: record})
        repository = base / 'git'; repository.mkdir()
        shutil.copytree(tools, repository / 'tools/dnsmasq', ignore=shutil.ignore_patterns('__pycache__'))
        repaired = repository / 'tools/dnsmasq'
        for name, contents in (changes or {'notes.py': '# unrelated new fixture documentation\n'}).items(): write(repaired, name, contents)
        if registry_change:
            value = copy.deepcopy(registry); registry_change(value); final.save(repaired / 'm5_final_families.draft.json', value)
        subprocess.run(['git', 'init', '-q'], cwd=repository, check=True)
        subprocess.run(['git', 'add', 'tools/dnsmasq'], cwd=repository, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'fixture'],
                       cwd=repository, check=True)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository, text=True).strip()
        archive = base / 'tools.tar'
        subprocess.run(['git', 'archive', '--format=tar', '--output', str(archive), 'HEAD', 'tools/dnsmasq'], cwd=repository, check=True)
        sidecar = source / 'private/tools-sidecar'; shutil.copytree(repaired, sidecar)
        args = argparse.Namespace(manifest=manifest, tools_root=sidecar, tools_archive=archive, tools_commit=commit,
                                  out=source / 'private/revised')
        return argparse.Namespace(args=args, old=spec, origin=record, source=source, manifest=manifest,
                                  sidecar=sidecar, archive=archive, revised=args.out / 'identity.json')

    def revise(self, case):
        # This fixture has one family; identity, archive and receipts remain real.
        with patch.object(final, 'PHASES', ['families']), contextlib.redirect_stdout(io.StringIO()):
            revision.revise(case.args)
        return json.loads(case.revised.read_text()), json.loads((case.args.out / 'completed.json').read_text())

    def test_unchanged_dependency_imports_the_real_receipt(self):
        case = self.fixture(); spec, completed = self.revise(case)
        record = final.prerequisite(spec, final.digest(case.revised), completed, 'family:fixture')
        self.assertEqual(record['commands'], case.origin['commands'])
        self.assertEqual(spec['source_files'], case.old['source_files'])
        self.assertEqual(spec['elf_sha256'], case.old['elf_sha256'])

    def test_changed_transitive_dependency_requires_replay(self):
        case = self.fixture(changes={'helper.py': 'QUALIFIED = False\n'})
        _, completed = self.revise(case)
        self.assertNotIn('family:fixture', completed)

    def test_dynamic_helper_dependency_cannot_import(self):
        case = self.fixture(changes={'helper.py': 'QUALIFIED = False\n'},
                            driver='import importlib\nhelper = importlib.import_module("helper")\n')
        _, completed = self.revise(case)
        self.assertNotIn('family:fixture', completed)

    def test_added_local_module_shadowing_stdlib_cannot_import(self):
        case = self.fixture(changes={'json.py': '# changed module resolution\n'})
        _, completed = self.revise(case)
        self.assertNotIn('family:fixture', completed)

    def test_dynamic_helper_launcher_inside_list_cannot_import(self):
        case = self.fixture(extra={'launcher_helper.py': 'print(True)\n'},
                            changes={'launcher_helper.py': 'print(False)\n'}, driver='''import pathlib,subprocess,sys,types
name='launcher_helper'
child=subprocess.run([sys.executable,str(pathlib.Path(__file__).parent/(name+'.py'))],capture_output=True,text=True,check=True)
helper=types.SimpleNamespace(QUALIFIED=child.stdout.strip()=='True')
''')
        _, completed = self.revise(case)
        self.assertNotIn('family:fixture', completed)

    def test_named_nested_data_dependency_cannot_import(self):
        case = self.fixture(extra={'profiles/cases.json': '{"qualified":true}\n'},
                            changes={'profiles/cases.json': '{"qualified":false}\n'}, driver='''import pathlib,json,types
value=json.loads((pathlib.Path(__file__).parent/'profiles/cases.json').read_text())
helper=types.SimpleNamespace(QUALIFIED=value['qualified'])
''')
        _, completed = self.revise(case)
        self.assertNotIn('family:fixture', completed)

    def test_origin_receipt_and_leaf_tampering_are_rejected(self):
        for mutation in ['leaf', 'receipt']:
            with self.subTest(mutation=mutation):
                case = self.fixture(); spec, completed = self.revise(case)
                if mutation == 'leaf': final.save(Path(case.origin['commands'][0]['result']), {'qualified': False})
                else:
                    case.origin['commands'][0]['elapsed_seconds'] += 1
                    final.save(Path(case.origin['receipt']), case.origin)
                    final.save(Path(case.old['output']) / 'completed.json', {'family:fixture': case.origin})
                with self.assertRaises(ValueError): final.prerequisite(spec, final.digest(case.revised), completed, 'family:fixture')

    def test_imported_receipt_cannot_change_the_original_command_or_metrics(self):
        case = self.fixture(); spec, completed = self.revise(case)
        record = completed['family:fixture']; record['commands'][0]['elapsed_seconds'] += 1
        final.save(Path(record['receipt']), record); final.save(case.args.out / 'completed.json', completed)
        with self.assertRaises(ValueError): final.prerequisite(spec, final.digest(case.revised), completed, 'family:fixture')

    def test_scope_checks_and_inventory_cannot_shrink(self):
        mutations = {
            'scope': lambda value: value['families'][0]['steps'][0]['argv'].__setitem__(-1, 'a'),
            'checks': lambda value: value['families'][0]['steps'][0].__setitem__('checks', {}),
            'inventory': lambda value: value['families'][0]['steps'][0]['inventory'].__setitem__('ids', ['a']),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                case = self.fixture(registry_change=mutation)
                with self.assertRaisesRegex(ValueError, 'scope|checks|inventory|schedule|arguments'): self.revise(case)

    def test_product_file_map_difference_cannot_publish_an_import(self):
        case = self.fixture(); spec, _ = self.revise(case)
        other = self.base / 'other-source'; shutil.copytree(case.source, other, ignore=shutil.ignore_patterns('private'))
        (other / 'components/dnsmasq/src/lib.rs').write_text('changed product source\n')
        spec.update(source_root=str(other), source_files=final.build_package.inputs(other)); final.save(case.revised, spec)
        (case.args.out / 'completed.json').unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            try: revision.import_unchanged(case.revised)
            except ValueError: pass
        completed = json.loads((case.args.out / 'completed.json').read_text()) if (case.args.out / 'completed.json').exists() else {}
        self.assertNotIn('family:fixture', completed)

    def test_sidecar_tool_and_archive_mutations_are_rejected(self):
        for mutation in ['tool', 'archive']:
            with self.subTest(mutation=mutation):
                case = self.fixture(); spec, _ = self.revise(case)
                path = case.sidecar / 'driver.py' if mutation == 'tool' else case.archive
                path.write_bytes(path.read_bytes() + b'changed')
                with self.assertRaises(ValueError): final.verify_identity(spec)

    def test_archive_tree_mismatch_and_commit_mismatch_are_rejected(self):
        for mutation in ['tree', 'commit']:
            with self.subTest(mutation=mutation):
                case = self.fixture()
                if mutation == 'tree': (case.sidecar / 'driver.py').write_text('changed\n')
                else: case.args.tools_commit = '0' * 40
                with self.assertRaises(ValueError): self.revise(case)


if __name__ == '__main__': unittest.main()
