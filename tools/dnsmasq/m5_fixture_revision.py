"""Freeze fixture repairs while retaining exact-ELF evidence with unchanged dependencies."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import tarfile
import m5_final_validation as final


def tools_root(spec):
    return Path(spec.get('tools_root', spec['source_root'] + '/tools/dnsmasq'))


def dependencies(spec, records):
    """Conservatively include local imports and named helper/data files."""
    root = tools_root(spec); pending = set()
    for record in records:
        for word in record['argv']:
            if word.startswith('-') and '=' in word: word = word.split('=', 1)[1]
            if word.startswith('-') and str(root) in word: word = word[word.index(str(root)):]
            path = Path(word)
            if path.is_relative_to(root) and path.is_file(): pending.add(str(path.relative_to(root)))
    if not pending and {record['id'] for record in records} == set(final.FUZZ):
        for record in records:
            final.require(record['passed'] is True and record['elapsed_seconds'] >= final.FUZZ_SECONDS
                          and not record['artifact_entries'] and final.digest(record['argv'][0]) == record['instrumented_target_sha256'],
                          'instrumented fuzz identity/window/artifacts changed')
        return {}
    final.require(pending, 'no direct driver dependency')
    found = set(); absent = set()
    while pending:
        name = pending.pop()
        if name in found: continue
        found.add(name); path = root / name
        if path.suffix not in ['.py', '.sh']: continue
        source = path.read_text()
        for other in re.findall(r'[A-Za-z0-9_/-]+\.(?:py|json|sh|rs|c)\b', source):
            matches = {name for name in spec['tools'] if name == other or Path(name).name == Path(other).name}
            pending.update(matches - found)
        if path.suffix == '.py':
            tree = ast.parse(source)
            image_command = any(isinstance(node, ast.ImportFrom) and node.module == 'm2_rootfs'
                and any(alias.name == 'command' and alias.asname in [None, 'command'] for alias in node.names) for node in ast.walk(tree))
            image_command &= not any(isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == 'command' for node in ast.walk(tree))
            # Unknown dynamic imports/helper launchers cannot certify a narrow
            # closure. Conservatively require the entire original tool set.
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    dynamic_import = isinstance(node.func, ast.Name) and node.func.id == '__import__'
                    dynamic_import |= isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module'
                    launcher = isinstance(node.func, ast.Attribute) and node.func.attr in ['Popen', 'run', 'check_output', 'check_call']
                    native_image = image_command and node.args and isinstance(node.args[0], ast.Call) and isinstance(node.args[0].func, ast.Name) and node.args[0].func.id == 'command'
                    native_network = node.args and isinstance(node.args[0], (ast.List, ast.Tuple)) and node.args[0].elts and isinstance(node.args[0].elts[0], ast.Constant) and node.args[0].elts[0].value == 'ip'
                    uncertain_launcher = launcher and (not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple))
                        or any(not isinstance(value, ast.Constant) for value in node.args[0].elts))
                    uncertain_launcher &= not (native_image or native_network)
                    if ((dynamic_import and (not node.args or not isinstance(node.args[0], ast.Constant))) or uncertain_launcher):
                        raise ValueError('dynamic helper dependency requires fresh replay')
            for node in ast.walk(tree):
                modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    dynamic_import = isinstance(node.func, ast.Name) and node.func.id == '__import__'
                    dynamic_import |= isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module'
                    if dynamic_import: modules.append(node.args[0].value)
                for module in modules:
                    candidate = module.split('.')[0] + '.py'
                    if candidate in spec['tools'] and candidate not in found: pending.add(candidate)
                    elif candidate not in spec['tools']:
                        absent.add(candidate); absent.add(module.split('.')[0] + '/__init__.py')
    return {**{name: spec['tools'][name] for name in sorted(found)}, **{name: None for name in sorted(absent)}}


def assert_schedule(spec, old, record, completed):
    phase = record['phase']; selected = [phase[7:]] if phase.startswith('family:') else []
    actual_phase = 'families' if selected else phase
    current = dict(spec, selected_families=selected)
    if phase == 'fuzz': current['fuzz_build_directory'] = completed['fuzz-build']['artifact_directory']
    expected = final.commands(current, actual_phase, Path(record['attempt']))
    if spec.get('fixture_revision', {}).get('mode') == 'selected-families':
        prior = dict(old, selected_families=selected)
        if phase == 'fuzz': prior['fuzz_build_directory'] = current['fuzz_build_directory']
        final.require(expected == final.commands(prior, actual_phase, Path(record['attempt'])),
                      'default frozen command schedule changed')
        # The origin prerequisite and receipt projection certify actual argv,
        # including earlier imports whose executable paths precede tools_root.
        return
    final.require(len(expected) == len(record['commands']), 'repaired schedule step count changed')
    for observed, wanted in zip(record['commands'], expected):
        normalized = copy.deepcopy(observed)
        normalized['argv'] = [word.replace(str(tools_root(old)), str(tools_root(spec))) for word in observed['argv']]
        final.require(all(normalized.get(key) == value for key, value in wanted.items()), 'repaired schedule changed')


def unchanged_default_tools(spec, old, phase):
    """An identical full default tree needs no inferred dependency closure."""
    final.require(spec.get('fixture_revision', {}).get('mode') == 'selected-families', 'selected revision required')
    family = phase.removeprefix('family:') if phase.startswith('family:') else None
    final.require(family not in spec.get('family_tool_overrides', {}), 'selected family requires fresh replay')
    final.require(tools_root(spec) == tools_root(old) and spec['tools'] == old['tools']
                  and spec['family_registry'] == old['family_registry'] and spec['assets'] == old['assets'],
                  'default frozen tools, scope or assets changed')


def verify_import(spec, record):
    origin = record['imported_from']; path = Path(origin['manifest'])
    final.require(final.digest(path) == origin['manifest_sha256'], 'origin manifest changed')
    old = json.loads(path.read_text()); final.verify_identity(old)
    final.require(old['source_files'] == spec['source_files'] and old['elf_sha256'] == spec['elf_sha256']
                  and old['source_commit'] == spec['source_commit'], 'import used another product')
    completed = json.loads((Path(old['output']) / 'completed.json').read_text())
    original = final.prerequisite(old, origin['manifest_sha256'], completed, record['phase'])
    canonical = json.dumps(original, sort_keys=True, separators=(',', ':')).encode()
    final.require(hashlib.sha256(canonical).hexdigest() == origin['record_sha256'], 'origin receipt changed')
    projected = {key: value for key, value in record.items() if key not in ['receipt', 'manifest_sha256', 'imported_from']}
    original_projection = {key: value for key, value in original.items() if key not in ['receipt', 'manifest_sha256', 'imported_from']}
    final.require(projected == original_projection, 'imported execution differs from origin')
    if origin.get('mode') == 'identical-default-tools':
        unchanged_default_tools(spec, old, record['phase'])
    else:
        required = dependencies(old, original['commands'])
        final.require(required == origin['dependencies'] and all(spec['tools'].get(name) == sha for name, sha in required.items()), 'driver dependency changed')
    assert_schedule(spec, old, original, completed)


def import_unchanged(manifest):
    manifest = Path(manifest); spec = json.loads(manifest.read_text()); final.verify_identity(spec)
    previous = Path(spec['fixture_revision']['previous_manifest']); old = json.loads(previous.read_text())
    final.verify_identity(old); old_sha = final.digest(previous)
    final.require(spec['source_commit'] == old['source_commit'] and spec['elf_sha256'] == old['elf_sha256']
                  and spec['source_files'] == old['source_files'], 'revision changed product identity')
    old_completed = json.loads((Path(old['output']) / 'completed.json').read_text())
    root = Path(spec['output']); retained = []; replay = []
    # Use the same publication lock as live family controllers.
    import fcntl
    with (root / '.completed.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = root / 'completed.json'; completed = json.loads(path.read_text()) if path.exists() else {}
        for phase, original in old_completed.items():
            if phase == 'families' or phase in completed: continue
            try:
                final.prerequisite(old, old_sha, old_completed, phase)
                if spec['fixture_revision'].get('mode') == 'selected-families':
                    unchanged_default_tools(spec, old, phase)
                    evidence = {'mode': 'identical-default-tools'}
                else:
                    required = dependencies(old, original['commands'])
                    final.require(all(spec['tools'].get(name) == sha for name, sha in required.items()), 'changed dependency')
                    evidence = {'dependencies': required}
                assert_schedule(spec, old, original, old_completed)
            except (ValueError, KeyError, OSError) as error:
                replay.append({'phase': phase, 'reason': str(error)}); continue
            record = copy.deepcopy(original)
            record.update(manifest_sha256=final.digest(manifest), receipt=str(root / 'imports' / (phase.replace(':', '-') + '.json')),
                          imported_from={'manifest': str(previous), 'manifest_sha256': old_sha,
                                         'record_sha256': hashlib.sha256(json.dumps(original, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                                         **evidence})
            Path(record['receipt']).parent.mkdir(exist_ok=True); final.atomic_save(Path(record['receipt']), record)
            completed[phase] = record; retained.append(phase)
        needed = ['family:' + row['id'] for row in spec['family_registry']['families']]
        if all(completed.get(name, {}).get('passed') is True for name in needed):
            folder = root / 'aggregates/families'; folder.mkdir(parents=True, exist_ok=True)
            result = dict(phase='families', passed=True, failures=[], commands=[], attempt=str(folder),
                          source_commit=spec['source_commit'], elf_sha256=spec['elf_sha256'], manifest_sha256=final.digest(manifest),
                          family_receipts={name: completed[name]['receipt'] for name in needed})
            final.atomic_save(folder / 'result.json', result); completed['families'] = result
        final.atomic_save(path, completed)
        final.save(root / 'imports/qualification.json', {'retained': retained, 'affected_replay': replay})
    print(json.dumps({'retained': retained, 'affected_replay': replay})); return 0


def revise(args):
    old = json.loads(args.manifest.read_text()); final.verify_identity(old)
    root = args.tools_root.resolve(); out = args.out.resolve()
    final.require(root.parent == Path(old['source_root']) / 'private' and out.parent == root.parent
                  and not out.exists(), 'fresh sibling fixture tools/output under original source/private required')
    final.require(re.fullmatch('[0-9a-f]{40}', args.tools_commit), 'full fixture commit required')
    with tarfile.open(args.tools_archive) as stream:
        final.require(stream.pax_headers.get('comment') == args.tools_commit, 'fixture archive commit changed')
        archived = {member.name.removeprefix('tools/dnsmasq/'): hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                    for member in stream.getmembers() if member.isfile() and member.name.startswith('tools/dnsmasq/')}
    updated = final.file_map(root); final.require(updated == archived, 'fixture files differ from their commit archive')
    families = json.loads((root / 'm5_final_families.draft.json').read_text())
    def inventory(value):
        return [{**family, 'steps': [{k: v for k, v in step.items() if k != 'argv'} for step in family['steps']]} for family in value['families']]
    final.require(inventory(families) == inventory(old['family_registry']), 'fixture revision changed frozen scope/checks/inventory')
    for family, prior in zip(families['families'], old['family_registry']['families']):
        for step, previous in zip(family['steps'], prior['steps']):
            normalized = list(step['argv'])
            if (family['id'] == 'm5_script_arp' and step['id'] == 'paired'
                    and '--allocator-map' in normalized and '--allocator-map' not in previous['argv']):
                at = normalized.index('--allocator-map')
                final.require(normalized[at:at+2] == ['--allocator-map', '{link_map}'], 'allocator map binding changed')
                del normalized[at:at+2]
            final.require(normalized == previous['argv'], 'fixture revision changed frozen arguments')
    spec = copy.deepcopy(old); spec.update(output=str(out),
        fixture_revision={'tools_commit': args.tools_commit, 'previous_manifest': str(args.manifest),
                          'previous_manifest_sha256': final.digest(args.manifest), 'archive': str(args.tools_archive),
                          'changed_files': sorted(name for name in set(old['tools']) | set(updated) if old['tools'].get(name) != updated.get(name))})
    selected = getattr(args, 'family', None)
    if selected:
        known = {row['id'] for row in old['family_registry']['families']}
        final.require(len(selected) == len(set(selected)) and set(selected) <= known, 'unknown or duplicate selected family')
        spec['fixture_revision']['mode'] = 'selected-families'
        spec['fixture_revision']['selected_families'] = selected
        overrides = spec.setdefault('family_tool_overrides', {})
        for family in selected:
            overrides[family] = {'root': str(root), 'files': updated, 'archive': str(args.tools_archive.resolve()),
                                 'archive_sha256': final.digest(args.tools_archive), 'commit': args.tools_commit}
    else:
        spec.update(tools_root=str(root), tools=updated, family_registry=families)
        spec['assets'][str(args.tools_archive.resolve())] = final.digest(args.tools_archive)
    out.mkdir(); (out / 'imports').mkdir(); final.save(out / 'identity.json', spec)
    final.save(out / 'commands.json', {phase: final.commands(spec, phase, out / 'runs' / phase / 'attempt-1') for phase in final.PHASES})
    return import_unchanged(out / 'identity.json')
