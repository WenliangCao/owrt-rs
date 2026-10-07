#!/usr/bin/env python3
"""Fresh exact-source C primitive receipts, separate from image-daemon gates."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

SOURCE_IDENTITY_SHA = '62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9'
CACHE_SHA = '51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c'
PRIMITIVES = {'cache-transfer': 36, 'cache-partial-eof': 9}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def snapshot(paths):
    files = {}
    for value in paths:
        path = Path(value).resolve()
        candidates = sorted(path.rglob('*')) if path.is_dir() else [path]
        for item in candidates:
            if item.is_file():
                files[str(item.resolve())] = digest(item)
    if not files:
        raise ValueError('fresh C source/build inputs required')
    return files


def compiler_probe(out, label, compiler, env=None):
    """Save the actual executable and compiler target/ABI, without Rust builds."""
    executable = Path(shutil.which(str(compiler)) or compiler).resolve()
    records = []
    for suffix, flags in [('version', ['--version']), ('machine', ['-dumpmachine']),
                          ('macros', ['-dM', '-E', '-x', 'c', '-'])]:
        stem = 'abi-' + label + '-' + suffix
        argv = [str(compiler), *flags]
        run = subprocess.run(argv, input=b'', capture_output=True, env=env, timeout=60)
        (out / (stem + '.stdout')).write_bytes(run.stdout)
        (out / (stem + '.stderr')).write_bytes(run.stderr)
        row = {'argv': argv, 'exit': run.returncode, 'stdout': stem + '.stdout',
               'stderr': stem + '.stderr', 'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(),
               'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()}
        save(out / (stem + '.command.json'), row)
        run.check_returncode()
        records.append(row)
    return {'label': label, 'compiler': str(executable), 'compiler_sha256': digest(executable),
            'staging_dir': (env or os.environ).get('STAGING_DIR'), 'records': records}


def elf(path):
    path = Path(path)
    header = path.read_bytes()[:64]
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('C primitive requires ELF64 little-endian: ' + str(path))
    return {'path': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path),
            'class': 64, 'endianness': 'little', 'machine': struct.unpack_from('<H', header, 18)[0]}


def inventory(out):
    return {str(path.relative_to(out)): {'bytes': path.stat().st_size, 'sha256': digest(path)}
            for path in sorted(out.rglob('*')) if path.is_file() and path.name != 'fresh-c-receipt.json'}


def freeze(out, primitive, source_identity, source_inputs, compilers, artifacts, passed):
    if primitive not in PRIMITIVES or digest(source_identity) != SOURCE_IDENTITY_SHA:
        raise ValueError('matching patched C source identity required')
    after = {name: digest(name) for name in source_inputs if Path(name).is_file()}
    save(out / 'source-inputs-after.json', after)
    if after != source_inputs:
        raise ValueError('C source/object/library input changed during fresh execution')
    save(out / 'compiler-probes.json', compilers)
    build_names = ['native-build', 'target-build'] if primitive == 'cache-transfer' else ['build']
    builds = [json.loads((out / (name + '.command.json')).read_text()) for name in build_names]
    if any(row.get('exit') != 0 or '-o' not in row.get('argv', []) for row in builds):
        raise ValueError('fresh C compile/link commands incomplete')
    rows = [elf(path) for path in artifacts]
    if any(row['machine'] != 183 for row in rows):
        raise ValueError('Oracle C primitive artifacts must be AArch64')
    receipt = {'schema': 1, 'kind': 'm6b-fresh-c-primitive', 'primitive': primitive,
               'passed': passed is True, 'planned_cases': PRIMITIVES[primitive],
               'source_identity': {'sha256': digest(source_identity)}, 'source_inputs': source_inputs,
               'cache_source_sha256': CACHE_SHA, 'identity_sha256': digest(out / 'identity.json'),
               'plan_sha256': digest(out / 'plan.json'), 'result_sha256': digest(out / 'result.json'),
               'compiler_probes_sha256': digest(out / 'compiler-probes.json'), 'build_argv': builds,
               'native_reference_objects_reused': True, 'artifacts': rows,
               'files': inventory(out), 'tool_sha256': digest(__file__),
               'image_daemon_qualification': False,
               'scope': 'fresh exact-source/compiler ABI/argv/corpus C primitive; not image daemon 097a9e21'}
    save(out / 'fresh-c-receipt.json', receipt)
    return receipt


def validate_fresh(baseline, receipt_path, primitive):
    baseline, receipt_path = Path(baseline).resolve(), Path(receipt_path).resolve()
    receipt = json.loads(receipt_path.read_text())
    if (primitive not in PRIMITIVES or receipt_path.parent != baseline
            or receipt.get('schema') != 1 or receipt.get('kind') != 'm6b-fresh-c-primitive'
            or receipt.get('primitive') != primitive or receipt.get('passed') is not True
            or receipt.get('planned_cases') != PRIMITIVES[primitive]
            or receipt.get('source_identity', {}).get('sha256') != SOURCE_IDENTITY_SHA
            or receipt.get('cache_source_sha256') != CACHE_SHA
            or receipt.get('tool_sha256') != digest(__file__)
            or receipt.get('files') != inventory(baseline)):
        raise ValueError('complete fresh C primitive receipt/inputs required')
    if (json.loads((baseline / 'source-inputs-before.json').read_text()) != receipt['source_inputs']
            or json.loads((baseline / 'source-inputs-after.json').read_text()) != receipt['source_inputs']):
        raise ValueError('fresh C input before/after maps differ')
    for name, key in [('identity.json', 'identity_sha256'), ('plan.json', 'plan_sha256'),
                      ('result.json', 'result_sha256'), ('compiler-probes.json', 'compiler_probes_sha256')]:
        if digest(baseline / name) != receipt[key]:
            raise ValueError('fresh C receipt differs: ' + name)
    identity = json.loads((baseline / 'identity.json').read_text())
    if identity.get('source_identity_sha256') != SOURCE_IDENTITY_SHA or identity.get('cache_source_sha256') != CACHE_SHA:
        raise ValueError('fresh C compiled source identity differs')
    build_names = ['native-build', 'target-build'] if primitive == 'cache-transfer' else ['build']
    builds = [json.loads((baseline / (name + '.command.json')).read_text()) for name in build_names]
    if receipt.get('build_argv') != builds or any(row.get('exit') != 0 or '-o' not in row.get('argv', []) for row in builds):
        raise ValueError('fresh C compile/link argv differs')
    if [elf(baseline / row['path']) for row in receipt['artifacts']] != receipt['artifacts']:
        raise ValueError('fresh C artifact identity/ABI differs')
    if any(row['machine'] != 183 for row in receipt['artifacts']):
        raise ValueError('fresh C primitive ABI must be AArch64')
    compilers = json.loads((baseline / 'compiler-probes.json').read_text())
    if len(compilers) != (2 if primitive == 'cache-transfer' else 1):
        raise ValueError('fresh C compiler ABI observations incomplete')
    for compiler in compilers:
        if len(compiler.get('records', [])) != 3:
            raise ValueError('compiler version/target/macros observations incomplete')
        for row in compiler['records']:
            if (row['exit'] != 0 or digest(baseline / row['stdout']) != row['stdout_sha256']
                    or digest(baseline / row['stderr']) != row['stderr_sha256']
                    or not (baseline / row['stdout']).stat().st_size):
                raise ValueError('fresh C compiler ABI receipt invalid')
    plan = json.loads((baseline / 'plan.json').read_text())
    report = json.loads((baseline / 'result.json').read_text())
    if (len(plan) != PRIMITIVES[primitive] or len(report['cases']) != len(plan)
            or [row['case'] for row in report['cases']] != [row.get('label', row.get('case')) for row in plan]):
        raise ValueError('fresh C corpus incomplete')
    if primitive == 'cache-transfer':
        if (report.get('completed_cases') != 36 or report.get('observations_per_runtime') != 307
                or report.get('cross_runtime_differences') or report.get('calibration', {}).get('changed_counter_detected') != 1):
            raise ValueError('fresh C transfer calibration/result differs')
        for case in plan:
            folder = baseline / case['label']
            rows = []
            for label in ['native', 'target']:
                for repeat in range(3):
                    stem = label + '-' + str(repeat)
                    command = json.loads((folder / (stem + '.command.json')).read_text())
                    if command['exit'] != 0:
                        raise ValueError('fresh C transfer case failed')
                    rows.append((folder / (stem + '.stdout')).read_text().splitlines())
            if any(row != rows[0] for row in rows) or not rows[0]:
                raise ValueError('fresh C transfer variant/repeat instability')
    else:
        if report.get('failed') != 0 or report.get('failures') or not report.get('checks') or any(row['pass'] is not True for row in report['checks']):
            raise ValueError('fresh C partial EOF calibration/result differs')
        for case in report['cases']:
            folder = baseline / case['case']
            trace = json.loads((folder / 'trace.json').read_text())
            raw = [json.loads(line) for line in (folder / 'oracle.stdout').read_text().splitlines()]
            command = json.loads((folder / 'oracle.command.json').read_text())
            if (trace != raw or len(trace) != 4 or command['exit'] != 0
                    or digest(folder / 'trace.json') != case['trace_sha256']
                    or digest(folder / 'complete-wire.bin') != case['raw_sha256']):
                raise ValueError('fresh C partial EOF raw case/trace differs')
    return {'mode': 'fresh-c-primitive', 'primitive': primitive,
            'receipt_sha256': digest(receipt_path), 'identity_sha256': receipt['identity_sha256'],
            'plan_sha256': receipt['plan_sha256'], 'result_sha256': receipt['result_sha256'],
            'compiler_probes_sha256': receipt['compiler_probes_sha256'],
            'image_daemon_qualification': False, 'scope': receipt['scope']}
