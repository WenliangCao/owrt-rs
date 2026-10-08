#!/usr/bin/env python3
"""C-first reverse cache transfer: exact native and SDK-musl source primitives.

Reuse the fully pinned non-cache objects from the original 307-observation
baseline, compile a separate driver including unchanged cache.c, and execute
real fork/pipe transfer. This is not execution of the stock image ELF.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import shutil

from cache_reverse_transfer_cases import cases
from cache_transfer_diff import CACHE_SHA, IDENTITY_SHA, NATIVE_SHA, TARGET_IDENTITY_SHA, command, save, sha

BASELINE_SHA = '96fc7eed20067ebc134853620a799aa4a779afdcdf0fdb306815740c339dc941'
PLAN_SHA = '2d546b0e47749a2dce5e3863be6136f336155db2dd05c680452f26f7717e468d'


def build(args, out):
    base = args.transfer_baseline.resolve()
    fresh_transfer = None
    if args.fresh_transfer_receipt:
        import c_primitive_receipt as fresh
        fresh_transfer = fresh.validate_fresh(base, args.fresh_transfer_receipt.resolve(), 'cache-transfer')
    else:
        assert sha(base / 'identity.json') == BASELINE_SHA
    old = json.loads((base / 'identity.json').read_text())
    objects = args.reference_build.resolve() / 'dnsmasq'
    assert sha(objects / 'dnsmasq') == NATIVE_SHA
    assert sha(objects / 'cache.c') == CACHE_SHA
    assert sha(args.source_identity) == IDENTITY_SHA
    source = json.loads(args.source_identity.read_text())
    for name, digest in source['patched_files'].items():
        if name.startswith('src/'):
            assert sha(objects / name[4:]) == digest, name
    for name, digest in old['native_objects'].items():
        path = base / name if name == 'dnsmasq-renamed.o' else objects / name
        assert sha(path) == digest, path
    for name, digest in old['target_objects'].items():
        assert sha(base / 'target-objects' / name) == digest, name
    for name, digest in old['sdk_files'].items():
        assert sha(args.sdk / name) == digest, name
    target = args.target_reference.resolve()
    assert sha(target / 'identity.json') == TARGET_IDENTITY_SHA
    target_identity = json.loads((target / 'identity.json').read_text())
    for name, record in target_identity['files'].items():
        assert sha(target / name) == record['sha256'], name
    driver = Path(__file__).with_name('cache_reverse_transfer_driver.c').resolve()
    built = {}
    for label in ['native', 'target']:
        prior = json.loads((base / f'{label}-build.command.json').read_text())
        assert prior['exit'] == 0
        argv = prior['argv']
        old_driver = [i for i, word in enumerate(argv) if word.endswith('/cache_transfer_driver.c')]
        assert len(old_driver) == 1 and argv[-2] == '-o'
        argv[old_driver[0]] = str(driver)
        argv[-1] = str(out / (label + '-oracle'))
        command(args, out, label + '-build', argv,
                env=dict(os.environ, STAGING_DIR=str(args.sdk / 'staging_dir')))
        built[label] = out / (label + '-oracle')
    target_prefix = [target / 'lib/libc.so', '--library-path', target / 'lib']
    command(args, out, 'target-dependencies', [*target_prefix, '--list', built['target']])
    identity = dict(scope=__doc__, baseline_identity_sha256=sha(base / 'identity.json'),
                    native_reference_sha256=NATIVE_SHA, source_identity_sha256=IDENTITY_SHA,
                    target_reference_identity_sha256=TARGET_IDENTITY_SHA,
                    source_files=source['patched_files'], reused_objects=old,
                    driver_sha256=sha(driver), tool_sha256=sha(Path(__file__)),
                    cases_sha256=sha(Path(__file__).with_name('cache_reverse_transfer_cases.py')),
                    native_oracle_sha256=sha(built['native']), target_oracle_sha256=sha(built['target']))
    save(out / 'identity.json', identity)
    if fresh_transfer:
        identity.update(cache_source_sha256=CACHE_SHA, fresh_transfer=fresh_transfer,
                        transfer_baseline=str(base), transfer_receipt=str(args.fresh_transfer_receipt.resolve()))
        save(out / 'identity.json', identity)
    return [built['native']], [*target_prefix, built['target']]


def freeze_reverse(args, out, inputs, compilers, report):
    import c_primitive_receipt as fresh
    after = {name: sha(Path(name)) for name in inputs if Path(name).is_file()}
    save(out / 'source-inputs-after.json', after)
    if after != inputs:
        raise ValueError('reverse C source/object/library input changed')
    save(out / 'compiler-probes.json', compilers)
    artifacts = [fresh.elf(out / (label + '-oracle')) for label in ('native', 'target')]
    if any(row['machine'] != 183 for row in artifacts):
        raise ValueError('fresh reverse primitives require AArch64 ELF64 little-endian')
    builds = [json.loads((out / (label + '-build.command.json')).read_text()) for label in ('native', 'target')]
    if any(row['exit'] != 0 or '-o' not in row['argv'] for row in builds):
        raise ValueError('reverse C compile/link receipt incomplete')
    transfer = fresh.validate_fresh(args.transfer_baseline, args.fresh_transfer_receipt, 'cache-transfer')
    receipt = dict(schema=1, kind='m6b-fresh-c-reverse-transfer', primitive='cache-reverse-transfer',
        passed=report['status'] == 'C-baseline-complete' and not report['failures'],
        source_identity_sha256=IDENTITY_SHA, cache_source_sha256=CACHE_SHA, planned_cases=21, planned_processes=126,
        transfer_baseline=str(args.transfer_baseline.resolve()), transfer_receipt=str(args.fresh_transfer_receipt.resolve()),
        fresh_transfer=transfer, source_inputs=inputs, identity_sha256=sha(out / 'identity.json'),
        plan_sha256=sha(out / 'plan.json'), result_sha256=sha(out / 'result.json'),
        compiler_probes_sha256=sha(out / 'compiler-probes.json'), build_argv=builds, artifacts=artifacts,
        tool_sha256=sha(Path(__file__)), cases_sha256=sha(Path(__file__).with_name('cache_reverse_transfer_cases.py')),
        files=fresh.inventory(out), image_daemon_qualification=False,
        scope='fresh 21-case exact-source reverse primitive; native/SDK each3; original exact ordered comparator; not stock image097')
    save(out / 'fresh-c-receipt.json', receipt)


def validate_fresh_reverse(base, receipt_path):
    """Use the unchanged main C helper for primitives; bind reverse-specific order."""
    import c_primitive_receipt as fresh
    base, receipt_path = Path(base).resolve(), Path(receipt_path).resolve()
    receipt = json.loads(receipt_path.read_text())
    if (receipt_path.parent != base or receipt.get('schema') != 1
            or receipt.get('kind') != 'm6b-fresh-c-reverse-transfer' or receipt.get('primitive') != 'cache-reverse-transfer'
            or receipt.get('passed') is not True or receipt.get('planned_cases') != 21 or receipt.get('planned_processes') != 126
            or receipt.get('source_identity_sha256') != IDENTITY_SHA or receipt.get('cache_source_sha256') != CACHE_SHA
            or receipt.get('tool_sha256') != sha(Path(__file__))
            or receipt.get('cases_sha256') != sha(Path(__file__).with_name('cache_reverse_transfer_cases.py'))
            or receipt.get('plan_sha256') != PLAN_SHA or receipt.get('files') != fresh.inventory(base)):
        raise ValueError('complete fresh reverse C source/ABI/corpus receipt required')
    if fresh.validate_fresh(receipt['transfer_baseline'], receipt['transfer_receipt'], 'cache-transfer') != receipt['fresh_transfer']:
        raise ValueError('fresh reused transfer objects/ABI receipt changed')
    for name, key in [('identity.json', 'identity_sha256'), ('plan.json', 'plan_sha256'),
                      ('result.json', 'result_sha256'), ('compiler-probes.json', 'compiler_probes_sha256')]:
        if sha(base / name) != receipt[key]:
            raise ValueError('fresh reverse receipt differs: ' + name)
    if (json.loads((base / 'source-inputs-before.json').read_text()) != receipt['source_inputs']
            or json.loads((base / 'source-inputs-after.json').read_text()) != receipt['source_inputs']
            or {name: sha(Path(name)) for name in receipt['source_inputs'] if Path(name).is_file()} != receipt['source_inputs']):
        raise ValueError('fresh reverse physical source inputs or before/after maps differ')
    identity = json.loads((base / 'identity.json').read_text())
    if (identity.get('source_identity_sha256') != IDENTITY_SHA or identity.get('cache_source_sha256') != CACHE_SHA
            or identity.get('fresh_transfer') != receipt['fresh_transfer']):
        raise ValueError('reverse compiled C source/reused transfer identity differs')
    builds = [json.loads((base / (label + '-build.command.json')).read_text()) for label in ('native', 'target')]
    if receipt['build_argv'] != builds or any(row['exit'] != 0 or '-o' not in row['argv'] for row in builds):
        raise ValueError('reverse C compile/link argv differs')
    if ([fresh.elf(base / row['path']) for row in receipt['artifacts']] != receipt['artifacts']
            or len(receipt['artifacts']) != 2 or any(row['machine'] != 183 for row in receipt['artifacts'])):
        raise ValueError('reverse ELF identity/ABI differs')
    compilers = json.loads((base / 'compiler-probes.json').read_text())
    if len(compilers) != 2 or any(len(row.get('records', [])) != 3 for row in compilers):
        raise ValueError('reverse compiler version/target/macros observations incomplete')
    for compiler in compilers:
        if sha(Path(compiler['compiler'])) != compiler['compiler_sha256']:
            raise ValueError('reverse compiler executable changed')
        for row in compiler['records']:
            if (row['exit'] != 0 or sha(base / row['stdout']) != row['stdout_sha256']
                    or sha(base / row['stderr']) != row['stderr_sha256'] or not (base / row['stdout']).stat().st_size):
                raise ValueError('reverse compiler ABI receipt invalid')
    schedule = json.loads((base / 'plan.json').read_text())
    report = json.loads((base / 'result.json').read_text())
    if (schedule != cases() or len(schedule) != 21 or report.get('status') != 'C-baseline-complete'
            or report.get('failures') or report.get('planned_processes') != 126
            or {row['case'] for row in report['cases'] + report['ordering_cases']} != {case['label'] for case in schedule}
            or len(report['cases']) + len(report['ordering_cases']) != 21):
        raise ValueError('reverse original 21-case corpus/result incomplete')
    for case in schedule:
        observed = []
        row = next(row for row in report['cases'] + report['ordering_cases'] if row['case'] == case['label'])
        for label in ('native', 'target'):
            for repeat in range(3):
                stem = label + '-' + str(repeat)
                folder = base / case['label']
                command_row = json.loads((folder / (stem + '.command.json')).read_text())
                lines = (folder / (stem + '.stdout')).read_text().splitlines()
                if command_row['exit'] != 0 or sha(folder / (stem + '.stdout')) != row['result_sha256'][stem]:
                    raise ValueError('reverse C case exit/stdout identity differs')
                calibrate(case, lines)
                observed.append(lines)
        if not case['ordering'] and any(lines != observed[0] for lines in observed):
            raise ValueError('reverse deterministic C variant/repeat instability')
        if row['distinct_exact_traces'] != len({tuple(lines) for lines in observed}) or row['processes'] != 6:
            raise ValueError('reverse ordered trace count changed')
    return dict(mode='fresh-c-reverse-primitive', receipt_sha256=sha(receipt_path),
                identity_sha256=receipt['identity_sha256'], plan_sha256=receipt['plan_sha256'],
                result_sha256=receipt['result_sha256'], fresh_transfer=receipt['fresh_transfer'],
                image_daemon_qualification=False, scope=receipt['scope'])


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError('missing observations')
    return [i for i, pair in enumerate(zip(expected, actual)) if pair[0] != pair[1]]


def calibrate(case, lines):
    transferred = sum(line.startswith('CH C 1 |') for line in lines)
    assert sum(line.startswith('R ') for line in lines) == transferred
    assert len(lines) == sum(len(case[s]) for s in ['pre', 'child', 'between', 'after']) + transferred
    if case['label'] == 'expiry-None-103':
        assert lines == ['R 1 | 1 0', 'CH B | 0 0', 'CH V 1 | 0 0', 'CH C 1 | 1 0',
                         'P2 T R4:Clock.test:110:c0000201 | 1 0', 'P2 A Clock.test:110:0 | 1 0']
    if case['label'] == 'parent-local-reverse-coexist':
        assert 'P2 A Local.test:200:1 Dynamic.test:160:0 | 1 0' in lines
    if case['label'] == 'empty-clears-parent-pending':
        assert 'R 1 | 1 0' in lines and 'P2 T | 1 0' in lines and 'P2 A | 1 0' in lines
    if case['label'] == 'multiple-ptr-export-order':
        assert 'CH T R4:First.test:160:c0000201 R4:Second.test:160:c0000201 R4:Third.test:160:c0000201 | 3 0' in lines
        assert lines.index('P2 T R4:Third.test:160:c0000201 R4:Second.test:160:c0000201 R4:First.test:160:c0000201 | 3 0') >= 0
    assert compare(lines, lines) == []
    changed = lines.copy(); changed[-1] += ' altered'
    assert compare(lines, changed) == [len(lines) - 1]
    try:
        compare(lines, lines[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError('missing row accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['reference-build', 'source-identity', 'sdk', 'target-reference', 'transfer-baseline', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--fresh-transfer-receipt', type=Path, help='explicit fresh transfer C receipt; historical identity pin otherwise')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert [n for _, n in socket.if_nameindex()] == ['lo']
    out = args.out.resolve(); assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    schedule = cases(); assert len(schedule) == 21
    save(out / 'plan.json', schedule)
    report = dict(scope=__doc__, planned_cases=21, cases=[], failures=[], ordering_cases=[],
                  status='incomplete', planned_processes=126)
    inputs = compilers = None
    try:
        if args.fresh_transfer_receipt:
            import c_primitive_receipt as fresh
            fresh.validate_fresh(args.transfer_baseline, args.fresh_transfer_receipt, 'cache-transfer')
            transfer_identity = json.loads((args.transfer_baseline / 'identity.json').read_text())
            prior_builds = [json.loads((args.transfer_baseline / (label + '-build.command.json')).read_text())
                            for label in ('native', 'target')]
            inputs = fresh.snapshot([args.source_identity, args.reference_build / 'dnsmasq', args.reference_build / 'deps',
                args.transfer_baseline, args.target_reference, Path(__file__).with_name('cache_reverse_transfer_driver.c'),
                Path(__file__), Path(__file__).with_name('cache_reverse_transfer_cases.py'),
                *[args.sdk / name for name in transfer_identity['sdk_files']],
                *[Path(shutil.which(row['argv'][0]) or row['argv'][0]) for row in prior_builds]])
            save(out / 'source-inputs-before.json', inputs)
            compilers = []
            for label in ('native', 'target'):
                prior = json.loads((args.transfer_baseline / (label + '-build.command.json')).read_text())
                compilers.append(fresh.compiler_probe(out, label, prior['argv'][0],
                    dict(os.environ, STAGING_DIR=str(args.sdk / 'staging_dir'))))
        native, target = build(args, out)
        for case in schedule:
            folder = out / case['label']; folder.mkdir()
            (folder / 'config').write_text(f"no-hosts\nno-resolv\ncache-size={case['capacity']}\n" + case['config'])
            for stage in ['pre', 'child', 'between', 'after']:
                (folder / stage).write_text(''.join(line + '\n' for line in case[stage]))
            suffix = [folder / name for name in ['config', 'pre', 'child', 'between', 'after']] + [str(case['now'])]
            observed = []
            for label, prefix in [('native', native), ('target', target)]:
                for repeat in range(3):
                    lines = command(args, folder, f'{label}-{repeat}', [*prefix, *suffix])
                    calibrate(case, lines)
                    observed.append(lines)
            row = dict(case=case['label'], observations=len(observed[0]), processes=6,
                       distinct_exact_traces=len({tuple(trace) for trace in observed}),
                       result_sha256={f'{label}-{repeat}': sha(folder / f'{label}-{repeat}.stdout')
                                      for label in ['native','target'] for repeat in range(3)})
            if case['ordering']:
                # Preserve exact order and any layout-dependent variation. No
                # sorted/set comparator and no conversion into six passes.
                report['ordering_cases'].append(row)
            else:
                assert all(trace == observed[0] for trace in observed), case['label'] + ' unexpected C instability'
                report['cases'].append(row)
            save(out / 'result.json', report)
        report.update(status='C-baseline-complete', deterministic_cases=len(report['cases']),
                      deterministic_observations=sum(r['observations'] for r in report['cases']),
                      ordering_observations=sum(r['observations'] for r in report['ordering_cases']),
                      calibration={'identical_passes':True,'changed_row_detected':True,'missing_row_rejected':True})
    except Exception as error:
        report['failures'].append(repr(error))
    save(out / 'result.json', report)
    if inputs is not None:
        freeze_reverse(args, out, inputs, compilers, report)
    print(json.dumps({k:v for k,v in report.items() if k not in ['cases','ordering_cases','scope']}))
    return bool(report['failures'])


if __name__ == '__main__':
    raise SystemExit(main())
