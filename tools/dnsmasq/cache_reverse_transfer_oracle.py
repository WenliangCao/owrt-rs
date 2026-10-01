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

from cache_reverse_transfer_cases import cases
from cache_transfer_diff import CACHE_SHA, IDENTITY_SHA, NATIVE_SHA, TARGET_IDENTITY_SHA, command, save, sha

BASELINE_SHA = '96fc7eed20067ebc134853620a799aa4a779afdcdf0fdb306815740c339dc941'


def build(args, out):
    base = args.transfer_baseline.resolve()
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
    identity = dict(scope=__doc__, baseline_identity_sha256=BASELINE_SHA,
                    native_reference_sha256=NATIVE_SHA, source_identity_sha256=IDENTITY_SHA,
                    target_reference_identity_sha256=TARGET_IDENTITY_SHA,
                    source_files=source['patched_files'], reused_objects=old,
                    driver_sha256=sha(driver), tool_sha256=sha(Path(__file__)),
                    cases_sha256=sha(Path(__file__).with_name('cache_reverse_transfer_cases.py')),
                    native_oracle_sha256=sha(built['native']), target_oracle_sha256=sha(built['target']))
    save(out / 'identity.json', identity)
    return [built['native']], [*target_prefix, built['target']]


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
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert [n for _, n in socket.if_nameindex()] == ['lo']
    out = args.out.resolve(); assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    schedule = cases(); assert len(schedule) == 21
    save(out / 'plan.json', schedule)
    report = dict(scope=__doc__, planned_cases=21, cases=[], failures=[], ordering_cases=[],
                  status='incomplete', planned_processes=126)
    try:
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
    print(json.dumps({k:v for k,v in report.items() if k not in ['cases','ordering_cases','scope']}))
    return bool(report['failures'])


if __name__ == '__main__':
    raise SystemExit(main())
