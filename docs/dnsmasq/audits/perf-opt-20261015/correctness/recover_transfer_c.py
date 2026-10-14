#!/usr/bin/env python3
"""Rebuild the frozen cache-transfer oracle from verified original inputs.

The deleted historical target metadata JSON cannot be substituted silently.
Verify every original runtime file instead, preserve the recovered original
native ELF/source identity pins, and additionally require the original complete
216-stdout digest. Cases, C driver, comparisons and expected traces are imported
unchanged. The existing fresh-c-receipt entry point binds these new build paths.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tools', 'reference-build', 'source-identity', 'sdk', 'target-reference', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.tools.resolve()))
    import cache_transfer_diff as original
    import cache_transfer_rust_diff as comparison
    import c_primitive_receipt as receipt
    import local_answer_diff as reference
    from dns_udp_refusal_diff import TARGET_FILES

    sha = receipt.digest
    save = original.save
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    objects = args.reference_build / 'dnsmasq'
    reference.validate_reference_variant(objects)
    assert sha(objects / 'dnsmasq') == original.NATIVE_SHA
    assert sha(args.source_identity) == original.IDENTITY_SHA
    identity = json.loads(args.source_identity.read_text())
    for name, expected in TARGET_FILES.items():
        assert sha(args.target_reference / name) == expected, name
    native_objects = sorted(p for p in objects.glob('*.o')
                            if p.name not in {'cache.o', 'dnsmasq.o', 'dnsmasq-renamed.o'})
    sources = [objects / (p.stem + '.c') for p in native_objects]
    sources += [objects / 'dnsmasq.c', objects / 'cache.c']
    for path in sources:
        assert sha(path) == identity['patched_files']['src/' + path.name], path
    driver = args.tools / 'cache_transfer_driver.c'
    frozen = receipt.snapshot([args.source_identity, objects,
                               args.reference_build / 'deps/include',
                               args.reference_build / 'deps/lib', args.target_reference, driver])
    save(out / 'source-inputs-before.json', frozen)
    flags = [*reference.REFERENCE_COPTS, '-DVERSION="2.93"', '-O2', '-Wall', '-Wextra',
             '-ffunction-sections', '-fdata-sections', f'-I{objects}',
             f'-I{args.reference_build / "deps/include"}']
    renamed = reference.rename_main(objects, out)
    deps = args.reference_build / 'deps/lib'
    original.command(args, out, 'native-build', ['cc', *flags, '-Werror', driver,
        *native_objects, renamed, f'-L{deps}', f'-Wl,-rpath,{deps}', '-lubus', '-lubox',
        '-o', out / 'native-oracle'])
    cc = args.sdk / 'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc'
    env = dict(os.environ, STAGING_DIR=str(args.sdk / 'staging_dir'))
    target_objects = out / 'target-objects'
    target_objects.mkdir()
    # One compiler job, preserving exactly the original flags and object set.
    for path in sources:
        if path.name == 'cache.c':
            continue
        extra = ['-Dmain=reference_main'] if path.name == 'dnsmasq.c' else []
        original.command(args, target_objects, path.stem,
            [cc, *flags, *extra, '-c', path, '-o', target_objects / (path.stem + '.o')], env=env)
    original.command(args, out, 'target-build', [cc, *flags, '-Werror', driver,
        *sorted(target_objects.glob('*.o')), '-Wl,--gc-sections', '-o', out / 'target-oracle'], env=env)
    target = [args.target_reference / 'lib/libc.so', '--library-path',
              args.target_reference / 'lib', out / 'target-oracle']
    original.command(args, out, 'target-dependencies', [*target[:3], '--list', target[-1]])
    compilers = [receipt.compiler_probe(out, 'native', 'cc'),
                 receipt.compiler_probe(out, 'target', cc, env)]
    save(out / 'identity.json', {
        'scope': 'Exact original C source/native ELF/driver/corpus; newly recorded target metadata paths',
        'native_reference_sha256': original.NATIVE_SHA,
        'source_identity_sha256': original.IDENTITY_SHA,
        'cache_source_sha256': original.CACHE_SHA,
        'compiled_sources': {p.name: sha(p) for p in sources},
        'native_objects': {p.name: sha(p) for p in [*native_objects, renamed]},
        'target_objects': {p.name: sha(p) for p in target_objects.glob('*.o')},
        'driver_sha256': sha(driver), 'builder_sha256': sha(__file__),
        'native_oracle_sha256': sha(out / 'native-oracle'),
        'target_oracle_sha256': sha(out / 'target-oracle'),
        'historical_target_metadata_missing': original.TARGET_IDENTITY_SHA,
        'verified_original_runtime_files': TARGET_FILES,
    })
    schedule = original.cases()
    assert len(schedule) == 36
    save(out / 'plan.json', schedule)
    assert sha(out / 'plan.json') == comparison.PLAN_SHA
    report = {'scope': 'Unchanged frozen transfer corpus, fresh C builds',
              'planned_cases': 36, 'cases': [], 'cross_runtime_differences': []}
    for case in schedule:
        folder = out / case['label']
        folder.mkdir()
        (folder / 'config').write_text(f"no-hosts\nno-resolv\ncache-size={case['capacity']}\n" + case['config'])
        for stage in ('pre', 'child', 'between', 'after'):
            (folder / stage).write_text(''.join(line + '\n' for line in case[stage]))
        suffix = [folder / n for n in ('config', 'pre', 'child', 'between', 'after')] + [str(case['now'])]
        observed = {}
        for label, prefix in [('native', [out / 'native-oracle']), ('target', target)]:
            runs = [original.command(args, folder, f'{label}-{i}', [*prefix, *suffix]) for i in range(3)]
            assert runs[0] == runs[1] == runs[2], (case['label'], label)
            transferred = sum(line.startswith('CH C 1 |') for line in runs[0])
            assert sum(line.startswith('R ') for line in runs[0]) == transferred
            assert len(runs[0]) == sum(len(case[s]) for s in ('pre', 'child', 'between', 'after')) + transferred
            observed[label] = runs[0]
        equal = observed['native'] == observed['target']
        report['cases'].append({'case': case['label'], 'native_observations': len(observed['native']),
                               'target_observations': len(observed['target']), 'cross_runtime_equal': equal})
        if not equal:
            report['cross_runtime_differences'].append(case['label'])
    report['completed_cases'] = len(report['cases'])
    report['observations_per_runtime'] = sum(row['native_observations'] for row in report['cases'])
    calibration = (out / 'expiry-None-103/native-0.stdout').read_text().splitlines()
    assert calibration == ['R 1 | 1 0', 'CH B | 0 0', 'CH I 1 | 0 0', 'CH C 1 | 1 0',
                           'CH Q 0:110:0:7 | 1 0', 'P2 Q 0:110:0:7 | 1 0']
    changed = calibration.copy()
    changed[-1] = changed[-1].replace('| 1 0', '| 2 0')
    assert len(comparison.compare(calibration, changed)) == 1
    report['calibration'] = {'equal': 6, 'changed_counter_detected': 1, 'all_schedules_count_checked': True}
    assert report['observations_per_runtime'] == 307 and not report['cross_runtime_differences']
    traces = {str(p.relative_to(out)): sha(p) for p in sorted(out.glob('*/*.stdout'))
              if p.parent.name != 'target-objects'}
    assert len(traces) == 216
    trace_digest = hashlib.sha256(json.dumps(traces, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert trace_digest == comparison.STDOUT_DIGEST, 'historical C raw output changed'
    report['original_216_stdout_digest'] = trace_digest
    report['status'] = 'C-baseline-only'
    save(out / 'result.json', report)
    receipt.freeze(out, 'cache-transfer', args.source_identity, frozen, compilers,
                   [out / 'native-oracle', out / 'target-oracle'], True)
    receipt.validate_fresh(out, out / 'fresh-c-receipt.json', 'cache-transfer')
    print(json.dumps({'completed_cases': 36, 'observations_per_runtime': 307,
                      'historical_216_stdout_digest_exact': trace_digest}))


if __name__ == '__main__':
    main()
