#!/usr/bin/env python3
"""Compare frozen reverse transfer C output with actual Rust Cache APIs.

A cfg(test) adapter is added only to a fresh private source copy. The candidate
runtime implementation is unchanged; local matching follows the existing
private TCP caller, including its configured-CNAME branch without a reverse guard.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from cache_reverse_transfer_oracle import calibrate, compare, save, sha, validate_fresh_reverse
import rust_lib_probe

IDENTITY = '258e62717009ad9e2567aeda2b82dab81dbd68e2c5a04cd0b7fc4e69a435c516'
PLAN = '2d546b0e47749a2dce5e3863be6136f336155db2dd05c680452f26f7717e468d'
RESULT = 'd581b6c4690f4ec9ba844cc09303c9a282eb4852243a172efc9deec5f5d7f705'
TEST = 'dns::cache::reverse_transfer_gate::exact_c_reverse_transfer_probe'
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source', type=Path, help='legacy private source copy; copied probes use rust-source-root')
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--inject-error', action='store_true')
    parser.add_argument('--fresh-c-receipt', type=Path, help='new reverse C receipt; historical identity/result pins otherwise')
    rust_lib_probe.add_arguments(parser)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    base, out = args.baseline.resolve(), args.out.resolve()
    try:
        probe, source, binding = rust_lib_probe.selection(args, args.source or ROOT, out)
    except ValueError as error:
        parser.error(str(error))
    if probe is None and not args.source:
        parser.error('--local-native reverse probe requires an explicit --source private copy')
    if args.source and args.source.resolve() != source:
        parser.error('--source and frozen --rust-source-root disagree')
    assert 'private' in out.parts
    if probe is None:
        assert 'private' in source.parts
    out.mkdir(parents=True, exist_ok=False)
    assert sha(base/'plan.json') == PLAN
    fresh_c = None
    if args.fresh_c_receipt:
        fresh_c = validate_fresh_reverse(base, args.fresh_c_receipt.resolve())
    else:
        assert sha(base/'identity.json') == IDENTITY and sha(base/'result.json') == RESULT
    cresult = json.loads((base/'result.json').read_text())
    assert cresult['status'] == 'C-baseline-complete' and not cresult['failures']
    schedule = json.loads((base/'plan.json').read_text())
    for row in cresult['cases'] + cresult['ordering_cases']:
        for run, digest in row['result_sha256'].items():
            assert sha(base/row['case']/(run+'.stdout')) == digest
    originals = {str(p.relative_to(source)): sha(p) for part in ['dnsmasq','ubus']
                 for p in (source/'components'/part).rglob('*')
                 if p.is_file() and 'target' not in p.parts and (p.suffix == '.rs' or p.name in ['Cargo.toml','Cargo.lock'])}
    adapter = Path(__file__).with_name('cache_reverse_transfer_probe.rs')
    target_adapter = source/'components/dnsmasq/src/dns/cache_reverse_transfer_gate.rs'
    cache = source/'components/dnsmasq/src/dns/cache.rs'
    if probe:
        if not target_adapter.exists() or sha(target_adapter) != sha(adapter) or 'mod reverse_transfer_gate;' not in cache.read_text():
            raise ValueError('copied reverse probe requires the exact cfg(test) adapter in its frozen build inputs')
    else:
        assert not target_adapter.exists()
        target_adapter.write_bytes(adapter.read_bytes())
        cache.write_text(cache.read_text() + '\n#[cfg(test)]\n#[path = "cache_reverse_transfer_gate.rs"]\nmod reverse_transfer_gate;\n')
        # Only the explicit legacy private-copy mode injects test source.
        binding['source_files'] = rust_lib_probe.source_files(source)
    report = dict(scope=__doc__, source_commit=args.source_commit, original_source_files=originals,
                  adapter_sha256=sha(adapter), instrumented_cache_sha256=sha(cache), tool_sha256=sha(Path(__file__)),
                  c_identity_sha256=sha(base/'identity.json'), c_plan_sha256=PLAN, c_result_sha256=sha(base/'result.json'),
                  fresh_c_receipt=fresh_c,
                  rust_probe=binding, rust_test=TEST,
                  original_source_scope='frozen probe inputs include cfg(test) adapter' if probe else 'legacy private copy before adapter injection',
                  c_reference_scope=('fresh exact-source reverse C primitive; original 21-case exact ordered comparator; not image097' if fresh_c else
                                     'historical pinned reverse native/target C transcripts; additional regression, not fresh A service'),
                  cases=[], ordering_cases=[], failures=[], inject_error=args.inject_error)
    if probe is None:
        command = [args.cargo,'+1.98.1','test','--manifest-path',str(source/'components/dnsmasq/Cargo.toml'),'--lib','--no-run','--message-format=json','--target-dir',str(out/'target')]
        build = subprocess.run(command, text=True, capture_output=True)
        (out/'build.stdout').write_text(build.stdout); (out/'build.stderr').write_text(build.stderr)
        save(out/'build-command.json', {'argv':command,'exit':build.returncode})
        if build.returncode:
            report['failures'].append('build failed; retained stderr'); save(out/'result.json',report); return 1
        executables = [Path(d['executable']) for line in build.stdout.splitlines() if (d := json.loads(line)).get('reason') == 'compiler-artifact' and d.get('executable') and d.get('profile',{}).get('test')]
        assert len(executables) == 1
        probe = executables[0]
    report['probe_sha256'] = sha(probe)
    for index, case in enumerate(schedule):
        rust_lib_probe.recheck(binding)
        if fresh_c is not None and validate_fresh_reverse(base, args.fresh_c_receipt.resolve()) != fresh_c:
            raise ValueError('fresh reverse C receipt/source/raw changed during comparison')
        env = dict(os.environ, DNSMASQ_REVERSE_TRANSFER_CASE=str(base/case['label']), DNSMASQ_REVERSE_TRANSFER_NOW=str(case['now']))
        command = rust_lib_probe.argv(probe, TEST)
        run = subprocess.run(command, env=env, text=True, capture_output=True)
        (out/(case['label']+'.stdout')).write_text(run.stdout); (out/(case['label']+'.stderr')).write_text(run.stderr)
        if run.returncode:
            report['failures'].append({'case':case['label'],'exit':run.returncode})
            save(out/'result.json',report)
            return 1
        rust_lib_probe.require_one_test(run.stdout, TEST)
        actual = rust_lib_probe.records(run.stdout, TEST, ('P0 ','P1 ','R ','CH ','P2 '))
        expected = (base/case['label']/'native-0.stdout').read_text().splitlines()
        if args.inject_error and index == 0: expected[-1] += ' altered'
        differences = compare(expected, actual)
        row = dict(case=case['label'],observations=len(actual),differences=[{'row':i,'c':expected[i],'rust':actual[i]} for i in differences])
        if case['ordering']:
            row['comparisons_to_all_frozen_runs'] = {f'{label}-{repeat}': compare((base/case['label']/f'{label}-{repeat}.stdout').read_text().splitlines(),actual) for label in ['native','target'] for repeat in range(3)}
            report['ordering_cases'].append(row)
        else: report['cases'].append(row)
        rust_lib_probe.recheck(binding)
    if fresh_c is not None and validate_fresh_reverse(base, args.fresh_c_receipt.resolve()) != fresh_c:
        raise ValueError('fresh reverse C receipt/source/raw changed after comparison')
    report['compared'] = sum(r['observations'] for r in report['cases'])
    report['differing_states'] = sum(len(r['differences']) for r in report['cases'])
    report['matched'] = report['compared'] - report['differing_states']
    report['ordering_observations'] = sum(r['observations'] for r in report['ordering_cases'])
    report['ordering_differences_vs_native0'] = sum(len(r['differences']) for r in report['ordering_cases'])
    save(out/'result.json',report)
    print(json.dumps({k:report[k] for k in ['compared','matched','differing_states','ordering_observations','ordering_differences_vs_native0','failures']}))
    return bool(report['failures'] or report['differing_states'] or report['ordering_differences_vs_native0'])


if __name__ == '__main__':
    raise SystemExit(main())
