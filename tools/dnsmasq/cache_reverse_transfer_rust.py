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

from cache_reverse_transfer_oracle import calibrate, compare, save, sha

IDENTITY = '258e62717009ad9e2567aeda2b82dab81dbd68e2c5a04cd0b7fc4e69a435c516'
PLAN = '2d546b0e47749a2dce5e3863be6136f336155db2dd05c680452f26f7717e468d'
RESULT = 'd581b6c4690f4ec9ba844cc09303c9a282eb4852243a172efc9deec5f5d7f705'
TEST = 'dns::cache::reverse_transfer_gate::exact_c_reverse_transfer_probe'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'source', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--inject-error', action='store_true')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    source, base, out = args.source.resolve(), args.baseline.resolve(), args.out.resolve()
    assert 'private' in out.parts and 'private' in source.parts
    out.mkdir(parents=True, exist_ok=False)
    assert sha(base/'identity.json') == IDENTITY and sha(base/'plan.json') == PLAN and sha(base/'result.json') == RESULT
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
    assert not target_adapter.exists()
    target_adapter.write_bytes(adapter.read_bytes())
    cache = source/'components/dnsmasq/src/dns/cache.rs'
    cache.write_text(cache.read_text() + '\n#[cfg(test)]\n#[path = "cache_reverse_transfer_gate.rs"]\nmod reverse_transfer_gate;\n')
    report = dict(scope=__doc__, source_commit=args.source_commit, original_source_files=originals,
                  adapter_sha256=sha(adapter), instrumented_cache_sha256=sha(cache), tool_sha256=sha(Path(__file__)),
                  c_identity_sha256=IDENTITY, c_plan_sha256=PLAN, c_result_sha256=RESULT,
                  cases=[], ordering_cases=[], failures=[], inject_error=args.inject_error)
    command = [args.cargo,'+1.98.1','test','--manifest-path',str(source/'components/dnsmasq/Cargo.toml'),'--lib','--no-run','--message-format=json','--target-dir',str(out/'target')]
    build = subprocess.run(command, text=True, capture_output=True)
    (out/'build.stdout').write_text(build.stdout); (out/'build.stderr').write_text(build.stderr)
    save(out/'build-command.json', {'argv':command,'exit':build.returncode})
    if build.returncode:
        report['failures'].append('build failed; retained stderr'); save(out/'result.json',report); return 1
    executables = [Path(d['executable']) for line in build.stdout.splitlines() if (d := json.loads(line)).get('reason') == 'compiler-artifact' and d.get('executable') and d.get('profile',{}).get('test')]
    assert len(executables) == 1
    report['probe_sha256'] = sha(executables[0])
    for index, case in enumerate(schedule):
        env = dict(os.environ, DNSMASQ_REVERSE_TRANSFER_CASE=str(base/case['label']), DNSMASQ_REVERSE_TRANSFER_NOW=str(case['now']))
        command = [str(executables[0]),TEST,'--ignored','--exact','--nocapture','--test-threads=1']
        run = subprocess.run(command, env=env, text=True, capture_output=True)
        (out/(case['label']+'.stdout')).write_text(run.stdout); (out/(case['label']+'.stderr')).write_text(run.stderr)
        assert run.returncode == 0, (case['label'],run.returncode)
        actual = [line for line in run.stdout.splitlines() if line.startswith(('P0 ','P1 ','R ','CH ','P2 '))]
        expected = (base/case['label']/'native-0.stdout').read_text().splitlines()
        if args.inject_error and index == 0: expected[-1] += ' altered'
        differences = compare(expected, actual)
        row = dict(case=case['label'],observations=len(actual),differences=[{'row':i,'c':expected[i],'rust':actual[i]} for i in differences])
        if case['ordering']:
            row['comparisons_to_all_frozen_runs'] = {f'{label}-{repeat}': compare((base/case['label']/f'{label}-{repeat}.stdout').read_text().splitlines(),actual) for label in ['native','target'] for repeat in range(3)}
            report['ordering_cases'].append(row)
        else: report['cases'].append(row)
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
