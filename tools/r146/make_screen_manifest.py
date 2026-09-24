#!/usr/bin/env python3
"""Bind the R146 build and completed correctness gates to the unchanged R142 screen."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r142.monitor_screen import ROOT, POLICY, TOOLS, R136, old, read, save, sha, check, validate_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'source', 'units', 'correctness', 'reference', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    plan_path, result_path = args.build / 'frozen-plan.json', args.build / 'results.json'
    plan, result, source = map(read, (plan_path, result_path, args.source))
    check(result['passed'] and result['frozen_plan_sha256'] == sha(plan_path), 'build proof failed')
    inputs = {r['label']: r for r in plan['variants']}
    builds = {r['label']: r for r in result['variants']}
    sources = {r['label']: r for r in source['variants']}
    check(set(inputs) == set(builds) == set(sources) == {'control', 'monitor'}, 'unexpected candidates')
    check(builds['control']['sha256'] == R136, 'R136 was not reproduced')
    flags = []
    for label in inputs:
        item, built = inputs[label], builds[label]
        check(built['status'] == 'built' and built['source_unchanged']
              and sha(item['output']) == built['sha256'], 'built artifact changed')
        check(item['source_sha256'] == sources[label]['source_sha256']
              and len(item['source_sha256']) == 30, 'source proof differs')
        check(all(sha(Path(item['components']) / p) == h for p, h in item['source_sha256'].items()), 'source changed')
        fingerprints = list(built['namespace']['cargo_dependency_fingerprints'].values())
        check(len(fingerprints) == 1, 'ambiguous dependency flags')
        flags.append(fingerprints[0]['rustflags'])
    changed = [p for p in inputs['control']['source_sha256']
               if inputs['control']['source_sha256'][p] != inputs['monitor']['source_sha256'][p]]
    check(changed == ['ubusd/src/client.rs', 'ubusd/src/server.rs'], 'unexpected source scope')
    check(flags[0] == flags[1] and not any('target-cpu' in f or 'profile-' in f for f in flags[0]), 'flags differ')
    candidate = builds['monitor']['sha256']
    units = read(args.units / 'result.json')
    check(units['passed'] and units['tests_passed'] == 62 and units['tests_failed'] == 0
          and units['candidate_sha256'] == candidate and units['effective_rustflags'] == flags[0]
          and units['unit_effective_flags_match_release'] and units['source_unchanged']
          and units['test_elf_sha256'] == sha(args.units / 'ubusd-tests')
          and units['tests_log_sha256'] == sha(args.units / 'tests.log'), 'unit proof differs')
    check('test result: ok. 62 passed; 0 failed;' in (args.units / 'tests.log').read_text(), 'unit suite incomplete')
    correctness = read(args.correctness / 'result.json')
    check(correctness == {'passed': True, 'candidate_sha256': candidate, 'inputs_unchanged': True,
                          'wire': 8, 'fd': 6, 'recovery': 2, 'stress': 12, 'monitor': 6}, 'correctness scope differs')
    for step in ('gates', 'recovery', 'stress', 'monitor'):
        check(read(args.correctness / f'{step}-exit.json') == {'exit': 0}
              and (args.correctness / step / 'COMPLETE').is_file(), 'correctness step failed')
    reference = read(args.reference)
    manifest = {k: reference[k] for k in ('schema', 'helper', 'rootfs', 'libraries')}
    manifest.update(policy=read(POLICY), policy_sha256=sha(POLICY),
        subjects={'c': reference['subjects']['c'],
                  'r136': {'path': inputs['control']['output'], 'sha256': R136, 'kind': 'rust'},
                  'candidate': {'path': inputs['monitor']['output'], 'sha256': candidate, 'kind': 'rust'}},
        tools={p: sha(ROOT / p) for p in TOOLS}, correctness={'passed': True, 'candidate_sha256': candidate},
        proofs={name: {'path': str(path.resolve()), 'sha256': sha(path)} for name, path in
                [('source', args.source), ('build_plan', plan_path), ('build_result', result_path),
                 ('units', args.units / 'result.json'), ('correctness', args.correctness / 'result.json'),
                 ('reference', args.reference), ('manifest_builder', Path(__file__))]})
    validate_manifest(manifest, live=True)
    save(args.output, manifest)
    print('Frozen one candidate, 54 cases, unchanged latency gate:', candidate)


if __name__ == '__main__':
    main()
