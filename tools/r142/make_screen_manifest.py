#!/usr/bin/env python3
"""Bind the single completed monitor build and correctness proof; no execution."""
import argparse
from pathlib import Path
from monitor_screen import ROOT, POLICY, TOOLS, R136, old, read, save, sha, check, validate_manifest


def manifest(build, source_path, correctness_path, reference_path, helper):
    plan_path, result_path = build / 'frozen-plan.json', build / 'results.json'
    plan, result, source, correctness = map(read, (plan_path, result_path, source_path, correctness_path))
    check(result['passed'] is True and result['frozen_plan_sha256'] == sha(plan_path)
          and plan['canonical_source_root'] == '/tmp/owrt-build/r135/r136-combined-01', 'build proof differs')
    variants = {v['label']: v for v in plan['variants']}
    built = {v['label']: v for v in result['variants']}
    sources = {v['label']: v for v in source['variants']}
    check(len(variants) == len(built) == len(sources) == 2 and set(variants) == set(built) == set(sources) == {'control', 'monitor'},
          'expected one generic control and one monitor candidate')
    check(built['control']['sha256'] == R136 and source['changed_files'] == ['ubusd/src/server.rs'], 'control/source scope differs')
    flags = []
    for label in variants:
        item, proof = variants[label], built[label]
        check(proof['status'] == 'built' and proof['source_unchanged'] is True and sha(item['output']) == proof['sha256']
              and item['source_sha256'] == sources[label]['source_sha256'] and len(item['source_sha256']) == 30, 'built identity/source differs')
        namespace = proof['namespace']
        fingerprints = list(namespace['cargo_dependency_fingerprints'].values())
        check(namespace['canonical_source_root'] == plan['canonical_source_root'] and len(fingerprints) == 1, 'build namespace differs')
        flags.append(fingerprints[0]['rustflags'])
    check(flags[0] == flags[1] and not any(any(s in flag for s in ('target-cpu', 'profile-generate', 'profile-use')) for flag in flags[0]), 'generic flags differ')
    check([p for p in sources['control']['source_sha256'] if sources['control']['source_sha256'][p] != sources['monitor']['source_sha256'][p]] == ['ubusd/src/server.rs'], 'unexpected source change')
    check(correctness['passed'] is True and correctness['artifacts']['r136_sha256'] == R136
          and correctness['artifacts']['candidate_sha256'] == built['monitor']['sha256']
          and correctness['unit_tests']['passed'] == 56 and len(correctness['wire']) == 8
          and len(correctness['fd']) == 3 and len(correctness['recovery']) == 4, 'candidate correctness proof incomplete')
    reference = read(reference_path)
    originals = [v for v in reference['subjects'] if v['kind'] == 'c']
    check(len(originals) == 1 and originals[0]['sha256'] == old.STOCK_SHA, 'exact C missing')
    rootfs = str(Path(reference['rootfs']['loader']).parent.parent)
    subjects = {'c': {k: originals[0][k] for k in ('path', 'sha256', 'kind')}}
    for label, variant in (('r136', 'control'), ('candidate', 'monitor')):
        subjects[label] = {'path': str(Path(variants[variant]['output']).resolve()), 'sha256': built[variant]['sha256'], 'kind': 'rust'}
    result = {'schema': 1, 'policy': read(POLICY), 'policy_sha256': sha(POLICY), 'subjects': subjects,
              'helper': {'path': str(helper.resolve()), 'sha256': old.HELPER_SHA}, 'rootfs': rootfs,
              'libraries': {str(Path(rootfs) / p.lstrip('/')): h for p, h in old.LIBRARIES.items()},
              'tools': {p: sha(ROOT / p) for p in TOOLS},
              'correctness': {'passed': True, 'candidate_sha256': built['monitor']['sha256']},
              'proofs': {name: {'path': str(path.resolve()), 'sha256': sha(path)} for name, path in
                         [('source', source_path), ('build_plan', plan_path), ('build_result', result_path),
                          ('correctness', correctness_path), ('reference', reference_path)]}}
    validate_manifest(result, live=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    for name in ('source', 'correctness', 'reference', 'helper', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    save(args.output, manifest(args.build, args.source, args.correctness, args.reference, args.helper))
    print(args.output)


if __name__ == '__main__':
    main()
