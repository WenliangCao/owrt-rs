#!/usr/bin/env python3
"""Bind one completed generic profile-use build/training set to the frozen screen.

Run where the existing Oracle artifact paths are accessible. This only writes a
manifest; the unchanged R136 collector owns execution, samples, and cleanup.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
BENCHMARK = '85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d'
TOOLS = ('tools/r136/oracle_batch.py', 'tools/r136/analyze_batch.py', 'tools/r135/analyze_screen.py',
         'tools/r141/make_screen_manifest.py', 'tools/r141/analyze_screen.py',
         'tools/r141/test_screen.py', 'tools/r141/screen-policy.json', 'docs/reviews/R141_SCREEN_PLAN.md')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def manifest(build, reference_path, training_path):
    plan_path, result_path = build / 'frozen-plan.json', build / 'results.json'
    plan, result = read(plan_path), read(result_path)
    require(result.get('passed') is True and result['stage'] == plan['stage'] == 'use'
            and result['frozen_plan_sha256'] == sha(plan_path), 'profile-use build proof failed or changed')
    require(plan['canonical_source_root'] == '/tmp/owrt-build/r135/r136-combined-01'
            and plan['std_rebuilt'] is False and plan['cpu_target'] == 'original generic; no target-cpu override',
            'profile-use is not the frozen generic R136 recipe')
    builds = {r['label']: r for r in result['variants']}
    variants = {r['label']: r for r in plan['variants']}
    require(len(result['variants']) == len(plan['variants']) == 2 and set(builds) == set(variants) == {'control', 'use'},
            'expected exactly the R136 control and one use candidate')
    require(builds['control']['sha256'] == R136 and len(variants['control']['source_sha256']) == 30
            and variants['control']['source_sha256'] == variants['use']['source_sha256'], 'control/source proof differs')
    for label in builds:
        require(builds[label]['status'] == 'built' and builds[label]['source_unchanged'] is True
                and sha(variants[label]['output']) == builds[label]['sha256'], f'build artifact changed: {label}')
    profile = plan['profile_input']
    extra = [f'-Cprofile-use={profile["path"]}', '-Cllvm-args=-pgo-warn-missing-function']
    flags = result['effective_rustflags']
    require(plan['extra_flags'] == extra and flags['use'] == flags['control'] + extra
            and not any(any(token in flag for token in ('target-cpu', 'profile-generate', 'profile-use'))
                        for flag in flags['control']), 'effective flags differ from generic profile-use only')
    require(sha(profile['path']) == profile['sha256'], 'merged profile changed after build')
    training, training_plan_path = read(training_path), training_path.with_name('plan.json')
    training_plan = read(training_plan_path)
    require((training_path.parent / 'COMPLETE').is_file() and not (training_path.parent / 'FAILED').exists()
            and training.get('passed') is True and training['frozen_plan_sha256'] == sha(training_plan_path)
            and training['profdata_sha256'] == profile['sha256'] == sha(training['profdata'])
            and all(training.get(k) is True for k in ('merged_once', 'no_timing_selection', 'smoke_excluded')),
            'one completed, unselected training profile is required')
    require(training_plan['expected_raw_profiles'] == len(training['profiles']) == 8
            and {p['class'] for p in training['profiles']} == set(training_plan['classes'])
            and all(p['passed'] is True and p['daemon_exit'] == 0
                    and p['daemon_sha256'] == training['instrumented_sha256']
                    and sha(p['profile']) == p['profile_sha256'] for p in training['profiles']),
            'training class/normal-exit/profile evidence differs')
    reference = read(reference_path)
    originals = [r for r in reference['subjects'] if r['kind'] == 'c']
    require(len(originals) == 1 and originals[0]['sha256'] == C
            and reference['benchmark']['sha256'] == BENCHMARK, 'C or original R135 caller identity differs')
    require(sha(originals[0]['path']) == C and sha(reference['benchmark']['path']) == BENCHMARK,
            'reference artifacts changed')
    require(all(sha(path) == expected for path, expected in reference['libraries'].items()), 'C libraries changed')
    subjects = [{**originals[0], 'label': 'c'}]
    for label, build_label in (('r136', 'control'), ('pgo', 'use')):
        subjects.append({'label': label, 'kind': 'rust', 'path': variants[build_label]['output'],
                         'sha256': builds[build_label]['sha256']})
    policy_path = Path(__file__).with_name('screen-policy.json')
    return {'schema': 1, **{k: reference[k] for k in ('benchmark', 'rootfs', 'libraries')},
            'subjects': subjects, 'r141_policy': read(policy_path),
            'provenance': {'build_plan_sha256': sha(plan_path), 'build_results_sha256': sha(result_path),
                           'reference_manifest_sha256': sha(reference_path),
                           'training_plan_sha256': sha(training_plan_path), 'training_results_sha256': sha(training_path),
                           'profile_sha256': profile['sha256'], 'profile_use_sha256': builds['use']['sha256'],
                           'same_source_sha256': variants['control']['source_sha256'],
                           'effective_rustflags': flags, 'policy_sha256': sha(policy_path),
                           'tool_sha256': {name: sha(ROOT / name) for name in TOOLS}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--training-results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = manifest(args.build, args.reference, args.training_results)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(args.output)


if __name__ == '__main__':
    main()
