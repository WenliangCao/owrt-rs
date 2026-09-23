#!/usr/bin/env python3
"""Verify the fixed A53 Oracle unit/wire/FD/recovery evidence, without running tests."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r130_registration_report import check, digest, hashes, read
from r92_recovery_probe import classify_checks

C = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
R131 = 'c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a'
A53 = 'd491a90b8c4c518648d7aa034acd64b0046ea6c2e6c46c19fda3229bf9285488'
PROBE = '5500effd5af3b8ac34c2be91941acd1873a997733174a0d6cc6aaeebd54723f6'
NS = 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'
SCENARIOS = ('object_events', 'events', 'monitor', 'release', 'utf8', 'monitor_lookup', 'method_acl', 'remove_reply')
FD_CASES = ('separate_waited', 'separate_queued', 'plain_first_then_fd_second', 'bundled',
            'fd_in_first_body', 'fd_on_first_body_plus_second_frame')


def verify_archive(root, archive):
    actual = {}
    for path in root.rglob('*'):
        check(not path.is_symlink() and (path.is_file() or path.is_dir()), 'nonregular evidence')
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = digest(path)
    archived = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            name = member.name.removeprefix('./')
            check(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                  'unsafe archive member')
            if member.isdir():
                continue
            check(member.isfile() and name not in archived, 'nonregular/duplicate archive member')
            archived[name] = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
    check(archived == actual, 'archive differs from extracted evidence')
    manifest = read(root / 'evidence-manifest.json')
    check(len(manifest) == len(actual) - 1 and len({r['path'] for r in manifest}) == len(manifest),
          'manifest file count/uniqueness differs')
    check({r['path']: r['sha256'] for r in manifest} ==
          {p: h for p, h in actual.items() if p != 'evidence-manifest.json'}, 'manifest hashes differ')
    check(all((root / r['path']).stat().st_size == r['bytes'] for r in manifest), 'manifest sizes differ')
    return actual


def analyze(root, archive):
    evidence = verify_archive(root, archive)
    check((root / 'COMPLETE').is_file() and not (root / 'FAILED').exists()
          and not (root / 'failure.json').exists(), 'functional run incomplete/failed')
    result, plan = read(root / 'result.json'), read(root / 'plan.json')
    check(result['candidate_sha256'] == plan['candidate_sha256'] == A53
          and all(result[k] is True for k in ('passed', 'source_unchanged', 'artifacts_unchanged',
              'unit_effective_flags_match_release', 'scripts_unchanged')), 'functional result failed')
    build_plan = read(root / 'build-proof/frozen-plan.json')
    build = read(root / 'build-proof/results.json')
    check(digest(root / 'build-proof/frozen-plan.json') == plan['build_plan_sha256'] == build['frozen_plan_sha256']
          and digest(root / 'build-proof/results.json') == plan['build_results_sha256'] and build['passed'] is True,
          'build proof differs')
    sources = {r['label']: r for r in build_plan['variants']}
    builds = {r['label']: r for r in build['variants']}
    check(set(sources) == set(builds) == {'control', 'a53'}
          and builds['control']['sha256'] == R136 and builds['a53']['sha256'] == A53
          and all(r['status'] == 'built' and r['source_unchanged'] is True for r in builds.values())
          and sources['control']['source_sha256'] == sources['a53']['source_sha256'] == plan['source_sha256'],
          'same-source control/candidate proof differs')
    runtime = read(root / 'source-runtime-identity.json')
    check(len(runtime) == plan['runtime_files'] == result['runtime_files'] == 20
          and all(plan['source_sha256'][p] == h for p, h in runtime.items()), 'unit runtime source differs')
    flags = build['effective_rustflags']
    check(flags['a53'] == flags['control'] + ['-Ctarget-cpu=cortex-a53']
          and plan['effective_rustflags'] == flags['a53'], 'unexpected effective flags')
    unit_namespace = read(root / 'units/namespace.json')
    fingerprints = list(unit_namespace['cargo_dependency_fingerprints'].values())
    check(len(fingerprints) == 1 and fingerprints[0]['rustflags'] == flags['a53']
          and (root / 'units/rustflags.txt').read_text().split() == flags['a53']
          and unit_namespace['canonical_source_root'] == build_plan['canonical_source_root'],
          'unit/release effective flags or source path differs')
    for path, expected in plan['scripts'].items():
        check(digest(root / 'scripts' / Path(path).name) == expected, 'frozen wrapper changed')
    for step in ('units', 'gates', 'recovery'):
        check(read(root / f'{step}-exit.json') == {'exit': 0} and (root / step / 'COMPLETE').is_file(),
              f'{step} failed/incomplete')
    unit_log = (root / 'units/tests.log').read_text()
    check('test result: ok. 55 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' in unit_log
          and len([line for line in unit_log.splitlines() if line.startswith('test ') and line.endswith(' ... ok')]) == 55,
          'expected all 55 unit tests')
    unit_sha = digest(root / 'units/ubusd-tests')
    check(set(hashes(root / 'units/artifact-identities.txt').values()) == {unit_sha, A53}, 'unit/release identities differ')
    wire = []
    fd = []
    reference = read(ROOT / 'docs/reviews/r138-correctness-results.json')
    expected_wire = {r['scenario']: r['transcript_sha256'] for r in reference['wire']}
    for family, control in (('wire', R136), ('fd', R131)):
        folder = root / 'gates' / family
        raw = folder / 'raw'
        check((folder / 'COMPLETE').is_file() and (raw / 'COMPLETE').is_file(), f'{family} incomplete')
        for name, expected in [('ubusd-rs', A53), ('before-rs', control), ('owrt-benchmark', PROBE), ('ns-exec', NS)]:
            check(digest(folder / 'bundle' / name) == expected, f'{family} bundle identity differs')
        check(hashes(raw / 'binary-sha256.txt') == {'/tmp/bin/ubusd-rs': A53}, 'tested ELF differs')
        expected = {'/tmp/bin/owrt-benchmark': PROBE, '/tmp/bin/before-rs': control, '/sbin/ubusd': C}
        if family == 'fd':
            expected['/tmp/bin/ubusd-rs'] = A53
        check(hashes(raw / ('probe-identities.txt' if family == 'wire' else 'identities.txt')) == expected,
              f'{family} live identities differ')
        for side in ('c', 'before', 'candidate'):
            check(not (raw / f'{side}-daemon.log').read_bytes(), 'unexpected daemon log')
        if family == 'wire':
            for scenario in SCENARIOS:
                paths = [raw / f'{side}-{scenario}.txt' for side in ('c', 'before', 'candidate')]
                check(all(digest(p) == expected_wire[scenario] for p in paths), 'wire transcript mismatch')
                check(all(not (raw / f'{side}-{scenario}.log').read_bytes() for side in ('c', 'before', 'candidate')),
                      'wire probe emitted stderr')
                wire.append({'scenario': scenario, 'c_r136_candidate_identical': True,
                             'transcript_sha256': digest(paths[0]), 'lines': len(paths[0].read_text().splitlines())})
        else:
            transcripts = {}
            for side in ('c', 'before', 'candidate'):
                lines = (raw / f'{side}-fd_boundary.txt').read_text().splitlines()
                check(len(lines) == 7 and lines[-1] == 'fd_boundary compatible=true cases=6'
                      and [line.split()[0] for line in lines[:6]] == [f'case={c}' for c in FD_CASES]
                      and all('witness=true no_leak=true' in line for line in lines[:6]), 'FD cases/witness/leaks differ')
                contract = 'read_ahead' if side == 'candidate' else 'c'
                check(all(f'handcrafted contract={contract} ' in line and 'contract_match=true' in line for line in lines[3:6])
                      and all('compatible=true' in line for line in lines[:3]), 'FD contract differs')
                check(not (raw / f'{side}-fd_boundary.log').read_bytes()
                      and not (raw / f'{side}-objects-after.txt').read_bytes(), 'FD stderr/objects remain')
                transcripts[side] = lines
                fd.append({'side': {'before': 'r131'}.get(side, side), 'contract': contract,
                           'transcript_sha256': digest(raw / f'{side}-fd_boundary.txt'), 'cases': lines[:6]})
            check(transcripts['c'] == transcripts['before'] and transcripts['c'][:3] == transcripts['candidate'][:3],
                  'C/R131 or sender-framed FD mismatch')
    recovery = read(root / 'recovery/results.json')
    check(len(recovery) == 4 and {(r['side'], r['case']) for r in recovery} ==
          {(side, case) for side in ('original', 'candidate') for case in ('ubusd_halfclose', 'ubusd_lookup_delete')},
          'recovery coverage differs')
    check(read(root / 'recovery/binaries.json') == {'ubusd': {'original': C, 'candidate': A53}}
          and digest(root / 'bins/ubusd-rs') == A53, 'recovery ELF differs')
    for row in recovery:
        classified = classify_checks(row['case'], row['side'], row['exit'], row['checks'])
        check(classified['passed'] is True and all(row[k] == v for k, v in classified.items()), 'recovery gate classification differs')
        check(row['side'] != 'candidate' or all(value is True for value in row['checks'].values()), 'candidate recovery failed')
    return {'scope': 'R140 same-source Cortex-A53-only Oracle correctness; no performance verdict', 'passed': True,
        'source': {'same_runtime_as_r136': True, 'runtime_files_verified': 20, 'source_unchanged': True,
                   'runtime_identity_manifest_sha256': digest(root / 'source-runtime-identity.json'),
                   'build_plan_sha256': plan['build_plan_sha256'], 'build_results_sha256': plan['build_results_sha256']},
        'artifacts': {'candidate_sha256': A53, 'r136_sha256': R136, 'r131_fd_control_sha256': R131,
                      'exact_c_sha256': C, 'unit_tests_sha256': unit_sha, 'wireprobe_sha256': PROBE,
                      'wire_workload_sha256': digest(root / 'scripts/wire.sh'),
                      'fd_workload_sha256': digest(root / 'scripts/ubusd_fd_boundary.sh')},
        'unit_tests': {'passed': 55, 'failed': 0, 'flags_match_release': True, 'target_cpu': 'cortex-a53',
                       'build': 'Rust 1.98.1 aarch64 musl / OpenWrt 25.12.5 SDK release test profile',
                       'canonical_source_path_matches_release': True, 'log_sha256': digest(root / 'units/tests.log'),
                       'new_unit_tests': 0},
        'wire': wire, 'fd': fd,
        'recovery': [{k: v for k, v in row.items() if k != 'observations'} for row in recovery],
        'evidence': {'archive_sha256': digest(archive), 'manifest_sha256': digest(root / 'evidence-manifest.json'),
                     'verified_files': len(evidence), 'files': dict(sorted(evidence.items())),
                     'analyzer_sha256': digest(Path(__file__)),
                     'support_sha256': {p: digest(ROOT / p) for p in ('tools/r130_registration_report.py',
                        'tools/r92_recovery_probe.py', 'docs/reviews/r138-correctness-results.json')}},
        'limits': ['Oracle functional evidence only; no router task, deployment, or comparative wall-performance gate.',
                   'Unit test ELF is separately built under the release test profile with exactly the A53 release RUSTFLAGS; it is not the deployed candidate ELF.',
                   'Three handcrafted FD cases enforce the accepted read-ahead contract, not exact C placement.',
                   'Known exact-C halfclose/lookup-delete failures remain the unchanged recovery gate expectations.',
                   'All existing functional probes are reused; no new test cases or runtime source changes.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.root, args.archive)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'passed': result['passed'], 'unit_tests': 55, 'wire': 8, 'fd': 6,
                      'recovery': 2, 'verified_files': result['evidence']['verified_files']}))


if __name__ == '__main__':
    main()
