#!/usr/bin/env python3
"""Offline verification of R142 unit/wire/FD/recovery and monitor boundaries."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r140 import analyze_correctness as old
from r134 import ubusd_stress_oracle as stress

check, digest, read, hashes = old.check, old.digest, old.read, old.hashes
C, R136, R131, PROBE, NS = old.C, old.R136, old.R131, old.PROBE, old.NS
CANDIDATE = '367badc11fb93b25208cda041048133b8439e1c703c2cb07d740312cc140db54'


def analyze(root, archive):
    evidence = old.verify_archive(root, archive)
    check((root / 'COMPLETE').is_file() and not (root / 'FAILED').exists(), 'functional run failed')
    result, plan = read(root / 'result.json'), read(root / 'plan.json')
    check(result == {'passed': True, 'candidate_sha256': CANDIDATE, 'inputs_unchanged': True,
                    'wire': 8, 'fd': 6, 'recovery': 2, 'stress': 12, 'monitor': 6}, 'coverage/result differs')
    check(plan['candidate_sha256'] == CANDIDATE and plan['wire_control'] == 'r136'
          and plan['fd_control'] == plan['stress_control'] == 'r131', 'control identity differs')
    build_plan, build = read(root / 'build-proof/frozen-plan.json'), read(root / 'build-proof/results.json')
    check(build['passed'] is True and build['frozen_plan_sha256'] == digest(root / 'build-proof/frozen-plan.json'), 'build failed')
    sources = {r['label']: r['source_sha256'] for r in build_plan['variants']}
    built = {r['label']: r for r in build['variants']}
    check(set(sources) == set(built) == {'control', 'monitor'}
          and built['control']['sha256'] == R136 and built['monitor']['sha256'] == CANDIDATE
          and all(r['status'] == 'built' and r['source_unchanged'] is True for r in built.values()), 'release identity differs')
    check(len(sources['control']) == len(sources['monitor']) == 30
          and set(sources['control']) == set(sources['monitor'])
          and [p for p in sources['control'] if sources['control'][p] != sources['monitor'][p]] == ['ubusd/src/server.rs'],
          'unexpected source difference')
    flags = [list(r['namespace']['cargo_dependency_fingerprints'].values())[0]['rustflags'] for r in built.values()]
    check(flags[0] == flags[1] and not any('target-cpu' in flag or 'profile-' in flag for flag in flags[0]), 'generic flags differ')
    for path, expected in plan['input_sha256'].items():
        p = Path(path)
        local = root / ('build-proof' if p.parent.name == 'build-01' else 'bins' if p.name == 'ubusd-rs' else 'scripts') / p.name
        check(digest(local) == expected, 'frozen functional input differs')
    units, unit_plan = read(root / 'units/result.json'), read(root / 'units/plan.json')
    check(all(units[k] is True for k in ('passed', 'source_unchanged', 'scripts_unchanged', 'unit_effective_flags_match_release'))
          and units['tests_passed'] == 56 and units['tests_failed'] == 0 and units['candidate_sha256'] == CANDIDATE
          and units['plan_sha256'] == digest(root / 'units/plan.json')
          and units['test_elf_sha256'] == digest(root / 'units/ubusd-tests')
          and units['tests_log_sha256'] == digest(root / 'units/tests.log'), 'unit result differs')
    check(unit_plan['source_sha256'] == sources['monitor'] and unit_plan['expected_rustflags'] == units['effective_rustflags'] == flags[0]
          and unit_plan['build_plan_sha256'] == digest(root / 'build-proof/frozen-plan.json')
          and unit_plan['build_results_sha256'] == digest(root / 'build-proof/results.json'), 'unit build proof differs')
    namespace = read(root / 'units/namespace.json')
    fingerprints = list(namespace['cargo_dependency_fingerprints'].values())
    check(len(fingerprints) == 1 and fingerprints[0]['rustflags'] == flags[0]
          and namespace['canonical_source_root'] == unit_plan['canonical_source_root'] == build_plan['canonical_source_root']
          and (root / 'units/rustflags.txt').read_text().split() == flags[0], 'unit/release flags or path differ')
    for name, expected in unit_plan['scripts'].items():
        check(digest(root / 'unit-scripts' / name) == expected, 'unit script differs')
    tests = (root / 'units/tests.log').read_text()
    check('test result: ok. 56 passed; 0 failed;' in tests and len([s for s in tests.splitlines() if s.startswith('test ') and s.endswith(' ... ok')]) == 56
          and 'independent_monitors_keep_wrapping_sequences_and_queued_bytes ... ok' in tests, '56 unit coverage missing')
    wire, fd = [], []
    wire_reference = {r['scenario']: r['transcript_sha256'] for r in read(ROOT / 'docs/reviews/r138-correctness-results.json')['wire']}
    for step in ('gates', 'recovery', 'stress', 'monitor'):
        check(read(root / f'{step}-exit.json') == {'exit': 0} and (root / step / 'COMPLETE').is_file(), f'{step} failed')
    for family, control in (('wire', R136), ('fd', R131)):
        folder = root / 'gates' / family; raw = folder / 'raw'
        check((folder / 'COMPLETE').is_file() and (raw / 'COMPLETE').is_file(), 'wire/FD incomplete')
        for name, expected in [('ubusd-rs', CANDIDATE), ('before-rs', control), ('owrt-benchmark', PROBE), ('ns-exec', NS)]:
            check(digest(folder / 'bundle' / name) == expected, 'wire/FD bundle differs')
        check(hashes(raw / 'binary-sha256.txt') == {'/tmp/bin/ubusd-rs': CANDIDATE}, 'wire/FD candidate differs')
        expected = {'/tmp/bin/owrt-benchmark': PROBE, '/tmp/bin/before-rs': control, '/sbin/ubusd': C}
        if family == 'fd': expected['/tmp/bin/ubusd-rs'] = CANDIDATE
        check(hashes(raw / ('probe-identities.txt' if family == 'wire' else 'identities.txt')) == expected, 'live wire/FD identity differs')
        for side in ('c', 'before', 'candidate'):
            check(not (raw / f'{side}-daemon.log').read_bytes(), 'wire/FD daemon log nonempty')
        if family == 'wire':
            for scenario in old.SCENARIOS:
                check(all(digest(raw / f'{s}-{scenario}.txt') == wire_reference[scenario]
                          and not (raw / f'{s}-{scenario}.log').read_bytes() for s in ('c', 'before', 'candidate')), 'wire transcript differs')
                wire.append({'scenario': scenario, 'c_r136_candidate_identical': True, 'transcript_sha256': wire_reference[scenario]})
        else:
            for side in ('c', 'before', 'candidate'):
                lines = (raw / f'{side}-fd_boundary.txt').read_text().splitlines()
                contract = 'read_ahead' if side == 'candidate' else 'c'
                check(len(lines) == 7 and lines[-1] == 'fd_boundary compatible=true cases=6'
                      and [s.split()[0] for s in lines[:6]] == [f'case={c}' for c in old.FD_CASES]
                      and all('witness=true no_leak=true' in s for s in lines[:6])
                      and all('compatible=true' in s for s in lines[:3])
                      and all(f'handcrafted contract={contract} ' in s and 'contract_match=true' in s for s in lines[3:6]), 'FD contract differs')
                check(not (raw / f'{side}-fd_boundary.log').read_bytes() and not (raw / f'{side}-objects-after.txt').read_bytes(), 'FD cleanup failed')
                fd.append({'side': {'before': 'r131'}.get(side, side), 'contract': contract, 'cases': lines[:6]})
            check(fd[0]['cases'] == fd[1]['cases'] and fd[0]['cases'][:3] == fd[2]['cases'][:3], 'FD C/R131 or framing differs')
    recovery = read(root / 'recovery/results.json')
    check(len(recovery) == 4 and {(r['side'], r['case']) for r in recovery} ==
          {(s, c) for s in ('original', 'candidate') for c in ('ubusd_halfclose', 'ubusd_lookup_delete')}, 'recovery set differs')
    check(read(root / 'recovery/binaries.json') == {'ubusd': {'original': C, 'candidate': CANDIDATE}}, 'recovery ELF differs')
    for row in recovery:
        classified = old.classify_checks(row['case'], row['side'], row['exit'], row['checks'])
        check(classified['passed'] is True and all(row[k] == v for k, v in classified.items())
              and (row['side'] != 'candidate' or all(row['checks'].values())), 'recovery classification failed')
    native = read(root / 'stress/result.json'); native_plan = read(root / 'stress/plan.json')
    check(native['passed'] is True and len(native['cases']) == 12 and native_plan['helper_sha256'] == stress.HELPER_SHA
          and native_plan['normal_count'] == 100 and native_plan['slow_count'] == 192, 'native helper plan differs')
    check({k: v['sha256'] for k, v in native_plan['subjects'].items()} == {'c': C, 'r131': R131, 'r134': CANDIDATE}, 'native subjects differ')
    check({(r['label'], r['mode']) for r in native['cases']} == {(s, m) for s in ('c', 'r131', 'r134') for m in ('grouped', 'interleaved', 'monitor', 'slow')}, 'native cases differ')
    for row in native['cases']:
        folder = root / 'stress' / f"{row['label']}-{row['mode']}"
        before, after = read(folder / 'identity-before.json'), read(folder / 'identity-after.json')
        check(row['passed'] and row['caller_exit'] == 0 and row['daemon_exit'] in (0, -15)
              and before == after and before['affinity'] == [1], 'native process/cleanup failed')
        check(row['checks'] == stress.validate((folder / 'caller.jsonl').read_text(), row['mode'],
              192 if row['mode'] == 'slow' else 100, before['pid']), 'native fixture check differs')
        check(not (folder / 'caller.stderr').read_bytes() and not (folder / 'daemon.log').read_bytes(), 'native logs nonempty')
        check(all(digest(folder / name) == h for name, h in row['raw_sha256'].items()), 'native raw differs')
    monitor = read(root / 'monitor/result.json'); monitor_plan = read(root / 'monitor/plan.json')
    check(monitor['passed'] is True and len(monitor['cases']) == 6 and monitor_plan['timing_gate'] is False
          and monitor_plan['script_sha256'] == digest(root / 'scripts/monitor_boundary_oracle.py')
          == digest(ROOT / 'tools/r142/monitor_boundary_oracle.py'), 'monitor probe identity differs')
    check({k: v['sha256'] for k, v in monitor_plan['subjects'].items()} == {'c': C, 'r136': R136, 'monitor': CANDIDATE}
          and {(r['subject'], r['case']) for r in monitor['cases']} == {(s, c) for s in ('c', 'r136', 'monitor') for c in ('lifecycle', 'slow_reader')}, 'monitor case set differs')
    for row in monitor['cases']:
        folder = root / 'monitor' / f"{row['subject']}-{row['case']}"
        before, after = read(folder / 'identity-before.json'), read(folder / 'identity-after.json')
        check(row['passed'] is True and row['fd_baseline_restored'] is True and row['daemon_exit'] in (0, -15)
              and before == after and before['affinity'] == [1] and not (folder / 'daemon.log').read_bytes(), 'monitor process/FD cleanup failed')
        check(all(digest(folder / name) == h for name, h in row['raw_sha256'].items()), 'monitor raw differs')
        c = row['checks']
        if row['case'] == 'lifecycle': check(all(v is True for v in c.values()), 'monitor lifecycle check failed')
        else:
            check(c['passed'] and c['pings'] == 128 and c['payload_bytes'] == 16384 and c['mirrors_expected'] == 384
                  and 0 < c['slow_mirrors_received'] < 384 and c['recovery_mirrors'] == 3
                  and all(c[k] is True for k in ('bounded_drop_exercised', 'survivor_bytes_order_sequences', 'fast_complete')), 'monitor queue/recovery failed')
    return {'schema': 1, 'passed': True, 'scope': 'Oracle monitor correctness only; no performance/adoption verdict',
        'artifacts': {'candidate_sha256': CANDIDATE, 'r136_sha256': R136, 'r131_fd_stress_control_sha256': R131,
                      'exact_c_sha256': C, 'wireprobe_sha256': PROBE, 'stress_helper_sha256': stress.HELPER_SHA},
        'source': {'changed_files': ['ubusd/src/server.rs'], 'files_per_snapshot': 30, 'generic_flags_match': True},
        'unit_tests': {'passed': 56, 'failed': 0, 'flags_match_release': True, 'new_multi_monitor_regression_passed': True,
                       'test_elf_sha256': units['test_elf_sha256'], 'tests_log_sha256': units['tests_log_sha256']},
        'wire': wire, 'fd': fd, 'recovery': [{k: v for k, v in row.items() if k != 'observations'} for row in recovery],
        'stress': [{k: v for k, v in row.items() if k != 'raw_sha256'} for row in native['cases']],
        'monitor_boundary': [{k: v for k, v in row.items() if k != 'raw_sha256'} for row in monitor['cases']],
        'evidence': {'archive_sha256': digest(archive), 'manifest_sha256': digest(root / 'evidence-manifest.json'),
                     'verified_files': len(evidence), 'files': dict(sorted(evidence.items())), 'analyzer_sha256': digest(Path(__file__)),
                     'support_sha256': {p: digest(ROOT / p) for p in ('tools/r140/analyze_correctness.py', 'tools/r134/ubusd_stress_oracle.py',
                        'tools/r130_registration_report.py', 'tools/r92_recovery_probe.py', 'docs/reviews/r138-correctness-results.json')}},
        'limits': ['No router operation, timing rank or heap/RSS acceptance.',
                   'FD handcrafted cases retain accepted read-ahead semantics; known C recovery failures remain unchanged.',
                   'New Python probe checks every monitor byte while running; archived assertions and process identities are not a full packet capture.',
                   'Independent resource measurements and frozen uninstrumented performance evidence remain required.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path); parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    result = analyze(args.root, args.archive)
    with args.output.open('x') as stream: json.dump(result, stream, indent=2, allow_nan=False); stream.write('\n')
    print(json.dumps({'passed': result['passed'], 'units': 56, 'wire': 8, 'fd': 6, 'recovery': 2,
                      'stress': 12, 'monitor_boundary': 6, 'verified_files': result['evidence']['verified_files']}))


if __name__ == '__main__': main()
