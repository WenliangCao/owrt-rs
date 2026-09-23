#!/usr/bin/env python3
"""Bind the single caller build and unit proof to a fixed smoke or screen."""
import argparse
from pathlib import Path
import caller_screen as screen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('smoke', 'screen'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--smoke-proof', type=Path)
    parser.add_argument('--old-build', type=Path, default=Path('/home/ubuntu/r144/control-rebuild-02'))
    parser.add_argument('--new-build', type=Path, default=Path('/home/ubuntu/r144/candidate-build-01'))
    parser.add_argument('--r136', type=Path, default=Path('/home/ubuntu/r138/build-01/r136/ubusd-rs'))
    parser.add_argument('--rootfs', type=Path, default=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'))
    args = parser.parse_args()
    check, read, sha = screen.check, screen.read, screen.sha
    check(not args.output.exists(), 'new manifest required')
    proofs, plans, callers = {}, {}, {}
    for label, directory, wanted, count in [('old', args.old_build, screen.OLD, 46), ('new', args.new_build, screen.NEW, 49)]:
        plan, result = read(directory / 'plan.json'), read(directory / 'result.json')
        unit = read(directory / 'artifacts/unit-proof.json')
        check(result['passed'] is True and result['exit'] == 0 and result['source_unchanged'] is True
              and result['effective_flags_match'] is True and result['sha256'] == wanted
              and result['plan_sha256'] == sha(directory / 'plan.json')
              and sha(directory / 'owrt-benchmark') == wanted, 'caller build identity failed')
        check(unit['passed'] is True and unit['unit_count'] == count and unit['doc_test_count'] == 0
              and unit['plan_sha256'] == result['plan_sha256']
              and unit['tests_log_sha256'] == result['tests_log_sha256'] == sha(directory / 'artifacts/tests.log')
              and unit['test_elf_sha256'] == sha(directory / 'artifacts/ubus-tests'), 'caller unit proof failed')
        fingerprints = list(result['namespace']['cargo_fingerprints'].values()) + list(unit['test_fingerprints'].values())
        check(all(row['rustflags'] == plan['expected_rustflags'] for row in fingerprints), 'effective caller/unit flags differ')
        check(len(plan['source_sha256']) == 18 and plan['canonical_source_root'] == '/home/ubuntu/r135/repo', 'source snapshot differs')
        for index, (name, digest) in enumerate(sorted(plan['source_sha256'].items())):
            path = Path(plan['source_root']) / name
            check(sha(path) == digest, 'build source changed')
            proofs[f'{label}_source_{index}'] = {'path': str(path), 'sha256': digest}
        for name in ('plan.json', 'result.json', 'artifacts/unit-proof.json', 'artifacts/tests.log', 'artifacts/ubus-tests'):
            path = directory / name; proofs[f'{label}_{name.replace("/", "_")}'] = {'path': str(path), 'sha256': sha(path)}
        plans[label] = plan; callers[label] = {'path': str((directory / 'owrt-benchmark').resolve()), 'sha256': wanted}
    check(plans['old']['expected_rustflags'] == plans['new']['expected_rustflags'], 'old/new flags differ')
    old, new = plans['old']['source_sha256'], plans['new']['source_sha256']
    check(set(old) == set(new) and [p for p in old if old[p] != new[p]] == ['components/ubus/src/conn.rs'], 'only conn.rs may differ')
    stock, cli = args.rootfs / 'sbin/ubusd', args.rootfs / 'bin/ubus'
    check(screen.sha(stock) == screen.C and screen.sha(args.r136) == screen.R136 and cli.is_file(), 'daemon/CLI identity differs')
    libraries = {str((args.rootfs / p.lstrip('/')).resolve()): h for p, h in screen.LIBRARIES.items()}
    check(all(sha(Path(p)) == h for p, h in libraries.items()), 'rootfs libraries differ')
    policy = read(screen.POLICY)
    value = {'schema': 1, 'phase': args.phase, 'policy': policy, 'policy_sha256': sha(screen.POLICY),
        'iterations': 10 if args.phase == 'smoke' else 10000, 'warmup': 20, 'cases': 12 if args.phase == 'smoke' else 72,
        'callers': callers, 'daemons': {'c': {'path': str(stock.resolve()), 'sha256': screen.C},
                                       'r136': {'path': str(args.r136.resolve()), 'sha256': screen.R136}},
        'rootfs': str(args.rootfs.resolve()), 'ubus_cli': {'path': str(cli.resolve()), 'sha256': sha(cli)},
        'libraries': libraries, 'proofs': proofs, 'build_verified': True,
        'tools': {p: sha(screen.ROOT / p) for p in screen.TOOLS}}
    if args.phase == 'screen':
        check(args.smoke_proof is not None, 'successful exact smoke proof required before screen freeze')
        smoke = read(args.smoke_proof)
        check(smoke['verified'] is True and smoke['phase'] == 'smoke' and smoke['cases'] == 12
              and smoke['new_caller_sha256'] == screen.NEW and smoke['old_caller_sha256'] == screen.OLD
              and smoke['daemon_sha256'] == {'c': screen.C, 'r136': screen.R136}
              and smoke['performance_gate'] is False, 'smoke proof differs')
        value['smoke'] = {k: smoke[k] for k in ('verified', 'cases', 'new_caller_sha256', 'manifest_sha256')}
        value['proofs']['smoke'] = {'path': str(args.smoke_proof.resolve()), 'sha256': sha(args.smoke_proof)}
    else:
        check(args.smoke_proof is None, 'smoke does not consume another smoke')
    screen.validate(value, live=True)
    args.output.parent.mkdir(parents=True, exist_ok=True); screen.save(args.output, value)
    print(args.output, sha(args.output))


if __name__ == '__main__': main()
