#!/usr/bin/env python3
"""Frozen main/shared-answer pairs; reuse the prior cgroup estimator unchanged."""
import argparse
import importlib.util
import json
import re
from pathlib import Path
import statistics
import sys

ROOT = Path('/home/ubuntu/dnsmasq-fix3-repair-20261013')
SOURCE = ROOT / 'source'
PRIOR = Path('/home/ubuntu/dnsmasq-audit-fix3-20261013')
MAIN = PRIOR / 'private/release-main/dnsmasq-rs'
MAIN_SHA = 'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863'
BASE = SOURCE / 'docs/dnsmasq/audits/20261011/fix2_repairs/performance-before-driver.py'
BASE_SHA = '096fbf5de8bb12bb4b2b42f7e1ed91855ba5d6a177514eea9b406f711be4848c'
NATIVE = Path('/home/ubuntu/dnsmasq-final135-889fe4f5/private/native')
WRAPPER = ROOT / 'private/raw_records_window.py'
PRIMARY = ('tcp-raw-100', 'tcp-raw-1000')
GUARDS = ('udp-raw-1000', 'tcp-raw-0')


def module():
    import hashlib
    if hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA:
        raise ValueError('unchanged prior CPU estimator required')
    spec = importlib.util.spec_from_file_location('cpu_base', BASE)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    return base


def prepare(args, base):
    out = args.out.resolve()
    identity_path = ROOT / f'private/source-{args.phase}-identity.json'
    identity = base.read(identity_path)
    base.require(identity['source_commit'] == args.source_commit, 'source commit mismatch')
    sys.path.insert(0, str(SOURCE / 'tools/dnsmasq'))
    from build_package import inputs
    base.require(inputs(SOURCE) == identity['source_files'], 'candidate source differs from freeze')
    main_identity_path = SOURCE / 'docs/dnsmasq/audits/20261012/fix3/identity.json'
    main_identity = base.read(main_identity_path)
    base.require(main_identity['commits']['main'] == base.MAIN_COMMIT, 'main commit mismatch')
    for name, expected in main_identity['source_checks']['main']['files'].items():
        base.require(base.sha(PRIOR / 'source-main' / name) == expected, 'prior main source changed: ' + name)
    assets = [Path(__file__).resolve(), BASE, WRAPPER, identity_path, main_identity_path,
              base.IMAGE / 'usr/sbin/dnsmasq']
    groups = {}
    for name, elf in [('main', MAIN), ('fix', ROOT / f'private/release-{args.phase}/dnsmasq-rs')]:
        build_path = elf.parent / 'build.json'
        build = base.read(build_path)
        expected = MAIN_SHA if name == 'main' else args.candidate_sha
        base.require(base.sha(elf) == expected, name + ' executable mismatch')
        base.require(build['kind'] == 'release' and build['opt_level'] == '3' and build['features'] == '', 'build profile mismatch')
        base.require(build['artifacts'] == [dict(path=elf.name, bytes=elf.stat().st_size, sha256=expected)], 'build receipt mismatch')
        expected_source = PRIOR / 'source-main' if name == 'main' else SOURCE
        base.require(Path(build['source']).resolve() == expected_source, 'build source mismatch')
        groups[name] = dict(elf=str(elf), sha256=expected, bytes=elf.stat().st_size, build_receipt=str(build_path), build=build)
        assets += [elf, build_path]
    base.require(base.normalize_flags(groups['fix']['build']['rustflags']) ==
                 base.normalize_flags(groups['main']['build']['rustflags']) + ' -Crelocation-model=pie -Ctarget-feature=+crt-static',
                 'release flags differ beyond declared static PIE')
    for name, expected in base.NATIVE_SHAS.items():
        base.require(base.sha(NATIVE / name) == expected, 'native executable changed')
        assets.append(NATIVE / name)
    tools = SOURCE / 'tools/dnsmasq'
    prior_plan_path = PRIOR / 'private/performance-dns/plan.json'
    prior_plan = base.read(prior_plan_path)
    for name in ('m6a_loadgen.c', 'm6a_upstream.c'):
        base.require(base.sha(tools / name) == base.sha(PRIOR / 'source-fix/tools/dnsmasq' / name), 'native source differs from audit source')
    for name in base.NATIVE_SHAS:
        base.require(prior_plan['assets'][str(NATIVE / name)] == base.sha(NATIVE / name), 'native executable differs from audit plan')
    assets.append(prior_plan_path)
    assets += sorted(tools.glob('*.py'))
    assets += [tools / name for name in ('run_isolated.sh', 'm6a_loadgen.c', 'm6a_upstream.c', 'oracle_build.sh')]
    assets += [SOURCE / name for name in identity['source_files']]
    assets += [PRIOR / 'source-main' / name for name in main_identity['source_checks']['main']['files']]
    base.require('private' in out.parts and not out.exists(), 'fresh private output required')
    out.mkdir(parents=True)
    plan = dict(schema=1, phase=args.phase, scope=f'N4 {args.phase} candidate/main Oracle release paired CPU comparison; not router or saturation qualification',
        source=str(SOURCE), source_commit=args.source_commit, main_commit=base.MAIN_COMMIT,
        source_identity=identity, groups=groups, assets={str(p): base.sha(p) for p in assets},
        image_manifest_sha256=base.image_digest(tools), windows=[],
        measurement=dict(idle_seconds=10, warmup_seconds=30, measured_seconds=120,
            primary_pairs_per_profile=6, guard_pairs_per_profile=2, total_windows=32,
            rate=1000, clients=20, cache_names=4096, tcp_queries_per_connection=100,
            cpus=dict(daemon=0, upstream=1, generator=2, controller=3),
            drain_seconds=[0, 1, 5], saturation=False, tracing=False, idle_subtraction=False),
        statistics=dict(primary='cgroup usage_usec delta / successful completions inside the measurement epoch',
            estimate='Per primary scenario: geometric mean of six paired fix/main CPU ratios and paired log-t 95% interval, df=5. Three AB and three BA pairs. Prior estimator unchanged.',
            decision=['Lower 95% bound >1 confirms increased CPU for the tested workload, even below 10%.',
                'Lower bound >1.10 confirms an increase exceeding 10%; 10% is a scale marker, not an allowed tolerance.',
                'Interval crossing 1 is unresolved, not proof of zero regression or noise. Retain all paired and order-group values.',
                'Upper bound below 1.10 bounds this tested workload below that scale, not equivalence.',
                'Intervals are per scenario, not a familywise confidence claim.'],
            guards='Two opposite-order pairs each for UDP/1000 records and TCP/0 records. Descriptive only, no inferential CI or S1 closure.',
            invalid_data='No retry, deletion, replacement, W/range filtering or all-pairs-direction rule. Keep every window/error. Invalid or incomplete scenarios cannot close the cost question.'),
        cache_proof='Stock m6a per-entry proof of 4096 A records, then disabled upstream answers; zero attempted upstream queries required during hit windows.',
        comparison='Same unrelated dns-rr type 65401 entries as the audit N4 probe. Compare main/fix within each profile; do not subtract across rates/configurations.')
    def add(profile, pair, order):
        transport, _, raw_count = profile.split('-')
        for variant in order:
            ident = f'{profile}-p{pair}-{variant}'
            seed = 0x4e344900 + pair
            argv = ['sh', str(tools / 'run_isolated.sh'), 'python3', str(WRAPPER), str(SOURCE), raw_count,
                '--implementation', 'rs', '--rust', groups[variant]['elf'], '--expected-rust-sha', groups[variant]['sha256'],
                '--image-root', str(base.IMAGE), '--loadgen', str(NATIVE / 'm6a_loadgen'), '--upstream', str(NATIVE / 'm6a_upstream'),
                '--preflight', '--scenario', 'tcp' if transport == 'tcp' else 'hit', '--tcp-profile', 'hit',
                '--round', str(pair), '--rate', '1000', '--cache-names', '4096', '--clients', '20',
                '--idle-seconds', '10', '--warmup', '30', '--duration', '120', '--saturation-seconds', '0',
                '--cpu-daemon', '0', '--cpu-upstream', '1', '--cpu-load', '2', '--cpu-control', '3',
                '--drain-sample-seconds', '0,1,5', '--drain-timeout-seconds', '30', '--seed', str(seed), '--output', str(out / ident)]
            plan['windows'].append(dict(id=ident, profile=profile, pair=pair, variant=variant,
                order='AB' if order[0] == 'main' else 'BA', seed=seed, argv=argv))
    for pair in range(1, 7):
        order = ['main', 'fix'] if pair % 2 else ['fix', 'main']
        profiles = PRIMARY if pair % 2 else PRIMARY[::-1]
        for profile in profiles:
            add(profile, pair, order)
        if pair in (3, 6):
            guard_pair = pair // 3
            guard_order = ['main', 'fix'] if guard_pair == 1 else ['fix', 'main']
            for profile in GUARDS:
                add(profile, guard_pair, guard_order)
    base.require(len(plan['windows']) == 32, 'window inventory mismatch')
    base.save(out / 'plan.json', plan)
    print(json.dumps(dict(status='prepared-only', windows=32, plan_sha256=base.sha(out / 'plan.json'))))


def summarize(out, base):
    plan = base.read(out / 'plan.json');base.verify(plan)
    sys.path.insert(0, str(SOURCE / 'tools/dnsmasq'))
    from m6a_analyze import analyze_window
    result = dict(schema=1, scope=plan['scope'], plan_sha256=base.sha(out / 'plan.json'),
        statistics=plan['statistics'], windows=[], comparisons=[], guards=[], errors=[])
    for window in plan['windows']:
        folder = out / window['id']
        row = {key: value for key, value in window.items() if key != 'argv'}
        result['windows'].append(row)
        row['controller_evidence'] = {suffix: dict(path=str(out / (window['id'] + suffix)), sha256=base.sha(out / (window['id'] + suffix)))
            for suffix in ('.log', '.host.jsonl', '.foreign-before.json') if (out / (window['id'] + suffix)).exists()}
        if not (folder / 'result.json').exists():
            row.update(status='not-analyzable', reason='no completed result');continue
        try:
            extracted, analysis = base.analyze_one_window(folder, plan['groups'][window['variant']]['sha256'], window['profile'], analyze_window)
            row.update(extracted);base.save(folder / 'paired-analysis.json', analysis)
            if not row['valid_for_comparison']:
                result['errors'].append(dict(id=row['id'], reason='invalid methodology/behavior/generator; retained'))
        except Exception as error:
            row.update(status='analysis-failed', error=repr(error));result['errors'].append(dict(id=row['id'], error=repr(error)))
        row['raw_files'] = {str(p.relative_to(folder)): base.sha(p) for p in sorted(folder.rglob('*'))
            if p.is_file() and 'filesystem' not in p.relative_to(folder).parts}
    result['complete'] = len(result['windows']) == 32 and all(row['status'] == 'analyzed' for row in result['windows'])
    for profile in (*PRIMARY, *GUARDS):
        rows = [row for row in result['windows'] if row['profile'] == profile]
        if not all(row['status'] == 'analyzed' for row in rows):continue
        count = 6 if profile in PRIMARY else 2
        values = []
        for number in range(1, count + 1):
            group = {row['variant']: row for row in rows if row['pair'] == number}
            values.append(dict(pair=number, order=group['main']['order'], main=group['main']['metrics']['cpu_us_per_correct'], fix=group['fix']['metrics']['cpu_us_per_correct']))
        valid = all(row['valid_for_comparison'] for row in rows)
        if profile in PRIMARY:
            comparison = dict(profile=profile, scenario_valid=valid, **base.paired(values))
            comparison['CPU_increase_confirmed'] = valid and comparison['numerical_CI_lower_bound_above_one']
            comparison['CPU_decrease_confirmed'] = valid and comparison['paired_log_t_95_ratio_interval'][1] < 1
            if not valid:comparison['interpretation'] = 'invalid/incomplete; observations retained without cost conclusion'
            result['comparisons'].append(comparison)
        else:
            for row in values:row.update(ratio=row['fix']/row['main'], delta_us=row['fix']-row['main'])
            result['guards'].append(dict(profile=profile, scenario_valid=valid, pairs=values,
                median_pair_ratio=statistics.median(row['ratio'] for row in values), inferential_CI=None,
                interpretation='descriptive only; two pairs cannot establish a small regression or equivalence'))
    base.save(out / 'summary.json', result)
    print(json.dumps({key: result[key] for key in ('complete', 'errors', 'comparisons', 'guards')}, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__);sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare');p.add_argument('--out', type=Path, required=True)
    for name in ('source-commit', 'candidate-sha'):p.add_argument('--' + name, required=True)
    p = sub.add_parser('run');p.add_argument('--out', type=Path, required=True);p.add_argument('--ready-receipt', type=Path, required=True)
    p = sub.add_parser('summarize');p.add_argument('--out', type=Path, required=True)
    for p in sub.choices.values():p.add_argument('--phase', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]*', args.phase):raise ValueError('simple phase label required')
    global SOURCE, BASE
    SOURCE = ROOT / f'source-{args.phase}'
    BASE = SOURCE / 'docs/dnsmasq/audits/20261011/fix2_repairs/performance-before-driver.py'
    base = module()
    if args.action == 'prepare':prepare(args, base)
    elif args.action == 'run':
        base.summarize = lambda out: summarize(out, base)
        base.run(args)
    else:summarize(args.out.resolve(), base)


if __name__ == '__main__':main()
