#!/usr/bin/env python3
"""O1 three-way TCP attribution and descriptive UDP guard; prepare never runs load."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess
import sys
import time

ROOT = Path('/home/ubuntu/dnsmasq-fix2-repair-20261011')
BASE_DRIVER = ROOT / 'paired_performance.py'
BASE_SHA = '096fbf5de8bb12bb4b2b42f7e1ed91855ba5d6a177514eea9b406f711be4848c'
BASE_PLAN = ROOT / 'private/performance-paired-01/plan.json'
BASE_PLAN_SHA = '8be1a47d0181ebe9791d140a60e6743d924d3340b3a75854f1286b3324189f98'
ORDERS = [('main', 'pre', 'post'), ('post', 'pre', 'main'), ('pre', 'main', 'post'),
          ('post', 'main', 'pre'), ('main', 'post', 'pre'), ('pre', 'post', 'main')]


def base_module():
    import hashlib
    if hashlib.sha256(BASE_DRIVER.read_bytes()).hexdigest() != BASE_SHA:
        raise ValueError('calibrated base analysis driver changed')
    spec = importlib.util.spec_from_file_location('paired_base', BASE_DRIVER)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    return base


def prepare(args, base):
    source, post, identity_path, out = [p.resolve() for p in
        (args.source, args.post, args.source_identity, args.out)]
    base.require(base.sha(BASE_PLAN) == BASE_PLAN_SHA, 'primary plan changed')
    old = base.read(BASE_PLAN)
    base.verify(old)
    identity = base.read(identity_path)
    base.require(identity['source_commit'] == args.source_commit, 'post source commit mismatch')
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    from build_package import inputs
    base.require(inputs(source) == identity['source_files'], 'post source inputs differ from freeze')
    build = base.read(post.parent / 'build.json')
    base.require(base.sha(post) == args.post_sha and build['kind'] == 'release' and
                 build['opt_level'] == '3' and build['features'] == '', 'post release identity/profile mismatch')
    base.require(Path(build['source']).resolve() == source and build['artifacts'] ==
                 [dict(path=post.name, bytes=post.stat().st_size, sha256=args.post_sha)], 'post build receipt mismatch')
    base.require(base.normalize_flags(build['rustflags']) ==
                 base.normalize_flags(old['groups']['fix']['build']['rustflags']), 'pre/post release flags differ')
    groups = {'main': old['groups']['main'], 'pre': old['groups']['fix'],
              'post': dict(elf=str(post), sha256=args.post_sha, bytes=post.stat().st_size,
                           build_receipt=str(post.parent / 'build.json'), build=build)}
    assets = dict(old['assets'])
    for path in (Path(__file__).resolve(), BASE_DRIVER, BASE_PLAN, identity_path, post, post.parent / 'build.json'):
        assets[str(path)] = base.sha(path)
    base.require('private' in out.parts and not out.exists(), 'fresh private output required')
    out.mkdir(parents=True)
    plan = dict(schema=1, scope='O1 main/pre/post TCP cache-hit paired long windows and two descriptive UDP-miss guard pairs',
        source=old['source'], product_source=str(source), source_commit=args.source_commit,
        pre_source_commit=old['source_commit'], main_commit=old['main_commit'], source_identity=identity,
        groups=groups, assets=assets, image_manifest_sha256=old['image_manifest_sha256'],
        base_analysis_driver_sha256=BASE_SHA, primary_plan_sha256=BASE_PLAN_SHA,
        measurement=dict(old['measurement'], TCP_rounds=6, TCP_variants_per_round=3, UDP_guard_pairs=2, total_windows=22), windows=[],
        statistics=dict(TCP='Six same-seed rounds; each of the six permutations occurs once. Paired log-ratio t interval df5 for pre/main, post/main, post/pre; retain all per-round and relative-order values.',
            estimator=old['statistics'], interpretation='post/pre measures the combined A+B change, not either change separately. post/main is current cumulative cost. Concurrent pre/main is a control and does not replace the original 36 windows.',
            UDP='Two main/post pairs in opposite order only; report both ratios and counts without inferential CI. A direct CNAME index check affects UDP too, so this is a guard, not a renewed broad performance-equivalence claim.',
            exclusion='No retries, W filter, direction unanimity requirement, removal or replacement. All invalid observations remain; invalid/incomplete comparisons cannot close the cost question.',
            DHCP='Not rerun: A+B are DNS lookup changes. Earlier long DHCP evidence remains scoped to its tested workload; no zero-regression claim.'),
        order_permutations=[list(order) for order in ORDERS])
    def add(profile, round_no, variant, position, order):
        old_id = ('tcp-hit-p1-main' if profile == 'tcp-hit' else 'udp-miss-p1-main')
        argv = next(w['argv'].copy() for w in old['windows'] if w['id'] == old_id)
        ident = f'{profile}-r{round_no}-{variant}'
        seed = 0x4f324900 + round_no
        for key, value in [('--rust', groups[variant]['elf']), ('--expected-rust-sha', groups[variant]['sha256']),
                           ('--round', str(round_no)), ('--seed', str(seed)), ('--output', str(out / ident))]:
            argv[argv.index(key) + 1] = value
        plan['windows'].append(dict(id=ident, profile=profile, round=round_no, variant=variant,
                                    position=position, order=list(order), seed=seed, argv=argv))
    for number, order in enumerate(ORDERS, 1):
        for position, variant in enumerate(order):
            add('tcp-hit', number, variant, position, order)
        if number in (3, 6):
            guard = number // 3
            guard_order = ('main', 'post') if guard == 1 else ('post', 'main')
            for position, variant in enumerate(guard_order):
                add('udp-miss', guard, variant, position, guard_order)
    base.require(len(plan['windows']) == 22, 'window inventory mismatch')
    base.save(out / 'plan.json', plan)
    print(json.dumps(dict(status='prepared-only', windows=22, sha256=base.sha(out / 'plan.json'))))


def summarize(out, base):
    plan = base.read(out / 'plan.json')
    base.verify(plan)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from m6a_analyze import analyze_window
    result = dict(schema=1, scope=plan['scope'], plan_sha256=base.sha(out / 'plan.json'),
                  statistics=plan['statistics'], windows=[], comparisons=[], UDP_guard={}, errors=[])
    for window in plan['windows']:
        folder = out / window['id']
        row = {key: value for key, value in window.items() if key != 'argv'}
        result['windows'].append(row)
        row['controller_evidence'] = {suffix: dict(path=str(out / (window['id'] + suffix)),
            sha256=base.sha(out / (window['id'] + suffix))) for suffix in ('.log', '.host.jsonl', '.foreign-before.json')
            if (out / (window['id'] + suffix)).exists()}
        if not (folder / 'result.json').exists():
            row.update(status='not-analyzable', reason='no result');continue
        try:
            extracted, analysis = base.analyze_one_window(folder, plan['groups'][window['variant']]['sha256'],
                                                          window['profile'], analyze_window)
            row.update(extracted)
            base.save(folder / 'three-way-analysis.json', analysis)
            if not row['valid_for_comparison']:
                result['errors'].append(dict(id=row['id'], reason='invalid methodology/behavior/generator retained'))
        except Exception as error:
            row.update(status='analysis-failed', error=repr(error))
            result['errors'].append(dict(id=row['id'], error=repr(error)))
        row['raw_files'] = {str(p.relative_to(folder)): base.sha(p) for p in sorted(folder.rglob('*'))
                           if p.is_file() and 'filesystem' not in p.relative_to(folder).parts}
    result['complete'] = len(result['windows']) == 22 and all(w['status'] == 'analyzed' for w in result['windows'])
    TCP = [w for w in result['windows'] if w['profile'] == 'tcp-hit']
    if all(w['status'] == 'analyzed' for w in TCP):
        for baseline, candidate in [('main', 'pre'), ('main', 'post'), ('pre', 'post')]:
            values = []
            for number in range(1, 7):
                group = {w['variant']: w for w in TCP if w['round'] == number}
                values.append(dict(pair=number,
                    order='AB' if group[baseline]['position'] < group[candidate]['position'] else 'BA',
                    main=group[baseline]['metrics']['cpu_us_per_correct'], fix=group[candidate]['metrics']['cpu_us_per_correct']))
            valid = all(w['valid_for_comparison'] for w in TCP if w['variant'] in (baseline, candidate))
            comparison = dict(profile='tcp-hit', baseline=baseline, candidate=candidate,
                numerical_pair_keys='main=selected baseline; fix=selected candidate; these names come from unchanged calibrated estimator',
                scenario_valid=valid, **base.paired(values))
            comparison['CPU_increase_confirmed'] = valid and comparison['numerical_CI_lower_bound_above_one']
            comparison['CPU_decrease_confirmed'] = valid and comparison['paired_log_t_95_ratio_interval'][1] < 1
            if not valid:
                comparison['interpretation'] = 'invalid/incomplete measurement; numerical observations retained without conclusion'
            result['comparisons'].append(comparison)
    UDP = [w for w in result['windows'] if w['profile'] == 'udp-miss']
    if all(w['status'] == 'analyzed' for w in UDP):
        values = []
        for number in (1, 2):
            group = {w['variant']: w for w in UDP if w['round'] == number}
            a, b = (group[v]['metrics']['cpu_us_per_correct'] for v in ('main', 'post'))
            values.append(dict(pair=number, order=group['main']['order'], main=a, post=b, ratio=b/a, delta_us=b-a))
        result['UDP_guard'] = dict(pairs=values, all_windows_valid=all(w['valid_for_comparison'] for w in UDP),
            median_ratio=statistics.median(w['ratio'] for w in values), inferential_CI=None,
            conclusion='descriptive guard only; two opposite-order pairs cannot establish a small regression or equivalence')
    base.save(out / 'summary.json', result)
    print(json.dumps(dict(complete=result['complete'], errors=result['errors'], comparisons=result['comparisons'], UDP_guard=result['UDP_guard']), indent=2))


def run(args, base):
    out = args.out.resolve();plan = base.read(out / 'plan.json');base.verify(plan)
    base.require(os.geteuid() == 0, 'root required')
    base.require(not (out / 'run.json').exists(), 'no automatic replacement/retry')
    ready = base.read(args.ready_receipt)
    base.require(ready.get('functional_complete') and ready.get('builds_complete') and
        ready.get('source_commit') == plan['source_commit'] and ready.get('candidate_sha256') == plan['groups']['post']['sha256'],
        'post-build and functional completion receipt mismatch')
    base.save(out / 'ready-receipt.json', ready)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from audit_20261011_pie_cost import foreign_workloads
    from m5_final_validation import remember_job_processes, stop_job_processes
    base.require({0, 1, 2, 3} <= os.sched_getaffinity(0), 'CPUs unavailable')
    state = dict(status='running', started_ns=time.time_ns(), windows=[],
                 plan_sha256=base.sha(out / 'plan.json'), ready_receipt_sha256=base.sha(args.ready_receipt))
    def interrupted(number, frame):
        raise InterruptedError(f'performance interrupted by signal {number}')
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB);os.sched_setaffinity(0, {3});base.save(out / 'run.json', state)
        try:
            for window in plan['windows']:
                base.verify(plan)
                busy = foreign_workloads();base.save(out / (window['id'] + '.foreign-before.json'), busy)
                base.require(not busy, 'foreign workload before ' + window['id'])
                row = dict(id=window['id'], started_ns=time.time_ns());state['windows'].append(row);base.save(out / 'run.json', state)
                with (out / (window['id'] + '.log')).open('wb') as log, (out / (window['id'] + '.host.jsonl')).open('w') as host:
                    process = subprocess.Popen(window['argv'], cwd=plan['source'], stdout=log, stderr=log,
                        start_new_session=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'));known = {}
                    try:
                        deadline = time.monotonic() + 360
                        while process.poll() is None:
                            remember_job_processes(process, known)
                            host.write(json.dumps(base.host_sample()) + '\n');host.flush()
                            if time.monotonic() > deadline:raise TimeoutError(window['id'])
                            try:process.wait(timeout=1)
                            except subprocess.TimeoutExpired:pass
                    finally:stop_job_processes(process, known)
                row.update(returncode=process.returncode, ended_ns=time.time_ns());base.save(out / 'run.json', state)
                print(json.dumps(row), flush=True)
                base.require(not process.returncode or (out / window['id'] / 'result.json').exists(), 'catastrophic missing result')
            base.verify(plan);busy = foreign_workloads();base.save(out / 'foreign-after.json', busy)
            base.require(not busy, 'foreign workload at series end');state['status'] = 'complete'
        except BaseException as error:
            state.update(status='incomplete', error=repr(error));raise
        finally:
            state['ended_ns'] = time.time_ns();base.save(out / 'run.json', state)
            for number, handler in previous.items():signal.signal(number, handler)
    summarize(out, base)


def main():
    parser = argparse.ArgumentParser(description=__doc__);sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare')
    for name in ('source', 'post', 'source-identity', 'out'):p.add_argument('--' + name, type=Path, required=True)
    for name in ('post-sha', 'source-commit'):p.add_argument('--' + name, required=True)
    p = sub.add_parser('run');p.add_argument('--out', type=Path, required=True);p.add_argument('--ready-receipt', type=Path, required=True)
    p = sub.add_parser('summarize');p.add_argument('--out', type=Path, required=True)
    args = parser.parse_args();base = base_module()
    if args.action == 'prepare':prepare(args, base)
    elif args.action == 'run':run(args, base)
    else:summarize(args.out.resolve(), base)


if __name__ == '__main__':main()
