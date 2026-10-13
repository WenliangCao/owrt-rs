#!/usr/bin/env python3
"""Frozen three-way cached-A screen, balanced order, no retry/selection.

Runs the prior review's unchanged native generator and m6a window machinery.
All raw packets, overlays, binaries, process maps and counters remain private.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

SOURCE = Path('/home/ubuntu/dnsmasq-fix3-recheck-20261013/source')
TOOLS = SOURCE / 'tools/dnsmasq'
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
NATIVE = Path('/home/ubuntu/dnsmasq-final135-889fe4f5/private/native')
MAIN = Path('/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs')
BEFORE = Path('/home/ubuntu/dnsmasq-fix3-recheck-20261013/private/release/dnsmasq-rs')
MAIN_SHA = 'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863'
BEFORE_SHA = '25b7291d0074b8c7a854aa9f63f7b5edb12bc1315e60dd26f8f6eed36d362fd8'
C_SHA = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
sys.path.insert(0, str(TOOLS))
from m6a_analyze import analyze_window
from m5_final_validation import remember_job_processes, stop_job_processes
from audit_20261011_pie_cost import foreign_workloads
from build_package import inputs


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def prepare(args):
    out = args.output
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    candidate = args.candidate or BEFORE
    if candidate == BEFORE:
        assert sha(candidate) == BEFORE_SHA
    assert sha(MAIN) == MAIN_SHA and sha(IMAGE / 'usr/sbin/dnsmasq') == C_SHA
    assets = [Path(__file__).resolve(), Path(__file__).with_name('raw_window.py').resolve(),
              NATIVE / 'm6a_loadgen', NATIVE / 'm6a_upstream']
    assets += [TOOLS / name for name in ('m6a_window.py', 'm6a_analyze.py', 'm2_rootfs.py',
               'run_isolated.sh', 'dns_service_probe.py', 'm5_final_validation.py')]
    groups = {}
    for variant, elf in [('c', IMAGE / 'usr/sbin/dnsmasq'), ('main', MAIN), ('current', candidate)]:
        groups[variant] = dict(elf=str(elf), sha256=sha(elf), bytes=elf.stat().st_size)
        assets.append(elf)
        if variant != 'c':
            receipt = elf.parent / 'build.json'
            build = json.loads(receipt.read_text())
            assert build['features'] == '' and build['opt_level'] == '3'
            assert build['artifacts'] == [dict(path=elf.name, bytes=elf.stat().st_size, sha256=sha(elf))]
            groups[variant]['build'] = build
            groups[variant]['source_files'] = inputs(Path(build['source']))
            assets.append(receipt)
            assets.extend(Path(build['source']) / name for name in groups[variant]['source_files'])
    profiles = [('tcp-raw-a-100', 'tcp', 100, 1), ('tcp-raw-a-1000', 'tcp', 1000, 1),
                ('udp-raw-a-100', 'hit', 100, 1), ('udp-raw-a-1000', 'hit', 1000, 1)]
    if args.suite == 'ordinary':
        profiles = [('tcp-ordinary', 'tcp', 0, 1), ('tcp-absent-100', 'tcp', 100, 65401),
                    ('tcp-absent-1000', 'tcp', 1000, 65401)]
    orders = [['c', 'main', 'current'], ['main', 'current', 'c'], ['current', 'c', 'main']]
    plan = dict(scope='Exact-image C / main / current branch; Oracle directed screen, not router qualification',
                suite=args.suite, baseline_product_commit='74c6b4531111819439e38881ff9be7dc025d57ca',
                main_commit='be531cee49e366bb5044443d473944dbea45b87e', candidate_commit=args.candidate_commit,
                groups=groups, assets={str(p): sha(p) for p in assets}, windows=[],
                method='Three Latin-square rounds, identical seeded workloads per triple. 1000QPS/20clients/3s warmup/15s measure. cache4096 proven, upstream answers then disabled. CPU0/1/2/3 daemon/upstream/load/controller. Descriptive medians/ranges; no asserted statistical equivalence or acceptance tolerance.')
    for round_no, order in enumerate(orders, 1):
        for profile, scenario, count, rrtype in profiles:
            for variant in order:
                ident = f'{profile}-r{round_no}-{variant}'
                argv = ['bash', str(TOOLS / 'run_isolated.sh'), 'python3',
                        str(Path(__file__).with_name('raw_window.py').resolve()), str(SOURCE), str(count), str(rrtype),
                        '--implementation', 'c' if variant == 'c' else 'rs',
                        '--rust', str(candidate if variant == 'c' else groups[variant]['elf']),
                        '--expected-rust-sha', groups['current' if variant == 'c' else variant]['sha256'],
                        '--image-root', str(IMAGE), '--loadgen', str(NATIVE / 'm6a_loadgen'),
                        '--upstream', str(NATIVE / 'm6a_upstream'), '--preflight', '--scenario', scenario,
                        '--tcp-profile', 'hit', '--round', str(round_no), '--rate', '1000', '--cache-names', '4096',
                        '--clients', '20', '--warmup', str(args.warmup), '--duration', str(args.duration), '--saturation-seconds', '0',
                        '--cpu-daemon', '0', '--cpu-upstream', '1', '--cpu-load', '2', '--cpu-control', '3',
                        '--drain-sample-seconds', '0,1', '--drain-timeout-seconds', '65',
                        '--seed', str(0x4d533100 + round_no), '--output', str(out / ident)]
                plan['windows'].append(dict(id=ident, profile=profile, variant=variant, round=round_no,
                                            declarations=count, rrtype=rrtype, argv=argv))
    save(out / 'plan.json', plan)
    print('prepared', len(plan['windows']), flush=True)


def verify(plan):
    for path, expected in plan['assets'].items():
        assert sha(path) == expected, path


def run(args):
    out = args.output
    assert os.geteuid() == 0
    plan = json.loads((out / 'plan.json').read_text())
    verify(plan)
    assert not (out / 'run.json').exists()
    with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        busy = foreign_workloads()
        save(out / 'foreign-before.json', busy)
        assert not busy, busy
        os.sched_setaffinity(0, {3})
        state = dict(status='running', started=time.time(), windows=[])
        save(out / 'run.json', state)
        try:
            for window in plan['windows']:
                verify(plan)
                busy = foreign_workloads()
                save(out / (window['id'] + '.foreign-before.json'), busy)
                assert not busy, busy
                row = dict(id=window['id'], started=time.time())
                state['windows'].append(row)
                save(out / 'run.json', state)
                with (out / (window['id'] + '.log')).open('wb') as log:
                    process = subprocess.Popen(window['argv'], cwd=SOURCE, stdout=log, stderr=log, start_new_session=True)
                    known = {}
                    try:
                        while process.poll() is None:
                            remember_job_processes(process, known)
                            if time.time() - row['started'] > max(180, args.duration + args.warmup + 120):
                                raise TimeoutError(window['id'])
                            try:
                                process.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        stop_job_processes(process, known)
                row.update(returncode=process.returncode, ended=time.time())
                save(out / 'run.json', state)
                print(json.dumps(row), flush=True)
                if process.returncode:
                    raise RuntimeError('failed window retained, no retry: ' + window['id'])
            state['status'] = 'complete'
        except BaseException as error:
            state.update(status='incomplete', error=repr(error))
            raise
        finally:
            state['ended'] = time.time()
            save(out / 'run.json', state)
    summarize(args)


def throttle_rows(value):
    if isinstance(value, dict):
        if 'nr_throttled' in value:
            yield {k: value[k] for k in ('nr_throttled', 'throttled_usec')}
        for child in value.values():
            yield from throttle_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from throttle_rows(child)


def summarize(args):
    out = args.output
    plan = json.loads((out / 'plan.json').read_text())
    verify(plan)
    result = dict(scope=plan['scope'], plan_sha256=sha(out / 'plan.json'), groups=plan['groups'],
                  windows=[], comparisons=[], errors=[])
    counts = dict.fromkeys(('scheduled', 'sent', 'correct', 'wrong', 'timeout', 'transport_error', 'scheduled_skipped'), 0)
    checks = dict(counters=counts, windows=[], triple_config_checks=[], cgroup_samples=0,
                  maximum_nr_throttled=0, maximum_throttled_usec=0)
    configs = {}
    assert json.loads((out / 'foreign-before.json').read_text()) == []
    for window in plan['windows']:
        folder = out / window['id']
        if not (folder / 'result.json').exists():
            continue
        observed = analyze_window(folder)
        save(folder / 'audit-analysis.json', observed)
        identity = json.loads((folder / 'process-identity.json').read_text())
        assert identity['sha256'] == plan['groups'][window['variant']]['sha256']
        assert observed['methodology_valid'] and not observed['analysis_errors'], observed['analysis_errors']
        assert json.loads((out / (window['id'] + '.foreign-before.json')).read_text()) == []
        data = json.loads((folder / 'result.json').read_text())
        assert data['measurement_valid']
        proof = json.loads((folder / 'cache-proof.json').read_text())
        assert proof['capacity'] == proof['filled_names'] == proof['validated_names'] == len(proof['rows']) == 4096
        assert proof['upstream_disabled'] and all(p['correct'] for p in proof['rows'])
        upstream = json.loads((folder / 'upstream.json').read_text())
        assert upstream['disabled'] and upstream['disabled_requests'] == upstream['phases']['steady']['requests'] == 0
        direct = None
        if window['declarations']:
            direct = json.loads((folder / 'same-type-proof.json').read_text())
            assert direct['declarations'] == window['declarations'] and direct['rrtype'] == window['rrtype']
            assert all(v['correct'] for v in direct['replies'].values())
        configs.setdefault((window['profile'], window['round']), {})[window['variant']] = sha(folder / 'config')
        for phase in ('warmup', 'measurement'):
            row = observed['load_counters'][phase]
            assert row['scheduled'] == row['sent'] == row['correct']
            assert all(row[key] == 0 for key in ('wrong', 'timeout', 'transport_error', 'scheduled_skipped'))
            for key in counts:
                counts[key] += row[key]
        for row in throttle_rows(data):
            checks['cgroup_samples'] += 1
            for key in ('nr_throttled', 'throttled_usec'):
                checks['maximum_' + key] = max(checks['maximum_' + key], row[key])
        measurement = observed['measurement']
        assert not measurement['generator_limited'], measurement['generator_limit_reasons']
        metrics = dict(cpu_us_per_correct=measurement['cpu_us_per_correct'], p95_ns=measurement['latency_ns']['p95'],
                       **measurement['resources']['sampled_tree_peaks'])
        result['windows'].append({**{k: v for k, v in window.items() if k != 'argv'}, 'metrics': metrics,
                                  'load_counters': observed['load_counters'], 'raw_inputs': observed['input_sha256']})
        checks['windows'].append(dict(id=window['id'], actual_elf_sha256=identity['sha256'],
               raw_assets={name: sha(folder / name) for name in ('config', 'upstream.json', 'cache-proof.json',
                                                                  'process-identity.json', 'result.json')},
               validated_cache_names=4096, upstream_disabled_requests=0, direct_raw_proof=direct))
    assert checks['maximum_nr_throttled'] == checks['maximum_throttled_usec'] == 0
    for (profile, round_no), digests in configs.items():
        assert len(set(digests.values())) == 1
        checks['triple_config_checks'].append(dict(profile=profile, round=round_no, sha256=next(iter(digests.values())), identical=True))
    result['complete'] = len(result['windows']) == len(plan['windows'])
    if result['complete']:
        for profile in dict.fromkeys(w['profile'] for w in plan['windows']):
            for metric in ('cpu_us_per_correct', 'p95_ns', 'pss_kib', 'rss_kib', 'fd_count'):
                values = {variant: [next(w['metrics'][metric] for w in result['windows']
                                        if w['profile'] == profile and w['variant'] == variant and w['round'] == round_no)
                                    for round_no in range(1, 4)] for variant in ('c', 'main', 'current')}
                medians = {variant: statistics.median(rows) for variant, rows in values.items()}
                ranges = {variant: (max(rows) - min(rows)) / medians[variant] for variant, rows in values.items()}
                result['comparisons'].append(dict(profile=profile, metric=metric, values=values, medians=medians,
                    relative_ranges=ranges, current_over_c=medians['current'] / medians['c'] - 1,
                    current_over_main=medians['current'] / medians['main'] - 1))
    save(out / 'counter-check.json', checks)
    save(out / 'summary.json', result)
    print(json.dumps(dict(complete=result['complete'], counters=counts,
                         cpu=[r for r in result['comparisons'] if r['metric'] == 'cpu_us_per_correct']), indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'run', 'summarize'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--candidate-commit', default='74c6b4531111819439e38881ff9be7dc025d57ca')
    parser.add_argument('--suite', choices=('raw', 'ordinary'), default='raw')
    parser.add_argument('--warmup', type=int, default=3)
    parser.add_argument('--duration', type=int, default=15)
    args = parser.parse_args()
    globals()[args.action](args)
