#!/usr/bin/env python3
"""Frozen fresh-main/fix AB/BA DNS cost screen; no automatic retries."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path('/home/ubuntu/dnsmasq-audit-fix3-20261013')
SOURCE = ROOT / 'source-fix'
TOOLS = SOURCE / 'tools/dnsmasq'
OUT = ROOT / 'private/performance-dns'
SCRIPTS = ROOT / 'performance'
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
NATIVE = Path('/home/ubuntu/dnsmasq-final135-889fe4f5/private/native')
sys.path.insert(0, str(TOOLS))
from m6a_analyze import analyze_window
from m5_final_validation import remember_job_processes, stop_job_processes
from audit_20261011_pie_cost import foreign_workloads


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def prepare():
    OUT.mkdir(exist_ok=False)
    groups = {}
    assets = [Path(__file__), SCRIPTS / 'cname_window.py', IMAGE / 'usr/sbin/dnsmasq',
              NATIVE / 'm6a_loadgen', NATIVE / 'm6a_upstream']
    assets += [TOOLS / name for name in ('m6a_window.py', 'm6a_analyze.py', 'm2_rootfs.py',
                                        'run_isolated.sh', 'dns_service_probe.py', 'm5_final_validation.py')]
    for variant in ('main', 'fix'):
        elf = ROOT / f'private/release-{variant}/dnsmasq-rs'
        receipt = elf.parent / 'build.json'
        build = json.loads(receipt.read_text())
        assert build['features'] == '' and build['opt_level'] == '3', build
        groups[variant] = dict(elf=str(elf), sha256=sha(elf), bytes=elf.stat().st_size, build=build)
        assets += [elf, receipt]
    profiles = [('udp-cname', 'hit', 'hit', 4000, 2048),
                ('tcp-cname', 'tcp', 'hit', 3000, 2048),
                ('udp-hit', 'hit', 'hit', 4000, 4096),
                ('udp-miss', 'miss', 'miss', 2000, 4096),
                ('tcp-hit', 'tcp', 'hit', 3000, 4096),
                ('tcp-miss', 'tcp', 'miss', 2000, 4096)]
    plan = dict(scope='Fresh release main/fix on Oracle, scoped paired cost screen, not router or saturation qualification',
                groups=groups, assets={str(p): sha(p) for p in assets}, windows=[],
                rule='Keep every window. 3 paired rounds ordered AB/BA/AB. Flag median cost increase >10%, greater than both relative ranges and all three pairs worse. Retain all scheduled skips and correctness errors. Exact image overlays and CPU separation 0/1/2/3. CNAME owner bank is 2048 plus one shared A terminal in 4096 slots; upstream disabled during hits.')
    for round_no in range(1, 4):
        for profile, scenario, tcp, rate, names in profiles:
            for variant in (['main', 'fix'] if round_no % 2 else ['fix', 'main']):
                ident = f'{profile}-r{round_no}-{variant}'
                runner = [str(SCRIPTS / 'cname_window.py'), str(SOURCE)] if 'cname' in profile else [str(TOOLS / 'm6a_window.py')]
                argv = ['bash', str(TOOLS / 'run_isolated.sh'), 'python3', *runner,
                        '--implementation', 'rs', '--rust', groups[variant]['elf'],
                        '--expected-rust-sha', groups[variant]['sha256'], '--image-root', str(IMAGE),
                        '--loadgen', str(NATIVE / 'm6a_loadgen'), '--upstream', str(NATIVE / 'm6a_upstream'),
                        '--preflight', '--scenario', scenario, '--tcp-profile', tcp, '--round', str(round_no),
                        '--rate', str(rate), '--cache-names', str(names), '--clients', '20',
                        '--warmup', '3', '--duration', '20' if 'cname' in profile else '10', '--saturation-seconds', '0',
                        '--cpu-daemon', '0', '--cpu-upstream', '1', '--cpu-load', '2', '--cpu-control', '3',
                        '--drain-sample-seconds', '0,1', '--drain-timeout-seconds', '65',
                        '--seed', str(0x4d463300 + round_no), '--output', str(OUT / ident)]
                plan['windows'].append(dict(id=ident, profile=profile, variant=variant, round=round_no, argv=argv))
    save(OUT / 'plan.json', plan)
    print('prepared', len(plan['windows']), flush=True)


def verify(plan):
    for path, expected in plan['assets'].items():
        assert sha(path) == expected, path


def run():
    assert os.geteuid() == 0
    plan = json.loads((OUT / 'plan.json').read_text())
    verify(plan)
    assert not (OUT / 'run.json').exists()
    with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        busy = foreign_workloads()
        save(OUT / 'foreign-before.json', busy)
        assert not busy, busy
        os.sched_setaffinity(0, {3})
        state = dict(status='running', started=time.time(), windows=[])
        save(OUT / 'run.json', state)
        try:
            for window in plan['windows']:
                verify(plan)
                row = dict(id=window['id'], started=time.time())
                state['windows'].append(row)
                save(OUT / 'run.json', state)
                with (OUT / (window['id'] + '.log')).open('wb') as log:
                    process = subprocess.Popen(window['argv'], cwd=SOURCE, stdout=log, stderr=log, start_new_session=True)
                    known = {}
                    try:
                        while process.poll() is None:
                            remember_job_processes(process, known)
                            if time.time() - row['started'] > 180:
                                raise TimeoutError(window['id'])
                            try:
                                process.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        stop_job_processes(process, known)
                row.update(returncode=process.returncode, ended=time.time())
                save(OUT / 'run.json', state)
                print(json.dumps(row), flush=True)
                if process.returncode:
                    raise RuntimeError('failed window retained, no retry: ' + window['id'])
            state['status'] = 'complete'
        except BaseException as error:
            state.update(status='incomplete', error=repr(error))
            raise
        finally:
            state['ended'] = time.time()
            save(OUT / 'run.json', state)
    summarize()


def summarize():
    plan = json.loads((OUT / 'plan.json').read_text())
    verify(plan)
    result = dict(scope=plan['scope'], plan_sha256=sha(OUT / 'plan.json'), groups=plan['groups'],
                  windows=[], comparisons=[], errors=[])
    for window in plan['windows']:
        folder = OUT / window['id']
        if not (folder / 'result.json').exists():
            continue
        observed = analyze_window(folder)
        save(folder / 'audit-analysis.json', observed)
        identity = json.loads((folder / 'process-identity.json').read_text())
        assert identity['sha256'] == plan['groups'][window['variant']]['sha256']
        assert observed['methodology_valid'] and not observed['analysis_errors'], observed['analysis_errors']
        measurement = observed['measurement']
        errors = {k: measurement['origin_counts'][k] for k in ('wrong', 'timeout', 'transport_error')}
        counters = {phase: {k: observed['load_counters'][phase].get(k) for k in
                    ('scheduled', 'sent', 'scheduled_skipped', 'correct', 'wrong', 'timeout', 'transport_error')}
                    for phase in ('warmup', 'measurement')}
        if any(errors.values()) or measurement['generator_limited']:
            result['errors'].append(dict(id=window['id'], errors=errors, generator_limit=measurement['generator_limit_reasons']))
        metrics = dict(cpu_us_per_correct=measurement['cpu_us_per_correct'],
                       p95_ns=measurement['latency_ns']['p95'], **measurement['resources']['sampled_tree_peaks'])
        result['windows'].append({**{k: v for k, v in window.items() if k != 'argv'},
                                  'metrics': metrics, 'errors': errors, 'load_counters': counters,
                                  'raw_inputs': observed['input_sha256']})
    result['complete'] = len(result['windows']) == len(plan['windows'])
    if result['complete']:
        for profile in dict.fromkeys(w['profile'] for w in plan['windows']):
            for metric in ('cpu_us_per_correct', 'p95_ns', 'pss_kib', 'rss_kib', 'fd_count'):
                values = {variant: [next(w['metrics'][metric] for w in result['windows']
                                        if w['profile'] == profile and w['variant'] == variant and w['round'] == round_no)
                                    for round_no in range(1, 4)] for variant in ('main', 'fix')}
                a, b = (statistics.median(values[v]) for v in ('main', 'fix'))
                wa, wb = ((max(values[v]) - min(values[v])) / statistics.median(values[v])
                          for v in ('main', 'fix'))
                delta = b / a - 1
                worse = sum(y > x for x, y in zip(values['main'], values['fix']))
                result['comparisons'].append(dict(profile=profile, metric=metric, **values,
                    main_median=a, fix_median=b, relative_delta=delta, main_W=wa, fix_W=wb,
                    worse_pairs=worse, flag=delta > .1 and delta > max(wa, wb) and worse == 3))
    save(OUT / 'summary.json', result)
    print(json.dumps(dict(complete=result['complete'], errors=result['errors'],
                         flags=[r for r in result['comparisons'] if r['flag']]), indent=2), flush=True)


if __name__ == '__main__':
    globals()[sys.argv[1]]()
