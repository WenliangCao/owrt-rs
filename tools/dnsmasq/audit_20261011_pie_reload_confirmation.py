#!/usr/bin/env python3
"""Predeclared six-window reload confirmation; retains the original failed screen."""
import argparse
import fcntl
import importlib.util
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path('/home/ubuntu/dnsmasq-audit-fix-20261011')
PRIVATE = ROOT / 'private'
ORIGINAL = PRIVATE / 'pie-screen-02-final'
spec = importlib.util.spec_from_file_location('original_pie_screen', PRIVATE / 'pie_screen.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
read, save, sha = base.read, base.save, base.sha


def prepare(out):
    original = read(ORIGINAL / 'plan.json')
    result = read(ORIGINAL / 'summary.json')
    base.verify_assets(original)
    assert result['complete'] and not result['accepted'] and not result['errors'] and not result['limited_windows']
    assert [(x['profile'], x['metric']) for x in result['comparisons'] if x['regression_flag']] == [('reload-concurrent', 'p95_ns')]
    out.mkdir(parents=True, exist_ok=False)
    plan = dict(scope='A07 targeted reload confirmation only; not M6 qualification, equivalence proof or router performance evidence',
                source=original['source'], image_root=original['image_root'], groups=original['groups'],
                original_plan=dict(path=str(ORIGINAL / 'plan.json'), sha256=sha(ORIGINAL / 'plan.json')),
                original_summary=dict(path=str(ORIGINAL / 'summary.json'), sha256=sha(ORIGINAL / 'summary.json')),
                assets=dict(original['assets']), windows=[],
                reason='Original three reload pairs flag p95. Retain them and add exactly rounds 4-6; never reclassify original three as passing.',
                acceptance='For CPU/correct-unit and p95, flag iff median PIE/static delta >10%, delta >max(W_static,W_pie), and every paired round worsens. Reject if either confirmation-three or combined-six flags any metric. Adoption requires neither flag and no behavior/method/generator issue.',
                limitations=['No flag is not a proof of performance equivalence.',
                             'Range/median W is sensitive to extreme samples; all samples are retained.',
                             'Only reload is repeated, so preceding workload history differs from the original four-profile screen.'])
    for path in (Path(__file__).resolve(), ORIGINAL / 'plan.json', ORIGINAL / 'summary.json'):
        plan['assets'][str(path)] = sha(path)
    for round_no in (4, 5, 6):
        for variant in (('pie', 'static') if round_no % 2 == 0 else ('static', 'pie')):
            prior = next(w for w in original['windows'] if w['profile'] == 'reload-concurrent' and w['variant'] == variant and w['round'] == 1)
            ident = f'reload-concurrent-r{round_no}-{variant}'
            argv = list(prior['argv'])
            for flag, value in (('--round', round_no), ('--seed', 0x4d364100 + round_no), ('--output', out / ident)):
                argv[argv.index(flag) + 1] = str(value)
            plan['windows'].append(dict(id=ident, profile='reload-concurrent', variant=variant, round=round_no, argv=argv))
    save(out / 'plan.json', plan)
    print(dict(status='prepared-only-no-load', windows=6, plan=str(out / 'plan.json'), sha256=sha(out / 'plan.json')))


def compare(rows, rounds, metric):
    values = {v: [next(x['metrics'][metric] for x in rows if x['variant'] == v and x['round'] == n) for n in rounds]
              for v in ('static', 'pie')}
    a, b = values['static'], values['pie']
    am, bm = statistics.median(a), statistics.median(b)
    wa, wb = (max(a) - min(a)) / am, (max(b) - min(b)) / bm
    delta = bm / am - 1
    worse = sum(y > x for x, y in zip(a, b))
    return dict(metric=metric, round_numbers=list(rounds), static_rounds=a, pie_rounds=b,
                static_median=am, pie_median=bm, relative_delta=delta, static_W=wa, pie_W=wb, max_W=max(wa, wb),
                worse_direction_rounds=worse, paired_rounds=len(a),
                regression_flag=delta > .10 and delta > max(wa, wb) and worse == len(a))


def summarize(out):
    plan = read(out / 'plan.json')
    base.verify_assets(plan)
    sys.path.insert(0, str(base.TOOLS))
    from m6a_analyze import analyze_window
    original = read(ORIGINAL / 'summary.json')
    rows = [dict(row, evidence_group='original') for row in original['windows'] if row['profile'] == 'reload-concurrent']
    result = dict(scope=plan['scope'], original_summary=plan['original_summary'], original_screen_accepted=False,
                  plan_sha256=sha(out / 'plan.json'), errors=[], limited_windows=[], windows=[], comparisons={},
                  complete=False, adoptable=False, limitations=plan['limitations'], elf_size=original['elf_size'])
    for window in plan['windows']:
        folder = out / window['id']
        try:
            observed = analyze_window(folder)
            save(folder / 'analysis.json', observed)
            actual = read(folder / 'process-identity.json')
            expected = plan['groups'][window['variant']]['sha256']
            assert actual['sha256'] == observed['identity']['expected_elf_sha256'] == expected
            assert observed['pilot'] and observed['methodology_valid'] and not observed['analysis_errors']
            m = observed['measurement']
            errors = {key: m['origin_counts'][key] for key in ('wrong', 'timeout', 'transport_error')}
            errors.update({'aux_' + key: value['errors'] for key, value in observed['auxiliary'].items()})
            for phase in ('warmup', 'measurement'):
                errors.update({phase + '_' + key: observed['load_counters'][phase][key]
                               for key in ('wrong', 'timeout', 'transport_error')})
            if any(errors.values()):
                result['errors'].append(dict(id=window['id'], behavior_errors=errors))
            if m['generator_limited']:
                result['limited_windows'].append(dict(id=window['id'], reasons=m['generator_limit_reasons']))
            metrics = dict(cpu_us_per_correct=m['cpu_us_per_correct'], p95_ns=m['latency_ns']['p95'])
            assert all(v is not None and math.isfinite(v) and v > 0 for v in metrics.values())
            row = dict(id=window['id'], profile=window['profile'], variant=window['variant'], round=window['round'],
                       evidence_group='confirmation', actual_elf_sha256=actual['sha256'], metrics=metrics, errors=errors,
                       analysis_sha256=sha(folder / 'analysis.json'), raw_inputs=observed['input_sha256'])
            rows.append(row)
            result['windows'].append(row)
        except Exception as error:
            result['errors'].append(dict(id=window['id'], error=repr(error)))
    result['complete'] = len(result['windows']) == 6
    result['original_windows'] = [row for row in rows if row['evidence_group'] == 'original']
    if result['complete']:
        for name, rounds in (('original_three', (1, 2, 3)), ('confirmation_three', (4, 5, 6)), ('combined_six', (1, 2, 3, 4, 5, 6))):
            result['comparisons'][name] = [compare(rows, rounds, metric) for metric in ('cpu_us_per_correct', 'p95_ns')]
    flags = [dict(group=group, **row) for group in ('confirmation_three', 'combined_six')
             for row in result['comparisons'].get(group, []) if row['regression_flag']]
    result['rejection_flags'] = flags
    result['adoptable'] = bool(result['complete'] and not result['errors'] and not result['limited_windows']
                              and result['elf_size']['passed'] and not flags)
    result['verdict'] = 'original_signal_not_sustained_under_this_confirmation' if result['adoptable'] else 'reject_PIE_or_inconclusive_invalid_measurement'
    save(out / 'summary.json', result)
    print(dict(summary=str(out / 'summary.json'), complete=result['complete'], adoptable=result['adoptable'],
               errors=result['errors'], limited_windows=result['limited_windows'], rejection_flags=flags), flush=True)
    return int(not result['adoptable'])


def run(out):
    assert os.geteuid() == 0 and not sys.flags.optimize
    plan = read(out / 'plan.json')
    base.verify_assets(plan)
    assert not (out / 'run.json').exists(), 'no automatic retry'
    busy = base.foreign_workloads()
    if busy:
        save(out / 'foreign-workloads.json', busy)
        raise ValueError('other Oracle workloads remain')
    assert {0, 1, 2, 3} <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, {3})
    sys.path.insert(0, str(base.TOOLS))
    import m5_final_validation as cleanup
    state = dict(status='running', scope=plan['scope'], started_ns=time.time_ns(), windows=[])
    save(out / 'run.json', state)
    try:
        for window in plan['windows']:
            base.verify_assets(plan)
            record = dict(id=window['id'], started_ns=time.time_ns(), status='running')
            state['windows'].append(record)
            save(out / 'run.json', state)
            with (out / (window['id'] + '.log')).open('wb') as log:
                process = subprocess.Popen(window['argv'], cwd=base.SOURCE, stdout=log, stderr=log, start_new_session=True)
                known = {}
                try:
                    deadline = time.monotonic() + 180
                    while process.poll() is None:
                        cleanup.remember_job_processes(process, known)
                        if time.monotonic() > deadline:
                            raise TimeoutError(window['id'])
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                finally:
                    cleanup.stop_job_processes(process, known)
            record.update(returncode=process.returncode, ended_ns=time.time_ns(), status='completed' if process.returncode == 0 else 'invalid')
            save(out / 'run.json', state)
            print(record, flush=True)
            assert process.returncode == 0, 'window failed; no automatic retry'
        base.verify_assets(plan)
        state['status'] = 'complete'
    except BaseException as error:
        state.update(status='failed-incomplete', error=repr(error))
        raise
    finally:
        state['ended_ns'] = time.time_ns()
        save(out / 'run.json', state)
    return summarize(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'summarize'))
    parser.add_argument('--out', type=Path, default=PRIVATE / 'pie-reload-confirmation')
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts
    if args.action == 'prepare':
        prepare(out)
        return 0
    if args.action == 'summarize':
        return summarize(out)
    with (PRIVATE / 'pie-screen.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as build_lock:
            fcntl.flock(build_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return run(out)


if __name__ == '__main__':
    raise SystemExit(main())
