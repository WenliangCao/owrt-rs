#!/usr/bin/env python3
"""Five new AB/BA pairs, 30s each, confirming TCP +1000 dns-rr cost."""
import json
from pathlib import Path
import statistics
import sys

import paired_dns as base

BASE_OUT = base.ROOT / 'private/performance-raw-records'
base.OUT = base.ROOT / 'private/performance-raw-confirm'


def prepare():
    base.OUT.mkdir(exist_ok=False)
    initial = json.loads((BASE_OUT / 'plan.json').read_text())
    assets = dict(initial['assets'])
    assets[str(Path(__file__))] = base.sha(__file__)
    plan = dict(scope='Independent longer confirmation of observed TCP cached A scaling regression: 1000 unrelated dns-rr records',
                groups=initial['groups'], assets=assets, windows=[],
                rule='Five NEW pairs AB/BA/AB/BA/AB; all original screen windows retained separately. 1000QPS, warmup5s, measure30s; no reruns. Flag >10% median CPU increase larger than both relative ranges with all five pairs worse.')
    for round_no in range(1, 6):
        for variant in (['main', 'fix'] if round_no % 2 else ['fix', 'main']):
            template = next(w for w in initial['windows'] if w['profile'] == 'tcp-raw-1000'
                            and w['round'] == 1 and w['variant'] == variant)
            ident = f'tcp-raw-1000-confirm-r{round_no}-{variant}'
            argv = list(template['argv'])
            for key, value in (('--warmup', '5'), ('--duration', '30'), ('--round', str(round_no)),
                               ('--seed', str(0x4d463400 + round_no)), ('--output', str(base.OUT / ident))):
                argv[argv.index(key) + 1] = value
            plan['windows'].append(dict(id=ident, profile='tcp-raw-1000', variant=variant, round=round_no, argv=argv))
    base.save(base.OUT / 'plan.json', plan)
    print('prepared', len(plan['windows']), flush=True)


def summarize():
    plan = json.loads((base.OUT / 'plan.json').read_text())
    base.verify(plan)
    result = dict(scope=plan['scope'], plan_sha256=base.sha(base.OUT / 'plan.json'), groups=plan['groups'],
                  windows=[], comparisons=[], errors=[])
    for window in plan['windows']:
        folder = base.OUT / window['id']
        observed = base.analyze_window(folder)
        base.save(folder / 'audit-analysis.json', observed)
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
    result['complete'] = len(result['windows']) == 10
    for metric in ('cpu_us_per_correct', 'p95_ns', 'pss_kib', 'rss_kib', 'fd_count'):
        values = {variant: [next(w['metrics'][metric] for w in result['windows']
                                if w['variant'] == variant and w['round'] == round_no)
                            for round_no in range(1, 6)] for variant in ('main', 'fix')}
        a, b = (statistics.median(values[v]) for v in ('main', 'fix'))
        wa, wb = ((max(values[v]) - min(values[v])) / statistics.median(values[v]) for v in ('main', 'fix'))
        delta = b / a - 1
        worse = sum(y > x for x, y in zip(values['main'], values['fix']))
        result['comparisons'].append(dict(profile='tcp-raw-1000', metric=metric, **values,
            main_median=a, fix_median=b, relative_delta=delta, main_W=wa, fix_W=wb,
            worse_pairs=worse, flag=delta > .1 and delta > max(wa, wb) and worse == 5))
    base.save(base.OUT / 'summary.json', result)
    print(json.dumps(dict(complete=result['complete'], errors=result['errors'],
                         flags=[r for r in result['comparisons'] if r['flag']]), indent=2), flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare()
    else:
        base.summarize = summarize
        getattr(base, sys.argv[1])()
