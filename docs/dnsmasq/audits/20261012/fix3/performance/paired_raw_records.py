#!/usr/bin/env python3
"""AB/BA cached A cost with unrelated dns-rr records; UDP is scan control."""
import json
from pathlib import Path
import sys

import paired_dns as base

BASE_OUT = base.OUT
base.OUT = base.ROOT / 'private/performance-raw-records'


def prepare():
    base.OUT.mkdir(exist_ok=False)
    initial = json.loads((BASE_OUT / 'plan.json').read_text())
    assets = dict(initial['assets'])
    for path in (Path(__file__), base.SCRIPTS / 'raw_records_window.py'):
        assets[str(path)] = base.sha(path)
    plan = dict(scope='Fresh release main/fix cached A with unrelated valid dns-rr entries; tests newly local-first TCP lookup scalability',
                groups=initial['groups'], assets=assets, windows=[],
                rule='3 rounds AB/BA/AB; UDP 1000-record control pays existing local scan on both revisions. 100/1000 unrelated custom type 65401 records. 1000QPS, warmup3s, measure15s. Upstream disabled after 4096 cache entries are proved. No retries, preserve skips/errors.')
    for round_no in range(1, 4):
        for transport, count in (('tcp', 100), ('tcp', 1000), ('udp', 1000)):
            profile = f'{transport}-raw-{count}'
            for variant in (['main', 'fix'] if round_no % 2 else ['fix', 'main']):
                template = next(w for w in initial['windows'] if w['profile'] == f'{transport}-hit'
                                and w['round'] == round_no and w['variant'] == variant)
                ident = f'{profile}-r{round_no}-{variant}'
                argv = list(template['argv'])
                index = argv.index('python3') + 1
                argv[index:index + 1] = [str(base.SCRIPTS / 'raw_records_window.py'), str(base.SOURCE), str(count)]
                for key, value in (('--rate', '1000'), ('--duration', '15'), ('--output', str(base.OUT / ident))):
                    argv[argv.index(key) + 1] = value
                plan['windows'].append(dict(id=ident, profile=profile, variant=variant, round=round_no, argv=argv))
    base.save(base.OUT / 'plan.json', plan)
    print('prepared', len(plan['windows']), flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        prepare()
    else:
        getattr(base, sys.argv[1])()
