#!/usr/bin/env python3
"""Compare frozen Rust and candidate netifd/procd matrices on the build host.

Usage: sudo python3 compare_lifecycle.py ROOTFS BASELINE_BUNDLE CANDIDATE_BUNDLE OUTPUT
Both bundles need the frozen owrt-benchmark and ns-exec. This is a build-host
comparison, not router acceptance. No failed request or incomplete run counts.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess

from analyze import COMPONENT_WORK, memory, stats
from analyze_candidate import NETIFD_EXTRA, PROCD_EXTRA, check_netifd_hotplug, parallel, serial

ORDER = ("baseline", "candidate", "candidate", "baseline",
         "candidate", "baseline", "baseline", "candidate")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "subject_cpu_us_per_op")


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("baseline", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--iterations", type=int, default=30000)
    p.add_argument("--cpus", help="optional taskset CPU list, held constant for all runs")
    p.add_argument("--components", nargs="+", choices=("procd", "netifd"), default=("procd", "netifd"))
    args = p.parse_args()
    if len(set(args.components)) != len(args.components):
        p.error("duplicate components")
    if os.geteuid() != 0 or Path('/etc/openwrt_release').exists():
        p.error("run as root on the Linux build host, not a physical router")
    if args.iterations < 1000 or args.iterations % 4:
        p.error("iterations must be >=1000 and divisible by four")
    args.output.mkdir(parents=True, exist_ok=False)
    bundles = {s: getattr(args, s).resolve() for s in ("baseline", "candidate")}
    for binary in ("ns-exec", "owrt-benchmark"):
        assert digest(bundles['baseline']/binary) == digest(bundles['candidate']/binary)
    identities = {component: {s: digest(b/(component+'-rs')) for s, b in bundles.items()}
                  for component in ("procd", "netifd")}
    rows, residents = [], []
    fixtures = defaultdict(set)
    boots, clients, kernels = set(), set(), set()
    script = Path(__file__).with_name('isolated.sh')
    for component in args.components:
        work = list(COMPONENT_WORK[component])
        work += [n+'_c4' for n in COMPONENT_WORK[component]]
        work += [n+s for n in (PROCD_EXTRA if component == 'procd' else NETIFD_EXTRA) for s in ('', '_c4')]
        for number, side in enumerate(ORDER, 1):
            raw = args.output/component/f'{number:02d}-{side}'
            raw.parent.mkdir(exist_ok=True)
            command = ['sh', str(script), str(args.rootfs.resolve()), str(bundles[side]), component, 'rs', str(raw), str(args.iterations)]
            if args.cpus:
                command = ['taskset', '-c', args.cpus, *command]
            print(f'START {component} {number} {side}', flush=True)
            with raw.with_suffix('.log').open('wb') as log:
                subprocess.run(command, env=dict(os.environ, **{'OWRT_'+component.upper()+'_MATRIX': '1'}),
                               stdout=log, stderr=log, check=True, timeout=1800)
            assert (raw/'COMPLETE').exists()
            meta = read(raw/'meta.json')
            assert meta['component'] == component and meta['dependencies'] == 'original OpenWrt'
            subject = meta['subject_pid']
            for name in ('binary-sha256.txt', 'subject-sha256.txt'):
                assert (raw/name).read_text().split()[0] == identities[component][side]
            boots.add((raw/'boot-id.txt').read_text())
            kernels.add((raw/'kernel.txt').read_text().strip())
            clients.add((raw/'benchmark-sha256.txt').read_text())
            fixtures[component].add((raw/(component+'-fixtures.sha256')).read_text())
            if component == 'netifd':
                for count in (2, 32):
                    names = [f'bench{i:02d}' for i in range(count-2)] + ['lan', 'loopback']
                    assert check_netifd_hotplug(raw, subject, count, names)
                    for phase in ('before', 'after'):
                        assert (raw/f'interface-names-{count}-{phase}.txt').read_text().splitlines() == names
                        assert (raw/f'interface-objects-{count}-{phase}.txt').read_text().splitlines() == ['network.interface.'+n for n in names]
            for workload in work:
                value = parallel(raw/workload, subject) if workload.endswith('_c4') else serial(raw/(workload+'.json'), subject)
                assert value['successful'] == args.iterations
                if component == 'netifd':
                    if workload.endswith('_c4'):
                        ticks = [next(x for x in read(raw/workload/(phase+'.json'))['processes'] if x['pid'] == subject)['child_cpu_ticks']
                                 for phase in ('before', 'after')]
                        assert ticks[0] == ticks[1]
                    else:
                        own = next(x for x in read(raw/(workload+'.json'))['daemon_cpu'] if x['pid'] == subject)
                        assert own['child_cpu_s'] == 0
                rows.append({'component':component, 'side':side, 'run':number, 'workload':workload,
                             **{k:value[k] for k in METRICS}})
            own = next(x for x in read(raw/'resident.json')['processes'] if x['pid'] == subject)
            residents.append({'component':component, 'side':side, 'run':number, **memory(own)})
            (args.output/'progress.json').write_text(json.dumps(rows, indent=2)+'\n')
            print(f'END {component} {number} {side}', flush=True)
    assert len(boots) == len(clients) == len(kernels) == 1
    assert all(len(v) == 1 for v in fixtures.values())
    groups = defaultdict(list)
    for row in rows:
        groups[(row['component'], row['workload'], row['side'])].append(row)
    summary = []
    for component, workload in sorted({(r['component'], r['workload']) for r in rows}):
        sides = {s:{m:stats(r[m] for r in groups[(component,workload,s)]) for m in METRICS}
                 for s in bundles}
        delta = {m:(sides['candidate'][m]['median']/sides['baseline'][m]['median']-1)*100 for m in METRICS
                 if sides['baseline'][m]['median'] > 0}
        summary.append({'component':component, 'workload':workload, **sides, 'candidate_vs_baseline_pct':delta})
    result = {'environment':'aarch64 Linux build host; not router acceptance', 'kernels':sorted(kernels),
              'cpus':args.cpus, 'components':args.components, 'iterations':args.iterations, 'order':ORDER, 'identities':identities,
              'benchmark_sha256':digest(bundles['baseline']/'owrt-benchmark'),
              'namespace_sha256':digest(bundles['baseline']/'ns-exec'), 'harness_sha256':digest(script),
              'summary':summary, 'runs':rows, 'resident':residents,
              'method':'Median of four per-run statistics per side; c4 CPU includes warm-up in one outer interval. Every request, binary identity and netifd child-settling gate must pass.'}
    (args.output/'results.json').write_text(json.dumps(result, indent=2)+'\n')
    (args.output/'COMPLETE').touch()
    for row in summary:
        print(row['component'], row['workload'], json.dumps(row['candidate_vs_baseline_pct']), flush=True)


if __name__ == '__main__':
    main()
