#!/usr/bin/env python3
"""Freeze/run/decode excluded CPU-clock diagnostic windows after formal timing.

prepare --base-plan RAW_AFTER/plan.json --source SOURCE_SCAN_V2 --output FRESH
        [--include-tcp] [--main-map-build DIRECTORY/build.json]
run --output FRESH
decode --output FRESH

TCP is opt-in after the ordinary comparison establishes a remaining cost.
This never replaces a performance window or retries a failed diagnostic.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def need(value, message):
    if not value:
        raise ValueError(message)


def set_arg(argv, flag, value):
    argv[argv.index(flag) + 1] = str(value)


def prepare(args):
    need(args.base_plan and args.source, 'prepare requires --base-plan and --source')
    need('private' in args.output.parts, 'private output required')
    args.output.mkdir(parents=True, exist_ok=False)
    base = read(args.base_plan)
    tools = args.source / 'tools/dnsmasq'
    assets = [Path(__file__).resolve(), args.base_plan.resolve(), *tools.glob('*.py'), tools / 'run_isolated.sh']
    groups = copy.deepcopy(base['groups'])
    for variant, group in groups.items():
        elf = Path(group['elf'])
        need(sha(elf) == group['sha256'] and elf.stat().st_size == group['bytes'], 'frozen ELF changed')
        assets.append(elf)
        if variant == 'c':
            receipt = args.output / 'c-image-identity.json'
            save(receipt, {'receipt_kind': 'exact_image_artifact_manifest_not_a_build',
                           'source_plan_sha256': sha(args.base_plan),
                           'artifacts': [{'path': elf.name, 'bytes': group['bytes'], 'sha256': group['sha256']}]})
        else:
            receipt = args.main_map_build if variant == 'main' and args.main_map_build else elf.parent / 'build.json'
        build = read(receipt)
        need(build['artifacts'] == [{'path': elf.name, 'bytes': group['bytes'], 'sha256': group['sha256']}],
             'artifact receipt must bind the original measured ELF; no replacement symbol ELF')
        group['analysis_receipt'] = str(receipt)
        assets.append(receipt)
        group['analysis_map'] = None
        if build.get('link_map'):
            link_map = Path(build['link_map']['path'])
            if not link_map.is_absolute():
                link_map = receipt.parent / link_map
            need(sha(link_map) == build['link_map']['sha256'], 'same-build map hash changed')
            group['analysis_map'] = str(link_map)
            assets.append(link_map)
    need(groups['current']['analysis_map'], 'current requires its same-build map')
    selected = [('udp-raw-a-100', 'c', 100), ('udp-raw-a-100', 'current', 100)]
    if args.include_tcp:
        selected = [('tcp-ordinary', 'main', 0), ('tcp-ordinary', 'current', 0), *selected]
    windows = []
    for profile, variant, count in selected:
        template_profile = 'tcp-raw-a-100' if profile == 'tcp-ordinary' else profile
        template = next(row for row in base['windows'] if row['profile'] == template_profile
                        and row['variant'] == variant and row['round'] == 1)
        argv = list(template['argv'])
        need(Path(argv[3]).name == 'raw_window.py', 'unexpected configured-record wrapper')
        assets.extend([Path(argv[3]), Path(argv[argv.index('--loadgen') + 1]), Path(argv[argv.index('--upstream') + 1])])
        argv[1], argv[4], argv[5] = str(tools / 'run_isolated.sh'), str(args.source), str(count)
        ident = profile + '-' + variant
        rust_group = groups['current' if variant == 'c' else variant]
        set_arg(argv, '--rust', rust_group['elf'])
        set_arg(argv, '--expected-rust-sha', rust_group['sha256'])
        for flag, value in (('--warmup', 30), ('--duration', 300), ('--rate', 1000),
                            ('--seed', 0x4d533101), ('--output', args.output / ident)):
            set_arg(argv, flag, value)
        need('--preflight' in argv and '--perf-record' not in argv, 'diagnostic base options')
        argv += ['--perf-record', '--perf-event', 'cpu-clock', '--perf-call-graph', 'none']
        windows.append({'id': ident, 'profile': profile, 'variant': variant,
                        'declarations': count, 'argv': argv, 'timeout_seconds': 450})
    save(args.output / 'plan.json', {'scope': 'Excluded attribution only; no primary CPU/latency acceptance claims',
         'source': str(args.source), 'base_plan_sha256': sha(args.base_plan), 'groups': groups, 'windows': windows,
         'method': 'Serial fixed 1000QPS/20clients, warmup30/measure300, cpu-clock997 without callgraph. '
                   'Per-scenario same seed/config. Trace covers warmup+measurement+drain. No retries.',
         'assets': {str(path): sha(path) for path in sorted(set(assets))}})
    print(json.dumps({'prepared_windows': len(windows), 'plan': str(args.output / 'plan.json')}))


def verify(plan):
    for path, expected in plan['assets'].items():
        need(sha(path) == expected, 'frozen input changed: ' + path)


def run(args):
    need(os.geteuid() == 0, 'root in Oracle required')
    plan = read(args.output / 'plan.json')
    need(not (args.output / 'run.json').exists(), 'attempt already exists; no rerun')
    verify(plan)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from audit_20261011_pie_cost import foreign_workloads
    from m5_final_validation import remember_job_processes, stop_job_processes
    os.sched_setaffinity(0, {3})
    state = {'status': 'running', 'plan_sha256': sha(args.output / 'plan.json'), 'started': time.time(), 'windows': []}
    with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        save(args.output / 'run.json', state)
        try:
            for window in plan['windows']:
                verify(plan)
                busy = foreign_workloads()
                save(args.output / (window['id'] + '.foreign-before.json'), busy)
                need(not busy, 'another experiment is active')
                row = {'id': window['id'], 'started': time.time()}
                state['windows'].append(row)
                save(args.output / 'run.json', state)
                with (args.output / (window['id'] + '.log')).open('xb') as log:
                    process = subprocess.Popen(window['argv'], stdout=log, stderr=log, start_new_session=True)
                    known = {}
                    try:
                        while process.poll() is None:
                            remember_job_processes(process, known)
                            need(time.time() - row['started'] <= window['timeout_seconds'], 'diagnostic timeout')
                            try:
                                process.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        stop_job_processes(process, known)
                row.update(returncode=process.returncode, ended=time.time())
                save(args.output / 'run.json', state)
                need(process.returncode == 0, 'failed diagnostic retained: ' + window['id'])
            state['status'] = 'complete'
        except BaseException as error:
            state.update(status='incomplete', error=repr(error))
            raise
        finally:
            state['ended'] = time.time()
            save(args.output / 'run.json', state)


def decode(args):
    plan = read(args.output / 'plan.json')
    need(read(args.output / 'run.json')['status'] == 'complete', 'decode only after every diagnostic stops')
    verify(plan)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from m6a_analyze import analyze_window
    from m6a_window import diagnostic_tools_finished
    os.sched_setaffinity(0, {3})
    results, configs = [], {}
    for window in plan['windows']:
        folder = args.output / window['id']
        identity = read(folder / 'process-identity.json')
        group = plan['groups'][window['variant']]
        need(identity['sha256'] == group['sha256'], 'profile process identity mismatch')
        audit = analyze_window(folder)
        need(audit['methodology_valid'] and not audit['analysis_errors'], 'diagnostic workload invalid')
        need(not audit['measurement']['generator_limited'], 'diagnostic generator limited')
        proof = read(folder / 'cache-proof.json')
        need(proof['capacity'] == proof['filled_names'] == proof['validated_names'] == len(proof['rows']) == 4096
             and proof['upstream_disabled'] and all(row['correct'] for row in proof['rows']), 'cache bank unproved')
        upstream = read(folder / 'upstream.json')
        need(upstream['disabled'] and upstream['disabled_requests'] == upstream['phases']['steady']['requests'] == 0,
             'diagnostic cache hits reached upstream')
        configs.setdefault(window['profile'], set()).add(sha(folder / 'config'))
        if window['declarations']:
            direct = read(folder / 'same-type-proof.json')
            need(set(direct['replies']) == {'udp', 'tcp'} and all(
                row['correct'] and int.from_bytes(bytes.fromhex(row['hex'])[2:4], 'big') == 0x8580
                for row in direct['replies'].values()), 'configured raw proof must be authoritative')
        scope = read(folder / 'diagnostic-scope.json')
        need(scope['scope_complete'] and diagnostic_tools_finished(scope), 'incomplete perf capture')
        need(scope['perf_settings'] == {'event': 'cpu-clock', 'frequency_hz': 997, 'call_graph': 'none'},
             'diagnostic sampling options changed')
        need(read(folder / 'perf-command.json') == ['taskset', '-c', '3', 'perf', 'record', '-F', '997',
             '-e', 'cpu-clock', '-p', str(identity['pid']), '-o', str(folder / 'perf.data')], 'actual perf argv differs')
        save(folder / 'audit-analysis.json', audit)
        commands = [('perf-samples', ['script', '--hide-call-graph', '-F', 'pid,tid,misc,period,event,ip,sym,dso']),
                    ('perf-self', ['report', '--stdio', '--no-children', '--sort', 'dso,symbol', '--show-nr-samples',
                     '--show-total-period', '--percent-limit', '0', '-g', 'none', '--field-separator', ';', '--no-demangle'])]
        for label, options in commands:
            argv = ['taskset', '-c', '3', 'perf', *options[:1], '-i', str(folder / 'perf.data'), *options[1:]]
            with (folder / (label + '.txt')).open('xb') as stdout, (folder / (label + '.stderr')).open('xb') as stderr:
                result = subprocess.run(argv, stdout=stdout, stderr=stderr)
            save(folder / (label + '.command.json'), {'argv': argv, 'returncode': result.returncode})
            need(result.returncode == 0, 'perf decoding failed and evidence retained')
        results.append({'id': window['id'], 'actual_elf_sha256': identity['sha256'],
                        'correct_warmup_plus_measurement': sum(audit['load_counters'][phase]['correct'] for phase in ('warmup', 'measurement')),
                        'analysis_inputs': {'elf': group['elf'], 'build_json': group['analysis_receipt'], 'map': group['analysis_map'],
                            'samples': str(folder / 'perf-samples.txt'), 'report': str(folder / 'perf-self.txt'),
                            'process_identity': str(folder / 'process-identity.json'),
                            'maps_after': str(folder / 'proc-snapshots' / f"load-finished.{identity['pid']}.maps")},
                        'decoded_sha256': {label + '.txt': sha(folder / (label + '.txt')) for label, _ in commands}})
    need(all(len(values) == 1 for values in configs.values()), 'paired diagnostic configurations differ')
    save(args.output / 'decoded.json', {'scope': plan['scope'], 'plan_sha256': sha(args.output / 'plan.json'), 'windows': results})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'decode'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--base-plan', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--main-map-build', type=Path)
    parser.add_argument('--include-tcp', action='store_true')
    args = parser.parse_args()
    globals()[args.action](args)
