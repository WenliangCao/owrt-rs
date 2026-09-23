#!/usr/bin/env python3
"""Collect and verify the frozen 54-case Oracle monitor screen using the R134 fixture."""
import argparse
from fractions import Fraction
import itertools
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r134 import ubusd_stress_oracle as old

R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
POLICY = Path(__file__).with_name('screen-policy.json')
TOOLS = ('tools/r142/monitor_screen.py', 'tools/r142/make_screen_manifest.py', 'tools/r142/screen-policy.json',
         'tools/r142/test_monitor_screen.py', 'docs/reviews/R142_SCREEN_PLAN.md',
         'tools/r134/ubusd_stress_oracle.py', 'tools/benchmark/r131_event_stress_libubus.c')
METRICS = ('mean_us', 'p50_us', 'p95_us', 'p99_us', 'wall_us_op', 'daemon_cpu_us_op', 'caller_cpu_us_op')
check, sha = old.require, old.sha


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def schedule(policy):
    return [(block, label, mode) for block, labels in enumerate(itertools.permutations(policy['labels']), 1)
            for label in labels for mode in policy['modes']]


def validate_manifest(manifest, live=False):
    policy = read(POLICY)
    check(manifest['schema'] == 1 and manifest['policy'] == policy
          and manifest['policy_sha256'] == sha(POLICY), 'frozen policy differs')
    check(list(manifest['subjects']) == policy['labels'] and manifest['subjects']['c']['sha256'] == old.STOCK_SHA
          and manifest['subjects']['r136']['sha256'] == R136 and manifest['helper']['sha256'] == old.HELPER_SHA,
          'C/R136/helper identity differs')
    check(set(manifest['tools']) == set(TOOLS), 'frozen tool set differs')
    for name, digest in manifest['tools'].items():
        check(sha(ROOT / name) == digest, f'frozen tool changed: {name}')
    check(manifest['correctness']['passed'] is True and manifest['correctness']['candidate_sha256'] ==
          manifest['subjects']['candidate']['sha256'], 'exact candidate correctness required')
    check(manifest['libraries'] == {str(Path(manifest['rootfs']) / p.lstrip('/')): h for p, h in old.LIBRARIES.items()},
          'deployment library set differs')
    if live:
        for entry in [manifest['helper'], *manifest['subjects'].values(), *manifest['proofs'].values()]:
            check(sha(entry['path']) == entry['sha256'], 'frozen artifact/proof changed')
        check(all(sha(p) == h for p, h in manifest['libraries'].items()), 'runtime libraries changed')
    return policy


def measure(text, mode, pid):
    old.validate(text, mode, 2000, pid)
    rows = [json.loads(line) for line in text.splitlines()]
    result = rows[-1]
    samples = sorted(result['latency_ns'])
    n = len(samples)
    check(type(result['wall_ns']) is int and 0 < sum(samples) <= result['wall_ns'] and all(type(result[k]) is int and 0 < result[k] <= result['wall_ns']
          for k in ('daemon_cpu_ns', 'caller_cpu_ns')), 'raw clocks invalid')
    baseline = rows[0]['fds']
    check(baseline > 0, 'FD baseline invalid')
    for row in rows[:-1]:
        check(all(type(row[k]) is int and row[k] >= 0 for k in ('rss_kib', 'rssanon_kib', 'vmdata_kib', 'fds')),
              'memory/FD snapshot invalid')
    for row in rows[1:-2]:
        check(row['fds'] == baseline + 3, 'live connection count differs')
    metrics = {'mean_us': Fraction(sum(samples), n * 1000), 'wall_us_op': Fraction(result['wall_ns'], n * 1000),
               'daemon_cpu_us_op': Fraction(result['daemon_cpu_ns'], n * 1000),
               'caller_cpu_us_op': Fraction(result['caller_cpu_ns'], n * 1000)}
    for key, percentile in (('p50_us', 50), ('p95_us', 95), ('p99_us', 99)):
        metrics[key] = Fraction(samples[((n - 1) * percentile + 50) // 100], 1000)
    return metrics, [{k: v for k, v in row.items() if k != 'subject_pid'} for row in rows[:-1]]


def comparisons(indexed, policy):
    comparisons, vetoes = {}, []
    for baseline in ('r136', 'c'):
        comparisons[baseline] = {}
        for mode in policy['modes']:
            comparisons[baseline][mode] = {}
            for metric in METRICS:
                ratios = [indexed[block, 'candidate', mode][metric] / indexed[block, baseline, mode][metric]
                          for block in range(1, 7)]
                median = statistics.median(ratios)
                higher, lower = sum(r > 1 for r in ratios), sum(r < 1 for r in ratios)
                row = {'ratios_by_block': list(map(float, ratios)), 'median_delta_pct': float((median - 1) * 100),
                       'lower_blocks': lower, 'higher_blocks': higher,
                       'direction': 'unresolved_within_1pct' if abs(median - 1) <= Fraction(1, 100)
                       else 'descriptive_lower' if median < 1 else 'descriptive_higher'}
                comparisons[baseline][mode][metric] = row
                if baseline == 'r136' and metric in policy['latency_veto_metrics'] and median > Fraction(policy['latency_veto_ratio_above']) and higher >= policy['latency_veto_min_higher_blocks']:
                    vetoes.append({'mode': mode, 'metric': metric, **row})
    ratios = [indexed[block, 'candidate', 'monitor']['mean_us'] / indexed[block, 'r136', 'monitor']['mean_us']
              for block in range(1, 7)]
    passed = statistics.median(ratios) < Fraction(policy['primary_ratio_below']) and sum(r < 1 for r in ratios) >= policy['primary_min_lower_blocks']
    return {'comparisons': comparisons, 'primary_passed': passed, 'latency_vetoes': vetoes,
            'latency_checks': 9, 'screen_passed': passed and not vetoes, 'router_acceptance': False}


def run_case(case, subject, helper, rootfs, libraries, mode):
    case.mkdir(parents=True)
    loader = str(Path(rootfs) / 'lib/libc.so')
    prefix = [loader, '--library-path', f'{rootfs}/lib:{rootfs}/usr/lib']
    with tempfile.TemporaryDirectory(prefix='r142-screen-') as tmp:
        sock = Path(tmp) / 'ubus.sock'
        c = subject['kind'] == 'c'
        command = prefix + ['--argv0', '/sbin/ubusd', subject['path'], '-s', str(sock)] if c else ['/sbin/ubusd', '-s', str(sock)]
        expected = {subject['path']: subject['sha256'], **(libraries if c else {})}
        with (case / 'daemon.log').open('xb') as log:
            daemon = subprocess.Popen(command, executable=None if c else subject['path'],
                preexec_fn=lambda: os.sched_setaffinity(0, {1}), start_new_session=True, stdout=log, stderr=log)
            caller_exit = None
            try:
                deadline = time.monotonic() + 5
                while not sock.exists():
                    check(daemon.poll() is None and time.monotonic() < deadline, 'socket startup failed')
                    time.sleep(.01)
                before = old.identity(daemon, case, 'before', expected)
                check(subject['path'] in before['mapped_sha256'], 'subject mapping absent')
                call = ['taskset', '-c', '0', *prefix, helper['path'], 'event-stress', str(sock), mode, '2000', str(daemon.pid)]
                save(case / 'commands.json', {'daemon': command, 'caller': call})
                result = subprocess.run(call, capture_output=True, text=True, timeout=70)
                caller_exit = result.returncode
                (case / 'caller.jsonl').write_text(result.stdout)
                (case / 'caller.stderr').write_text(result.stderr)
                check(caller_exit == 0 and not result.stderr, 'helper failed or emitted stderr')
                measure(result.stdout, mode, daemon.pid)
                check(before == old.identity(daemon, case, 'after', expected), 'daemon identity changed')
                for stage in ('before', 'after'):
                    check((case / f'cmdline-{stage}.bin').read_bytes() == b'\0'.join(v.encode() for v in command) + b'\0', 'live daemon argv differs')
            finally:
                if daemon.poll() is None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=5)
                save(case / 'cleanup.json', {'caller_exit': caller_exit, 'daemon_exit': daemon.returncode})
        check(daemon.returncode in (0, -15) and not (case / 'daemon.log').read_bytes(), 'daemon cleanup/log failed')
    check(not sock.exists(), 'owned socket remains')
    (case / 'COMPLETE').touch()


def collect(manifest_path, out):
    manifest = read(manifest_path)
    policy = validate_manifest(manifest, live=True)
    check(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0
          and Path('/home/ubuntu/owrt-evidence').is_dir() and not Path('/etc/openwrt_release').exists()
          and {0, 1} <= os.sched_getaffinity(0), 'Oracle root CPU gate')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'manifest.json').write_bytes(manifest_path.read_bytes())
    def stop(signum, _frame):
        raise RuntimeError(f'stop requested by signal {signum}')
    handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for block, label, mode in schedule(policy):
            run_case(out / f'{block:02d}-{label}' / mode, manifest['subjects'][label], manifest['helper'],
                     manifest['rootfs'], manifest['libraries'], mode)
            print(f'COMPLETE block={block} subject={label} mode={mode}', flush=True)
        validate_manifest(manifest, live=True)
        (out / 'COMPLETE').touch()
        save(out / 'hashes.json', {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
    except BaseException as error:
        save(out / 'failure.json', {'error': str(error), 'type': type(error).__name__})
        (out / 'FAILED').touch()
        raise
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def analyze(root, manifest_path):
    manifest = read(manifest_path)
    policy = validate_manifest(manifest)
    check((root / 'COMPLETE').is_file() and not (root / 'FAILED').exists()
          and not (root / 'failure.json').exists(), 'series incomplete/failed')
    check((root / 'manifest.json').read_bytes() == manifest_path.read_bytes(), 'manifest changed')
    check(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in root.rglob('*')), 'nonregular evidence')
    hashes = read(root / 'hashes.json')
    check({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()} == set(hashes) | {'hashes.json'}, 'unlisted files')
    check(all(sha(root / p) == h for p, h in hashes.items()), 'evidence hashes differ')
    indexed, records, starts, identities = {}, [], [], set()
    for block, label, mode in schedule(policy):
        case = root / f'{block:02d}-{label}' / mode
        check((case / 'COMPLETE').is_file() and not (case / 'caller.stderr').read_bytes()
              and not (case / 'daemon.log').read_bytes(), 'case incomplete/logs nonempty')
        cleanup = read(case / 'cleanup.json')
        check(cleanup['caller_exit'] == 0 and cleanup['daemon_exit'] in (0, -15), 'unclean case')
        before, after = [read(case / f'identity-{stage}.json') for stage in ('before', 'after')]
        subject = manifest['subjects'][label]
        check(before == after and before['affinity'] == [1]
              and before['mapped_sha256'].get(subject['path']) == subject['sha256'], 'daemon identity changed')
        starts.append(int(before['start_ticks']))
        identities.add((before['pid'], before['start_ticks']))
        expected = {subject['path']: subject['sha256'], **(manifest['libraries'] if label == 'c' else {})}
        executable_sha = manifest['libraries'][str(Path(manifest['rootfs']) / 'lib/libc.so')] if label == 'c' else subject['sha256']
        check(before['exe_sha256'] == executable_sha and all(expected.get(p) == h for p, h in before['mapped_sha256'].items()), 'mapping identity differs')
        commands = read(case / 'commands.json')
        prefix = [str(Path(manifest['rootfs']) / 'lib/libc.so'), '--library-path', f"{manifest['rootfs']}/lib:{manifest['rootfs']}/usr/lib"]
        daemon = commands['daemon']
        sock = daemon[-1]
        check(daemon == (prefix + ['--argv0', '/sbin/ubusd', subject['path'], '-s', sock] if label == 'c' else ['/sbin/ubusd', '-s', sock]), 'daemon command changed')
        check(commands['caller'] == ['taskset', '-c', '0', *prefix, manifest['helper']['path'], 'event-stress', sock, mode, '2000', str(before['pid'])], 'caller command changed')
        for stage in ('before', 'after'):
            status = dict(line.split(':', 1) for line in (case / f'status-{stage}.txt').read_text().splitlines() if ':' in line)
            check(int(status['Pid']) == before['pid'] and int(status['Threads']) == 1 and status['Cpus_allowed_list'].strip() == '1', 'outer status differs')
            stat = (case / f'stat-{stage}.txt').read_text().rsplit(') ', 1)[1].split()
            check(stat[19] == before['start_ticks'], 'start ticks differ')
            check((case / f'cmdline-{stage}.bin').read_bytes() == b'\0'.join(v.encode() for v in daemon) + b'\0', 'live argv changed')
        metrics, memory = measure((case / 'caller.jsonl').read_text(), mode, before['pid'])
        indexed[block, label, mode] = metrics
        records.append({'block': block, 'label': label, 'mode': mode, 'metrics': {k: float(v) for k, v in metrics.items()},
                        'memory_diagnostic': memory, 'raw_sha256': sha(case / 'caller.jsonl')})
    check(len(records) == 54 and len(list(root.glob('*/*/caller.jsonl'))) == 54, 'case set differs')
    check(starts == sorted(starts) and len(identities) == 54, 'serial schedule/fresh daemons differ')
    return {'schema': 1, 'verified': True, 'scope': policy['scope'], 'cases': 54, 'samples': 108000,
            'verified_file_count': len(hashes), 'hash_manifest_sha256': sha(root / 'hashes.json'),
            'manifest_sha256': sha(manifest_path), 'policy': policy, 'policy_sha256': sha(POLICY),
            'subjects': {k: v['sha256'] for k, v in manifest['subjects'].items()}, 'helper_sha256': old.HELPER_SHA,
            'proofs': {k: v['sha256'] for k, v in manifest['proofs'].items()}, 'tools': manifest['tools'],
            'records': records, **comparisons(indexed, policy)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'analyze'))
    parser.add_argument('manifest', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.action == 'collect':
        check(args.output is None, 'collect writes only inside root')
        collect(args.manifest.resolve(), args.root.resolve())
    else:
        check(args.output is not None, 'analysis output required')
        report = analyze(args.root.resolve(), args.manifest.resolve())
        save(args.output, report)
        print(json.dumps({k: report[k] for k in ('verified', 'cases', 'primary_passed', 'latency_vetoes', 'screen_passed')}))


if __name__ == '__main__':
    main()
