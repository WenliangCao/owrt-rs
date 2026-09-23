#!/usr/bin/env python3
"""Fixed crossed-caller Oracle collection and offline raw verification."""
import argparse
from decimal import Decimal, localcontext
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
from r136 import oracle_batch as base
from r134.ubusd_stress_oracle import LIBRARIES

C = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
OLD = '85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d'
NEW = '7adea8683e2ccd726ea918c700fec595fc77200c3f5c2cfc59bb1abc27b1d9ca'
POLICY = Path(__file__).with_name('screen-policy.json')
TOOLS = ('tools/r144/caller_screen.py', 'tools/r144/make_screen_manifest.py', 'tools/r144/screen-policy.json',
         'tools/r144/test_caller_screen.py', 'docs/reviews/R144_SCREEN_PLAN.md',
         'tools/r136/oracle_batch.py', 'tools/r134/ubusd_stress_oracle.py')
METRICS = (*base.METRICS, 'wall_us_per_op')
check, sha = base.require, base.sha256


def read(path):
    def unique(items):
        result = {}
        for k, v in items:
            check(k not in result, 'duplicate JSON key'); result[k] = v
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False); stream.write('\n')


def schedule(manifest):
    policy = manifest['policy']
    count = 1 if manifest['phase'] == 'smoke' else 6
    return [(b, daemon, caller, lane) for b in range(count) for daemon, caller in policy['orders'][b]
            for lane in policy['lane_orders'][b]]


def validate(manifest, live=False):
    policy = read(POLICY)
    check(manifest['phase'] in ('smoke', 'screen') and manifest['policy'] == policy
          and manifest['policy_sha256'] == sha(POLICY), 'policy/phase differs')
    check({k: v['sha256'] for k, v in manifest['daemons'].items()} == {'c': C, 'r136': R136}
          and {k: v['sha256'] for k, v in manifest['callers'].items()} == {'old': OLD, 'new': NEW}, 'fixed ELF identities differ')
    check(manifest['iterations'] == (10 if manifest['phase'] == 'smoke' else 10000)
          and manifest['warmup'] == 20 and manifest['cases'] == (12 if manifest['phase'] == 'smoke' else 72), 'fixed counts differ')
    check(set(manifest['tools']) == set(TOOLS) and all(sha(ROOT / p) == h for p, h in manifest['tools'].items()), 'frozen tool differs')
    check(manifest['libraries'] == {str(Path(manifest['rootfs']) / p.lstrip('/')): h for p, h in LIBRARIES.items()}, 'library set differs')
    check(manifest['build_verified'] is True, 'verified caller build/units required')
    if manifest['phase'] == 'screen':
        check(manifest['smoke']['verified'] is True and manifest['smoke']['cases'] == 12
              and manifest['smoke']['new_caller_sha256'] == NEW, 'exact functional smoke required')
    if live:
        entries = [*manifest['daemons'].values(), *manifest['callers'].values(), manifest['ubus_cli'], *manifest['proofs'].values()]
        check(all(sha(Path(e['path'])) == e['sha256'] for e in entries), 'frozen artifact/proof changed')
        check(all(sha(Path(p)) == h for p, h in manifest['libraries'].items()), 'library identity changed')


def native_prefix(manifest):
    root = manifest['rootfs']
    return [root + '/lib/libc.so', '--library-path', root + '/lib:' + root + '/usr/lib']


def object_list(manifest, sock):
    cmd = [*native_prefix(manifest), manifest['ubus_cli']['path'], '-s', str(sock), '-t', '1', 'list']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
    check(result.returncode == 0 and not result.stderr, 'object fixture query failed')
    return result.stdout


def capture(process, out, name, expected_args, cpu, expected_files, expected_exe, required_file):
    check(process.poll() is None, 'process exited during case')
    root = Path(f'/proc/{process.pid}')
    data = base.proc_identity(process.pid)
    check(data['Cpus_allowed_list'] == str(cpu) and data['Threads'] == 1, 'process affinity/threads differ')
    raw = (root / 'cmdline').read_bytes()
    check(raw == b'\0'.join(s.encode() for s in expected_args) + b'\0', 'live command differs')
    check(sha(root / 'exe') == expected_exe, 'live executable differs')
    maps = (root / 'maps').read_text(); mapped = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith('/'):
            path = str(Path(fields[5]).resolve())
            check(path in expected_files and sha(Path(path)) == expected_files[path], 'unexpected mapped file')
            mapped[path] = expected_files[path]
    check(mapped.get(required_file) == expected_files[required_file], 'required executable mapping absent')
    data.update(exe_sha256=expected_exe, mapped_sha256=mapped)
    save(out / f'{name}.json', data)
    (out / f'{name}.cmdline').write_bytes(raw); (out / f'{name}.maps').write_text(maps)
    return data


def same_process(before, after):
    check(all(before[k] == after[k] for k in ('pid', 'start_ticks', 'Threads', 'Cpus_allowed_list', 'exe_sha256', 'mapped_sha256')),
          'process identity changed')


def caller_args(lane, sock, out, n, pid):
    tail = [str(n), '20', str(pid)]
    if lane == 'register_1': return ['register-cycle', str(sock), '1', '8', *tail]
    if lane == 'lookup_1': return ['lookup', str(sock), 'bench.target', *tail]
    check(lane == 'invoke_1', 'unknown lane')
    return ['rpc', str(sock), 'bench.target', 'ping', str(out / 'input.json'), str(out / 'expect.json'), *tail]


def run_case(manifest, out, sock, daemon_label, caller_label, lane):
    out.mkdir(parents=True, exist_ok=False)
    daemon_info, caller_info = manifest['daemons'][daemon_label], manifest['callers'][caller_label]
    old = manifest['callers']['old']['path']
    acl = sock.parent / 'acl'; acl.mkdir(exist_ok=True)
    subject = {**daemon_info, 'kind': 'c' if daemon_label == 'c' else 'rust'}
    rootfs = {'loader': native_prefix(manifest)[0], 'library_path': native_prefix(manifest)[2]}
    command = base.subject_command(subject, Path(old), 1, sock, rootfs)
    live_command = command[3:] if daemon_label == 'c' else command[4:]
    files = {daemon_info['path']: daemon_info['sha256'], **(manifest['libraries'] if daemon_label == 'c' else {})}
    exe = manifest['libraries'][rootfs['loader']] if daemon_label == 'c' else daemon_info['sha256']
    provider_command = [old, 'exec-cpu', '0', old, 'serve', str(sock), '1']
    daemon = caller = provider = None; caller_exit = None
    save(out / 'daemon-command.json', command)
    try:
        with (out / 'daemon.log').open('xb') as log:
            daemon = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 5
        while not sock.exists():
            check(daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed'); time.sleep(.01)
        before = capture(daemon, out, 'daemon-before', live_command, 1, files, exe, daemon_info['path'])
        check(object_list(manifest, sock) == '', 'initial fixture not empty')
        if lane != 'register_1':
            save(out / 'provider-command.json', provider_command)
            with (out / 'provider.log').open('xb') as log:
                provider = subprocess.Popen(provider_command, stdout=log, stderr=log, start_new_session=True)
            deadline = time.monotonic() + 5
            while object_list(manifest, sock) != 'bench.target\n':
                check(provider.poll() is None and time.monotonic() < deadline, 'provider fixture not ready'); time.sleep(.01)
            (out / 'objects-before.txt').write_text('bench.target\n')
            provider_before = capture(provider, out, 'provider-before', provider_command[3:], 0, {old: OLD}, OLD, old)
        (out / 'input.json').write_text('{"n":1}\n'); (out / 'expect.json').write_text('{"ok":1}\n')
        call = [old, 'exec-cpu', '0', caller_info['path'], *caller_args(lane, sock, out, manifest['iterations'], daemon.pid)]
        save(out / 'caller-command.json', call)
        with (out / 'caller.json').open('xb') as stdout, (out / 'caller.log').open('xb') as stderr:
            caller = subprocess.Popen(call, stdout=stdout, stderr=stderr, start_new_session=True)
            caller_exit = caller.wait(timeout=120)
        save(out / 'caller-run.json', {'pid': caller.pid, 'exit': caller_exit})
        check(caller_exit == 0 and not (out / 'caller.log').read_bytes(), 'caller failed')
        base.check_measurement(read(out / 'caller.json'), daemon.pid, before['start_ticks'], caller.pid, '1', '0', manifest['iterations'], 20)
        if provider is not None:
            fixture = object_list(manifest, sock); (out / 'objects-with-provider-after.txt').write_text(fixture)
            check(fixture == 'bench.target\n', 'provider fixture changed')
            same_process(provider_before, capture(provider, out, 'provider-after', provider_command[3:], 0, {old: OLD}, OLD, old))
            check(not (out / 'provider.log').read_bytes(), 'provider log nonempty')
            base.stop_process(provider); check(provider.returncode in (0, -15), 'provider abnormal exit')
        deadline = time.monotonic() + 5
        while (remaining := object_list(manifest, sock)):
            check(time.monotonic() < deadline, 'fixture did not empty'); time.sleep(.01)
        (out / 'objects-after.txt').write_text(remaining)
        same_process(before, capture(daemon, out, 'daemon-after', live_command, 1, files, exe, daemon_info['path']))
        check(not (out / 'daemon.log').read_bytes(), 'daemon log nonempty')
    finally:
        for process in (caller, provider, daemon): base.stop_process(process)
        sock.unlink(missing_ok=True)
        save(out / 'cleanup.json', {'caller_exit': None if caller is None else caller.returncode,
            'provider_exit': None if provider is None else provider.returncode,
            'daemon_exit': None if daemon is None else daemon.returncode, 'socket_absent': not sock.exists()})
    check(daemon.returncode in (0, -15), 'daemon abnormal exit')
    (out / 'COMPLETE').touch()


def collect(manifest_path, out):
    manifest = read(manifest_path); validate(manifest, live=True)
    check(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0
          and Path('/home/ubuntu/owrt-evidence').is_dir() and not Path('/etc/openwrt_release').exists(), 'Oracle root only')
    out.mkdir(parents=True, exist_ok=False); (out / 'manifest.json').write_bytes(manifest_path.read_bytes())
    def stop(signum, _frame): raise RuntimeError(f'stop signal {signum}')
    handlers = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        with tempfile.TemporaryDirectory(prefix='r144-caller-') as temp:
            sock = Path(temp) / 'bus.sock'
            for block, daemon, caller, lane in schedule(manifest):
                run_case(manifest, out / f'b{block}-{daemon}-{caller}-{lane}', sock, daemon, caller, lane)
                print('COMPLETE', block, daemon, caller, lane, flush=True)
        validate(manifest, live=True)
        (out / 'COMPLETE').touch()
        save(out / 'hashes.json', {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
    except BaseException as error:
        save(out / 'failure.json', {'type': type(error).__name__, 'error': str(error)}); (out / 'FAILED').touch(); raise
    finally:
        for sig, handler in handlers.items(): signal.signal(sig, handler)


def metrics(data, n):
    values = sorted(data['latency_ns'])
    out = {'mean_us': Fraction(sum(values), n * 1000), 'wall_us_per_op': Fraction(str(data['wall_s'])) * 1000000 / n,
           'daemon_cpu_us_per_op': Fraction(data['daemon_cpu'][0]['cpu_clock_ns'], n * 1000),
           'caller_cpu_us_per_op': Fraction(data['client_cpu_clock_ns'], n * 1000)}
    for name, pct in (('p50_us', 50), ('p95_us', 95), ('p99_us', 99)):
        out[name] = Fraction(values[((n - 1) * pct + 50) // 100], 1000)
    return out


def decisions(indexed, policy):
    comparisons, vetoes, primary = [], [], []
    check(set(indexed) == set(itertools.product(range(6), ('c', 'r136'), ('old', 'new'), policy['lanes'])), '72-case decision set required')
    for daemon, lane, metric in itertools.product(policy['daemons'], policy['lanes'], METRICS):
        ratios = [indexed[b, daemon, 'new', lane][metric] / indexed[b, daemon, 'old', lane][metric] for b in range(6)]
        med = statistics.median(ratios)
        row = {'daemon': daemon, 'lane': lane, 'metric': metric, 'ratios_by_block': list(map(float, ratios)),
               'median_delta_pct': float((med - 1) * 100), 'lower_blocks': sum(r < 1 for r in ratios), 'higher_blocks': sum(r > 1 for r in ratios),
               'direction': 'unresolved_within_1pct' if abs(med - 1) <= Fraction(1, 100) else 'descriptive_lower' if med < 1 else 'descriptive_higher'}
        comparisons.append(row)
        if metric in policy['latency_veto_metrics'] and med > Fraction('1.03') and all(r > 1 for r in ratios): vetoes.append(row)
    with localcontext() as context:
        context.prec = 60
        for daemon in policy['daemons']:
            geometric = []
            for b in range(6):
                product = Fraction(1)
                for lane in policy['lanes']: product *= indexed[b, daemon, 'new', lane]['mean_us'] / indexed[b, daemon, 'old', lane]['mean_us']
                geometric.append(((Decimal(product.numerator) / Decimal(product.denominator)) ** (Decimal(1) / 3)).quantize(Decimal('1e-30')))
            med = statistics.median(geometric); lower = sum(r < 1 for r in geometric)
            primary.append({'daemon': daemon, 'geometric_ratios_by_block': list(map(str, geometric)), 'median_geometric_ratio': str(med),
                            'median_delta_pct': float((med - 1) * 100), 'lower_blocks': lower, 'passed': med < Decimal('.99') and lower >= 5})
    return {'comparisons': comparisons, 'primary': primary, 'veto_items': 18, 'vetoes': vetoes,
            'screen_passed': all(r['passed'] for r in primary) and not vetoes, 'router_acceptance': False}


def analyze(manifest_path, root):
    manifest = read(manifest_path); validate(manifest)
    check((root / 'COMPLETE').is_file() and not (root / 'FAILED').exists() and not (root / 'failure.json').exists(), 'run incomplete')
    check((root / 'manifest.json').read_bytes() == manifest_path.read_bytes(), 'manifest changed')
    hashes = read(root / 'hashes.json')
    check(all(not p.is_symlink() for p in root.rglob('*')) and {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()} == set(hashes) | {'hashes.json'}, 'evidence set differs')
    check(all(sha(root / p) == h for p, h in hashes.items()), 'raw hash mismatch')
    records, indexed, identities, starts, sockets = [], {}, set(), [], set()
    for block, daemon, caller, lane in schedule(manifest):
        case = root / f'b{block}-{daemon}-{caller}-{lane}'
        check((case / 'COMPLETE').exists() and not (case / 'caller.log').read_bytes() and not (case / 'daemon.log').read_bytes()
              and not (case / 'objects-after.txt').read_bytes(), 'case logs/fixture failed')
        before, after = read(case / 'daemon-before.json'), read(case / 'daemon-after.json'); same_process(before, after)
        ident = before['pid'], before['start_ticks']; check(ident not in identities, 'daemon reused'); identities.add(ident); starts.append(ident[1])
        check(before['Cpus_allowed_list'] == '1' and before['Threads'] == 1, 'daemon placement differs')
        subject = manifest['daemons'][daemon]; old = manifest['callers']['old']['path']
        command = read(case / 'daemon-command.json'); sock = command[-3]; acl = command[-1]
        sockets.add(sock)
        check(Path(acl) == Path(sock).parent / 'acl', 'isolated ACL path differs')
        expected = [*native_prefix(manifest), '--argv0', '/sbin/ubusd', subject['path'], '-s', sock, '-A', acl] if daemon == 'c' else [old, 'exec-cpu-as', '1', subject['path'], '/sbin/ubusd', '-s', sock, '-A', acl]
        check(command == (['taskset', '-c', '1', *expected] if daemon == 'c' else expected), 'daemon command differs')
        for stage in ('before', 'after'):
            live = command[3:] if daemon == 'c' else command[4:]
            check((case / f'daemon-{stage}.cmdline').read_bytes() == b'\0'.join(s.encode() for s in live) + b'\0', 'daemon live argv differs')
        check(before['mapped_sha256'].get(subject['path']) == subject['sha256'], 'daemon mapping identity differs')
        allowed = {subject['path']: subject['sha256'], **(manifest['libraries'] if daemon == 'c' else {})}
        wanted_exe = manifest['libraries'][native_prefix(manifest)[0]] if daemon == 'c' else subject['sha256']
        check(before['exe_sha256'] == wanted_exe and all(allowed.get(p) == h for p, h in before['mapped_sha256'].items()), 'daemon executable/library identity differs')
        run = read(case / 'caller-run.json'); check(run['exit'] == 0, 'caller failed')
        original_case = Path(read(case / 'caller-command.json')[-5]).parent if lane == 'invoke_1' else Path('/unused')
        if lane != 'invoke_1': original_case = case
        wanted_call = [old, 'exec-cpu', '0', manifest['callers'][caller]['path'], *caller_args(lane, Path(sock), original_case, manifest['iterations'], before['pid'])]
        check(read(case / 'caller-command.json') == wanted_call, 'caller command differs')
        check((case / 'input.json').read_bytes() == b'{"n":1}\n' and (case / 'expect.json').read_bytes() == b'{"ok":1}\n', 'RPC fixture differs')
        data = read(case / 'caller.json'); base.check_measurement(data, before['pid'], before['start_ticks'], run['pid'], '1', '0', manifest['iterations'], 20)
        cleanup = read(case / 'cleanup.json'); check(cleanup['caller_exit'] == 0 and cleanup['daemon_exit'] in (0, -15) and cleanup['socket_absent'] is True, 'cleanup failed')
        if lane != 'register_1':
            pbefore, pafter = read(case / 'provider-before.json'), read(case / 'provider-after.json'); same_process(pbefore, pafter)
            check(pbefore['Cpus_allowed_list'] == '0' and pbefore['exe_sha256'] == OLD and pbefore['mapped_sha256'] == {old: OLD}, 'provider changed')
            check(read(case / 'provider-command.json') == [old, 'exec-cpu', '0', old, 'serve', sock, '1'], 'provider command differs')
            check(all((case / f'provider-{s}.cmdline').read_bytes() == b'\0'.join(x.encode() for x in [old, 'serve', sock, '1']) + b'\0' for s in ('before', 'after')), 'provider live argv differs')
            check(cleanup['provider_exit'] in (0, -15) and not (case / 'provider.log').read_bytes()
                  and (case / 'objects-before.txt').read_bytes() == (case / 'objects-with-provider-after.txt').read_bytes() == b'bench.target\n', 'provider fixture/cleanup failed')
        else: check(cleanup['provider_exit'] is None, 'unexpected provider')
        values = metrics(data, manifest['iterations']); indexed[block, daemon, caller, lane] = values
        records.append({'block': block, 'daemon': daemon, 'caller': caller, 'lane': lane, 'raw_sha256': sha(case / 'caller.json'), 'metrics': {k: float(v) for k, v in values.items()}})
    check(len(records) == manifest['cases'] and len(list(root.glob('*/caller.json'))) == manifest['cases'] and starts == sorted(starts) and len(sockets) == 1, 'case count/serial order/socket differs')
    result = {'schema': 1, 'verified': True, 'phase': manifest['phase'], 'cases': len(records), 'new_caller_sha256': NEW,
              'old_caller_sha256': OLD, 'daemon_sha256': {'c': C, 'r136': R136}, 'manifest_sha256': sha(manifest_path),
              'policy_sha256': sha(POLICY), 'hash_manifest_sha256': sha(root / 'hashes.json'), 'verified_files': len(hashes),
              'records': records, 'performance_gate': manifest['phase'] == 'screen', 'router_acceptance': False}
    if manifest['phase'] == 'screen': result.update(decisions(indexed, manifest['policy']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'analyze')); parser.add_argument('manifest', type=Path); parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path); args = parser.parse_args()
    if args.action == 'collect': check(args.output is None, 'collect output is its root'); collect(args.manifest.resolve(), args.root.resolve())
    else:
        check(args.output is not None, 'analysis output required'); report = analyze(args.manifest.resolve(), args.root.resolve()); save(args.output, report)
        print(json.dumps({k: report[k] for k in ('verified', 'phase', 'cases', 'router_acceptance')}, ensure_ascii=False))


if __name__ == '__main__': main()
