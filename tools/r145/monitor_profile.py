#!/usr/bin/env python3
"""Freeze or collect the fixed R145 whole-invocation monitor CPU profile."""
import argparse
from collections import Counter
import contextlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r121_perf_record as old
import r121_symbolize as sym

R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
HELPER = '1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499'
check, save = old.require, old.save_json
OPTIONS = ['-e', 'cpu-clock', '-F', '499', '--strict-freq', '-m', '8M', '-T', '-P', '--sample-cpu', '--clockid', 'mono', '--no-buildid-cache']


def freeze(args):
    check(not args.plan.exists(), 'plan must be new')
    reference = json.loads(args.reference_plan.read_text())
    build = json.loads((args.symbol_build / 'results.json').read_text())
    check(build['passed'] and all(v['sha256'] == R136 for v in build['variants']), 'symbol build identity failed')
    check(build['frozen_plan_sha256'] == old.sha(args.symbol_build / 'frozen-plan.json'), 'symbol build plan changed')
    check(build['map_sha256'] == old.sha(args.symbol_build / 'symbols/r136.map'), 'map changed after build')
    for label in ('control', 'symbols'):
        old.check_hash(args.symbol_build / label / 'ubusd-rs', R136)
    plan = {'schema': 1, 'scope': 'Oracle diagnostic only; whole invocation; no latency verdict',
            'rootfs': reference['rootfs'], 'subjects': {'c': reference['subjects']['c'],
                'r136': {'path': '/home/ubuntu/r136/build-01/combined/ubusd-rs', 'sha256': R136, 'kind': 'static'}},
            'helper': {'path': '/home/ubuntu/r131-event-batch/r131-event-stress-libubus', 'sha256': HELPER},
            'perf': '/usr/lib/linux-oracle-6.17-tools-6.17.0-1020/perf', 'taskset': '/usr/bin/taskset',
            'phase_order': ['c', 'r136', 'r136', 'c'], 'invocations_per_phase': 10, 'n': 5000, 'warmup': 20,
            'perf_options': OPTIONS, 'daemon_cpu': 1, 'caller_cpu': 0, 'collector_cpus': [2, 3],
            'helper_timeout_seconds': 70, 'minimum_daemon_samples': 1000, 'optional_extension': False,
            'symbols': {'c': '/home/ubuntu/r121-symbol-profile/c-symbols',
                        'r136_sectionful': str(args.symbol_build / 'symbols/target/aarch64-unknown-linux-musl/release/ubusd-rs'),
                        'r136_map': str(args.symbol_build / 'symbols/r136.map')},
            'symbol_build_result': str(args.symbol_build / 'results.json')}
    paths = [Path(__file__), Path(old.__file__), Path(sym.__file__), args.reference_plan,
             args.symbol_build / 'results.json', args.symbol_build / 'frozen-plan.json',
             args.symbol_build / 'control/ubusd-rs', args.symbol_build / 'symbols/ubusd-rs',
             *(Path(v) for v in plan['symbols'].values()), Path(plan['perf']), Path(plan['taskset'])]
    old.check_hash(plan['symbols']['c'], reference['symbol_evidence']['c']['symbols_sha256'])
    rootfs = Path(plan['rootfs']['path'])
    plan['dynamic_symbols'] = {}
    assets = args.plan.with_suffix('.assets')
    assets.mkdir(parents=True, exist_ok=False)
    for i, (relative, digest) in enumerate(plan['rootfs']['libraries'].items()):
        path = (rootfs / relative.lstrip('/')).resolve(strict=True)
        old.check_hash(path, digest)
        text = subprocess.check_output(['readelf', '--use-dynamic', '--symbols', '-W', str(path)], text=True)
        target = assets / f'library-{i}.symbols.txt'
        target.write_text(text)
        plan['dynamic_symbols'][str(path)] = str(target)
        paths.extend((path, target))
    for item in [*plan['subjects'].values(), plan['helper']]:
        old.check_hash(item['path'], item['sha256'])
        check(os.access(item['path'], os.X_OK), 'ELF lacks executable mode')
        paths.append(Path(item['path']))
    plan['input_sha256'] = {str(p.resolve(strict=True)): old.sha(p) for p in paths}
    # Validate all ranges while freezing, before any profile can run.
    _, evidence = images(plan)
    plan['symbol_identity'] = evidence
    plan['perf_version'] = subprocess.check_output([plan['perf'], '--version'], text=True).strip()
    save(args.plan, plan)
    print(json.dumps({'plan': str(args.plan), 'sha256': old.sha(args.plan), 'symbol_identity': evidence}, indent=2))


def images(plan):
    result, evidence = {}, {}
    for label, item in plan['subjects'].items():
        elf = sym.ELF(item['path'])
        side = sym.ELF(plan['symbols']['c' if label == 'c' else 'r136_sectionful'])
        text = side.section('.text')
        check(elf.sha256 == item['sha256'] and elf.kind == side.kind, 'image kind/hash differs')
        check(elf.virtual_bytes(text.address, text.size) == side.virtual_bytes(text.address, text.size), 'symbol text differs')
        ranges = (sym.elf_function_ranges(side) if label == 'c' else
                  sym.linker_map_ranges(Path(plan['symbols']['r136_map']).read_text(), text.address, text.size))
        result[item['path']] = {'elf': elf, 'ranges': ranges}
        evidence[label] = {'elf_sha256': elf.sha256, 'sidecar_sha256': side.sha256,
                           'text_sha256': sym.sha256(elf.virtual_bytes(text.address, text.size)), 'ranges': len(ranges)}
    helper = sym.ELF(plan['helper']['path'])
    result[plan['helper']['path']] = {'elf': helper, 'ranges': sym.elf_function_ranges(helper)}
    for path, source in plan['dynamic_symbols'].items():
        elf = sym.ELF(path)
        result[path] = {'elf': elf, 'ranges': sym.dynamic_symbol_ranges(Path(source).read_text(), elf)}
    return result, evidence


def caller_snapshot(perf, out, client, loader, expected, command):
    """One live snapshot once the recorded child execs the original pinned helper."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        check(perf.poll() is None, 'caller perf exited before live identity capture')
        children = Path(f'/proc/{perf.pid}/task/{perf.pid}/children').read_text().split()
        if len(children) == 1:
            pid = int(children[0])
            proc = Path(f'/proc/{pid}')
            try:
                maps = (proc / 'maps').read_text()
                if str(client) in maps and os.sched_getaffinity(pid) == {0}:
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
        time.sleep(0.001)
    else:
        raise RuntimeError('caller executable/affinity snapshot unavailable')
    check((proc / 'exe').resolve() == loader, 'caller loader differs')
    old.check_hash(proc / 'exe', expected[loader])
    mapped = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith('/'):
            continue
        path = Path(fields[5]).resolve(strict=True)
        check(path in expected and not fields[5].endswith(' (deleted)'), 'unexpected caller mapping')
        info = path.stat()
        major, minor = (int(v, 16) for v in fields[3].split(':'))
        check((info.st_ino, os.major(info.st_dev), os.minor(info.st_dev)) == (int(fields[4]), major, minor), 'caller mapped inode differs')
        if path not in mapped:
            mapped[path] = old.check_hash(path, expected[path])
    check(client in mapped and loader in mapped, 'caller/loader mapping missing')
    (out / 'maps-before.txt').write_text(maps)
    for name in ('stat', 'status', 'cmdline'):
        (out / f'{name}-before.bin').write_bytes((proc / name).read_bytes())
    check((out / 'cmdline-before.bin').read_bytes() == b'\0'.join(v.encode() for v in command) + b'\0', 'live caller argv differs')
    save(out / 'identity-before.json', {'pid': pid, 'affinity': [0], 'exe': str(loader),
         'captured_monotonic_ns': time.monotonic_ns(),
         'mapped_sha256': {str(k): v for k, v in mapped.items()}})
    return pid


def control(write_fd, read_fd, command):
    requested = time.monotonic_ns()
    os.write(write_fd, command.encode() + b'\n')
    # perf v6.17 writes sizeof("ack\n"), including the terminating NUL.
    # Pipes may split reads; consume exactly one ACK without eating the next.
    expected = b'ack\n\0'
    reply = bytearray()
    deadline = time.monotonic() + 5
    while len(reply) < len(expected):
        remaining = deadline - time.monotonic()
        check(remaining > 0 and select.select([read_fd], [], [], remaining)[0], 'perf control ACK timed out')
        part = os.read(read_fd, len(expected) - len(reply))
        check(part, 'perf control ACK pipe closed')
        reply.extend(part)
    check(reply == expected, 'unexpected perf control ACK')
    return {'command': command, 'requested_monotonic_ns': requested,
            'ack_monotonic_ns': time.monotonic_ns(), 'ack_hex': reply.hex()}


def stop_group(process):
    # A fresh session belongs only to this caller perf and its recorded child.
    if process is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue
    process.wait(timeout=5)


def validate_helper(path, pid):
    rows = [json.loads(s) for s in path.read_text().splitlines()]
    check([r['phase'] for r in rows] == ['empty', 'registered', 'delivered', 'closed', 'RESULT'], 'helper phase list differs')
    r = rows[-1]
    expected = {'mode': 'monitor', 'n': 5000, 'warmup': 20, 'handlers': 8, 'owners': 1,
                'subject_pid': pid, 'subject_cpu': 1, 'client_cpu': 0, 'received': 40000, 'mirrored': 40000,
                'payload_bytes': 0, 'payload_target_order_sequence_checked': True,
                'handlers_removed': True, 'fd_baseline_restored': True}
    check(all(r.get(k) == v for k, v in expected.items()), 'helper result validation failed')
    check(rows[0]['fds'] == rows[3]['fds'] and rows[1]['fds'] == rows[0]['fds'] + 3, 'helper FD baseline differs')
    check(len(r['latency_ns']) == 5000 and all(type(v) is int and v > 0 for v in r['latency_ns']), 'invalid helper latency vector')
    return {k: v for k, v in r.items() if k != 'latency_ns'}


def report(plan, out, image_table, env):
    prefix = [plan['perf'], '--buildid-dir', str(out / 'empty-buildid-cache')]
    data = ['-i', str(out / 'perf.data')]
    for stem, command in (
        ('report', ['report', *data, '--stdio', '--header', '--no-children', '--show-nr-samples', '--show-total-period', '--percent-limit', '0', '--sort', 'dso,symbol']),
        ('samples', ['script', *data, '-F', 'misc,ip,sym,dso']),
        ('samples-detail', ['script', *data, '--ns', '-F', 'pid,tid,cpu,misc,time,period,event,ip,sym,dso']),
        ('events', ['script', *data, '--ns', '--show-lost-events', '--show-mmap-events', '-F', 'pid,tid,misc,time,ip,sym,dso']),
        ('stats', ['report', *data, '--stdio', '--stats', '--no-skip-empty'])):
        old.run_saved(prefix + command, out, stem, env)
    old.summarize_samples(out, {})
    identity = json.loads((out / 'identity-before.json').read_text())
    times, cpu_counts = [], Counter()
    for line in (out / 'samples-detail.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.match(r'^\s*(\d+)/(\d+)\s+\[(\d+)\]', line)
        check(match and int(match[1]) == int(match[2]) == identity['pid'], 'unexpected sample PID/TID')
        check(int(match[3]) in (0, 2, 3) if out.name.startswith('caller-') else int(match[3]) == 1, 'sample CPU outside planned process scope')
        stamp = re.search(r'\s(\d+)\.(\d{9}):\s', line)
        check(stamp, 'missing nanosecond sample timestamp')
        stamp_ns = int(stamp[1]) * 1000000000 + int(stamp[2])
        if out.name.startswith('caller-') and stamp_ns >= identity['captured_monotonic_ns']:
            check(int(match[3]) == 0, 'caller migrated after live affinity verification')
        times.append(stamp_ns)
        cpu_counts[int(match[3])] += 1
    samples = sym.parse_perf_script((out / 'samples.txt').read_text())
    check(len(times) == len(samples), 'detailed/raw sample counts differ')
    # Before the one live snapshot, taskset/host-loader mappings may overlap the
    # final helper mappings. Keep these samples in every denominator, but never
    # apply the later mappings to their user IPs, including perf's [unknown].
    pre, selected = [], []
    for sample, stamp in zip(samples, times):
        target = pre if sample.mode[0] == 'U' and stamp < identity.get('captured_monotonic_ns', 0) else selected
        target.append(sample)
    result = sym.sample_report(selected, sym.parse_proc_maps((out / 'maps-before.txt').read_text()), image_table, top=10000)
    if pre:
        result['sample_count'] += len(pre)
        result['samples_by_mode']['U'] = result['samples_by_mode'].get('U', 0) + len(pre)
        result['user_sample_count'] += len(pre)
        result['unknown_count'] += len(pre)
        result['unknown_reasons']['before_live_snapshot'] = len(pre)
        result['unknown_fraction_of_user_samples'] = result['unknown_count'] / result['user_sample_count']
        for row in result['top_functions']:
            row['fraction_of_all_samples'] = row['sample_count'] / result['sample_count']
            row['fraction_of_user_samples'] = row['sample_count'] / result['user_sample_count']
        result['top_unknown_ips'].extend({'reason': 'before_live_snapshot', 'dso': dso, 'ip': hex(ip), 'sample_count': n}
            for (dso, ip), n in Counter((s.dso, s.ip) for s in pre).most_common())
    result.update(pre_snapshot_user_samples=len(pre), sample_cpu_counts=dict(cpu_counts))
    save(out / 'symbolized.json', result)
    return result['sample_count']


def phase(plan, label, out, env):
    out.mkdir()
    subject = Path(plan['subjects'][label]['path'])
    dynamic = label == 'c'
    rootfs = Path(plan['rootfs']['path'])
    libraries = {(rootfs / p.lstrip('/')).resolve(): h for p, h in plan['rootfs']['libraries'].items()}
    loader, client = (rootfs / 'lib/libc.so').resolve(), Path(plan['helper']['path'])
    expected = {**libraries, subject: plan['subjects'][label]['sha256']}
    libargs = [str(loader), '--library-path', f'{rootfs}/lib:{rootfs}/usr/lib']
    daemon = perf = caller_perf = None
    pipes, calls = [], []
    meta = {'subject': label, 'status': 'starting', 'calls': calls, 'ack_log': []}
    with tempfile.TemporaryDirectory(prefix='r145-profile-') as temp, contextlib.ExitStack() as stack:
        def file(name):
            return stack.enter_context((out / name).open('xb'))
        try:
            socket = str(Path(temp) / 'bus.sock')
            command = libargs + ['--argv0', '/sbin/ubusd', str(subject), '-s', socket] if dynamic else ['/sbin/ubusd', '-s', socket]
            daemon = subprocess.Popen(command, executable=str(loader if dynamic else subject), env=env,
                                      stdout=file('daemon.log'), stderr=subprocess.STDOUT, preexec_fn=old.pin_subject)
            meta.update(daemon_command=command, daemon_pid=daemon.pid)
            deadline = time.monotonic() + 5
            while not Path(socket).is_socket():
                check(daemon.poll() is None and time.monotonic() < deadline, 'daemon socket unavailable')
                time.sleep(0.01)
            before = old.snapshot(daemon, out, 'before', expected, subject, loader, dynamic)
            cr, cw = os.pipe(); ar, aw = os.pipe(); pipes.extend((cr, cw, ar, aw))
            command = [plan['perf'], 'record', '-D', '-1', '--control', f'fd:{cr},{aw}', *OPTIONS, '-p', str(daemon.pid), '-o', str(out / 'perf.data')]
            perf = subprocess.Popen(command, pass_fds=(cr, aw), env=env, stdout=file('perf.stdout'), stderr=file('perf.stderr'))
            meta['daemon_perf_command'] = command
            for fd in (cr, aw):
                os.close(fd); pipes.remove(fd)
            for number in range(1, 11):
                case = out / f'caller-{number:02d}'; case.mkdir()
                helper_command = [plan['taskset'], '-c', '0', *libargs, str(client), 'event-stress', socket, 'monitor', '5000', str(daemon.pid)]
                command = [plan['perf'], 'record', *OPTIONS, '-o', str(case / 'perf.data'), '--', *helper_command]
                save(case / 'command.json', command)
                meta['ack_log'].append({'invocation': number, **control(cw, ar, 'enable')})
                save(out / 'meta.json', meta)
                with (case / 'caller.jsonl').open('xb') as stdout, (case / 'perf.stderr').open('xb') as stderr:
                    caller_perf = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                    caller_pid = caller_snapshot(caller_perf, case, client, loader, {**libraries, client: HELPER}, helper_command[3:])
                    check(caller_perf.wait(timeout=70) == 0, 'caller/perf failed')
                meta['ack_log'].append({'invocation': number, **control(cw, ar, 'disable')})
                check(not Path(f'/proc/{caller_pid}').exists(), 'caller survived perf completion')
                calls.append({'number': number, 'caller_pid': caller_pid, 'caller_perf_exit': caller_perf.returncode,
                              'result': validate_helper(case / 'caller.jsonl', daemon.pid)})
                caller_perf = None
                save(out / 'meta.json', meta)
            after = old.snapshot(daemon, out, 'after', expected, subject, loader, dynamic)
            check(before['mapped_sha256'] == after['mapped_sha256'], 'daemon mapping identity changed')
            old.stop(perf, signal.SIGINT)
            check(perf.returncode in (0, -signal.SIGINT), 'daemon perf failed')
            meta['status'] = 'recorded'
        except BaseException as error:
            meta['error'] = f'{type(error).__name__}: {error}'
            raise
        finally:
            cleanup_errors = []
            for action in (lambda: stop_group(caller_perf), lambda: old.stop(perf, signal.SIGINT), lambda: old.stop(daemon)):
                try:
                    action()
                except Exception as error:
                    cleanup_errors.append(str(error))
            for fd in pipes:
                try:
                    os.close(fd)
                except OSError as error:
                    cleanup_errors.append(str(error))
            meta['cleanup'] = {'daemon_exit': daemon.returncode if daemon else None,
                               'perf_exit': perf.returncode if perf else None,
                               'caller_perf_exit': caller_perf.returncode if caller_perf else 0, 'errors': cleanup_errors}
            save(out / 'meta.json', meta)
    check(meta['status'] == 'recorded' and not meta['cleanup']['errors'] and meta['cleanup']['daemon_exit'] in (0, -signal.SIGTERM), 'phase did not cleanly finish')
    check(not (out / 'daemon.log').read_bytes(), 'daemon logged unexpected output')
    (out / 'RECORDED').touch()


def run(args):
    check(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0, 'Oracle root only')
    check(not Path('/etc/openwrt_release').exists(), 'never run on OpenWrt')
    plan = json.loads(args.plan.read_text())
    check(plan['phase_order'] == ['c', 'r136', 'r136', 'c'] and plan['invocations_per_phase'] == 10 and plan['n'] == 5000, 'fixed budget differs')
    check(plan['perf_options'] == OPTIONS and not plan['optional_extension'], 'sampling policy differs')
    for path, digest in plan['input_sha256'].items():
        old.check_hash(path, digest)
    check(set(range(4)) <= os.sched_getaffinity(0), 'expected four CPUs unavailable')
    os.sched_setaffinity(0, {2, 3})
    image_table, identity = images(plan)
    check(identity == plan['symbol_identity'], 'symbol identity changed')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('LD_', 'OWRT_PERF_'))}
    env.update(LC_ALL='C', PERF_CONFIG='/dev/null', PERF_CONFIG_NOSYSTEM='1', DEBUGINFOD_URLS='')
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'plan.json').write_bytes(args.plan.read_bytes())
    save(args.out / 'host.json', {'kernel': platform.release(), 'plan_sha256': old.sha(args.plan),
         'collector_affinity': sorted(os.sched_getaffinity(0)), 'perf_version': plan['perf_version']})
    (args.out / 'kallsyms.txt').write_bytes(Path('/proc/kallsyms').read_bytes())
    try:
        for number, label in enumerate(plan['phase_order'], 1):
            print(f'PHASE {number}/4 {label}', flush=True)
            phase(plan, label, args.out / f'{number:02d}-{label}', env)
        summaries = []
        # All parsing/symbolization happens after the complete fixed collection.
        for number, label in enumerate(plan['phase_order'], 1):
            out = args.out / f'{number:02d}-{label}'
            count = report(plan, out, image_table, env)
            callers = [report(plan, out / f'caller-{i:02d}', image_table, env) for i in range(1, 11)]
            summaries.append({'phase': number, 'subject': label, 'daemon_samples': count,
                              'daemon_undersampled': count < 1000, 'caller_samples': callers})
        for path, digest in plan['input_sha256'].items():
            old.check_hash(path, digest)
        save(args.out / 'results.json', {'passed': True, 'phases': summaries, 'interpretation': plan['scope']})
        (args.out / 'COMPLETE').touch()
    except BaseException as error:
        (args.out / 'FAILED').write_text(f'{type(error).__name__}: {error}\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('freeze'); p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--reference-plan', type=Path, required=True); p.add_argument('--symbol-build', type=Path, required=True)
    p = sub.add_parser('run'); p.add_argument('--plan', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGHUP, interrupted)
    return freeze(args) if args.action == 'freeze' else run(args)


if __name__ == '__main__':
    main()
