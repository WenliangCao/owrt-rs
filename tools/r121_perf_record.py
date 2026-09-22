#!/usr/bin/env python3
"""Oracle-only, ACK-bracketed cpu-clock IP sampling of exact ubusd ELFs.

Usage: sudo python3 r121_perf_record.py --oracle-host-only --plan plan.json --out NEW
Plan schema (all paths absolute; sha256 values lowercase hex):
  {"schema_version": 1, "runner_sha256": "...",
   "rootfs": {"path": "/...", "libraries": {"/lib/libc.so": "...", ...}},
   "client": {"path": "/...", "sha256": "..."},
   "subjects": {"label": {"path": "/...", "sha256": "...", "kind": "static|dynamic"}},
   "runs": [{"subject": "label", "held_clients": 0, "n": 50000, "warmup": 5000}]}

No chroot, mounts, rootfs changes, router access, or daemon source changes.
Stripped subjects remain valid IP measurements, never full-symbol evidence.
The client must implement OWRT_PERF_CTL_FD/ACK_FD enable/disable acknowledgements.
musl --argv0: https://git.musl-libc.org/cgit/musl/tree/ldso/dynlink.c
perf control: https://github.com/torvalds/linux/blob/v6.17/tools/perf/Documentation/perf-record.txt
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def checked_path(value):
    path = Path(value)
    require(path.is_absolute(), f'path must be absolute: {value}')
    return path.resolve(strict=True)


def check_hash(path, expected):
    require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected),
            f'invalid SHA-256 for {path}')
    actual = sha(path)
    require(actual == expected, f'SHA-256 mismatch for {path}: {actual}')
    return actual


def stop(process, sig=signal.SIGTERM):
    """Only signal children owned by this Popen; never pkill or process groups."""
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(sig)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def pin_subject():
    os.sched_setaffinity(0, {1})


def run_saved(command, out, stem, env):
    save_json(out / f'{stem}.command.json', command)
    with (out / f'{stem}.txt').open('wb') as stdout, \
            (out / f'{stem}.stderr').open('wb') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, env=env,
                                timeout=45, check=False)
    require(result.returncode == 0, f'{stem} exited {result.returncode}')
    return (out / f'{stem}.txt').read_text(errors='replace')


def elf_info(path, out, stem, env):
    data = run_saved(['readelf', '-W', '-h', '-l', '-S', '-s', str(path)], out, stem, env)
    require(re.search(r'Machine:\s+AArch64\b', data), f'not an AArch64 ELF: {path}')
    in_symtab = False
    functions = 0
    for line in data.splitlines():
        if line.startswith('Symbol table '):
            in_symtab = "'.symtab'" in line
        fields = line.split()
        if (in_symtab and len(fields) >= 8 and fields[3] in ('FUNC', 'IFUNC')
                and fields[6] != 'UND'):
            functions += 1
    return {'path': str(path), 'sha256': sha(path),
            'interpreter_present': bool(re.search(r'^\s*INTERP\s', data, re.M)),
            'defined_symtab_functions': functions,
            'full_symbols_available': functions > 0}


def snapshot(process, out, stage, expected, subject, loader, dynamic):
    require(process.poll() is None, 'subject exited before process snapshot')
    proc = Path(f'/proc/{process.pid}')
    maps = (proc / 'maps').read_text()
    (out / f'maps-{stage}.txt').write_text(maps)
    (out / f'stat-{stage}.txt').write_text((proc / 'stat').read_text())
    (out / f'cmdline-{stage}.bin').write_bytes((proc / 'cmdline').read_bytes())
    require(os.sched_getaffinity(process.pid) == {1}, 'subject affinity changed')
    exe = loader if dynamic else subject
    check_hash(proc / 'exe', expected[exe])
    require((proc / 'exe').resolve() == exe, 'unexpected /proc/exe path')
    mapped = {}
    executable = set()
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 6 or not fields[5].startswith('/'):
            continue
        require(not fields[5].endswith(' (deleted)'), 'deleted file mapping')
        path = Path(fields[5]).resolve(strict=True)
        require(path in expected, f'unplanned mapped file: {path}')
        # A pathname alone is insufficient if a mapped file has been replaced.
        st = path.stat()
        major, minor = (int(x, 16) for x in fields[3].split(':'))
        require((st.st_ino, os.major(st.st_dev), os.minor(st.st_dev)) ==
                (int(fields[4]), major, minor), f'mapped inode changed: {path}')
        if path not in mapped:
            mapped[path] = check_hash(path, expected[path])
        if 'x' in fields[1]:
            executable.add(path)
    require(subject in executable, 'subject ELF missing from executable maps')
    if dynamic:
        require(loader in executable, 'exact loader missing from executable maps')
    else:
        require(executable == {subject}, 'static subject loaded another executable file')
    evidence = {'pid': process.pid, 'exe': str((proc / 'exe').resolve()),
                'exe_sha256': expected[exe], 'affinity': [1],
                'mapped_sha256': {str(path): digest for path, digest in mapped.items()}}
    save_json(out / f'identity-{stage}.json', evidence)
    return evidence


def summarize_samples(out, symbol_info):
    counts = Counter()
    unresolved = Counter()
    parsed = unparsed = 0
    # perf's documented misc field identifies mode; do not infer it from addresses.
    pattern = re.compile(r'^\s*([KUHGg][MESp]*)\s+([0-9a-fA-F]+)\s+(.+?)\s+\((.*)\)\s*$')
    for line in (out / 'samples.txt').read_text(errors='replace').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = pattern.match(line)
        if not match:
            unparsed += 1
            continue
        mode, ip, symbol, dso = match.groups()
        parsed += 1
        key = (mode, dso)
        counts[key] += 1
        if symbol == '[unknown]' or re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', symbol):
            unresolved[key] += 1
    report = (out / 'report.txt').read_text(errors='replace')
    lost = re.findall(r'Total Lost Samples:\s*([0-9,]+)', report)
    statistics = {}
    for name, value in re.findall(r'^\s*([A-Z_]+) events:\s*(\d+)',
                                  (out / 'stats.txt').read_text(), re.M):
        # Aggregated stats precede per-event stats: retain the first count.
        statistics.setdefault(name, int(value))
    summary = {
        'scope': 'Oracle cpu-clock self samples, user and kernel; no callgraph',
        'symbolized': False,
        'symbol_status': 'IP evidence; symbol availability and resolution are recorded separately',
        'subject_elf': symbol_info,
        'parsed_samples': parsed,
        'sample_status': 'parsed' if parsed else ('unparsed' if unparsed else 'no_samples'),
        'unparsed_lines': unparsed,
        'unresolved_samples': sum(unresolved.values()),
        'unresolved_fraction_of_parsed_samples': sum(unresolved.values()) / parsed if parsed else None,
        'total_lost_samples_reported': [int(value.replace(',', '')) for value in lost] or None,
        'perf_event_stats': statistics,
        'by_mode_dso': [
            {'mode': mode, 'dso': dso, 'samples': count,
             'unresolved_samples': unresolved[(mode, dso)],
             'unresolved_fraction': unresolved[(mode, dso)] / count}
            for (mode, dso), count in counts.most_common()
        ],
        'limitations': [
            'Stripped addresses require symbols matched to this exact ELF before function attribution.',
            'A resolved exported symbol does not establish full internal symbol coverage.',
            'No samples at an address do not establish that the code never executed.',
            'Oracle samples do not establish router performance or causality.',
        ],
    }
    save_json(out / 'sample-summary.json', summary)
    require(statistics.get('SAMPLE', 0) > 0, 'perf recorded no samples')
    for event in ('LOST', 'LOST_SAMPLES', 'THROTTLE', 'UNTHROTTLE'):
        require(statistics.get(event) == 0, f'nonzero or unavailable {event} record count')
    require(not any(int(value.replace(',', '')) for value in lost), 'report contains lost samples')


def sample(out, item, plan, subjects, client, loader, libraries, perf_path, env, symbols):
    out.mkdir()
    label = item['subject']
    subject = subjects[label]
    dynamic = plan['subjects'][label]['kind'] == 'dynamic'
    expected = {**libraries, subject: plan['subjects'][label]['sha256']}
    daemon = perf = client_process = None
    pipes = []
    meta = {'run': item, 'status': 'starting', 'client_timeout_seconds': 45,
            'perf_control': 'client enable/ACK after warmup before clocks; disable/ACK after loop and clocks',
            'argv0': '/sbin/ubusd', 'subject_sha256': expected[subject]}
    library_path = f'{plan["rootfs"]["path"]}/lib:{plan["rootfs"]["path"]}/usr/lib'
    error = None
    with tempfile.TemporaryDirectory(prefix='r121-perf-') as temporary, \
            (out / 'daemon.log').open('wb') as daemon_log, \
            (out / 'perf.stdout').open('wb') as perf_stdout, \
            (out / 'perf.stderr').open('wb') as perf_stderr, \
            (out / 'client.stderr').open('wb') as client_stderr, \
            (out / 'client.json').open('wb') as client_json:
        try:
            for path, digest in {**expected, client: plan['client']['sha256']}.items():
                check_hash(path, digest)
            socket = str(Path(temporary) / 'bus.sock')
            command = ([str(loader), '--library-path', library_path, '--argv0',
                        '/sbin/ubusd', str(subject), '-s', socket] if dynamic else
                       ['/sbin/ubusd', '-s', socket])
            executable = loader if dynamic else subject
            meta.update(daemon_command=command, daemon_executable=str(executable))
            save_json(out / 'meta.json', meta)
            daemon = subprocess.Popen(command, executable=str(executable), env=env,
                                      stdout=daemon_log, stderr=subprocess.STDOUT,
                                      preexec_fn=pin_subject)
            meta['daemon_pid'] = daemon.pid
            save_json(out / 'meta.json', meta)
            deadline = time.monotonic() + 5
            while not Path(socket).is_socket():
                require(daemon.poll() is None, 'subject exited before socket readiness')
                require(time.monotonic() < deadline, 'socket readiness timeout')
                time.sleep(0.01)
            before = snapshot(daemon, out, 'before', expected, subject, loader, dynamic)
            ctl_read, ctl_write = os.pipe()
            pipes.extend((ctl_read, ctl_write))
            ack_read, ack_write = os.pipe()
            pipes.extend((ack_read, ack_write))
            perf_command = [perf_path, 'record', '-D', '-1', '--control',
                            f'fd:{ctl_read},{ack_write}', '-e', 'cpu-clock', '-F', '499',
                            '--strict-freq', '-m', '8M', '-T', '-P',
                            '--no-buildid-cache', '-p', str(daemon.pid),
                            '-o', str(out / 'perf.data')]
            meta['perf_command'] = perf_command
            perf = subprocess.Popen(perf_command, pass_fds=(ctl_read, ack_write),
                                    stdout=perf_stdout, stderr=perf_stderr, env=env)
            meta['perf_pid'] = perf.pid
            # Close unused parent ends so a dead perf cannot be masked by the parent.
            for fd in (ctl_read, ack_write):
                os.close(fd)
                pipes.remove(fd)
            client_env = dict(env, OWRT_PERF_CTL_FD=str(ctl_write), OWRT_PERF_ACK_FD=str(ack_read))
            client_command = [str(loader), '--library-path', library_path, str(client),
                              'user-event', socket, '1', '1', str(item['n']),
                              str(item['warmup']), str(daemon.pid), str(item['held_clients'])]
            meta['client_command'] = client_command
            save_json(out / 'meta.json', meta)
            client_process = subprocess.Popen(client_command, pass_fds=(ctl_write, ack_read),
                                              env=client_env, stdout=client_json, stderr=client_stderr)
            meta['client_pid'] = client_process.pid
            save_json(out / 'meta.json', meta)
            require(client_process.wait(timeout=45) == 0, 'client failed; see client.stderr')
            require(perf.poll() is None, 'perf exited before controlled shutdown')
            stop(perf, signal.SIGINT)
            require(perf.returncode in (0, -signal.SIGINT), f'perf exited {perf.returncode}')
            after = snapshot(daemon, out, 'after', expected, subject, loader, dynamic)
            require(before['mapped_sha256'] == after['mapped_sha256'], 'subject mappings changed')
            check_hash(client, plan['client']['sha256'])
            client_json.flush()
            data = json.loads((out / 'client.json').read_text())
            for key in ('perf_controlled', 'payload_checked', 'handlers_removed', 'matched'):
                require(data.get(key) is True, f'client validation failed: {key}')
            for key, value in {'received': item['n'], 'n': item['n'], 'warmup': item['warmup'],
                               'warmup_received': item['warmup'], 'held_clients': item['held_clients'],
                               'subject_pid': daemon.pid, 'client_pid': client_process.pid,
                               'subject_cpu': 1, 'client_cpu': 0, 'listeners': 1}.items():
                require(data.get(key) == value, f'client validation mismatch: {key}')
            meta['status'] = 'recorded'
        except BaseException as exc:
            error = exc
            meta.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        finally:
            cleanup_errors = []
            for process, sig in ((client_process, signal.SIGTERM), (perf, signal.SIGINT),
                                 (daemon, signal.SIGTERM)):
                try:
                    stop(process, sig)
                except Exception as exc:
                    cleanup_errors.append(str(exc))
            for fd in pipes:
                os.close(fd)
            meta['returncodes'] = {name: proc.returncode if proc else None for name, proc in
                                   (('client', client_process), ('perf', perf), ('daemon', daemon))}
            if cleanup_errors:
                meta['cleanup_errors'] = cleanup_errors
                meta['status'] = 'failed'
                error = error or RuntimeError('child cleanup failed')
            save_json(out / 'meta.json', meta)
    # Preserve partial reports even when the client or collection failed.
    if (out / 'perf.data').exists():
        prefix = [perf_path, '--buildid-dir', str(out / 'empty-buildid-cache')]
        try:
            run_saved(prefix + ['report', '-i', str(out / 'perf.data'), '--stdio', '--header',
                                '--no-children', '--show-nr-samples', '--show-total-period',
                                '--show-cpu-utilization', '--percent-limit', '0',
                                '--sort', 'dso,symbol'], out, 'report', env)
            run_saved(prefix + ['script', '-i', str(out / 'perf.data'), '-F', 'misc,ip,sym,dso'],
                      out, 'samples', env)
            run_saved(prefix + ['script', '-i', str(out / 'perf.data'), '-F',
                                'pid,tid,misc,time,event,ip,sym,dso'], out, 'samples-detail', env)
            run_saved(prefix + ['script', '-i', str(out / 'perf.data'), '--show-lost-events',
                                '--show-mmap-events', '-F', 'misc,ip,sym,dso'], out, 'events', env)
            run_saved(prefix + ['report', '-i', str(out / 'perf.data'), '--stdio',
                                '--stats', '--no-skip-empty'], out, 'stats', env)
            summarize_samples(out, symbols[label])
        except Exception as exc:
            meta['report_error'] = f'{type(exc).__name__}: {exc}'
            error = error or exc
    else:
        error = error or RuntimeError('no perf.data produced')
    meta['status'] = 'failed' if error else 'complete'
    save_json(out / 'meta.json', meta)
    if error:
        (out / 'FAILED').write_text(f'{type(error).__name__}: {error}\n')
        raise error
    (out / 'COMPLETE').touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--oracle-host-only', action='store_true', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    # Route service/SSH termination through the same child cleanup as Ctrl-C.
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0,
            'requires root on the aarch64 Linux Oracle host')
    require(not Path('/etc/openwrt_release').exists() and
            'openwrt' not in Path('/etc/os-release').read_text().lower(), 'never run on OpenWrt')
    require({0, 1}.issubset(os.sched_getaffinity(0)), 'CPUs 0 and 1 must be available')
    plan_bytes = args.plan.read_bytes()
    plan = json.loads(plan_bytes)
    require(plan['schema_version'] == 1, 'unsupported plan schema')
    check_hash(__file__, plan['runner_sha256'])
    rootfs = checked_path(plan['rootfs']['path'])
    require(rootfs != Path('/'), 'rootfs must be an extracted reference directory')
    plan['rootfs']['path'] = str(rootfs)
    libraries = {}
    for name, digest in plan['rootfs']['libraries'].items():
        require(name.startswith('/') and '..' not in Path(name).parts, 'invalid library name')
        path = (rootfs / name.lstrip('/')).resolve(strict=True)
        require(path.is_relative_to(rootfs), f'library escapes rootfs: {name}')
        check_hash(path, digest)
        libraries[path] = digest
    loader = (rootfs / 'lib/libc.so').resolve(strict=True)
    require(loader in libraries, 'plan must hash the exact /lib/libc.so loader')
    client = checked_path(plan['client']['path'])
    check_hash(client, plan['client']['sha256'])
    subjects = {}
    for label, spec in plan['subjects'].items():
        require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', label), 'invalid subject label')
        require(spec['kind'] in ('static', 'dynamic'), 'invalid subject kind')
        subjects[label] = checked_path(spec['path'])
        check_hash(subjects[label], spec['sha256'])
    require(plan['runs'], 'plan has no runs')
    for item in plan['runs']:
        require(item['subject'] in subjects, 'run subject missing from plan')
        for key, minimum, maximum in (('held_clients', 0, 64), ('n', 1, 1000000),
                                      ('warmup', 0, 100000)):
            require(type(item[key]) is int and minimum <= item[key] <= maximum,
                    f'invalid run {key}')
    perf_path = shutil.which('perf')
    require(perf_path and shutil.which('readelf'), 'perf and readelf are required')
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('LD_', 'OWRT_PERF_'))}
    env.update(LC_ALL='C', PERF_CONFIG='/dev/null', PERF_CONFIG_NOSYSTEM='1', DEBUGINFOD_URLS='')
    args.out = args.out.absolute()
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'plan.json').write_bytes(plan_bytes)
    save_json(args.out / 'host.json', {
        'machine': platform.machine(), 'kernel': platform.release(),
        'perf_path': perf_path, 'perf_sha256': sha(perf_path),
        'runner_sha256': sha(__file__), 'plan_sha256': hashlib.sha256(plan_bytes).hexdigest(),
        'scope': 'Oracle diagnostic only; no physical router actions',
    })
    try:
        run_saved([perf_path, 'version'], args.out, 'perf-version', env)
        symbols = {}
        for label, path in subjects.items():
            info = elf_info(path, args.out, f'elf-{label}', env)
            require(info['interpreter_present'] == (plan['subjects'][label]['kind'] == 'dynamic'),
                    f'ELF launch kind mismatch: {label}')
            symbols[label] = info
        save_json(args.out / 'symbols.json', symbols)
        for index, item in enumerate(plan['runs'], 1):
            label = item['subject']
            held = item['held_clients']
            print(f'START {index}/{len(plan["runs"])} {label} held={held} n={item["n"]}', flush=True)
            sample(args.out / f'{index:03d}-{label}-{held}', item, plan, subjects, client,
                   loader, libraries, perf_path, env, symbols)
    except BaseException as exc:
        (args.out / 'FAILED').write_text(f'{type(exc).__name__}: {exc}\n')
        raise
    (args.out / 'COMPLETE').touch()


if __name__ == '__main__':
    main()
