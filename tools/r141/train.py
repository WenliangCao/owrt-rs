#!/usr/bin/env python3
"""Freeze or execute one eight-class Oracle PGO training set and one merge."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HOST = Path('/home/ubuntu/r141')
BUILD = HOST / 'build-generate-01'
ROOTFS = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
PROFDATA = Path('/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata')
PROFDATA_SHA = 'c7160d195180796edf7cc4c3f087f72b5425fc9ec2d9734b956a265e506f982e'
ELF_SHA = '9452594e10f36ea2008382ea513525e5bdadfa7f32bf954031f1fca36a7451c9'
CLASSES = {
    'registration': [f'register-{m}-{b}' for m in (1, 16) for b in (8, 128)],
    'lookup': [f'lookup-{n}-{k}' for n in (1, 64, 128) for k in ('exact', 'prefix', 'all')],
    'invoke': ['invoke-single'] + [f'invoke-concurrent-{i}' for i in range(1, 5)],
    'object_events': ['event-1', 'event-8', 'event-nomatch'],
    'user_events': ['user-1', 'user-8', 'user-nomatch'],
    'ownership': ['stress-grouped', 'stress-interleaved', 'stress-monitor'],
    'transport': ['fd', 'slowlookup', 'stress-slow'],
    'lifecycle': ['pathless', 'release', 'remove_reply', 'method_acl', 'monitor_lookup', 'utf8'],
}
ARTIFACTS = {
    'ubusd-rs': (BUILD / 'generate/ubusd-rs', ELF_SHA),
    'owrt-benchmark': (Path('/home/ubuntu/r134/out/owrt-benchmark'), '0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693'),
    'wireprobe': (Path('/home/ubuntu/r138/correctness-01/bin/wireprobe'), '5500effd5af3b8ac34c2be91941acd1873a997733174a0d6cc6aaeebd54723f6'),
    'user-event': (Path('/home/ubuntu/r131-latency/build-03/user-event-latency-libubus'), 'aef917bf15119f5108e963e6b2e1745b3aee74fc71b2fcf2f6a7ccf65de859f3'),
    'event-stress': (Path('/home/ubuntu/r131-event-batch/r131-event-stress-libubus'), '1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499'),
    'ns-exec': (Path('/home/ubuntu/r90-batch1/baseline/ns-exec'), 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'),
}
ISOLATED = Path('/home/ubuntu/r131-event-batch/correctness-01/probe-tools/isolated.sh')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False); stream.write('\n')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def prepare(args):
    require(not args.out.exists() and not args.results.exists(), 'new plan and result directories required')
    build = read(BUILD / 'results.json')
    require(build['passed'] is True and build['stage'] == 'generate'
            and build['frozen_plan_sha256'] == sha(BUILD / 'frozen-plan.json'), 'generate build proof invalid')
    require(read(args.smoke)['passed'] is True and read(args.smoke)['candidate_sha256'] == ELF_SHA
            and read(args.smoke)['daemon_exit'] == 0 and read(args.smoke)['profile_count'] == 1,
            'exact normal-exit profile smoke required')
    require(sha(PROFDATA) == PROFDATA_SHA, 'wrong profdata binary')
    require(all(sha(p) == h for p, h in ARTIFACTS.values()), 'training artifact changed')
    inputs = [Path(__file__), ROOT / 'tools/r141/train.sh.in', ROOT / 'docs/reviews/R141_TRAINING_PLAN.md',
              ROOT / 'tools/r134/ubusd_stress_oracle.py', BUILD / 'frozen-plan.json', BUILD / 'results.json',
              args.smoke, ISOLATED, PROFDATA, *(p for p, _ in ARTIFACTS.values())]
    libraries = [ROOTFS / p for p in ('lib/libc.so', 'lib/libubus.so.20251202',
                 'lib/libubox.so.20260213', 'lib/libgcc_s.so.1')]
    args.out.mkdir(parents=True)
    template = (ROOT / 'tools/r141/train.sh.in').read_text()
    scripts = {}
    for name in CLASSES:
        script = template.replace('@CLASS@', name).replace('@ELF_SHA@', ELF_SHA)
        subprocess.run(['sh', '-n'], input=script, text=True, check=True)
        path = args.out / f'{name}.sh'; path.write_text(script); scripts[name] = str(path)
        inputs.append(path)
    write(args.out / 'plan.json', {
        'schema': 1, 'scope': 'One generic R136 PGO training set; timing is not a selection criterion',
        'output': str(args.results), 'instrumented_sha256': ELF_SHA, 'classes': CLASSES,
        'scripts': scripts, 'input_sha256': {str(p): sha(p) for p in inputs + libraries},
        'artifacts': {name: {'path': str(p), 'sha256': h} for name, (p, h) in ARTIFACTS.items()},
        'smoke': {'path': str(args.smoke), 'sha256': sha(args.smoke), 'excluded_from_merge': True},
        'generate_build_results_sha256': sha(BUILD / 'results.json'), 'profdata_sha256': PROFDATA_SHA,
        'namespace_timeout_seconds': 120, 'instrumented_daemons_per_class': 1,
        'expected_raw_profiles': 8, 'profile_pattern': '/tmp/out/profile-%p.profraw',
        'exit_required': 0, 'merge_count': 1, 'merge_weights': 'LLVM default count sum; no weights or timing adjustment',
        'stopping': 'Any failed command, fixture, identity, abnormal daemon exit, invalid raw or merge error stops; no retries/additional samples.',
        'coverage_limits': ['No alternating duplicate ADD workload, arbitrary byte fragmentation, halfclose/lookup-delete crash fixture, daemon crash/restart or OOM injection.',
            'The eight classes have different fixed counts and internal fanout; neither equal class weight nor representative device traffic is claimed.',
            'N1 scheduling/EAGAIN/backpressure and instrumentation differ from A53; only an independent uninstrumented candidate can be timed.']})
    print(args.out / 'plan.json')


def show_profile(path, output):
    with output.open('x') as stream:
        result = subprocess.run([str(PROFDATA), 'show', '--all-functions', '--counts', str(path)],
                                stdout=stream, stderr=subprocess.PIPE, text=True)
    require(result.returncode == 0 and not result.stderr, 'profile parse failed/warned: ' + result.stderr)
    text = output.read_text()
    summary = {name: int(re.search(r'^' + re.escape(name) + r': (\d+)$', text, re.M)[1])
               for name in ('Total functions', 'Maximum function count', 'Maximum internal block count',
                            'Total number of blocks', 'Total count')}
    require(summary['Total functions'] > 0 and summary['Total count'] > 0, 'empty profile counters')
    return summary


def run(args):
    plan = read(args.plan)
    require(plan['classes'] == CLASSES and plan['instrumented_sha256'] == ELF_SHA, 'unexpected frozen training plan')
    require(all(sha(Path(p)) == h for p, h in plan['input_sha256'].items()), 'frozen training input changed')
    out = Path(plan['output']); out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(args.plan, out / 'plan.json')
    bundle = out / 'bundle'; bundle.mkdir()
    for name, info in plan['artifacts'].items(): shutil.copy2(info['path'], bundle / name)
    spec = importlib.util.spec_from_file_location('stress_validation', ROOT / 'tools/r134/ubusd_stress_oracle.py')
    validation = importlib.util.module_from_spec(spec); spec.loader.exec_module(validation)
    records = []
    try:
        for name, calls in CLASSES.items():
            folder = out / name; folder.mkdir()
            for directory in ('tools', 'raw', 'work'): (folder / directory).mkdir()
            shutil.copy2(ISOLATED, folder / 'tools/isolated.sh')
            shutil.copy2(plan['scripts'][name], folder / 'tools/workload.sh')
            command = ['sudo', '-n', 'timeout', '-k', '5', '120', 'taskset', '-c', '0,1', str(bundle / 'ns-exec'),
                '/bin/sh', str(folder / 'tools/workload.sh'), '--namespace', str(ROOTFS), str(bundle), 'ubusd', 'rs',
                str(folder / 'raw'), '1', str(folder / 'work'), str(folder / 'tools/workload.sh')]
            write(folder / 'command.json', command)
            with (folder / 'driver.log').open('x') as stream:
                code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT).returncode
            write(folder / 'driver-exit.json', {'exit': code})
            subprocess.run(['sudo', '-n', 'chown', '-R', 'ubuntu:ubuntu', str(folder / 'raw'), str(folder / 'work')], check=True)
            raw = folder / 'raw'
            require(code == 0 and (raw / 'COMPLETE').is_file(), f'{name}: incomplete/failed training')
            require({p.stem for p in raw.glob('*.exit')} == set(calls) | {'daemon'} |
                    ({'provider-1', 'provider-64', 'provider-128'} if name == 'lookup' else {'provider-1'} if name == 'invoke' else set()),
                    f'{name}: call/daemon/provider set differs')
            pid = int((raw / 'daemon.pid').read_text())
            require((raw / 'daemon.exit').read_text().strip() == '0', 'daemon did not exit normally')
            before = (raw / 'daemon-before.stat').read_text()
            after = (raw / 'daemon-after.stat').read_text()
            require(int(before.split(' ', 1)[0]) == int(after.split(' ', 1)[0]) == pid
                    and before.rsplit(') ', 1)[1].split()[19] == after.rsplit(') ', 1)[1].split()[19],
                    'daemon PID/starttime changed')
            environ = (raw / 'daemon.environ').read_bytes().split(b'\0')
            require(b'LLVM_PROFILE_FILE=/tmp/out/profile-%p.profraw' in environ, 'profile environment differs')
            require((raw / 'daemon-exe.sha256').read_text().split() == [ELF_SHA, f'/proc/{pid}/exe'], 'profile daemon identity differs')
            for call in calls:
                require((raw / f'{call}.exit').read_text().strip() == '0' and not (raw / f'{call}.stderr').read_bytes(), 'caller failed')
                stdout = (raw / f'{call}.stdout').read_text()
                if name in ('registration', 'lookup', 'invoke', 'object_events'):
                    data = json.loads(stdout); n = 250 if call.startswith('invoke-concurrent-') else 1000
                    require(data['successful'] == n and data['warmup'] == 20 and data['errors'] == 0
                            and len(data['latency_ns']) == n and data['daemon_cpu'][0]['pid'] == pid, 'benchmark counts differ')
                elif name == 'user_events':
                    data = json.loads(stdout)
                    listeners, matched = (8 if call == 'user-8' else 1), call != 'user-nomatch'
                    require(data['n'] == 1000 and data['warmup'] == 20 and data['subject_pid'] == pid
                            and data['received'] == (1000 * listeners if matched else 0)
                            and data['payload_checked'] is True and data['handlers_removed'] is True, 'native event validation failed')
                elif call.startswith('stress-'):
                    mode = call.removeprefix('stress-')
                    validation.validate(stdout, mode, 192 if mode == 'slow' else 1000, pid)
                else:
                    require(bool(stdout.strip()), 'wire fixture output missing')
                    if call == 'method_acl': require('canonical=false' not in stdout, 'ACL canonical check failed')
            profile = raw / f'profile-{pid}.profraw'
            require(list(raw.glob('*.profraw')) == [profile] and profile.stat().st_size > 0, 'raw count/PID/size differs')
            summary = show_profile(profile, folder / 'profile-show.txt')
            smoke = read(Path(plan['smoke']['path']))
            require(all(summary[k] == smoke['counters'][k] for k in ('Total functions', 'Total number of blocks')),
                    'profile schema/function set differs from same-ELF smoke')
            records.append({'class': name, 'passed': True, 'daemon_pid': pid, 'daemon_sha256': ELF_SHA,
                            'daemon_exit': 0, 'profile': str(profile), 'profile_sha256': sha(profile),
                            'profile_bytes': profile.stat().st_size, 'counters': summary})
            write(folder / 'result.json', records[-1])
        require(len(records) == 8, 'incomplete profile set')
        profile_paths = [r['profile'] for r in records]
        require(len(set(profile_paths)) == 8, 'profile reused')
        merged = out / 'merged.profdata'
        command = [str(PROFDATA), 'merge', '-o', str(merged), *profile_paths]
        write(out / 'merge-command.json', command)
        result = subprocess.run(command, capture_output=True, text=True)
        (out / 'merge.stdout').write_text(result.stdout); (out / 'merge.stderr').write_text(result.stderr)
        require(result.returncode == 0 and not result.stderr and merged.stat().st_size > 0, 'single profile merge failed/warned')
        summary = show_profile(merged, out / 'merged-show.txt')
        require(all(sha(Path(p)) == h for p, h in plan['input_sha256'].items()), 'training input changed')
        write(out / 'result.json', {'schema': 1, 'passed': True, 'frozen_plan_sha256': sha(args.plan),
            'instrumented_sha256': ELF_SHA, 'profdata_tool_sha256': PROFDATA_SHA,
            'profdata': str(merged), 'profdata_sha256': sha(merged), 'profdata_bytes': merged.stat().st_size,
            'merged_once': True, 'no_timing_selection': True, 'smoke_excluded': True,
            'profiles': records, 'merged_counters': summary})
        (out / 'COMPLETE').touch(); print('COMPLETE', sha(merged))
    except BaseException as error:
        write(out / 'failure.json', {'type': type(error).__name__, 'error': str(error), 'completed_classes': records})
        (out / 'FAILED').touch(); raise


def main():
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64'
            and not Path('/etc/openwrt_release').exists() and ROOTFS.is_dir(), 'Oracle build host only')
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    freeze = sub.add_parser('prepare')
    freeze.add_argument('--out', type=Path, required=True)
    freeze.add_argument('--results', type=Path, required=True)
    freeze.add_argument('--smoke', type=Path, required=True)
    execute = sub.add_parser('run'); execute.add_argument('plan', type=Path)
    args = parser.parse_args()
    prepare(args) if args.command == 'prepare' else run(args)


if __name__ == '__main__': main()
