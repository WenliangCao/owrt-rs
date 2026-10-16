#!/usr/bin/env python3
"""Root-only controller for unchanged device-safe v3 measurement binaries.

Owns only /tmp/dnsmasq-perf-20261015. Never controls production. Every attempted
window and copied file is retained; failures cannot be replaced selectively.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import threading
import time

ROOT = '/tmp/dnsmasq-perf-20261015'
PRODUCTION = '8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7'
HEALTH_EVIDENCE_SHA = '8e3367d933207920b4d59f65bd4bd807002ffd0c4d9e0eea36828c9bcd868b1e'
SCENES = [
    ('udp-hit', 'udp', 'hit', 200, 5, 20, 150),
    ('udp-miss', 'udp', 'miss', 200, 5, 20, 150),
    ('udp-mixed', 'udp', 'mixed', 200, 5, 20, 150),
    ('tcp-hit', 'tcp', 'hit', 200, 5, 20, 150),
    ('tcp-miss', 'tcp', 'miss', 200, 5, 20, 150),
    ('dhcp-home6', 'dhcp', 'hit', 100, 5, 20, 6),
    ('dhcp', 'dhcp', 'hit', 100, 5, 20, 150),
    ('startup-small', 'life-startup', 7, 6, 20, 1000, 150),
    ('config-small', 'life-config', 7, 6, 20, 1000, 150),
    ('hup-small', 'life-hup', 7, 6, 20, 1000, 150),
    ('hup-large', 'life-hup', 999, 150, 20, 1000, 150),
]


def case_deadline_seconds(scene):
    return 100 if scene[1].startswith('life-') else max(100, scene[4] + scene[5] + 40)


def ssh(command, check=True, timeout=20):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                           'openwrt', command], capture_output=True, check=check,
                          timeout=timeout)


def write(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def production_identity():
    script = f'''set -eu
test "$(sha256sum /usr/sbin/dnsmasq | cut -d ' ' -f 1)" = {PRODUCTION}
for p in $(pidof dnsmasq); do
  if test "$(sha256sum /proc/$p/exe | cut -d ' ' -f 1)" = {PRODUCTION}; then
    printf '%s %s\\n' "$p" "$(awk '{{print $22}}' /proc/$p/stat)"
  fi
done'''
    rows = ssh(script).stdout.decode().splitlines()
    if len(rows) != 1:
        raise RuntimeError('exactly one live deployed daemon required')
    return list(map(int, rows[0].split()))


def stop_owned(reason):
    # Validate group ownership even if the independent guard itself has died.
    script = f'''printf '%s\\n' {shlex.quote(reason)} > {ROOT}/STOP
if test -f {ROOT}/active.group; then
  read p expected < {ROOT}/active.group
  case "$p:$expected" in *[!0-9:]*|:*) exit 2;; esac
  test "$p" -gt 1 || exit 2
  test "$(awk '{{print $22}}' /proc/$p/stat 2>/dev/null)" = "$expected" || exit 0
  test "$(awk '{{print $5}}' /proc/$p/stat 2>/dev/null)" = "$p" || exit 2
  tr '\\000' '\\n' < /proc/$p/cmdline | grep -F '{ROOT}/' > /dev/null || exit 2
  test "$(awk '{{print $22}}' /proc/$p/stat 2>/dev/null)" = "$expected" || exit 0
  kill -KILL -- -"$p"
fi'''
    ssh(script, check=False)


def archive_run(out, label):
    manifest = ssh(f'cd {ROOT}/runs/{label} && find . -type f -exec sha256sum {{}} \\;').stdout.decode()
    raw = ssh(f'tar -C {ROOT}/runs -czf - {label}', timeout=60).stdout
    (out / (label + '.tar.gz')).write_bytes(raw)
    target = out / 'runs'
    target.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
        for member in tar.getmembers():
            if member.name.startswith('/') or '..' in Path(member.name).parts or not (member.isfile() or member.isdir()):
                raise RuntimeError('unsafe archive entry')
        # The host's Python 3.9 predates tarfile extraction filters. Only copy
        # validated regular files/directories, without archive ownership/modes.
        for member in tar.getmembers():
            path = target / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(tar.extractfile(member).read())
    hashes = {}
    for line in manifest.splitlines():
        digest, name = line.split('  ', 1)
        name = name.removeprefix('./')
        if hashlib.sha256((target / label / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('copy hash mismatch: ' + name)
        hashes[name] = digest
    actual = {str(p.relative_to(target / label)) for p in (target / label).rglob('*') if p.is_file()}
    if actual != set(hashes):
        raise RuntimeError('copy manifest membership mismatch')
    write(out / (label + '.archive.json'), {'files': hashes, 'archive_sha256': hashlib.sha256(raw).hexdigest()})
    return target / label


def validate(folder, scene, expected_hash):
    errors = []
    if not (folder / 'COMPLETE').exists():
        errors.append('case did not complete')
    identities = ('elf.sha256',) + (() if scene[1].startswith('life-') else ('live.sha256',))
    for name in identities:
        if not (folder / name).exists() or (folder / name).read_text().split()[0] != expected_hash:
            errors.append(name + ' identity')
    if scene[1].startswith('life-'):
        rows = [json.loads(x) for x in (folder / 'lifecycle.jsonl').read_text().splitlines()]
        if len(rows) != 20 or not all(r['ok'] for r in rows):
            errors.append('lifecycle markers')
    else:
        load = json.loads((folder / 'client.json').read_text())
        for phase, expected in [('warmup', scene[3]*scene[4]), ('measurement', scene[3]*scene[5])]:
            counts = load[phase]
            if any(counts[k] for k in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped')):
                errors.append(phase + ' error counters')
            if any(counts[k] != expected for k in ('scheduled', 'sent', 'correct')):
                errors.append(phase + ' completion count')
        if load['interrupted'] or load['output_failed']:
            errors.append('load interrupted/output failed')
        up = json.loads((folder / 'upstream.json').read_text())
        if up['delay_queue_dropped'] or up['total']['requests'] != up['total']['replies'] or any(up['total'][k] for k in ('invalid_queries','dropped_requests','disabled_requests')):
            errors.append('upstream completeness')
        if scene[1] == 'dhcp':
            n = scene[6]
            if load['warmup']['dora_correct'] != n or load['measurement']['dora_correct'] or load['measurement']['renew_correct'] != 2000 or load['leased_clients_final'] != n:
                errors.append('DORA/renew boundary')
        elif scene[2] == 'miss' and load.get('saturation_seconds') == 0:
            # Miss has no prewarm. Client cohorts include their drained replies,
            # while upstream time buckets can cross either measurement boundary.
            expected = scene[3] * (scene[4] + scene[5])
            if (load.get('mode') != scene[1] or load.get('profile') != 'miss'
                    or (folder / 'prewarm.json').exists()
                    or any(up['phases'][phase]['requests'] for phase in ('fault', 'recovery'))
                    or up['total']['requests'] != expected):
                errors.append('upstream miss cohort count')
        elif up['phases']['steady']['requests'] != {'hit':0, 'miss':4000, 'mixed':800}[scene[2]]:
            errors.append('upstream hit/miss count')
    return errors


def external_health(out, finished, failed):
    with (out / 'external-health.jsonl').open('a') as log:
        while not finished.is_set():
            for version in (4, 6):
                p = subprocess.run(['curl', f'-{version}', '--max-time', '5', '-sS', '-o', '/dev/null',
                                    '-w', '%{http_code} %{time_total}', 'https://www.cloudflare.com/'], capture_output=True)
                row = {'epoch':time.time(), 'ip_version':version, 'exit':p.returncode,
                       'result':p.stdout.decode(), 'error':p.stderr.decode()}
                log.write(json.dumps(row) + '\n'); log.flush()
                if p.returncode or not row['result'].startswith('200 '):
                    failed.set()
                    stop_owned('external_https_failure')
                    return
            finished.wait(30)


def guard_start(pid, label, threshold):
    result = ssh(f'''set -eu
test ! -e {ROOT}/STOP
{ROOT}/device_perf_guard {ROOT} {pid} 3600 {threshold} > {ROOT}/{label}.jsonl 2> {ROOT}/{label}.stderr < /dev/null &
g=$!
echo "$g" > {ROOT}/guard.pid
printf '%s %s\\n' "$g" "$(awk '{{print $22}}' /proc/$g/stat)" > {ROOT}/guard.identity
cat {ROOT}/guard.identity
''')
    return tuple(map(int, result.stdout.split()))


def guard_check(identity):
    pid, start = identity
    return ssh(f'test ! -e {ROOT}/STOP && test "$(readlink /proc/{pid}/exe)" = {ROOT}/device_perf_guard && test "$(awk \'{{print $22}}\' /proc/{pid}/stat 2>/dev/null)" = {start} && kill -0 {pid}', check=False).returncode == 0


def guard_stop(identity):
    pid, start = identity
    ssh(f'if test "$(readlink /proc/{pid}/exe)" = {ROOT}/device_perf_guard && test "$(awk \'{{print $22}}\' /proc/{pid}/stat 2>/dev/null)" = {start}; then kill -TERM {pid}; fi', check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--prefix', default='baseline')
    parser.add_argument('--c-hash', default='097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87')
    parser.add_argument('--rust-hash', default=PRODUCTION)
    parser.add_argument('--scenes', nargs='*')
    parser.add_argument('--health-baseline', required=True, type=Path)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    # The helper also imports this module for its unchanged guard primitives.
    # Import only at execution time; its standalone baseline still pins 7c93.
    import device_health_baseline as health_evidence
    helper_sha = hashlib.sha256(Path(health_evidence.__file__).read_bytes()).hexdigest()
    if helper_sha != HEALTH_EVIDENCE_SHA:
        raise RuntimeError('health evidence helper identity differs')
    health = json.loads(args.health_baseline.read_text())
    assert health['valid'] and health['elapsed_seconds'] >= 120
    threshold = health['threshold_ms']
    assert 1 <= threshold <= 700
    if not args.prefix.replace('-', '').isalnum():
        raise ValueError('unsafe prefix')
    selected = [s for s in SCENES if not args.scenes or s[0] in args.scenes]
    if args.scenes and len(selected) != len(args.scenes):
        raise ValueError('unknown or duplicate scene')
    args.out.mkdir(parents=True, exist_ok=args.resume)
    identity = production_identity()
    run_identity = {'production_pid_start':identity, 'production_sha256':PRODUCTION,
          'comparison':{'c':args.c_hash, 'rust':args.rust_hash}, 'controller_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'health_evidence_sha256':helper_sha,
          'scenes':selected, 'threshold_ms':threshold, 'health_baseline_sha256':hashlib.sha256(args.health_baseline.read_bytes()).hexdigest()}
    results = []
    if args.resume:
        previous = json.loads((args.out / 'identity.json').read_text())
        for key in ('production_pid_start', 'comparison', 'threshold_ms', 'health_baseline_sha256',
                    'controller_sha256', 'health_evidence_sha256'):
            if previous.get(key) != run_identity[key]:
                raise RuntimeError('resume identity differs: ' + key)
        results = json.loads((args.out / 'progress.json').read_text())
        for row in results:
            archive = json.loads((args.out / (row['label'] + '.archive.json')).read_text())
            for name, digest in archive['files'].items():
                if hashlib.sha256((args.out / 'runs' / row['label'] / name).read_bytes()).hexdigest() != digest:
                    raise RuntimeError('resume evidence hash mismatch')
        write(args.out / ('resume-' + str(time.time_ns()) + '.json'), run_identity)
    else:
        write(args.out / 'identity.json', run_identity)
    completed = {row['label'] for row in results}
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=external_health, args=(args.out, finished, failed), daemon=True)
    monitor.start()
    guard = None
    label = guard_label = None
    try:
        for scene in selected:
            expected_labels = {f'{args.prefix}-{scene[0]}-r{n}-{s}' for n in range(1,6) for s in ('c','rust')}
            if expected_labels <= completed:
                continue
            # A resumed scene must never overwrite the previous guard segment.
            guard_label = f'{args.prefix}-{scene[0]}-guard-{time.time_ns()}'
            guard = guard_start(identity[0], guard_label, threshold)
            for round_number in range(1, 6):
                for side in (('c', 'rust') if round_number % 2 else ('rust', 'c')):
                    if failed.is_set() or production_identity() != identity:
                        raise RuntimeError('health or production identity changed')
                    label = f'{args.prefix}-{scene[0]}-r{round_number}-{side}'
                    if label in completed:
                        continue
                    argv = [side, label, *map(str, scene[1:])]
                    command = 'setsid /bin/sh ' + ROOT + '/group.sh ' + shlex.join(argv)
                    with (args.out / (label + '.controller.log')).open('wb') as log:
                        p = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', 'openwrt', command], stdout=log, stderr=log)
                        started = time.monotonic()
                        while p.poll() is None:
                            if failed.wait(5):
                                raise RuntimeError('external health failed')
                            if not guard_check(guard) or time.monotonic()-started > case_deadline_seconds(scene):
                                raise RuntimeError('guard unavailable or case deadline')
                        exit_code = p.returncode
                    if not guard_check(guard):
                        raise RuntimeError('guard unavailable or STOP at case completion')
                    ssh(f'rm -f {ROOT}/active.group')
                    folder = archive_run(args.out, label)
                    errors = validate(folder, scene, args.c_hash if side == 'c' else args.rust_hash)
                    if exit_code:
                        errors.append('controller exit ' + str(exit_code))
                    row = {'label':label, 'scene':scene[0], 'round':round_number, 'side':side,
                           'valid':not errors, 'errors':errors, 'epoch':time.time()}
                    results.append(row)
                    write(args.out / 'progress.json', results)
                    print(json.dumps(row), flush=True)
                    if exit_code or failed.is_set():
                        raise RuntimeError('case or health failure')
                    if row['valid']:
                        # archive_run verified every local copy before progress
                        # was committed. Retain failed windows on the device.
                        ssh('rm -rf -- ' + shlex.quote(ROOT + '/runs/' + label))
            if failed.is_set() or not guard_check(guard) or production_identity() != identity:
                raise RuntimeError('health or guard changed at scene completion')
            # All scene windows, CPU endpoints and archives are complete. Each
            # segment keeps its own immutable capture boundary, including resume.
            guard_out = args.out / guard_label
            guard_out.mkdir()
            prefix = health_evidence.capture_before_stop(guard_out, guard_label)
            guard_stop(guard); guard = None
            final_path = args.out / (guard_label + '.jsonl')
            for _ in range(10):
                final = ssh(f'cat {ROOT}/{guard_label}.jsonl').stdout
                final_path.write_bytes(final)
                if final.endswith(b'\n'):
                    rows = [json.loads(line) for line in final.splitlines()]
                    if rows and rows[-1].get('event') == 'monitor_stopped':
                        break
                time.sleep(.2)
            (args.out / (guard_label + '.stderr')).write_bytes(ssh(f'cat {ROOT}/{guard_label}.stderr').stdout)
            # The existing external monitor spans scenes. Snapshot whole lines
            # now; its complete final log is checked again after joining below.
            external_capture = (args.out / 'external-health.jsonl').read_bytes()
            (guard_out / 'external-health-capture.raw').write_bytes(external_capture)
            external_prefix = external_capture[:external_capture.rfind(b'\n') + 1]
            qualified, samples, end = health_evidence.validate_runtime_guard_evidence(
                prefix, final, [json.loads(line) for line in external_prefix.splitlines()], identity,
                (guard_out / 'pre-stop-capture.raw').read_bytes())
            write(guard_out / 'guard-verification.json', {
                'health_evidence_sha256':helper_sha,
                'qualified_samples':len(qualified), 'final_samples':len(samples),
                'final_tail_samples':len(samples)-len(qualified),
                'pre_stop_elapsed_seconds':qualified[-1]['elapsed_s'] if qualified else None,
                'final_elapsed_seconds':end['elapsed_s'],
                'final_sha256':hashlib.sha256(final).hexdigest()})
        finished.set(); monitor.join(timeout=12)
        if monitor.is_alive() or failed.is_set():
            raise RuntimeError('external health failed or did not finish')
        external = [json.loads(line) for line in (args.out / 'external-health.jsonl').read_text().splitlines()]
        if any(row['ip_version'] not in (4, 6) or row['exit'] != 0
               or not row['result'].startswith('200 ') for row in external):
            raise RuntimeError('final external health evidence failed')
        write(args.out / 'complete.json', {'complete':True, 'windows':len(results), 'valid':sum(r['valid'] for r in results)})
    except BaseException as error:
        recovery = {}
        try:
            stop_owned('controller_failed')
            if label is not None:
                if any(row['label'] == label for row in results):
                    recovery['attempt_already_archived'] = label
                else:
                    archive_run(args.out, label)
                    recovery['attempt_archived'] = label
            if guard_label is not None:
                for suffix in ('jsonl', 'stderr'):
                    (args.out / (guard_label + '.' + suffix)).write_bytes(ssh(f'cat {ROOT}/{guard_label}.{suffix}').stdout)
        except Exception as archive_error:
            recovery['archive_error'] = repr(archive_error)
        write(args.out / 'failure.json', {'error':repr(error), 'attempt':label, 'results':results, 'recovery':recovery})
        raise
    finally:
        finished.set(); monitor.join(timeout=10)
        if guard is not None:
            guard_stop(guard)


if __name__ == '__main__':
    main()
