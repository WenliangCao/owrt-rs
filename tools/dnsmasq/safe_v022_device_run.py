#!/usr/bin/env python3
"""Frozen v0.2.2 isolated batch. Default dry-run never accesses a device.

Execution imports the archived functions, not their historical main/prepare.
The separate shared qualification gate must pass before the first SSH call.
"""
import argparse
import importlib
import itertools
import json
from pathlib import Path
import re
import shlex
import statistics
import struct
import subprocess
import sys
import threading
import time

import safe_v022_device_plan as plan_tool


GROUPS = {'safe_v022_group.sh', 'safe_v022_startup_group.sh'}
LABEL = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*')


def load_plan(path, bundle):
    value = json.loads(path.read_text())
    if value != plan_tool.make_plan(value['prefix'], bundle,
                                    short=value.get('scope') == 'short-safety-regression'):
        raise ValueError('plan differs from the frozen local schedule/tool/bundle')
    return value


def bind_modules(bundle):
    plan_tool.verify_bundle(bundle)
    directory = (bundle / 'modules').resolve()
    sys.path.insert(0, str(directory))
    names = ('perf_opt_device_run', 'perf_opt_analyze', 'research_device_run',
             'research_full_analyze', 'udp_stage_device_run', 'device_health_baseline')
    modules = {}
    for name in names:
        module = importlib.import_module(name)
        if Path(module.__file__).resolve() != directory / (name + '.py'):
            raise ValueError('unexpected imported module: ' + name)
        modules[name] = module
    modules['perf_opt_device_run'].ROOT = plan_tool.ROOT
    modules['perf_opt_device_run'].PRODUCTION = plan_tool.K_SHA256
    return modules


def current_boot(run):
    value = run.ssh('cat /proc/sys/kernel/random/boot_id').stdout.decode().strip()
    if not re.fullmatch(r'[0-9a-f-]{36}', value):
        raise RuntimeError('invalid boot identity')
    return value


def check_live(ctx):
    run = ctx['run']
    if (ctx['failed'].is_set() or run.production_identity() != ctx['identity']
            or current_boot(run) != ctx['boot']):
        raise RuntimeError('production/boot/external health changed')
    if ctx.get('guard') is not None and not run.guard_check(ctx['guard']):
        raise RuntimeError('independent guard unavailable or stopped')


def stage_files(ctx, qualification, labels):
    """Stage immutable files before baseline, only after shared qualification."""
    run = ctx['run']; root = run.ROOT
    run.ssh(f'''set -eu
test ! -L {root}
if test ! -e {root}; then mkdir -m 700 {root}; fi
# Exact stock BusyBox has ls but no stat applet. The fixed task path has no
# whitespace; numeric ls metadata preserves the same root/0700 checks.
set -- $(ls -ldn {root})
test "$1" = drwx------
test "$3" = 0
test ! -e {root}/STOP
test ! -e {root}/active.group
test ! -L {root}/runs
mkdir -p {root}/runs
for p in /proc/[0-9]*/exe; do
  case "$(readlink "$p" 2>/dev/null || :)" in {root}/*) exit 2;; esac
done
''')
    ctx['owns_root'] = True
    files = dict(qualification['files'])
    for row in qualification['artifacts'].values():
        files[row['name']] = row
    for name, row in files.items():
        if name in ('.', '..') or not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
            raise ValueError('unsafe remote filename')
        local = Path(row['local'])
        if local.is_symlink() or plan_tool.digest(local) != row['sha256'] or local.stat().st_size != row['bytes']:
            raise ValueError('qualified local artifact changed: ' + name)
        destination = root + '/' + name
        command = f'''set -eu
test ! -L {destination}
if test -e {destination}; then
  test "$(sha256sum {destination} | cut -d ' ' -f 1)" = {row['sha256']}
else
  test ! -e {destination}.new
  cat > {destination}.new
  test "$(sha256sum {destination}.new | cut -d ' ' -f 1)" = {row['sha256']}
  chmod 755 {destination}.new
  mv {destination}.new {destination}
fi'''
        subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', 'openwrt', command],
                       input=local.read_bytes(), check=True, capture_output=True, timeout=30)
    ctx['shared'].verify_files({name: row['sha256'] for name, row in files.items()})
    # Hundreds of exact labels exceed the stock SSH command-length boundary.
    # Keep every absence check, but carry the script on stdin.
    checks = 'set -eu\n' + '\n'.join(f'test ! -e {root}/runs/{label}' for label in labels)
    subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                    'openwrt', '/bin/sh -s'], input=checks.encode(),
                   check=True, capture_output=True, timeout=20)
    ctx['shared'].set_slots(qualification['artifacts'], 'k', 'k')
    check_live(ctx)
    run.write(ctx['out'] / 'staging.json', {'files': files, 'labels_checked': labels,
              'production': ctx['identity'], 'boot': ctx['boot']})


def execute_owned_group(ctx, label, group_name, argv, deadline_seconds):
    """Shared traffic/startup boundary. Return (archived_folder, exit_code).

    Requires run/out/identity/boot/guard/failed/research/archived in ctx.
    Never prunes raw. An attempted window is archived even after health failure.
    """
    if not LABEL.fullmatch(label) or group_name not in GROUPS or deadline_seconds <= 0:
        raise ValueError('invalid owned group request')
    run = ctx['run']; out = ctx['out']; process = None; error = None; folder = None
    check_live(ctx)
    run.ssh(f'test ! -e {run.ROOT}/runs/{label} && test ! -e {run.ROOT}/active.group')
    command = 'setsid /bin/sh ' + run.ROOT + '/' + group_name + ' ' + shlex.join(argv)
    run.write(out / (label + '.attempt.json'), {'label': label, 'argv': argv,
              'group': group_name, 'deadline_seconds': deadline_seconds, 'epoch': time.time()})
    try:
        with (out / (label + '.controller.log')).open('xb') as log:
            process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                                        'openwrt', command], stdout=log, stderr=log)
            started = time.monotonic()
            while process.poll() is None:
                if (ctx['failed'].wait(5) or not run.guard_check(ctx['guard'])
                        or time.monotonic() - started > deadline_seconds):
                    raise RuntimeError('health/guard/case deadline')
        check_live(ctx)
    except BaseException as caught:
        error = caught
        try:
            run.stop_owned('v022_owned_group_failed')
        except Exception as stop_error:
            run.write(out / (label + '.stop-failure.json'), {'error': repr(stop_error)})
    finally:
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()  # Host SSH client; remote owned group was stopped above.
                process.wait(timeout=5)
        try:
            folder = run.archive_run(out, label)
            ctx['archived'].add(label)
        except Exception as archive_error:
            run.write(out / (label + '.archive-failure.json'), {'error': repr(archive_error)})
            if error is None:
                error = archive_error
    if error is not None:
        run.write(out / (label + '.failure.json'), {'error': repr(error), 'archived': folder is not None})
        raise error
    ctx['research'].clear_exited_group()
    return folder, process.returncode


def dual_errors(folder):
    """Original 534a6fc7 dual predicates; the underlying comparator is unchanged."""
    errors = []; warmers = []
    try:
        for prefix, qtype, code in [('prewarm-a', 'a', 1), ('prewarm', 'aaaa', 28)]:
            data = json.loads((folder / (prefix + '.json')).read_text()); warmers.append(data)
            counts = data['measurement']; first_sequence = (data['seed'] << 32) + 1
            records = list(struct.iter_unpack('<QQQHHBBBB', (folder / (prefix + '.latencies.bin')).read_bytes()))
            if (data['mode'] != 'udp' or data['profile'] != 'hit' or data['qtype'] != qtype
                    or data['name_prefix'] != 'm6a.example' or data['seed'] != 0x293001
                    or data['rate'] != 200 or data['warmup_seconds'] != 0 or data['measurement_seconds'] != 5
                    or data['interrupted'] or data['output_failed']
                    or any(counts[k] != 1000 for k in ('scheduled', 'sent', 'correct'))
                    or any(counts[k] for k in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
                    or len(records) != 1000 or {row[0] for row in records} != set(range(first_sequence, first_sequence + 1000))
                    or any(row[4:] != (code, 0, 1, 0, 0) for row in records)):
                errors.append(prefix + ' dual-family prewarm')
        load = json.loads((folder / 'client.json').read_text())
        up = json.loads((folder / 'upstream.json').read_text())
        if (load['qtype'] != 'aaaa30' or load['name_prefix'] != 'm6a.example' or load['seed'] != 0x293001
                or not (warmers[0]['run_end_ns'] <= warmers[1]['warmup_start_ns']
                        and warmers[1]['run_end_ns'] <= load['warmup_start_ns'])
                or load['run_end_ns'] - warmers[0]['warmup_start_ns'] >= 120_000_000_000):
            errors.append('dual-family fixture identity or freshness')
        if (up['ttl'] != 120 or up['total']['requests'] != 800 or up['total']['replies'] != 800
                or up['phases']['setup_warmup']['requests'] != 800
                or any(up['phases'][phase]['requests'] for phase in ('steady', 'saturation', 'fault', 'recovery'))):
            errors.append('dual-family exact 800 fills and pure hit')
    except (OSError, ValueError, KeyError, struct.error) as error:
        errors.append('dual-family fixture records: ' + str(error))
    return errors


def measure_window(ctx, window, folder, exit_code, qualification):
    run = ctx['run']; analyze = ctx['analyze']; scene = tuple(window['scene'])
    artifact = qualification['artifacts'][window['artifact']]
    measurement = None; errors = []
    try:
        short_startup = ctx.get('short') and scene[1] == 'life-startup'
        if short_startup:
            if not (folder / 'COMPLETE').is_file():
                errors.append('case did not complete')
            if (folder / 'elf.sha256').read_text().split()[0] != artifact['sha256']:
                errors.append('elf.sha256 identity')
        else:
            errors.extend(run.validate(folder, scene, artifact['sha256']))
        if exit_code:
            errors.append('case exit ' + str(exit_code))
        if window['case_kind'] == 'dual':
            errors.extend(dual_errors(folder))
        expected_tools = {'m6a_loadgen', 'device_perf_resource_probe', 'device_perf_lifecycle',
                          f"safe_v022_{window['case_kind']}_case.sh", 'safe_v022_group.sh', 'research_cpu_clock_probe',
                          'm6a_upstream_mixed_cohort' if scene[1:3] == ('udp', 'mixed') else 'm6a_upstream'}
        actual_tools = {}
        for line in (folder / 'tools.sha256').read_text().splitlines():
            digest, path = line.split(None, 1); actual_tools[path.strip()] = digest
        expected = {run.ROOT + '/' + name: qualification['files'][name]['sha256'] for name in expected_tools}
        if actual_tools != expected:
            errors.append('actual measurement tool identities')
        if short_startup:
            values = analyze.json_lines(folder / 'lifecycle.jsonl')
            if (len(values) != 5 or [v['index'] for v in values] != list(range(5)) or
                    any(not v['ok'] or v['mode'] != 'startup' or v['hosts'] != 8 or
                        v['initial_leases'] != 6 or v['threads'] != 1 or
                        v['visible_ns'] - v['start_ns'] != v['latency_ns'] for v in values)):
                raise ValueError('five-start workload/count/readiness differs')
            cpu, hz = map(int, re.search(r'children_cpu_usec=(\d+) clk_tck=(\d+)',
                                         (folder / 'lifecycle.stderr').read_text()).groups())
            measurement = {'latency_ms': analyze.quantiles([v['latency_ns'] / 1e6 for v in values]),
                           'startup_ready_ms': [v['latency_ns'] / 1e6 for v in values],
                           'cpu_ticks': cpu / 1e6 * hz, 'cpu_hz': hz, 'cpu_operations': 5,
                           'cpu_us_per_operation': cpu / 5,
                           'cpu_scope': 'whole five-start RUSAGE_CHILDREN; descriptive, one block per version',
                           'tree_fd_peak': max(v['fds'] for v in values),
                           'parent_fd_peak': max(v['fds'] for v in values),
                           'rss_peak_kib': max(v['rss_kib'] for v in values)}
        elif scene[1].startswith('life-'):
            measurement = analyze.lifecycle(folder, {'valid': not errors})
        else:
            if (folder / 'netns.txt').read_bytes() != (folder / 'daemon.netns').read_bytes():
                errors.append('daemon namespace differs')
            if int((folder / 'observer.exit').read_text()) not in (0, 1):
                errors.append('observer did not finish normally')
            if not (folder / 'resources.jsonl').stat().st_size or (folder / 'resources.stderr').stat().st_size:
                errors.append('observer output missing or stderr nonempty')
            resources = analyze.json_lines(folder / 'resources.jsonl')
            observer = (int((folder / 'observer.pid').read_text()), int((folder / 'observer.starttime').read_text()))
            args = [int(v) for v in (folder / 'observer.args').read_text().split()]
            daemon = int((folder / 'actual.pid').read_text())
            if (len(args) != 4 or args[:2] != [daemon, scene[4] + scene[5] + 5]
                    or any(v <= 0 for v in args)
                    or any((r['observer_self_cpu']['pid'], r['observer_self_cpu']['starttime_ticks']) != observer for r in resources)
                    or any([p['pid'] for p in r['helper_self_cpu']] != args[2:] for r in resources)):
                errors.append('observer/helper identity evidence')
            measurement = analyze.traffic(folder, {'valid': not errors}, scene[4], scene[5])
            if scene[1] == 'udp':
                clock = ctx['research'].clock_measurement(folder, measurement)
                measurement['cpu_clock'] = clock
                if not clock['valid']:
                    errors.extend(clock['errors'])
                resolution = max(clock[key]['clock']['reported_resolution_ns'] for key in ('before', 'after'))
                measurement['clock_endpoint_resolution_us_per_op'] = 2 * resolution / 1000 / measurement['cpu_operations']
                if measurement['clock_endpoint_resolution_us_per_op'] > 5 / 3:
                    errors.append('CPU-clock reported resolution exceeds instrument gate')
        if measurement['cpu_operations'] != window['cpu_operations']:
            # Exact counts already fail original validate. Keep only its classified
            # scheduled-skipped errors eligible for one symmetric replacement.
            if scene[1].startswith('life-') or not any(measurement['counts'][p]['scheduled_skipped'] for p in ('warmup', 'measurement')):
                errors.append('CPU operation denominator')
    except (OSError, ValueError, KeyError, TypeError, AssertionError, IndexError, ArithmeticError) as error:
        errors.append('measurement evidence: ' + repr(error))
    tool_invalid = (exit_code == 0 and measurement is not None
                    and ctx['research'].tool_invalid(folder, errors))
    return {**window, 'valid': not errors, 'errors': errors, 'tool_invalid': tool_invalid,
            'case_exit': exit_code, 'elf_sha256': artifact['sha256'], 'measurement': measurement}


def selected_pairs(rows):
    selected = []
    for number in sorted({row['round'] for row in rows}):
        pair = [row for row in rows if row['round'] == number]
        attempt = max(row.get('attempt', 0) for row in pair)
        sides = {row['side']: row for row in pair if row.get('attempt', 0) == attempt}
        if set(sides) != {'c', 'rust'} or not all(row['valid'] for row in sides.values()):
            raise RuntimeError('incomplete valid selected pair')
        selected.append((sides['c'], sides['rust']))
    return selected


def assess(ctx, group, rows, noise, qualification):
    pairs = selected_pairs(rows); analyze = ctx['analyze']; count = len(pairs)
    left, right = [[pair[side]['measurement'] for pair in pairs] for side in (0, 1)]
    scene = rows[0]['scene']; calibration = rows[0]['stage'] == 'calibration'
    if ctx.get('short') and scene[1] == 'life-startup':
        if count != 1:
            raise RuntimeError('short startup requires one five-start block per version')
        a, b = left[0], right[0]
        latency = analyze.compare(a['startup_ready_ms'], b['startup_ready_ms'], resolution=1)
        reasons = ['startup readiness regression'] if latency['direction'] == 'slower' else []
        if b['parent_fd_peak'] > a['parent_fd_peak']:
            reasons.append('startup FD growth')
        return {'starts': 10, 'latency_ms': latency, 'blocks': {'k': a, 'candidate': b},
                'stop_reasons': reasons, 'extend_mixed': False,
                'scope': 'Original startup-small, five starts per version; CPU descriptive, 1ms readiness floor.'}
    metrics = {key + '_ms': analyze.compare([r['latency_ms'][key] for r in left],
               [r['latency_ms'][key] for r in right], resolution=1 if scene[1].startswith('life-') else 0)
               for key in ('p50', 'p95')}
    metrics['cpu_us'] = analyze.compare([r['cpu_us_per_operation'] for r in left],
        [r['cpu_us_per_operation'] for r in right],
        cpu=([r['cpu_ticks'] for r in left], [r['cpu_ticks'] for r in right]))
    if ctx.get('short'):
        if count != 3:
            raise RuntimeError('short regression requires three complete pairs')
        for key, metric in metrics.items():
            # The historical comparator requires four directions out of five;
            # a three-pair check must not silently make regression impossible.
            precision = metric['precision_ok']
            if key == 'cpu_us':
                precision = (min(r['cpu_ticks'] for r in left + right) >= 10 and
                             abs(statistics.median(r['cpu_ticks'] for r in right) -
                                 statistics.median(r['cpu_ticks'] for r in left)) > 2)
            discernible = (abs(metric['relative_change_pct']) > metric['W_pct'] and
                           metric['same_direction_pairs'] == count and precision)
            metric.update(direction_pairs_required=count, precision_ok=precision,
                          discernible=discernible,
                          direction=('slower' if metric['relative_change_pct'] > 0 else 'faster')
                          if discernible else 'within_variation_or_resolution')
    if count == 9:
        for metric in metrics.values():
            metric['direction_pairs_required'] = 8
            metric['discernible'] = metric['discernible'] and metric['same_direction_pairs'] >= 8
            if not metric['discernible']:
                metric['direction'] = 'within_variation_or_resolution'
    result = {'pairs': count, 'original_primary_metrics': metrics, 'stop_reasons': [], 'extend_mixed': False}
    if not calibration:
        result['stop_reasons'] += [key + ' legacy regression' for key, value in metrics.items()
                                   if value['direction'] == 'slower']
        for key in ('tree_fd_peak', 'parent_fd_peak'):
            change = max(r[key] for r in right) - max(r[key] for r in left)
            allowed = qualification.get('fd_growth_limits', {}).get(group, {}).get(key, 0)
            if change > allowed:
                result['stop_reasons'].append(key + ' exceeds bound growth')
    if scene[1] == 'udp':
        deltas = [b['cpu_clock']['cpu_us_per_operation'] - a['cpu_clock']['cpu_us_per_operation']
                  for a, b in zip(left, right)]
        result['cpu_clock_pair_differences_us'] = deltas
        result['cpu_clock_summary'] = analyze.spread(deltas)
        resolution = max(r['clock_endpoint_resolution_us_per_op'] for r in left + right)
        if calibration:
            result['AA_max_absolute_pair_cpu_us'] = max(map(abs, deltas))
            if result['AA_max_absolute_pair_cpu_us'] >= 4:
                result['stop_reasons'].append('AA noise >=4us; instrument review required')
        else:
            median = statistics.median(deltas)
            aa = noise.get({'full-udp-hit': 'ordinary-aa', 'full-udp-mixed': 'mixed-aa',
                            'dual-confirm': 'dual-aa'}.get(group))
            if count == 9:
                result['d2_d8_us'] = [sorted(deltas)[1], sorted(deltas)[7]]
                chronological = sorted(pairs, key=lambda pair: max(row['execution_index'] for row in pair))
                ordered = [b['measurement']['cpu_clock']['cpu_us_per_operation'] - a['measurement']['cpu_clock']['cpu_us_per_operation']
                           for a, b in chronological]
                result['block_round_order'] = [pair[0]['round'] for pair in chronological]
                result['three_block_medians_us'] = [statistics.median(ordered[i:i + 3]) for i in (0, 3, 6)]
                if aa is not None and result['d2_d8_us'][0] > max(aa, resolution) and all(v > 0 for v in result['three_block_medians_us']):
                    result['stop_reasons'].append('nine-pair CPU-clock regression')
            if median >= 5:
                result['stop_reasons'].append('adverse CPU median >=5us; model review required')
            if ctx.get('short'):
                floor = max(max(r['cpu_clock']['cpu_us_per_operation'] for r in side) -
                            min(r['cpu_clock']['cpu_us_per_operation'] for r in side)
                            for side in (left, right))
                result['within_version_cpu_range_us'] = floor
                if all(v > 0 for v in deltas) and median > max(floor, resolution):
                    result['stop_reasons'].append('three-pair consistent CPU regression')
            if count == 5 and aa is not None and all(v > 0 for v in deltas) and median > max(aa, resolution):
                if group == 'full-udp-mixed' and median < 5 and not result['stop_reasons']:
                    result['extend_mixed'] = True
                else:
                    result['stop_reasons'].append('five-pair consistent CPU regression')
    return result


def begin_guard(ctx, name, threshold):
    check_live(ctx)
    label = name + '-guard-' + str(time.time_ns())
    ctx['guard'] = ctx['run'].guard_start(ctx['identity'][0], label, threshold)
    ctx['guard_label'] = label
    return label


def end_guard(ctx, baseline=False):
    run = ctx['run']; health = ctx['health']; label = ctx['guard_label']
    destination = ctx['out'] / label; destination.mkdir()
    capture_error = None
    try:
        prefix = health.capture_before_stop(destination, label)
    except Exception as error:
        capture_error = error
    finally:
        run.guard_stop(ctx['guard'])
        ctx['guard'] = None
    final = b''
    # Original bounded guard termination observation; retain its unchanged tail.
    for _ in range(10):
        final = run.ssh(f'cat {run.ROOT}/{label}.jsonl').stdout
        (destination / 'guard.jsonl').write_bytes(final)
        if final.endswith(b'\n') and json.loads(final.splitlines()[-1]).get('event') == 'monitor_stopped':
            break
        time.sleep(.2)
    (destination / 'guard.stderr').write_bytes(run.ssh(f'cat {run.ROOT}/{label}.stderr').stdout)
    if capture_error is not None:
        run.write(destination / 'capture-failure.json', {'error': repr(capture_error)})
        raise capture_error
    external_capture = (ctx['out'] / 'external-health.jsonl').read_bytes()
    (destination / 'external-health-capture.raw').write_bytes(external_capture)
    external = [json.loads(line) for line in health.complete_prefix(external_capture).splitlines()]
    capture = (destination / 'pre-stop-capture.raw').read_bytes()
    if baseline:
        result = health.validate_baseline(prefix, final, external, ctx['identity'], capture)
    else:
        qualified, samples, end = health.validate_runtime_guard_evidence(prefix, final, external, ctx['identity'], capture)
        result = {'qualified_samples': len(qualified), 'samples': len(samples), 'end': end}
    samples = [row for row in map(json.loads, final.splitlines()) if row.get('event') == 'sample']
    result['minimum_memory_kib'] = min(row['mem_available_kib'] for row in samples)
    run.write(destination / 'verification.json', result)
    return result


def extension_windows(plan):
    if plan.get('scope') == 'short-safety-regression':
        return []
    template = next(row for row in plan['schedule'] if row['group'] == 'full-udp-mixed')
    rows = []
    for number in range(6, 10):
        for side in (('c', 'rust') if number % 2 else ('rust', 'c')):
            label = f"{plan['prefix']}-full-udp-mixed-r{number}-{side}"
            rows.append({**template, 'round': number, 'side': side, 'artifact': 'k' if side == 'c' else 'candidate',
                         'label': label, 'group_argv': ['full', side, label, *map(str, template['scene'][1:])]})
    if [row['label'] for row in rows] != plan['conditional_mixed_extension']['labels']:
        raise ValueError('mixed extension labels differ')
    return rows


def execute(plan, bundle, qualification, out, startup_runner):
    modules = bind_modules(bundle); run = modules['perf_opt_device_run']
    out.mkdir(parents=True, exist_ok=False)
    ctx = {'out': out, 'run': run, 'analyze': modules['perf_opt_analyze'],
           'research': modules['research_device_run'], 'shared': modules['udp_stage_device_run'],
           'health': modules['device_health_baseline'], 'guard': None, 'owns_root': False,
           'failed': threading.Event(), 'archived': set()}
    ctx['short'] = plan.get('scope') == 'short-safety-regression'
    ctx['identity'] = run.production_identity(); ctx['boot'] = current_boot(run)
    run.write(out / 'launch.json', {'plan': plan, 'qualification': qualification,
              'driver_sha256': plan_tool.digest(Path(__file__)), 'production_pid_start': ctx['identity'], 'boot': ctx['boot']})
    extensions = extension_windows(plan)
    all_labels = [row['label'] for row in plan['schedule'] + extensions]
    all_labels += [label + '-repeat1' for label in all_labels]
    if not ctx['short']:
        all_labels += startup_runner.labels(plan['prefix'])
    finished = threading.Event(); rows = []; results = {}; noise = {}; cleanup = []
    monitor = threading.Thread(target=run.external_health, args=(out, finished, ctx['failed']), daemon=True)
    try:
        stage_files(ctx, qualification, all_labels)
        monitor.start(); begin_guard(ctx, plan['prefix'] + '-baseline', 200)
        started = time.monotonic()
        while time.monotonic() - started < 125:
            if ctx['failed'].wait(5):
                raise RuntimeError('baseline external health failed')
            check_live(ctx)
        baseline = end_guard(ctx, baseline=True)
        if baseline['minimum_memory_kib'] < 90112:
            raise RuntimeError('baseline below 88MiB entry margin')
        run.write(out / 'baseline.json', baseline)
        # The new exec boundary is the largest remaining uncertainty. Collect
        # its fixed40 starts before spending time on the traffic matrix.
        supplement = {'scope': 'short startup-small is included in the main schedule'}
        if not ctx['short']:
            begin_guard(ctx, plan['prefix'] + '-startup-supplement', baseline['threshold_ms'])
            supplement = startup_runner.execute_supplement(ctx, qualification)
            run.write(out / 'startup-supplement.json', supplement)
            end_guard(ctx); check_live(ctx)
        for group, iterator in itertools.groupby(plan['schedule'], key=lambda row: row['group']):
            original = list(iterator); queue = list(original); pending = set(); group_rows = []; at = 0; extended = False
            begin_guard(ctx, plan['prefix'] + '-' + group, baseline['threshold_ms'])
            ctx['shared'].set_slots(qualification['artifacts'], original[0]['left'], original[0]['right'])
            while at < len(queue):
                window = queue[at]; at += 1
                folder, code = execute_owned_group(ctx, window['label'], 'safe_v022_group.sh', window['group_argv'], window['deadline_seconds'])
                row = measure_window(ctx, window, folder, code, qualification)
                row['execution_index'] = len(rows) + 1
                rows.append(row); group_rows.append(row); run.write(out / 'progress.json', rows)
                print(json.dumps({'windows': len(rows), 'label': row['label'], 'valid': row['valid']}), flush=True)
                if not row['valid'] and (not row['tool_invalid'] or row.get('attempt', 0)):
                    raise RuntimeError('invalid window retained; no automatic retry')
                if row['tool_invalid']:
                    pending.add(row['round'])
                if row['valid']:
                    # archive_run verified every local file; progress is already durable.
                    run.ssh('rm -rf -- ' + shlex.quote(run.ROOT + '/runs/' + row['label']))
                if at == len(original):
                    for previous in original:
                        if previous['round'] in pending:
                            label = previous['label'] + '-repeat1'; argv = list(previous['group_argv']); argv[2] = label
                            queue.append({**previous, 'label': label, 'group_argv': argv, 'attempt': 1})
                if at == len(queue):
                    result = assess(ctx, group, group_rows, noise, qualification)
                    results[group] = result; run.write(out / 'comparisons.json', results)
                    if result['stop_reasons']:
                        raise RuntimeError('stop for review: ' + '; '.join(result['stop_reasons']))
                    if result['extend_mixed'] and not extended:
                        queue.extend(extensions); extended = True
                    elif original[0]['stage'] == 'calibration':
                        noise[group] = result['AA_max_absolute_pair_cpu_us']
            end_guard(ctx)
        check_live(ctx)
        run.write(out / 'collected.json', {'windows': len(rows), 'selected_groups': results,
                  'startup_supplement': supplement, 'status': 'COLLECTED_REQUIRES_FINAL_REVIEW'})
    except BaseException as error:
        run.write(out / 'failure.json', {'error': repr(error), 'windows': len(rows)})
        if isinstance(error, subprocess.CalledProcessError):
            (out / 'failed-command.stdout').write_bytes(error.stdout or b'')
            (out / 'failed-command.stderr').write_bytes(error.stderr or b'')
        if ctx['owns_root']:
            run.stop_owned('v022_batch_failed')
        raise
    finally:
        if ctx['guard'] is not None:
            try:
                end_guard(ctx)
            except Exception as error:
                cleanup.append('guard closure: ' + repr(error))
        finished.set()
        if monitor.ident is not None:
            monitor.join(timeout=12)
            if monitor.is_alive():
                cleanup.append('external monitor did not finish')
        if ctx['owns_root']:
            try:
                ctx['research'].clear_exited_group()
                ctx['shared'].set_slots(qualification['artifacts'], 'k', 'k')
                ctx['shared'].verify_files({'dnsmasq-c': plan_tool.K_SHA256, 'dnsmasq-rust': plan_tool.K_SHA256})
                if run.production_identity() != ctx['identity'] or current_boot(run) != ctx['boot']:
                    raise RuntimeError('postflight production/boot changed')
                run.write(out / 'restored.json', {'slots': 'K/K', 'production_pid_start': ctx['identity'], 'boot': ctx['boot']})
            except Exception as error:
                cleanup.append('restore: ' + repr(error))
        run.write(out / 'cleanup.json', {'errors': cleanup})
    if cleanup or ctx['failed'].is_set():
        raise RuntimeError('final health or cleanup incomplete')
    run.write(out / 'complete.json', {'windows': len(rows), 'status': 'EVIDENCE_COMPLETE_REQUIRES_FINAL_REVIEW'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--qualification', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    plan = load_plan(args.plan, args.bundle.resolve())
    if not args.execute:
        print(json.dumps({'status': 'DRY_RUN_ONLY', 'windows': len(plan['schedule']),
                          'conditional_extra_windows': 0 if plan.get('scope') == 'short-safety-regression' else 8,
                          'startup_starts': plan['startup_supplement']['total_starts'],
                          'qualification_supplied': args.qualification is not None,
                          'remote_access': False, 'root': plan_tool.ROOT}))
        return
    if args.qualification is None or args.out is None:
        parser.error('--execute requires --qualification and a new private --out')
    private = (Path(__file__).resolve().parents[2] / 'private').resolve()
    out = args.out.resolve()
    if private not in out.parents or out.exists():
        parser.error('--out must be a new directory under repository/private')
    from safe_v022_qualification import load_qualification
    qualification = load_qualification(args.qualification, args.bundle.resolve(), args.plan)
    if qualification.get('driver_sha256') != plan_tool.digest(Path(__file__)):
        raise ValueError('qualified host driver identity differs')
    import safe_v022_startup_run
    if qualification.get('startup_runner_sha256') != plan_tool.digest(Path(safe_v022_startup_run.__file__)):
        raise ValueError('qualified startup runner identity differs')
    execute(plan, args.bundle.resolve(), qualification, out, safe_v022_startup_run)


if __name__ == '__main__':
    main()
