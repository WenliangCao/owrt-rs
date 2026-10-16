#!/usr/bin/env python3
"""One fixed research batch under FROZEN_RESEARCH_SUPPLEMENT_20261016.md."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import statistics
import subprocess
import threading
import time

import device_health_baseline as health
import perf_opt_analyze as analyze
import perf_opt_device_run as run
import udp_stage_device_run as shared


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schedule(confirmation=None, residual=False, g_pgo_screen=False, residual_candidate='pgo',
             d1_pgo_screen=False, local_rules_screen=False):
    windows = []

    def pair(group, number, rate, left, right):
        for side in (('c', 'rust') if number % 2 else ('rust', 'c')):
            windows.append({'group': group, 'round': number, 'rate': rate,
                            'side': side, 'artifact': left if side == 'c' else right,
                            'left': left, 'right': right, 'warmup_seconds': 5,
                            'measurement_seconds': 20,
                            'label': f'research-reset-{group}-r{number}-{side}'})

    if d1_pgo_screen or local_rules_screen:
        aa_group = 'i-rules-aa95' if local_rules_screen else 'i-aa95'
        group = 'i-rules-next95' if local_rules_screen else 'i-d1-pgo95'
        candidate = 'j-pgo' if local_rules_screen else 'd1-pgo'
        for number in (1, 2):
            pair(aa_group, number, 200, 'g-pgo', 'g-pgo')
        for number in range(1, 6):
            pair(group, number, 200, 'g-pgo', candidate)
        return [{**row, 'measurement_seconds': 95} for row in windows]
    if g_pgo_screen:
        for number in (1, 2):
            pair('h-aa', number, 200, 'pgo', 'pgo')
        for number in range(1, 6):
            pair('h-g-pgo', number, 200, 'pgo', 'g-pgo')
        return windows
    if confirmation:
        left, right = {'e-pgo': ('e', 'pgo'), 'g-c95': ('g', 'c95')}[confirmation]
        for number in range(1, 10):
            pair('confirm-' + confirmation, number, 200, left, right)
        return [{**row, 'measurement_seconds': 45} for row in windows]
    if residual:
        for rate, pairs in ((200, 5), (2000, 3)):
            for number in range(1, pairs + 1):
                pair(f'c-{residual_candidate}-{rate}', number, rate, 'exact-c', residual_candidate)
        return [{**row, 'measurement_seconds': 45 if row['rate'] == 200 else 20}
                for row in windows]
    for number in (1, 2):
        pair('g-aa', number, 200, 'g', 'g')
    for number, rates in enumerate(((200, 1000, 2000), (2000, 1000, 200),
                                    (1000, 200, 2000)), 1):
        for rate in rates:
            pair(f'c-g-{rate}', number, rate, 'exact-c', 'g')
    for group, left, right in (('e-pgo', 'e', 'pgo'), ('g-c95', 'g', 'c95')):
        for number in range(1, 6):
            pair(group, number, 200, left, right)
    return windows


def clock_measurement(folder, measurement):
    before, after = [analyze.json_lines(folder / name)[0]
                     for name in ('cpu-before.jsonl', 'cpu-after.jsonl')]
    samples = [row for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl')
               for row in analyze.json_lines(folder / name)]
    errors = []
    identity = (before['pid'], before['starttime_ticks'])
    if not all(row['same_identity'] and (row['pid'], row['starttime_ticks']) == identity
               for row in (before, after)):
        errors.append('CPU endpoint identity')
    if not all(len(row['processes']) == 1 and not row['tree_truncated'] and
               row['children_disappeared'] == 0 and
               (row['processes'][0]['pid'], row['processes'][0]['starttime_ticks']) == identity and
               row['processes'][0]['thread_count'] == 1 for row in samples):
        errors.append('single stable process/thread cohort')
    # The original tick includes waited children. A parent-only CPU clock is
    # usable only for this observed single-process UDP cohort with no child CPU.
    for key in ('waited_child_user_ticks', 'waited_child_system_ticks'):
        if after[key] != before[key] or any(row['processes'][0][key] != before[key] for row in samples):
            errors.append('waited child CPU changed')
    clocks = [row['clock'] for row in (before, after)]
    if any(c['getcpuclockid_error'] or c['gettime_error'] or c['getres_error'] for c in clocks):
        errors.append('CPU clock error')
    delta = None
    if not errors:
        delta = clocks[1]['cpu_ns'] - clocks[0]['cpu_ns']
        if delta < 0:
            errors.append('CPU clock decreased')
    tick_delta = analyze.cpu_ticks(after) - analyze.cpu_ticks(before)
    if tick_delta < 0:
        errors.append('endpoint ticks decreased')
    return {'valid': not errors, 'errors': errors, 'cpu_ns': delta,
            'cpu_us_per_operation': delta / 1000 / measurement['cpu_operations'] if not errors else None,
            'same_endpoint_cpu_ticks': tick_delta,
            'same_endpoint_tick_us_per_operation': tick_delta / measurement['cpu_hz'] * 1e6 / measurement['cpu_operations'],
            'before': before, 'after': after,
            'scope': 'Same PID/start and endpoint brackets for CPU clock and endpoint ticks; original resource ticks remain separately retained. Sampled single-process UDP cohort only; no claim to detect an unsampled zero-tick fork.'}


def window_measurement(folder, window, valid):
    result = analyze.traffic(folder, {'valid': valid}, window['warmup_seconds'], window['measurement_seconds'])
    result['cpu_clock'] = clock_measurement(folder, result)
    return result


def comparisons(rows):
    output = {}
    for group in dict.fromkeys(row['group'] for row in rows):
        original = [row for row in rows if row['group'] == group]
        # A replacement is the whole pair, used once only after the original
        # batch. Original invalid rows remain in result.windows and archives.
        selected = []
        for number in sorted({row['round'] for row in original}):
            pair = [row for row in original if row['round'] == number]
            attempt = max(row.get('attempt', 0) for row in pair)
            selected.extend(row for row in pair if row.get('attempt', 0) == attempt)
        pairs = []
        for number in sorted({row['round'] for row in selected}):
            sides = {row['side']: row for row in selected if row['round'] == number}
            if set(sides) != {'c', 'rust'}:
                continue
            left, right = (sides[s]['measurement'] for s in ('c', 'rust'))
            valid = all(sides[s]['valid'] and sides[s]['measurement']['cpu_clock']['valid'] for s in sides)
            pairs.append({'round': number, 'valid': valid,
                          'cpu_us_delta': right['cpu_clock']['cpu_us_per_operation'] - left['cpu_clock']['cpu_us_per_operation'] if valid else None,
                          'same_endpoint_tick_delta': right['cpu_clock']['same_endpoint_cpu_ticks'] - left['cpu_clock']['same_endpoint_cpu_ticks'],
                          'legacy_tick_us_delta': right['cpu_us_per_operation'] - left['cpu_us_per_operation'],
                          'p50_ms_delta': right['latency_ms']['p50'] - left['latency_ms']['p50'],
                          'p95_ms_delta': right['latency_ms']['p95'] - left['latency_ms']['p95']})
        deltas = [row['cpu_us_delta'] for row in pairs if row['valid']]
        left = [row['measurement'] for row in sorted(selected, key=lambda r: r['round']) if row['side'] == 'c']
        right = [row['measurement'] for row in sorted(selected, key=lambda r: r['round']) if row['side'] == 'rust']
        legacy = analyze.compare([row['cpu_us_per_operation'] for row in left],
                                 [row['cpu_us_per_operation'] for row in right],
                                 cpu=([row['cpu_ticks'] for row in left], [row['cpu_ticks'] for row in right])) if len(left) == len(right) and left else None
        output[group] = {'pairs': pairs, 'cpu_delta': analyze.spread(deltas) if len(deltas) == len(pairs) and deltas else None,
                         'legacy_resource_tick_W_comparison': legacy}
        if group.startswith('confirm-') and len(deltas) == len(pairs) == 9:
            ordered = sorted(deltas)
            output[group]['confirmation'] = {
                'order_statistic_interval_d2_d8': [ordered[1], ordered[7]],
                'three_pair_block_medians': [statistics.median(deltas[i:i + 3]) for i in (0, 3, 6)],
                'scope': 'Fixed nine pairs. Nominal 96.09% coverage requires continuous approximately independent differences; this output does not establish those assumptions.'}
    aa_group = next((name for name in ('i-rules-aa95', 'i-aa95', 'h-aa', 'g-aa') if name in output), 'g-aa')
    aa = output.get(aa_group, {}).get('cpu_delta')
    noise = max(abs(v) for v in aa['rounds']) if aa else None
    for name in ('e-pgo', 'g-c95', 'h-g-pgo', 'i-d1-pgo95', 'i-rules-next95'):
        result = output.get(name)
        if result and result['cpu_delta'] and noise is not None:
            values = result['cpu_delta']['rounds']
            key = 'independent_confirmation_trigger' if name in ('e-pgo', 'g-c95') else 'cpu_screen_trigger'
            result[key] = (len(values) == 5 and sum(v < 0 for v in values) >= 4
                           and statistics.median(values) <= -5
                           and -statistics.median(values) > noise)
    return {'groups': output, 'AA_max_absolute_pair_cpu_us': noise,
            'AA_group': aa_group if aa else None,
            'scope': 'Fixed exploratory pairs and batch-local A/A noise; no significance claim and no historical pooling.'}


def clear_exited_group():
    # A stop marker is evidence and stays. Only remove a stale active.group
    # after no non-zombie member of its exact recorded group remains.
    script = f'''set -eu
if test -f {run.ROOT}/active.group; then
  read owner expected < {run.ROOT}/active.group
  case "$owner:$expected" in *[!0-9:]*|:*) exit 2;; esac
  test "$owner" -gt 1
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    live=0
    for stat in /proc/[0-9]*/stat; do
      if awk -v g="$owner" '$5==g && $3!="Z" {{found=1}} END {{exit !found}}' "$stat" 2>/dev/null; then live=1; fi
    done
    test "$live" = 1 || break
    sleep 0.2
  done
  test "$live" = 0
  rm -- {run.ROOT}/active.group
fi'''
    run.ssh(script)


def tool_invalid(folder, errors):
    if not errors or not (folder / 'client.json').exists() or not (folder / 'COMPLETE').exists():
        return False
    load = json.loads((folder / 'client.json').read_text())
    phases = [load[key] for key in ('warmup', 'measurement')]
    # Explicit generator loss only. DNS timeout/wrong/transport failure, crash,
    # upstream failure and unclassified tool deadlines are never relabelled.
    return (all(row['correct'] == row['sent'] and not any(row[key] for key in
                ('timeout', 'wrong', 'transport_error')) for row in phases)
            and any(row['scheduled_skipped'] for row in phases)
            and set(errors) <= {'warmup error counters', 'measurement error counters',
                                'warmup completion count', 'measurement completion count'})


def prepare(bindings, out):
    assert run.production_identity() == bindings['production_pid_start']
    shared.verify_files({**bindings['measurement_artifacts'], **bindings['original_slots']})
    run.ssh(f'test ! -e {run.ROOT}/STOP && test ! -e {run.ROOT}/active.group')
    records = {}
    for name, row in {**bindings['artifacts'], **bindings['new_tools']}.items():
        path = Path(row['local']); assert sha(path) == row['sha256']
        remote = run.ROOT + '/' + row['name']
        # The capability helper/group may already be present; identity must match.
        command = '\n'.join(['set -eu', f'if test -e {remote}; then',
            f'test "$(sha256sum {remote} | cut -d " " -f 1)" = {row["sha256"]}',
            'else', f'test ! -e {remote}.new', f'cat > {remote}.new',
            f'test "$(sha256sum {remote}.new | cut -d " " -f 1)" = {row["sha256"]}',
            f'chmod 755 {remote}.new', f'mv {remote}.new {remote}', 'fi'])
        subprocess.run(['ssh', '-o', 'BatchMode=yes', 'openwrt', command], input=path.read_bytes(),
                       check=True, capture_output=True, timeout=30)
        records[name] = {'remote': remote, 'sha256': row['sha256'], 'bytes': path.stat().st_size}
    shared.verify_files(bindings['original_slots'])
    assert run.production_identity() == bindings['production_pid_start']
    run.write(out / 'staging.json', {'epoch': time.time(), 'records': records, 'production_unchanged': True})


def execute(bindings, out, health_path, confirmation=None, residual=False, g_pgo_screen=False,
            residual_candidate='pgo', d1_pgo_screen=False, local_rules_screen=False):
    baseline = json.loads(health_path.read_text())
    assert baseline['valid'] and baseline['elapsed_seconds'] >= 120
    artifacts = bindings['artifacts']
    identity = run.production_identity(); assert identity == bindings['production_pid_start']
    shared.verify_files({**bindings['measurement_artifacts'], **bindings['original_slots'],
                         **{v['name']: v['sha256'] for v in artifacts.values()},
                         **{v['name']: v['sha256'] for v in bindings['new_tools'].values()}})
    assert not (out / 'progress.json').exists()
    original_schedule = schedule(confirmation, residual, g_pgo_screen, residual_candidate,
                                 d1_pgo_screen, local_rules_screen)
    group_helper = 'research_local_rules_group.sh' if local_rules_screen else 'research_device_group.sh'
    assert group_helper in bindings['new_tools']
    if any(row['artifact'] == 'exact-c' for row in original_schedule):
        checks = [f'test "$(sha256sum {path} | cut -d " " -f 1)" = {digest}'
                  for path, digest in bindings['exact_C_runtime_libraries'].items()]
        checks.append('test "$(readlink /lib/ld-musl-aarch64.so.1)" = libc.so')
        run.ssh('set -eu\n' + '\n'.join(checks))
    run.write(out / 'launch.json', {'epoch': time.time(), 'schedule': original_schedule, 'bindings': bindings,
                                   'health_sha256': sha(health_path), 'controller_sha256': sha(Path(__file__))})
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=run.external_health, args=(out, finished, failed), daemon=True)
    guard = None; label = None; archived = set(); rows = []; cleanup = []
    guard_label = 'research-reset-guard-' + str(time.time_ns())
    try:
        guard = run.guard_start(identity[0], guard_label, baseline['threshold_ms']); monitor.start()
        previous_pair = None
        queue = list(original_schedule); original_count = len(queue); pending = set(); at = 0
        while at < len(queue):
            window = queue[at]; at += 1
            label = window['label']
            assert run.production_identity() == identity and not failed.is_set()
            pair = (window['group'], window['round'])
            if pair != previous_pair:
                shared.set_slots(artifacts, window['left'], window['right']); previous_pair = pair
            scene = ('research-hit', 'udp', 'hit', window['rate'], 5, window['measurement_seconds'], 150)
            command = 'setsid /bin/sh ' + run.ROOT + '/' + group_helper + ' ' + shlex.join([window['side'], label, *map(str, scene[1:])])
            with (out / (label + '.controller.log')).open('xb') as log:
                process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', 'openwrt', command], stdout=log, stderr=log)
                started = time.monotonic()
                while process.poll() is None:
                    if (failed.wait(5) or not run.guard_check(guard)
                            or time.monotonic() - started > run.case_deadline_seconds(scene)):
                        raise RuntimeError('health/guard/case deadline')
            if not run.guard_check(guard): raise RuntimeError('guard lost')
            run.ssh(f'rm -f {run.ROOT}/active.group')
            archived.add(label); folder = run.archive_run(out, label)
            errors = run.validate(folder, scene, artifacts[window['artifact']]['sha256'])
            if process.returncode: errors.append('case exit ' + str(process.returncode))
            measurement = window_measurement(folder, window, not errors)
            generator_invalid = tool_invalid(folder, errors)
            row = {**window, 'valid': not errors, 'errors': errors, 'tool_invalid': generator_invalid,
                   'case_exit': process.returncode,
                   'elf_sha256': artifacts[window['artifact']]['sha256'], 'measurement': measurement, 'archived_epoch': time.time()}
            rows.append(row); run.write(out / 'progress.json', rows)
            run.write(out / 'result.json', {'complete': False, 'windows': rows, 'comparisons': comparisons(rows)})
            print(json.dumps({'windows': len(rows), 'label': label, 'valid': not errors,
                              'ns_valid': measurement['cpu_clock']['valid']}), flush=True)
            if failed.is_set() or (errors and not generator_invalid):
                raise RuntimeError('invalid original window retained; stop for classification')
            if generator_invalid:
                if window.get('attempt', 0): raise RuntimeError('one allowed replacement pair also invalid')
                pending.add(pair)
            run.ssh('rm -rf -- ' + shlex.quote(run.ROOT + '/runs/' + label))
            if at == original_count:
                for retry in original_schedule:
                    if (retry['group'], retry['round']) in pending:
                        queue.append({**retry, 'label': retry['label'] + '-repeat1', 'attempt': 1})
        finished.set(); monitor.join(timeout=12)
        if monitor.is_alive() or failed.is_set() or not run.guard_check(guard): raise RuntimeError('final health')
        health.capture_before_stop(out, guard_label); run.guard_stop(guard); guard = None
    except BaseException as error:
        run.write(out / 'failure.json', {'error': repr(error), 'label': label, 'completed_windows': len(rows)})
        run.stop_owned('research_reset_failed')
        if label and label not in archived:
            try: run.archive_run(out, label)
            except Exception as archive_error: cleanup.append(repr(archive_error))
        raise
    finally:
        finished.set()
        if monitor.is_alive(): monitor.join(timeout=12)
        if guard is not None: run.guard_stop(guard)
        for suffix in ('jsonl', 'stderr'):
            result = run.ssh(f'cat {run.ROOT}/{guard_label}.{suffix}', check=False)
            (out / ('guard.' + suffix)).write_bytes(result.stdout)
        try:
            clear_exited_group()
            shared.set_slots(artifacts, 'e', 'f'); shared.verify_files(bindings['original_slots'])
            assert run.production_identity() == identity
            run.write(out / 'restored.json', {'epoch': time.time(), 'slots': bindings['original_slots'], 'production_pid_start': identity})
        except Exception as error: cleanup.append(repr(error))
        run.write(out / 'cleanup.json', {'errors': cleanup})
    if cleanup: raise RuntimeError('restore/cleanup incomplete')
    qualified, samples, end = health.validate_guard_evidence((out / 'pre-stop-prefix.jsonl').read_bytes(),
        (out / 'guard.jsonl').read_bytes(), analyze.json_lines(out / 'external-health.jsonl'), identity,
        (out / 'pre-stop-capture.raw').read_bytes())
    run.write(out / 'result.json', {'complete': True, 'windows': rows, 'comparisons': comparisons(rows),
        'health': {'qualified_samples': len(qualified), 'samples': len(samples), 'end': end},
        'restored': json.loads((out / 'restored.json').read_text())})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--health', type=Path)
    parser.add_argument('--prepare', action='store_true')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--confirmation', choices=('e-pgo', 'g-c95'))
    selection.add_argument('--residual', action='store_true')
    selection.add_argument('--residual-g-pgo', action='store_true',
                           help='Fixed exact C/G+PGO residual sixteen windows')
    selection.add_argument('--g-pgo-screen', action='store_true',
                           help='Fixed H/H two pairs followed by H/G+PGO five pairs')
    selection.add_argument('--d1-pgo-screen', action='store_true',
                           help='Fixed I/I two pairs then I/D1 five pairs; 95s measurement')
    selection.add_argument('--local-rules-screen', action='store_true',
                           help='Fixed public local-rule I/I and I/J screen using separate case/group')
    args = parser.parse_args(); bindings = json.loads(args.bindings.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    if args.prepare: prepare(bindings, args.out)
    else:
        if not args.health: parser.error('--health required for execution')
        execute(bindings, args.out, args.health, args.confirmation,
                args.residual or args.residual_g_pgo, args.g_pgo_screen,
                'g-pgo' if args.residual_g_pgo else 'pgo', args.d1_pgo_screen, args.local_rules_screen)


if __name__ == '__main__':
    main()
