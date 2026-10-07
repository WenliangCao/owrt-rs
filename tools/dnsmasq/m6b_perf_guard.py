#!/usr/bin/env python3
"""Feature-off UDP/idle/TCP regression guard; thresholds must be frozen inputs.

Uses the existing exact-image window and native workload, never builds a helper
or product. These two short windows are a protection gate, not the formal 135
window performance comparison. All failed evidence stays under fresh private/.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import re
import sys

import m6a_analyze as analyze
import m6a_suite as suite
from m2_rootfs import STOCK_SHA256, sha256

CLIENTS, WARMUP, DURATION, RATE = 20, 2, 10, 10000
CAPACITY, TTL = 4096, 3600
LIMITS = ('udp_p50_max_ns', 'idle_cpu_max_seconds', 'tcp_peak_pss_max_kib')


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    suite.save(path, value)


def inputs(path, tools):
    """Validate the threshold freeze and reusable native helper provenance."""
    plan = json.loads(path.read_text())
    require(type(plan.get('schema')) is int and plan['schema'] == 1 and plan.get('frozen') is True, 'frozen performance guard plan required')
    limits = plan.get('thresholds', {})
    require(set(limits) == set(LIMITS), 'all three explicit frozen thresholds required')
    require(all(type(limits[key]) in (int, float) and math.isfinite(limits[key]) and limits[key] > 0
                for key in LIMITS), 'thresholds must be finite positive numbers, not null or booleans')
    require(limits['udp_p50_max_ns'] <= 1_000_000, 'UDP p50 cap cannot exceed protocol 1 ms protection line')
    require(plan.get('basis'), 'threshold freeze requires a measurement basis')
    native_path = Path(plan['native_manifest']['path'])
    require(sha256(native_path) == plan['native_manifest']['sha256'], 'native helper manifest changed')
    native = json.loads(native_path.read_text())
    assets = {str(path.resolve()): sha256(path), str(native_path.resolve()): sha256(native_path)}
    for name in ('m6a_loadgen', 'm6a_upstream'):
        require(native['tools_files'][name + '.c'] == sha256(tools / (name + '.c')),
                'native workload source differs from this frozen guard')
        item = native['native'][name]
        require(sha256(Path(item['path'])) == item['sha256'], 'native helper ELF changed')
        assets[str(Path(item['path']).resolve())] = item['sha256']
        assets[str((tools / (name + '.c')).resolve())] = sha256(tools / (name + '.c'))
    return plan, native['native'], assets


def window_command(args, native, profile, out):
    tools = Path(__file__).resolve().parent
    command = ['sh', str(tools / 'run_isolated.sh'), sys.executable, str(tools / 'm6a_window.py'),
               '--implementation', 'r3', '--rust', str(args.elf), '--expected-rust-sha', args.expected_elf_sha,
               '--allow-rust-identity-change', '--image-root', str(args.image_root),
               '--loadgen', native['m6a_loadgen']['path'], '--upstream', native['m6a_upstream']['path'],
               '--scenario', 'hit' if profile == 'udp-hit' else 'tcp', '--tcp-profile', 'hit',
               '--clients', str(CLIENTS), '--warmup', str(WARMUP), '--duration', str(DURATION),
               '--rate', str(RATE), '--cache-names', str(CAPACITY), '--saturation-seconds', '0',
               '--idle-seconds', '60' if profile == 'udp-hit' else '0',
               '--drain-timeout-seconds', '5', '--drain-sample-seconds', '0', '--preflight',
               '--seed', '29302026', '--output', str(out), '--cpu-daemon', '0', '--cpu-upstream', '1',
               '--cpu-load', '2', '--cpu-control', '3']
    if profile == 'tcp-cache':
        command.append('--perf-guard-tcp-hold')
    return command


def assess_window(path, profile, expected_sha):
    """Reject absent observations, incorrect answers and incomplete resource proof."""
    result = json.loads((path / 'result.json').read_text())
    identity = result['identity']
    require(result.get('measurement_valid') is True and result.get('accepted') is True, 'window methodology failed')
    require(identity['expected_elf_sha256'] == expected_sha and identity['implementation'] == 'r3', 'guard ELF identity differs')
    require(identity['clients'] == CLIENTS and identity['warmup_seconds'] == WARMUP
            and identity['duration_seconds'] == DURATION and identity['rate'] == RATE
            and identity['saturation_seconds'] == 0, 'guard workload changed')
    require(all(key in identity and identity[key] is False for key in ('wake_metrics', 'perf_record', 'strace_summary')), 'missing/instrumented guard identity is forbidden')
    require(identity['perf_guard_tcp_hold'] is (profile == 'tcp-cache'), 'TCP hold identity differs')
    require(identity['cpus'] == {'daemon': 0, 'upstream': 1, 'loadgen': 2, 'control': 3}, 'guard affinity changed')
    expected_scenario = 'hit' if profile == 'udp-hit' else 'tcp'
    require(identity['scenario'] == expected_scenario and identity['tcp_profile'] == 'hit', 'guard profile changed')
    require(result['cleanup']['returncode'] == 0 and not result['cleanup']['forced_kill'], 'guard daemon cleanup failed')
    measurement = result['measurement']
    require(measurement['quality'] and all(value is True for value in measurement['quality'].values()), 'window quality proof missing/failed')
    load = measurement['load']
    require(load == json.loads((path / 'load.json').read_text()), 'window load counters differ from native evidence')
    for stage in ('warmup', 'measurement'):
        counter = load[stage]
        require(counter['correct'] > 0 and counter['correct'] == counter['sent']
                and all(counter[key] == 0 for key in ('wrong', 'timeout', 'transport_error')), 'incorrect/incomplete guard answers')
    proof = json.loads((path / 'cache-proof.json').read_text())
    require(proof['capacity'] == CAPACITY and proof['ttl'] == TTL and proof['upstream_disabled'] is True
            and proof['filled_names'] == CAPACITY and proof['validated_names'] == CAPACITY
            and len(proof['rows']) == CAPACITY and all(row['correct'] is True for row in proof['rows']), 'full cache proof missing')
    require(result['upstream']['disabled_requests'] == 0 and result['upstream']['invalid_queries'] == 0,
            'cache guard unexpectedly queried upstream')
    latencies, clients = [], set()
    for sequence, latency, sent, client, qtype, status, phase, kind, padding in analyze.binary_records(path / 'load.latencies.bin', analyze.LATENCY):
        require(status == 0 and phase == 1 and 0 <= client < CLIENTS and qtype == 1 and padding == 0,
                'invalid/error guard latency record')
        require(load['measurement_start_ns'] <= sent < load['measurement_end_ns'] and latency > 0,
                'latency sample does not belong to measured requests')
        latencies.append(latency); clients.add(client)
    require(len(latencies) == load['measurement']['correct'] and len(latencies) >= 1000
            and clients == set(range(CLIENTS)), 'latency/correct count or 20-client coverage missing')
    measured_wire = []
    with (path / 'load.wire-samples.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            require(row['correct'] is True and analyze.sample_dns_correct(bytes.fromhex(row['query_hex']), bytes.fromhex(row['reply_hex'])),
                    'guard wire sample has incorrect content')
            if row['phase'] == 1:
                measured_wire.append(row)
    require(len(measured_wire) >= 10, 'measured wire sample coverage missing')
    resources = json.loads((path / 'resources.json').read_text())
    rows = [row for row in resources if 0 <= row['measurement_elapsed_seconds'] < DURATION]
    require(len(rows) >= DURATION - 2 and all(row['tree']['pss_kib'] > 0 for row in rows), 'PSS resource observations missing')
    require(all(row['tree']['thread_count'] == 1 and row['tree']['child_processes'] == 0
                and row['parent']['affinity'] == [0] for row in rows), 'single-owner/CPU0 resource proof missing')
    sampled_peak = max(row['tree']['pss_kib'] for row in rows)
    require(sampled_peak == measurement['peaks']['pss_kib'], 'reported peak differs from actual samples')
    observations = {'p50_ns': analyze.quantiles(latencies)['p50'], 'correct': len(latencies),
                    'sampled_peak_pss_kib': sampled_peak, 'resource_samples': len(rows), 'measured_wire_samples': len(measured_wire)}
    if profile == 'udp-hit':
        idle = measurement['idle_cpu']
        require(idle['enabled'] is True and idle['requested_seconds'] == 60 and 60 <= idle['elapsed_seconds'] <= 61,
                'actual 60-second idle CPU window missing')
        before, after = idle['cgroup_before'], idle['cgroup_after']
        require(before['path'] == after['path'], 'idle cgroup identity changed')
        cpu = (after['usage_usec'] - before['usage_usec']) / 1e6
        require(cpu >= 0 and math.isclose(cpu, idle['cpu_seconds'], abs_tol=1e-6), 'idle CPU is not the actual cgroup delta')
        observations['idle_cpu_seconds'] = cpu
    else:
        hold = result['tcp_hold_20']
        require(hold['complete'] is True and hold['clients'] == CLIENTS and len(hold['replies']) == CLIENTS
                and all(row['correct'] is True for row in hold['replies']), '20 TCP correct held replies missing')
        for row in hold['replies']:
            require(analyze.sample_dns_correct(bytes.fromhex(row['query']), bytes.fromhex(row['reply'])), 'held TCP answer changed')
        before, held = hold['before']['tree'], hold['held']['tree']
        require(held['fd_count'] == before['fd_count'] + CLIENTS and held['child_processes'] == 0
                and held['thread_count'] == 1 and held['pss_kib'] > 0, 'exact 20 TCP owner/PSS proof missing')
        observations['held_20_pss_kib'] = held['pss_kib']
        observations['peak_pss_kib'] = max(held['pss_kib'], sampled_peak)
    return observations


def classify(observed, thresholds):
    values = {'udp_p50_max_ns': observed['udp-hit']['p50_ns'],
              'idle_cpu_max_seconds': observed['udp-hit']['idle_cpu_seconds'],
              'tcp_peak_pss_max_kib': observed['tcp-cache']['peak_pss_kib']}
    return {key: {'observed': values[key], 'maximum': thresholds[key], 'passed': values[key] <= thresholds[key]}
            for key in LIMITS}


def run(args):
    require(os.geteuid() == 0, 'root required for isolated exact-image guard')
    args.out = args.out.resolve()
    require('private' in args.out.parts and not args.out.exists(), 'fresh private output required')
    args.out.mkdir(parents=True)
    report = {'passed': False, 'source_commit': args.source_commit, 'elf_sha256': args.expected_elf_sha,
              'scope': 'low-cost regression protection on Oracle; not formal performance or router evidence',
              'failures': [], 'observed': {}, 'commands': []}
    try:
        tools = Path(__file__).resolve().parent
        require(sha256(args.inputs) == args.expected_plan_sha, 'guard plan changed after freeze')
        plan, native, assets = inputs(args.inputs.resolve(), tools)
        report['plan_sha256'] = args.expected_plan_sha
        report['plan'] = plan; report['assets'] = assets; report['runner_sha256'] = sha256(Path(__file__))
        require(re.fullmatch('[0-9a-f]{40}', args.source_commit), 'full source identity required')
        require(sha256(args.elf) == args.expected_elf_sha and sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256,
                'guard product or exact image C identity changed')
        build = json.loads(args.build_json.read_text())
        require(build['kind'] == 'release' and build['features'] == '' and any(
            item['sha256'] == args.expected_elf_sha and item['path'] == 'dnsmasq-rs' and item['bytes'] == args.elf.stat().st_size
            for item in build['artifacts']), 'feature-off release identity required')
        report['build_json_sha256'] = sha256(args.build_json)
        report['opt_level'] = build.get('opt_level')
        os.sched_setaffinity(0, {3})
        state = {}; state_path = args.out / 'controller-state.json'
        with (suite.TARGET / '.dnsmasq-build.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(not suite.foreign_load(), 'foreign load before guard')
            for profile in ('udp-hit', 'tcp-cache'):
                output = args.out / profile
                command = window_command(args, native, profile, output)
                record = suite.execute(command, args.out / (profile + '.log'), state, state_path)
                report['commands'].append(record)
                save(args.out / 'result.json', report)
                require(record['returncode'] == 0, profile + ': window failed')
                report['observed'][profile] = assess_window(output, profile, args.expected_elf_sha)
            require(not suite.foreign_load(), 'foreign load after guard')
        require(all(sha256(Path(path)) == value for path, value in assets.items()), 'guard input changed during windows')
        require(sha256(args.elf) == args.expected_elf_sha, 'guard ELF changed during windows')
        require(sha256(args.build_json) == report['build_json_sha256'] and
                sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256, 'build/image identity changed during guard')
        report['checks'] = classify(report['observed'], plan['thresholds'])
        report['passed'] = all(check['passed'] for check in report['checks'].values())
        if not report['passed']:
            report['failures'].append('regression threshold exceeded')
    except Exception as error:
        report['failures'].append(repr(error))
    save(args.out / 'result.json', report)
    print(json.dumps(report)); return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs', 'elf', 'build-json', 'image-root', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-elf-sha', required=True)
    parser.add_argument('--expected-plan-sha', required=True)
    parser.add_argument('--source-commit', required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
