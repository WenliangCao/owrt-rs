#!/usr/bin/env python3
"""Collect the frozen R113 memory screen serially; never install a daemon."""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys

from r105_rx_spare_report import digest, read, verify_memory_snapshots


REPO = Path(__file__).resolve().parent.parent
HEALTH = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
          'same_production_identity', 'same_host_mounts')


def verify_files(plan):
    for path, expected in plan['source_scripts'].items():
        assert digest(REPO / path) == expected, (path, 'script changed')
    for side, path in plan['subject_paths'].items():
        assert digest(REPO / path) == plan['subjects'][side], (side, 'ELF changed')
    for name in ('benchmark', 'guard', 'recovery_gate'):
        assert digest(REPO / plan[name + '_path']) == plan[name + '_sha256'], name
    gate = read(REPO / plan['recovery_gate_path'])
    assert gate['offline_backup_verified'] and gate['configuration_matches_backup']
    assert gate['boot_id'] == plan['boot_id']


def verify_prerequisites(plan):
    frozen = {}
    for prerequisite in plan['preflights']:
        root = REPO / prerequisite['path']
        for name, expected in prerequisite['sha256'].items():
            path = root / name
            assert digest(path) == expected, (path, 'preflight changed')
            frozen[str(path.relative_to(REPO))] = expected
        result = read(root / 'result.json')
        assert all(result.get(key) is True for key in HEALTH)
        assert result['exit'] == 0 and result['correctness_smoke_only']
        assert not result['installed'] and not result['pilot_only'] and not result['matrix']
        assert result['production_mode'] == 'stock' and result['implementation'] == 'rs'
        assert result['candidate_sha256'] == plan['subjects']['candidate']
        assert result['before_candidate_sha256'] == plan['subjects']['r112']
        assert result['workload_sha256'] == prerequisite['workload_sha256']
        for key in ('guard_sha256', 'recovery_gate_sha256'):
            assert result[key] == plan[key]
        assert result['driver_sha256'] == plan['source_scripts']['tools/r95_device_smoke.py']
        assert (root / 'raw/COMPLETE').is_file()
        if prerequisite.get('unit_tests_sha256'):
            assert result['unit_tests']['exit'] == 0
            assert result['unit_tests']['sha256'] == prerequisite['unit_tests_sha256']
        for when in ('before', 'after'):
            assert read(root / f'health-{when}.json')['boot_id'] == plan['boot_id']
    path = REPO / plan['oracle_gates']['path']
    assert digest(path) == plan['oracle_gates']['sha256'], 'Oracle gate report changed'
    gates = read(path)
    expected = set(plan['oracle_gates']['required'])
    assert gates['passed'] is True and gates['finished'], 'Oracle gates incomplete'
    assert set(gates['gate_selection']) == expected
    assert len(gates['results']) == len(expected)
    assert {row['name'] for row in gates['results']} == expected
    assert all(row['required'] is True and row['exit'] == 0 for row in gates['results'])
    assert gates['binary_sha256']['ubusd-rs'] == plan['subjects']['candidate']
    assert gates['driver_sha256'] == plan['source_scripts']['tools/r92_validate.py']
    frozen[str(path.relative_to(REPO))] = digest(path)
    return frozen


def verify_window(root, plan, side):
    result = read(root / 'result.json')
    assert all(result.get(key) is True for key in HEALTH)
    assert result['exit'] == 0 and result['pilot_only'] and not result['correctness_smoke_only']
    assert not result['installed'] and not result['matrix'] and result['production_mode'] == 'stock'
    assert result['implementation'] == ('c' if side == 'stock' else 'rs')
    assert result['iterations'] == plan['iterations']
    for key in ('benchmark_sha256', 'guard_sha256', 'recovery_gate_sha256'):
        assert result[key] == plan[key]
    assert result['candidate_sha256'] == plan['subjects'][side]
    assert result['driver_sha256'] == plan['source_scripts']['tools/r95_device_smoke.py']
    assert result['workload_sha256'] == plan['source_scripts'][plan['workload_script']]
    for when in ('before', 'after'):
        assert read(root / f'health-{when}.json')['boot_id'] == plan['boot_id']
    raw = root / 'raw'
    assert (raw / 'COMPLETE').is_file() and (root / 'raw.tar.gz').is_file()
    assert (raw / 'binary-sha256.txt').read_text().split()[0] == plan['subjects'][side]
    tools = {line.split()[1]: line.split()[0]
             for line in (raw / 'benchmark-sha256.txt').read_text().splitlines()}
    assert tools == {'/tmp/bin/owrt-benchmark': plan['benchmark_sha256'],
                     '/tmp/bin/ns-exec': plan['namespace_sha256']}
    rows = list(csv.DictReader((raw / 'memory.csv').read_text().splitlines()))
    assert [int(row['clients']) for row in rows] == plan['workloads']
    for row in rows:
        count = int(row['clients'])
        assert row['pss_before_kb'] == row['pss_after_kb'] == 'NA'
        metrics = {key: int(value) for key, value in row.items()
                   if key != 'clients' and not key.startswith('pss')}
        reclaimed = (raw / f'after-disconnect-{count}.csv').read_text().strip().split(',')
        assert len(reclaimed) == 4 and reclaimed[3] == 'NA'
        for name, value in zip(('vmrss', 'rssanon', 'vmdata'), reclaimed[:3]):
            metrics[name + '_after_disconnect_kb'] = int(value)
        assert all(value >= 0 for value in metrics.values())
        verify_memory_snapshots(raw, count, metrics)
        command = (raw / f'cmdline-{count}.txt').read_text().splitlines()
        assert len(command) == 3 and command[:2] == [plan['argv0'], '-s']
        if count:
            holder = read(raw / f'clients-{count}.json')
            assert holder['clients'] == holder['ping_frames_sent'] == count
            assert holder['replies_validated'] is True and holder['holding'] is True
            assert not (raw / f'clients-{count}.err').read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, default=REPO / 'docs/reviews/r113-memory-plan.json')
    parser.add_argument('--out', type=Path, default=REPO / 'private/r113-fd-boundary/memory')
    parser.add_argument('--host', default='openwrt')
    parser.add_argument('--interface', default='en0')
    args = parser.parse_args()
    plan_path, out = args.plan.resolve(), args.out.resolve()
    plan = read(plan_path)
    plan_sha = digest(plan_path)
    verify_files(plan)
    prerequisites = verify_prerequisites(plan)
    assert len(plan['blocks']) == 2 and len(plan['subjects']) == 5
    assert plan['blocks'][1]['order'] == list(reversed(plan['blocks'][0]['order']))
    assert all(len(block['order']) == 5 and set(block['order']) == set(plan['subjects']) for block in plan['blocks'])
    assert plan['workloads'] == [0, 1, 8, 32, 64] and plan['after_disconnect']
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    (out / 'plan.json').write_bytes(plan_path.read_bytes())
    (out / 'prerequisites.json').write_text(json.dumps(prerequisites, indent=2) + '\n')
    window = None
    try:
        for block in plan['blocks']:
            for side in block['order']:
                assert digest(plan_path) == plan_sha, 'plan changed'
                verify_files(plan)
                assert verify_prerequisites(plan) == prerequisites, 'prerequisite evidence changed'
                window = out / f'{block["block"]:02d}-{side}'
                command = [sys.executable, str(REPO / 'tools/r95_device_smoke.py'), 'ubusd',
                           str(REPO / plan['subject_paths'][side]), str(window), '--pilot',
                           '--iterations', str(plan['iterations']), '--implementation', 'c' if side == 'stock' else 'rs',
                           '--benchmark', str(REPO / plan['benchmark_path']),
                           '--workload-script', str(REPO / plan['workload_script']),
                           '--guard', str(REPO / plan['guard_path']),
                           '--recovery-gate', str(REPO / plan['recovery_gate_path']),
                           '--host', args.host, '--interface', args.interface]
                print(f'START {window.name}', flush=True)
                with (out / f'{window.name}.log').open('wb') as log:
                    subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, check=True)
                verify_window(window, plan, side)
                verify_files(plan)
                assert digest(plan_path) == plan_sha
                assert verify_prerequisites(plan) == prerequisites
                print(f'VERIFIED {window.name}', flush=True)
        (out / 'COMPLETE').touch()
        subprocess.run([sys.executable, str(REPO / 'tools/r105_rx_spare_report.py'), 'memory',
                        str(out), str(plan_path), str(out / 'report.json')], cwd=REPO, check=True)
        report = read(out / 'report.json')
        growth = [row['rssanon_growth_kb'] for row in report['runs']
                  if row['side'] == 'candidate' and row['workload'] == 64]
        assert len(growth) == 2
        decision = {'candidate_64_client_rssanon_growth_kib': growth,
                    'limit_kib': plan['memory_gate']['max_growth_kib'],
                    'memory_gate_passed': all(value <= plan['memory_gate']['max_growth_kib'] for value in growth),
                    'scope': 'HELLO/PING held connections only; no CPU, FD-workload, full-memory or adoption verdict.'}
        (out / 'memory-gate.json').write_text(json.dumps(decision, indent=2) + '\n')
        print(json.dumps(decision), flush=True)
    except BaseException as error:
        (out / 'COMPLETE').unlink(missing_ok=True)
        (out / 'FAILED.json').write_text(json.dumps({'window': str(window), 'type': type(error).__name__,
                                                     'error': str(error)}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
