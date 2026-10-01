#!/usr/bin/env python3
"""Freeze and check pressure traces against exact C before an expiry optimization.

Local, socket-free source primitives only; no candidate or timing measurement.
All generated source, binary and trace artifacts stay under ignored private/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import dns_cache_diff as reference

ROOT = Path(__file__).resolve().parents[2]
BASELINE = 'bb0a923'
CACHE_SHA = 'ce40fbf1bb34e01f5d760e46fa7ad377af5e6daf5368c3b49dded5fe850faf75'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def queries(names, now):
    return [f'Q {name} {kind} {now} 0' for name, kind in dict.fromkeys(names)]


def scenarios():
    yield next(reference.scenarios())
    for capacity in [8, 64, 1000]:
        for phase in ['unexpired', 'simultaneous', 'mixed-expiry', 'deleted-minimum',
                      'shorter-replacement', 'abort', 'cname', 'backward-time',
                      'negative', 'rrset', 'stale-5', 'stale-forever']:
            stale = 5 if phase == 'stale-5' else -1 if phase == 'stale-forever' else 0
            config = [capacity, 0, 0, stale, 0]
            names, commands = [], ['B']
            for i in range(capacity):
                name = f'n{i:04}.test'
                kind, ttl, negative = 1 if i % 10 < 7 else 28, 120, 0
                if phase in ['simultaneous', 'stale-5', 'stale-forever']:
                    ttl = 1
                elif phase == 'mixed-expiry':
                    ttl = 1 if i % 2 == 0 else 120
                elif phase == 'deleted-minimum' and i == 0:
                    ttl = 1
                elif phase == 'negative':
                    kind, ttl, negative = 65536, 1 if i % 2 == 0 else 30, 1
                elif phase == 'rrset' and i < 3:
                    name, kind = 'rrset.test', 1
                elif phase == 'cname' and i == 0:
                    kind = 5
                names.append((name, kind))
                commands.append(f'I {name} {kind} {ttl} {i % 251} {negative} 100')
            if phase == 'cname':
                commands.append('L 0 1')
            commands.append('C')
            if phase in ['deleted-minimum', 'shorter-replacement']:
                ttl = 120 if phase == 'deleted-minimum' else 1
                commands += ['B', f'I n0000.test 1 {ttl} 99 0 100', 'C']
            if phase == 'cname':
                commands += ['B', 'I n0001.test 1 1 99 0 100', 'C', 'Q n0000.test 5 100 0']
            if phase == 'abort':
                commands += ['B', 'I pending.test 1 120 98 0 100',
                             'I failed.test 1 0 99 0 100', 'C', 'Q pending.test 1 100 0',
                             'B', 'I replacement.test 1 120 97 0 100', 'C']
            times = [100, 100, 100, 100] if phase == 'unexpired' else [101, 102, 106, 107]
            if phase == 'backward-time':
                times = [120, 90, 91, 150]
            if phase == 'stale-5':
                times = [100, 101, 105, 106]
            for i, now in enumerate(times):
                name = f'pressure{i}.test'
                commands += ['B', f'I {name} 1 {1 if phase == "backward-time" else 120} {i + 1} 0 {now}', 'C']
                commands += queries(names[:4] + [(name, 1)], now)
            commands += queries(names, times[-1])
            yield f'{phase}-{capacity}', config, commands


def differences(expected, actual):
    if len(expected) != len(actual):
        return [{'error': 'row-count', 'expected': len(expected), 'actual': len(actual)}]
    return [{'line': i, 'expected_c': left, 'actual': right}
            for i, (left, right) in enumerate(zip(expected, actual)) if left != right]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to((ROOT / 'private').resolve()):
        raise ValueError('raw output must be under ignored private/')
    out.mkdir(parents=True, exist_ok=False)
    snapshot = out / 'source-snapshot'
    source_hashes = {}
    for name in ['cache.rs', 'wire.rs']:
        relative = f'components/dnsmasq/src/dns/{name}'
        data = subprocess.run(['git', 'show', f'{BASELINE}:{relative}'], cwd=ROOT,
                              capture_output=True, check=True).stdout
        source_hashes[relative] = digest(data)
        if name == 'cache.rs' and digest(data) != CACHE_SHA:
            raise ValueError('frozen baseline cache identity')
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    vectors = []
    for name, config, commands in scenarios():
        data = ('\n'.join(commands) + '\n').encode()
        (out / f'{name}.input').write_bytes(data)
        vectors.append({'name': name, 'config': config, 'commands': len(commands),
                        'input_sha256': digest(data)})
    manifest = {'scope': 'exact-source C primitive pressure gate; no candidate, timings or full-daemon claim',
                'baseline_git': BASELINE, 'rust_source_sha256': source_hashes,
                'tool_sha256': digest(Path(__file__).read_bytes()),
                'plan_sha256': digest((ROOT / 'docs/dnsmasq/CACHE_EXPIRY_SCREEN_V1.md').read_bytes()),
                'cases': vectors, 'status': 'prepared'}
    write_json(out / 'manifest.json', manifest)
    if args.prepare_only:
        print(json.dumps({'status': 'prepared', 'scenarios': len(vectors)}))
        return 0

    reference.ROOT = snapshot  # The imported builder now points only at frozen Rust inputs.
    manifest['c_source_sha256'] = reference.build(out, args.rustc)
    manifest['binary_sha256'] = {name: digest((out / name).read_bytes()) for name in ['oracle', 'driver']}
    manifest['compiler'] = subprocess.run([args.rustc, '--version'], capture_output=True, text=True, check=True).stdout.strip()
    layout = f'''#[path={json.dumps(str(snapshot / "components/dnsmasq/src/dns/wire.rs"))}] mod wire;
#[path={json.dumps(str(snapshot / "components/dnsmasq/src/dns/cache.rs"))}] mod cache;
fn main() {{ println!("{{}} {{}} {{}}", std::mem::size_of::<cache::Cache>(), std::mem::size_of::<cache::Entry>(), std::mem::size_of::<i64>()); }}
'''
    (out / 'layout.rs').write_text(layout)
    subprocess.run([args.rustc, '--edition=2021', '-A', 'dead_code', str(out / 'layout.rs'), '-o', str(out / 'layout')], check=True)
    sizes = subprocess.run([str(out / 'layout')], capture_output=True, text=True, check=True).stdout.split()
    manifest['baseline_layout_bytes'] = dict(zip(['Cache', 'Entry', 'proposed_bound_payload'], map(int, sizes)))
    results, errors = [], []
    for vector in vectors:
        name, config = vector['name'], vector['config']
        inputs = (out / f'{name}.input').read_text()
        observed = []
        for run_name, binary in [('c1', 'oracle'), ('c2', 'oracle'), ('c3', 'oracle'), ('baseline-rust', 'driver')]:
            run = subprocess.run([str(out / binary), *map(str, config)], input=inputs, capture_output=True, text=True)
            (out / f'{name}.{run_name}.stdout').write_text(run.stdout)
            (out / f'{name}.{run_name}.stderr').write_text(run.stderr)
            if run.returncode or len(run.stdout.splitlines()) != vector['commands']:
                raise RuntimeError(f'{name}/{run_name}: exit {run.returncode}, rows {len(run.stdout.splitlines())}')
            observed.append(run.stdout.splitlines())
        if name == 'calibration':
            expected = ['B', 'I 1', 'C 1', 'Q 1:7:0:102:2:0', 'Q', 'B', 'I 0', 'C 0', 'B', 'I 1', 'L 0', 'C 1', 'Q']
            if any(differences(expected, value) for value in observed):
                raise RuntimeError('known success/failure/expiry calibration failed')
            changed = observed[0].copy()
            changed[3] = 'Q 1:8:0:102:2:0'
            if not differences(observed[0], changed):
                raise RuntimeError('deliberate wrong-data comparison passed')
        stability = differences(observed[0], observed[1]) + differences(observed[0], observed[2])
        mismatch = differences(observed[0], observed[3])
        results.append({'name': name, 'commands': vector['commands'], 'c_repeat_mismatches': len(stability),
                        'c_rust_mismatches': len(mismatch), 'status': 'failed' if stability or mismatch else 'passed'})
        errors.extend({'scenario': name, 'comparison': comparison, **item}
                      for comparison, values in [('C/C', stability), ('C/Rust', mismatch)] for item in values)
    manifest.update(status='failed' if errors else 'passed', results=results,
                    commands_per_implementation=sum(vector['commands'] for vector in vectors),
                    mismatches=len(errors), normalization='none', deliberate_wrong_data_rejected=True)
    write_json(out / 'mismatches.json', errors)
    write_json(out / 'manifest.json', manifest)
    print(json.dumps({key: manifest[key] for key in ['status', 'commands_per_implementation', 'mismatches', 'baseline_layout_bytes']}))
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
