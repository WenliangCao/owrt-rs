#!/usr/bin/env python3
"""Compare the opt-in Rust cache transfer primitive with frozen independent C.

The ignored driver seeds separate owners from common commands. It selects no
snapshot representation and creates no transport/resolver or production CLI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PLAN_SHA = "7502e674a279a3c784062a69fa30ce101644553ebdbf015bfbec704565632fff"
IDENTITY_SHA = "96fc7eed20067ebc134853620a799aa4a779afdcdf0fdb306815740c339dc941"
STDOUT_DIGEST = "6624663c148bea679075197a0a3d0847673513893620a217094c7fb66e5eb43b"
TEST = "dns::cache::transfer_tests::exact_c_transfer_probe"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("observation count mismatch")
    return [dict(row=index, c=c, rust=rust) for index, (c, rust) in enumerate(zip(expected, actual)) if c != rust]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--target")
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    baseline, out = args.baseline.resolve(), args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    assert sha(baseline / "plan.json") == PLAN_SHA
    assert sha(baseline / "identity.json") == IDENTITY_SHA
    traces = {str(path.relative_to(baseline)): sha(path)
              for path in sorted(baseline.glob('*/*.stdout')) if path.parent.name != 'target-objects'}
    assert len(traces) == 216
    assert hashlib.sha256(json.dumps(traces, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == STDOUT_DIGEST
    identity = json.loads((baseline / "identity.json").read_text())
    for label in ['native', 'target']:
        assert sha(baseline / f'{label}-oracle') == identity[f'{label}_oracle_sha256']
    schedule = json.loads((baseline / "plan.json").read_text())
    reference = {}
    for case in schedule:
        traces = [(baseline / case['label'] / f'{label}-{repeat}.stdout').read_text().splitlines()
                  for label in ['native', 'target'] for repeat in range(3)]
        assert all(trace == traces[0] for trace in traces)
        assert all(json.loads((baseline / case['label'] / f'{label}-{repeat}.command.json').read_text())['exit'] == 0
                   for label in ['native', 'target'] for repeat in range(3))
        reference[case['label']] = traces[0]
    assert len(schedule) == 36 and sum(map(len, reference.values())) == 307
    calibration = next(iter(reference.values()))
    assert compare(calibration, calibration) == []
    changed = calibration.copy()
    changed[-1] = changed[-1].replace('| 1 0', '| 2 0')
    assert len(compare(calibration, changed)) == 1
    try:
        compare(calibration, calibration[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError('short count accepted')
    sources = {str(path.relative_to(ROOT)): sha(path)
               for component in ['dnsmasq', 'ubus']
               for path in (ROOT / 'components' / component).rglob('*')
               if path.is_file() and 'target' not in path.parts and
               (path.suffix == '.rs' or path.name in ['Cargo.toml', 'Cargo.lock'])}
    command = [args.cargo, '+1.98.1', 'test', '--manifest-path', str(ROOT / 'components/dnsmasq/Cargo.toml'),
               '--lib', '--no-run', '--message-format=json', '--target-dir', str(out / 'target')]
    if args.target:
        command += ['--target', args.target]
    build = subprocess.run(command, text=True, capture_output=True)
    (out / 'build.stdout').write_text(build.stdout)
    (out / 'build.stderr').write_text(build.stderr)
    (out / 'build-command.json').write_text(json.dumps({'argv': command, 'exit': build.returncode}, indent=2) + '\n')
    assert build.returncode == 0, 'build failed; retained stderr'
    executables = []
    for line in build.stdout.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable') and row.get('profile', {}).get('test'):
            executables.append(Path(row['executable']))
    assert len(executables) == 1
    probe = executables[0]
    report = {'scope': __doc__, 'baseline_identity_sha256': IDENTITY_SHA, 'plan_sha256': PLAN_SHA,
              'baseline_stdout_digest': STDOUT_DIGEST,
              'source_files': sources, 'tool_sha256': sha(Path(__file__)), 'probe_sha256': sha(probe),
              'target': args.target, 'calibration': {'equal': 1, 'counter_mutation_detected': 1, 'short_count_rejected': 1},
              'inject_error': args.inject_error, 'cases': [], 'failures': []}
    for index, case in enumerate(schedule):
        env = dict(os.environ, DNSMASQ_CACHE_TRANSFER_CASE=str(baseline / case['label']),
                   DNSMASQ_CACHE_TRANSFER_NOW=str(case['now']))
        command = [str(probe), TEST, '--ignored', '--exact', '--nocapture', '--test-threads=1']
        run = subprocess.run(command, env=env, text=True, capture_output=True)
        (out / f"{case['label']}.stdout").write_text(run.stdout)
        (out / f"{case['label']}.stderr").write_text(run.stderr)
        assert run.returncode == 0, (case['label'], run.returncode)
        actual = [line for line in run.stdout.splitlines() if line.startswith(('P0 ', 'P1 ', 'R ', 'CH ', 'P2 '))]
        expected = reference[case['label']].copy()
        if args.inject_error and index == 0:
            expected[-1] = expected[-1].replace('| 1 0', '| 2 0')
        failures = compare(expected, actual)
        report['cases'].append({'case': case['label'], 'observations': len(actual), 'failed': len(failures), 'exit': run.returncode})
        report['failures'] += [{'case': case['label'], **failure} for failure in failures]
    assert sources == {name: sha(ROOT / name) for name in sources}
    report['compared'] = sum(row['observations'] for row in report['cases'])
    report['failed'] = len(report['failures'])
    report['passed'] = report['compared'] - report['failed']
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['compared', 'passed', 'failed', 'target', 'inject_error']}))
    return bool(report['failed'])


if __name__ == '__main__':
    raise SystemExit(main())
