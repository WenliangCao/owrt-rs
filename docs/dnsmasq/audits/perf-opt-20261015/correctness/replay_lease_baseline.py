#!/usr/bin/env python3
"""Replay original v0.2.0 test ELF against every unchanged lease corpus input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'driver', 'build-receipt', 'c-baseline', 'freeze', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and not sys.flags.optimize
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    frozen = json.loads(args.freeze.read_text())
    build = json.loads(args.build_receipt.read_text())
    assert build['source'] == str(args.source.resolve()) and build['kind'] == 'tests'
    driver_sha = sha(args.driver)
    assert driver_sha == '227989d2164f3006e8f86ccb84b06ce821c976388d4ff185c224dabf34aaab52'
    assert any(row['path'] == args.driver.name and row['sha256'] == driver_sha for row in build['artifacts'])
    source_files = {name: spec['sha256'] for name, spec in frozen['files'].items()
                    if name.startswith(('components/dnsmasq/', 'components/ubus/', 'tools/dnsmasq/'))}
    for name, digest in source_files.items():
        assert sha(args.source / name) == digest, name
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    import lease_names_diff
    import rust_lib_probe
    identity = json.loads((args.c_baseline / 'result.json').read_text())
    assert identity['cases'] == 36 and not identity['failures']
    assert sha(args.c_baseline / 'local-answer-oracle') == identity['c_oracle_sha256']
    command = [str(args.driver), 'dns::daemon::lease_cache_tests::exact_c_lease_cache_driver',
               '--ignored', '--exact', '--nocapture', '--test-threads=1']
    rows, differences = [], []
    for case in identity['rows']:
        number = case['case']
        for suffix in ['input', 'conf']:
            shutil.copy2(args.c_baseline / f'{number:02}.{suffix}', args.out / f'{number:02}.{suffix}')
        env = {**os.environ, 'DNSMASQ_LEASE_CACHE_CONFIG': str(args.out / f'{number:02}.conf'),
               'DNSMASQ_LEASE_CACHE_INPUT': str(args.out / f'{number:02}.input')}
        run = subprocess.run(command, capture_output=True, text=True, env=env)
        (args.out / f'{number:02}.rust.stdout').write_text(run.stdout)
        (args.out / f'{number:02}.rust.stderr').write_text(run.stderr)
        assert run.returncode == 0 and 'test result: ok. 1 passed; 0 failed;' in run.stdout
        commands = (args.out / f'{number:02}.input').read_text().splitlines()
        actual = '\n'.join(line.removeprefix('LEASE_CACHE_ORACLE ') for line in
            rust_lib_probe.records(run.stdout, command[1], 'LEASE_CACHE_ORACLE ')) + '\n'
        c_raw = (args.c_baseline / f'{number:02}.stdout').read_text()
        (args.out / f'{number:02}.c.stdout').write_text(c_raw)
        expected = lease_names_diff.observations(commands, c_raw)
        observed = lease_names_diff.observations(commands, actual)
        for step, (left, right) in enumerate(zip(expected, observed, strict=True)):
            if left != right:
                differences.append({'case': number, 'label': case['label'], 'step': step,
                                    'command': commands[step], 'c': left, 'rust': right})
        rows.append({'case': number, 'label': case['label'], 'commands': len(commands),
                     'input_sha256': sha(args.out / f'{number:02}.input'),
                     'config_sha256': sha(args.out / f'{number:02}.conf'),
                     'c_stdout_sha256': sha(args.out / f'{number:02}.c.stdout'),
                     'rust_stdout_sha256': sha(args.out / f'{number:02}.rust.stdout'),
                     'c_semantics_sha256': canonical_sha(expected),
                     'rust_semantics_sha256': canonical_sha(observed)})
    report = {'scope': 'fresh original v0.2.0 Rust replay; raw C differences are not waived',
              'source_commit': frozen['frozen_source_commit'], 'source_files': source_files,
              'driver_sha256': driver_sha, 'build_receipt_sha256': sha(args.build_receipt),
              'c_baseline_sha256': sha(args.c_baseline / 'result.json'),
              'c_oracle_sha256': identity['c_oracle_sha256'], 'cases': rows,
              'commands': sum(row['commands'] for row in rows), 'mismatches': differences,
              'raw_comparison_passed': not differences}
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(rows), 'commands': report['commands'],
                      'mismatches': len(differences), 'raw_comparison_passed': not differences}))


if __name__ == '__main__':
    main()
