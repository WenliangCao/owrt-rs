#!/usr/bin/env python3
"""Fresh release with its actual linker map, plus complete ordinary units."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--phase', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'[a-z][a-z0-9-]*', args.phase)
    root, phase = args.root.resolve(), args.phase
    source, private = root / ('source-' + phase), root / 'private'
    identity_path = private / ('source-' + phase + '-identity.json')
    identity = json.loads(identity_path.read_text())
    spec = importlib.util.spec_from_file_location('package_build', source / 'tools/dnsmasq/build_package.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    assert package.inputs(source) == identity['source_files']
    path = private / ('build-' + phase + '-result.json')
    assert not path.exists()
    report = {'source_commit': identity['source_commit'], 'source_digest': identity['source_digest'],
              'source_identity_sha256': sha(identity_path), 'controller_sha256': sha(__file__),
              'phase': phase, 'commands': [], 'passed': False, 'started': time.time()}

    def save():
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(path)

    def run(name, argv, *, link_map=False):
        log = private / (phase + '-' + name + '.driver.log')
        row = {'name': name, 'argv': list(map(str, argv)), 'link_map': link_map, 'started': time.time()}
        report['commands'].append(row)
        save()
        env = os.environ.copy()
        env['ORACLE_BUILD_LINK_MAP'] = '1' if link_map else '0'
        with log.open('xb') as stream:
            process = subprocess.run(row['argv'], stdout=stream, stderr=stream, env=env, timeout=1800)
        row.update(returncode=process.returncode, elapsed_seconds=time.time() - row['started'],
                   log_path=str(log), log_sha256=sha(log))
        save()
        print(json.dumps(row), flush=True)
        assert process.returncode == 0, name
        return row

    save()
    try:
        for kind in ('release', 'tests'):
            destination = private / (kind + '-' + phase)
            run(kind + '-build', ['sh', source / 'tools/dnsmasq/oracle_build.sh', source, destination, kind], link_map=kind == 'release')
            report[kind] = json.loads((destination / 'build.json').read_text())
        counts = []
        for name in ('lib-dnsmasq_rs', 'bin-dnsmasq-rs'):
            binary = private / ('tests-' + phase) / name
            row = run(name, ['sudo', '-n', 'sh', source / 'tools/dnsmasq/run_isolated.sh', 'sh', '-c',
                             'mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"', 'unit', binary, '--test-threads=1'])
            match = re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', Path(row['log_path']).read_text())
            assert match, name
            row['counts'] = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), map(int, match.groups())))
            row['elf_sha256'] = sha(binary)
            counts.append(row['counts'])
        report['ordinary_units'] = {key: sum(row[key] for row in counts) for key in counts[0]}
        assert report['ordinary_units']['passed'] >= 846 and report['ordinary_units']['failed'] == 0
        assert package.inputs(source) == identity['source_files']
        assert sha(private / ('release-' + phase) / 'link.map') == report['release']['link_map']['sha256']
        report['passed'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['ended'] = time.time()
        save()


if __name__ == '__main__':
    main()
