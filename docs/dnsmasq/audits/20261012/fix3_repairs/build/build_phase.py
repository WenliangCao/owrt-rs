#!/usr/bin/env python3
"""Frozen source release, ordinary units, and two actual clean SDK builds."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path('/home/ubuntu/dnsmasq-fix3-repair-20261013')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, report):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]*', args.phase):
        raise ValueError('simple phase label required')
    phase = args.phase
    SOURCE = ROOT / f'source-{phase}'
    PRIVATE = ROOT / 'private'
    SDK = PRIVATE / 'sdk-isolated/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64'
    REPORT = PRIVATE / f'build-{phase}-result.json'
    if REPORT.exists():raise ValueError('fresh build result required')
    identity = json.loads((PRIVATE / f'source-{phase}-identity.json').read_text())
    spec = importlib.util.spec_from_file_location('package_build', SOURCE / 'tools/dnsmasq/build_package.py')
    package = importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
    if package.inputs(SOURCE) != identity['source_files']:raise ValueError('source inputs changed before build')
    report = dict(phase=phase, source_commit=identity['source_commit'], source_digest=identity['source_digest'],
        source_date_epoch=identity['source_date_epoch'], controller_sha256=sha(__file__),
        identity_sha256=sha(PRIVATE / f'source-{phase}-identity.json'), sdk_driver_sha256=sha(PRIVATE / 'sdk_source_build.py'),
        commands=[], passed=False)
    save(REPORT, report)
    def run(name, argv, timeout=1800):
        row = dict(name=name, argv=list(map(str, argv)), started=time.time())
        report['commands'].append(row);save(REPORT, report)
        log = PRIVATE / (phase + '-' + name + '.driver.log')
        with log.open('wb') as stream:
            process = subprocess.run(row['argv'], stdout=stream, stderr=stream, timeout=timeout)
        row.update(returncode=process.returncode, elapsed_seconds=time.time()-row['started'],
                   log_path=str(log), log_sha256=sha(log));save(REPORT, report)
        print(json.dumps({key:row[key] for key in ('name','returncode','elapsed_seconds')}), flush=True)
        return row
    try:
        for kind in ('release', 'tests'):
            destination = PRIVATE / f'{kind}-{phase}'
            row = run(kind + '-build', ['sh', SOURCE / 'tools/dnsmasq/oracle_build.sh', SOURCE, destination, kind])
            if row['returncode']:raise ValueError(kind + ' build failed')
            row['build_receipt_sha256'] = sha(destination / 'build.json');save(REPORT, report)
        counts = []
        for name in ('lib-dnsmasq_rs', 'bin-dnsmasq-rs'):
            binary = PRIVATE / f'tests-{phase}' / name
            row = run(name, ['sudo', '-n', 'sh', SOURCE / 'tools/dnsmasq/run_isolated.sh',
                'sh', '-c', 'mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"', 'unit', binary, '--test-threads=1'], 900)
            if row['returncode']:raise ValueError(name + ' ordinary units failed')
            text = Path(row['log_path']).read_text()
            match = re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', text)
            if not match:raise ValueError('unit summary missing')
            row['counts'] = dict(zip(('passed','failed','ignored','measured','filtered_out'),map(int,match.groups())))
            row['elf_sha256'] = sha(binary);counts.append(row['counts']);save(REPORT, report)
        report['ordinary_units'] = {key:sum(row[key] for row in counts) for key in counts[0]};save(REPORT, report)
        common = ['python3', PRIVATE / 'sdk_source_build.py', '--source', SOURCE, '--sdk', SDK,
            '--workspace', PRIVATE / f'sdk-workspace-{phase}', '--source-commit', identity['source_commit'],
            '--source-date-epoch', str(identity['source_date_epoch']), '--expected-source-digest', identity['source_digest']]
        acquire = run('sdk-acquire', common + ['--out', PRIVATE / f'sdk-acquire-{phase}', '--acquire'])
        first = json.loads((PRIVATE / f'sdk-acquire-{phase}/manifest.json').read_text())
        if not first.get('source_build_passed') or first.get('error'):raise ValueError('standard SDK source build failed')
        if acquire['returncode'] != (1 if first.get('budget_error') else 0):raise ValueError('unexpected SDK acquisition exit')
        acquire['manifest_sha256'] = sha(PRIVATE / f'sdk-acquire-{phase}/manifest.json');save(REPORT, report)
        verify = run('sdk-verify', common + ['--out', PRIVATE / f'sdk-verify-{phase}', '--expected-elf-sha256', first['elf']['sha256'], '--link-map'])
        second = json.loads((PRIVATE / f'sdk-verify-{phase}/manifest.json').read_text())
        if not second.get('artifact_identity_verified') or not second.get('apk_byte_identical') or second.get('error'):
            raise ValueError('clean SDK map rebuild identity failed; never use mismatching map')
        if verify['returncode'] != (1 if second.get('budget_error') else 0):raise ValueError('unexpected SDK verify exit')
        verify['manifest_sha256'] = sha(PRIVATE / f'sdk-verify-{phase}/manifest.json')
        if package.inputs(SOURCE) != identity['source_files']:raise ValueError('source inputs changed during build')
        report.update(passed=True, sdk_elf_sha256=first['elf']['sha256'], sdk_apk_sha256=first['artifact']['sha256'],
            sdk_elf_bytes=first['elf']['size'], sdk_apk_bytes=first['artifact']['size'],
            original_budget_passed=not first.get('budget_error'), exact_sdk_link_map=second['link_map'],
            map_build_elf_and_apk_identical_to_standard=True)
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['ended'] = time.time();save(REPORT, report)


if __name__ == '__main__':main()
