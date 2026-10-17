#!/usr/bin/env python3
"""Run the existing gates once, serial stages, against one CI-bound ELF."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/srv/owrt-archive/dnsmasq-work')
BASE = ROOT / 'private/fork-a97edbc1'
NEW_ROOT = Path('/srv/owrt-archive/unified-work')
SOURCE = NEW_ROOT / 'source-e21245d2'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
out = Path(sys.argv[1]).resolve()
assert out.is_relative_to(NEW_ROOT / "private") and not (out / 'qualification.json').exists()
preparation = json.loads((out / 'preparation.json').read_text())
built = json.loads((out / 'input/build.json').read_text())
assert sha(out / 'input/build.json') == preparation['build_adapter_sha256']
assert sha(out / 'input/dnsmasq-rs') == preparation['elf_sha256']
assert preparation['status'] == 'prepared-not-executed'
for name, row in preparation['adapted_tools'].items():
    assert sha(out / name) == row['adapted_sha256']
assert sha(out / 'run_family_gates.py') == preparation['family_runner_sha256']
report = {'status': 'running', 'source_commit': built['source_commit'], 'source_digest': built['source_digest'],
          'elf_sha256': preparation['elf_sha256'], 'apk_sha256': built['artifact']['sha256'],
          'ci_provenance': built['provenance'], 'preparation_sha256': sha(out / 'preparation.json'),
          'commands': [], 'receipts': {}, 'physical_router_touched': False}


def save():
    (out / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')


def run(name, argv):
    row = {'name': name, 'argv': argv, 'start_epoch': time.time()}
    report['commands'].append(row)
    save()
    with (out / (name + '.controller.log')).open('x') as log:
        result = subprocess.run(argv, stdout=log, stderr=log)
    row.update(returncode=result.returncode, end_epoch=time.time())
    save()
    assert result.returncode == 0, name + ' command failed; original failure retained; stop'


def receipt(name, path):
    report['receipts'][name] = {'path': str(path), 'sha256': sha(path)}
    return json.loads(path.read_text())


save()
try:
    native = receipt('native', NEW_ROOT / 'private/dnsmasq-native/summary.json')
    assert native['status'] == 'passed' and native['passed_tests'] == 988
    assert native['commit'] == built['source_commit'] and native['source_digest'] == built['source_digest']
    reuse = receipt('source-corpus-reuse', NEW_ROOT / 'private/corpus-reuse.json')
    assert reuse['integrated_product_commit'] == built['source_commit'] and reuse['groups'] == 8
    assert reuse['strict_passed'] == 7 and reuse['known_C_layout_difference_groups'] == 1
    run('runtime', ['python3', str(out / 'runtime/run.py')])
    runtime = receipt('runtime', out / 'runtime/batch-result.json')
    assert runtime['status'] == 'completed' and runtime['regressions_against_k'] == [] and runtime['resolver4_passed']
    candidate = [r for r in runtime['pressure_rows'] if r['role'] == 'candidate']
    assert len(candidate) == 8
    assert all(r['passed'] for r in candidate if r['mode'] == 'resolver')
    run('shipping', ['sudo', '-n', 'env', 'DNSMASQ_TEST_ISOLATED=1', 'unshare', '--mount', '--net',
                    'sh', '-c', 'mount --make-rprivate / && ip link set lo up && exec "$@"',
                    'isolated', 'python3', str(out / 'run_shipping.py')])
    shipping = receipt('shipping', out / 'shipping/result.json')
    assert shipping['status'] == 'passed-existing-shipping-runtime'
    assert shipping['elf_sha256'] == report['elf_sha256'] and shipping['apk_sha256'] == report['apk_sha256']
    run('families', ['python3', str(out / 'run_family_gates.py'), '--source', str(SOURCE),
                    '--elf', str(out / 'input/dnsmasq-rs'), '--link-map', str(out / 'input/link.map'),
                    '--commit', built['source_commit'], '--base-identity',
                    str(ROOT / 'private/correctness-inputs/family-base-v022-root.json'),
                    '--out', str(out / 'families'), '--jobs', '3'])
    families = receipt('families', out / 'families/result.json')
    assert families['passed'] and len(families['families']) == 44 and families['completed_jobs'] == 67
    run('startup', ['sudo', '-n', 'python3', str(out / 'startup/run_preview.py')])
    startup = receipt('startup', out / 'startup/preview-result.json')
    assert startup['status'] == 'passed-tool-preview' and startup['starts'] == 40
    assert startup['observer_sha256'] == '7de91a0c55b4e4137b4a243c4374f1fbedb1b3a8039bb23548368fd1dc8c8e0b'
    assert sha(out / 'input/dnsmasq-rs') == report['elf_sha256']
    report.update(status='qualified-actual-canonical-ci-elf', families=44, jobs=67, startup_starts=40,
                  native_integrated_checks=988, source_corpus_groups_reused=8,
                  performance_acceptance='pending-unified-device-qualification', release_qualified=False)
except BaseException as error:
    report.update(status='failed-preserved', error=repr(error))
    raise
finally:
    save()
    print(json.dumps({k: report[k] for k in ('status', 'elf_sha256', 'receipts')}), flush=True)
