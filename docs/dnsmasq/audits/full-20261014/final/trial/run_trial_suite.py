#!/usr/bin/env python3
"""Repeat the original 12 trial cases using the frozen final ELF and tools."""
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import signal
import subprocess
import time

BASE = Path('/dev/shm/full-final-trial-20261014/private')
FROZEN = Path('/dev/shm/full-integrated-fix-20261014/private')
TOOLS = FROZEN / 'source-final/tools/dnsmasq'
ELF = FROZEN / 'release-final/dnsmasq-rs'
EXPECTED_SHA256 = 'fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b'
SOURCE_COMMIT = '19bd6162e1b33c92a1e5ea26e864497800c7cfed'
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
CASES = ('confirm-rollback', 'deadline', 'crash', 'hang', 'watch-killed',
         'partial-rollback', 'reload', 'rollback-killed',
         'confirmed-rollback-killed', 'rollback-cleanup-killed',
         'rollback-c-dns-loss', 'documented-path')


def now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def identity():
    return {
        'candidate_sha256': sha256(ELF),
        'stock_sha256': sha256(IMAGE / 'usr/sbin/dnsmasq'),
        'tools_sha256': {str(path.relative_to(TOOLS)): sha256(path)
            for path in sorted(TOOLS.rglob('*'))
            if path.is_file() and '__pycache__' not in path.parts},
    }


def run(case):
    out = BASE / ('trial-' + case)
    argv = ['env', 'PYTHONPATH=' + str(TOOLS), 'sh', str(TOOLS / 'run_isolated.sh'),
            'python3', str(TOOLS / 'actual_config_network.py'),
            '--source-root', str(BASE / 'trial-network-source'),
            '--router-cidr', '192.168.1.1/24', '--output', str(out) + '-network',
            '--', 'python3', str(TOOLS / 'test_trial_oracle.py'),
            '--image-root', str(IMAGE), '--rust-binary', str(ELF),
            '--trial', str(TOOLS / 'deploy/dnsmasq-trial'), '--case', case,
            '--output', str(out)]
    write_json(BASE / ('trial-' + case + '.command.json'), argv)
    row = {'case': case, 'started_at': now(), 'argv': argv, 'timeout_seconds': 210}
    start = time.monotonic()
    with (BASE / ('trial-' + case + '.log')).open('x') as log:
        try:
            process = subprocess.Popen(argv, stdout=log, stderr=log,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), start_new_session=True)
            try:
                row['exit'] = process.wait(timeout=210)
            except subprocess.TimeoutExpired:
                row['timeout'] = True
                os.killpg(process.pid, signal.SIGKILL)
                row['exit'] = process.wait(timeout=10)
        except Exception as error:
            row['runner_error'] = repr(error)
            row.setdefault('exit', None)
    row.update(finished_at=now(), elapsed_seconds=round(time.monotonic() - start, 3))
    result = out / 'result.json'
    if result.exists():
        report = json.loads(result.read_text())
        row.update(passed=report['passed'], error=report.get('error'),
                   fault=report.get('fault'), result_sha256=sha256(result),
                   candidate_sha256=report.get('candidate_sha256'),
                   stock_sha256=report.get('stock_sha256'),
                   trial_sha256=report.get('trial_sha256'))
    else:
        row['passed'] = False
        row['missing_result'] = True
    row['same_elf'] = row.get('candidate_sha256') == EXPECTED_SHA256
    write_json(BASE / ('trial-' + case + '.receipt.json'), row)
    print(json.dumps({key: value for key, value in row.items() if key != 'argv'}), flush=True)
    return row


def main():
    BASE.mkdir(parents=True, exist_ok=True)
    source = BASE / 'trial-network-source/tmp/resolv.conf.d'
    source.mkdir(parents=True, exist_ok=False)
    (source / 'resolv.conf.auto').write_text('')
    pre = identity()
    assert pre['candidate_sha256'] == EXPECTED_SHA256, pre['candidate_sha256']
    write_json(BASE / 'preflight.json', dict(pre, recorded_at=now(),
        source_commit=SOURCE_COMMIT, source_path=str(FROZEN / 'source-final'),
        candidate_path=str(ELF), image_root=str(IMAGE), max_workers=2,
        driver_sha256=sha256(Path(__file__)), cases=CASES))
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(run, CASES))
    post = identity()
    write_json(BASE / 'postflight.json', dict(post, recorded_at=now(),
        unchanged=post == pre))
    passed = post == pre and all(row['exit'] == 0 and row['passed'] and row['same_elf'] for row in rows)
    write_json(BASE / 'trial-suite.json', {'passed': passed, 'cases': rows,
        'identities_unchanged': post == pre, 'source_commit': SOURCE_COMMIT,
        'candidate_sha256': EXPECTED_SHA256})
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
