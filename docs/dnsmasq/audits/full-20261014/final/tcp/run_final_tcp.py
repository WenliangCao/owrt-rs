#!/usr/bin/env python3
"""Re-run the existing TCP acceptance drivers on the frozen combined ELF."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

BASE = Path('/dev/shm/full-final-tcp-20261014/private')
ORIGINAL = Path('/dev/shm/full-integrated-fix-20261014/private')
HELPERS = Path('/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq')
ELF_SHA = 'fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b'
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    assert os.geteuid() == 0
    BASE.mkdir(parents=True)
    (BASE / 'tools').mkdir()
    (BASE / 'release').mkdir()
    shutil.copy2(__file__, BASE / 'run_final_tcp.py')
    origin_elf = ORIGINAL / 'release-final/dnsmasq-rs'
    assert sha(origin_elf) == ELF_SHA
    elf = BASE / 'release/dnsmasq-rs'
    shutil.copy2(origin_elf, elf)
    assert sha(elf) == ELF_SHA
    shutil.copy2(ORIGINAL / 'freeze-19bd-identity.json', BASE / 'source-freeze-identity.json')
    origins = {}
    for name in ('full_tcp_hosts_cgroup.py', 'full_tcp_hosts_memory.py', 'full_tcp_hosts_snapshot.py'):
        source = ORIGINAL / 'tools' / name
        shutil.copy2(source, BASE / 'tools' / name)
        origins[name] = str(source)
    for name in ('run_isolated.sh', 'm2_rootfs.py', 'dns_service_probe.py', 'elf_cost.py'):
        source = HELPERS / name
        shutil.copy2(source, BASE / 'tools' / name)
        origins[name] = str(source)
    identity = {
        'source_commit': '19bd6162', 'elf_origin': str(origin_elf),
        'elf_used': str(elf), 'elf_sha256': ELF_SHA,
        'stock_elf_sha256': sha(IMAGE / 'usr/sbin/dnsmasq'),
        'suite_driver_sha256': sha(__file__),
        'tools': {name: {'sha256': sha(BASE / 'tools' / name), 'origin': origin}
                  for name, origin in origins.items()},
        'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    write(BASE / 'identity.json', identity)
    results = []
    cases = [
        ('tcp64-hup', 'full_tcp_hosts_cgroup.py', ['--budget-mib', '64', '--hup']),
        ('tcp-memory', 'full_tcp_hosts_memory.py', ['--rows', '0,10000,50000']),
        ('tcp-snapshot', 'full_tcp_hosts_snapshot.py', []),
    ]
    for label, script, extra in cases:
        assert sha(elf) == ELF_SHA
        argv = ['env', 'PYTHONPATH=' + str(BASE / 'tools'), 'PYTHONDONTWRITEBYTECODE=1',
                'sh', str(BASE / 'tools/run_isolated.sh'),
                'python3', str(BASE / 'tools' / script),
                '--image-root', str(IMAGE), '--rust', str(elf),
                '--output', str(BASE / label), *extra]
        write(BASE / (label + '.command.json'), argv)
        start = time.monotonic()
        with (BASE / (label + '.log')).open('xb') as log:
            process = subprocess.Popen(argv, stdout=log, stderr=log, start_new_session=True)
            timed_out = False
            try:
                process.wait(timeout=240)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        row = {'case': label, 'exit': process.returncode, 'timed_out': timed_out,
               'seconds': time.monotonic() - start}
        results.append(row)
        write(BASE / 'suite-results.json', results)
        print(json.dumps(row), flush=True)
    assert sha(elf) == ELF_SHA
    raise SystemExit(any(row['exit'] != 0 or row['timed_out'] for row in results))


if __name__ == '__main__':
    main()
