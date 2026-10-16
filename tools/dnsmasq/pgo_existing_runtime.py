#!/usr/bin/env python3
"""Smoke existing E/PGO use artifacts in the original isolated namespace."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


plan_path = Path(sys.argv[1])
plan = json.loads(plan_path.read_text())
assert sha(plan_path) == sys.argv[2]
assert os.getuid() == 0 and os.getpid() == 1
assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
assert os.readlink('/proc/self/ns/net') != sys.argv[3]
assert os.readlink('/proc/self/ns/mnt') != sys.argv[4]
helper_path = Path(plan['existing_smoke_helper']['path'])
assert sha(helper_path) == plan['existing_smoke_helper']['sha256']
spec = importlib.util.spec_from_file_location('original_smoke', helper_path)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
signal.signal(signal.SIGTERM, helper.interrupted)
signal.signal(signal.SIGINT, helper.interrupted)
out = Path(plan['output'])
out.mkdir()
result = {'status': 'running', 'plan_sha256': sha(plan_path), 'sides': {},
          'performance_window': False, 'budget_exception': 'diagnostic execution only'}
builds = {}
try:
    for side, identity in plan['artifacts'].items():
        base = Path(identity['directory'])
        for name, digest in identity['files'].items():
            assert sha(base / name) == digest, (side, name)
        built = json.loads((base / 'build.json').read_text())
        assert built['source_commit'] == plan['source_commit'] and built['source_unchanged']
        assert built['elf_layout'] == plan['static_elf_layout']
        builds[side] = built
    for key in ('source_files', 'source_digest', 'source_date_epoch', 'toolchain', 'features', 'opt_level'):
        assert builds['E'][key] == builds['PGO'][key], key
    assert len(builds['E']['source_files']) == 179
    assert sha(plan['training_profile']['path']) == plan['training_profile']['sha256']
    for side, identity in plan['artifacts'].items():
        folder = out / side
        folder.mkdir()
        elf = Path(identity['directory']) / 'dnsmasq-rs'
        config = folder / 'config'
        config.write_text('\n'.join(plan['config_lines'] + ['pid-file=' + str(folder / 'daemon.pid')]) + '\n')
        row = {'elf_sha256': sha(elf), 'queries': [], 'status': 'starting'}
        result['sides'][side] = row
        process = None
        try:
            with (folder / 'stdout').open('xb') as stdout, (folder / 'stderr').open('xb') as stderr:
                process = subprocess.Popen([str(elf), '--keep-in-foreground', '--conf-file=' + str(config)],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
                deadline = time.monotonic() + 10
                while True:
                    assert process.poll() is None, 'daemon exited before readiness'
                    try:
                        row['queries'].append(helper.query(plan['queries'][0], 0x5047))
                        break
                    except (socket.timeout, ConnectionRefusedError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError('readiness timeout')
                        time.sleep(0.05)
                row['queries'].append(helper.query(plan['queries'][1], 0x5048))
                assert sha('/proc/' + str(process.pid) + '/exe') == identity['files']['dnsmasq-rs']
                maps_text = Path('/proc/' + str(process.pid) + '/maps').read_text()
                (folder / 'maps').write_text(maps_text)
                maps = []
                for line in maps_text.splitlines():
                    fields = line.split(maxsplit=5)
                    start, end = [int(value, 16) for value in fields[0].split('-')]
                    path = fields[5] if len(fields) == 6 else ''
                    maps.append({'start': start, 'end': end, 'offset': int(fields[2], 16),
                                 'permissions': fields[1], 'path': path, 'main': path == str(elf)})
                row['protections'] = helper.protections(elf.read_bytes(), maps, os.sysconf('SC_PAGE_SIZE'))
                process.send_signal(signal.SIGTERM)
                row['exit_status'] = process.wait(timeout=10)
                assert row['exit_status'] == 0
                row['status'] = 'passed'
        finally:
            if process is not None:
                row['forced_cleanup'] = helper.group_exists(process.pid)
                row['cleanup'] = helper.stop_group(process)
            row['raw_files'] = {f.name: sha(f) for f in folder.iterdir() if f.is_file()}
        assert not row['forced_cleanup']
    assert result['sides']['E']['queries'] == result['sides']['PGO']['queries']
    result['status'] = 'PASS_EXISTING_E_PGO_STARTUP_TWO_QUERIES_RUNTIME_PROTECTIONS_NORMAL_EXIT'
except BaseException as error:
    result.update(status='failed', error=repr(error))
    raise
finally:
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'output': str(out)}), flush=True)
