#!/usr/bin/env python3
"""Exact-image startup input family: files, shell output and descendant effects."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, read_name, semantics
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, process_identity, sha256
from m5_option_matrix import descendants, normalized_text

DEPENDENCIES = ['dns_service_probe.py', 'm2_rootfs.py', 'm5_option_matrix.py',
                'm5_option_matrix_probes.py', 'run_isolated.sh']
BASE = ['--no-hosts', '--no-resolv', '--no-0x20-encode', '--no-round-robin',
        '--user=root', '--group=root', '--listen-address=127.0.0.1', '--port=15353',
        '--pid-file=/m2/input/daemon.pid', '--host-record=matrix.ready,8.8.8.8']


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def install(root, case):
    folder = root / 'm2/input'
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    for name in ['effects', 'pids', *case.get('directories', [])]:
        (folder / name).mkdir(parents=True, exist_ok=True)
    default = image_path(root, '/etc/dnsmasq.conf', follow_leaf=False)
    default.unlink(missing_ok=True)
    if 'default' in case:
        default_data = case['default']
        default_data = {'text': default_data} if isinstance(default_data, str) else default_data
        default.write_text(default_data['text'])
        default.chmod(default_data.get('mode', 0o644))
    for name, data in case.get('files', {}).items():
        data = {'text': data} if isinstance(data, str) else data
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data['text'])
        path.chmod(data.get('mode', 0o644))
    for name, target in case.get('hardlinks', {}).items():
        os.link(folder / target, folder / name)
    for name, target in case.get('symlinks', {}).items():
        (folder / name).symlink_to(target)
    return folder


def dns(name, kind, ident, transport):
    wire = query(name, kind, ident)
    if transport == 'udp':
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(.03)
            endpoint.sendto(wire, ('127.0.0.1', 15353))
            response = endpoint.recv(65535)
    else:
        with socket.create_connection(('127.0.0.1', 15353), .3) as endpoint:
            endpoint.sendall(struct.pack('!H', len(wire)) + wire)
            response = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
    if response[:2] != wire[:2]:
        raise AssertionError('DNS client transaction changed')
    result = semantics(response)
    result['question_wire'] = response[12:read_name(response, 12)[1] + 4].hex()
    return result, {'request': wire.hex(), 'response': response.hex(), 'transport': transport}


def processes(pids, start):
    rows = []
    for pid in sorted(pids):
        try:
            raw = Path(f'/proc/{pid}/stat').read_text()
            fields = raw[raw.rindex(')') + 2:].split()
            rows.append({'pid': pid, 'ppid': int(fields[1]), 'pgid': int(fields[2]),
                         'state': fields[0], 'at': time.monotonic() - start,
                         'command': Path(f'/proc/{pid}/cmdline').read_bytes().hex()})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return rows


def run_phase(root, side, case, phase, out):
    out.mkdir()
    folder = install(root, case)
    args = [*([] if case.get('minimal') else BASE), '--test' if phase == 'test' else '-k',
            *case.get('argv', [])]
    executable = '/usr/sbin/dnsmasq' + ('-rs' if side == 'rust' else '')
    argv = command(root, '/bin/sh', '-c', 'cd /m2/input && exec "$@"', 'config-inputs', executable, *args)
    if case.get('userspec'):
        argv.insert(1, '--userspec=' + case['userspec'])
    save(out / 'fixture.json', case)
    save(out / 'command.json', argv)
    start = time.monotonic()
    trace = {'samples': [], 'reaped': {}, 'queries': [], 'stdin': case.get('stdin', ''), 'command': argv}
    observed = {'ready': False, 'exit': None, 'dns': [], 'effects': {}, 'early_dns_reply': False,
                'forced_pids': [], 'live_pids': [], 'pid_file': False}
    owned = set()
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
        process.stdin.write(case.get('stdin', '').encode())
        process.stdin.close()
        owned.add(process.pid)

        def sample():
            owned.update(descendants(root))
            for path in (folder / 'pids').glob('*'):
                try:
                    owned.add(int(path.read_text()))
                except ValueError:
                    pass
            current = processes(owned, start)
            key = [(row['pid'], row['ppid'], row['state']) for row in current]
            if not trace['samples'] or key != trace['samples'][-1]['key']:
                trace['samples'].append({'at': time.monotonic() - start, 'key': key, 'processes': current})
            return current

        try:
            deadline = start + 5
            while time.monotonic() < deadline:
                sample()
                if process.poll() is not None:
                    break
                if phase == 'run':
                    try:
                        answer, raw = dns('matrix.ready', 1, 0x5010, 'udp')
                        if [row['data'] for row in answer['records']] != ['8.8.8.8']:
                            raise AssertionError('wrong readiness answer')
                        trace['queries'].append(raw)
                        observed['ready'] = True
                        trace['identity'] = process_identity(root, process.pid)
                        wanted = sha256(root / executable.lstrip('/'))
                        if trace['identity']['sha256'] != wanted:
                            raise AssertionError('wrong running daemon ELF')
                        if case.get('gate') and not (folder / 'effects' / case['gate']).exists():
                            observed['early_dns_reply'] = True
                        break
                    except socket.timeout:
                        pass
                time.sleep(.01)
            else:
                raise AssertionError('startup/test timeout')
            trace['startup_elapsed'] = time.monotonic() - start
            if case.get('minimum_seconds', 0) > trace['startup_elapsed']:
                raise AssertionError('script wait/slow output was bypassed')
            if observed['ready']:
                for index, probe in enumerate(case.get('probes', [])):
                    for transport in ['udp', 'tcp']:
                        answer, raw = dns(probe['name'], probe.get('type', 1), 0x5100 + index, transport)
                        observed['dns'].append({'id': probe['id'], 'transport': transport, 'response': answer})
                        trace['queries'].append(raw)
                if case.get('hup'):
                    for name, contents in case.get('change_before_hup', {}).items():
                        (folder / name).write_text(contents)
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.05)
                    observed['dns_after_hup'] = []
                    for index, probe in enumerate(case['probes']):
                        for transport in ['udp', 'tcp']:
                            answer, raw = dns(probe['name'], probe.get('type', 1), 0x5100 + index, transport)
                            observed['dns_after_hup'].append({'id': probe['id'], 'transport': transport, 'response': answer})
                            trace['queries'].append(dict(raw, stage='after-HUP'))
                    if observed['dns_after_hup'] != observed['dns']:
                        raise AssertionError('HUP changed startup configuration effects')
                process.send_signal(signal.SIGTERM)
                process.wait(2)
            observed['exit'] = process.poll()
            trace['parent_exit_at'] = time.monotonic() - start
            observed['effects_at_parent_exit'] = sorted(p.name for p in (folder / 'effects').iterdir())
            observed['scripts_at_parent_exit'] = {}
            for path in sorted((folder / 'pids').glob('*')):
                pid = int(path.read_text())
                snapshot = processes({pid}, start)
                observed['scripts_at_parent_exit'][path.name] = bool(snapshot and snapshot[0]['state'] != 'Z')
            # C can exit while a configuration script is still unwinding.
            # Observe the finite fixture naturally before any cleanup signal.
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                sample()
                for pid in owned - {process.pid}:
                    try:
                        reaped, status = os.waitpid(pid, os.WNOHANG)
                        if reaped:
                            trace['reaped'][str(pid)] = status
                    except (ChildProcessError, ProcessLookupError):
                        pass
                if not processes(owned, start):
                    break
                time.sleep(.01)
            observed['live_pids'] = [row['pid'] for row in processes(owned, start)]
        finally:
            for row in processes(owned, start):
                observed['forced_pids'].append(row['pid'])
                try:
                    os.kill(row['pid'], signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.wait(2)
            for pid in owned - {process.pid}:
                try:
                    os.waitpid(pid, 0)
                except (ChildProcessError, ProcessLookupError):
                    pass
            observed['pid_file'] = (folder / 'daemon.pid').exists()
            observed['effects'] = {str(p.relative_to(folder / 'effects')): p.read_bytes().hex()
                                   for p in sorted((folder / 'effects').rglob('*')) if p.is_file()}
            trace['final_processes'] = processes(owned, start)
            trace['duration'] = time.monotonic() - start
            save(out / 'trace.json', trace)
    observed['stdout'] = (out / 'stdout').read_text(errors='backslashreplace')
    observed['stderr'] = (out / 'stderr').read_text(errors='backslashreplace')
    save(out / 'observed.json', observed)
    return observed


def compare(c, rust, case, reference_only=False):
    failures = []
    for phase in ['test', 'run']:
        expected = c[phase]
        if expected['exit'] != case.get('expected_exit', 0):
            failures.append({'phase': phase, 'kind': 'C-calibration-exit', 'actual': expected['exit']})
        wanted_ready = phase == 'run' and case.get('expected_exit', 0) == 0
        if expected['ready'] != wanted_ready:
            failures.append({'phase': phase, 'kind': 'C-calibration-readiness', 'actual': expected['ready']})
        for field in ['effects', 'effects_at_parent_exit', 'scripts_at_parent_exit']:
            if 'expected_' + field in case and expected[field] != case['expected_' + field]:
                failures.append({'phase': phase, 'kind': 'C-calibration-' + field, 'actual': expected[field]})
        sides = [('c', expected)] if reference_only else [('c', expected), ('rust', rust[phase])]
        for side, row in sides:
            if row['forced_pids'] or row['live_pids'] or row['pid_file'] or row['early_dns_reply']:
                failures.append({'phase': phase, 'side': side, 'kind': 'lifecycle', 'actual': row})
        if phase == 'run' and expected['ready']:
            wanted_rows = [(probe['id'], transport) for probe in case['probes'] for transport in ['udp', 'tcp']]
            if [(row['id'], row['transport']) for row in expected['dns']] != wanted_rows:
                failures.append({'phase': phase, 'kind': 'C-calibration-missing-query'})
            for row in expected['dns']:
                probe = next(p for p in case['probes'] if p['id'] == row['id'])
                answers = [r for r in row['response']['records'] if r['section'] == 'answer']
                if 'answers' in probe and [r['data'] for r in answers] != probe['answers']:
                    failures.append({'phase': phase, 'kind': 'C-calibration-answer', 'row': row})
                if 'ttl' in probe and any(r['ttl'] != probe['ttl'] for r in answers):
                    failures.append({'phase': phase, 'kind': 'C-calibration-TTL', 'row': row})
        left, right = copy.deepcopy(expected), copy.deepcopy(rust[phase])
        for row in [left, right]:
            for stream in ['stdout', 'stderr']:
                row[stream] = normalized_text(row[stream])
        if case.get('reference_defect'):
            allowed = (case['id'] == 'null-second-config' and case.get('minimal')
                       and case['argv'] == ['-C', '/m2/input/empty', '-C', '']
                       and case['files'] == {'empty': ''})
            if (not allowed or left['exit'] != -signal.SIGSEGV or left['stderr'] or left['stdout']
                    or left['dns'] or left['effects'] or left['scripts_at_parent_exit']):
                failures.append({'phase': phase, 'kind': 'unclassified-reference-defect'})
            else:
                left['exit'] = 1
                left['stderr'] = '\ndnsmasq: empty additional conf-file\n'
        if not reference_only and left != right:
            failures.append({'phase': phase, 'kind': 'difference', 'c': left, 'rust': right})
    return failures


def controls():
    case = {'probes': [{'id': 'value', 'name': 'value.input', 'answers': ['192.0.2.10'], 'ttl': 17}]}
    base = {'ready': False, 'exit': 0, 'dns': [], 'effects': {'done': '31'},
            'early_dns_reply': False, 'forced_pids': [], 'live_pids': [], 'pid_file': False,
            'stdout': '', 'stderr': '', 'effects_at_parent_exit': ['done'],
            'scripts_at_parent_exit': {'script': False}}
    c = {'test': copy.deepcopy(base), 'run': copy.deepcopy(base)}
    c['run']['ready'] = True
    for transport in ['udp', 'tcp']:
        c['run']['dns'].append({'id': 'value', 'transport': transport, 'response': {
            'records': [{'section': 'answer', 'data': '192.0.2.10', 'ttl': 17}]}})
    assert not compare(c, copy.deepcopy(c), case)
    checks = {}
    for label in ['exit', 'diagnostic', 'missing-query', 'answer', 'ttl', 'effect',
                  'parent-effect-order', 'script-live-at-exit', 'premature-listener', 'leaked-child']:
        bad = copy.deepcopy(c)
        row = bad['run']
        if label == 'exit': bad['test']['exit'] = 1
        elif label == 'diagnostic': bad['test']['stderr'] = 'wrong error\n'
        elif label == 'missing-query': row['dns'].pop()
        elif label == 'answer': row['dns'][0]['response']['records'][0]['data'] = '192.0.2.11'
        elif label == 'ttl': row['dns'][0]['response']['records'][0]['ttl'] = 16
        elif label == 'effect': row['effects'].clear()
        elif label == 'parent-effect-order': row['effects_at_parent_exit'].clear()
        elif label == 'script-live-at-exit': row['scripts_at_parent_exit']['script'] = True
        elif label == 'premature-listener': row['early_dns_reply'] = True
        elif label == 'leaked-child': row['live_pids'] = [123]
        assert compare(c, bad, case), label
        checks[label] = 'detected'
    null_case = {'id': 'null-second-config', 'minimal': True, 'reference_defect': 'NULL strcmp',
                 'expected_exit': -11, 'argv': ['-C', '/m2/input/empty', '-C', ''], 'files': {'empty': ''}}
    dead = {phase: dict(copy.deepcopy(base), exit=-11, effects={}, effects_at_parent_exit=[],
                        scripts_at_parent_exit={}) for phase in ['test', 'run']}
    safe = copy.deepcopy(dead)
    for row in safe.values():
        row.update(exit=1, stderr='\ndnsmasq-rs: empty additional conf-file\n')
    assert not compare(dead, safe, null_case)
    wrong = copy.deepcopy(safe); wrong['test']['stderr'] = '\ndnsmasq: wrong rejection\n'
    assert compare(dead, wrong, null_case)
    checks['NULL-difference-requires-exact-safe-diagnostic'] = 'detected'
    wrong_case = dict(null_case, argv=['-C', 'ordinary'])
    assert compare(dead, safe, wrong_case)
    checks['NULL-difference-not-blanket'] = 'detected'
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--manifest', type=Path, default=Path(__file__).with_suffix('.json'))
    parser.add_argument('--scenarios')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    calibration = controls()
    if args.self_test:
        print(json.dumps(calibration, sort_keys=True))
        return 0
    if not all([args.image_root, args.rust, args.rust_sha256, args.source_commit, args.output]):
        parser.error('--image-root --rust --rust-sha256 --source-commit --output required')
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('isolated namespace required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sha256(args.rust) != args.rust_sha256:
        parser.error('candidate identity mismatch')
    out = args.output.resolve()
    if 'private' not in out.parts or out.exists():
        parser.error('fresh private output required')
    out.mkdir(parents=True)
    manifest = json.loads(args.manifest.read_text())
    if not manifest['executable']:
        parser.error('manifest is not executable')
    cases = manifest['scenarios']
    if args.scenarios:
        selected = args.scenarios.split(',')
        if set(selected) - {case['id'] for case in cases}:
            parser.error('unknown case')
        cases = [case for case in cases if case['id'] in selected]
    driver = out / 'driver'
    driver.mkdir()
    for name in [Path(__file__).name, args.manifest.name, *DEPENDENCIES]:
        (driver / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    sides = ['c'] if args.reference_only else ['c', 'rust']
    roots = {side: prepare(args.image_root, None, out / side, args.rust) for side in sides}
    result = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'c_sha256': STOCK_SHA256, 'manifest_sha256': sha256(args.manifest),
              'tool_sha256': sha256(Path(__file__)), 'reference_only': args.reference_only,
              'negative_controls': calibration,
              'scenarios': [], 'options': {}, 'failures': []}
    for case in cases:
        folder = out / case['id']
        folder.mkdir()
        row = {'id': case['id'], 'options': case['options'], 'failures': []}
        if case.get('reference_defect'):
            row['reference_difference'] = case['reference_defect']
        try:
            values = {}
            for side in sides:
                values[side] = {}
                for phase in ['test', 'run']:
                    values[side][phase] = run_phase(roots[side], side, case, phase, folder / f'{side}-{phase}')
            row['failures'] = compare(values['c'], values.get('rust', values['c']), case, args.reference_only)
        except Exception as error:
            row['failures'].append({'kind': 'infrastructure', 'error': repr(error)})
        result['scenarios'].append(row)
        save(out / 'progress.json', result)
    for option, detail in manifest['options'].items():
        selected = {row['id']: row for row in result['scenarios'] if option in row['options']}
        missing = sorted(set(detail['scenarios']) - selected.keys())
        failed = [key for key, row in selected.items() if row['failures']]
        qualified = manifest.get('qualification_ready', False) and all(boundary['required_scenarios'] for boundary in detail['checklist'])
        result['options'][option] = {'closed': not args.reference_only and qualified and not missing and not failed,
                                    'missing': missing, 'failed': failed,
                                    'checklist': [dict(boundary, checked=not args.reference_only and qualified and all(
                                        key in selected and not selected[key]['failures'] for key in boundary['required_scenarios']))
                                        for boundary in detail['checklist']]}
    result['failures'] = [dict(case=row['id'], **error) for row in result['scenarios'] for error in row['failures']]
    save(out / 'result.json', result)
    print(json.dumps({'cases': len(cases), 'failures': len(result['failures']),
                      'closed': [name for name, value in result['options'].items() if value['closed']]}))
    return int(bool(result['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
