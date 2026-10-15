#!/usr/bin/env python3
"""Execute the frozen two-build PGO smoke after the host reservation is released."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def interrupted(signum, _frame):
    raise InterruptedError(f'interrupted by signal {signum}')


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_group(process):
    receipt = {'term_sent': False, 'kill_sent': False, 'group_exited': False}
    process.poll()
    for signum, field in ((signal.SIGTERM, 'term_sent'), (signal.SIGKILL, 'kill_sent')):
        if not group_exists(process.pid):
            break
        receipt[field] = True
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except PermissionError:
            # The isolated namespace command is owned by sudo/root.
            subprocess.run(['sudo', '-n', 'kill', '-' + signal.Signals(signum).name.removeprefix('SIG'),
                            '--', '-' + str(process.pid)], check=True)
        deadline = time.monotonic() + 5
        while group_exists(process.pid) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)
    process.wait(timeout=5)
    assert not group_exists(process.pid), f'owned process group {process.pid} remains'
    receipt['group_exited'] = True
    return receipt


def check_build(plan, mode, plan_sha, tools):
    out = Path(plan['outputs'][mode])
    built = json.loads((out / 'build.json').read_text())
    assert built['status'] == 'built-unqualified' and built['source_unchanged']
    for key in ('source_commit', 'source_date_epoch', 'source_digest', 'builder_sha256', 'build_helper_sha256'):
        assert built[key] == plan[key], key
    assert built['toolchain']['map_wrapper_sha256'] == plan['map_cc_sha256']
    layout = built['elf_layout']
    assert layout['type'] == 'ET_DYN' and layout['machine'] == 'AArch64'
    assert layout['linkage'] == 'static-pie' and layout['interpreter'] is None and layout['needed'] == []
    assert all(layout[key] for key in ('pie', 'bind_now', 'gnu_relro', 'nx_stack'))
    assert not layout['writable_executable_load']
    artifact, = built['artifacts']
    assert artifact['path'] == 'dnsmasq-rs' and sha(out / artifact['path']) == artifact['sha256']
    assert sha(out / 'link.map') == built['link_map']['sha256']
    assert sha(out / 'dnsmasq-prestrip') == built['prestrip']['sha256']
    invocation = json.loads(Path(plan['invocation_receipts'][mode]).read_text())
    extra = '' if mode == 'control' else '-Cprofile-generate=' + plan['default_profile_directory']
    assert invocation['mode'] == mode and invocation['plan_sha256'] == plan_sha
    assert invocation['wrapper_sha256'] == plan['wrapper_sha256']
    assert invocation['cargo_sha256'] == tools['cargo'] and invocation['rustc_sha256'] == tools['rustc']
    assert invocation['rustc_environment'] == plan['rustc']
    assert invocation['recipe_rustflags'] == plan['recipe_rustflags']
    assert invocation['added_rustflags'] == extra
    assert invocation['effective_rustflags'] == plan['recipe_rustflags'] + (' ' + extra if extra else '')
    if mode == 'control':
        assert built['baseline_matches_expected'] is True
        assert artifact['sha256'] == plan['expected_control_elf_sha256']
        assert built['within_existing_budget']
    return built


def protections(data, maps, page):
    assert data[:6] == b'\x7fELF\x02\x01' and page > 0 and page & (page - 1) == 0
    offset, = struct.unpack_from('<Q', data, 32)
    width, count = struct.unpack_from('<HH', data, 54)
    assert width == 56
    headers = [struct.unpack_from('<IIQQQQQQ', data, offset + index * width) for index in range(count)]
    first, = [row for row in headers if row[0] == 1 and row[2] == 0]
    zero, = [row for row in maps if row['main'] and row['offset'] == 0]
    base = zero['start'] - (first[3] & -page)
    relro, = [row for row in headers if row[0] == 0x6474e552]
    start, end = (base + relro[3]) & -page, base + relro[3] + relro[6]
    assert end > start and end % page == 0
    cursor = start
    while cursor < end:
        row, = [row for row in maps if row['start'] <= cursor < row['end']]
        assert row['main'] and row['permissions'][:3] == 'r--'
        cursor = min(end, row['end'])
    assert all(not ('w' in row['permissions'] and 'x' in row['permissions']) for row in maps)
    stacks = [row for row in maps if row['path'] == '[stack]']
    assert stacks and all('x' not in row['permissions'] for row in stacks)
    return {'load_base': base, 'relro_start': start, 'relro_end': end,
            'relro_read_only': True, 'no_writable_executable_mapping': True, 'stack_nx': True}


def name(packet, position):
    labels, following, seen = [], None, set()
    while True:
        assert position not in seen and position < len(packet)
        seen.add(position)
        size = packet[position]
        if size & 0xc0 == 0xc0:
            assert position + 1 < len(packet)
            if following is None:
                following = position + 2
            position = ((size & 0x3f) << 8) | packet[position + 1]
        elif size == 0:
            return b'.'.join(labels).decode('ascii'), following or position + 1
        else:
            assert size <= 63 and position + 1 + size <= len(packet)
            labels.append(packet[position + 1:position + 1 + size])
            position += size + 1


def query(row, identifier):
    qtype = {'A': 1, 'AAAA': 28}[row['qtype']]
    wire = b''.join(bytes([len(part)]) + part.encode() for part in row['name'].split('.')) + b'\0'
    packet = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + wire + struct.pack('!HH', qtype, 1)
    # A fresh endpoint prevents a late readiness reply being mistaken for AAAA.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(('127.0.0.1', 15353))
        sock.settimeout(0.2)
        sock.send(packet)
        answer = sock.recv(512)
    rid, flags, questions, answers, authority, additional = struct.unpack_from('!6H', answer)
    assert rid == identifier and flags & 0x820f == 0x8000
    assert (questions, answers, authority, additional) == (1, 1, 0, 0)
    owner, cursor = name(answer, 12)
    assert owner == row['name'] and struct.unpack_from('!HH', answer, cursor) == (qtype, 1)
    owner, cursor = name(answer, cursor + 4)
    rrtype, klass, ttl, length = struct.unpack_from('!HHIH', answer, cursor)
    expected = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, row['expected_address'])
    assert owner == row['name'] and (rrtype, klass, ttl, length) == (qtype, 1, 120, len(expected))
    assert answer[cursor + 10:] == expected
    return {'query_hex': packet.hex(), 'answer_hex': answer.hex()}


def runtime(plan, parent_netns, parent_mntns):
    spec = plan['runtime']
    out = Path(spec['directory'])
    out.mkdir()
    result = {'status': 'starting', 'queries': [], 'forced_cleanup': False}
    process = None
    try:
        assert os.getuid() == 0 and os.getpid() == 1 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
        assert os.readlink('/proc/self/ns/net') != parent_netns
        assert os.readlink('/proc/self/ns/mnt') != parent_mntns
        elf = Path(plan['outputs']['generate']) / 'dnsmasq-rs'
        built = json.loads((elf.parent / 'build.json').read_text())
        expected_sha = built['artifacts'][0]['sha256']
        assert sha(elf) == expected_sha
        config = out / 'config'
        config.write_text('\n'.join(spec['config_lines']) + '\n')
        result['config_sha256'] = sha(config)
        env = dict(os.environ, LLVM_PROFILE_FILE=spec['llvm_profile_file'])
        with (out / 'daemon.stdout').open('xb') as stdout, (out / 'daemon.stderr').open('xb') as stderr:
            process = subprocess.Popen(spec['daemon_argv'], env=env, stdout=stdout, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            result['daemon_pid'] = process.pid
            save(out / 'runtime.json', result)
            deadline = time.monotonic() + spec['readiness_timeout_seconds']
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                try:
                    result['queries'].append(query(spec['queries'][0], 0x5047))
                    break
                except (socket.timeout, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('readiness timeout')
                    time.sleep(0.05)
            result['queries'].append(query(spec['queries'][1], 0x5048))
            assert sha(f'/proc/{process.pid}/exe') == expected_sha
            result['live_elf_sha256'] = expected_sha
            text = Path(f'/proc/{process.pid}/maps').read_text()
            (out / 'live.maps').write_text(text)
            maps = []
            for line in text.splitlines():
                fields = line.split(maxsplit=5)
                start, end = [int(value, 16) for value in fields[0].split('-')]
                path = fields[5] if len(fields) == 6 else ''
                maps.append({'start': start, 'end': end, 'offset': int(fields[2], 16),
                             'permissions': fields[1], 'path': path, 'main': path == str(elf)})
            result['protections'] = protections(elf.read_bytes(), maps, os.sysconf('SC_PAGE_SIZE'))
            result['maps_sha256'] = sha(out / 'live.maps')
            process.send_signal(signal.SIGTERM)
            result['exit_status'] = process.wait(timeout=spec['normal_exit_timeout_seconds'])
            assert result['exit_status'] == spec['normal_exit_status']
        raw = Path(spec['llvm_profile_file'].replace('%p', str(process.pid)))
        assert list(out.glob('*.profraw')) == [raw] and raw.stat().st_size > 0
        assert not any(Path(plan['default_profile_directory']).iterdir())
        result['profile'] = {'path': str(raw), 'bytes': raw.stat().st_size, 'sha256': sha(raw)}
        result['status'] = 'complete'
    except BaseException as error:
        result.update(status='failed', error=repr(error))
        raise
    finally:
        try:
            if process is not None:
                result['forced_cleanup'] = group_exists(process.pid)
                result['cleanup'] = stop_group(process)
        except BaseException as error:
            result['cleanup_error'] = repr(error)
            raise
        finally:
            for filename in ('daemon.stdout', 'daemon.stderr'):
                if (out / filename).exists():
                    result[filename + '_sha256'] = sha(out / filename)
            save(out / 'runtime.json', result)


def execute(plan_path):
    plan = json.loads(plan_path.read_text())
    base = Path(plan['attempt'])
    assert plan_path == base / 'inputs/plan.json' and sha(__file__) == plan['controller_sha256']
    state_path = base / 'state.json'
    with state_path.open('x') as stream:
        stream.write('{}\n')
    state = {'status': 'preflight', 'pid': os.getpid(), 'plan_sha256': sha(plan_path),
             'commands': [], 'builds': {}, 'active': None}

    def command(label, argv, extra=None, timeout=900):
        row = {'label': label, 'argv': list(map(str, argv)), 'environment_updates': extra or {}}
        process = None
        try:
            with (base / (label + '.stdout')).open('xb') as stdout, (base / (label + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(row['argv'], env=dict(os.environ, **(extra or {})),
                                           stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
                                           start_new_session=True)
                state['active'] = {'label': label, 'pid': process.pid}
                save(state_path, state)
                row['returncode'] = process.wait(timeout=timeout)
                assert row['returncode'] == 0, label
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            try:
                if process is not None:
                    row['cleanup'] = stop_group(process)
                    row['returncode'] = process.returncode
            except BaseException as error:
                row['cleanup_error'] = repr(error)
                raise
            finally:
                for suffix in ('stdout', 'stderr'):
                    path = base / (label + '.' + suffix)
                    if path.exists():
                        row[suffix + '_sha256'] = sha(path)
                state['commands'].append(row)
                if process is None or not group_exists(process.pid):
                    state['active'] = None
                save(state_path, state)
        return (base / (label + '.stdout')).read_text()

    try:
        assert [stage['mode'] for stage in plan['stages']] == ['control', 'generate']
        fixed = {str(plan_path): state['plan_sha256'],
                 str(Path(__file__).resolve()): plan['controller_sha256'],
                 plan['builder']: plan['builder_sha256'],
                 str(Path(plan['builder']).with_name('build_package.py')): plan['build_helper_sha256'],
                 str(Path(plan['source']) / 'packaging/openwrt/owrt-dnsmasq/Makefile'): plan['recipe_sha256'],
                 str(Path(plan['source']) / 'packaging/openwrt/owrt-dnsmasq/static-pie-linker.py'): plan['static_pie_linker_sha256'],
                 plan['map_cc']: plan['map_cc_sha256'],
                 plan['isolator']['path']: plan['isolator']['sha256'],
                 plan['profdata']['path']: plan['profdata']['sha256']}
        assert all(sha(path) == digest for path, digest in fixed.items())
        wrapper = Path(plan['wrapper_remote_path'])
        wrapper.parent.mkdir()
        shutil.copyfile(base / 'inputs/pgo_smoke_cargo.py', wrapper)
        wrapper.chmod(0o755)
        assert sha(wrapper) == plan['wrapper_sha256']
        fixed[str(wrapper)] = plan['wrapper_sha256']
        wrapper.with_name('rustc').symlink_to(plan['rustc'])
        Path(plan['default_profile_directory']).mkdir()
        tools = {key: sha(plan[key]) for key in ('cargo', 'pinned_cargo', 'rustc')}
        runtime_libraries = list((Path(plan['rustc']).parent.parent / 'lib/rustlib/aarch64-unknown-linux-musl/lib').glob('libprofiler_builtins-*.rlib'))
        assert len(runtime_libraries) == 1
        fixed[str(runtime_libraries[0])] = sha(runtime_libraries[0])
        rustc = command('rustc-version', [plan['rustc'], '-vV'])
        assert rustc.startswith('rustc 1.98.1 ') and 'LLVM version: 22.1.8\n' in rustc
        assert 'host: aarch64-unknown-linux-gnu\n' in rustc
        assert command('cargo-version', [plan['cargo'], '--version'],
                       {'RUSTUP_TOOLCHAIN': '1.98.1'}).startswith('cargo 1.98.1 ')
        assert '22.1.8' in command('profdata-version', [plan['profdata']['path'], '--version'])
        state.update(tools_sha256=tools, fixed_inputs_sha256=fixed)
        for stage in plan['stages']:
            mode = stage['mode']
            assert mode in ('control', 'generate')
            if mode == 'generate':
                assert 'control' in state['builds'], 'exact E control must pass first'
            state['status'] = mode + '-build'
            command(mode + '-build', stage['argv'], stage['environment'])
            built = check_build(plan, mode, state['plan_sha256'], tools)
            if mode == 'generate':
                assert built['source_files'] == control['source_files'] and built['sdk'] == control['sdk']
            else:
                control = built
            state['builds'][mode] = {'receipt_sha256': sha(Path(plan['outputs'][mode]) / 'build.json'),
                                    'artifacts': built['artifacts'], 'within_existing_budget': built['within_existing_budget']}
            save(state_path, state)
        assert set(state['builds']) == {'control', 'generate'}
        state['status'] = 'builds-complete-runtime'
        save(state_path, state)
        print('Control and generate SDK builds passed; starting isolated smoke.', flush=True)
        command('isolated-runtime', ['sudo', '-n', 'sh', plan['isolator']['path'], 'python3', str(Path(__file__).resolve()),
                                    str(plan_path), '--runtime', '--parent-netns', os.readlink('/proc/self/ns/net'),
                                    '--parent-mntns', os.readlink('/proc/self/ns/mnt')], timeout=60)
        result = json.loads((Path(plan['runtime']['directory']) / 'runtime.json').read_text())
        assert result['status'] == 'complete' and not result['forced_cleanup']
        raw = result['profile']
        assert sha(raw['path']) == raw['sha256'] and sha(plan['profdata']['path']) == plan['profdata']['sha256']
        command('profile-merge', [plan['profdata']['path'], 'merge', '-o', plan['runtime']['merged_path'], raw['path']])
        shown = command('profile-show', [plan['profdata']['path'], *plan['runtime']['show_argv']])
        for key in ('Total functions', 'Maximum function count'):
            found = re.search(r'^\s*' + key + r':\s*(\d+)\s*$', shown, re.M)
            assert found and int(found[1]) > 0, key
        assert all(not (base / (label + '.stderr')).read_text().strip() for label in ('profile-merge', 'profile-show'))
        assert all(sha(path) == digest for path, digest in fixed.items())
        assert all(sha(plan[key]) == digest for key, digest in tools.items())
        assert all(sha(Path(plan['source']) / name) == digest for name, digest in control['source_files'].items())
        check_build(plan, 'control', state['plan_sha256'], tools)
        check_build(plan, 'generate', state['plan_sha256'], tools)
        state.update(status='complete', runtime_receipt_sha256=sha(Path(plan['runtime']['directory']) / 'runtime.json'),
                     profile=raw, merged_sha256=sha(plan['runtime']['merged_path']))
    except BaseException as error:
        state.update(status='failed', error=repr(error))
        raise
    finally:
        save(state_path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('--runtime', action='store_true')
    parser.add_argument('--parent-netns')
    parser.add_argument('--parent-mntns')
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.runtime:
        assert args.parent_netns and args.parent_mntns
        runtime(json.loads(args.plan.read_text()), args.parent_netns, args.parent_mntns)
    else:
        execute(args.plan.resolve())


if __name__ == '__main__':
    main()
