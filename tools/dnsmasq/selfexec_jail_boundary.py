#!/usr/bin/env python3
"""Oracle-only no-/proc self-exec boundary, using public helper/resolver paths.

Run the observer in a private mount/net namespace with lo up, retaining host
/proc and PID namespace. It launches each target in another mount namespace
and a private PID namespace, then chroots without /proc. The exact supplied
ELF is a regular root:root 0755 /usr/sbin/dnsmasq, including argv[0].

The target starts as root and its own user/group configuration drops the owner
to 453, matching Helper::start-before-drop_privileges. Resolver is triggered
only AFTER the owner is observed at UID/GID 453, CapPrm/CapEff 0x3400,
CapInh/CapAmb 0, NoNewPrivs/Seccomp 0. No file/ambient capabilities are added.
The resolver's actual DNS response is held until its own UID/capabilities,
SigIgn, comm and all FDs (including 0/1/2) are observed through host /proc.
The persistent helper is observed separately after its real old callback.
This reproduces these boundaries, not all ujail mounts or policies.

Example (Linux Oracle only; NEVER use the router):
  sudo -n unshare --mount --net sh -c '
    mount --make-rprivate / && ip link set lo up && exec "$@"
  ' isolated python3 tools/dnsmasq/selfexec_jail_boundary.py \
    --image-root IMAGE_ROOT --binary ELF --sha256 SHA --source-commit COMMIT \
    --expect success --output PRIVATE_FRESH_DIRECTORY
Use --expect proc-selfexec-failure for the frozen b8617f57 negative control,
with its own exact binary hash and fresh output. Each invocation runs both
helper and resolver once; this is a behavioral gate, not a timing benchmark.
--case helper narrows a necessary helper-only recheck. Exact K's preexisting
no-/proc lookup boundary uses --case resolver --expect resolver-proc-failure;
it does not borrow the b861 helper expectation.
"""
from __future__ import annotations

import argparse
import copy
import errno
import json
import os
from pathlib import Path
import select
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from dns_service_probe import answer, query, read_name, rr, semantics
from m2_rootfs import bind_unix_socket, image_path, sha256

TARGET = '/usr/sbin/dnsmasq'
CALLBACK = 'old 02:00:00:de:00:01 127.0.0.10 startup\n'
CAPS = 0x3400


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def status(pid):
    fields = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ['Uid', 'Gid', 'NSpid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'SigIgn']:
            fields[key] = ([int(part) for part in value.split()] if key in ['Uid', 'Gid', 'NSpid']
                           else int(value.strip(), 16 if key.startswith('Cap') or key == 'SigIgn' else 10))
    return fields


def namespaces(pid):
    return {name: os.readlink(f'/proc/{pid}/ns/{name}') for name in ['mnt', 'pid', 'net']}


def boundary_errors(row, observer, runtime, proc_visible=False):
    errors = []
    identity = 453 if runtime else 0
    if row['status'].get('Uid') != [identity] * 4 or row['status'].get('Gid') != [identity] * 4:
        errors.append('wrong target UID/GID')
    if row['status'].get('NoNewPrivs') != 0 or row['status'].get('Seccomp') != 0:
        errors.append('unexpected seccomp or no-new-privileges')
    if any(row['namespaces'].get(name) == observer[name] for name in ['mnt', 'pid']):
        errors.append('target did not get private mount/PID namespaces')
    if row['namespaces'].get('net') != observer['net']:
        errors.append('target left the isolated observer network')
    if row.get('proc_exists') is not proc_visible:
        errors.append('wrong target /proc visibility')
    if row.get('target_metadata') != {'regular': True, 'mode': 0o755, 'uid': 0, 'gid': 0, 'file_capability': None}:
        errors.append('target is not a regular root:root 0755 executable')
    if runtime:
        if any(row['status'].get(key) != CAPS for key in ['CapPrm', 'CapEff']):
            errors.append('wrong retained network capabilities')
        if any(row['status'].get(key) != 0 for key in ['CapInh', 'CapAmb']):
            errors.append('unexpected inheritable/ambient capabilities')
        if row.get('argv0') != TARGET:
            errors.append('wrong target argv[0]')
    return errors


def metadata(path):
    value = path.lstat()
    try: capability = os.getxattr(path, 'security.capability').hex()
    except OSError as error:
        if error.errno not in [errno.ENODATA, getattr(errno, 'ENOATTR', -1)]: raise
        capability = None
    return {'regular': stat.S_ISREG(value.st_mode), 'mode': stat.S_IMODE(value.st_mode),
            'uid': value.st_uid, 'gid': value.st_gid, 'file_capability': capability}


def child_entry(root, entry_fd, release_fd, proc_visible=False):
    if proc_visible:
        (Path(root) / 'proc').mkdir()
        subprocess.run(['mount', '-t', 'proc', 'proc', str(Path(root) / 'proc')], check=True)
    os.chroot(root)
    os.chdir('/')
    receipt = {'uid': os.getuid(), 'gid': os.getgid(), 'namespace_pid': os.getpid(),
               'proc_exists': os.path.lexists('/proc'), 'target_metadata': metadata(Path(TARGET)),
               'target_sha256': sha256(TARGET)}
    os.write(entry_fd, json.dumps(receipt).encode() + b'\n')
    os.close(entry_fd)
    if os.read(release_fd, 1) != b'G':
        raise RuntimeError('observer did not release target exec')
    os.close(release_fd)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    os.execve(TARGET, [TARGET, '--keep-in-foreground', '--conf-file=/fixture/config'],
              {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})


def remove(path):
    if path.is_symlink() or path.is_file(): path.unlink()
    elif path.exists(): shutil.rmtree(path)


def write_image(root, name, text, mode=0o644):
    path = image_path(root, name, follow_leaf=False)
    if path.is_symlink(): path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    os.chown(path, 0, 0)
    return path


def prepare_root(image, binary, folder, helper, proc_visible=False):
    root = folder / 'rootfs'
    shutil.copytree(image, root, symlinks=True)
    remove(root / 'proc')
    remove(root / 'dev')
    (root / 'dev').mkdir(mode=0o755)
    for name, minor in [('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)]:
        os.mknod(root / 'dev' / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        (root / 'dev' / name).chmod(0o666)
    executable = image_path(root, TARGET, follow_leaf=False)
    if executable.is_symlink(): executable.unlink()
    shutil.copyfile(binary, executable)
    executable.chmod(0o755); os.chown(executable, 0, 0)
    if 'security.capability' in os.listxattr(executable):
        os.removexattr(executable, 'security.capability')
    write_image(root, '/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nfixture453:x:453:453:fixture:/:/bin/false\n')
    write_image(root, '/etc/group', 'root:x:0:\nfixture453:x:453:\n')
    write_image(root, '/etc/hosts', '127.0.0.1 localhost\n')
    write_image(root, '/etc/resolv.conf', 'nameserver 127.0.0.2\noptions timeout:2 attempts:1\n')
    fixture = root / 'fixture'; fixture.mkdir(mode=0o755)
    os.chown(fixture, 453, 453)
    config = ('no-hosts\nno-resolv\nno-poll\nuser=fixture453\ngroup=fixture453\n'
              'interface=lo\nbind-dynamic\nlisten-address=127.0.0.1\nport=53\n'
              'dns-forward-max=16\ncache-size=0\nno-0x20-encode\n'
              'host-record=ready.jail.test,192.0.2.7\n'
              'pid-file=/fixture/pid\nlog-facility=/fixture/daemon.log\n'
              'dhcp-authoritative\ndhcp-lease-max=1\n'
              'dhcp-range=127.0.0.10,127.0.0.10,255.0.0.0,127.255.255.255,12h\n'
              'dhcp-leasefile=/fixture/leases\n')
    if helper:
        config += 'dhcp-script=/fixture/script\n'
        write_image(root, '/fixture/script', '#!/bin/sh\n'
                    '[ "$#" -eq 4 ] && [ "$1" = old ] && [ "$2" = 02:00:00:de:00:01 ] && '
                    '[ "$3" = 127.0.0.10 ] && [ "$4" = startup ] || exit 64\n' +
                    ('[ -d /proc/self/fd ] || exit 65\n' if proc_visible else
                     '[ ! -e /proc ] && [ ! -L /proc ] || exit 65\n') +
                    'printf "%s %s %s %s\\n" "$1" "$2" "$3" "$4" >> /fixture/callback\n', 0o755)
    else:
        config += 'servers-file=/fixture/servers\n'
        write_image(root, '/fixture/servers', 'server=/before.jail.test/127.0.0.1#15354\n')
    write_image(root, '/fixture/config', config)
    leases = write_image(root, '/fixture/leases', f'{int(time.time()) + 43200} 02:00:00:de:00:01 127.0.0.10 startup *\n', 0o644)
    os.chown(leases, 453, 453)
    return root


def observe(pid, root, observer, runtime, digest, proc_visible=False):
    proc = Path('/proc') / str(pid)
    actual_root = Path(os.path.realpath(proc / 'root'))
    if actual_root != root: raise AssertionError('wrong target chroot')
    row = {'pid': pid, 'root': str(actual_root), 'status': status(pid), 'namespaces': namespaces(pid),
           'nofile': list(resource.prlimit(pid, resource.RLIMIT_NOFILE)),
           'comm': (proc / 'comm').read_text().rstrip('\n'),
           'proc_exists': os.path.lexists(proc / 'root/proc'),
           'target_metadata': metadata(proc / ('root' + TARGET)),
           'argv0': (proc / 'cmdline').read_bytes().split(b'\0')[0].decode(errors='backslashreplace')}
    if runtime:
        row['exe_sha256'] = sha256(proc / 'exe')
        if row['exe_sha256'] != digest: raise AssertionError('running target ELF mismatch')
    row['errors'] = boundary_errors(row, observer, runtime, proc_visible)
    if row['errors']: raise AssertionError(row['errors'])
    return row


def read_entry(fd):
    deadline = time.monotonic() + 5; raw = b''
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
        if not ready: break
        chunk = os.read(fd, 4096)
        if not chunk: break
        raw += chunk
        if raw.endswith(b'\n'): return json.loads(raw)
        if len(raw) > 8192: break
    raise RuntimeError('target entry handshake missing')


def worker_observation(owner_pid, root, digest, kind, proc_visible=False):
    """Lookup is held at its DNS question; helper is observed after callback."""
    children = Path(f'/proc/{owner_pid}/task/{owner_pid}/children').read_text().split()
    if len(children) != 1:
        return {'captured': False, 'reason': f'{kind} did not have exactly one direct child', 'children': children}
    pid = int(children[0]); proc = Path('/proc') / str(pid)
    row = {'captured': True, 'pid': pid, 'status': status(pid), 'namespaces': namespaces(pid),
           'nofile': list(resource.prlimit(pid, resource.RLIMIT_NOFILE)),
           'comm': (proc / 'comm').read_text().rstrip('\n'),
           'argv': (proc / 'cmdline').read_bytes().split(b'\0')[:-1],
           'exe_sha256': sha256(proc / 'exe'), 'root': os.path.realpath(proc / 'root'),
           'proc_exists': os.path.lexists(proc / 'root/proc')}
    row['fds'] = [{'fd': int(fd.name), 'target': os.readlink(fd),
                   'fdinfo': (proc / 'fdinfo' / fd.name).read_text()}
                  for fd in sorted((proc / 'fd').iterdir(), key=lambda entry: int(entry.name))]
    row['argv'] = [part.decode(errors='backslashreplace') for part in row['argv']]
    expected_uid = 0 if kind == 'helper' else 453
    row['valid'] = (row['status']['Uid'] == [expected_uid] * 4 and row['status']['Gid'] == [expected_uid] * 4
                    and row['status']['NoNewPrivs'] == 0 and row['status']['Seccomp'] == 0
                    and row['namespaces'] == namespaces(owner_pid) and row['root'] == str(root)
                    and row['proc_exists'] == proc_visible and row['exe_sha256'] == digest)
    # Record the child's own CapEff/CapPrm without requiring inherited 0x3400.
    return row


def resolver_answer(packet, expected_name='selfexec-resolver.test'):
    name, end = read_name(packet, 12)
    kind, cls = struct.unpack_from('!HH', packet, end)
    if name.lower() != expected_name or cls != 1 or kind not in [1, 28]:
        raise AssertionError('unexpected libc resolver question')
    data = rr(1, socket.inet_aton('127.0.0.1')) if kind == 1 else b''
    return packet[:2] + struct.pack('!5H', 0x8180, 1, int(kind == 1), 0, 0) + packet[12:end + 4] + data


def probe(name, upstream, receipts, process, timeout=5, resolver=None, on_lookup=None):
    wire = query(name)
    deadline = time.monotonic() + timeout; next_send = 0; attempts = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setblocking(False)
        while time.monotonic() < deadline and process.poll() is None:
            now = time.monotonic()
            if now >= next_send:
                client.sendto(wire, ('127.0.0.1', 53)); next_send = now + .1
            ready, _, _ = select.select([client, upstream] + ([resolver] if resolver else []), [], [], min(.05, max(0, deadline - now)))
            if resolver is not None and resolver in ready:
                packet, peer = resolver.recvfrom(65535)
                # Withhold the actual response until the external observer has
                # captured the live lookup child; no inferred owner identity.
                received_at = time.monotonic_ns()
                if on_lookup is not None: on_lookup(packet, received_at)
                resolver.sendto(resolver_answer(packet), peer)
            if upstream in ready:
                packet, peer = upstream.recvfrom(65535)
                response = answer(packet)
                upstream.sendto(response, peer)
                receipts.append({'request': packet.hex(), 'reply': response.hex(), 'at_ns': time.monotonic_ns(),
                                 'semantics': semantics(packet)})
            if client in ready:
                response, peer = client.recvfrom(65535)
                value = semantics(response)
                attempts.append({'reply': response.hex(), 'peer': list(peer), 'semantics': value})
                if (response[:2] == wire[:2] and value['flags'] & 15 == 0
                        and value['questions'] == [[name, 1, 1]]
                        and [row['data'] for row in value['records'] if row['section'] == 'answer'] == ['192.0.2.7']):
                    return {'ok': True, 'name': name, 'attempts': attempts}
    return {'ok': False, 'name': name, 'attempts': attempts}


def run_case(args, mode, observer, prepare_hook=None, trial=None):
    folder = args.output / mode; folder.mkdir()
    proc_visible = getattr(args, 'proc_visible', False)
    root = prepare_root(args.image_root, args.binary, folder, mode == 'helper', proc_visible).resolve()
    if prepare_hook is not None: prepare_hook(root, mode)
    row = {'mode': mode, 'expect': args.expect, 'passed': False, 'upstream': [], 'forced': False}
    entry_read, entry_write = os.pipe(); release_read, release_write = os.pipe()
    process = None; target_pid = None; target_fd = None
    with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver, \
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as syslog:
        upstream.bind(('127.0.0.1', 15354))
        resolver.bind(('127.0.0.2', 53))
        bind_unix_socket(syslog, root / 'dev/log')
        (root / 'dev/log').chmod(0o666)
        syslog.setblocking(False)
        try:
            argv = ['unshare', '--mount', '--pid', '--fork', sys.executable, str(Path(__file__).resolve()),
                    '--child', str(root), str(entry_write), str(release_read)]
            if proc_visible: argv.append('--proc-visible')
            if getattr(args, 'initial_nofile', None):
                soft, hard = args.initial_nofile
                argv = ['prlimit', f'--nofile={soft}:{hard}', '--', *argv]
            save(folder / 'command.json', argv)
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       pass_fds=(entry_write, release_read), start_new_session=True)
            os.close(entry_write); entry_write = -1
            os.close(release_read); release_read = -1
            row['entry_receipt'] = read_entry(entry_read)
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
            if len(children) != 1: raise AssertionError('unshare did not own exactly one target entry')
            target_pid = int(children[0])
            target_fd = os.pidfd_open(target_pid)
            row['entry_boundary'] = observe(target_pid, root, observer, False, args.sha256, proc_visible)
            if row['entry_receipt'] != {'uid': 0, 'gid': 0, 'namespace_pid': 1, 'proc_exists': proc_visible,
                                       'target_metadata': row['entry_boundary']['target_metadata'], 'target_sha256': args.sha256}:
                raise AssertionError('inside/outside entry witnesses disagree')
            os.write(release_write, b'G'); os.close(release_write); release_write = -1
            row['initial_dns'] = probe('ready.jail.test', upstream, row['upstream'], process)
            if row['initial_dns']['ok']:
                row['runtime_boundary'] = observe(target_pid, root, observer, True, args.sha256, proc_visible)
            if mode == 'helper':
                callback = root / 'fixture/callback'
                deadline = time.monotonic() + 3
                while row['initial_dns']['ok'] and not callback.exists() and time.monotonic() < deadline and process.poll() is None:
                    row['callback_health'] = probe('ready.jail.test', upstream, row['upstream'], process, .1)
                    select.select([], [], [], .05)
                row['callback'] = callback.read_text() if callback.exists() else None
                row['helper_child'] = (worker_observation(target_pid, root, args.sha256, 'helper', proc_visible)
                                       if row['initial_dns']['ok'] and process.poll() is None else
                                       {'captured': False, 'reason': 'helper startup did not complete'})
            else:
                if not row['initial_dns']['ok']: raise AssertionError('resolver control owner never became ready')
                row['before'] = probe('probe.before.jail.test', upstream, row['upstream'], process)
                if not row['before']['ok']: raise AssertionError('numeric resolver control failed')
                (root / 'fixture/servers').write_text('server=/after.jail.test/selfexec-resolver.test#15354\n')
                row['resolver_child'] = {'captured': False, 'reason': 'no resolver DNS request observed'}
                row['resolver_dns'] = []
                def pending_lookup(packet, received_at):
                    if not row['resolver_child']['captured']:
                        try: row['resolver_child'] = worker_observation(target_pid, root, args.sha256, 'lookup', proc_visible)
                        except (OSError, ValueError) as error:
                            row['resolver_child'] = {'captured': False, 'reason': str(error)}
                    row['resolver_dns'].append({'request': packet.hex(), 'received_ns': received_at,
                                                'observed_before_release_ns': time.monotonic_ns()})
                signal.pidfd_send_signal(target_fd, signal.SIGHUP)
                row['after'] = probe('probe.after.jail.test', upstream, row['upstream'], process,
                                     resolver=resolver, on_lookup=pending_lookup)
                row['after_health'] = probe('ready.jail.test', upstream, row['upstream'], process)
                row['after_boundary'] = observe(target_pid, root, observer, True, args.sha256, proc_visible)
            if trial is not None:
                row['fd_pressure'] = trial(args, mode, root, row, process, target_pid, target_fd, upstream, resolver)
        except Exception as error:
            row['error'] = f'{type(error).__name__}: {error}'
        finally:
            for fd in [entry_read, entry_write, release_read, release_write]:
                if fd >= 0: os.close(fd)
            if process is not None:
                if target_fd is not None and process.poll() is None:
                    try: signal.pidfd_send_signal(target_fd, signal.SIGTERM)
                    except ProcessLookupError: pass
                try: row['exit'] = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    row['forced'] = True
                    os.killpg(process.pid, signal.SIGKILL)
                    row['exit'] = process.wait(timeout=2)
            if target_fd is not None: os.close(target_fd)
            row['syslog'] = []
            while True:
                try: row['syslog'].append(syslog.recv(65535).hex())
                except BlockingIOError: break
    row['stderr'] = (folder / 'stderr').read_text(errors='backslashreplace')
    log = root / 'fixture/daemon.log'
    row['daemon_log'] = log.read_text(errors='backslashreplace') if log.exists() else ''
    text = row['stderr'] + row['daemon_log'] + ''.join(bytes.fromhex(value).decode(errors='backslashreplace') for value in row['syslog'])
    missing = 'No such file or directory' in text or 'os error 2' in text
    if 'error' not in row and not row['forced']:
        if args.expect == 'success':
            row['passed'] = row.get('exit') == 0 and row['initial_dns']['ok'] and bool(row.get('runtime_boundary')) and (
                row.get('callback') == CALLBACK and row['helper_child'].get('valid') is True
                if mode == 'helper' else row['after']['ok'] and row['after_health']['ok']
                and row['resolver_child'].get('valid') is True)
        elif mode == 'helper':
            row['passed'] = row.get('exit') == 5 and row.get('callback') is None and missing and 'failed to create helper' in text
        else:
            row['passed'] = (not row['after']['ok'] and row['after_health']['ok'] and row.get('exit') == 0
                             and missing and 'at line 1 of /fixture/servers' in text)
    if trial is not None:
        row['passed'] = row['passed'] and row.get('fd_pressure', {}).get('passed') is True
    save(folder / 'result.json', row)
    return row


def self_test():
    observer = {'mnt': 'm0', 'pid': 'p0', 'net': 'n1'}
    good = {'status': {'Uid': [453] * 4, 'Gid': [453] * 4, 'NoNewPrivs': 0, 'Seccomp': 0,
                       'CapPrm': CAPS, 'CapEff': CAPS, 'CapInh': 0, 'CapAmb': 0},
            'namespaces': {'mnt': 'm1', 'pid': 'p1', 'net': 'n1'}, 'proc_exists': False,
            'target_metadata': {'regular': True, 'mode': 0o755, 'uid': 0, 'gid': 0, 'file_capability': None}, 'argv0': TARGET}
    assert not boundary_errors(good, observer, True)
    changes = [('proc_exists', True), ('argv0', '/other')]
    for key, value in changes:
        row = copy.deepcopy(good); row[key] = value
        assert boundary_errors(row, observer, True)
    for key in ['Uid', 'Gid', 'NoNewPrivs', 'Seccomp', 'CapEff', 'CapPrm', 'CapInh', 'CapAmb']:
        row = copy.deepcopy(good); row['status'][key] = [0] * 4 if key in ['Uid', 'Gid'] else 1
        assert boundary_errors(row, observer, True)
    for name in ['mnt', 'pid']:
        row = copy.deepcopy(good); row['namespaces'][name] = observer[name]
        assert boundary_errors(row, observer, True)
    for key, value in [('regular', False), ('mode', 0o777), ('uid', 453), ('gid', 453), ('file_capability', 'poison')]:
        row = copy.deepcopy(good); row['target_metadata'][key] = value
        assert boundary_errors(row, observer, True)
    resolved = semantics(resolver_answer(query('selfexec-resolver.test')))
    assert resolved['records'][0]['data'] == '127.0.0.1'
    assert semantics(resolver_answer(query('selfexec-resolver.test', 28)))['records'] == []
    try: resolver_answer(query('unexpected.test'))
    except AssertionError: pass
    else: raise AssertionError('resolver accepted an unexpected name')
    print(json.dumps({'boundary_positive': True, 'boundary_negative_controls': 17, 'resolver_wire_controls': 3}))


def main():
    if sys.argv[1:2] == ['--child']:
        child_entry(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5:] == ['--proc-visible']); return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--expect', choices=['success', 'proc-selfexec-failure', 'resolver-proc-failure'])
    parser.add_argument('--case', choices=['both', 'helper', 'resolver'], default='both')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test: self_test(); return 0
    if not all([args.image_root, args.binary, args.sha256, args.source_commit, args.expect, args.output]):
        parser.error('image-root/binary/sha256/source-commit/expect/output required')
    if args.expect == 'resolver-proc-failure' and args.case != 'resolver':
        parser.error('resolver-proc-failure requires --case resolver')
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux Oracle root required')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        parser.error('Python/Linux pidfd support required for owned target signals')
    observer = namespaces('self')
    if any(observer[name] == namespaces(1)[name] for name in ['mnt', 'net']):
        parser.error('observer requires private mount/net namespaces and host /proc')
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        parser.error('isolated network must contain loopback only')
    owner_status = status('self')
    if owner_status['Seccomp'] or owner_status['NoNewPrivs'] or owner_status['CapPrm'] & CAPS != CAPS:
        parser.error('observer must have seccomp=0, NoNewPrivs=0 and required network capabilities')
    args.binary = args.binary.resolve(); args.image_root = args.image_root.resolve(); args.output = args.output.resolve()
    if sha256(args.binary) != args.sha256 or 'private' not in args.output.parts or args.output.exists():
        parser.error('exact binary SHA and fresh private output required')
    args.output.mkdir(parents=True)
    result = {'source_commit': args.source_commit, 'binary_sha256': args.sha256, 'tool_sha256': sha256(__file__),
              'image_root': str(args.image_root), 'expect': args.expect, 'observer': {'namespaces': observer, 'status': owner_status},
              'scope': 'no-proc self-exec startup/drop-to-453 boundary; not a complete ujail replica', 'cases': []}
    for mode in (['helper', 'resolver'] if args.case == 'both' else [args.case]):
        result['cases'].append(run_case(args, mode, observer))
        save(args.output / 'result.json', result)
    result['passed'] = all(row['passed'] for row in result['cases'])
    save(args.output / 'result.json', result)
    print(json.dumps({'passed': result['passed'], 'cases': [{'mode': row['mode'], 'passed': row['passed']} for row in result['cases']]}))
    return int(not result['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
