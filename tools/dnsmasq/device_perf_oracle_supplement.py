#!/usr/bin/env python3
"""Sequential supplementary benchmark. Oracle only, explicitly not router tooling."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import struct
import subprocess
import time

C_HASH = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
R_HASH = '50e591a9d9dc1e6578888b14690b5b38415a9db886a492a2960a0c75b3eeb57c'
SCENARIOS = ['udp-hit', 'udp-miss', 'udp-mixed', 'tcp-hit', 'tcp-miss', 'dhcp',
             'startup-small', 'config-small', 'hup-small', 'hup-large']
ACTIVE = []


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def start(args, folder, label):
    out = open(folder / (label + '.stdout'), 'wb')
    err = open(folder / (label + '.stderr'), 'wb')
    p = subprocess.Popen(list(map(str, args)), stdout=out, stderr=err)
    out.close(); err.close()
    ACTIVE.append(p)
    dump(folder / (label + '.command.json'), list(map(str, args)))
    return p


def reap(p, folder, label, terminate=False):
    if terminate:
        try: os.kill(p.pid, signal.SIGTERM)
        except ProcessLookupError: pass
    _, status, usage = os.wait4(p.pid, 0)
    p.returncode = os.waitstatus_to_exitcode(status)
    ACTIVE.remove(p)
    result = {'exit': p.returncode, 'user_seconds': usage.ru_utime,
              'system_seconds': usage.ru_stime, 'maxrss_kib': usage.ru_maxrss}
    dump(folder / (label + '.usage.json'), result)
    return result


def process_ticks(pid):
    values = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'monotonic_ns': time.monotonic_ns(),
            'ticks': [int(values[i]) for i in (11, 12, 13, 14)],
            'starttime_ticks': int(values[19])}


def ready_dns():
    name = b'\x05ready\x0bdevice-perf\x04test\0'
    q = struct.pack('!6H', 0x2930, 0x100, 1, 0, 0, 0) + name + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(.1); sock.sendto(q, ('127.0.0.1', 15353))
        data = sock.recv(4096)
    return len(data) > 12 and data[:2] == q[:2] and data[-4:] == bytes([192, 0, 2, 1])


def record_identity(pid, folder):
    mapping = Path(f'/proc/{pid}/maps').read_text()
    (folder / 'daemon.maps').write_text(mapping)
    paths = sorted({line.split()[-1] for line in mapping.splitlines()
                    if len(line.split()) >= 6 and line.split()[-1].startswith('/')})
    dump(folder / 'daemon-identity.json', {'proc_exe': os.readlink(f'/proc/{pid}/exe'),
         'cmdline': Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(),
         'mapped_files': {path: digest(path) for path in paths if Path(path).is_file()}})


def check_load(folder, prefix, expected, dhcp=False):
    value = json.loads((folder / (prefix + '.json')).read_text())
    counts = value['measurement']
    errors = [key for key in ['timeout', 'wrong', 'transport_error', 'scheduled_skipped'] if counts[key]]
    if counts['scheduled'] != expected or counts['sent'] != expected or counts['correct'] != expected:
        errors.append('completion count')
    if value['interrupted'] or value['output_failed']: errors.append('output or interrupted')
    if dhcp and (counts['dora_correct'] or counts['release_sent'] or counts['renew_correct'] != expected
                 or value['leased_clients_final'] != 150): errors.append('renew contract')
    return value, errors


def traffic_case(root, folder, scenario, side):
    inputs = root / 'inputs'; dhcp = scenario == 'dhcp'
    mode, profile = ('dhcp', 'hit') if dhcp else scenario.split('-')
    rate, clients = (100, 150) if dhcp else (200, 8 if mode == 'tcp' else 32)
    conf = ('no-hosts\nno-resolv\nno-poll\nuser=root\ngroup=root\ninterface=lo\n'
            'bind-interfaces\nlisten-address=127.0.0.1\nport=15353\ncache-size=1000\n'
            'edns-packet-max=1232\ndns-forward-max=150\nserver=127.0.0.1#15354\n'
            'host-record=ready.device-perf.test,192.0.2.1\n'
            f'pid-file={folder}/pid\nlog-facility={folder}/daemon.log\n')
    if dhcp:
        conf += ('no-ping\ndhcp-authoritative\ndhcp-range=127.0.0.10,127.0.0.159,255.0.0.0,127.255.255.255,12h\n'
                 f'dhcp-lease-max=150\ndhcp-leasefile={folder}/leases\ndomain=device-perf.test\n')
        conf += ''.join(f'dhcp-host=02:00:00:6a:00:{i:02x},127.0.0.{i+10},lease{i:03d}\n' for i in range(150))
    (folder / 'config').write_text(conf)
    up = start([inputs/'m6a_upstream', '--port', '15354', '--delay-us', '1000', '--ttl', '120',
                '--output', folder/'upstream.json', '--ready-file', folder/'ready',
                '--epoch-file', folder/'epoch', '--steady-seconds', '10'], folder, 'upstream')
    daemon = start([inputs/(side+'-exec'), '--keep-in-foreground', '--conf-file='+str(folder/'config')], folder, 'daemon')
    for _ in range(100):
        try:
            if ready_dns(): break
        except (OSError, TimeoutError): pass
        time.sleep(.01)
    else: raise RuntimeError('daemon readiness failed')
    record_identity(daemon.pid, folder)
    common = [inputs/'m6a_loadgen', '--host', '127.0.0.1', '--clients', str(clients), '--rate', str(rate),
              '--seed', '0x293001', '--name-prefix', 'm6a.test', '--profile', profile, '--qtype', 'aaaa30',
              '--cache-names', '800', '--timeout-ms', '1000']
    if not dhcp and profile != 'miss':
        pre = start([inputs/'m6a_loadgen', '--mode', 'udp', '--host', '127.0.0.1', '--port', '15353',
                     '--clients', '32', '--rate', '200', '--seed', '0x293001', '--name-prefix', 'm6a.test',
                     '--profile', 'hit', '--qtype', 'aaaa30', '--cache-names', '800', '--timeout-ms', '1000',
                     '--duration-seconds', '5', '--warmup-seconds', '0', '--output', folder/'prewarm'], folder, 'prewarm')
        assert reap(pre, folder, 'prewarm')['exit'] == 0
        _, errors = check_load(folder, 'prewarm', 1000)
        if errors: raise RuntimeError('prewarm '+str(errors))
    before = process_ticks(daemon.pid); dump(folder/'before.json', before)
    observer = start([inputs/'predeploy_resource_probe', 'monitor', str(daemon.pid), '17'], folder, 'resources')
    args = common + ['--mode', mode, '--port', '67' if dhcp else '15353', '--duration-seconds', '10',
                     '--warmup-seconds', '5', '--output', folder/'client', '--epoch-file', folder/'epoch',
                     '--epoch-output', folder/'epoch.json']
    if dhcp: args += ['--client-port', '68', '--interface', 'lo', '--dhcp-first-address', '127.0.0.10', '--dhcp-renew-only']
    load = start(args, folder, 'client'); assert reap(load, folder, 'client')['exit'] == 0
    time.sleep(.3)
    # C's finished TCP children must be reaped before the cumulative endpoint.
    children = Path(f'/proc/{daemon.pid}/task/{daemon.pid}/children')
    for _ in range(100):
        if not children.read_text().strip(): break
        time.sleep(.01)
    else: raise RuntimeError('TCP children not reaped')
    after = process_ticks(daemon.pid); dump(folder/'after.json', after)
    reap(observer, folder, 'resources', terminate=True)
    reap(up, folder, 'upstream', terminate=True)
    reap(daemon, folder, 'daemon', terminate=True)
    value, errors = check_load(folder, 'client', rate*10, dhcp)
    upstream = json.loads((folder/'upstream.json').read_text())
    if upstream['delay_queue_dropped'] or upstream['total']['invalid_queries']: errors.append('upstream errors')
    if dhcp:
        lease_lines = len((folder/'leases').read_text().splitlines())
        if lease_lines != 150: errors.append('lease count')
    else: lease_lines = None
    result = {'valid': not errors, 'errors': errors, 'scenario': scenario, 'side': side,
              'window_cpu_ticks': sum(after['ticks'])-sum(before['ticks']),
              'window_completions': value['warmup']['correct']+value['measurement']['correct'],
              'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'), 'leases': lease_lines,
              'upstream_steady_requests': upstream['phases']['steady']['requests']}
    dump(folder/'result.json', result)
    return result


def lifecycle_case(root, folder, scenario, side):
    mode, scale = scenario.split('-'); hosts, leases = (999, 150) if scale == 'large' else (7, 6)
    p = start([root/'inputs/device_perf_lifecycle', mode, root/'inputs'/(side+'-exec'), folder,
               str(hosts), '10', '1000', str(leases)], folder, 'lifecycle')
    usage = reap(p, folder, 'lifecycle')
    rows = [json.loads(line) for line in (folder/'lifecycle.stdout').read_text().splitlines()]
    valid = usage['exit'] == 0 and len(rows) == 10 and all(row['ok'] for row in rows)
    dump(folder/'result.json', {'valid': valid, 'scenario': scenario, 'side': side, 'rows': len(rows)})
    return {'valid': valid}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args(); root = args.root.resolve(); inputs = root/'inputs'
    assert str(root).startswith('/tmp/dnsmasq-perf-oracle-')
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    assert digest(inputs/'dnsmasq-c') == C_HASH and digest(inputs/'dnsmasq-rust') == R_HASH
    for side in ('c', 'rust'):
        command = (f'{inputs}/lib/ld-musl-aarch64.so.1 --library-path {inputs}/lib {inputs}/dnsmasq-c'
                   if side == 'c' else f'{inputs}/dnsmasq-rust')
        path = inputs/(side+'-exec'); path.write_text('#!/bin/sh\nexec '+command+' "$@"\n'); path.chmod(0o755)
    dump(root/'identity.json', {'uname': list(platform.uname()), 'cpuinfo': Path('/proc/cpuinfo').read_text(),
         'meminfo': Path('/proc/meminfo').read_text(), 'input_hashes': {str(p.relative_to(inputs)):digest(p)
         for p in inputs.rglob('*') if p.is_file()}, 'protocol_sha256':digest(root/'protocol.md'),
         'netns': os.readlink('/proc/self/ns/net'), 'proc_pid_exe_note':'C is run by the exact image musl loader; exe is libc.so'})
    results = []
    try:
        for scenario in SCENARIOS:
            for pair in range(5):
                order = ('c','rust') if pair%2 == 0 else ('rust','c')
                for side in order:
                    label=f'{scenario}-r{pair+1}-{side}'; folder=root/'runs'/label; folder.mkdir(parents=True)
                    print(json.dumps({'event':'start','label':label,'epoch':time.time()}),flush=True)
                    if scenario.endswith(('small','large')): result=lifecycle_case(root,folder,scenario,side)
                    else: result=traffic_case(root,folder,scenario,side)
                    result['label']=label; results.append(result); dump(root/'progress.json',results)
                    print(json.dumps({'event':'finish',**result,'epoch':time.time()}),flush=True)
        dump(root/'complete.json',{'complete':True,'windows':len(results),'valid':sum(r['valid'] for r in results)})
    finally:
        for p in ACTIVE[:]:
            try: os.kill(p.pid,signal.SIGTERM)
            except ProcessLookupError: pass
        for p in ACTIVE[:]:
            try: os.wait4(p.pid,0)
            except ChildProcessError: pass


if __name__ == '__main__': main()
