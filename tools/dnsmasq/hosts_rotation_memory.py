#!/usr/bin/env python3
"""Exact-image TCP order page memory, cgroup and snapshot regression.

Run only through run_isolated.sh. Each name has two addresses. Hold a seed
connection while warming the parent, then accept and query 20 new connections.
The optional rolling case accepts a new child before dropping the previous one.
Unique addresses separate order/snapshot semantics from shared-address aliases.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from m2_rootfs import prepare, command, sha256, STOCK_SHA256

def stats(pid):
    rows = []
    pending = [pid]
    while pending:
        p = pending.pop()
        try:
            pending.extend(map(int, Path(f'/proc/{p}/task/{p}/children').read_text().split()))
            row = {'pid': p}
            for line in Path(f'/proc/{p}/smaps_rollup').read_text().splitlines():
                parts = line.split()
                key = parts[0].rstrip(':')
                if key in ('Pss', 'Rss', 'Private_Dirty', 'Private_Clean', 'Anonymous'):
                    row[key] = int(parts[1])
            rows.append(row)
        except FileNotFoundError:
            continue
    return {'processes': rows, 'sum': {key: sum((row.get(key, 0) for row in rows)) for key in ('Pss', 'Rss', 'Private_Dirty', 'Private_Clean', 'Anonymous')}}

def q(name):
    return struct.pack('!6H', 1234, 256, 1, 0, 0, 0) + b''.join((bytes([len(x)]) + x.encode() for x in name.split('.'))) + b'\x00' + struct.pack('!HH', 1, 1)

def validate(data, expected):
    assert len(data) >= 12 and data[:2] == b'\x04\xd2' and (struct.unpack('!H', data[6:8])[0] == expected), (expected, data.hex())

def address_order(data):
    # This fixture has exactly two A answers, each a 16-byte compressed RR.
    validate(data, 2)
    assert data[-6:-4] == data[-22:-20] == b'\0\4'
    return [data[-20:-16].hex(), data[-4:].hex()]

def relative_order(row, initial):
    # Do not assume large exact-C tables have identical order across starts.
    # Keep raw wire, and compare rotations relative to each
    # daemon's observed starting order rather than assuming a shared start.
    data = bytearray.fromhex(row['wire'])
    start = initial[row['name']]
    order = address_order(data)
    data[-20:-16] = bytes([0, 0, 0, start.index(order[0]) + 1])
    data[-4:] = bytes([0, 0, 0, start.index(order[1]) + 1])
    return {**row, 'wire': data.hex()}

def udp(name, expected=2):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        s.sendto(q(name), ('127.0.0.1', 15353))
        data = s.recv(4096)
        validate(data, expected)
        return data

def tcp(s, name, expected=2):
    p = q(name)
    s.sendall(struct.pack('!H', len(p)) + p)
    hdr = s.recv(2)
    assert len(hdr) == 2
    size = struct.unpack('!H', hdr)[0]
    data = b''
    while len(data) < size:
        block = s.recv(size - len(data))
        assert block
        data += block
    validate(data, expected)
    return data

def connect():
    s = socket.create_connection(('127.0.0.1', 15353), 2)
    s.settimeout(2)
    return s

def measure(cg):
    return {n: (cg / n).read_text().strip() for n in ('memory.current', 'memory.peak', 'memory.events', 'cgroup.procs')}

def run(a, side):
    out = a.output / side
    out.mkdir()
    root = prepare(a.image_root, None, out / 'stage', a.rust)

    def address(i, j):
        return f'10.{j + 1}.{i // 256}.{i % 256}' if a.unique_addresses else f'192.0.{j + 2}.{i % 250 + 1}'
    (root / 'm2/hosts').write_text(''.join((f'{address(i, j)} host{i:06d}.test\n' for i in range(a.names) for j in (0, 1))))
    argv = ['-k', '--conf-file=', '--no-resolv', '--no-hosts', '--user=root', '--group=root', '--listen-address=127.0.0.1', '--bind-interfaces', '--port=15353', '--pid-file=/m2/pid', '--host-record=ready.test,192.0.2.41', '--addn-hosts=/m2/hosts', '--cache-size=1000', '--log-facility=/dev/null']
    cg = None
    if a.budget_mib:
        cg = Path(tempfile.mkdtemp(prefix='full-rotation-check-', dir='/sys/fs/cgroup'))
        (cg / 'memory.max').write_text(str(a.budget_mib * 1024 * 1024))
        (cg / 'memory.swap.max').write_text('0')

    def enter():
        if cg:
            (cg / 'cgroup.procs').write_text(str(os.getpid()))
    result = {'side': side, 'argv': argv, 'names': a.names, 'rows': a.names * 2, 'unique_addresses': a.unique_addresses, 'budget_bytes': a.budget_mib * 1024 * 1024, 'samples': [], 'connections': [], 'orders': [], 'initial_order': {}}
    socks = []
    seed = None

    def sample(label):
        row = {'label': label, 'new_connections': len(socks), 'seed_open': seed is not None, 'process_exit': p.poll()}
        if p.poll() is None:
            row['stats'] = stats(p.pid)
        if cg:
            row['cgroup'] = measure(cg)
        result['samples'].append(row)
    try:
        with (out / 'stderr').open('wb') as log:
            p = subprocess.Popen(command(root, side, *argv), stdout=log, stderr=log, preexec_fn=enter)
            try:
                for _ in range(100):
                    if p.poll() is not None:
                        raise RuntimeError('startup exited')
                    try:
                        udp('ready.test', 1)
                        break
                    except (TimeoutError, ConnectionRefusedError):
                        time.sleep(0.02)
                else:
                    raise RuntimeError('startup timeout')
                sample('startup')
                seed = connect()
                tcp(seed, 'ready.test', 1)
                sample('seed_held')
                t = time.monotonic()
                last_keepalive = t
                for i in range(a.names if a.warmup else 0):
                    name = f'host{i:06d}.test'
                    result['initial_order'][name] = address_order(udp(name))
                    if time.monotonic() - last_keepalive > 2:
                        tcp(seed, 'ready.test', 1)
                        last_keepalive = time.monotonic()
                result['warmup_seconds'] = time.monotonic() - t
                result['warmup_queries'] = a.names if a.warmup else 0
                sample('parent_udp_warmed')
                for i in range(20):
                    # Retire the seed before adding the twentieth new child (C limit).
                    if i == 19:
                        seed.close()
                        seed = None
                        time.sleep(0.1)
                    row = {'connection': i + 1}
                    try:
                        s = connect()
                        socks.append(s)
                        data = tcp(s, f'host{i:06d}.test')
                        result['orders'].append({'label': f'new-{i}', 'name': f'host{i:06d}.test', 'wire': data.hex()})
                        row['ok'] = True
                    except Exception as e:
                        row.update(ok=False, error=repr(e))
                    time.sleep(0.025)
                    row['process_exit'] = p.poll()
                    if cg:
                        row['cgroup'] = measure(cg)
                    result['connections'].append(row)
                    if i in (0, 9, 18, 19) or not row['ok']:
                        sample('new_tcp_' + str(i + 1))
                    if not row['ok']:
                        break
                if a.rolling and len(socks) == 20 and all((row['ok'] for row in result['connections'])):
                    for client in socks[1:]:
                        client.close()
                    socks = socks[:1]
                    time.sleep(0.1)
                    sample('rolling_start')
                    for i in range(a.rolling):
                        name = f'host{i % a.names:06d}.test'
                        result['orders'].append({'label': f'rolling-parent-{i}', 'name': name, 'wire': udp(name).hex()})
                        client = connect()
                        socks.append(client)
                        result['orders'].append({'label': f'rolling-new-{i}', 'name': name, 'wire': tcp(client, name).hex()})
                        result['orders'].append({'label': f'rolling-old-{i}', 'name': name, 'wire': tcp(socks[0], name).hex()})
                        socks[0].close()
                        socks.pop(0)
                    sample('rolling_end')
                try:
                    udp('ready.test', 1)
                    result['udp_after'] = True
                except Exception as e:
                    result.update(udp_after=False, udp_error=repr(e))
                result['exit_before_cleanup'] = p.poll()
                if cg:
                    result['final_cgroup'] = measure(cg)
            except Exception as e:
                result['driver_error'] = repr(e)
                if cg:
                    result['final_cgroup'] = measure(cg)
            finally:
                for s in socks:
                    s.close()
                if seed:
                    seed.close()
                if p.poll() is None:
                    p.terminate()
                try:
                    p.wait(3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                result['exit'] = p.returncode
        if cg:
            for _ in range(100):
                if not (cg / 'cgroup.procs').read_text().strip():
                    break
                time.sleep(0.02)
            result['cleanup_cgroup'] = measure(cg)
    finally:
        if cg:
            (cg / 'cgroup.kill').write_text('1')
            for _ in range(100):
                try:
                    cg.rmdir()
                    break
                except OSError:
                    time.sleep(0.02)
            result['cgroup_removed'] = not cg.exists()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--image-root', type=Path, required=True)
    ap.add_argument('--rust', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--budget-mib', type=int, default=0)
    ap.add_argument('--names', type=int, default=25000)
    ap.add_argument('--warmup', action='store_true')
    ap.add_argument('--rolling', type=int, default=0)
    ap.add_argument('--unique-addresses', action='store_true')
    a = ap.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert a.names >= 20 and a.rolling >= 0 and a.budget_mib >= 0
    assert not a.unique_addresses or a.names <= 65536
    assert not a.output.exists()
    a.output.mkdir()
    (a.output / 'driver.py').write_bytes(Path(__file__).read_bytes())
    result = {'driver_sha256': sha256(Path(__file__)), 'c_sha256': sha256(a.image_root / 'usr/sbin/dnsmasq'), 'rust_sha256': sha256(a.rust), 'runs': []}
    assert result['c_sha256'] == STOCK_SHA256
    for side in ('c', 'rust'):
        r = run(a, side)
        result['runs'].append(r)
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(side, [(s['label'], s.get('stats', {}).get('sum', {}).get('Pss')) for s in r['samples']], r.get('udp_after'), r.get('driver_error'), r.get('final_cgroup'), flush=True)
    result['orders_matched'] = result['runs'][0]['orders'] == result['runs'][1]['orders']
    result['raw_order_differences'] = [c['label'] for c, r in zip(
        result['runs'][0]['orders'], result['runs'][1]['orders']) if c != r]
    if a.unique_addresses and a.warmup:
        relative = [[relative_order(row, run['initial_order']) for row in run['orders']]
                    for run in result['runs']]
        result['relative_orders_matched'] = relative[0] == relative[1]
    result['healthy'] = all(
        not r.get('driver_error') and len(r['connections']) == 20
        and all(c['ok'] for c in r['connections']) and r.get('udp_after')
        and r.get('exit_before_cleanup') is None
        and (not a.budget_mib or (
            r.get('cgroup_removed')
            and 'oom_kill 0' in r.get('final_cgroup', {}).get('memory.events', '').splitlines()
        ))
        for r in result['runs']
    )
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert result['healthy'], 'a daemon failed the connection/UDP/recovery checks'
    assert result.get('relative_orders_matched', result['orders_matched']), 'C/Rust inherited or private order differs'
if __name__ == '__main__':
    main()
