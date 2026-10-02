#!/usr/bin/env python3
"""Exact-image ENOSPC and EMFILE recovery probes for M3."""
import argparse, hashlib, json, os, resource, signal, socket, subprocess, time
from pathlib import Path

from dhcp_lease_lifecycle import packet, rows
from dns_service_probe import query, semantics
from m2_rootfs import command, prepare, sha256


def dora(root, lease, out):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('0.0.0.0', 68)); sock.settimeout(3)
    try:
        discover = packet(1, 0x4d330001, 1, '127.0.0.10')
        sock.sendto(discover, ('255.255.255.255', 67))
        offer, _ = sock.recvfrom(16384)
        request = packet(3, 0x4d330002, 1, socket.inet_ntoa(offer[16:20]), True)
        sock.sendto(request, ('255.255.255.255', 67))
        reply, _ = sock.recvfrom(16384)
        (out / 'discover').write_bytes(discover); (out / 'offer').write_bytes(offer)
        (out / 'request').write_bytes(request); (out / 'ack').write_bytes(reply)
        return socket.inet_ntoa(reply[16:20])
    finally:
        sock.close()


def start(root, impl, config, pid):
    p = subprocess.Popen(command(root, impl, '-k', '-C', '/m3/config', '-x', '/m3/pid'),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if p.poll() is not None: raise RuntimeError(f'{impl} exited {p.returncode}')
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(.1); s.sendto(query('m3.test'), ('127.0.0.1', 15353)); s.recv(4096)
            return p
        except OSError: time.sleep(.05)
    raise TimeoutError(f'{impl} readiness')


def stop(p):
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try: p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(5)
    return p.returncode == 0


def run_side(args, impl, out):
    out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, out / 'rootfs-stage', args.rust)
    (root / 'm3').mkdir(exist_ok=True)
    config = root / 'm3/config'
    config.write_text('no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\n'
                      'user=root\nno-ping\ndhcp-authoritative\n'
                      'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,60s\n'
                      'dhcp-leasefile=/m3/leases\nserver=127.0.0.2#15354\n')
    lease = root / 'm3/leases'; lease.write_bytes(b'')
    result = {'implementation': impl, 'binary_sha256': sha256(root / ('usr/sbin/dnsmasq' if impl == 'c' else 'usr/sbin/dnsmasq-rs')), 'checks': []}
    process = None
    try:
        process = start(root, impl, config, root / 'm3/pid')
        result['checks'].append({'name': 'ready', 'pass': True})
        (out / 'enospc').mkdir()
        mount = root / 'm3/full'; mount.mkdir(exist_ok=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=4096', 'm3-full', str(mount)], check=True)
        try:
            (mount / 'full').write_bytes(b'x' * 4096)
            address = dora(root, lease, out / 'enospc')
            result['checks'].append({'name': 'enospc-no-corrupt-ack', 'pass': not rows(lease)})
            (mount / 'full').unlink()
            deadline = time.monotonic() + 65
            while time.monotonic() < deadline and not rows(lease): time.sleep(.25)
            result['checks'].append({'name': 'enospc-retry-recovers', 'pass': bool(rows(lease)), 'address': address})
        finally:
            subprocess.run(['umount', str(mount)], check=True)
        limit = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)[0]
        resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (limit, limit))
        result['fd_limit'] = limit
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(.5); sock.sendto(query('m3.test'), ('127.0.0.1', 15353))
            try: sock.recv(4096)
            except socket.timeout: pass
        result['checks'].append({'name': 'emfile-daemon-alive', 'pass': process.poll() is None})
        resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (1024, 1024))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2); sock.sendto(query('m3.test'), ('127.0.0.1', 15353)); sock.recv(4096)
        result['checks'].append({'name': 'emfile-recovery', 'pass': process.poll() is None})
    except Exception as error:
        result['checks'].append({'name': 'runner', 'pass': False, 'error': repr(error)})
    finally:
        result['checks'].append({'name': 'clean-exit', 'pass': stop(process) if process else False})
    result['passed'] = all(check['pass'] for check in result['checks'])
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image-root', type=Path, required=True); parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); args.out.mkdir(parents=True, exist_ok=False)
    results = {impl: run_side(args, impl, args.out / impl) for impl in ('c', 'rust')}
    report = {'c': results['c'], 'rust': results['rust'], 'binary_distinct': results['c']['binary_sha256'] != results['rust']['binary_sha256']}
    report['passed'] = all(results[impl]['passed'] for impl in ('c', 'rust'))
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'c_sha256': results['c']['binary_sha256'], 'rust_sha256': results['rust']['binary_sha256']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
