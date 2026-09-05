#!/usr/bin/env python3
"""Upload acceptance probe for httpd-rs (R30-05).

Run from the repository root after `cargo build --manifest-path
components/httpd/Cargo.toml`. Loopback only, temporary directories only; never
touches a router and never triggers sysupgrade. Prints one line per case.
"""
import hashlib
import json
import os
import pathlib
import resource
import socket
import subprocess
import sys
import tempfile
import threading
import time

BIN = pathlib.Path('components/httpd/target/debug/httpd-rs').resolve()
SINK = """#!/bin/sh
sum=$(sha256sum | cut -d' ' -f1)
printf 'Content-Type: text/plain\\r\\n\\r\\n%s %s\\n' "$CONTENT_LENGTH" "$sum"
"""
# rejects before reading a byte of the body
DENY = """#!/bin/sh
printf 'Status: 403 Forbidden\\r\\nContent-Type: text/plain\\r\\n\\r\\nrejected\\n'
"""


def cpu_ms(pid):
    """Process CPU time. /proc on Linux, ps elsewhere."""
    stat = pathlib.Path(f'/proc/{pid}/stat')
    if stat.exists():
        d = stat.read_text().split()
        return (int(d[13]) + int(d[14])) * 10
    out = subprocess.run(['ps', '-o', 'time=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
    m, sec = out.split(':')[-2:]
    return int(float(m) * 60000 + float(sec) * 1000)


def rss_kib(pid):
    out = subprocess.run(['ps', '-o', 'rss=', '-p', str(pid)], capture_output=True, text=True).stdout
    return int(out.strip() or 0)


def read_response(sock):
    buf = b''
    while b'\r\n\r\n' not in buf:
        c = sock.recv(65536)
        if not c:
            return buf.decode(errors='replace'), b''
        buf += c
    head, rest = buf.split(b'\r\n\r\n', 1)
    while True:
        c = sock.recv(65536)
        if not c:
            break
        rest += c
    return head.decode(errors='replace'), unchunk(head, rest)


def unchunk(head, body):
    """Strip chunk framing when the response used it (CGI relays always do)."""
    if b'transfer-encoding: chunked' not in head.lower():
        return body
    out, i = b'', 0
    while True:
        j = body.find(b'\r\n', i)
        if j < 0:
            return out
        size = int(body[i:j].split(b';')[0], 16)
        if size == 0:
            return out
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def read_framed(f, head):
    """Body of one keep-alive response: chunked (what CGI relays use) or length."""
    lines = head.split(b'\r\n')
    if any(l.lower().startswith(b'transfer-encoding: chunked') for l in lines):
        out = b''
        while True:
            size = int(f.readline().strip().split(b';')[0], 16)
            if size == 0:
                f.readline()
                return out
            out += f.read(size)
            f.read(2)
    n = [l.split(b': ')[1] for l in lines if l.lower().startswith(b'content-length')]
    return f.read(int(n[0])) if n else b''


def post(port, path, payload, chunked=False, expect100=False, extra=''):
    with socket.create_connection(('127.0.0.1', port), timeout=60) as s:
        if chunked:
            head = f'POST {path} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n{extra}\r\n'
        else:
            head = (f'POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(payload)}\r\n'
                    f'Connection: close\r\n{extra}\r\n')
        s.sendall(head.encode())
        if expect100:
            s.settimeout(5)
            first = s.recv(64)
            if not first.startswith(b'HTTP/1.1 100'):
                return f'no 100-continue: {first!r}', b''
            s.settimeout(60)
        if chunked:
            for i in range(0, len(payload), 65536):
                part = payload[i:i + 65536]
                s.sendall(f'{len(part):X}\r\n'.encode() + part + b'\r\n')
            s.sendall(b'0\r\n\r\n')
        else:
            s.sendall(payload)
        return read_response(s)


def main():
    results = {}
    with tempfile.TemporaryDirectory(prefix='owrt-upload-') as tmp:
        root = pathlib.Path(tmp)
        (root / 'cgi-bin').mkdir()
        sink = root / 'cgi-bin' / 'sink'
        sink.write_text(SINK)
        sink.chmod(0o755)
        deny = root / 'cgi-bin' / 'deny'
        deny.write_text(DENY)
        deny.chmod(0o755)
        (root / 'static.txt').write_text('static\n')
        with socket.socket() as k:
            k.bind(('127.0.0.1', 0))
            port = k.getsockname()[1]
        srv = subprocess.Popen([str(BIN), '-p', f'127.0.0.1:{port}', '-h', tmp,
                                '-t', '5', '-T', '60', '-u', '/ubus'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        base_rss = rss_kib(srv.pid)
        # Sample continuously, not once per request: a per-request sample can
        # miss the transfer itself, which is exactly where growth would show.
        peak = [base_rss]
        watching = threading.Event()
        watching.set()

        def watch():
            while watching.is_set():
                peak[0] = max(peak[0], rss_kib(srv.pid))
                time.sleep(0.01)

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        try:
            sizes = [0, 1024, 4 * 1024 * 1024 - 1, 4 * 1024 * 1024 + 1,
                     5 * 1024 * 1024, 32 * 1024 * 1024]
            for n in sizes:
                payload = os.urandom(n)
                want = hashlib.sha256(payload).hexdigest()
                head, body = post(port, '/cgi-bin/sink', payload)
                got = body.decode(errors='replace').split()
                ok = head.startswith('HTTP/1.1 200') and len(got) == 2 and got[1] == want
                ok = ok and (got[0] == str(n) if n else True)
                results[f'content-length {n}'] = 'ok' if ok else f'MISMATCH head={head.splitlines()[0]} got={got[:1]}'
            # chunked, and chunked + Expect: 100-continue
            payload = os.urandom(6 * 1024 * 1024)
            want = hashlib.sha256(payload).hexdigest()
            head, body = post(port, '/cgi-bin/sink', payload, chunked=True)
            results['chunked 6 MiB'] = 'ok' if want in body.decode(errors='replace') else f'MISMATCH {head.splitlines()[0]}'
            head, body = post(port, '/cgi-bin/sink', payload, expect100=True, extra='Expect: 100-continue\r\n')
            results['expect-100 6 MiB'] = 'ok' if want in body.decode(errors='replace') else f'MISMATCH {head.splitlines()[0]}'
            # /ubus keeps its own 65536 cap
            # at the cap the bridge answers normally (a JSON-RPC parse error);
            # one byte over must be refused by the transport, not silently dropped
            head, _ = post(port, '/ubus', b'{' + b'x' * 65535)
            line = head.splitlines()[0] if head else 'no response'
            results['/ubus 65536 bytes (at cap)'] = 'ok' if '413' not in line and line else f'got {line}'
            head, _ = post(port, '/ubus', b'{' + b'x' * 65536)
            line = head.splitlines()[0] if head else 'no response'
            results['/ubus 65537 bytes (over cap)'] = 'ok' if '413' in line else f'got {line}'
            # keep-alive: two POSTs on one connection must not bleed
            with socket.create_connection(('127.0.0.1', port), timeout=30) as s:
                f = s.makefile('rb')
                for tag in (b'first', b'second'):
                    s.sendall(f'POST /cgi-bin/sink HTTP/1.1\r\nHost: x\r\nContent-Length: {len(tag)}\r\n\r\n'.encode() + tag)
                    h = b''
                    while not h.endswith(b'\r\n\r\n'):
                        h += f.read(1)
                    body = read_framed(f, h)
                    got = body.decode(errors='replace').split()
                    want = hashlib.sha256(tag).hexdigest()
                    results[f'keep-alive {tag.decode()}'] = 'ok' if len(got) == 2 and got[1] == want else f'MISMATCH {got}'
            # a request rejected before any handler must still get its status
            for name, raw in (
                ('conflicting framing', b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n'
                                        b'Transfer-Encoding: chunked\r\n\r\n'),
                ('garbage request line', b'NOTAMETHOD\r\n\r\n'),
            ):
                with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
                    s.sendall(raw)
                    s.settimeout(3)
                    try:
                        line = s.recv(200).split(b'\r\n')[0].decode()
                    except OSError as e:
                        line = f'<{e}>'
                results[f'reject: {name}'] = 'ok' if '400' in line else f'got {line or "EMPTY"}'
            # A client that sends headers then stops. Its own server with a
            # tight script timeout and a long network timeout, so the result
            # shows which of the two actually bounded the request.
            with socket.socket() as k:
                k.bind(('127.0.0.1', 0))
                port2 = k.getsockname()[1]
            srv2 = subprocess.Popen([str(BIN), '-p', f'127.0.0.1:{port2}', '-h', tmp,
                                     '-t', '1', '-T', '30'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            try:
                for path, want, limit in (('sink', '504', 2.5), ('deny', '403', 2.5)):
                    with socket.create_connection(('127.0.0.1', port2), timeout=30) as s:
                        s.sendall(f'POST /cgi-bin/{path} HTTP/1.0\r\nContent-Length: 100\r\n\r\n'.encode())
                        t0 = time.monotonic()
                        try:
                            line = s.recv(200).split(b'\r\n')[0].decode()
                        except OSError as e:
                            line = f'<{e}>'
                        took = time.monotonic() - t0
                    ok = want in line and took < limit
                    results[f'stalled upload -> /cgi-bin/{path}'] = (
                        'ok' if ok else f'got {line or "EMPTY"} after {took:.3f}s')
                # Several idle uploads at once: waiting must cost almost no CPU.
                # Registering stdin for POLLOUT with nothing to write used to
                # spin, burning ~1 core per stalled connection.
                before, t0 = cpu_ms(srv2.pid), time.monotonic()
                idle = []
                for _ in range(3):
                    s = socket.create_connection(('127.0.0.1', port2), timeout=30)
                    s.sendall(b'POST /cgi-bin/sink HTTP/1.0\r\nContent-Length: 100\r\n\r\n')
                    idle.append(s)
                for s in idle:
                    try:
                        s.recv(200)
                    except OSError:
                        pass
                    s.close()
                wall = time.monotonic() - t0
                cpu = (cpu_ms(srv2.pid) - before) / 1000
                results['3 stalled uploads: cpu/wall'] = (
                    'ok' if cpu < wall * 0.25 else f'{cpu:.3f}s cpu over {wall:.3f}s wall (busy-wait)')
            finally:
                srv2.terminate()
                srv2.wait(timeout=10)
            # a slow drip must still arrive byte-exact
            payload = os.urandom(300 * 1024)
            with socket.create_connection(('127.0.0.1', port), timeout=60) as s:
                s.sendall(f'POST /cgi-bin/sink HTTP/1.0\r\nContent-Length: {len(payload)}\r\n\r\n'.encode())
                for i in range(0, len(payload), 4096):
                    s.sendall(payload[i:i + 4096])
                    time.sleep(0.002)
                _, body = read_response(s)
            got = body.decode(errors='replace').split()
            want = hashlib.sha256(payload).hexdigest()
            results['slow drip 300 KiB'] = 'ok' if len(got) == 2 and got[1] == want else f'MISMATCH {got}'
            watching.clear()
            watcher.join(timeout=2)
            results['rss_kib'] = {'idle': base_rss, 'peak_sampled_during_transfer': peak[0],
                                  'delta': peak[0] - base_rss}
        finally:
            watching.clear()
            srv.terminate()
            srv.wait(timeout=10)
    print(json.dumps(results, indent=2))
    bad = [k for k, v in results.items() if isinstance(v, str) and v != 'ok']
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
