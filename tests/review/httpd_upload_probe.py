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
import time

BIN = pathlib.Path('components/httpd/target/debug/httpd-rs').resolve()
SINK = """#!/bin/sh
sum=$(sha256sum | cut -d' ' -f1)
printf 'Content-Type: text/plain\\r\\n\\r\\n%s %s\\n' "$CONTENT_LENGTH" "$sum"
"""


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
        (root / 'static.txt').write_text('static\n')
        with socket.socket() as k:
            k.bind(('127.0.0.1', 0))
            port = k.getsockname()[1]
        srv = subprocess.Popen([str(BIN), '-p', f'127.0.0.1:{port}', '-h', tmp,
                                '-t', '60', '-T', '60', '-u', '/ubus'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        base_rss = rss_kib(srv.pid)
        peak = base_rss
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
                peak = max(peak, rss_kib(srv.pid))
                results[f'content-length {n}'] = 'ok' if ok else f'MISMATCH head={head.splitlines()[0]} got={got[:1]}'
            # chunked, and chunked + Expect: 100-continue
            payload = os.urandom(6 * 1024 * 1024)
            want = hashlib.sha256(payload).hexdigest()
            head, body = post(port, '/cgi-bin/sink', payload, chunked=True)
            results['chunked 6 MiB'] = 'ok' if want in body.decode(errors='replace') else f'MISMATCH {head.splitlines()[0]}'
            head, body = post(port, '/cgi-bin/sink', payload, expect100=True, extra='Expect: 100-continue\r\n')
            results['expect-100 6 MiB'] = 'ok' if want in body.decode(errors='replace') else f'MISMATCH {head.splitlines()[0]}'
            peak = max(peak, rss_kib(srv.pid))
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
            results['rss_kib'] = {'idle': base_rss, 'peak': peak, 'delta': peak - base_rss}
        finally:
            srv.terminate()
            srv.wait(timeout=10)
    print(json.dumps(results, indent=2))
    bad = [k for k, v in results.items() if isinstance(v, str) and v != 'ok']
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
