#!/usr/bin/env python3
"""Diagnostic probe, not a passing regression test.

Run from the repository root after building components/httpd. Starts only a
loopback server with temporary CGI fixtures; prints timing and child state.
The finite sleep fixtures terminate on their own. Never accesses a router.
"""
import json
import pathlib
import socket
import subprocess
import tempfile
import time


def main():
    binary = pathlib.Path('components/httpd/target/debug/httpd-rs').resolve()
    results = {}
    cases = {
        'closed': 'exec 1>&-\nsleep 3\n',
        'descendant': 'sleep 3 &\nwait\n',
        'stream': (
            "printf 'Content-Type: text/plain\\r\\n\\r\\nhello\\n'\n"
            "sleep 2\nprintf 'done\\n'\n"
        ),
        'bad': "printf 'invalid\\r\\n'\nsleep 1\n",
    }
    with tempfile.TemporaryDirectory(prefix='owrt-audit-') as tmp:
        root = pathlib.Path(tmp)
        (root / 'cgi-bin').mkdir()
        for name, body in cases.items():
            script = root / 'cgi-bin' / name
            script.write_text('#!/bin/sh\n' + body)
            script.chmod(0o755)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [str(binary), '-p', f'127.0.0.1:{port}', '-h', tmp,
             '-t', '1', '-T', '5'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(process.stderr.read().decode())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            for name in cases:
                with socket.create_connection(('127.0.0.1', port), timeout=6) as sock:
                    start = time.monotonic()
                    sock.sendall(f'GET /cgi-bin/{name} HTTP/1.0\r\n\r\n'.encode())
                    first = sock.recv(65536)
                    results[name] = {
                        'first_byte_seconds': round(time.monotonic() - start, 3),
                        'status': first.split(b'\r\n')[0].decode(),
                    }
                    while sock.recv(65536):
                        pass
            time.sleep(.1)
            children = subprocess.run(
                ['ps', '-axo', 'pid,ppid,stat,comm'],
                capture_output=True, text=True, check=True,
            ).stdout
            results['remaining_children'] = [
                line.strip() for line in children.splitlines()[1:]
                if line.split()[1] == str(process.pid)
            ]
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stderr.close()
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
