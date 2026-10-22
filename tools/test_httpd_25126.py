#!/usr/bin/env python3
"""25.12.6 HTTP security regressions in disposable Linux namespaces.

Run on Linux with sudo/unshare, an extracted exact 25.12.6 rootfs, and an
AArch64 musl candidate. No physical router or host interface is used.
"""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True)


@contextlib.contextmanager
def disposable_rootfs(source, candidate):
    temp = Path(tempfile.mkdtemp(prefix="owrt-25126-httpd-")).resolve()
    root = temp / "rootfs"
    try:
        # Preserve exact permissions and device nodes; do not make the source
        # image writable/readable just to accommodate the unprivileged runner.
        run("sudo", "-n", "cp", "-a", "--reflink=auto", source, root)
        run("sudo", "-n", "mkdir", "-p", root / "tmp")
        run("sudo", "-n", "install", "-m", "755", candidate, root / "tmp/httpd-rs")
        yield root
    finally:
        run("sudo", "-n", "rm", "-rf", "--", temp)


def put(root, name, text, mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def request(path="/plain.txt", fields=b"", method="GET", body=b"", version="1.0"):
    return f"{method} {path} HTTP/{version}\r\n".encode() + fields + b"\r\n" + body


def exchange(port, raw, context=None):
    data = bytearray()
    closed = False
    transport = socket.create_connection(("127.0.0.1", port), timeout=4)
    with context.wrap_socket(transport, server_hostname="fixture.invalid") if context else transport as sock:
        sock.sendall(raw)
        try:
            while part := sock.recv(65536):
                data.extend(part)
            closed = True
        except ConnectionResetError:
            closed = True
        except TimeoutError:
            pass
    return bytes(data), closed


def summary(raw, closed):
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else None
    headers = {}
    for field in head.split(b"\r\n")[1:]:
        name, separator, value = field.partition(b":")
        if separator and name.lower() in (b"content-type", b"www-authenticate"):
            headers[name.decode().lower()] = value.strip().decode()
    # All exact-comparison cases use HTTP/1.0, so no chunk decoding is needed.
    try:
        content = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        content = body.decode("utf-8", "replace")
    return {"status": status, "headers": headers, "body": content, "closed": closed}


def field_bytes(size):
    lines = bytearray()
    while size > 3000:
        lines.extend(b"X:" + b"v" * 2996 + b"\r\n")
        size -= 3000
    assert size >= 4
    return bytes(lines) + b"X:" + b"v" * (size - 4) + b"\r\n"


def inside(args):
    root, output = args.rootfs, args.output
    output.mkdir(parents=True, exist_ok=True)
    run("mount", "--make-rprivate", "/")
    run("ip", "link", "set", "lo", "up")
    for name in ("proc", "dev", "tmp", "tmp/out", "var/run/ubus"):
        (root / name).mkdir(parents=True, exist_ok=True)
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "tmpfs", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", str(minor))
    put(root, "www/plain.txt", "ordinary-response\n")
    put(root, "www/cgi-bin/tls-echo", "#!/bin/sh\nprintf 'Content-Type: application/octet-stream\\r\\n\\r\\n'\ncat\n", 0o755)
    put(root, "www/sentinel", "HIDDEN-REQUEST-EXECUTED\n")
    put(root, "www/target.css", "body {}\n")
    (root / "www/alias.dat").symlink_to("target.css")
    (root / "www/chain.txt").symlink_to("alias.dat")
    put(root, "tmp/httpd-empty.conf", "")
    put(root, "tmp/httpd-auth.conf", "/ubus:user:secret\n")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=fixture.invalid", "-keyout", root / "tmp/tls-key.pem", "-out", root / "tmp/tls-cert.pem")
    run("openssl", "x509", "-in", root / "tmp/tls-cert.pem", "-outform", "DER", "-out", root / "tmp/tls-cert.der")
    run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", root / "tmp/tls-key.pem", "-outform", "DER",
        "-out", root / "tmp/tls-key.der")
    processes, logs = [], []
    records = {}

    def start(name, *command):
        log = (output / (name + ".log")).open("wb")
        logs.append(log)
        child = subprocess.Popen(["chroot", str(root), *command], stdout=log, stderr=log)
        processes.append(child)
        return child

    def observe(name, raw, expected=None, port=18080, exact=True, context=None):
        wire, closed = exchange(port, raw, context)
        (output / (name + ".bin")).write_bytes(wire)
        item = summary(wire, closed)
        item["exact"] = exact
        if expected is not None:
            assert item["status"] == expected, (name, item)
        assert closed, (name, "connection did not close")
        records[name] = item
        return item, wire

    try:
        start("ubusd", "/sbin/ubusd")
        for _ in range(100):
            if (root / "var/run/ubus/ubus.sock").exists():
                break
            time.sleep(.05)
        start("rpcd", "/sbin/rpcd", "-s", "/var/run/ubus/ubus.sock")
        for _ in range(100):
            ready = subprocess.run(["chroot", str(root), "/bin/ubus", "list", "session"], capture_output=True)
            if ready.returncode == 0 and b"session" in ready.stdout:
                break
            time.sleep(.05)
        else:
            raise AssertionError("exact-image rpcd session object did not register")
        binary = "/usr/sbin/uhttpd" if args.side == "original" else "/tmp/httpd-rs"
        common = ("-f", "-h", "/www", "-x", "/cgi-bin", "-u", "/ubus", "-a", "-k", "2", "-T", "2", "-t", "2")
        subject = start("httpd", binary, *common, "-c", "/tmp/httpd-empty.conf", "-p", "127.0.0.1:18080")
        start("auth", binary, *common, "-c", "/tmp/httpd-auth.conf", "-p", "127.0.0.1:18081")
        start("tls", binary, *common, "-c", "/tmp/httpd-empty.conf", "-s", "127.0.0.1:18082",
              "-C", "/tmp/tls-cert.der", "-K", "/tmp/tls-key.der")
        for port in (18080, 18081):
            for _ in range(100):
                try:
                    if exchange(port, request())[0].startswith(b"HTTP/1.0 200 "):
                        break
                except OSError:
                    pass
                time.sleep(.05)
            else:
                raise AssertionError(f"listener {port} did not become ready")
        observe("ordinary", request(), 200)
        # The exact image's TLS provider supports TLS 1.2. TLS 1.3 is checked
        # separately against the existing Rust server, not claimed as stock parity.
        for version in (ssl.TLSVersion.TLSv1_2,):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = context.maximum_version = version
            item, _ = observe(f"tls-{version.name}", request(), 200, port=18082, context=context)
            assert item["body"] == "ordinary-response\n", item
            body = b"tls-cgi-payload\n" * 2048
            item, _ = observe(f"tls-{version.name}-cgi", request("/cgi-bin/tls-echo",
                f"Content-Length: {len(body)}\r\n".encode(), "POST", body), 200, port=18082, context=context)
            assert item["body"] == body.decode(), item
        for name, expected in (("alias.dat", "text/css"), ("chain.txt", "application/octet-stream")):
            item, _ = observe("mime-" + name, request("/" + name), 200)
            assert item["headers"]["content-type"] == expected, item
        for count in (99, 100, 101):
            observe(f"fields-{count}", request(fields=b"X:\r\n" * count), 200 if count <= 100 else 431)
        for size in (16383, 16384, 16385):
            observe(f"bytes-{size}", request(fields=field_bytes(size)), 200 if size <= 16384 else 431)
        for index, field in enumerate((b": x", b" X: x", b"X : x", b"X\t: x", b"X@Y: x", b"X(Y): x", b"X: a\rb", b"X: a\r")):
            observe(f"bad-field-{index}", request(fields=field + b"\r\n"), 400)
        observe("ows", request(fields=b"X: \tvalue\t \r\n"), 200)
        observe("adjacent-tab-space", request(fields=b"Host:\t x\r\n"), 200)
        observe("adjacent-tab-backspace", request(fields=b"Host:\t\x08x\r\n"), 400)
        for index, (path, auth, status) in enumerate((("/ubus", "", 401), ("/ubus/list", "", 401),
                ("/ubus/subscribe/session", "", 401), ("/ubus/call/session", "Basic dXNlcjp3cm9uZw==", 401),
                ("/ubus?x=1", "Bearer wrong", 401), ("/ubus", "Basic dXNlcjpzZWNyZXQ=", 200))):
            observe(f"auth-{index}", request(path, f"Authorization: {auth}\r\n".encode(), "OPTIONS"), status, port=18081)
        for index, params in enumerate((None, True, 7, 1.5, "scalar", [], {"ubus_rpc_session": "injected"})):
            body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "access", "params": params}).encode()
            item, _ = observe(f"params-{index}", request("/ubus/call/session", f"Content-Length: {len(body)}\r\n".encode(), "POST", body), 200)
            assert item["body"].get("error", {}).get("code") == -32602, item
        for name, payload in (("valid", b"2\r\n{}\r\n0\r\n\r\n"),
                ("extension", b"2;name=value;flag\r\n{}\r\n0\r\n\r\n"),
                ("trailer", b"2\r\n{}\r\n0\r\nX: v\r\n\r\n")):
            observe("chunk-" + name, request("/ubus", b"Transfer-Encoding: chunked\r\n", "POST", payload), 200)
        hidden = request("/sentinel", b"Connection: close\r\n", version="1.1")
        for index, size in enumerate((b"", b" 2", b"+2", b"0x2", b"2 ", b"2;bad=oops!", b"80000000")):
            payload = size + b"\r\n{}\r\n0\r\n\r\n" + hidden
            _, wire = observe(f"bad-chunk-{index}", request("/ubus", b"Transfer-Encoding: chunked\r\n", "POST", payload, "1.1"), exact=False)
            assert b"HIDDEN-REQUEST-EXECUTED" not in wire and wire.count(b"HTTP/1.1 ") <= 1
        _, wire = observe("bad-chunk-separator", request("/ubus", b"Transfer-Encoding: chunked\r\n", "POST", b"2\r\n{}XX0\r\n\r\n" + hidden, "1.1"), exact=False)
        assert b"HIDDEN-REQUEST-EXECUTED" not in wire and wire.count(b"HTTP/1.1 ") <= 1
        trailer = b"2\r\n{}\r\n0\r\nGET /sentinel HTTP/1.1\r\n\r\n"
        _, wire = observe("trailer-pipeline", request("/ubus", b"Transfer-Encoding: chunked\r\n", "POST", trailer, "1.1") + request(fields=b"Connection: close\r\n", version="1.1"), exact=False)
        assert b"HIDDEN-REQUEST-EXECUTED" not in wire and wire.count(b"HTTP/1.1 ") == 2 and b"ordinary-response" in wire
        _, wire = observe("unread-body", request(fields=f"Content-Length: {len(hidden)}\r\n".encode(), body=hidden, version="1.1"), exact=False)
        assert b"HIDDEN-REQUEST-EXECUTED" not in wire and wire.count(b"HTTP/1.1 ") == 1
        observe("final-health", request(), 200)
        assert subject.poll() is None, "HTTP daemon exited"
        return records
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for log in logs:
            log.close()
        (output / "results.json").write_text(json.dumps(records, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--side", choices=("original", "candidate"))
    args = parser.parse_args()
    args.rootfs, args.output = args.rootfs.resolve(), args.output.resolve()
    if args.inside:
        inside(args)
        return
    assert args.candidate and args.candidate.is_file(), "candidate binary required"
    assert "25.12.6" in (args.rootfs / "etc/openwrt_release").read_text(), "requires exact 25.12.6 rootfs"
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for side in ("original", "candidate"):
        with disposable_rootfs(args.rootfs, args.candidate) as root:
            subprocess.run(["sudo", "-n", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                            sys.executable, str(Path(__file__).resolve()), "--inside", "--side", side,
                            "--rootfs", str(root), "--output", str(args.output / side)], check=True, timeout=180)
            results[side] = json.loads((args.output / side / "results.json").read_text())
    differences = [name for name, item in results["original"].items() if item["exact"] and item != results["candidate"][name]]
    report = {"case_count": len(results["original"]), "exact_cases": sum(item["exact"] for item in results["original"].values()),
              "differences": differences, "passed": not differences,
              "reference_sha256": hashlib.sha256((args.rootfs / "usr/sbin/uhttpd").read_bytes()).hexdigest(),
              "candidate_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest()}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    assert not differences, differences


if __name__ == "__main__":
    main()
