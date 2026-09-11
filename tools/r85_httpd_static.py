#!/usr/bin/env python3
"""HTTPD static-file regression gates in disposable Linux namespaces.

Exercise changing files/permissions and persistent requests, so optimizations
cannot turn a successful lookup into a stale cross-request cache. The outer
process never enters or changes the host's network namespace.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import quote

from r14_httpd_check import disposable_rootfs


def memory_connections(pid, port, fixture, count):
    def snapshot():
        values = {}
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            name, _, value = line.partition(":")
            if name in ("VmRSS", "RssAnon", "VmHWM", "Threads"):
                values[name] = int(value.split()[0])
        values["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        return values

    time.sleep(.2)
    before = snapshot()
    expected = fixture.read_bytes()
    clients = []
    try:
        for _ in range(count):
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            clients.append(client)
            first_socket = None
            for _ in range(2):
                client.request("GET", "/resident.dat")
                response = client.getresponse()
                client.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                assert response.status == 200 and response.read() == expected
                if first_socket is None:
                    first_socket = client.sock
                assert client.sock is first_socket
        time.sleep(.2)
        held = snapshot()
        assert held["fds"] == before["fds"] + count, "idle connections were not all held"
    finally:
        for client in clients:
            client.close()
    deadline = time.monotonic() + 3
    while True:
        after = snapshot()
        if after["fds"] == before["fds"] and after["Threads"] == before["Threads"]:
            break
        assert time.monotonic() < deadline, "idle connection resources were not released"
        time.sleep(.02)
    return {"connections": count, "response_bytes": len(expected),
            "before": before, "held": held, "after_close": after,
            "held_rss_growth_kib": held["VmRSS"] - before["VmRSS"]}


def worker(rootfs, candidate, side, memory_count=0):
    if os.environ.get("OWRT_BENCH_NAMESPACE") != "1":
        raise RuntimeError("requires the verified namespace launcher")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with disposable_rootfs(rootfs, candidate) as (_, root):
        docroot = root / "www/r85-static"
        docroot.mkdir()
        (root / "tmp/r85-httpd.conf").write_text("/private:user:fixture\n")
        protected = docroot / "private/content.txt"
        protected.parent.mkdir()
        protected.write_bytes(b"protected fixture")
        mutable = docroot / "mutable.dat"
        mutable.write_bytes(b"first")
        mutable.chmod(0o644)
        script = docroot / "cgi-bin/stream"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\ncgi body\\n'\n")
        script.chmod(0o755)
        echo = script.with_name("echo")
        echo.write_text("#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\ncat\n")
        echo.chmod(0o755)
        binary = "/usr/sbin/uhttpd" if side == "stock" else "/tmp/httpd-rs"
        command = ["chroot", str(root), binary, "-f", "-h", "/www/r85-static",
                   "-c", "/tmp/r85-httpd.conf", "-x", "/cgi-bin",
                   "-p", "127.0.0.1:18080", "-k", "20", "-T", "3"]
        server = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        results = {}
        resident = None

        def fetch(name, path="/mutable.dat", method="GET", headers=None, body=None, raw_target=False,
                  encode_chunked=False):
            target = path if raw_target else quote(path, safe="/?=")
            connection.request(method, target, body=body, headers=headers or {}, encode_chunked=encode_chunked)
            response = connection.getresponse()
            if connection.sock is not None and hasattr(socket, "TCP_QUICKACK"):
                connection.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            data = response.read()
            results[name] = {"status": response.status, "content_type": response.getheader("Content-Type"),
                             "content_length": response.getheader("Content-Length"),
                             "body_bytes": len(data), "body_sha256": hashlib.sha256(data).hexdigest()}
            return response, data

        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("static test server exited")
                try:
                    with socket.create_connection(("127.0.0.1", 18080), timeout=.1):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError("static test server did not listen")
            first, data = fetch("initial")
            assert first.status == 200 and data == b"first"
            initial_socket = connection.sock
            etag = first.getheader("ETag")
            assert etag
            response, data = fetch("cgi-on-reused-connection", "/cgi-bin/stream")
            assert response.status == 200 and data == b"cgi body\n"
            response, data = fetch("static-after-cgi")
            assert response.status == 200 and data == b"first"
            response, data = fetch("unchanged", headers={"If-None-Match": etag})
            assert response.status == 304 and data == b""
            for name, target in [
                ("repeated-slash", "//mutable.dat"),
                ("dot-segment", "/./mutable.dat"),
                ("parent-segment", "/absent/../mutable.dat"),
                ("escaped-dot", "/mutable%2edat"),
                ("escaped-name-query", "/%6dutable.dat?key=value"),
            ]:
                response, data = fetch(name, target, raw_target=True)
                assert response.status == 200 and data == b"first"
            sibling = docroot.with_name(docroot.name + "-sibling")
            sibling.mkdir()
            (sibling / "outside.dat").write_bytes(b"outside document root")
            response, _ = fetch("docroot-prefix-boundary", "/../r85-static-sibling/outside.dat")
            assert response.status == 404
            response, _ = fetch("malformed-path-escape", "/%GG", raw_target=True)
            assert response.status == 404
            replacement = docroot / "replacement"
            replacement.write_bytes(b"replacement with a different length")
            replacement.chmod(0o644)
            os.replace(replacement, mutable)
            changed, data = fetch("atomic-replacement", headers={"If-None-Match": etag})
            assert changed.status == 200 and data == b"replacement with a different length"
            assert changed.getheader("ETag") != etag
            mutable.chmod(0o600)
            response, _ = fetch("permission-revoked")
            assert response.status == 403
            mutable.chmod(0o644)
            response, data = fetch("permission-restored")
            assert response.status == 200 and data == mutable.read_bytes()
            response, data = fetch("head", method="HEAD")
            assert response.status == 200 and data == b""
            assert response.getheader("Content-Length") == str(mutable.stat().st_size)
            mutable.unlink()
            response, _ = fetch("deleted")
            assert response.status == 404
            mutable.mkdir()
            (mutable / "index.html").write_bytes(b"new directory index")
            response, data = fetch("became-directory")
            assert response.status == 302 and response.getheader("Location") == "/mutable.dat/"
            response, data = fetch("new-index", "/mutable.dat/")
            assert response.status == 200 and data == b"new directory index"
            assert connection.sock is initial_socket, "static requests unexpectedly lost keep-alive"

            for filename, mime in [
                ("UPPER.CSS", "text/css"), ("目录.HTML", "text/html"),
                ("archive.TAR.GZ", "application/x-compressed-tar"),
                ("archive.tar.bz2", "application/x-bzip-compressed-tar"),
                ("WPAD.DAT", "application/x-ns-proxy-autoconfig"),
                ("README", "text/plain"), ("unknown.dat", "application/octet-stream"),
            ]:
                (docroot / filename).write_bytes(b"mime fixture")
                response, data = fetch("mime-" + filename, "/" + filename)
                assert response.status == 200 and data == b"mime fixture"
                assert response.getheader("Content-Type") == mime
            for length in (16383, 16384, 16385, 65537, 1048577):
                data = bytes(i % 251 for i in range(length))
                (docroot / "boundary.dat").write_bytes(data)
                response, received = fetch(f"boundary-{length}", "/boundary.dat")
                assert response.status == 200 and received == data
                response, received = fetch(f"boundary-head-{length}", "/boundary.dat", method="HEAD")
                assert response.status == 200 and not received
                assert response.getheader("Content-Length") == str(length)
            reused_socket = connection.sock
            for label, body, headers, chunked in (
                ("length", b"request body", {}, False),
                ("chunked", [b"request", b" body"], {"Transfer-Encoding": "chunked"}, True),
            ):
                response, received = fetch("reused-post-" + label, "/cgi-bin/echo", method="POST",
                                           headers=headers, body=body, encode_chunked=chunked)
                assert response.status == 200 and received == b"request body"
                response, received = fetch("reused-get-after-" + label, "/unknown.dat")
                assert response.status == 200 and received == b"mime fixture"
                assert connection.sock is reused_socket, "framing change lost the persistent connection"
            credentials = "Basic " + base64.b64encode(b"user:fixture").decode()
            response, received = fetch("reused-credentials", "/private/content.txt",
                                       headers={"Authorization": credentials})
            assert response.status == 200 and received == b"protected fixture"
            assert connection.sock is reused_socket
            response, _ = fetch("credentials-not-retained", "/private/content.txt")
            assert response.status == 401, "previous request's credentials were reused"
            assert server.poll() is None
            if memory_count:
                connection.close()
                fixture = docroot / "resident.dat"
                fixture.write_bytes(bytes(16384))
                resident = memory_connections(server.pid, 18080, fixture, memory_count)
        finally:
            connection.close()
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        return {"cases": results, "resident": resident}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("ns_exec", type=Path)
    parser.add_argument("--worker", choices=("stock", "candidate"))
    parser.add_argument("--memory-connections", type=int, default=0,
                        help="also measure 1-64 held keep-alive connections (default: disabled)")
    args = parser.parse_args()
    if not 0 <= args.memory_connections <= 64:
        parser.error("memory-connections must be between 0 and 64")
    if args.worker:
        print(json.dumps(worker(args.rootfs.resolve(), args.candidate.resolve(), args.worker,
                                args.memory_connections)))
        return
    results = []
    for side in ("stock", "candidate"):
        run = subprocess.run(["sudo", "-n", str(args.ns_exec.resolve()), sys.executable,
                              str(Path(__file__).resolve()), str(args.rootfs.resolve()),
                              str(args.candidate.resolve()), str(args.ns_exec.resolve()), "--worker", side,
                              "--memory-connections", str(args.memory_connections)],
                             check=True, capture_output=True, text=True, timeout=120)
        results.append(json.loads(run.stdout))
    assert results[0]["cases"] == results[1]["cases"], "static wire behavior differs from the original"
    summary = {"passed": True, "cases": len(results[0]["cases"]), "case_names": list(results[0]["cases"])}
    if args.memory_connections:
        summary["memory"] = {side: value["resident"] for side, value in zip(("stock", "candidate"), results)}
        summary["host"] = {"kernel": os.uname().release, "architecture": os.uname().machine}
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
