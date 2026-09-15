"""HTTP cases used by r92_compat_probe, on exact-image disposable fixtures."""
import errno
import http.client
import json
import os
import socket
import threading
import time
from pathlib import Path

from r92_recovery_probe import run, write


def raw(port, request, host="127.0.0.1", source=None, timeout=4):
    with socket.create_connection((host, port), timeout=timeout, source_address=(source, 0) if source else None) as sock:
        sock.sendall(request)
        output = bytearray()
        while True:
            data = sock.recv(65536)
            if not data:
                return bytes(output)
            output.extend(data)


def get(port, path="/health", headers=None, host="127.0.0.1", timeout=4):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Connection": "close", **(headers or {})})
        reply = conn.getresponse()
        return reply.status, dict((k.lower(), v) for k, v in reply.getheaders()), reply.read()
    finally:
        conn.close()


def setup(f, *args):
    write(f.root / "www/health", "r92-http-ok")
    f.start_bus()
    f.start_subject("-f", "-h", "/www", "-x", "/cgi-bin", "-p", "18080", "-T", "2", "-t", "1", *args)

    def ready():
        try:
            return get(18080)[0] in (200, 307)
        except OSError:
            return False

    assert f.wait(ready), "HTTP not listening"


def tls_fixture(f):
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=r92.invalid", "-keyout", f.root / "tmp/key.pem", "-out", f.root / "tmp/cert.pem", capture_output=True)
    run("openssl", "x509", "-in", f.root / "tmp/cert.pem", "-outform", "DER", "-out", f.root / "tmp/cert.der", capture_output=True)
    run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", f.root / "tmp/key.pem", "-outform", "DER", "-out", f.root / "tmp/key.der", capture_output=True)


def policy(f):
    tls_fixture(f)
    for addr in ("10.92.0.2/32", "198.51.100.1/32", "198.51.100.2/32"):
        run("ip", "addr", "add", addr, "dev", "lo")
    setup(f, "-R", "-q", "-s", "127.0.0.1:18443", "-s", "443", "-C", "/tmp/cert.der", "-K", "/tmp/key.der")
    head = b"POST /health?q=r92 HTTP/1.1\r\nHost: fixture.invalid:18080\r\nExpect: 100-continue\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
    private = raw(18080, head, "198.51.100.1", "10.92.0.2")
    public = raw(18080, head, "198.51.100.1", "198.51.100.2")
    (f.output / "private-response.bin").write_bytes(private)
    (f.output / "public-response.bin").write_bytes(public)
    f.check("filter_before_continue_redirect", private.startswith(b"HTTP/1.1 403 ") and b"100 Continue" not in private and b"307 " not in private)
    f.check("redirect_before_continue", public.startswith(b"HTTP/1.1 307 ") and b"100 Continue" not in public)
    f.check("prefer_443", b"Location: https://fixture.invalid/health?q=r92\r\n" in public)
    status, headers, _ = get(18080, host="::1")
    f.check("bare_port_ipv6", status, 307)
    f.check("bare_tls_ipv6", headers.get("location"), "https://[::1]/health")
    f.check("serving", f.subject.poll() is None and get(18080)[0] == 307)


def files_cgi(f):
    write(f.root / "www/denied", "not readable")
    (f.root / "www/denied").chmod(0o600)
    (f.root / "www/dir").mkdir()
    handler = f.root / "www/cgi-bin/r92-error"
    write(handler, "#!/bin/sh\nprintf 'Status: %s Fixture\\r\\nContent-Type: text/plain\\r\\n\\r\\nredirect=%s\\n' \"$REDIRECT_STATUS\" \"$REDIRECT_STATUS\"\n")
    handler.chmod(0o755)
    for value in ("abc", "12x", "-12", "+12"):
        path = f.root / ("www/cgi-bin/r92-" + value)
        write(path, "#!/bin/sh\nprintf 'Status: " + value + " text\\r\\nContent-Type: text/plain\\r\\n\\r\\nbody\\n'\n")
        path.chmod(0o755)
    setup(f, "-D", "-E", "/cgi-bin/r92-error")
    for label, path, code in (("file", "/denied", 403), ("directory", "/dir/", 403), ("missing", "/notfound", 404)):
        status, _, body = get(18080, path)
        f.check("handler_" + label, [status, body.decode()], [code, f"redirect={code}\n"])
    for value, expected in (("abc", "000"), ("12x", "012"), ("-12", "-12"), ("+12", "012")):
        reply = raw(18080, f"GET /cgi-bin/r92-{value} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
        f.check("status_" + value, reply.split(b"\r\n", 1)[0].decode(), f"HTTP/1.1 {expected} text")
    handler.chmod(0o600)
    f.check("handler_recursion_bounded", get(18080, "/denied")[0], 403)
    f.check("serving", f.subject.poll() is None and get(18080)[2] == b"r92-http-ok")


def date_and_framing(f):
    setup(f, "-u", "/ubus", "-a")
    code, headers, _ = get(18080)
    assert code == 200
    f.check("if_modified_since", get(18080, headers={"If-Modified-Since": headers["last-modified"]})[0], 200)
    f.check("if_unmodified_since", get(18080, headers={"If-Unmodified-Since": "Sun, 06 Nov 1994 08:49:37 GMT"})[0], 200)
    f.check("etag", get(18080, headers={"If-None-Match": headers["etag"]})[0], 304)
    reply = raw(18080, b"POST /ubus HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n")
    (f.output / "header-error.bin").write_bytes(reply)
    f.check("header_error", reply.startswith(b"HTTP/1.1 501 "))
    f.check("header_error_terminator", reply.endswith(b"0\r\n\r\n"), f.side != "original")
    body = b'{"jsonrpc":"2.0","id":1,"method":"list"}'
    replies = {}
    for name, encoded in (("extension", b"%x;fixture=yes\r\n%s\r\n0\r\n\r\n" % (len(body), body)),
                          ("trailer", b"%x\r\n%s\r\n0\r\nX-Fixture: value\r\n\r\n" % (len(body), body))):
        head = b"POST /ubus HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        reply = raw(18080, head + encoded)
        (f.output / (name + ".bin")).write_bytes(reply)
        replies[name] = b'"result"' in reply
    f.check("chunk_extension", replies["extension"], f.side != "original")
    f.check("chunk_trailer", replies["trailer"])
    malformed = raw(18080, b"POST /ubus HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\n")
    (f.output / "malformed-chunk.bin").write_bytes(malformed)
    f.check("malformed_body_status", malformed.split(b" ", 2)[1].decode(), "200" if f.side == "original" else "400")
    f.check("malformed_body_json_error", b'"code":-32700' in malformed.replace(b" ", b""), f.side == "original")
    f.check("serving", f.subject.poll() is None and get(18080)[2] == b"r92-http-ok")


def script_queue(f):
    script = f.root / "www/cgi-bin/r92-queue"
    # Block on an explicit release instead of a polling shell: the exact
    # image's sleep rejects fractions and turned the old loop into a spin.
    for i in range(5):
        os.mkfifo(f.root / f"tmp/release-{i}")
    write(script, "#!/bin/sh\necho \"$QUERY_STRING\" >> /tmp/out/queue-starts\nread -r release < /tmp/release-\"$QUERY_STRING\"\nprintf 'Content-Type: text/plain\\r\\n\\r\\n%s' \"$QUERY_STRING\"\n")
    script.chmod(0o755)
    setup(f, "-n", "1", "-t", "10")
    starts = f.output / "queue-starts"
    replies, errors, workers = {}, [], []

    def request(i):
        try:
            replies[i] = get(18080, "/cgi-bin/r92-queue?" + str(i), timeout=10)
        except Exception as error:
            errors.append(repr(error))

    def order():
        return starts.read_text().splitlines() if starts.exists() else []

    for i in range(5):
        worker = threading.Thread(target=request, args=(i,))
        worker.start()
        workers.append(worker)
        if i == 0:
            assert f.wait(lambda: order() == ["0"])
        time.sleep(0.08)
    time.sleep(0.15)
    f.check("queue_initial_slot_bound", order(), ["0"])
    bounded = True
    for i in range(5):
        assert f.wait(lambda: len(order()) > i), "script queue stopped making progress"
        active = order()
        bounded &= len(active) == i + 1
        # Nonblocking open fails if the CGI never reaches its read; avoid
        # hanging the host test on a broken script.
        release = f.root / ("tmp/release-" + active[i])
        def release_ready():
            try:
                fd = os.open(release, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                if error.errno == errno.ENXIO:
                    return False
                raise
            try:
                os.write(fd, b"release\n")
            finally:
                os.close(fd)
            return True
        assert f.wait(release_ready), "script did not wait for its release"
    for worker in workers:
        worker.join(timeout=4)
    f.observations["queue_order"] = order()
    f.observations["request_errors"] = errors
    f.check("queue_slot_bound", bounded)
    f.check("queue_exactly_once", sorted(order()), [str(i) for i in range(5)])
    f.check("queue_completes", not errors and len(replies) == 5 and all(code == 200 and body == str(i).encode() for i, (code, _, body) in replies.items()))
    if f.side == "original":
        f.check("queue_original_lifo", order(), ["0", "4", "3", "2", "1"])
    f.check("serving", f.subject.poll() is None and get(18080)[2] == b"r92-http-ok")


def bus_errors(f):
    setup(f, "-u", "/ubus", "-a")
    code, _, body = get(18080, "/ubus/list/missing")
    f.check("not_found", [code, json.loads(body).get("code")], [500, 4])
    f.bus.kill()
    f.bus.wait(timeout=2)
    time.sleep(0.15)
    code, _, body = get(18080, "/ubus/list/missing")
    f.check("disconnected_list", [code, json.loads(body).get("code")], [500, 2])
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=3)
    try:
        conn.request("POST", "/ubus", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "call", "params": ["0" * 32, "missing", "x", {}]}), headers={"Connection": "close"})
        reply = conn.getresponse()
        f.check("disconnected_call", [reply.status, json.loads(reply.read()).get("error", {}).get("code")], [200, -32000])
    finally:
        conn.close()
    f.bus = f.start("/sbin/ubusd")
    f.check("reconnected", f.wait(lambda: json.loads(get(18080, "/ubus/list/missing")[2]).get("code") == 4), f.side != "original")
    f.check("serving", f.subject.poll() is None and get(18080)[2] == b"r92-http-ok")


def bus_timeout(f):
    setup(f, "-u", "/ubus", "-a")
    assert get(18080, "/ubus/list/missing")[0] == 500
    f.bus.send_signal(19)
    started = time.monotonic()
    result = []
    completed = threading.Event()

    def lookup():
        try:
            result.append(get(18080, "/ubus/list/missing", timeout=5))
        finally:
            completed.set()

    worker = threading.Thread(target=lookup)
    worker.start()
    try:
        bounded = completed.wait(2.2)
        f.check("lookup_deadline", bounded, f.side != "original")
    finally:
        f.bus.send_signal(18)
    worker.join(timeout=4)
    assert result, "lookup did not recover after the bus resumed"
    code, _, body = result[0]
    f.observations["timeout_seconds"] = time.monotonic() - started
    f.check("lookup_timeout_status", [code, json.loads(body).get("code")], [500, 4 if f.side == "original" else 7])
    f.check("serving", f.subject.poll() is None and get(18080)[2] == b"r92-http-ok")


CASES = {
    "httpd_policy": ("httpd", policy, {"identity", "filter_before_continue_redirect", "redirect_before_continue", "prefer_443", "bare_port_ipv6", "bare_tls_ipv6", "serving"}),
    "httpd_files_cgi": ("httpd", files_cgi, {"identity", "handler_file", "handler_directory", "handler_missing", "status_abc", "status_12x", "status_-12", "status_+12", "handler_recursion_bounded", "serving"}),
    "httpd_date_framing": ("httpd", date_and_framing, {"identity", "if_modified_since", "if_unmodified_since", "etag", "header_error", "header_error_terminator", "chunk_extension", "chunk_trailer", "malformed_body_status", "malformed_body_json_error", "serving"}),
    "httpd_script_queue": ("httpd", script_queue, {"identity", "queue_initial_slot_bound", "queue_slot_bound", "queue_exactly_once", "queue_completes", "serving"}),
    "httpd_bus_errors": ("httpd", bus_errors, {"identity", "not_found", "disconnected_list", "disconnected_call", "reconnected", "serving"}),
    "httpd_bus_timeout": ("httpd", bus_timeout, {"identity", "lookup_deadline", "lookup_timeout_status", "serving"}),
}
