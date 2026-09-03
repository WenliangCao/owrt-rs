#!/usr/bin/env python3
"""Malformed-request fuzzing of httpd-rs against the exact image's uhttpd.

Reuses r14's sandbox (exact rootfs, ubusd + rpcd + the server under test in a
chroot, requests from the host over loopback) but speaks raw bytes on the
socket instead of http.client: broken request lines, odd methods and versions,
path traversal and bad percent-encoding, oversized and malformed headers,
Content-Length / chunked mismatches, JSON-RPC bodies that are not JSON or
are absurdly large or deep, pipelining, absolute-URI requests, CGI oddities.

For every case the status line, the (masked, sorted) headers, the normalised
body and whether the server closed the connection are compared.

Usage: r27_httpd_fuzz.py --rootfs DIR --candidate httpd-rs [--port N]
Exit code 1 when any case differs.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r14_httpd_check as base  # noqa: E402

MASK = {"date", "etag", "keep-alive", "set-cookie", "last-modified"}


def req(name, raw, close_after=True):
    return {"id": name, "raw": raw if isinstance(raw, bytes) else raw.encode("latin-1"), "close": close_after}


def line(method="GET", path="/index.html", version="HTTP/1.1", headers=(), body=b""):
    h = "".join("%s: %s\r\n" % kv for kv in headers)
    return ("%s %s %s\r\n%s\r\n" % (method, path, version, h)).encode("latin-1") + body


def cases():
    H = [("Host", "127.0.0.1"), ("Connection", "close")]
    C = []
    C.append(req("plain", line(headers=H)))
    C.append(req("no-host", line(headers=[("Connection", "close")])))
    C.append(req("http10-no-headers", line(version="HTTP/1.0")))
    C.append(req("http09", b"GET /index.html\r\n\r\n"))
    C.append(req("http12", line(version="HTTP/1.2", headers=H)))
    C.append(req("http2", line(version="HTTP/2.0", headers=H)))
    C.append(req("httpx", line(version="HTTX/1.1", headers=H)))
    C.append(req("lowercase-method", line(method="get", headers=H)))
    C.append(req("unknown-method", line(method="FROB", headers=H)))
    C.append(req("trace", line(method="TRACE", path="/", headers=H)))
    C.append(req("connect", line(method="CONNECT", path="127.0.0.1:443", headers=H)))
    C.append(req("options-star", line(method="OPTIONS", path="*", headers=H)))
    C.append(req("delete", line(method="DELETE", headers=H)))
    C.append(req("head-ubus", line(method="HEAD", path="/ubus", headers=H)))
    C.append(req("method-only", b"GET\r\n\r\n"))
    C.append(req("empty", b"\r\n\r\n"))
    C.append(req("leading-crlf", b"\r\n\r\n" + line(headers=H)))
    C.append(req("lf-only", b"GET /index.html HTTP/1.1\nHost: x\nConnection: close\n\n"))
    C.append(req("double-space", b"GET  /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("tab-separated", b"GET\t/index.html\tHTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("extra-token", b"GET /index.html HTTP/1.1 extra\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("no-slash", line(path="index.html", headers=H)))
    C.append(req("absolute-uri", line(path="http://127.0.0.1/index.html", headers=H)))
    C.append(req("absolute-uri-other-host", line(path="http://example.com/index.html", headers=H)))
    C.append(req("double-slash", line(path="//index.html", headers=H)))
    C.append(req("dot-segment", line(path="/./index.html", headers=H)))
    C.append(req("dotdot-inside", line(path="/luci-static/../index.html", headers=H)))
    C.append(req("dotdot-encoded", line(path="/luci-static/..%2f..%2fetc/passwd", headers=H)))
    C.append(req("dotdot-double-encoded", line(path="/%252e%252e/etc/passwd", headers=H)))
    C.append(req("percent-bad", line(path="/%zz", headers=H)))
    C.append(req("percent-truncated", line(path="/index.html%", headers=H)))
    C.append(req("percent-nul", line(path="/index.html%00.txt", headers=H)))
    C.append(req("percent-slash", line(path="/luci-static%2fresources%2fcbi.js", headers=H)))
    C.append(req("percent-upper", line(path="/%49ndex.html", headers=H)))
    C.append(req("raw-space-in-path", b"GET /index .html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("raw-highbytes-path", b"GET /caf\xc3\xa9 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("raw-ctrl-path", b"GET /a\x01b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    C.append(req("long-path-8k", line(path="/" + "a" * 8000, headers=H)))
    C.append(req("long-path-64k", line(path="/" + "a" * 65000, headers=H)))
    C.append(req("long-query", line(path="/index.html?" + "q" * 20000, headers=H)))
    C.append(req("query-only", line(path="/?", headers=H)))
    C.append(req("fragment", line(path="/index.html#frag", headers=H)))
    C.append(req("semicolon-params", line(path="/index.html;x=1", headers=H)))
    C.append(req("many-headers", line(headers=H + [("X-%d" % i, "v") for i in range(300)])))
    C.append(req("huge-header", line(headers=H + [("X-Big", "v" * 70000)])))
    C.append(req("header-no-colon", b"GET /index.html HTTP/1.1\r\nHost: x\r\nBroken header\r\nConnection: close\r\n\r\n"))
    C.append(req("header-empty-name", b"GET /index.html HTTP/1.1\r\nHost: x\r\n: value\r\nConnection: close\r\n\r\n"))
    C.append(req("header-obs-fold", b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-A: one\r\n two\r\nConnection: close\r\n\r\n"))
    C.append(req("header-ctrl", b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\nConnection: close\r\n\r\n"))
    C.append(req("header-highbytes", b"GET /index.html HTTP/1.1\r\nHost: x\r\nX-A: caf\xc3\xa9\xff\r\nConnection: close\r\n\r\n"))
    C.append(req("host-with-port", line(headers=[("Host", "127.0.0.1:99999"), ("Connection", "close")])))
    C.append(req("host-twice", line(headers=[("Host", "a"), ("Host", "b"), ("Connection", "close")])))
    C.append(req("range", line(headers=H + [("Range", "bytes=0-10")])))
    C.append(req("range-bad", line(headers=H + [("Range", "bytes=abc")])))
    C.append(req("if-none-match-star", line(headers=H + [("If-None-Match", "*")])))
    C.append(req("if-none-match-garbage", line(headers=H + [("If-None-Match", "\"zz\" , garbage")])))
    C.append(req("if-modified-garbage", line(headers=H + [("If-Modified-Since", "not a date")])))
    C.append(req("accept-encoding", line(headers=H + [("Accept-Encoding", "gzip, br")])))
    C.append(req("authorization-garbage", line(headers=H + [("Authorization", "Basic !!!!")])))
    C.append(req("cookie-huge", line(headers=H + [("Cookie", "sysauth=" + "c" * 9000)])))
    C.append(req("connection-keepalive-http10", line(version="HTTP/1.0", headers=[("Host", "x"), ("Connection", "keep-alive")]), close_after=False))
    C.append(req("upgrade-websocket", line(headers=H + [("Upgrade", "websocket"), ("Connection", "Upgrade")])))
    C.append(req("expect-continue-nobody", line(method="POST", path="/ubus", headers=H + [("Expect", "100-continue"), ("Content-Length", "30")])))
    C.append(req("cl-negative", line(method="POST", path="/ubus", headers=H + [("Content-Length", "-1")], body=b"{}")))
    C.append(req("cl-alpha", line(method="POST", path="/ubus", headers=H + [("Content-Length", "abc")], body=b"{}")))
    C.append(req("cl-huge", line(method="POST", path="/ubus", headers=H + [("Content-Length", "99999999999")], body=b"{}")))
    C.append(req("cl-short-body", line(method="POST", path="/ubus", headers=H + [("Content-Length", "100")], body=b"{}")))
    C.append(req("cl-long-body", line(method="POST", path="/ubus", headers=H + [("Content-Length", "2")], body=b'{"jsonrpc":"2.0","id":1,"method":"list"}')))
    C.append(req("cl-twice", line(method="POST", path="/ubus", headers=H + [("Content-Length", "2"), ("Content-Length", "3")], body=b"{}")))
    C.append(req("post-no-cl", line(method="POST", path="/ubus", headers=H, body=b'{"jsonrpc":"2.0","id":1,"method":"list"}')))
    C.append(req("get-with-body", line(headers=H + [("Content-Length", "2")], body=b"{}")))
    j = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "list"}).encode()
    C.append(req("chunked-ok", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked")],
                                    body=b"%x\r\n%s\r\n0\r\n\r\n" % (len(j), j))))
    C.append(req("chunked-two-chunks", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked")],
                                            body=b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (10, j[:10], len(j) - 10, j[10:]))))
    C.append(req("chunked-bad-size", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked")], body=b"zz\r\n{}\r\n0\r\n\r\n")))
    C.append(req("chunked-huge-size", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked")], body=b"ffffffff\r\n{}\r\n0\r\n\r\n")))
    C.append(req("chunked-no-terminator", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked")], body=b"2\r\n{}\r\n")))
    C.append(req("chunked-and-cl", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "chunked"), ("Content-Length", "2")], body=b"2\r\n{}\r\n0\r\n\r\n")))
    C.append(req("te-gzip", line(method="POST", path="/ubus", headers=H + [("Transfer-Encoding", "gzip")], body=b"{}")))
    def post(name, body, path="/ubus", extra=()):
        C.append(req(name, line(method="POST", path=path, headers=H + [("Content-Length", str(len(body)))] + list(extra), body=body)))
    post("json-empty", b"")
    post("json-null", b"null")
    post("json-number", b"42")
    post("json-string", b'"x"')
    post("json-array-empty", b"[]")
    post("json-object-empty", b"{}")
    post("json-trailing-garbage", b'{"jsonrpc":"2.0","id":1,"method":"list"} garbage')
    post("json-two-docs", b'{"jsonrpc":"2.0","id":1,"method":"list"}{"jsonrpc":"2.0","id":2,"method":"list"}')
    post("json-deep-array", b"[" * 5000 + b"]" * 5000)
    post("json-deep-object", b'{"a":' * 3000 + b"1" + b"}" * 3000)
    post("json-1mib", b'{"jsonrpc":"2.0","id":1,"method":"list","params":["' + b"x" * (1 << 20) + b'"]}')
    post("json-bad-utf8", b'{"jsonrpc":"2.0","id":1,"method":"list","params":["\xff\xfe"]}')
    post("json-nul-escape", b'{"jsonrpc":"2.0","id":1,"method":"list","params":["\\u0000"]}')
    post("json-dup-keys", b'{"jsonrpc":"2.0","jsonrpc":"1.0","id":1,"method":"list"}')
    post("json-big-number", b'{"jsonrpc":"2.0","id":1e400,"method":"list"}')
    post("json-id-string", b'{"jsonrpc":"2.0","id":"abc","method":"list"}')
    post("json-id-null", b'{"jsonrpc":"2.0","id":null,"method":"list"}')
    post("json-id-object", b'{"jsonrpc":"2.0","id":{"a":1},"method":"list"}')
    post("json-no-id", b'{"jsonrpc":"2.0","method":"list"}')
    post("json-params-string", b'{"jsonrpc":"2.0","id":1,"method":"call","params":"x"}')
    post("json-params-short", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000"]}')
    post("json-params-long", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","session","access",{},"extra"]}')
    post("json-sid-short", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["abc","session","access",{"scope":"ubus","object":"session","function":"login"}]}')
    post("json-sid-nonhex", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","session","list",{}]}')
    post("json-args-array", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","session","access",[1,2]]}')
    post("json-object-name-long", b'{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","' + b"o" * 5000 + b'","x",{}]}')
    post("json-list-many", b'{"jsonrpc":"2.0","id":1,"method":"list","params":["' + b'","'.join([b"a"] * 500) + b'"]}')
    post("json-batch-empty", b"[]")
    post("json-batch-mixed", b'[{"jsonrpc":"2.0","id":1,"method":"list"},42,"x",null,{"jsonrpc":"2.0","id":2,"method":"nope"}]')
    post("json-batch-1000", b"[" + b",".join([b'{"jsonrpc":"2.0","id":1,"method":"list","params":["session"]}'] * 1000) + b"]")
    post("json-content-type-text", b'{"jsonrpc":"2.0","id":1,"method":"list"}', extra=[("Content-Type", "text/plain")])
    post("json-to-ubus-slash", b'{"jsonrpc":"2.0","id":1,"method":"list"}', path="/ubus/")
    post("json-to-ubus-call-path", b'{"jsonrpc":"2.0","id":1,"method":"list"}', path="/ubus/call/session/extra/parts")
    post("json-to-ubus-list-path", b'{"jsonrpc":"2.0","id":1,"method":"list"}', path="/ubus/list/a/b/c")
    post("json-to-static", b"{}", path="/index.html")
    post("json-to-missing", b"{}", path="/nope")
    post("json-to-cgi", b"a=b", path="/cgi-bin/luci", extra=[("Content-Type", "application/x-www-form-urlencoded")])
    post("cgi-cl-mismatch-short", b"abc", path="/cgi-bin/luci")
    C.append(req("cgi-query-bad-pct", line(path="/cgi-bin/luci?x=%zz", headers=H)))
    C.append(req("cgi-pathinfo-traversal", line(path="/cgi-bin/luci/../../etc/passwd", headers=H)))
    C.append(req("cgi-pathinfo-encoded", line(path="/cgi-bin/luci/%2e%2e/admin", headers=H)))
    C.append(req("cgi-pathinfo-nul", line(path="/cgi-bin/luci/%00", headers=H)))
    C.append(req("cgi-dir", line(path="/cgi-bin/", headers=H)))
    C.append(req("cgi-dir-noslash", line(path="/cgi-bin", headers=H)))
    C.append(req("cgi-head", line(method="HEAD", path="/cgi-bin/luci", headers=H)))
    C.append(req("cgi-huge-header", line(path="/cgi-bin/luci", headers=H + [("X-Big", "v" * 30000)])))
    C.append(req("pipelined-two", line(headers=[("Host", "x")]) + line(headers=H), close_after=False))
    C.append(req("pipelined-bad-second", line(headers=[("Host", "x")]) + b"GARBAGE\r\n\r\n", close_after=False))
    C.append(req("ubus-get-list-deep", line(path="/ubus/list/session/extra", headers=H)))
    C.append(req("ubus-get-call", line(path="/ubus/call/session/list", headers=H)))
    C.append(req("ubus-get-query", line(path="/ubus?x=1", headers=H)))
    C.append(req("ubus-put", line(method="PUT", path="/ubus", headers=H + [("Content-Length", "2")], body=b"{}")))
    C.append(req("dirlist-traversal", line(path="/luci-static/%2e%2e/", headers=H)))
    C.append(req("dot-file", line(path="/.htaccess", headers=H)))
    C.append(req("index-dir-noslash", line(path="/luci-static/resources", headers=H)))
    return C


def talk(port, raw, close_after, timeout=4.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(raw)
        chunks = []
        closed = False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                closed = True
                break
            chunks.append(d)
            if not close_after and len(b"".join(chunks)) > 0 and time.time() > deadline - timeout / 2:
                break
        return b"".join(chunks), closed
    finally:
        s.close()


def normalize(data, closed):
    if not data:
        return {"empty": True, "closed": closed}
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1")
    headers = []
    for h in lines[1:]:
        k, _, v = h.partition(b":")
        k = k.decode("latin-1").strip().lower()
        v = v.decode("latin-1").strip()
        if k in MASK:
            v = "<masked>"
        headers.append("%s: %s" % (k, v))
    headers.sort()
    if b"chunked" in head.lower():
        # collapse chunk framing so both sides are compared on payload
        out, rest = b"", body
        while b"\r\n" in rest:
            size, _, rest = rest.partition(b"\r\n")
            try:
                n = int(size.split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[:n]
            rest = rest[n + 2:]
        body = out
    try:
        js = json.loads(body.decode("utf-8"))
        js = re.sub(r'"(time|expires|uptime|localtime)":\s*-?\d+', r'"\1":0', json.dumps(js, sort_keys=True))
        body_repr = "json:" + js[:2000]
    except Exception:
        text = body.decode("utf-8", errors="replace")
        text = re.sub(r"\d{2}:\d{2}:\d{2}", "<t>", text)
        body_repr = "bytes:%d sha256:%s head:%r" % (len(body), hashlib.sha256(body).hexdigest()[:16], text[:120])
    return {"status": status, "headers": headers, "body": body_repr, "closed": closed}


def run_side(rootfs, candidate, impl, port):
    with base.disposable_rootfs(rootfs, candidate if impl == "candidate" else None) as (temp, root):
        script = temp / "scenario.sh"
        script.write_text(base.SCENARIO)
        log = temp / f"{impl}.log"
        with log.open("w") as sink:
            proc = subprocess.Popen(
                ["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "/bin/bash", str(script), str(root), impl, str(port)],
                stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT)
        ready = False
        for _ in range(40):
            try:
                d, _ = talk(port, line(headers=[("Host", "x"), ("Connection", "close")]), True, timeout=2)
                if d.startswith(b"HTTP/1."):
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.5)
        results = {}
        if ready:
            for c in cases():
                try:
                    data, closed = talk(port, c["raw"], c["close"])
                    results[c["id"]] = normalize(data, closed)
                except Exception as e:  # noqa: BLE001
                    results[c["id"]] = {"error": "%s: %s" % (type(e).__name__, e)}
                # the server must still be alive after every case
                try:
                    d, _ = talk(port, line(headers=[("Host", "x"), ("Connection", "close")]), True, timeout=4)
                    results[c["id"]]["alive_after"] = d.startswith(b"HTTP/1.")
                except Exception as e:  # noqa: BLE001
                    results[c["id"]]["alive_after"] = "%s: %s" % (type(e).__name__, e)
        base.run(["sudo", "-n", "touch", str(root / "tmp/out/stop")])
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd_log = root / "tmp/out/httpd.log"
        daemon = httpd_log.read_text(errors="replace")[-1500:] if httpd_log.exists() else ""
        if not ready:
            raise RuntimeError("%s never became ready\n%s" % (impl, log.read_text(errors="replace")[-2000:]))
        return results, daemon


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rootfs", required=True, type=Path)
    ap.add_argument("--candidate", required=True, type=Path)
    ap.add_argument("--port", type=int, default=18082)
    a = ap.parse_args()
    orig, olog = run_side(a.rootfs.resolve(), a.candidate.resolve(), "original", a.port)
    cand, clog = run_side(a.rootfs.resolve(), a.candidate.resolve(), "candidate", a.port + 1)
    bad = 0
    for c in cases():
        o, n = orig.get(c["id"]), cand.get(c["id"])
        if o == n:
            continue
        bad += 1
        print("DIFF %s" % c["id"])
        for k in sorted(set(o) | set(n)):
            if o.get(k) != n.get(k):
                print("   %-12s orig=%r\n   %-12s cand=%r" % (k, o.get(k), "", n.get(k)))
    if clog.strip():
        print("== candidate httpd log tail: %r" % clog[-800:])
    print("cases=%d differing=%d" % (len(cases()), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
