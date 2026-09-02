#!/usr/bin/env python3
"""Differentially test httpd-rs against the exact image's uhttpd.

Each server runs inside a disposable copy of the exact rootfs (private mount
namespace, shared network namespace) together with the exact ubusd and rpcd.
The same HTTP request set is sent from the host to 127.0.0.1:<port>; status,
selected headers and body hashes are compared after masking time-dependent
values (Date, Keep-Alive, ETag inode, cookies, CGI page bodies).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

SCENARIO = r"""
set -eu
root=$1
impl=$2
port=$3
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
mknod -m 666 "$root/dev/random" c 1 8
trap 'umount "$root/dev" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s "$impl" "$port" <<'CHROOT_TEST'
set -u
impl=$1
port=$2
mkdir -p /var/run/ubus /tmp/out /var/lock /var/state
exec 2>/tmp/out/trace.txt
set -x
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
/sbin/rpcd -s /var/run/ubus/ubus.sock >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
for i in 1 2 3 4 5 6; do ubus list session >/dev/null 2>&1 && break; sleep 1; done
ARGS="-f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R -p 127.0.0.1:$port"
if [ "$impl" = original ]; then
  /usr/sbin/uhttpd $ARGS >/tmp/out/httpd.log 2>&1 &
else
  /tmp/httpd-rs $ARGS --call-log /tmp/out/calls.txt >/tmp/out/httpd.log 2>&1 &
fi
httpd_pid=$!
echo "$httpd_pid" >/tmp/out/httpd.pid
# hold until the host removes the go file
while [ ! -e /tmp/out/stop ]; do sleep 1; done
kill $httpd_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
CHROOT_TEST
"""

MASK_HEADERS = {"date", "keep-alive", "set-cookie", "etag"}

REQUESTS: list[dict[str, Any]] = [
    {"id": "root", "method": "GET", "path": "/"},
    {"id": "head-index", "method": "HEAD", "path": "/index.html"},
    {"id": "index-http10", "method": "GET", "path": "/index.html", "version": 10},
    {"id": "dir-redirect", "method": "GET", "path": "/luci-static"},
    {"id": "dirlist", "method": "GET", "path": "/luci-static/", "body_mask": "dirlist"},
    {"id": "static-js", "method": "GET", "path": "/luci-static/resources/cbi.js"},
    {"id": "static-css", "method": "HEAD", "path": "/luci-static/bootstrap/cascade.css"},
    {"id": "missing", "method": "GET", "path": "/nope.txt"},
    {"id": "traversal", "method": "GET", "path": "/../etc/passwd"},
    {"id": "encoded", "method": "GET", "path": "/index%2ehtml"},
    {"id": "query", "method": "GET", "path": "/index.html?x=1&y=2"},
    {"id": "if-none-match", "method": "GET", "path": "/index.html", "etag_of": "/index.html"},
    {"id": "if-modified-since-old", "method": "GET", "path": "/index.html", "headers": {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}},
    {"id": "if-modified-since-new", "method": "GET", "path": "/index.html", "headers": {"If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT"}},
    {"id": "options-ubus", "method": "OPTIONS", "path": "/ubus"},
    {"id": "ubus-get-list", "method": "GET", "path": "/ubus/list", "body_mask": "json"},
    {"id": "ubus-get-list-session", "method": "GET", "path": "/ubus/list/session", "body_mask": "json"},
    {"id": "ubus-get-other", "method": "GET", "path": "/ubus/other"},
    {"id": "ubus-list", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 1, "method": "list"}, "body_mask": "json"},
    {"id": "ubus-list-session", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 2, "method": "list", "params": ["session"]}, "body_mask": "json"},
    {"id": "ubus-access-login", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 3, "method": "call", "params": ["00000000000000000000000000000000", "session", "access", {"scope": "ubus", "object": "session", "function": "login"}]}},
    {"id": "ubus-denied", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 4, "method": "call", "params": ["00000000000000000000000000000000", "uci", "get", {"config": "system"}]}},
    {"id": "ubus-bad-sid", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 5, "method": "call", "params": ["ffffffffffffffffffffffffffffffff", "session", "list", {}]}},
    {"id": "ubus-no-object", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 6, "method": "call", "params": ["00000000000000000000000000000000", "nosuch", "x", {}]}},
    {"id": "ubus-bad-method", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 7, "method": "frob"}},
    {"id": "ubus-bad-version", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "1.0", "id": 8, "method": "list"}},
    {"id": "ubus-session-in-args", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 9, "method": "call", "params": ["00000000000000000000000000000000", "session", "access", {"ubus_rpc_session": "x", "object": "session", "function": "login"}]}},
    {"id": "ubus-batch", "method": "POST", "path": "/ubus", "json": [{"jsonrpc": "2.0", "id": 10, "method": "list", "params": ["log"]}, {"jsonrpc": "2.0", "id": 11, "method": "call", "params": ["00000000000000000000000000000000", "session", "access", {"scope": "ubus", "object": "session", "function": "login"}]}], "body_mask": "json"},
    {"id": "ubus-garbage", "method": "POST", "path": "/ubus", "raw": b"{not json"},
    {"id": "ubus-legacy-call", "method": "POST", "path": "/ubus/call/session", "json": {"jsonrpc": "2.0", "id": 12, "method": "access", "params": {"scope": "ubus", "object": "session", "function": "login"}}},
    {"id": "ubus-legacy-nosuch", "method": "POST", "path": "/ubus/call/nosuch", "json": {"jsonrpc": "2.0", "id": 13, "method": "x", "params": {}}},
    {"id": "ubus-login-badpass", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 14, "method": "call", "params": ["00000000000000000000000000000000", "session", "login", {"username": "root", "password": "definitely-wrong"}]}},
    {"id": "cgi-luci", "method": "GET", "path": "/cgi-bin/luci", "body_mask": "cgi"},
    {"id": "cgi-luci-admin", "method": "GET", "path": "/cgi-bin/luci/admin/status/overview", "body_mask": "cgi"},
    {"id": "cgi-luci-head", "method": "HEAD", "path": "/cgi-bin/luci/"},
    {"id": "cgi-missing", "method": "GET", "path": "/cgi-bin/nope"},
    {"id": "put-index", "method": "PUT", "path": "/index.html", "raw": b"x"},
    {"id": "expect-continue", "method": "POST", "path": "/ubus", "json": {"jsonrpc": "2.0", "id": 15, "method": "list"}, "headers": {"Expect": "100-continue"}, "body_mask": "json"},
]


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


@contextlib.contextmanager
def disposable_rootfs(source: Path, candidate: Path | None):
    temp = Path(tempfile.mkdtemp(prefix="owrt-r14-")).resolve()
    root = temp / "rootfs"
    try:
        shutil.copytree(source, root, symlinks=True)
        (root / "tmp").mkdir(exist_ok=True)
        if candidate is not None:
            shutil.copy2(candidate, root / "tmp/httpd-rs")
            (root / "tmp/httpd-rs").chmod(0o755)
        yield temp, root
    finally:
        cleanup = run(["sudo", "-n", "rm", "-rf", "--", str(temp)])
        if cleanup.returncode != 0:
            raise RuntimeError(f"cannot remove {temp}: {cleanup.stderr}")


def fetch(port: int, spec: dict[str, Any], etags: dict[str, str]) -> dict[str, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    if spec.get("version") == 10:
        conn._http_vsn = 10  # type: ignore[attr-defined]
        conn._http_vsn_str = "HTTP/1.0"  # type: ignore[attr-defined]
    headers = dict(spec.get("headers", {}))
    body = None
    if "json" in spec:
        body = json.dumps(spec["json"]).encode()
        headers.setdefault("Content-Type", "application/json")
    elif "raw" in spec:
        body = spec["raw"]
    if "etag_of" in spec and spec["etag_of"] in etags:
        headers["If-None-Match"] = etags[spec["etag_of"]]
    conn.putrequest(spec["method"], spec["path"], skip_accept_encoding=True)
    conn.putheader("Host", "127.0.0.1")
    for k, v in headers.items():
        conn.putheader(k, v)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders()
    if body:
        conn.send(body)
    resp = conn.getresponse()
    data = resp.read()
    if spec["method"] == "HEAD":
        data = b""
    raw_headers = [(k.lower(), v) for k, v in resp.getheaders()]
    if spec["path"] == "/index.html" and resp.getheader("ETag"):
        etags["/index.html"] = resp.getheader("ETag")
    conn.close()
    return {"status": resp.status, "reason": resp.reason, "version": resp.version, "headers": raw_headers, "body": data}


def normalize(spec: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    headers = sorted((k, v) for k, v in result["headers"] if k not in MASK_HEADERS)
    header_names = sorted(k for k, _ in result["headers"])
    body = result["body"]
    mask = spec.get("body_mask")
    if mask == "json" or spec["path"].startswith("/ubus"):
        # object ids, session ids and timestamps differ per run; compare structure
        try:
            parsed = json.loads(body.decode())
            body_repr = json.dumps(parsed, sort_keys=True)
        except Exception:
            body_repr = body.decode(errors="replace")
        body_repr = re.sub(r"[0-9a-f]{32}", "SID", body_repr)
        body_repr = re.sub(r'"(expires|timeout)": \d+', r'"\1": N', body_repr)
        body_digest = hashlib.sha256(body_repr.encode()).hexdigest()[:16]
    elif mask == "cgi":
        body_digest = f"len~{len(body) // 512}"
    elif mask == "dirlist":
        text = re.sub(r"modified: [^<]+", "modified: T", body.decode(errors="replace"))
        body_digest = hashlib.sha256(text.encode()).hexdigest()[:16] + " " + text[:1400]
    else:
        body_digest = hashlib.sha256(body).hexdigest()[:16]
    return {
        "status": result["status"],
        "reason": result["reason"],
        "http_version": result["version"],
        "headers": headers,
        "header_names": header_names,
        "body": body_digest,
        "body_len": len(body) if mask != "cgi" else None,
    }


def run_scenario(rootfs: Path, candidate: Path, impl: str, port: int) -> tuple[dict[str, dict[str, Any]], str, str]:
    with disposable_rootfs(rootfs, candidate if impl == "candidate" else None) as (temp, root):
        script = temp / "scenario.sh"
        script.write_text(SCENARIO)
        log = temp / f"{impl}.log"
        print(f"[{impl}] starting servers in {root} on port {port}", flush=True)
        with log.open("w") as sink:
            proc = subprocess.Popen(
                ["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "/bin/bash", str(script), str(root), impl, str(port)],
                stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
            )
        # wait for the server
        ready = False
        for _ in range(40):
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                c.request("GET", "/index.html")
                c.getresponse().read()
                c.close()
                ready = True
                break
            except Exception:
                time.sleep(0.5)
        results: dict[str, dict[str, Any]] = {}
        etags: dict[str, str] = {}
        if ready:
            for spec in REQUESTS:
                try:
                    results[spec["id"]] = normalize(spec, fetch(port, spec, etags))
                except Exception as error:  # noqa: BLE001
                    results[spec["id"]] = {"error": f"{type(error).__name__}: {error}"}
        # stop
        run(["sudo", "-n", "touch", str(root / "tmp/out/stop")])
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        httpd_log = (root / "tmp/out/httpd.log")
        daemon = httpd_log.read_text(errors="replace")[-1500:] if httpd_log.exists() else "(no httpd log)"
        calls = (root / "tmp/out/calls.txt")
        inventory = calls.read_text() if calls.exists() else ""
        if not ready:
            trace = (root / "tmp/out/trace.txt")
            raise RuntimeError(f"{impl} server never became ready\n{log.read_text(errors='replace')[-2000:]}\ntrace:\n{trace.read_text(errors='replace')[-2000:] if trace.exists() else ''}\nhttpd:\n{daemon}")
        print(f"[{impl}] {len(results)} requests done", flush=True)
        return results, daemon, inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()

    original, orig_log, _ = run_scenario(args.rootfs.resolve(), args.candidate.resolve(), "original", args.port)
    candidate, cand_log, inventory = run_scenario(args.rootfs.resolve(), args.candidate.resolve(), "candidate", args.port + 1)
    comparisons = []
    for spec in REQUESTS:
        a = original.get(spec["id"], {})
        b = candidate.get(spec["id"], {})
        diff = {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}
        comparisons.append({"request": spec["id"], "identical": not diff, "original": a if diff else None, "candidate": b if diff else None, "diff_keys": sorted(diff)})
    passed = all(c["identical"] for c in comparisons)
    payload = {
        "schema_version": 1,
        "stage": "3-r14-httpd",
        "status": "complete" if passed else "failed",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "device_access": False,
            "rootfs_copy_is_disposable": True,
            "servers": "exact ubusd + rpcd + uhttpd vs candidate in chroot; requests from host over loopback",
            "masked": sorted(MASK_HEADERS) + ["cgi body (length bucket only)", "dirlist mtimes", "json key order"],
        },
        "candidate": {"sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(), "size_bytes": args.candidate.stat().st_size},
        "requests": len(REQUESTS),
        "comparisons": comparisons,
        "candidate_call_inventory": inventory.splitlines(),
        "candidate_stderr_tail": cand_log[-600:],
        "original_stderr_tail": orig_log[-600:],
        "gate": {"all_requests_identical": passed},
    }
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"passed": passed, "requests": len(REQUESTS), "different": [c["request"] for c in comparisons if not c["identical"]]}, indent=2))
    if not passed:
        for c in comparisons:
            if not c["identical"]:
                print(c["request"], json.dumps({"o": c["original"], "c": c["candidate"]})[:900])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
