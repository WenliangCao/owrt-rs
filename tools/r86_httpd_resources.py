#!/usr/bin/env python3
"""Check HTTPD survival and connection-slot recovery after thread allocation fails.

Only the disposable test server receives RLIMIT_AS. The host and production
router are never limited. Requires the existing Linux namespace launcher.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import time

from r14_httpd_check import disposable_rootfs


def worker(rootfs, candidate, side):
    if os.environ.get("OWRT_BENCH_NAMESPACE") != "1":
        raise RuntimeError("requires the verified namespace launcher")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with disposable_rootfs(rootfs, candidate) as (_, root):
        (root / "www/r86-resource.txt").write_bytes(b"resource recovery\n")
        binary = "/usr/sbin/uhttpd" if side == "stock" else "/tmp/httpd-rs"
        process = subprocess.Popen([
            "chroot", str(root), binary, "-f", "-h", "/www", "-p", "127.0.0.1:18080",
            "-N", "2", "-k", "0", "-T", "2",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        def request():
            connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=2)
            try:
                connection.request("GET", "/r86-resource.txt")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == b"resource recovery\n"
            finally:
                connection.close()

        old_limit = None
        try:
            for _ in range(100):
                assert process.poll() is None, "server exited before fault injection"
                try:
                    request()
                    break
                except (OSError, http.client.HTTPException):
                    time.sleep(.02)
            else:
                raise AssertionError("server did not listen")
            time.sleep(.2)
            before_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
            status = Path(f"/proc/{process.pid}/status").read_text()
            vm_kib = int(next(line.split()[1] for line in status.splitlines() if line.startswith("VmSize:")))
            old_limit = resource.prlimit(process.pid, resource.RLIMIT_AS)
            # Small request allocations fit, but another default 2 MiB Rust
            # connection stack cannot be reserved. Do not alter any stack size.
            imposed = vm_kib * 1024 + 512 * 1024
            resource.prlimit(process.pid, resource.RLIMIT_AS, (imposed, old_limit[1]))
            accepted = 0
            for _ in range(3):
                try:
                    request()
                    accepted += 1
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.1)
                assert process.poll() is None, f"server exited under memory pressure: {process.returncode}"
            resource.prlimit(process.pid, resource.RLIMIT_AS, old_limit)
            old_limit = None
            # More requests than the configured cap prove failed spawns did
            # not leak connection slots, in addition to checking process life.
            for _ in range(4):
                request()
            deadline = time.monotonic() + 2
            while len(list(Path(f"/proc/{process.pid}/fd").iterdir())) != before_fds:
                assert time.monotonic() < deadline, "connection descriptors leaked"
                time.sleep(.02)
            return {"side": side, "survived": True, "limited_requests": 3,
                    "accepted_while_limited": accepted, "requests_after_restore": 4,
                    "connection_slots_recovered": True, "fds_recovered": True}
        finally:
            if old_limit is not None and process.poll() is None:
                resource.prlimit(process.pid, resource.RLIMIT_AS, old_limit)
            process.terminate()
            try:
                _, errors = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, errors = process.communicate()
            if errors:
                print(errors.decode(errors="replace"), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("ns_exec", type=Path)
    parser.add_argument("--worker", choices=("stock", "candidate"))
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.rootfs.resolve(), args.candidate.resolve(), args.worker)))
        return
    results = []
    for side in ("stock", "candidate"):
        result = subprocess.run([
            "sudo", "-n", str(args.ns_exec.resolve()), sys.executable, str(Path(__file__).resolve()),
            str(args.rootfs.resolve()), str(args.candidate.resolve()), str(args.ns_exec.resolve()),
            "--worker", side,
        ], capture_output=True, text=True, timeout=45)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            result.check_returncode()
        results.append(json.loads(result.stdout))
    print(json.dumps({"passed": True, "results": results}))


if __name__ == "__main__":
    main()
