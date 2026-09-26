#!/usr/bin/env python3
"""Negative gates for the benchmark and its Linux namespace lifetime.

Run as root on the build host, with the compiled bundle directory. This does
not touch a router, an image, or any process that this test did not start.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time


def run(args, success, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15, **kwargs)
    assert (result.returncode == 0) == success, (args, result.returncode, result.stderr)
    if not success:
        assert not result.stdout, "invalid run emitted successful measurements"
    return result


def namespace_members(namespace):
    members = []
    for path in Path("/proc").glob("[0-9]*/ns/pid"):
        try:
            if os.readlink(path) == namespace:
                members.append(path.parts[2])
        except (FileNotFoundError, PermissionError):
            pass
    return members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run with sudo"
    bench = str(args.bundle.resolve() / "owrt-benchmark")
    namespace = str(args.bundle.resolve() / "ns-exec")
    with tempfile.TemporaryDirectory(prefix="r84-selftest-") as directory:
        root = Path(directory)
        empty = root / "empty"
        empty.write_bytes(b"")
        expected = root / "expected"
        expected.write_bytes(b"expected\n")
        run([bench, "exec", "3", "1", str(empty), "-", "--", "/bin/false"], False)
        run([bench, "exec", "3", "1", str(expected), "-", "--", "/bin/echo", "wrong"], False)
        run([bench, "snapshot", "4294967294"], False)
        result = run([bench, "exec", "7", "1", str(expected), "-", "--", "/bin/echo", "expected"], True)
        measured = json.loads(result.stdout)
        assert measured["successful"] == len(measured["latency_ns"]) == 7

        from selftest_lanes import accounting_tests, event_analyzer_tests, native_tests
        lane_root = root / "lanes"; lane_root.mkdir()
        accounting_tests(lane_root)
        event_analyzer_tests(lane_root)
        native_tests(bench, lane_root)

        class ErrorResponse(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"jsonrpc":"2.0","id":1,"result":[6]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), ErrorResponse)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        rpc_expected = root / "expected.json"
        rpc_expected.write_text('{"result":[0,{"values":{}}]}')
        try:
            run([bench, "http", f"127.0.0.1:{server.server_port}", "GET", "/",
                 "-", str(rpc_expected), "3", "1", "-", "json"], False)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        mounts = Path("/proc/self/mountinfo").read_bytes()
        result = run([namespace, "/bin/sh", "-c",
                      'test "$$" = 2 || exit 1; setsid /bin/sleep 300 >/dev/null 2>&1 & '
                      'readlink /proc/self/ns/pid'], True)
        ns = result.stdout.strip()
        assert ns.startswith("pid:["), result.stdout
        assert not namespace_members(ns), "descendant survived namespace command exit"
        assert Path("/proc/self/mountinfo").read_bytes() == mounts, "namespace mount escaped"

        marker = root / "namespace"
        process = subprocess.Popen([namespace, "/bin/sh", "-c",
                                    'readlink /proc/self/ns/pid > "$1"; '
                                    'setsid /bin/sleep 300 >/dev/null 2>&1 & wait',
                                    "sh", str(marker)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert marker.exists(), "namespace failed to start"
            ns = marker.read_text().strip()
            process.send_signal(signal.SIGKILL)
            process.wait(timeout=5)
            deadline = time.monotonic() + 3
            while namespace_members(ns) and time.monotonic() < deadline:
                time.sleep(0.02)
            assert not namespace_members(ns), "descendant survived launcher death"
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        print("benchmark negative gates and namespace cleanup: PASS")


if __name__ == "__main__":
    main()
