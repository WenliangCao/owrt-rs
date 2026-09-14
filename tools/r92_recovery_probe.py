#!/usr/bin/env python3
"""R92 fault injection against an exact image and a candidate in disposable namespaces.

Never uses a physical watchdog or a host network interface. Each case owns a
mount/net/PID namespace; timeout kills the namespace and every descendant.
Raw observations, daemon identities and failures are retained in OUTPUT.
"""
import argparse
import array
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

CASES = {"ubusd_halfclose": "ubusd", "ubusd_lookup_delete": "ubusd",
         "procd_disconnect_logs": "procd", "procd_watchdog": "procd",
         "netifd_overflow": "netifd", "logd_slow": "logd",
         "rpcd_closed_output": "rpcd", "rpcd_closed_empty": "rpcd", "rpcd_output_limit": "rpcd",
         "httpd_batch": "httpd"}
CHECKS = {
    "ubusd_halfclose": {"identity", "no_read_spin", "complete_reply", "closed_after_reply", "serving"},
    "ubusd_lookup_delete": {"identity", "no_duplicate", "continued_to_end", "serving"},
    "procd_disconnect_logs": {"identity", "writer_progress_without_bus", "writer_completed_after_reconnect", "serving"},
    "procd_watchdog": {"identity", "pumped", "magic_close", "serving"},
    "netifd_overflow": {"identity", "overflow_reached", "buffer_grown", "removed_device_seen", "subsequent_events", "serving"},
    "logd_slow": {"identity", "queue_bounded", "slow_disconnected", "healthy_reader", "serving"},
    "rpcd_closed_output": {"identity", "deadline_observed", "child_reaped", "serving"},
    "rpcd_closed_empty": {"identity", "deadline_observed", "child_reaped", "serving"},
    "rpcd_output_limit": {"identity", "limit_status", "child_reaped", "serving"},
    "httpd_batch": {"identity", "complete_order", "queue_bounded", "serving"},
}
# These are observed failures of the exact original, not successful controls.
# A candidate must satisfy every invariant; never inherit these exceptions.
ORIGINAL_DIFFERENCES = {
    "ubusd_halfclose": {"complete_reply": False},
    "ubusd_lookup_delete": {"no_duplicate": False, "continued_to_end": False, "serving": False},
    "procd_watchdog": {"pumped": False},
    "logd_slow": {"queue_bounded": False, "slow_disconnected": False},
    "httpd_batch": {"queue_bounded": False},
    "rpcd_closed_output": {"deadline_observed": False, "child_reaped": False},
    "rpcd_output_limit": {"child_reaped": False},
}


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attr(kind, data):
    raw = struct.pack(">I", (kind << 24) | (len(data) + 4)) + data
    return raw + b"\0" * (-len(raw) % 4)


def fields(data):
    result = []
    while len(data) >= 4:
        word, = struct.unpack(">I", data[:4])
        size = word & 0xffffff
        if size < 4 or size > len(data):
            break
        result.append(((word >> 24) & 127, data[4:size]))
        data = data[(size + 3) & ~3:]
    return result


def message(name, kind, data):
    key = name.encode() + b"\0"
    header = struct.pack(">H", len(key) - 1) + key
    header += b"\0" * (-len(header) % 4)
    return attr(0x80 | kind, header + data)


class Bus:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(str(path))
        self.seq = 0
        self.fds = []
        assert self.recv()[0] == 0, "missing HELLO"

    def exact(self, count):
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise EOFError("ubus closed")
            data += chunk
        return data

    def recv(self):
        header, control, _, _ = self.sock.recvmsg(12, socket.CMSG_SPACE(4))
        if not header:
            raise EOFError("ubus closed")
        for level, kind, data in control:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                self.fds.extend(array.array("i", data))
        header += self.exact(12 - len(header))
        version, kind, seq, peer, size = struct.unpack(">BBHII", header)
        assert version == 0 and 4 <= size <= 1048576
        return kind, seq, peer, fields(self.exact(size - 4))

    def send(self, kind, data=b"", peer=0):
        self.seq += 1
        self.sock.sendall(struct.pack(">BBHII", 0, kind, self.seq, peer, len(data) + 4) + data)
        return self.seq

    def reply(self, seq):
        replies = []
        while True:
            kind, got, peer, data = self.recv()
            if got != seq:
                continue
            if kind == 1:
                return struct.unpack(">I", dict(data)[1])[0], replies
            replies.append((kind, peer, data))

    def request(self, kind, data=b"", peer=0):
        return self.reply(self.send(kind, data, peer))

    def add(self, path, big=False):
        # A valid method TABLE with a large policy: the lookup response must
        # exceed the kernel send buffer before the next object is reached.
        name = b"method\0"
        table = struct.pack(">H", len(name) - 1) + name
        table += b"\0" * (-len(table) % 4)
        if big:
            for i in range(1024):
                key = ("argument%04d" % i).encode() + b"\0"
                item = struct.pack(">H", len(key) - 1) + key
                item += b"\0" * (-len(item) % 4)
                item += struct.pack(">I", 3)
                table += attr(0x80 | 5, item)
        code, replies = self.request(6, attr(2, path.encode() + b"\0") + attr(6, attr(0x80 | 2, table)))
        assert code == 0 and replies
        return struct.unpack(">I", dict(replies[0][2])[3])[0]

    def paths(self):
        code, replies = self.request(4)
        assert code == 0
        return [dict(data)[2].rstrip(b"\0").decode() for kind, _, data in replies if kind == 2]

    def lookup(self, path):
        code, replies = self.request(4, attr(2, path.encode() + b"\0"))
        assert code == 0 and replies
        return struct.unpack(">I", dict(replies[0][2])[3])[0]

    def invoke(self, obj, method, data=b""):
        return self.request(5, attr(3, struct.pack(">I", obj)) + attr(4, method.encode() + b"\0") + attr(7, data))


def inner(root, side, case):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("mount", "--bind", root / "dev/null", root / "proc/kmsg")
    run("ip", "link", "set", "lo", "up")
    output = root / "tmp/out"
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(root / "dev/log"))
    receiver.setblocking(False)
    processes = []
    checks = {}
    observations = {}

    def drain():
        while True:
            try:
                receiver.recv(65536)
            except (BlockingIOError, OSError):
                return

    stop_receiver = threading.Event()

    def receive_logs():
        while not stop_receiver.wait(0.005):
            drain()

    receiver_thread = threading.Thread(target=receive_logs, daemon=True)
    receiver_thread.start()

    def wait_for(fn, seconds=6):
        until = time.monotonic() + seconds
        while True:
            drain()
            if fn():
                return True
            if time.monotonic() >= until:
                return False
            time.sleep(0.02)

    def start(binary, *args):
        with (output / (Path(binary).name + ".log")).open("ab") as log:
            process = subprocess.Popen(["chroot", str(root), binary, *args], stdout=log, stderr=log)
        processes.append(process)
        return process

    def call(obj, method, data=None):
        result = run("chroot", root, "ubus", "-S", "-t", "2", "call", obj, method,
                     json.dumps(data or {}), capture_output=True, timeout=4)
        return json.loads(result.stdout or "{}")

    def ready(obj):
        result = subprocess.run(["chroot", str(root), "ubus", "-S", "-t", "1", "list", obj],
                                capture_output=True, timeout=3)
        return result.returncode == 0 and result.stdout.strip() == obj.encode()

    component = CASES[case]
    binary = ("/usr/sbin/uhttpd" if component == "httpd" else "/sbin/" + component) if side == "original" else "/tmp/" + component + "-rs"
    sock = root / "var/run/ubus/ubus.sock"
    try:
        bus = start(binary if component == "ubusd" else "/sbin/ubusd")
        assert wait_for(sock.exists), "bus did not start"
        if component == "ubusd":
            subject = bus
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])
            keep = Bus(sock)
            keep.add("r92.a")
            keep.add("r92.z")
            bulk = Bus(sock)
            for i in range(128):
                bulk.add("r92.m%04d" % i, big=True)
            slow = Bus(sock)
            seq = slow.send(4)
            time.sleep(0.2)
            assert len(slow.sock.recv(1024 * 1024, socket.MSG_PEEK)) > 65536, "lookup never reached backpressure"
            if case == "ubusd_halfclose":
                slow.sock.shutdown(socket.SHUT_WR)
                time.sleep(0.1)

                def ticks():
                    values = Path(f"/proc/{subject.pid}/stat").read_text().split(")", 1)[1].split()
                    return int(values[11]) + int(values[12])

                before = ticks()
                time.sleep(0.8)
                cpu = (ticks() - before) / os.sysconf("SC_CLK_TCK")
                observations["cpu_seconds_in_0_8s"] = cpu
                checks["no_read_spin"] = cpu < 0.15
                code, replies = None, []
                while True:
                    try:
                        kind, got, peer, data = slow.recv()
                    except EOFError:
                        break
                    assert got == seq
                    if kind == 1:
                        code = struct.unpack(">I", dict(data)[1])[0]
                        break
                    replies.append((kind, peer, data))
                paths = [dict(data)[2].rstrip(b"\0").decode() for kind, _, data in replies if kind == 2]
                observations.update(reply_status=code, paths=paths)
                checks["complete_reply"] = code == 0 and paths == sorted(["r92.a", "r92.z"] + ["r92.m%04d" % i for i in range(128)])
                checks["closed_after_reply"] = slow.sock.recv(1) == b""
            else:
                bulk.sock.close()
                assert wait_for(lambda: keep.paths() == ["r92.a", "r92.z"]), "objects not removed"
                try:
                    code, replies = slow.reply(seq)
                    paths = [dict(data)[2].rstrip(b"\0").decode() for kind, _, data in replies if kind == 2]
                    observations["paths"] = paths
                    checks["no_duplicate"] = len(paths) == len(set(paths))
                    checks["continued_to_end"] = code == 0 and paths[-1:] == ["r92.z"]
                except (EOFError, OSError):
                    checks.update(no_duplicate=False, continued_to_end=False)
            try:
                checks["serving"] = subject.poll() is None and keep.paths()[-1:] == ["r92.z"]
            except (EOFError, OSError):
                # The original can close its sockets before waitpid reports
                # its UAF crash. Record failed health instead of losing the
                # result to an exception in the probe itself.
                checks["serving"] = False
                wait_for(lambda: subject.poll() is not None, 0.2)
        elif component == "httpd":
            provider = Bus(sock)
            provider.add("r92.large", big=True)
            write(root / "www/r92-health", "ok")
            subject = start(binary, "-f", "-h", "/www", "-p", "127.0.0.1:18080", "-u", "/ubus", "-a", "-N", "4", "-k", "0", "-T", "3")

            def http_request(body=None):
                connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
                try:
                    connection.request("GET" if body is None else "POST", "/r92-health" if body is None else "/ubus",
                                       body=body, headers={"Connection": "close"})
                    response = connection.getresponse()
                    assert response.status == 200
                    return response.read()
                finally:
                    connection.close()

            def listening():
                try:
                    return http_request() == b"ok"
                except (OSError, http.client.HTTPException):
                    return False

            assert wait_for(listening)
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])

            def batch(count):
                return json.dumps([{"jsonrpc": "2.0", "id": i, "method": "list", "params": ["r92.large"]}
                                   for i in range(count)], separators=(",", ":")).encode()

            complete = json.loads(http_request(batch(4)))
            checks["complete_order"] = [item["id"] for item in complete] == list(range(4)) and all("r92.large" in item["result"] for item in complete)
            data = batch(800)
            assert len(data) <= 65536
            assert len(json.dumps(complete[0])) * 800 > 12 * 1024 * 1024, "fixture too small to amplify memory"

            def rss():
                return int(re.search(r"VmRSS:\s+(\d+)", Path(f"/proc/{subject.pid}/status").read_text())[1])

            before = rss()
            slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            slow.settimeout(5)
            slow.connect(("127.0.0.1", 18080))
            slow.sendall(b"POST /ubus HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + str(len(data)).encode() + b"\r\nConnection: close\r\n\r\n" + data)
            samples = []
            for _ in range(100):
                samples.append(rss())
                time.sleep(0.02)
            assert slow.recv(20, socket.MSG_PEEK).startswith(b"HTTP/1.1 200"), "batch not dispatched"
            checks["queue_bounded"] = max(samples) - before < 4096
            slow.close()
            checks["serving"] = subject.poll() is None and wait_for(listening)
            observations.update(request_bytes=len(data), projected_response_bytes=len(json.dumps(complete[0])) * 800,
                                rss_before_kib=before, rss_peak_kib=max(samples), rss_samples_kib=samples)
            provider.sock.close()
        elif component == "netifd":
            run("ip", "link", "add", "probe0", "type", "veth", "peer", "name", "probe1")
            run("ip", "link", "set", "probe0", "up")
            subject = start(binary)
            assert wait_for(lambda: ready("network.interface.probe"))
            assert wait_for(lambda: call("network.interface.probe", "status").get("up"))
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])

            def event_socket(label):
                data = run("ss", "-f", "netlink", "-a", "-n", "-m", "-e", capture_output=True).stdout.decode()
                write(output / (label + ".ss"), data)
                # Only netifd subscribes to rtnetlink group LINK in this namespace.
                # inet_diag can list the same multicast socket in both its
                # port-id and multicast walks. Require one distinct record.
                lines = sorted({line for line in data.splitlines() if "groups=0x00000001" in line
                                and re.search(r"\s0:\d+\s", line)})
                assert len(lines) == 1, lines
                return {"buffer": int(re.search(r"\brb(\d+)", lines[0])[1]),
                        "drops": int(re.search(r",d(\d+)\)", lines[0])[1])}

            before = event_socket("before")
            subject.send_signal(signal.SIGSTOP)
            commands = "link set probe0 down\nlink set probe0 up\n" * 1500 + "link del probe0\n"
            write(output / "flood.ip", commands)
            run("ip", "-batch", output / "flood.ip", capture_output=True)
            lost = event_socket("stopped")
            checks["overflow_reached"] = lost["drops"] > 0
            subject.send_signal(signal.SIGCONT)
            checks["removed_device_seen"] = wait_for(lambda: call("network.interface.probe", "status").get("available") is False)
            after = event_socket("after")
            checks["buffer_grown"] = after["buffer"] > before["buffer"]
            observations.update(before=before, stopped=lost, after=after)
            run("ip", "link", "add", "probe0", "type", "veth", "peer", "name", "probe1")
            run("ip", "link", "set", "probe0", "up")
            checks["subsequent_events"] = wait_for(lambda: call("network.interface.probe", "status").get("up") is True)
            checks["serving"] = subject.poll() is None and ready("network")
        elif component == "logd":
            receiver.close()
            (root / "dev/log").unlink()
            # drain() remains harmless while logd owns the real fixture socket.
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.setblocking(False)
            subject = start(binary, "-S", "64")
            assert wait_for(lambda: ready("log"))
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])
            client = Bus(sock)
            obj = client.lookup("log")
            readers = []
            for _ in range(2):
                code, _ = client.invoke(obj, "read", message("lines", 5, struct.pack(">I", 0)))
                assert code == 0 and len(client.fds) == 1
                fd = client.fds.pop()
                os.set_blocking(fd, False)
                readers.append(fd)

            def rss():
                return int(re.search(r"VmRSS:\s+(\d+)", Path(f"/proc/{subject.pid}/status").read_text())[1])

            def take(fd):
                chunks = []
                eof = False
                while True:
                    try:
                        value = os.read(fd, 65536)
                    except BlockingIOError:
                        break
                    if not value:
                        eof = True
                        break
                    chunks.append(value)
                return b"".join(chunks), eof

            before = rss()
            sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sender.connect(str(root / "dev/log"))
            healthy_eof = False
            for i in range(12000):
                sender.send(("<30>r92-%05d-" % i).encode() + b"x" * 950)
                if i % 8 == 0:
                    _, eof = take(readers[1])
                    healthy_eof |= eof
            time.sleep(0.1)
            after = rss()
            slow_bytes, slow_eof = take(readers[0])
            _, eof = take(readers[1])
            healthy_eof |= eof
            sender.send(b"<30>r92-final-marker")
            healthy = bytearray()

            def marker():
                value, _ = take(readers[1])
                healthy.extend(value)
                return b"r92-final-marker" in healthy

            checks["queue_bounded"] = after - before < 4096
            checks["slow_disconnected"] = slow_eof
            checks["healthy_reader"] = not healthy_eof and wait_for(marker)
            checks["serving"] = subject.poll() is None and ready("log")
            observations.update(rss_before_kib=before, rss_after_kib=after, slow_bytes=len(slow_bytes))
            for fd in readers:
                os.close(fd)
            sender.close()
        elif component == "rpcd":
            subject = start(binary, "-t", "1")
            assert wait_for(lambda: ready("file"))
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])
            started = time.monotonic()
            request = subprocess.Popen(["chroot", str(root), "ubus", "-S", "-t", "4", "call", "file", "exec",
                                     json.dumps({"command": "/tmp/output_lifecycle", "params": [
                                         "overflow" if case == "rpcd_output_limit" else "empty" if case == "rpcd_closed_empty" else "closed"]})],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert wait_for(lambda: (output / "child").exists()), "child never started"
            pid = int((output / "child").read_text())
            if case == "rpcd_closed_output":
                # Both pipes become readable+EOF before the C ustream loop
                # resumes. Without this schedule its first read can race
                # close(), leaving only a HUP on an already-drained pipe.
                subject.send_signal(signal.SIGSTOP)
                write(root / "tmp/close-output", "")
                assert wait_for(lambda: (output / "closed").exists())
                subject.send_signal(signal.SIGCONT)
            time.sleep(0.08)
            directory = Path(f"/proc/{pid}/fd")
            observations["child_fds"] = {p.name: os.readlink(p) for p in directory.iterdir()} if directory.exists() else {}
            stdout, stderr = request.communicate(timeout=6)
            result = subprocess.CompletedProcess(request.args, request.returncode, stdout, stderr)
            elapsed = time.monotonic() - started
            assert (output / "child").exists(), "child never started"
            pid = int((output / "child").read_text())
            # A dead but unreaped child is still a resource leak here.
            checks["child_reaped"] = wait_for(lambda: not Path(f"/proc/{pid}").exists(), 0.3)
            if case == "rpcd_output_limit":
                checks["limit_status"] = result.returncode == 8
            else:
                checks["deadline_observed"] = result.returncode == 7 and 0.8 <= elapsed <= 3
            checks["serving"] = subject.poll() is None and isinstance(call("session", "list"), dict)
            observations.update(elapsed_seconds=elapsed, status=result.returncode, stdout_hex=result.stdout.hex(), stderr=result.stderr.decode(), child_pid=pid)
        else:
            # This is a regular file on the private /dev tmpfs. There is no
            # path from this fixture to a hardware watchdog.
            write(root / "dev/watchdog", "")
            subject = start(binary, "-S", "-I", "/tmp/initd", "-R", "/tmp/rcd")
            assert wait_for(lambda: ready("service")), "procd not ready"
            checks["identity"] = digest(Path(f"/proc/{subject.pid}/exe")) == digest(root / binary[1:])
            if case == "procd_watchdog":
                call("system", "watchdog", {"frequency": 1, "timeout": 4, "stop": False})
                before = (root / "dev/watchdog").stat().st_size
                time.sleep(3.2)
                after = (root / "dev/watchdog").stat().st_size
                observations.update(before=before, after=after)
                checks["pumped"] = after - before >= 2
                call("system", "watchdog", {"magicclose": True, "stop": True})
                checks["magic_close"] = (root / "dev/watchdog").read_bytes().endswith(b"V")
            else:
                command = "echo ready >/tmp/out/ready; while [ ! -e /tmp/go ]; do sleep .05; done; dd if=/dev/zero bs=4096 count=256 2>/dev/null | tr '\\000' x; echo; echo done >/tmp/out/done; sleep 30"
                call("service", "set", {"name": "r92", "instances": {"i": {
                    "command": ["/bin/sh", "-c", command], "stdout": True, "stderr": True}}})
                assert wait_for(lambda: (output / "ready").exists())
                bus.kill()
                bus.wait(timeout=2)
                time.sleep(0.15)
                write(root / "tmp/go", "")
                checks["writer_progress_without_bus"] = wait_for(lambda: (output / "done").exists(), 4)
                bus = start("/sbin/ubusd")
                assert wait_for(lambda: ready("service")), "no reconnect"
                checks["writer_completed_after_reconnect"] = wait_for(lambda: (output / "done").exists())
            checks["serving"] = subject.poll() is None and isinstance(call("service", "list"), dict)
        observations["subject_exit"] = subject.poll()
    finally:
        stop_receiver.set()
        receiver_thread.join(timeout=1)
        write(output / "result.json", json.dumps({"checks": checks, "observations": observations}, indent=2) + "\n")
        receiver.close()
        for p in reversed(processes):
            if p.poll() is None:
                p.kill()
        for p in processes:
            p.wait(timeout=3)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bins", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--sides", nargs="+", choices=("original", "candidate"), default=("original", "candidate"))
    parser.add_argument("--output-helper", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        parser.error("run as root on the Linux build host")
    if any(c.startswith("rpcd_") for c in args.cases) and not args.output_helper:
        parser.error("rpcd cases require --output-helper (the output_lifecycle musl example)")
    args.output.mkdir(parents=True, exist_ok=False)
    components = sorted({CASES[c] for c in args.cases})
    identities = {c: {"original": digest(args.rootfs / ("usr/sbin/uhttpd" if c == "httpd" else "sbin/" + c)),
                      "candidate": digest(args.bins / (c + "-rs"))} for c in components}
    write(args.output / "binaries.json", json.dumps(identities, indent=2) + "\n")
    if args.output_helper:
        write(args.output / "helper.sha256", digest(args.output_helper) + "\n")
    rows = []
    for side in args.sides:
        for case in args.cases:
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="r92-recovery-") as temporary:
                root = Path(temporary) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state", "initd", "rcd"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                for component in components:
                    shutil.copy2(args.bins / (component + "-rs"), root / "tmp" / (component + "-rs"))
                if args.output_helper:
                    shutil.copy2(args.output_helper, root / "tmp/output_lifecycle")
                write(root / "etc/config/network", "config interface 'probe'\n option proto 'static'\n option device 'probe1'\n option ipaddr '10.92.0.1/24'\n option force_link '0'\n")
                write(root / "etc/config/wireless", "")
                with (destination / "driver.log").open("wb") as log:
                    result = subprocess.run(["timeout", "-k", "3", "45", "unshare", "--mount", "--net",
                                             "--pid", "--fork", "--kill-child", sys.executable,
                                             str(Path(__file__).resolve()), "--inner", str(root), side, case],
                                            stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            path = destination / "raw/result.json"
            values = json.loads(path.read_text()) if path.exists() else {"checks": {}, "observations": {}}
            expected = ORIGINAL_DIFFERENCES.get(case, {}) if side == "original" else {}
            row = {"side": side, "case": case, "exit": result.returncode, **values,
                   "expected_original_failures": expected,
                   "passed": result.returncode == 0 and values["checks"].keys() == CHECKS[case]
                   and all(value is expected.get(key, True) for key, value in values["checks"].items())}
            rows.append(row)
            write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
            print(json.dumps({key: value for key, value in row.items() if key != "observations"}), flush=True)
    passed = len(rows) == len(args.sides) * len(args.cases) and all(r["passed"] for r in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
