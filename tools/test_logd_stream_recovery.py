#!/usr/bin/env python3
"""Exercise logd stream isolation/recovery using only disposable Unix sockets.

Linux only; run with an exact known ubusd and a candidate logd-rs binary.
No host /dev/log, network interface, service or router is accessed. Each case
owns its child processes and temporary directory. Run the same probe against
pre-fix and fixed binaries; failures remain failures in the JSON output.
"""
import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from r92_recovery_probe import Bus, digest, message


def integer(name, value):
    return message(name, 5, struct.pack(">I", value))


def boolean(name, value):
    return message(name, 7, bytes([bool(value)]))


def string(name, value):
    return message(name, 3, value + b"\0")


def wait_for(check, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.01)
    return False


def take(fd):
    chunks = []
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return b"".join(chunks), False
        if not data:
            return b"".join(chunks), True
        chunks.append(data)


def receive(fd, marker=None, eof=False, timeout=3):
    data = bytearray()
    closed = False
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        chunk, closed = take(fd)
        data.extend(chunk)
        if closed or (not eof and marker is not None and marker in data):
            break
        select.select([fd], [], [], min(0.05, max(0, end - time.monotonic())))
    return bytes(data), closed


def complete_frame_count(data):
    """Return a count only when all received root blobs are complete."""
    offset = count = 0
    while offset < len(data):
        if len(data) - offset < 4:
            return None
        size = struct.unpack_from(">I", data, offset)[0]
        assert 4 <= size <= 1048576, f"invalid log frame size {size}"
        padded = (size + 3) & ~3
        if offset + padded > len(data):
            return None
        offset += padded
        count += 1
    return count


def receive_frames(fd, count, timeout=3):
    data = bytearray()
    offset = complete = 0
    frame_end = None
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        chunk, closed = take(fd)
        data.extend(chunk)
        # Keep the parse cursor across reads. Recounting every prior frame
        # here makes a fragmented stream quadratic in its record count.
        while offset < len(data):
            if frame_end is None:
                if len(data) - offset < 4:
                    break
                size = struct.unpack_from(">I", data, offset)[0]
                assert 4 <= size <= 1048576, f"invalid log frame size {size}"
                frame_end = offset + ((size + 3) & ~3)
            if frame_end > len(data):
                break
            offset = frame_end
            frame_end = None
            complete += 1
        assert complete <= count, "received more log frames than expected"
        if complete == count and offset == len(data):
            return bytes(data), closed
        assert not closed, f"log stream ended with {complete}/{count} frames and {len(data) - offset} trailing bytes"
        select.select([fd], [], [], min(0.05, max(0, end - time.monotonic())))
    raise AssertionError(f"received only {len(data)} bytes before log frame deadline")


def assert_records(data, messages, first_id=0):
    """Validate every frame/field and the entire byte-exact ordered history."""
    assert complete_frame_count(data) == len(messages), "missing, duplicate or truncated log frames"
    offset = 0
    for index, expected in enumerate(messages):
        size = struct.unpack_from(">I", data, offset)[0]
        payload = data[offset + 4:offset + size]
        offset += (size + 3) & ~3
        found = {}
        pos = 0
        while pos < len(payload):
            assert pos + 4 <= len(payload), "truncated blobmsg header"
            word = struct.unpack_from(">I", payload, pos)[0]
            length = word & 0xffffff
            padded = (length + 3) & ~3
            assert word & 0x80000000 and length >= 8 and pos + padded <= len(payload), "invalid blobmsg extent"
            field = payload[pos + 4:pos + length]
            pos += padded
            name_len = struct.unpack_from(">H", field)[0]
            value_at = (name_len + 3 + 3) & ~3
            assert name_len + 2 < len(field) and field[name_len + 2] == 0 and value_at <= len(field), "invalid blobmsg name"
            name = field[2:name_len + 2]
            assert name not in found, f"duplicate field {name!r}"
            found[name] = ((word >> 24) & 127, field[value_at:])
        assert set(found) == {b"msg", b"id", b"priority", b"source", b"time"}, "unexpected log field set"
        assert found[b"msg"] == (3, expected + b"\0"), f"wrong message at index {index}"
        assert found[b"id"] == (5, struct.pack(">I", first_id + index)), f"wrong/duplicate id at index {index}"
        assert found[b"priority"] == (5, struct.pack(">I", 0)), "wrong priority"
        assert found[b"source"] == (5, struct.pack(">I", 1)), "wrong source"
        kind, timestamp = found[b"time"]
        assert kind == 4 and len(timestamp) == 8 and int.from_bytes(timestamp, "big") > 0, "invalid time field"


class Fixture:
    def __init__(self, ubusd, logd):
        self.temp = tempfile.TemporaryDirectory(prefix="logd-stream-")
        self.root = Path(self.temp.name)
        self.bus_path = self.root / "ubus.sock"
        self.log_path = self.root / "log.sock"
        self.ubusd_binary, self.logd_binary = ubusd, logd
        self.children, self.handles, self.readers, self.connections = [], [], [], []
        self.bus = self.subject = None

    def start(self, binary, args, name):
        output = open(self.root / (name + ".log"), "ab")
        self.handles.append(output)
        child = subprocess.Popen([str(binary), *map(str, args)], stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=output, start_new_session=True)
        self.children.append(child)
        return child

    def start_bus(self):
        acl = self.root / "acl"
        acl.mkdir(exist_ok=True)
        self.bus_path.unlink(missing_ok=True)
        self.bus = self.start(self.ubusd_binary, ["-s", self.bus_path, "-A", acl], "ubusd")
        assert wait_for(self.bus_path.exists), "private ubusd did not listen"

    def connect(self):
        client = Bus(self.bus_path)
        self.connections.append(client)
        return client

    def ready(self):
        try:
            client = self.connect()
            try:
                client.lookup("log")
                return True
            finally:
                client.sock.close()
        except (OSError, EOFError, AssertionError):
            return False

    def __enter__(self):
        try:
            self.start_bus()
            self.subject = self.start(self.logd_binary, ["-S", "2048", "--ubus-socket", self.bus_path,
                "--log-socket", self.log_path, "--kmsg", "none", "--no-drop-privileges"], "logd")
            assert wait_for(self.ready), "log object did not register (run as root for the private ubusd ACL)"
            self.client = self.connect()
            self.obj = self.client.lookup("log")
            return self
        except BaseException:
            self.close()
            raise

    def stream(self, oneshot=False, lines=0):
        code, _ = self.client.invoke(self.obj, "read", integer("lines", lines) + boolean("oneshot", oneshot))
        if code != 0:
            return code, None
        assert len(self.client.fds) == 1, "successful stream did not transfer exactly one fd"
        fd = self.client.fds.pop()
        os.set_blocking(fd, False)
        self.readers.append(fd)
        return code, fd

    def close_reader(self, fd):
        os.close(fd)
        self.readers.remove(fd)

    def log(self, value):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(value, str(self.log_path))

    def stop_subject(self):
        self.subject.send_signal(signal.SIGSTOP)
        assert wait_for(lambda: ") T" in Path(f"/proc/{self.subject.pid}/stat").read_text()), "SIGSTOP failed"

    def fd_count(self):
        return len(list(Path(f"/proc/{self.subject.pid}/fd").iterdir()))

    def close(self):
        for fd in self.readers:
            os.close(fd)
        for client in self.connections:
            client.sock.close()
            for fd in client.fds:
                os.close(fd)
        for child in reversed(self.children):
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)
        for handle in self.handles:
            handle.close()
        self.temp.cleanup()

    def __exit__(self, *_):
        self.close()


def disconnected_reader_does_not_close_healthy(f):
    _, a = f.stream()
    _, b = f.stream()
    assert a is not None and b is not None
    # Freeze before making both the old stream and input fd ready. This makes
    # the ordering repeatable: poll sees A's HUP and the syslog datagram together.
    f.stop_subject()
    f.close_reader(a)
    first = b"same-poll-log-marker"
    f.log(first)
    f.subject.send_signal(signal.SIGCONT)
    first_data, closed = receive_frames(b, 1)
    assert_records(first_data, [first])
    assert not closed, "healthy reader inherited another reader's POLLHUP"
    second = b"healthy-reader-still-follows"
    f.log(second)
    second_data, closed = receive_frames(b, 1)
    assert not closed, "healthy stream no longer follows"
    assert_records(first_data + second_data, [first, second])
    return {"healthy_reader_received_both": True, "exact_frames": 2}


def bus_loss_keeps_existing_streams_live(f):
    for i in range(600):
        value = f"backlog-{i:04d}-".encode() + b"x" * 980
        assert f.client.invoke(f.obj, "write", string("event", value))[0] == 0
    _, oneshot = f.stream(oneshot=True, lines=600)
    _, follow = f.stream()
    assert oneshot is not None and follow is not None
    f.stop_subject()
    before = f.fd_count()
    # Explicit lines=0 asks for no history. Prove the fixture instead has a
    # nonempty prefix in the kernel and a remaining tail inside the stopped
    # daemon before disconnecting anything. No timeout can fake this check.
    prefix, closed = take(oneshot)
    assert prefix and not closed, "fixture did not create a blocked oneshot backlog"
    assert b"backlog-0000-" in prefix and b"backlog-0599-" not in prefix, "fixture backlog already fitted in the socket"
    f.bus.kill()
    f.bus.wait(timeout=3)
    f.subject.send_signal(signal.SIGCONT)
    # No new log is sent until the accumulated stream has finished. The old
    # reconnect loop never polled POLLOUT and stalls permanently at this point.
    remainder, closed = receive(oneshot, eof=True)
    data = prefix + remainder
    assert closed and b"backlog-0599-" in data, "oneshot backlog stopped when ubusd disconnected"
    assert_records(data, [f"backlog-{i:04d}-".encode() + b"x" * 980 for i in range(600)])
    f.close_reader(follow)
    assert wait_for(lambda: f.fd_count() <= before - 2), "closed/oneshot stream fds leaked during reconnect"
    f.close_reader(oneshot)
    marker = b"logged-while-bus-was-gone"
    f.log(marker)
    f.start_bus()
    assert wait_for(f.ready), "log object did not re-register"
    client = f.connect()
    code, replies = client.invoke(client.lookup("log"), "read", integer("lines", 1) + boolean("stream", False))
    assert code == 0 and any(marker in payload for _, _, fields in replies for _, payload in fields), "ring lost offline log"
    return {"backlog_bytes": len(data), "blocked_prefix_bytes": len(prefix),
            "exact_frames": 600, "sequential_ids": [0, 599],
            "fds_reclaimed": True, "ring_survived_reconnect": True}


def reconnect_attempts_remain_paced(f):
    f.bus.kill()
    f.bus.wait(timeout=3)
    f.bus_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(f.bus_path))
    listener.listen(16)
    listener.settimeout(0.05)
    stopped = threading.Event()
    attempts = []

    def reject_connections():
        while not stopped.is_set():
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                continue
            with peer:
                attempts.append(time.monotonic())
                # Valid frame, wrong HELLO type: fail immediately, never leave
                # logd blocked waiting for this test listener's reply.
                peer.sendall(struct.pack(">BBHII", 0, 1, 0, 1, 4))

    worker = threading.Thread(target=reject_connections)
    worker.start()
    try:
        end = time.monotonic() + 2.4
        sent = 0
        while time.monotonic() < end:
            f.log(b"keep-syslog-readable")
            sent += 1
            time.sleep(0.002)
        gaps = [b - a for a, b in zip(attempts, attempts[1:])]
        assert 1 <= len(attempts) <= 3 and all(gap >= 0.85 for gap in gaps), f"unpaced reconnects: {len(attempts)}"
        return {"log_datagrams": sent, "attempts": len(attempts), "gaps_seconds": gaps}
    finally:
        stopped.set()
        worker.join(timeout=1)
        listener.close()


def stream_limit_recovers(f):
    for _ in range(64):
        assert f.stream()[0] == 0
    assert f.stream()[0] == 8, "65th stream bypassed the limit"
    baseline = f.fd_count()
    for fd in list(f.readers):
        f.close_reader(fd)
    assert wait_for(lambda: f.fd_count() <= baseline - 64), "closed stream slots were not reclaimed"
    assert f.stream()[0] == 0, "stream capacity did not recover"
    return {"first_64": True, "rejected_65th": True, "capacity_recovered": True}


def aggregate_budget_keeps_fast_reader(f):
    _, fast = f.stream()
    assert fast is not None
    slow = []
    for _ in range(8):
        code, fd = f.stream()
        assert code == 0 and fd is not None
        slow.append(fd)
    # The first reader consumes every record immediately. The later readers
    # jointly exceed the 6 MiB budget for this fixture's 2 MiB ring, while
    # each pending queue remains below even the small-ring 1 MiB limit.
    for i in range(1100):
        marker = f"aggregate-{i:04d}-".encode()
        assert f.client.invoke(f.obj, "write", string("event", marker + b"x" * 980))[0] == 0
        data, closed = receive(fast, marker)
        assert marker in data and not closed, f"healthy first reader evicted at record {i}"
    f.stop_subject()
    closed = sum(take(fd)[1] for fd in slow)
    f.subject.send_signal(signal.SIGCONT)
    assert 0 < closed < len(slow), f"unexpected slow stream eviction count {closed}"
    return {"healthy_records": 1100, "slow_streams_evicted": closed}


CASES = {
    "reader_isolation": disconnected_reader_does_not_close_healthy,
    "bus_loss_streams": bus_loss_keeps_existing_streams_live,
    "reconnect_pacing": reconnect_attempts_remain_paced,
    "stream_limit": stream_limit_recovers,
    "aggregate_budget": aggregate_budget_keeps_fast_reader,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubusd", required=True, type=Path)
    parser.add_argument("--logd", required=True, type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("requires Linux: the daemon's SCM_RIGHTS ABI is Linux-specific")
    args.ubusd, args.logd = args.ubusd.resolve(strict=True), args.logd.resolve(strict=True)
    result = {"ubusd_sha256": digest(args.ubusd), "logd_sha256": digest(args.logd),
              "probe_sha256": digest(Path(__file__)),
              "bus_helper_sha256": digest(Path(__file__).with_name("r92_recovery_probe.py")), "cases": {}}
    for name in args.case or CASES:
        try:
            with Fixture(args.ubusd, args.logd) as fixture:
                observation = CASES[name](fixture)
            result["cases"][name] = {"passed": True, "observation": observation}
        except Exception as error:
            result["cases"][name] = {"passed": False, "error": f"{type(error).__name__}: {error}"}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 0 if all(case["passed"] for case in result["cases"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
