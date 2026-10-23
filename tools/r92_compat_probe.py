#!/usr/bin/env python3
"""R92 byte, lifecycle and resource contracts in disposable Linux namespaces.

Uses the exact image as the original. Every row records its expected outcome;
an original's known adverse behaviour is never a candidate acceptance waiver.
The namespace owns /dev, the network and all children, including on failure.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from r92_recovery_probe import Bus, attr, digest, fields, message, run, write
from r92_httpd_probe import CASES as HTTP_CASES


def members(data):
    result = []
    for kind, payload in fields(data):
        length, = struct.unpack(">H", payload[:2])
        name = payload[2:2 + length]
        offset = (length + 3 + 3) & ~3
        result.append((name, kind, payload[offset:]))
    return result


def values(data):
    result = {}
    for name, kind, value in members(data):
        if kind == 3:
            value = value.rstrip(b"\0")
        elif kind == 2:
            value = values(value)
        elif kind == 1:
            value = [values(message("value", k, v))[b"value"] for _, k, v in members(value)]
        elif kind in (4, 5, 6, 7):
            value = int.from_bytes(value, "big")
        result[name] = value
    return result


def response_data(replies):
    return [values(dict(data)[7]) for kind, _, data in replies if kind == 2 and 7 in dict(data)]


def string(name, value):
    return message(name, 3, value.encode() + b"\0" if isinstance(value, str) else value + b"\0")


def integer(name, value):
    return message(name, 5, struct.pack(">I", value))


class Fixture:
    def __init__(self, root, side, component):
        self.root, self.side, self.component = root, side, component
        self.output = root / "tmp/out"
        self.sock = root / "var/run/ubus/ubus.sock"
        self.binary = ("/usr/sbin/uhttpd" if component == "httpd" else "/sbin/" + component) if side == "original" else "/tmp/" + component + "-rs"
        self.processes, self.clients, self.checks, self.observations = [], [], {}, {}
        run("mount", "--make-rprivate", "/")
        run("mount", "-t", "proc", "proc", "/proc")
        run("mount", "-t", "proc", "proc", root / "proc")
        run("mount", "-t", "sysfs", "sysfs", root / "sys")
        run("mount", "-t", "tmpfs", "tmpfs", root / "dev")
        for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
            run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
        run("mount", "--bind", root / "dev/null", root / "proc/kmsg")
        run("ip", "link", "set", "lo", "up")
        self.stop_logs = threading.Event()
        self.log_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.log_socket.settimeout(0.05)
        if component != "logd":
            self.log_socket.bind(str(root / "dev/log"))
        self.logs = []

        def drain():
            while not self.stop_logs.is_set():
                try:
                    self.logs.append(self.log_socket.recv(65536))
                except (socket.timeout, OSError):
                    pass

        self.log_thread = threading.Thread(target=drain, daemon=True)
        if component != "logd":
            self.log_thread.start()

    def check(self, name, actual, expected=True):
        self.checks[name] = {"actual": actual, "expected": expected, "passed": actual == expected}

    def wait(self, predicate, timeout=5):
        until = time.monotonic() + timeout
        while True:
            if predicate():
                return True
            if time.monotonic() >= until:
                return False
            time.sleep(0.01)

    def start(self, binary, *args):
        with (self.output / (Path(binary).name + ".log")).open("ab") as log:
            process = subprocess.Popen(["chroot", str(self.root), binary, *args], stdout=log, stderr=log)
        self.processes.append(process)
        return process

    def start_bus(self):
        self.bus = self.start(self.binary if self.component == "ubusd" else "/sbin/ubusd")
        assert self.wait(self.sock.exists), "ubusd did not bind"
        if self.component == "ubusd":
            self.subject = self.bus
            self.identity()

    def start_subject(self, *args, obj=None):
        self.subject = self.start(self.binary, *args)
        if obj:
            assert self.wait(lambda: self.ready(obj)), f"{obj} not registered"
        self.identity()

    def identity(self):
        expected = digest(self.root / self.binary[1:])
        executable = Path(f"/proc/{self.subject.pid}/exe")
        # Popen returns before chroot's exec. A listener/object is optional
        # for some probes, so explicitly wait for the expected executable.
        def matches():
            try:
                return digest(executable) == expected
            except OSError:
                return False
        self.wait(matches)
        self.check("identity", digest(executable) if executable.exists() else None, expected)

    def connect(self):
        client = Bus(self.sock)
        self.clients.append(client)
        return client

    def ready(self, obj):
        result = subprocess.run(["chroot", str(self.root), "ubus", "-S", "-t", "1", "list", obj], capture_output=True, timeout=2)
        return result.returncode == 0 and result.stdout.strip() == obj.encode()

    def call(self, obj, method, data=None):
        result = run("chroot", self.root, "ubus", "-S", "-t", "2", "call", obj, method, json.dumps(data or {}), capture_output=True, timeout=3)
        return json.loads(result.stdout or b"{}")

    def close(self):
        for client in self.clients:
            client.sock.close()
            for fd in client.fds:
                os.close(fd)
        self.stop_logs.set()
        if self.log_thread.is_alive():
            self.log_thread.join(timeout=1)
        self.log_socket.close()
        (self.output / "syslog.bin").write_bytes(b"\n".join(self.logs))
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
        for process in self.processes:
            process.wait(timeout=2)


def ubusd_wire(f):
    f.start_bus()
    provider, client = f.connect(), f.connect()
    provider.add("r92.a")
    for length in (1, 2, 3):
        code, replies = client.request(4, struct.pack(">I", length) + attr(2, b"r92.a\0"))
        f.check(f"short_top_{length}", [code, len(replies)], [0, 1])
        code, replies = provider.request(6, attr(2, f"r92.short{length}\0".encode()) + attr(6, struct.pack(">I", length)))
        attrs = dict(replies[0][2]) if replies else {}
        f.check(f"short_signature_{length}", [code, 3 in attrs, 5 in attrs], [0, True, False])
    code, replies = client.request(4, attr(2, b"r92.a\0"))
    type_id = dict(replies[0][2])[5]
    code, replies = provider.request(6, attr(2, b"r92.reuse\0") + attr(5, type_id) + attr(6, b""))
    f.check("reused_type_reply", [code, dict(replies[0][2]).get(5) == type_id], [0, True])
    # Legal non-table method attributes exercise padded prefix sizing in a
    # debug daemon, where the old fast path aborted at its size assertion.
    for i in range(4):
        code, _ = provider.request(6, attr(2, f"r92.pad{i}\0".encode()) + attr(6, string("m" + "x" * i, "v")))
        assert code == 0
    code, replies = client.request(4, attr(2, b"r92.pad*\0"))
    f.check("padded_prefix", [code, len(replies)], [0, 4])
    event_obj = provider.add("r92.listener")
    registration = integer("object", event_obj) + integer("object", 1) + string("pattern", b"r92.\xff") + string("pattern", "ignored")
    f.check("event_first_fields", provider.invoke(1, "register", registration)[0], 0)
    event = string("id", b"r92.\xff") + string("id", "ignored") + message("data", 2, integer("n", 1)) + message("data", 2, integer("n", 2))
    f.check("event_send", client.invoke(1, "send", event)[0], 0)
    kind, _, _, data = provider.recv()
    f.check("event_bytes_and_first_data", [kind, dict(data)[4].hex(), values(dict(data)[7]).get(b"n")], [5, b"r92.\xff\0".hex(), 1])
    f.check("event_wrong_object_type", provider.invoke(1, "register", message("object", 6, b"\0\x01") + string("pattern", "r92.bad"))[0], 2)
    watch_obj = client.add("r92.watch")
    target = struct.pack(">I", event_obj)
    f.check("target_first_four", client.request(8, attr(3, struct.pack(">I", watch_obj)) + attr(8, target + b"tail"))[0], 0)
    f.check("target_unsubscribe", client.request(9, attr(3, struct.pack(">I", watch_obj)) + attr(8, target + b"tail"))[0], 0)
    short = []
    for length in (0, 1, 2, 3):
        # The next attr fixes the bytes C reads beyond the short TARGET;
        # Rust rejects the declared underflow before decoding.
        code, _ = client.request(8, attr(3, struct.pack(">I", watch_obj)) + attr(8, b"\0" * length) + attr(0, b"\0" * 4))
        short.append(code)
    f.check("target_short", short, [4] * 4 if f.side == "original" else [2] * 4)
    f.check("serving", f.subject.poll() is None and "r92.a" in client.paths())


def ubusd_acl_types(f):
    specs = {
        "good": {"methods": ["method"], "tags": ["tag"], "acl": {"read": ["ok"]}},
        "bad_methods": {"methods": {"method": True}, "acl": {"read": ["ok"]}},
        "bad_tags": {"tags": {"tag": True}},
        "bad_acl": {"methods": ["method"], "acl": ["not-a-table"]},
        "only_bad": {"methods": "*", "tags": "*", "acl": ["not-a-table"]},
    }
    path = f.root / "usr/share/acl.d/r92.json"
    write(path, json.dumps({"user": "nobody", "access": {"r92.acl." + k: v for k, v in specs.items()}}))
    path.chmod(0o644)
    f.start_bus()
    provider = f.connect()
    for name in specs:
        provider.add("r92.acl." + name)
    code, replies = provider.invoke(2, "query")
    private = response_data(replies)[0][b"acl"]
    f.check("private_tables_only", [code, sorted(row[b"obj"].decode() for row in private)], [0, ["r92.acl.bad_methods", "r92.acl.good"]])
    f.check("private_table_bytes", all(row[b"acl"] == {b"read": [b"ok"]} for row in private))
    # chroot drops credentials after entering the image, so the build host's
    # account database and the private parent directory do not affect ACLs.
    result = subprocess.run(["chroot", "--userspec=nobody:nogroup", str(f.root), "/bin/ubus", "-S", "list", "r92.acl.*"], capture_output=True, timeout=3)
    f.check("typed_methods_visibility", [result.returncode, sorted(result.stdout.decode().splitlines())], [0, ["r92.acl.bad_acl", "r92.acl.good"]])
    f.check("serving", f.subject.poll() is None and "r92.acl.good" in provider.paths())


def uci_rename(f):
    f.observations["binary_sha256"] = digest(f.root / f.binary[1:])
    original = b"config a 's'\n option o 'value'\n"
    for label, target in (("section", b"r92.s"), ("option", b"r92.s.o")):
        savedir = "/tmp/uci-r92-" + label
        (f.root / savedir[1:]).mkdir()
        config = f.root / "etc/config/r92"
        config.write_bytes(original)
        cmd = ["chroot", str(f.root), f.binary, "-t", savedir]
        result = subprocess.run(cmd + ["batch"], input=b"rename " + target + b"=\xff\xfe\nexport r92\nchanges r92\n", capture_output=True, timeout=3)
        (f.output / (label + "-stdout.bin")).write_bytes(result.stdout)
        (f.output / (label + "-stderr.bin")).write_bytes(result.stderr)
        delta = f.root / savedir[1:] / "r92"
        delta_bytes = delta.read_bytes() if delta.exists() else b""
        # Both CLIs unload packages between batch commands. C's transient
        # raw rename survives in the saved delta, but export reloads and
        # rejects that delta; it does not expose a raw name in this batch.
        f.check(label + "_raw_rename", b"\xff\xfe" in result.stdout, False)
        f.check(label + "_raw_delta", b"\xff\xfe" in delta_bytes, f.side == "original")
        f.check(label + "_no_replacement", b"\xef\xbf\xbd" not in result.stdout + delta_bytes)
        f.check(label + "_diagnostic", b"Invalid argument" in result.stderr, f.side != "original")
        f.check(label + "_config_untouched", config.read_bytes().hex(), original.hex())
        fresh = subprocess.run(cmd + ["export", "r92"], capture_output=True, timeout=3)
        f.check(label + "_fresh_load", fresh.returncode == 0 and b"config a 's'" in fresh.stdout and b"option o 'value'" in fresh.stdout and b"\xff" not in fresh.stdout)


def logd_bytes(f):
    f.start_bus()
    f.start_subject("-S", "64", obj="log")
    client = f.connect()
    obj = client.lookup("log")
    payloads = [b"\xff\x80-a", b"a" * 1022 + "中".encode(), b"b" * 1023 + b"tail", b"c\0ignored", b"<30>x\xfe\nline\t "]
    expected = [payloads[0], b"a" * 1022 + b"\xe4", b"b" * 1023, b"c", b"x\xfe line"]
    for i, (payload, want) in enumerate(zip(payloads, expected)):
        code, _ = client.invoke(obj, "write", string("event", payload))
        code_read, replies = client.invoke(obj, "read", integer("lines", 1) + message("stream", 7, b"\0"))
        got = response_data(replies)[0][b"log"][-1][b"msg"]
        f.check(f"write_bytes_{i}", [code, code_read, got.hex()], [0, 0, want.hex()])
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sender.connect(str(f.root / "dev/log"))
    sender.send(b"<30>datagram-\xff\x80")
    sender.close()

    def datagram():
        code, replies = client.invoke(obj, "read", integer("lines", 1) + message("stream", 7, b"\0"))
        return code == 0 and response_data(replies)[0][b"log"][-1][b"msg"] == b"datagram-\xff\x80"

    f.check("datagram_bytes", f.wait(datagram))
    f.check("serving", f.subject.poll() is None and f.ready("log"))


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


def backlog_admission_matches(statuses, bounded):
    """The long-record 2 MiB corpus admits two histories, then hits 6 MiB."""
    if len(statuses) != 4 or statuses[:2] != [0, 0]:
        return False
    if not bounded:
        return statuses[2:] == [0, 0]
    # Pipe buffering can move the rejection between the third and fourth
    # history. Either way, an unbounded or old 1 MiB limit must fail this gate.
    return statuses[2:] in ([0, 8], [8, 8])


def logd_limits(f):
    f.start_bus()
    f.start_subject("-S", "2048", obj="log")
    client = f.connect()
    obj = client.lookup("log")
    readers = []

    def stream(data=integer("lines", 0)):
        code, _ = client.invoke(obj, "read", data)
        if client.fds:
            fd = client.fds.pop()
            os.set_blocking(fd, False)
            readers.append(fd)
        return code

    try:
        f.check("first_64", [stream() for _ in range(64)], [0] * 64)
        f.check("client_65", stream(), 0 if f.side == "original" else 8)
        for fd in readers:
            os.close(fd)
        readers.clear()
        client.invoke(obj, "write", string("event", "release closed clients"))
        f.check("capacity_recovers", stream(), 0)
        os.close(readers.pop())
        client.invoke(obj, "write", string("event", "release replacement"))
        for _ in range(8):
            assert stream() == 0
        # v0.3.2 already budgets max(1 MiB, 3 * ring) per stream and
        # max(4 MiB, per-stream) in total: this 2 MiB ring has a 6 MiB budget.
        # 1100 long frames each stay below one stream's cap, while eight
        # undrained copies exceed 6 MiB even after their pipe buffering.
        for i in range(1100):
            assert client.invoke(obj, "write", string("event", f"{i:04d}-".encode() + b"x" * 995))[0] == 0
        time.sleep(0.05)
        f.subject.send_signal(signal.SIGSTOP)
        closed = sum(take(fd)[1] for fd in readers)
        f.subject.send_signal(signal.SIGCONT)
        f.observations["aggregate_closed_streams"] = closed
        f.check("aggregate_bound", closed > 0, f.side != "original")
        f.check("aggregate_keeps_readers", closed < 8)
        for fd in readers:
            os.close(fd)
        readers.clear()
        for i in range(1500):
            assert client.invoke(obj, "write", string("event", f"backlog-{i:04d}-".encode() + b"x" * 980))[0] == 0
        # A full ring is a legal history stream; rejecting it at 1 MiB is
        # the retired behavior. Multiple unread histories must still hit the
        # aggregate cap. Keep the accepted descriptors alive through refusal.
        statuses = [stream(message("oneshot", 7, b"\x01")) for _ in range(4)]
        f.observations["initial_backlog_statuses"] = statuses
        f.check("full_ring_allowed", statuses[:2], [0, 0])
        f.check("initial_backlog_bound", backlog_admission_matches(statuses, f.side != "original"))
        history = bytearray()

        def history_complete():
            data, eof = take(readers[0])
            history.extend(data)
            return eof

        f.check("existing_history_after_refusal", f.wait(history_complete)
                and len(history) > 1024 * 1024 and b"backlog-1499-" in history)
        for fd in readers:
            os.close(fd)
        readers.clear()
        assert client.invoke(obj, "write", string("event", "release histories"))[0] == 0
        f.check("bounded_oneshot", stream(integer("lines", 10) + message("oneshot", 7, b"\x01")), 0)
        payload = bytearray()

        def complete():
            data, eof = take(readers[-1])
            payload.extend(data)
            return eof

        f.check("oneshot_complete", f.wait(complete) and b"backlog-1499-" in payload)
        f.check("serving", f.subject.poll() is None and f.ready("log"))
    finally:
        for fd in readers:
            os.close(fd)


def netifd_restart(f):
    write(f.root / "etc/config/network", "config interface 'r92'\n option proto 'none'\n option auto '0'\n")
    write(f.root / "etc/config/wireless", "")
    f.start_bus()
    f.start_subject("-c", "/etc/config", obj="network.interface.r92")
    client = f.connect()
    old_id = client.lookup("network")
    before = Path(f"/proc/{f.subject.pid}/cmdline").read_bytes()
    started = time.monotonic()
    f.call("network", "restart")
    elapsed = None
    while time.monotonic() - started < 4:
        try:
            if client.lookup("network") != old_id:
                elapsed = time.monotonic() - started
                break
        except (AssertionError, OSError):
            pass
        time.sleep(0.01)
    f.observations["reregister_seconds"] = elapsed
    f.check("delayed_reexec", elapsed is not None and 0.90 <= elapsed <= 2.5)
    f.check("same_pid_and_argv", f.subject.poll() is None and Path(f"/proc/{f.subject.pid}/cmdline").read_bytes() == before)
    f.check("fresh_objects", f.wait(lambda: f.ready("network.interface.r92")) and client.lookup("network") != old_id)
    f.check("serving", isinstance(f.call("network.interface.r92", "status"), dict))


def procd_bundle(f):
    # ujail is an execution-plane boundary: replace it ONLY in the disposable
    # image with an argv recorder. No container or host jail is created.
    jail = f.root / "sbin/ujail"
    if jail.is_symlink():
        jail.unlink()
    write(jail, "#!/bin/sh\nprintf '%s\\n' \"$@\" > /tmp/out/ujail-argv.tmp\nmv /tmp/out/ujail-argv.tmp /tmp/out/ujail-argv\necho $$ > /tmp/out/jail-pid\nexec sleep 30\n")
    jail.chmod(0o755)
    f.start_bus()
    f.start_subject("-S", "-I", "/tmp/initd", "-R", "/tmp/rcd", obj="service")
    for label, command in (("only", None), ("ignored", ["/bin/false"])):
        argv_path = f.output / "ujail-argv"
        argv_path.unlink(missing_ok=True)
        instance = {"bundle": "/tmp/bundle-r92", "jail": {"name": "r92"}}
        if command:
            instance["command"] = command
        f.call("service", "set", {"name": "r92-" + label, "instances": {"i": instance}})
        started = f.wait(argv_path.exists)
        f.check(f"bundle_{label}_spawn", started)
        argv = argv_path.read_text().splitlines() if started else []
        f.observations[f"argv_{label}"] = argv
        f.check(f"bundle_{label}_argv", argv, ["-t", "5", "-n", "r92", "-J", "/tmp/bundle-r92", "--"])
        status = f.call("service", "list", {"name": "r92-" + label})
        f.check(f"bundle_{label}_running", status.get("r92-" + label, {}).get("instances", {}).get("i", {}).get("running"), True)
    f.check("serving", f.subject.poll() is None and f.ready("service"))


GLOB_CASES = [
    (b"[", b"[", True), (b"[ab", b"[ab", True),
    (b"[]x]", b"]", True), (b"[]x]", b"x", True), (b"[]x]", b"y", False),
    (b"[!a]", b"b", True), (b"[!a]", b"a", False),
    (b"[^a]", b"b", True), (b"[[:digit:]]", b"5", True),
    (b"[[:digit:]]", b"x", False), (b"[[:alpha:]]", b"z", True),
    (b"\\*", b"*", False), (b"\\*", b"\\suffix", True),
    # Both daemons run fnmatch in the C locale: '?' consumes one byte here.
    (b"?", "é".encode(), False), (b"a?b", b"a/b", True),
    (b"a*b", b"a/path/b", True), (b"*", b"raw-\xff", True),
    (b"prefix\0ignored", b"prefix", True),
]


FEATURE_OUTPUTS = [
    (b"netifd-2024.12\n", False), (b"netifd-2025.00\n", True),
    (b"netifd-2099\n", True), (b"netifd-2100\n", False),
    (b"netifd-20xx\n", False), ("netifd-20中\n".encode(), False),
    (b"notice\nnetifd-2026\n", True), (b"netifd-2025tail\n", True),
    (b"", False), (b" netifd-2026\n", False), (b"netifd-202\n", False),
]


def rpcd_features(f):
    apk = f.root / "usr/bin/apk"
    f.observations["real_apk_sha256"] = digest(apk)
    actual = subprocess.run(["chroot", str(f.root), "/usr/bin/apk", "list", "-I", "netifd"], capture_output=True, timeout=5)
    (f.output / "real-apk.bin").write_bytes(actual.stdout)
    f.start_bus()
    f.start_subject(obj="luci")
    real = [f.call("luci", "getFeatures").get("netifd_vrf") for _ in range(12)]
    f.observations["real_probe_values"] = real
    # Original helper output may be interrupted by SIGCHLD. Retain the
    # observed misses; candidate must match the image's installed version.
    f.check("real_probe_responses", all(isinstance(v, bool) for v in real))
    if f.side != "original":
        f.check("real_probe_complete", real, [True] * 12)
    apk.rename(apk.with_name("apk.r92-real"))
    # The image BusyBox rejects fractional sleep; keep EOF separate from
    # SIGCHLD with a supported integer delay for these fixed parser inputs.
    write(apk, "#!/bin/sh\nif [ \"$*\" = 'list -I netifd' ]; then\n cat /tmp/apk-output\n exec 1>&-\n sleep 1\n exit 0\nfi\nexec /usr/bin/apk.r92-real \"$@\"\n")
    apk.chmod(0o755)
    for i, (output, expected) in enumerate(FEATURE_OUTPUTS):
        (f.root / "tmp/apk-output").write_bytes(output)
        f.check(f"version_{i}", f.call("luci", "getFeatures").get("netifd_vrf"), expected)
    f.check("serving", f.subject.poll() is None and f.ready("luci"))


def rpcd_compat(f):
    password = run("openssl", "passwd", "-6", "-salt", "r92fixture", "r92-pass", capture_output=True).stdout.decode().strip()
    write(f.root / "etc/config/rpcd", f"config login\n option username 'r92'\n option password '{password}'\n list read 'r92\\*'\nconfig login\n option username 'r92negative'\n option password '{password}'\n list read 'r92*'\n list read '!r92\\*'\n")
    write(f.root / "usr/share/rpcd/acl.d/r92.json", json.dumps({
        "r92*": {"read": {"ubus": {"r92.allowed": ["read"]}}},
        "r92X": {"read": {"ubus": {"r92.denied": ["read"]}}},
    }))
    # Invalid raw JSON string bytes are accepted by json-c but cannot become
    # candidate ACL identifiers. Verify whole-file rejection, not U+FFFD.
    (f.root / "usr/share/rpcd/acl.d/r92-invalid.json").write_bytes(b'{"r92*":{"read":{"ubus":{"r92.invalid":["\xff","valid"]}}}}')
    (f.root / "etc/config/r92bytes").write_bytes(b"config item 's'\n option scalar 'a\xff'\n list items 'b\xfe'\n list items 'c'\n")
    f.start_bus()
    f.start_subject(obj="session")
    client = f.connect()
    session = client.lookup("session")
    code, replies = client.invoke(session, "create")
    assert code == 0
    sid = response_data(replies)[0][b"ubus_rpc_session"]
    for i, (pattern, name, expected) in enumerate(GLOB_CASES):
        scope = string("scope", f"r92-{i}")
        args = string("ubus_rpc_session", sid) + scope
        pair = message("", 1, string("", pattern) + string("", "read"))
        grant, _ = client.invoke(session, "grant", args + message("objects", 1, pair))
        access, replies = client.invoke(session, "access", args + string("object", name) + string("function", "read"))
        f.check(f"glob_{i}", [grant, access, response_data(replies)[0].get(b"access")], [0, 0, int(expected)])
    for username, allowed in (("r92", True), ("r92negative", False)):
        login_code, login_replies = client.invoke(session, "login", string("username", username) + string("password", "r92-pass"))
        assert login_code == 0
        login = {"ubus_rpc_session": response_data(login_replies)[0][b"ubus_rpc_session"].decode("ascii")}
        for obj, want in (("r92.allowed", allowed), ("r92.denied", not allowed)):
            result = f.call("session", "access", {"ubus_rpc_session": login["ubus_rpc_session"], "scope": "ubus", "object": obj, "function": "read"})
            f.check(username + "_" + obj, result.get("access"), want)
        if allowed:
            login_sid = string("ubus_rpc_session", login["ubus_rpc_session"])
            _, listed = client.invoke(session, "list", login_sid)
            acl_wire = b"".join(v for _, _, data in listed for _, v in data)
            f.check("acl_file_invalid_bytes", b"\xff\0" in acl_wire, f.side == "original")
            f.check("acl_file_no_replacement", b"\xef\xbf\xbd" not in acl_wire)
            result = f.call("session", "access", {"ubus_rpc_session": login["ubus_rpc_session"], "scope": "ubus", "object": "r92.invalid", "function": "valid"})
            f.check("acl_file_whole_rejection", result.get("access"), f.side == "original")
    args = string("ubus_rpc_session", sid) + string("scope", "r92-invalid")
    pair = message("", 1, string("", "raw") + string("", b"\xff") + string("", "read"))
    code, _ = client.invoke(session, "grant", args + message("objects", 1, pair))
    assert code == 0
    _, replies = client.invoke(session, "access", args + string("object", "raw") + string("function", "read"))
    f.check("invalid_function_no_promotion", response_data(replies)[0].get(b"access"), 0)
    _, replies = client.invoke(session, "list", string("ubus_rpc_session", sid))
    raw_reply = b"".join(v for _, _, data in replies for _, v in data)
    f.check("invalid_function_disposition", b"\xff\0" in raw_reply, f.side == "original")
    valid_pair = message("", 1, string("", "raw") + string("", "read"))
    assert client.invoke(session, "grant", args + message("objects", 1, valid_pair))[0] == 0
    assert client.invoke(session, "revoke", args + message("objects", 1, pair))[0] == 0
    _, replies = client.invoke(session, "access", args + string("object", "raw") + string("function", "read"))
    f.check("invalid_revoke_no_promotion", response_data(replies)[0].get(b"access"), 1)
    assert client.invoke(session, "revoke", args + message("objects", 1, valid_pair))[0] == 0
    _, replies = client.invoke(session, "access", args + string("object", "raw") + string("function", "read"))
    f.check("valid_revoke", response_data(replies)[0].get(b"access"), 0)
    code, _ = client.invoke(session, "access", string("ubus_rpc_session", b"\xff"))
    f.check("invalid_sid_disposition", code, 4 if f.side == "original" else 2)
    uci = client.lookup("uci")
    for method in ("get", "state"):
        code, replies = client.invoke(uci, method, string("config", "r92bytes") + string("section", "s"))
        got = response_data(replies)[0][b"values"]
        f.check("uci_" + method + "_bytes", [code, got[b"scalar"].hex(), [v.hex() for v in got[b"items"]]], [0, b"a\xff".hex(), [b"b\xfe".hex(), b"c".hex()]])
    f.check("serving", f.subject.poll() is None and f.ready("session"))


def rpcd_lease_boundary(f):
    # DHCP client identifiers are bytes. A character spanning C's fixed
    # IAID/DUID split used to panic in Rust's string indexing.
    duid = b"ff:1234567890" + "中".encode() + b"tail"
    write(f.root / "etc/config/dhcp", "config dnsmasq\n option leasefile '/tmp/r92.leases'\n")
    (f.root / "tmp/r92.leases").write_bytes(b"0 02:00:00:00:00:92 192.0.2.92 r92 " + duid + b"\n")
    f.start_bus()
    f.start_subject(obj="luci-rpc")
    client = f.connect()
    obj = client.lookup("luci-rpc")
    code, replies = client.invoke(obj, "getDHCPLeases")
    data = response_data(replies)
    f.check("lease_reply", [code, len(data)], [0, 1])
    if data:
        lease = data[0][b"dhcp_leases"][0]
        convert = lambda v: v if f.side == "original" else v.decode(errors="replace").encode()
        for field, expected in ((b"iaid", duid[3:14]), (b"duid", duid[15:])):
            f.check(field.decode() + "_byte_boundary", lease[field].hex(), convert(expected).hex())
    f.check("duid_hints_after", client.invoke(obj, "getDUIDHints")[0], 0)
    f.check("serving", f.subject.poll() is None and f.ready("luci-rpc"))


def rpcd_plugin_boundaries(f):
    f.start_bus()
    f.start_subject(obj="iwinfo")
    client = f.connect()
    iw = client.lookup("iwinfo")
    for method in ("info", "scan", "assoclist", "freqlist", "txpowerlist", "countrylist", "survey"):
        f.check("iw_" + method + "_missing", client.invoke(iw, method)[0], 2)
        f.check("iw_" + method + "_absent", client.invoke(iw, method, string("device", "r92-none"))[0], 4)
    f.check("iw_phyname_missing", client.invoke(iw, "phyname")[0], 2)
    f.check("iw_phyname_absent", client.invoke(iw, "phyname", string("section", "r92-none"))[0], 4)
    f.check("iw_devices", client.invoke(iw, "devices")[0], 0)
    # devices closes the backend; one failed probe may lazily reopen it.
    assert client.invoke(iw, "info", string("device", "r92-none"))[0] == 4
    fd_count = lambda: len(list(Path(f"/proc/{f.subject.pid}/fd").iterdir()))
    before = fd_count()
    for _ in range(100):
        assert client.invoke(iw, "info", string("device", "r92-none"))[0] == 4
    f.check("iw_failed_open_fds", fd_count(), before)

    rr = client.lookup("network.rrdns")
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(2)
    port = peer.getsockname()[1]
    request = (message("addrs", 1, string("", "192.0.2.92")) + string("server", "127.0.0.1")
               + message("port", 6, struct.pack(">H", port)) + integer("timeout", 300))
    observed = []

    def respond(case):
        query, address = peer.recvfrom(512)
        observed.append(case)
        hdr = query[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
        rdata = b"\x04host\x03lan\0"
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 60, len(rdata)) + rdata
        packet = hdr + query[12:] + answer
        if case == "truncated":
            packet = packet[:-1]
        elif case == "bad_additional":
            packet = packet[:10] + b"\0\x01" + packet[12:] + b"\xc0\x0c\0\x01"
        elif case == "pointer_loop":
            offset = len(hdr + query[12:]) + 12
            packet = hdr + query[12:] + answer[:10] + b"\0\x02" + struct.pack(">H", 0xc000 | offset)
        elif case == "unknown_id_then_valid":
            peer.sendto(bytes([packet[0] ^ 0xff]) + packet[1:], address)
        elif case == "short_then_valid":
            peer.sendto(query[:2], address)
        peer.sendto(packet, address)

    try:
        for case in ("valid", "truncated", "bad_additional", "pointer_loop", "unknown_id_then_valid", "short_then_valid", "valid_after"):
            thread = threading.Thread(target=respond, args=(case,))
            thread.start()
            start = time.monotonic()
            code, replies = client.invoke(rr, "lookup", request)
            elapsed = time.monotonic() - start
            thread.join(timeout=2)
            data = response_data(replies)
            expected = {} if case in ("truncated", "bad_additional", "pointer_loop") else {b"192.0.2.92": b"host.lan"}
            f.check("rr_" + case, [code, data == [expected], elapsed < 1], [0, True, True])
        f.check("rr_fixture_received", len(observed), 7)
    finally:
        peer.close()
    f.check("serving", f.subject.poll() is None and f.ready("luci-rpc"))


CASES = {
    "rpcd_lease_boundary": ("rpcd", rpcd_lease_boundary, {"identity", "lease_reply", "iaid_byte_boundary", "duid_byte_boundary", "duid_hints_after", "serving"}),
    "rpcd_plugin_boundaries": ("rpcd", rpcd_plugin_boundaries, {"identity", "iw_failed_open_fds", "rr_fixture_received", "serving"} | {"rr_" + c for c in ("valid", "truncated", "bad_additional", "pointer_loop", "unknown_id_then_valid", "short_then_valid", "valid_after")}),
    "rpcd_features": ("rpcd", rpcd_features, {"identity", "real_probe_responses", "serving"} | {f"version_{i}" for i in range(len(FEATURE_OUTPUTS))}),
    "ubusd_acl_types": ("ubusd", ubusd_acl_types, {"identity", "private_tables_only", "private_table_bytes", "typed_methods_visibility", "serving"}),
    "uci_rename": ("uci", uci_rename, {label + "_" + what for label in ("section", "option") for what in ("raw_rename", "raw_delta", "no_replacement", "diagnostic", "config_untouched", "fresh_load")}),
    "ubusd_wire": ("ubusd", ubusd_wire, {"identity", "reused_type_reply", "padded_prefix", "event_first_fields", "event_send", "event_bytes_and_first_data", "event_wrong_object_type", "target_first_four", "target_unsubscribe", "target_short", "serving"} | {f"short_{what}_{n}" for what in ("top", "signature") for n in (1, 2, 3)}),
    "logd_bytes": ("logd", logd_bytes, {"identity", "datagram_bytes", "serving"} | {f"write_bytes_{i}" for i in range(5)}),
    "logd_limits": ("logd", logd_limits, {"identity", "first_64", "client_65", "capacity_recovers", "aggregate_bound", "aggregate_keeps_readers", "full_ring_allowed", "initial_backlog_bound", "existing_history_after_refusal", "bounded_oneshot", "oneshot_complete", "serving"}),
    "netifd_restart": ("netifd", netifd_restart, {"identity", "delayed_reexec", "same_pid_and_argv", "fresh_objects", "serving"}),
    "procd_bundle": ("procd", procd_bundle, {"identity", "serving"} | {f"bundle_{label}_{what}" for label in ("only", "ignored") for what in ("spawn", "argv", "running")}),
    "rpcd_compat": ("rpcd", rpcd_compat, {"identity", "serving", "acl_file_invalid_bytes", "acl_file_no_replacement", "acl_file_whole_rejection", "invalid_revoke_no_promotion", "valid_revoke", "invalid_function_no_promotion", "invalid_function_disposition", "invalid_sid_disposition", "uci_get_bytes", "uci_state_bytes"} | {f"glob_{i}" for i in range(len(GLOB_CASES))} | {user + "_" + obj for user in ("r92", "r92negative") for obj in ("r92.allowed", "r92.denied")}),
}
CASES.update(HTTP_CASES)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        root, side, case = Path(sys.argv[2]), sys.argv[3], sys.argv[4]
        f = Fixture(root, side, CASES[case][0])
        try:
            CASES[case][1](f)
        finally:
            write(f.output / "result.json", json.dumps({"checks": f.checks, "observations": f.observations}, indent=2) + "\n")
            f.close()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("bins", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--sides", nargs="+", choices=("original", "candidate"), default=("original", "candidate"))
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        parser.error("run as root on the Linux build host")
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    write(args.output / "probe.sha256", digest(Path(__file__)) + "\n")
    for side in args.sides:
        for case in args.cases:
            component = CASES[case][0]
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="r92-compat-") as temporary:
                root = Path(temporary) / "root"
                # Exact extracted root filesystems can contain device nodes;
                # copy them as nodes instead of opening them as regular files.
                subprocess.run(["cp", "-a", str(args.rootfs), str(root)], check=True)
                for directory in ("out", "run/ubus", "lock", "state", "initd", "rcd"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.bins / (component + "-rs"), root / "tmp" / (component + "-rs"))
                with (destination / "driver.log").open("wb") as log:
                    result = subprocess.run(["timeout", "-k", "3", "60", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case], stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            path = destination / "raw/result.json"
            data = json.loads(path.read_text()) if path.exists() else {"checks": {}, "observations": {}}
            passed = result.returncode == 0 and CASES[case][2] <= data["checks"].keys() and all(c["passed"] for c in data["checks"].values())
            rows.append({"side": side, "case": case, "exit": result.returncode, "passed": passed, **data})
            write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
            print(json.dumps({"side": side, "case": case, "exit": result.returncode, "passed": passed, "failed": [k for k, v in data["checks"].items() if not v["passed"]]}), flush=True)
    passed = len(rows) == len(args.sides) * len(args.cases) and all(row["passed"] for row in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
