#!/usr/bin/env python3
"""Measure full logread correctness/RSS for C and Rust with identical input.

Linux root only. Each trial owns a copied native rootfs, minimal /dev and a
private mount namespace. /proc/kmsg is replaced by an empty regular file before
either daemon starts; no host or device kernel log is consumed. Message input
is a private JSON array of base64 strings. Outputs and failed trials are kept.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import time
import traceback


ENTER = r'''#!/bin/sh
set -eu
root=$1
size=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount --bind "$root/tmp/empty-kmsg" "$root/proc/kmsg"
stat -c '%F %s' "$root/proc/kmsg" >"$root/tmp/probe/kmsg-fixture.txt"
u=
l=
cleanup() {
    [ -z "$l" ] || kill "$l" 2>/dev/null || true
    [ -z "$u" ] || kill "$u" 2>/dev/null || true
    wait 2>/dev/null || true
    umount "$root/proc/kmsg" "$root/proc"
}
trap cleanup EXIT
trap 'exit 143' INT TERM
chroot "$root" /usr/libexec/owrt-stock/sbin/ubusd >"$root/tmp/probe/ubusd.log" 2>&1 & u=$!
# Wait until ubusd has loaded ACLs and serves requests before opening /dev/log.
# Otherwise C captures ubusd startup messages and Rust may race its socket.
until chroot "$root" /bin/ubus -t 1 list >/dev/null 2>&1; do sleep 0.02; done
chroot "$root" /tmp/logd-under-test -S "$size" >"$root/tmp/probe/logd.log" 2>&1 & l=$!
printf '%s\n' "$l" >"$root/tmp/probe/logd.pid"
while [ ! -f "$root/tmp/probe/stop" ]; do sleep 0.1; done
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def status(pid):
    wanted = {"VmRSS", "VmHWM", "VmSize"}
    return {key: int(value.split()[0]) for key, value in
            (line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
             if ":" in line) if key in wanted}


def normalized(data):
    lines = data.splitlines(keepends=True)
    records = []
    for line in lines:
        match = re.fullmatch(rb"[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] [0-9:]{8} [0-9]{4} [a-z0-9]+\.[a-z0-9]+ (.*)\n", line)
        assert match, "invalid or truncated logread line"
        records.append(match[1])
    return records


def trial(source, binary, messages, size, out):
    out.mkdir()
    root = out / "root"
    subprocess.run(["cp", "-a", source, root], check=True)
    shutil.rmtree(root / "dev")
    (root / "dev").mkdir()
    for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
        os.mknod(root / "dev" / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
    probe = root / "tmp/probe"
    probe.mkdir(parents=True)
    (root / "tmp/run/ubus").mkdir(parents=True, exist_ok=True)
    (root / "tmp/empty-kmsg").touch()
    shutil.copy2(binary, root / "tmp/logd-under-test")
    (root / "tmp/logd-under-test").chmod(0o755)
    script = out / "enter.sh"
    script.write_text(ENTER)
    log = (out / "namespace.log").open("wb")
    process = subprocess.Popen(["unshare", "--mount", "--fork", "/bin/sh", script, root, str(size)],
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, "namespace exited before readiness"
            if (probe / "logd.pid").exists() and (root / "dev/log").is_socket():
                lookup = subprocess.run(["chroot", root, "/bin/ubus", "-t", "1", "list", "log"], capture_output=True)
                (out / "ready-last.stdout").write_bytes(lookup.stdout)
                (out / "ready-last.stderr").write_bytes(lookup.stderr)
                if lookup.returncode == 0 and lookup.stdout.strip() == b"log":
                    break
            assert time.monotonic() < deadline, "log object never became ready"
            time.sleep(0.02)
        pid = int((probe / "logd.pid").read_text())
        initial = status(pid)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
            sender.settimeout(10)
            sender.connect(str(root / "dev/log"))
            for message in messages:
                assert len(message) <= 1000 and b"\0" not in message and b"\n" not in message
                # Supply a real syslog timestamp field: C strips byte 15 being
                # a space, even when a message only happens to look that way.
                sender.send(b"<13>Jan  1 00:00:00 " + message)
        deadline = time.monotonic() + 10
        while True:
            tail = subprocess.run(["chroot", root, "/bin/ubus", "-t", "1", "-S", "call", "log", "read",
                                   '{"lines":1,"stream":false}'], capture_output=True)
            if tail.returncode == 0:
                records = json.loads(tail.stdout).get("log", [])
                if records and records[-1]["msg"].encode() == messages[-1]:
                    break
            assert time.monotonic() < deadline, "final input marker never reached the ring"
            time.sleep(0.02)
        filled = status(pid)
        start = time.perf_counter_ns()
        timed_out = False
        try:
            read = subprocess.run(["chroot", root, "/sbin/logread"], capture_output=True, timeout=5)
            stdout, stderr, exit_code = read.stdout, read.stderr, read.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, exit_code = error.stdout or b"", error.stderr or b"", 124
            timed_out = True
        elapsed = time.perf_counter_ns() - start
        (out / "logread.stdout").write_bytes(stdout)
        (out / "logread.stderr").write_bytes(stderr)
        observed = normalized(stdout)
        after_read = status(pid)
        result = {"binary_sha256": sha(binary), "input_records": len(messages),
                  "retained_records": len(observed), "full_input_retained": observed == messages,
                  "oldest_marker_retained": bool(observed) and observed[0] == messages[0],
                  "logread_exit": exit_code, "logread_timeout": timed_out, "logread_nanoseconds": elapsed,
                  "logread_bytes": len(stdout), "message_sha256": hashlib.sha256(b"\n".join(observed)).hexdigest(),
                  "rss_kib": {"initial": initial, "filled": filled, "after_read": after_read},
                  "size_kib": size, "physical_router_accessed": False, "real_kmsg_read": False}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result, observed
    finally:
        (probe / "stop").touch()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--size-kib", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect", choices=("red", "green"), required=True)
    parser.add_argument("--allow-eviction", action="store_true")
    args = parser.parse_args()
    assert platform.system() == "Linux" and platform.machine() == "aarch64" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    os.umask(0o022)
    source, candidate, out = args.rootfs.resolve(), args.candidate.resolve(), args.output.resolve()
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    messages = [base64.b64decode(value) for value in json.loads(args.messages.read_text())["messages_b64"]]
    reference = source / "usr/libexec/owrt-stock/sbin/logd"
    result = {"passed": False, "expected": args.expect, "messages_sha256": sha(args.messages),
              "tool_sha256": sha(Path(__file__)), "source_release_sha256": sha(source / "usr/share/owrt-control-plane/release.json"),
              "logread_sha256": sha(source / "usr/libexec/logread-ubox"), "rounds": []}
    try:
        for repeat in range(1, 5):
            runs, contents = {}, {}
            for side, binary in (("c", reference), ("rust", candidate)):
                runs[side], contents[side] = trial(source, binary, messages, args.size_kib, out / f"{side}-{repeat}")
            assert runs["c"]["logread_exit"] == 0
            if not args.allow_eviction:
                assert contents["c"] == messages, "C did not retain the complete replay"
            equal = contents["c"] == contents["rust"]
            if args.expect == "green":
                assert equal and runs["rust"]["logread_exit"] == 0
            else:
                assert not equal and not runs["rust"]["full_input_retained"]
            result["rounds"].append({"repeat": repeat, "c_rust_equal": equal, **runs})
            (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result["rounds"][-1]), flush=True)
        result["passed"] = True
    except Exception:
        result["error"] = traceback.format_exc()
        raise
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
