#!/usr/bin/env python3
"""Independent hosts-file memory boundary comparison; isolated Linux only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import socket
import struct
import subprocess
import time


def query():
    packet = struct.pack("!6H", 0x1234, 0x100, 1, 0, 0, 0)
    packet += b"\x05audit\x04test\0" + struct.pack("!2H", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.15)
        sock.sendto(packet, ("127.0.0.1", 15353))
        try:
            answer = sock.recv(4096)
        except socket.timeout:
            return {"received": False, "expected_a": False}
    return {"received": True, "expected_a": answer.endswith(bytes([192, 0, 2, 1])),
            "rcode": answer[3] & 15, "answers": struct.unpack_from("!H", answer, 6)[0]}


def proc_memory(pid):
    try:
        fields = {}
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("VmHWM:", "VmRSS:", "VmPeak:")):
                key, value, _ = line.split()
                fields[key.rstrip(":") + "_kib"] = int(value)
        return fields
    except FileNotFoundError:
        return {}


def write_hosts(path, size_mib):
    with path.open("wb") as stream:
        stream.write(b"192.0.2.1 audit.test\n")
        # Ordinary short comment lines: parsing needs no large token buffer.
        block = (b"#" + b"x" * 126 + b"\n") * 8192
        for _ in range(size_mib):
            stream.write(block)


def run_case(label, command, out, limit_mib, reload):
    directory = out / f"{label}-limit{limit_mib}-{'reload' if reload else 'startup'}"
    directory.mkdir()
    hosts = directory / "hosts"
    write_hosts(hosts, 0 if reload else 48)
    log = directory / "daemon.log"
    argv = command + ["-C", "/dev/null", "-k", "--user=root", "--group=root",
                      "--port=15353", "--no-resolv", "--no-hosts",
                      "--listen-address=127.0.0.1", "--bind-interfaces",
                      f"--addn-hosts={hosts}", "--pid-file=", "--log-facility=-"]

    def set_limit():
        if limit_mib:
            resource.setrlimit(resource.RLIMIT_AS, (limit_mib * 1048576,) * 2)

    with log.open("wb") as stream:
        proc = subprocess.Popen(argv, stdout=stream, stderr=stream, preexec_fn=set_limit)
        try:
            before = None
            deadline = time.monotonic() + 15
            while proc.poll() is None and time.monotonic() < deadline:
                before = query()
                if before["received"]:
                    break
            if not before or not before["received"]:
                raise RuntimeError(f"startup did not answer: {log.read_text()}")
            if reload:
                if not before["expected_a"]:
                    raise RuntimeError("small-file control failed")
                write_hosts(hosts, 48)
                proc.send_signal(signal.SIGHUP)
                time.sleep(2)
            after = query()
            memory = proc_memory(proc.pid)
            status = proc.poll()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    text = log.read_text(errors="replace").replace(str(directory), "<case>")
    return {"implementation": label, "address_space_limit_mib": limit_mib,
            "reload": reload, "hosts_bytes": hosts.stat().st_size,
            "before": before, "after": after, "memory": memory,
            "exit_before_cleanup": status, "cleanup_exit": proc.returncode,
            "log": text}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run through tools/dnsmasq/run_isolated.sh")
    args.out.mkdir(parents=True, exist_ok=False)
    root = args.image_root
    c_binary = root / "usr/sbin/dnsmasq"
    implementations = [("c-image", [str(root / "lib/libc.so"), "--library-path",
                        f"{root}/lib:{root}/usr/lib", str(c_binary)]),
                       ("rust", [str(args.rust)])]
    rows = [run_case(label, command, args.out, limit, reload)
            for limit, reload in ((0, False), (32, False), (32, True))
            for label, command in implementations]
    result = {"isolated": True, "synthetic_input": "one valid host plus 48 MiB of short comments",
              "binary_sha256": {"c-image": hashlib.sha256(c_binary.read_bytes()).hexdigest(),
                                "rust": hashlib.sha256(args.rust.read_bytes()).hexdigest()},
              "cases": rows}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
