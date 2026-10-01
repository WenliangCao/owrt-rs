#!/usr/bin/env python3
"""One isolated C/Rust check of foreground identity, capabilities and PID files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from dns_service_probe import name


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(binary, mode, out):
    out.mkdir()
    out.chmod(0o777)
    pid = out / "daemon.pid"
    sentinel = out / "sentinel"
    sentinel.write_text("preserve\n")
    if mode == "symlink":
        pid.symlink_to(sentinel)
    if mode == "debug":
        pid.write_text("untouched\n")
    if mode == "pid-error":
        pid = out / "missing/daemon.pid"
    user = "absent-dnsmasq-user" if mode == "unknown-user" else "dnsmasq"
    group = "absent-dnsmasq-group" if mode == "unknown-group" else "dnsmasq"
    config = out / "dnsmasq.conf"
    config.write_text("no-resolv\nno-hosts\nport=15353\nlisten-address=127.0.0.1\n"
                      "host-record=identity.test,192.0.2.7\nno-ping\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,600s\n"
                      f"dhcp-leasefile={out / 'leases'}\nuser={user}\ngroup={group}\n")
    command = [str(binary), "-d" if mode == "debug" else "-k", "-C", str(config), "-x", str(pid)]
    record = {"command": command}
    with (out / "stdout").open("wb") as stdout, (out / "stderr").open("wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(0.1)
        query = bytes.fromhex("123401000001000000000000") + name("identity.test") + bytes.fromhex("00010001")
        try:
            if mode in ("unknown-user", "unknown-group", "pid-error"):
                record["exit"] = process.wait(timeout=5)
                record["pid_exists"] = pid.exists()
            else:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"startup exited {process.returncode}")
                    client.sendto(query, ("127.0.0.1", 15353))
                    try:
                        packet = client.recv(4096)
                        break
                    except socket.timeout:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("DNS readiness timeout")
                (out / "reply.hex").write_text(packet.hex() + "\n")
                assert packet[:2] == query[:2] and packet[-4:] == bytes([192, 0, 2, 7])
                status = Path(f"/proc/{process.pid}/status").read_text()
                (out / "proc-status").write_text(status)
                fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                record["identity"] = {key: fields[key].split() for key in ("Uid", "Gid", "Groups", "CapEff", "CapPrm")}
                if mode == "debug":
                    record["pid_untouched"] = pid.read_text() == "untouched\n"
                else:
                    stat = pid.stat()
                    record["pid"] = {"matches_process": pid.read_text() == f"{process.pid}\n",
                                     "owner": [stat.st_uid, stat.st_gid], "mode": stat.st_mode & 0o777,
                                     "symlink": pid.is_symlink()}
                record["sentinel_unchanged"] = sentinel.read_text() == "preserve\n"
                process.send_signal(signal.SIGTERM)
                record["exit"] = process.wait(timeout=5)
                record["pid_exists_after_exit"] = pid.exists()
        except Exception as error:
            record["failure"] = repr(error)
        finally:
            client.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return {key: value for key, value in record.items() if key != "command"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert [label for _, label in socket.if_nameindex()] == ["lo"]
    args.out = args.out.resolve()
    assert "private" in args.out.parts
    args.out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "identity-check", "/etc"], check=True)
    Path("/etc/passwd").write_text("root:x:0:0:root:/:/bin/false\ndnsmasq:x:453:453:dnsmasq:/:/bin/false\n")
    Path("/etc/group").write_text("root:x:0:\ndnsmasq:x:453:\n")
    Path("/etc/nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")
    result = {"c_sha256": sha(args.c), "rust_sha256": sha(args.rust), "cases": [], "failures": []}
    for mode in ("foreground", "debug", "symlink", "unknown-user", "unknown-group", "pid-error"):
        folder = args.out / mode
        folder.mkdir()
        expected = run(args.c, mode, folder / "c")
        actual = run(args.rust, mode, folder / "rust")
        row = {"case": mode, "c": expected, "rust": actual}
        result["cases"].append(row)
        if "failure" in expected or "failure" in actual or expected != actual:
            result["failures"].append(row)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(result["cases"]), "failures": result["failures"]}))
    return bool(result["failures"])


if __name__ == "__main__":
    raise SystemExit(main())
