#!/usr/bin/env python3
"""Exercise real PID 1 startup in disposable Linux pid/mount/net namespaces.

Requires root, the matching stock rootfs, and a static candidate procd binary.
Never runs procd in the host PID namespace or accesses a router.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from r92_recovery_probe import Bus, attr


def restored_watch(root, path):
    """A newly published object must be watched and its event must run a trigger."""
    config = {"name": "v030watch", "triggers": [["v030.changed", [[
        "run_script", "/bin/sh", "-c", "echo observed > /tmp/watch-triggered"
    ]]]], "instances": {"main": {"command": ["/bin/sleep", "60"],
                                      "watch": ["v030.late"]}}}
    subprocess.run(["chroot", str(root), "/bin/ubus", "-t", "3", "call", "service", "set",
                    json.dumps(config)], check=True, capture_output=True, timeout=4)
    provider = Bus(path)
    try:
        target = provider.add("v030.late")
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            seq = provider.send(10, attr(3, struct.pack(">I", target))
                                + attr(4, b"v030.changed\0") + attr(7, b""))
            while True:
                kind, received, _, fields = provider.recv()
                if kind == 1 and received == seq:
                    attached = bool(dict(fields).get(11))
                    break
            if attached:
                while time.monotonic() < deadline:
                    if (root / "tmp/watch-triggered").exists():
                        return True
                    time.sleep(0.02)
                return False
            time.sleep(0.02)
        return False
    finally:
        provider.sock.close()


def stop(process):
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=5)


def receive_frame(connection):
    data = bytearray()
    while len(data) < 12:
        part = connection.recv(12 - len(data))
        if not part:
            raise EOFError("registration peer closed")
        data.extend(part)
    size = 8 + (struct.unpack_from(">I", data, 8)[0] & 0xFFFFFF)
    assert 12 <= size <= 1048584
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise EOFError("partial registration frame")
        data.extend(part)
    return data


def send_frame(connection, kind, sequence, fields):
    connection.sendall(struct.pack(">BBHII", 0, kind, sequence, 0, len(fields) + 4) + fields)


def run_case(rootfs, candidate, output, side, fail_at, empty_respawn=False):
    # Keep the filesystem socket pathname below sockaddr_un's 108-byte limit.
    with tempfile.TemporaryDirectory(prefix="v030-pid1-") as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(rootfs, root, symlinks=True)
        (root / "tmp/run/ubus").mkdir(parents=True, exist_ok=True)
        (root / "proc").mkdir(exist_ok=True)
        (root / "dev").mkdir(exist_ok=True)
        shutil.copy2(root / "sbin/ubusd", root / "tmp/ubusd-real")
        if side == "rust":
            shutil.copy2(candidate, root / "sbin/procd")
        # No host uevents, real watchdog, kernel log, or production init scripts.
        (root / "etc/hotplug.json").write_text("[]\n")
        shutil.rmtree(root / "etc/hotplug.d")
        (root / "etc/hotplug.d").mkdir()
        (root / "sbin/udevtrigger").write_text("#!/bin/sh\nexit 0\n")
        (root / "sbin/udevtrigger").chmod(0o755)
        (root / "sbin/ubusd").write_text("#!/bin/sh\nexec sleep 300\n")
        (root / "sbin/ubusd").chmod(0o755)
        inittab = "::sysinit:/etc/init.d/rcS S boot\n"
        if empty_respawn:
            inittab = "null::respawn:\n" + inittab
        (root / "etc/inittab").write_text(inittab)
        shutil.rmtree(root / "etc/rc.d")
        (root / "etc/rc.d").mkdir()
        probe = root / "etc/rc.d/S10probe"
        probe.write_text("#!/bin/sh\ntouch /tmp/boot-ready\n")
        probe.chmod(0o755)
        path = root / "tmp/run/ubus/ubus.sock"
        listener = None
        if fail_at > 0:
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path))
            listener.listen(4)
            listener.settimeout(8)
            path.chmod(0o666)
        elif fail_at == 0:
            (root / "sbin/ubusd").unlink()
        else:
            shutil.copy2(root / "tmp/ubusd-real", root / "sbin/ubusd")
        command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                   "/bin/sh", "-c", '''
set -eu
mount --make-rprivate /
mount -t proc proc "$1/proc"
mount -t tmpfs tmpfs "$1/dev"
mknod -m 666 "$1/dev/null" c 1 3
mknod -m 666 "$1/dev/zero" c 1 5
mknod -m 666 "$1/dev/urandom" c 1 9
exec chroot "$1" /sbin/procd -S
''', "sh", str(root)]
        daemon = bus = None
        observed = {"side": side, "fail_at": fail_at, "empty_respawn": empty_respawn}
        with (output / f"{side}-pid1.log").open("w") as log, \
                (output / f"{side}-ubusd.log").open("w") as bus_log:
            try:
                daemon = subprocess.Popen(command, stdout=log, stderr=log,
                                          env={**os.environ, "container": "1"})
                if fail_at == 0:
                    # No process exists to reap after Rust's failed exec.
                    # Restore the dependency without signaling PID 1.
                    time.sleep(1.2)
                    shutil.copy2(root / "tmp/ubusd-real", root / "sbin/ubusd")
                elif fail_at > 0:
                    inject_registration_failure(listener, fail_at, observed)
                    listener.close()
                    path.unlink(missing_ok=True)
                    bus = subprocess.Popen(["chroot", str(root), "/tmp/ubusd-real"],
                                           stdout=bus_log, stderr=bus_log)
                deadline = time.monotonic() + 8
                observed["service_registered"] = False
                while time.monotonic() < deadline and daemon.poll() is None:
                    if (root / "tmp/boot-ready").exists():
                        lookup = subprocess.run(["chroot", str(root), "/bin/ubus", "-t", "1",
                                                 "list", "service"], capture_output=True, timeout=2)
                        if lookup.returncode == 0 and lookup.stdout.strip() == b"service":
                            observed["service_registered"] = True
                            break
                    time.sleep(0.02)
                observed["pid1_alive"] = daemon.poll() is None
                observed["exit_code"] = daemon.poll()
                observed["sysinit_reached"] = (root / "tmp/boot-ready").exists()
                observed["healthy_bus_alive"] = bus.poll() is None if bus else path.exists()
                observed["core_objects"] = []
                observed["watch_triggered"] = False
                if observed["pid1_alive"] and observed["service_registered"]:
                    lookup = subprocess.run(["chroot", str(root), "/bin/ubus", "-t", "1", "list"],
                                            check=True, capture_output=True, timeout=2)
                    observed["core_objects"] = sorted(set(lookup.stdout.decode().splitlines())
                                                       & {"service", "system", "container"})
                    if side == "rust":
                        observed["watch_triggered"] = restored_watch(root, path)
            finally:
                if listener:
                    listener.close()
                stop(daemon)
                stop(bus)
        return observed


def inject_registration_failure(listener, fail_at, observed):
    with listener.accept()[0] as connection:
        connection.settimeout(4)
        connection.sendall(struct.pack(">BBHII", 0, 0, 0, 1025, 4))
        observed["request_types"] = []
        for index in range(1, fail_at + 1):
            request = receive_frame(connection)
            kind = request[1]
            observed["request_types"].append(kind)
            if index == fail_at:
                break
            sequence = struct.unpack_from(">H", request, 2)[0]
            if kind == 6:
                fields = struct.pack(">IIII", 0x03000008, 2000 + index,
                                     0x05000008, 3000 + index)
                send_frame(connection, 2, sequence, fields)
            send_frame(connection, 1, sequence, struct.pack(">II", 0x01000008, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fail-at", type=int, choices=range(-1, 7), default=1,
                        help="registration request to disconnect; 0 tests a late ubusd executable; -1 is healthy")
    parser.add_argument("--empty-respawn", action="store_true",
                        help="include an inittab respawn entry with an empty command")
    parser.add_argument("--sides", nargs="+", choices=("c", "rust"), default=["c", "rust"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root required for disposable namespaces")
    args.output.mkdir(parents=True, exist_ok=True)
    results = [run_case(args.rootfs, args.candidate, args.output, side, args.fail_at, args.empty_respawn)
               for side in args.sides]
    (args.output / "result.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    # The exact C reference survives and reaches sysinit, but does not restore
    # an object whose first registration failed. Record that limitation rather
    # than treating it as the desired Rust recovery behavior.
    assert all(r["pid1_alive"] and r["sysinit_reached"] and r["healthy_bus_alive"]
               and (r["side"] == "c" and r["fail_at"] != 0 or r["service_registered"])
               and (r["side"] == "c" or r["core_objects"] == ["container", "service", "system"]
                    and r["watch_triggered"])
               for r in results), "PID 1 did not recover from startup bus loss"


if __name__ == "__main__":
    main()
