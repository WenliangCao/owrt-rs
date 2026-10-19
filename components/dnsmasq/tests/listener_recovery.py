#!/usr/bin/env python3
"""Run with sudo unshare -n env DNSMASQ_TEST_ISOLATED=1 python3 ... BINARY.

Exercise the real bind-dynamic owner with each DNS protocol temporarily busy.
Only the isolated namespace and a temporary directory are modified.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

ADDRESS = "192.0.2.1"
PORT = 15353
QUERY = (struct.pack("!HHHHHH", 0xDEAD, 0x100, 1, 0, 0, 0)
         + b"\x05probe\x04test\x00" + struct.pack("!HH", 1, 1))


def ip(*args):
    subprocess.run(["ip", *args], check=True, stdout=subprocess.DEVNULL)


def ask(tcp):
    try:
        kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as client:
            client.settimeout(0.2)
            if tcp:
                client.connect((ADDRESS, PORT))
                client.sendall(struct.pack("!H", len(QUERY)) + QUERY)
                header = client.recv(2)
                if len(header) != 2:
                    return False
                length = struct.unpack("!H", header)[0]
                data = b""
                while len(data) < length:
                    part = client.recv(length - len(data))
                    if not part:
                        return False
                    data += part
            else:
                client.sendto(QUERY, (ADDRESS, PORT))
                data = client.recv(4096)
            return (len(data) >= 12 and data[:2] == QUERY[:2]
                    and data[3] & 15 == 0
                    and struct.unpack("!H", data[6:8])[0] == 1
                    and data[-4:] == socket.inet_aton("192.0.2.42"))
    except OSError:
        return False


def wait_answer(tcp, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if ask(tcp):
            return True
        time.sleep(0.05)
    return False


def sockets(pid):
    # Ignore short-lived accepted TCP clients; compare the actual listener inodes.
    listeners = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        for line in Path(f"/proc/{pid}/net/{name}").read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[1].split(":")[1], 16) == PORT and (
                name.startswith("udp") or fields[3] == "0A"
            ):
                listeners.add(f"socket:[{fields[9]}]")
    owned = {os.readlink(fd) for fd in Path(f"/proc/{pid}/fd").iterdir()}
    return owned & listeners


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run(binary, tcp):
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, kind) as blocker:
        config = Path(directory) / "dnsmasq.conf"
        config.write_text(
            f"port={PORT}\nbind-dynamic\ninterface=dummy0\nno-resolv\nno-hosts\n"
            f"address=/probe.test/192.0.2.42\nuser=root\npid-file={directory}/pid\n")
        # Bind only the future address; wildcard bind would also break startup's loopback.
        blocker.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND
        blocker.bind((ADDRESS, PORT))
        if tcp:
            blocker.listen(4)
        with (Path(directory) / "stderr").open("w+") as log:
            process = subprocess.Popen([binary, "-k", "-C", str(config)],
                                       stderr=log, stdout=subprocess.DEVNULL)
            try:
                time.sleep(0.4)
                assert process.poll() is None, "dnsmasq failed before address addition"
                ip("addr", "add", ADDRESS + "/24", "dev", "dummy0")
                assert wait_answer(not tcp), "healthy protocol did not start"
                retained = sockets(process.pid)
                # Cross two retry deadlines while the conflicting socket remains held.
                time.sleep(2.2)
                assert ask(not tcp), "healthy protocol stopped during retries"
                assert sockets(process.pid) == retained, "retry replaced or leaked healthy sockets"
                ip("addr", "del", ADDRESS + "/24", "dev", "dummy0")
                time.sleep(1.2)
                assert len(sockets(process.pid)) == len(retained) - 1, "failed address was not retired"
                ip("addr", "add", ADDRESS + "/24", "dev", "dummy0")
                assert wait_answer(not tcp), "healthy protocol did not return after address re-add"
                retained = sockets(process.pid)
                blocker.close()
                assert wait_answer(tcp), "missing DNS protocol did not recover after bind failure"
                recovered = sockets(process.pid)
                assert retained < recovered and len(recovered - retained) == 1
                time.sleep(1.2)
                assert ask(tcp) and ask(not tcp)
                assert sockets(process.pid) == recovered, "healthy listeners were recreated"
                ip("addr", "del", ADDRESS + "/24", "dev", "dummy0")
                time.sleep(1.2)
                assert len(sockets(process.pid)) == len(retained) - 1, "retired address retained sockets"
                # Re-add without a blocker: the same process must restore both protocols.
                ip("addr", "add", ADDRESS + "/24", "dev", "dummy0")
                assert wait_answer(tcp) and wait_answer(not tcp)
                print(json.dumps({"blocked": "tcp" if tcp else "udp", "recovered": True,
                                  "preserved_healthy_sockets": True, "retired_and_readded": True}))
            finally:
                stop(process)
                log.seek(0)
                print(log.read(), file=sys.stderr)
                ip("addr", "flush", "dev", "dummy0")


def main():
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1", \
        "run in an isolated root network namespace"
    binary = str(Path(sys.argv[1]).resolve())
    ip("link", "set", "lo", "up")
    ip("link", "add", "dummy0", "type", "dummy")
    ip("link", "set", "dummy0", "up")
    for tcp in (True, False):
        run(binary, tcp)


if __name__ == "__main__":
    main()
