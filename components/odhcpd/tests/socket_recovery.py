#!/usr/bin/env python3
"""Real socket recovery test; run only in a new Linux network namespace.

sudo unshare --net env ODHCPD_TEST_ISOLATED=1 \
    python3 components/odhcpd/tests/socket_recovery.py /path/to/odhcpd-rs
"""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def socket_inodes(pid):
    result = set()
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = entry.readlink().as_posix()
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            result.add(target)
    return result


def reply(client):
    # A unicast Request must get UseMulticast even without a current binding.
    query = bytes.fromhex("030102030001000a00030001020304050607")
    client.sendto(query, ("fd00:30::1", 547))
    try:
        packet, _ = client.recvfrom(8192)
    except TimeoutError:
        return None
    assert packet[:4] == bytes.fromhex("07010203"), packet.hex()
    assert packet.endswith(bytes.fromhex("000d00020005")), packet.hex()
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert os.environ.get("ODHCPD_TEST_ISOLATED") == "1"
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    binary = args.binary.resolve(strict=True)
    for command in [
        ["ip", "link", "set", "lo", "up"],
        ["ip", "link", "add", "retry0", "type", "dummy"],
        ["ip", "link", "set", "retry0", "up"],
        ["ip", "-6", "addr", "add", "fd00:30::1/64", "dev", "retry0", "nodad"],
        ["ip", "-6", "addr", "add", "fd00:30::2/64", "dev", "retry0", "nodad"],
        ["ip", "-6", "addr", "add", "fe80::1/64", "dev", "retry0", "nodad"],
    ]:
        subprocess.run(command, check=True)
    with tempfile.TemporaryDirectory(prefix="odhcpd-socket-recovery-") as name:
        directory = Path(name)
        (directory / "dhcp").write_text(
            "config dhcp 'lan'\n option interface 'lan'\n option ifname 'retry0'\n"
            " option dhcpv6 'server'\n option ra 'server'\n"
        )
        (directory / "network").write_text("")
        (directory / "system").write_text("")
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as blocker, \
                socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client, \
                (directory / "stderr").open("w+") as log:
            blocker.bind(("::", 547))
            client.bind(("fd00:30::2", 546))
            client.settimeout(0.2)
            process = subprocess.Popen(
                [str(binary), "-u", "-f", "-c", name], stderr=log
            )
            try:
                # Hold the conflict across multiple retry deadlines. The RA
                # socket must remain alive throughout the DHCPv6-only failure.
                time.sleep(2.2)
                assert process.poll() is None, "daemon exited on local bind failure"
                log.seek(0)
                errors = log.read()
                assert "DHCPv6 socket:" in errors, errors
                assert "RA socket:" not in errors, errors
                assert errors.count("DHCPv6 socket:") == 1, errors
                before = socket_inodes(process.pid)
                assert len(before) >= 3, "kernel event/command and RA sockets must exist"
                blocker.close()
                deadline = time.monotonic() + 3
                while reply(client) is None:
                    assert process.poll() is None, "daemon exited during recovery"
                    assert time.monotonic() < deadline, (
                        "DHCPv6 never recovered after UDP/547 was released; no HUP sent"
                    )
                after = socket_inodes(process.pid)
                assert before < after, "retry replaced a healthy socket instead of adding DHCPv6"
                time.sleep(1.2)
                assert socket_inodes(process.pid) == after, "healthy sockets were reopened"
                assert reply(client) is not None, "service stopped after retry completed"
                print("PASS: autonomous DHCPv6 recovery, healthy RA/socket identity retained")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
