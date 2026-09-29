#!/usr/bin/env python3
"""Linux build-host tests in a new network namespace; never run on OpenWrt."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def packets(path):
    data = path.read_bytes()
    assert struct.unpack_from("<IHH", data) == (0xA1B2C3D4, 2, 4)
    offset = 24
    result = []
    while offset < len(data):
        _, _, captured, original = struct.unpack_from("<IIII", data, offset)
        assert captured <= original and captured <= 1536
        offset += 16
        assert offset + captured <= len(data)
        result.append(data[offset:offset + captured])
        offset += captured
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("helper", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--inside", action="store_true")
    args = p.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists(), "build host only"
    helper = args.helper.resolve()
    output = args.output.resolve()
    if not args.inside:
        subprocess.run(["unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                        str(helper), str(output), "--inside"], check=True)
        return
    assert {name for _, name in socket.if_nameindex()} == {"lo"}, "requires a fresh, empty netns"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    child_pid = output / "child.pid"
    before = time.monotonic()
    timeout = subprocess.run([str(helper), "bounded", "1", "/bin/sh", "-c",
                              'sleep 30 & echo "$!" > "$1"; wait', "sh", str(child_pid)])
    assert timeout.returncode == 124 and time.monotonic() - before < 4
    proc = Path("/proc") / child_pid.read_text().strip() / "stat"
    assert not proc.exists() or proc.read_text().split(")", 1)[1].split()[0] == "Z"
    assert subprocess.run([str(helper), "bounded", "2", "/bin/sh", "-c", "exit 7"]).returncode == 7
    big = output / "bounded-output.txt"
    with big.open("wb") as stream:
        capped = subprocess.run([str(helper), "bounded", "2", "head", "-c", "200000", "/dev/zero"], stdout=stream)
    assert capped.returncode != 0 and big.stat().st_size <= 65536

    capture = output / "capture"
    capture.mkdir()
    recorder = subprocess.Popen([str(helper), "events", str(capture), "wan", "0"])
    try:
        time.sleep(0.5)
        assert recorder.poll() is None
        run("ip", "link", "add", "wan", "address", "02:00:00:00:00:01", "type", "veth", "peer", "name", "peer")
        run("ip", "link", "set", "wan", "up")
        run("ip", "link", "set", "peer", "up")
        run("ip", "address", "add", "198.18.0.1/24", "dev", "wan")
        run("ip", "route", "add", "default", "via", "198.18.0.2", "dev", "wan")
        time.sleep(1.5)
        eth = bytes.fromhex("ffffffffffff0200000000010800")
        def udp4(port, payload):
            udp = struct.pack("!HHHH", 68, port, 8 + len(payload), 0) + payload
            if port == 53:
                udp = struct.pack("!HHHH", 12345, port, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                             b"\0" * 4, b"\xff" * 4)
            return eth + ip + udp
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sender:
            sender.bind(("peer", 0))
            sender.send(udp4(67, b"DHCP_TEST_RECORD"))
            sender.send(udp4(53, b"ORDINARY_DNS_MUST_NOT_BE_RECORDED"))
            sender.send(bytes.fromhex("ffffffffffff0200000000010806") + b"\0" * 28)
            sender.send(bytes.fromhex("ffffffffffff0200000000990806") + b"FOREIGN_ARP_MUST_BE_FILTERED!!")
            udp6 = struct.pack("!HHHH", 546, 547, 8 + 8, 0) + b"DHCP6_OK"
            ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(udp6), 17, 64,
                                socket.inet_pton(socket.AF_INET6, "fe80::1"),
                                socket.inet_pton(socket.AF_INET6, "ff02::1:2"))
            sender.send(eth[:12] + bytes.fromhex("86dd") + ipv6 + udp6)
        run("ip", "link", "set", "peer", "down")
        time.sleep(2.5)  # Cross the recorder's fsync interval before abrupt kill.
        recorder.send_signal(signal.SIGKILL)
        recorder.wait(timeout=3)
        saved = (capture / "wan.pcap").read_bytes()
        captured = packets(capture / "wan.pcap")
        assert any(b"DHCP_TEST_RECORD" in data for data in captured)
        assert any(b"DHCP6_OK" in data for data in captured)
        assert any(data[12:14] == bytes.fromhex("0806") for data in captured)
        assert all(b"ORDINARY_DNS_MUST_NOT_BE_RECORDED" not in data for data in captured)
        assert all(b"FOREIGN_ARP_MUST_BE_FILTERED" not in data for data in captured)
        types = set()
        for line in (capture / "netlink.hex").read_text().splitlines():
            body = bytes.fromhex(line.split("hex=", 1)[1])
            pos = 0
            while pos + 16 <= len(body):
                length, typ = struct.unpack_from("<IH", body, pos)
                assert length >= 16
                types.add(typ)
                pos += (length + 3) & ~3
        assert {16, 20, 24} <= types, types  # link, address and route changes
        subprocess.run([str(helper), "events", str(capture), "wan", "1"], check=True)
        assert (capture / "wan.pcap").read_bytes().startswith(saved)
        packets(capture / "wan.pcap")  # Restart did not inject a second header.
        result = {"timeout_kills_command_tree": True, "exit_status_preserved": True,
                  "output_limit": True, "late_wan_observed": True,
                  "DHCPv4_DHCPv6_ARP_captured": True, "ordinary_DNS_excluded": True,
                  "unrelated_ARP_excluded": True,
                  "link_address_route_events": True, "abrupt_process_death_evidence_retained": True,
                  "restart_appends_without_overwrite": True,
                  "power_failure_durability_tested": False}
        (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
    finally:
        if recorder.poll() is None:
            recorder.kill()
            recorder.wait()


if __name__ == "__main__":
    main()
