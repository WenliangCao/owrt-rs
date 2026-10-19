#!/usr/bin/env python3
"""Isolated real-packet stalled-helper regression, including exact delete delivery.

sudo unshare -n env DNSMASQ_TEST_ISOLATED=1 python3 helper_backpressure.py BINARY [ARGS...]
Use --observe before BINARY to record the unbounded C/old-Rust baseline.
DNSMASQ_BACKPRESSURE_CYCLES=32 with --observe checks ordinary below-limit traffic.
"""
import collections
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time


def ip(*args):
    subprocess.run(["ip", *args], check=True, stdout=subprocess.DEVNULL)


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return ~value & 65535


def rss(pid):
    return int(next(line.split()[1] for line in Path(f"/proc/{pid}/status")
                    .read_text().splitlines() if line.startswith("VmRSS:")))


def main():
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    arguments = sys.argv[1:]
    observe = arguments[0] == "--observe"
    binary = arguments[1:] if observe else arguments
    cycles = int(os.environ.get("DNSMASQ_BACKPRESSURE_CYCLES", "1024"))
    assert 1 <= cycles <= 4096 and (observe or cycles >= 1024)
    ip("link", "set", "lo", "up")
    ip("link", "add", "lan0", "type", "veth", "peer", "name", "client0")
    for interface in ("lan0", "client0"):
        ip("link", "set", interface, "up")
    ip("addr", "add", "192.0.2.1/24", "dev", "lan0")
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    raw.bind(("client0", 0))
    raw.settimeout(2)
    mac = raw.getsockname()[4]

    def packet(kind, xid, client=1, name=None):
        hardware = mac[:-1] + bytes([(mac[-1] + client) % 256])
        payload = bytearray(240)
        payload[:4] = bytes([1, 1, 6, 0])
        payload[4:8] = struct.pack("!I", xid)
        payload[10:12] = b"\x80\x00"
        payload[28:34] = hardware
        payload[236:240] = bytes([99, 130, 83, 99])
        address = socket.inet_aton(f"192.0.2.{99 + client}")
        if kind == 7:
            payload[12:16] = address
        payload += bytes([53, 1, kind, 54, 4]) + socket.inet_aton("192.0.2.1")
        if kind == 3:
            payload += bytes([50, 4]) + address
            if name:
                payload += bytes([12, len(name)]) + name.encode()
        payload += b"\xff"
        payload.extend(bytes(max(0, 300 - len(payload))))
        udp = struct.pack("!HHHH", 1068, 1067, len(payload) + 8, 0) + payload
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20,
                             xid & 65535, 0, 64, 17, 0, bytes(4), bytes([255] * 4))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return bytes([255] * 6) + hardware + b"\x08\x00" + header + udp

    def request(xid, client=1, name=None):
        raw.send(packet(3, xid, client, name))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            frame = raw.recv(65535)
            if len(frame) < 282 or frame[23] != 17:
                continue
            ihl = (frame[14] & 15) * 4
            if struct.unpack("!H", frame[14 + ihl + 2:14 + ihl + 4])[0] != 1068:
                continue
            payload = frame[14 + ihl + 8:]
            if payload[0] != 2 or payload[4:8] != struct.pack("!I", xid):
                continue
            options = payload[240:]
            while options:
                code, options = options[0], options[1:]
                if code == 255:
                    break
                if code == 0:
                    continue
                size, options = options[0], options[1:]
                value, options = options[:size], options[size:]
                if code == 53:
                    assert value in (b"\x05", b"\x06"), value
                    return value[0]
        raise AssertionError("no DHCP response")

    def dns():
        query = (struct.pack("!HHHHHH", 0x1234, 0x100, 1, 0, 0, 0)
                 + b"\x05probe\x04test\0" + struct.pack("!HH", 1, 1))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(query, ("192.0.2.1", 15353))
            answer = client.recv(4096)
        return answer[:2] == query[:2] and answer[-4:] == socket.inet_aton("192.0.2.42")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        release, entered = root / "release", root / "entered"
        script = root / "script"
        script.write_text('#!/bin/sh\n[ "$1" = init ] && exit 0\n'
                          f'printf "%s %s\\n" "$1" "$4" >> "{entered}"\n'
                          f'while [ ! -e "{release}" ]; do sleep 0.05; done\n')
        script.chmod(0o755)
        config = root / "conf"
        config.write_text(
            "port=15353\ninterface=lan0\nbind-dynamic\nuser=root\nno-ping\n"
            "no-resolv\nno-hosts\naddress=/probe.test/192.0.2.42\n"
            "dhcp-authoritative\ndhcp-lease-max=2\nleasefile-ro\n"
            "dhcp-alternate-port=1067,1068\n"
            "dhcp-range=192.0.2.100,192.0.2.101,255.255.255.0,10m\n"
            f"dhcp-script={script}\npid-file={root / 'pid'}\n")
        with (root / "stderr").open("w+") as log:
            process = subprocess.Popen([*binary, "-k", "-C", str(config)],
                                       stderr=log, stdout=subprocess.DEVNULL)
            try:
                time.sleep(0.4)
                assert process.poll() is None
                assert request(5000, 2, "incumbent") == 5
                expected = []
                first_refusal = None
                samples = []
                for index in range(1, cycles + 1):
                    name = f"lease-{index}"
                    response = request(index, name=name)
                    if response == 5:
                        expected.append(name)
                        raw.send(packet(7, index))
                    else:
                        first_refusal = first_refusal or index
                    if index in (256, 512, cycles):
                        samples.append({"requests": index, "rss_kib": rss(process.pid)})
                assert len(entered.read_text().splitlines()) == 1
                renewal = request(6000, 2, "incumbent") == 5
                dns_healthy = dns()
                raw.send(packet(7, 6000, 2))
                expected.append("incumbent")
                release.touch()
                deadline = time.monotonic() + 30
                deleted = []
                while time.monotonic() < deadline:
                    deleted = [line.split()[1] for line in entered.read_text().splitlines()
                               if line.startswith("del ")]
                    if len(deleted) >= len(expected):
                        break
                    time.sleep(0.05)
                exact_deletes = collections.Counter(deleted) == collections.Counter(expected)
                recovered = request(7000, name="recovered") == 5
                result = {"binary": binary, "first_refusal": first_refusal,
                          "admitted_churn": len(expected) - 1, "samples": samples,
                          "renewal_healthy": renewal, "dns_healthy": dns_healthy,
                          "expected_deletes": len(expected), "actual_deletes": len(deleted),
                          "exact_deletes": exact_deletes, "allocation_recovered": recovered}
                print(json.dumps(result), flush=True)
                assert renewal and dns_healthy and exact_deletes and recovered
                if not observe:
                    assert first_refusal is not None, "stalled helper never bounds new leases"
                    assert samples[-1]["rss_kib"] - samples[-2]["rss_kib"] <= 64
            finally:
                release.touch()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                log.seek(0)
                print(log.read(), file=sys.stderr)


if __name__ == "__main__":
    main()
