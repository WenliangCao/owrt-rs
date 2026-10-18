#!/usr/bin/env python3
"""Capture-only helper validation in a fresh Oracle network namespace."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("helper", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    helper, output = args.helper.resolve(), args.output.resolve()
    if not args.inside:
        subprocess.run(["unshare", "--net", sys.executable, str(Path(__file__).resolve()), str(helper), str(output), "--inside"], check=True)
        return
    assert {name for _, name in socket.if_nameindex()} == {"lo"}
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for command in (["ip", "link", "add", "lan", "type", "veth", "peer", "name", "client"],
                    ["ip", "link", "set", "lan", "address", "02:00:00:00:00:01", "up"],
                    ["ip", "link", "set", "client", "address", "02:00:00:00:00:02", "up"]):
        subprocess.run(command, check=True)
    def flags():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            value = fcntl.ioctl(endpoint, 0x8913, struct.pack("256s", b"lan"))
            return struct.unpack_from("H", value, 16)[0]
    before = flags()
    assert not before & 0x100
    log = output / "capture.jsonl"
    with log.open("w") as stream, (output / "stderr").open("w") as error:
        process = subprocess.Popen([str(helper), "lan", "2", str(output / "capture.pcap")], stdout=stream, stderr=error)
        deadline = time.monotonic() + 1
        while not log.stat().st_size and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(.01)
        assert log.stat().st_size
        assert flags() == before
        duid = bytes.fromhex("00030001020000000002")
        xid = bytes.fromhex("abc123")
        def udp(message, source_port, destination_port):
            body = bytes([message]) + xid + struct.pack("!HH", 1, len(duid)) + duid
            return struct.pack("!HHHH", source_port, destination_port, len(body) + 8, 0) + body
        def frame(payload, protocol, outgoing=False):
            source = socket.inet_pton(socket.AF_INET6, "fe80::1" if outgoing else "fe80::2")
            destination = socket.inet_pton(socket.AF_INET6, "fe80::2" if outgoing else "fe80::1")
            ether = bytes.fromhex("02000000000202000000000186dd" if outgoing else "02000000000102000000000286dd")
            ipv6 = struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 255, source, destination)
            return ether + ipv6 + payload
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as client, \
             socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as server:
            client.bind(("client", 0)); server.bind(("lan", 0))
            client.send(frame(udp(5, 546, 547), 17))
            server.send(frame(udp(7, 547, 546), 17, True))
            server.send(frame(bytes.fromhex("8600000040c000000000000000000000"), 58, True))
            client.send(frame(bytes.fromhex("8500000000000000"), 58))
            client.send(frame(struct.pack("!HHHH", 1234, 53, 12, 0) + b"DROP", 17))
        assert process.wait(timeout=4) == 0, (output / "stderr").read_text()
    assert flags() == before
    records = [json.loads(line) for line in log.read_text().splitlines()]
    packets = [record for record in records if record["kind"] in ("ra", "dhcpv6")]
    assert len(packets) == 3, records
    dhcp = [record for record in packets if record["kind"] == "dhcpv6"]
    assert [record["message_type"] for record in dhcp] == [5, 7]
    assert all(record["xid"] == xid.hex() and record["client_duid"] == duid.hex() for record in dhcp)
    assert dhcp[0]["packet_type"] != 4 and dhcp[1]["packet_type"] == 4
    assert all(not record["truncated"] and record["packet_realtime_ns"] > 0 for record in packets)
    assert records[-1]["socket_dropped"] == 0 and records[-1]["signal"] == 14
    pcap = (output / "capture.pcap").read_bytes()
    assert struct.unpack_from("<IHH", pcap) == (0xa1b2c3d4, 2, 4)
    at = 24
    for packet in packets:
        _, _, captured, original = struct.unpack_from("<IIII", pcap, at)
        at += 16
        assert captured == original == packet["captured_bytes"]
        assert pcap[at:at + captured].hex() == packet["frame_hex"]
        at += captured
    assert at == len(pcap)
    assert subprocess.run([str(helper), "lan", "1801", str(output / "bad.pcap")]).returncode == 2
    assert subprocess.run([str(helper), "lan", "1", str(output / "capture.pcap")], capture_output=True).returncode != 0
    result = {"passed": True, "incoming_renew_and_outgoing_reply": True, "DUID_XID_preserved": True,
              "outgoing_RA": True, "RS_and_ordinary_UDP_excluded": True, "pcap_matches_raw_JSON": True,
              "bounded_exit": True, "no_promiscuity_change": True, "existing_output_refused": True,
              "physical_router_accessed": False}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
