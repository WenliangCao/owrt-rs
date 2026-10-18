#!/usr/bin/env python3
"""Functional RA/DHCPv6 client for the private native-eleven boot fixture.

No timing measurements or performance thresholds. Runs in client0's separate
network namespace and uses the already reviewed baseline packet codecs.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

from odhcpd_baseline import decode_dhcp, decode_ra, opt, options

sys.path.insert(0, str(Path(__file__).resolve().parent / "dnsmasq"))
from dns_service_probe import query, semantics

DUID = bytes.fromhex("00030001020000000028")
HOSTNAME = "native-v6-client"


def receive(sock, matches, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not select.select([sock], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        packet, ancillary, flags, source = sock.recvmsg(8192, 128)
        assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "truncated IPv6 reply"
        if matches(packet, source):
            return packet, ancillary, source
    raise AssertionError("IPv6 functional reply timed out")


def resources(message, kind):
    result = []
    for code, body in options(message[4:]):
        if code != kind:
            continue
        assert len(body) >= 12
        for subcode, item in options(body[12:]):
            if subcode == 13:
                assert len(item) >= 2 and struct.unpack("!H", item[:2])[0] == 0
            elif subcode == 5 and kind == 3:
                assert len(item) == 24
                preferred, valid = struct.unpack("!II", item[16:24])
                assert 0 < preferred <= valid
                result.append({"address": str(ipaddress.IPv6Address(item[:16])), "length": 128})
            elif subcode == 26 and kind == 25:
                assert len(item) >= 25
                preferred, valid, length = struct.unpack("!IIB", item[:9])
                assert 0 < preferred <= valid and 60 <= length <= 64
                result.append({"address": str(ipaddress.IPv6Address(item[9:25])), "length": length})
    assert result, f"missing DHCPv6 resources for option {kind}"
    return result


def run():
    assert os.environ.get("NATIVE_BOOT_ISOLATED") == "1"
    assert os.geteuid() == 0 and sys.platform == "linux"
    assert {name for _, name in socket.if_nameindex()} == {"lo", "client0"}
    index = socket.if_nametoindex("client0")
    result = {"passed": False, "duid": DUID.hex(), "hostname": HOSTNAME}
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"client0\0")
        raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
        raw.sendto(bytes.fromhex("8500000000000000"), ("ff02::2", 0, 0, index))
        packet, ancillary, source = receive(raw, lambda packet, _: len(packet) >= 16 and packet[0] == 134)
        assert ipaddress.IPv6Address(source[0]).is_link_local
        hops = [struct.unpack("i", data)[0] for level, kind, data in ancillary
                if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_HOPLIMIT]
        assert hops == [255]
        ra = decode_ra(packet)
        assert ra["flags"] == 0xc0 and ra["router_lifetime"] > 0
        pios = [item for item in ra["options"] if item["type"] == 3]
        assert {item["prefix"] for item in pios} == {"2001:db8:1::", "fd12:3456:789a::"}
        assert all(item["length"] == 64 and item["flags"] == 0xc0
                   and 0 < item["preferred"] <= item["valid"] for item in pios)
        assert any(item["type"] == 25 for item in ra["options"])
        result["ra"] = {"source": source[0], "hop_limit": 255, "decoded": ra, "hex": packet.hex()}

    # No DHCPv6 address has been installed by this client. These /64 addresses
    # must therefore come from the kernel's processing of autonomous RA PIOs.
    expected_prefixes = {ipaddress.IPv6Network("2001:db8:1::/64"),
                         ipaddress.IPv6Network("fd12:3456:789a::/64")}
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        data = subprocess.check_output(["ip", "-j", "-6", "addr", "show", "dev", "client0"], text=True)
        addresses = [item for link in json.loads(data) for item in link["addr_info"]
                     if item["scope"] == "global" and item["prefixlen"] == 64
                     and "tentative" not in item.get("flags", [])]
        found = {ipaddress.IPv6Network(item["local"] + "/64", strict=False) for item in addresses}
        if expected_prefixes <= found:
            result["slaac_addresses"] = sorted(item["local"] for item in addresses)
            break
        time.sleep(.1)
    else:
        raise AssertionError("client kernel did not configure both autonomous SLAAC prefixes")

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"client0\0")
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        udp.bind(("::", 546))
        counter = 0

        def exchange(kind, ias, server=None, hostname=False):
            nonlocal counter
            counter += 1
            transaction = counter.to_bytes(3, "big")
            packet = bytes([kind]) + transaction + opt(1, DUID)
            if server:
                packet += opt(2, server)
            packet += opt(6, struct.pack("!HHHH", 23, 24, 41, 42))
            packet += b"".join(opt(code, body) for code, body in ias)
            if hostname:
                packet += opt(39, b"\x00" + bytes([len(HOSTNAME)]) + HOSTNAME.encode() + b"\0")
            udp.sendto(packet, ("ff02::1:2", 547, 0, index))
            reply, _, source = receive(udp, lambda reply, source: len(reply) >= 4
                                      and reply[1:4] == transaction and source[1] == 547)
            assert reply[0] == (2 if kind == 1 else 7)
            result.setdefault("messages", []).append({"request": packet.hex(), "reply": reply.hex(),
                                                       "decoded": decode_dhcp(reply), "source": source[0]})
            return reply

        offered = exchange(1, [(3, struct.pack("!III", 1, 0, 0))], hostname=True)
        offered_options = dict(options(offered[4:]))
        server = offered_options[2]
        result["ia_na"] = resources(exchange(3, [(3, offered_options[3])], server, True), 3)
        assert len(result["ia_na"]) == 2
        offered = exchange(1, [(25, struct.pack("!III", 2, 0, 0))])
        offered_options = dict(options(offered[4:]))
        assert offered_options[2] == server
        result["ia_pd"] = resources(exchange(3, [(25, offered_options[25])], server), 25)
        assert len(result["ia_pd"]) == 1
        delegated = result["ia_pd"][0]
        assert ipaddress.IPv6Address(delegated["address"]) in ipaddress.IPv6Network("fd12:3456:789a::/60")

    # The exact odhcpd-update script signals the real supervised dnsmasq.
    # Its new AAAA answer proves the actual hosts-file -> trigger -> reload path.
    expected = {item["address"] for item in result["ia_na"]}
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
            dns.settimeout(1)
            dns.sendto(query(HOSTNAME + ".lan", 28), ("192.168.1.1", 53))
            try:
                answer = semantics(dns.recv(8192))
            except socket.timeout:
                continue
        received = {item["data"] for item in answer["records"] if item["section"] == "answer" and item["type"] == 28}
        if received == expected:
            result["leasetrigger_dns_aaaa"] = sorted(received)
            break
        time.sleep(.1)
    else:
        raise AssertionError("odhcpd-update did not publish the bound client's AAAA records through dnsmasq")
    result["passed"] = True
    return result


if __name__ == "__main__":
    print(json.dumps(run()))
