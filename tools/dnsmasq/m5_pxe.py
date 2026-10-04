#!/usr/bin/env python3
"""Daemon-level PXE/BOOTP image-C family differential in private namespaces.

Known undefined C configurations are syntax-only witnesses; no unsafe C
packet path is executed. Other profiles compare raw packets and endpoints.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

import m5_relay as net
from dns_service_probe import query
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from test_single_poll_service import stop

SERVER = net.DOWN
CLIENT = net.CLIENT
DNS_PORT = 15353
net.PORTS = sorted(set(net.PORTS + [4011]))


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Peer(net.Peer):
    def argv(self, *args):
        # Reuse the audited peer transport, but start this file's actor mode
        # so its extra4011 socket exists in the child namespace too.
        if args and args[-1] == "--actor":
            args = (sys.executable, Path(__file__).resolve(), "--actor")
        return super().argv(*args)


def option(code, value):
    if len(value) > 255:
        raise ValueError("one DHCP option exceeds255 bytes")
    return bytes([code, len(value)]) + value


def request(kind=1, arch=0, vendor=b"PXEClient:Arch:00000", uuid=None,
            prl=b"\x01\x03\x06\x2b\x3c", boot_item=None, ciaddr="0.0.0.0",
            giaddr="0.0.0.0", flags=0x8000, extra=b"", cookie=True, hlen=6,
            filename=b"", length=None):
    options = option(53, bytes([kind])) if kind else b""
    if vendor is not None:
        options += option(60, vendor)
    if arch is not None:
        options += option(93, struct.pack("!H", arch) if isinstance(arch, int) else arch)
    if uuid is not None:
        options += option(97, uuid)
    if prl is not None:
        options += option(55, prl)
    if boot_item is not None:
        options += option(43, option(71, boot_item))
    options += extra + b"\xff"
    packet = net.packet(op=1, ciaddr=ciaddr, yiaddr="0.0.0.0", giaddr=giaddr,
                        flags=flags, options=options, cookie=cookie, hlen=hlen, length=length)
    packet[108:108+min(128, len(filename))] = filename[:128]
    return packet


def profiles():
    serial = 0

    def case(name, reply=True, listener=67, source_port=68, *, raw=None,
             reload_hosts=None, copies=1, sender="client", upstream=0, **fields):
        nonlocal serial
        serial += 1
        packet = bytearray(raw) if raw is not None else request(**fields)
        if len(packet) >= 8:
            packet[4:8] = struct.pack("!I", 0x5F000000 + serial)
        return {"name": name, "request": packet.hex(), "reply": reply,
                "listener": listener, "source_port": source_port,
                "reload_hosts": reload_hosts, "copies": copies,"sender":sender,"upstream":upstream}

    def profile(name, options, cases, ids, *, mode="proxy", **extra):
        return dict(name=name, options=options, cases=cases, boundaries=ids, mode=mode, **extra)

    legacy = ["pxe-service=x86PC,Network boot,netboot"]
    efi = ["pxe-service=7,EFI boot,boot.efi"]
    item = lambda service=32768, layer=0: struct.pack("!HH", service, layer)
    rows = [
        profile("legacy-proxy", legacy, [
            case("discover67"), case("discover4011", listener=4011, source_port=4011),
            case("request67", kind=3, reply=False),
            case("request4011", kind=3, listener=4011, source_port=4011, ciaddr=CLIENT, flags=0),
            case("no-vendor", vendor=None, reply=False), case("vendor-case", vendor=b"pxeclient", reply=False),
            case("short-vendor", vendor=b"PXE", reply=False), case("missing-arch", arch=None, reply=False),
            case("short-arch", arch=b"\0", reply=False), case("arch-list-first", arch=b"\0\0\0\7"),
            case("uuid16", uuid=bytes(range(16))), case("uuid17", uuid=bytes(range(17))),
            case("uuid18", uuid=bytes(range(18))), case("bad-cookie", cookie=False, reply=False),
            case("bad-hlen", hlen=17, reply=False), case("inform-no71", kind=8, ciaddr=CLIENT, reply=False),
        ], ["RX01", "RX02", "PROXY01", "PROXY02", "MENU01"]),
        profile("efi-proxy", efi, [
            case("efi67", arch=7), case("efi4011", kind=3, arch=7, ciaddr=CLIENT, listener=4011, source_port=4011, flags=0),
            case("efi-zero-ciaddr", kind=3, arch=7, listener=4011, source_port=9999, flags=0),
            case("arch5", arch=5), case("arch6", arch=6),
        ], ["PROXY03", "UEFI01", "UEFI02"]),
        profile("efi-multiple", efi+["pxe-service=7,Second,second.efi"], [
            case("two67", arch=7), case("two4011", arch=7, kind=3, ciaddr=CLIENT, listener=4011),
        ], ["UEFI01", "MENU01", "MENU03"]),
        profile("boot-item", legacy, [
            case("request-item67", kind=3, ciaddr=CLIENT, boot_item=item(32768,2)),
            case("request-item4011", kind=3, ciaddr=CLIENT, boot_item=item(32768,2), listener=4011, source_port=9999),
            case("inform-item4011", kind=8, ciaddr=CLIENT, boot_item=item(), listener=4011),
            case("mismatched-architecture", kind=3, arch=7, ciaddr=CLIENT, boot_item=item()),
            case("unknown-type", kind=3, ciaddr=CLIENT, boot_item=item(32000), reply=False),
            case("bis-layer", kind=3, ciaddr=CLIENT, boot_item=item(32768,0x8000), reply=False),
            case("wrong-subnet", kind=3, ciaddr="192.0.2.1", boot_item=item(), reply=False),
            case("zero-ciaddr", kind=3, boot_item=item(), reply=False),
            case("long71", kind=3, ciaddr=CLIENT, boot_item=item()+b"extra"),
            case("short71", kind=3, ciaddr=CLIENT, boot_item=b"\x80\0\0", reply=False),
            case("all-ones4011", kind=3, ciaddr=CLIENT, giaddr="255.255.255.255", boot_item=item(), listener=4011),
            case("agent-tail", kind=3, ciaddr=CLIENT, boot_item=item(), extra=option(82,b"\x01\x03abc")),
        ], ["BOOT01", "BOOT02", "BOOT03", "BOOT04", "BOOT05"]),
        profile("numeric-service", ["pxe-service=0,Remote,32768,10.77.0.8"], [
            case("numeric-menu"), case("numeric-no-basename", kind=3, ciaddr=CLIENT, boot_item=item(), reply=False),
        ], ["CFG-S02", "MENU02", "BOOT02"]),
        profile("local-boot-service", ["pxe-service=0,Local disk"], [case("local-menu")], ["CFG-S02", "MENU02"]),
        profile("unknown-server", ["pxe-service=0,Remote,12"], [case("broadcast-discovery")], ["MENU02"]),
        profile("no-matching-menu", ["pxe-service=7,EFI,boot.efi", "dhcp-boot=fallback.0"], [case("fallback-discovery")], ["MENU02", "PROXY04"]),
        profile("prompt-default", legacy+["pxe-prompt=Choose a boot service"], [case("prompt")], ["CFG-P01", "MENU03"]),
        profile("prompt-empty", legacy+["pxe-prompt="], [case("empty-prompt")], ["CFG-P03"]),
        profile("prompt-timeout", legacy+["pxe-prompt=Choose,256"], [case("wrapped-timeout")], ["CFG-P01"]),
        profile("prompt-shared-order", legacy+["pxe-prompt=First,1", "dhcp-option=vendor:PXEClient,10,second", "pxe-prompt=Last,3"], [case("prompt-order")], ["CFG-P02", "MENU03"]),
        profile("prompt-tag-pruned", legacy+["pxe-prompt=tag:missing,Hidden,5"], [case("generated-prompt")], ["MENU03", "CFG-P02"]),
        profile("vendor-custom", legacy+["dhcp-pxe-vendor=custom,custom-long"], [
            case("custom-prefix", vendor=b"custom-long:client"), case("old-default-rejected", reply=False),
        ], ["CFG-V01", "RX01"]),
        profile("pxe-options", legacy+["dhcp-option=224,normal", "dhcp-option-pxe=225,pxe", "dhcp-option-pxe=encap:172,17,nested", "dhcp-option-pxe=vi-encap:13,17,enterprise"], [
            case("proxy-prl-absent", prl=None), case("proxy-prl-empty", prl=b""),
        ], ["CFG-O01", "PROXY05"]),
        profile("static-pxe", legacy, [case("static-discover"), case("static-select", kind=3, extra=option(50,socket.inet_aton("10.77.0.10"))+option(54,socket.inet_aton(SERVER)))], ["NORMAL01", "CFG-R01"], mode="static"),
        profile("dynamic-pxe", legacy+["dhcp-option=224,normal", "dhcp-option-pxe=225,pxe"], [
            case("dynamic-discover", prl=bytes([43,60,224,225])),
            case("dynamic-select", kind=3, prl=bytes([43,60,224,225]), extra=option(50,socket.inet_aton("10.77.0.10"))+option(54,socket.inet_aton(SERVER))),
            case("dynamic-inform", kind=8, ciaddr=CLIENT, prl=bytes([43,60,224,225])),
            case("nonpxe-options", vendor=b"ordinary", arch=None, prl=bytes([43,60,224,225])),
            case("vendor-no-arch", arch=None),
        ], ["NORMAL01", "NORMAL02"], mode="dynamic"),
        profile("normal-prl", legacy+["pxe-prompt=Choose,2"], [
            case("prl43", prl=b"\x2b"), case("prl60", prl=b"\x3c"),
            case("prl-neither", prl=b"\x01"), case("prl-absent", prl=None),
            case("ordinary-substring", arch=None, vendor=b"other-PXEClient", prl=b"\x2b"),
        ], ["NORMAL04", "MENU03"], mode="dynamic"),
        profile("normal-encap-mode", legacy+["dhcp-option-pxe=encap:172,17,nested", "dhcp-option-pxe=vi-encap:13,17,enterprise"], [
            case("nonpxe-minus1", vendor=b"ordinary", arch=None, prl=bytes([172,125])),
            case("arch0", arch=0, prl=bytes([172,125])), case("pc98-arch1", arch=1, prl=bytes([172,125])),
            case("efi-arch7", arch=7, prl=bytes([172,125])),
        ], ["NORMAL03"], mode="dynamic"),
        profile("bootp-global", ["bootp-dynamic", "dhcp-boot=legacy.img"], [case("bootp",kind=0,arch=None,vendor=None,prl=None)], ["BOOTP01", "BOOTP03", "BOOTP04"], mode="dynamic", static_host=False),
        profile("bootp-scoped", ["bootp-dynamic=tag:bootp", "dhcp-boot=tag:bootp,tagged.img"], [case("bootp-tag",kind=0,arch=None,vendor=None,prl=None)], ["CFG-B01", "BOOTP01", "BOOTP02", "BOOTP04"], mode="dynamic", static_host=False),
        profile("bootp-denied", ["bootp-dynamic=tag:missing"], [case("bootp-denied",kind=0,arch=None,vendor=None,prl=None,reply=False)], ["BOOTP02"], mode="dynamic", static_host=False),
        profile("bootp-static", ["dhcp-boot=static.img"], [case("static-without-permission",kind=0,arch=None,vendor=None,prl=None)], ["BOOTP02", "BOOTP03"], mode="static"),
        profile("no-override-default", legacy+["dhcp-boot=file.img,server-name"], [case("requested-boot-options",prl=bytes([43,60,66,67]))], ["NOOVERRIDE01"], mode="dynamic"),
        profile("no-override-enabled", legacy+["dhcp-boot=file.img,server-name", "dhcp-no-override"], [case("fixed-boot-fields",prl=bytes([43,60,66,67]))], ["NOOVERRIDE01", "CFG-N01"], mode="dynamic"),
        profile("4011-leasequery", legacy+["leasequery"], [
            case("query-unassigned4011",kind=10,giaddr=CLIENT,ciaddr="10.77.0.10",listener=4011,source_port=67),
            case("query-unknown4011",kind=10,giaddr=CLIENT,ciaddr="192.0.2.1",listener=4011,source_port=67),
        ], ["RX05"], mode="dynamic"),
        profile("enabled-no-range", legacy, [case("no-dhcp67",reply=False),case("no-pxe4011",listener=4011,reply=False)], ["START01"], mode="none", expect4011=False),
        profile("vendor-option-only", ["dhcp-pxe-vendor=PXEClient", "dhcp-option-pxe=225,not-enabled"], [case("ordinary67"),case("4011-absent",listener=4011,reply=False)], ["START01", "CFG-O01", "CFG-V01"], mode="dynamic", expect4011=False),
    ]
    rows.extend([
        profile("boot-target-hosts",["pxe-service=0,Host target,netboot,boot-server"],[
            case("host-target",kind=3,ciaddr=CLIENT,boot_item=item()),
            case("host-target-reloaded",kind=3,ciaddr=CLIENT,boot_item=item(),reload_hosts="10.77.0.9 boot-server\n"),
        ],["CFG-S03","BOOT03"]),
        profile("boot-target-missing",["pxe-service=0,Missing host,netboot,absent-host"],[
            case("missing-target",kind=3,ciaddr=CLIENT,boot_item=item()),
        ],["CFG-S03","BOOT03"]),
        profile("efi-target-hosts",["pxe-service=7,Host target,boot.efi,boot-server"],[
            case("host-sname",kind=3,arch=7,ciaddr=CLIENT,listener=4011),
        ],["UEFI02"]),
        profile("efi-target-missing",["pxe-service=7,Missing target,boot.efi,absent-host"],[
            case("missing-sname",kind=3,arch=7,ciaddr=CLIENT,listener=4011),
        ],["UEFI02"]),
        profile("duplicate-type-numeric-first",["pxe-service=7,Numeric,32768", "pxe-service=0,Basename,netboot"],[
            case("first-no-basename",kind=3,ciaddr=CLIENT,boot_item=item(),reply=False),
        ],["CFG-S04","BOOT02"]),
        profile("duplicate-type-basename-first",["pxe-service=7,Basename,netboot", "pxe-service=0,Numeric,32768"],[
            case("first-basename-other-arch",kind=3,ciaddr=CLIENT,boot_item=item()),
        ],["CFG-S04","BOOT02"]),
        profile("service-tags",["pxe-service=tag:missing,0,Hidden,hidden", "pxe-service=tag:known,0,Known,known", "pxe-service=0,Common,common"],[
            case("known-menu"),case("boot-item-tag-unchecked",kind=3,ciaddr=CLIENT,boot_item=item()),
        ],["CFG-S04","MENU01","BOOT02"]),
        profile("ignored-proxy",legacy+["dhcp-ignore=tag:client0"],[case("ignored",reply=False)], ["PROXY06"]),
        profile("ignored-boot-item",legacy+["dhcp-ignore=tag:client0"],[case("ignored-item",kind=3,ciaddr=CLIENT,boot_item=item(),reply=False)], ["BOOT01","PROXY06"]),
        profile("boot-filename-bounds",["pxe-service=0,Long,"+"b"*150],[
            case("filename-truncated",kind=3,ciaddr=CLIENT,boot_item=item(32768,65535),reply=False),
            case("filename-127",kind=3,ciaddr=CLIENT,boot_item=item(32768,32767)),
        ],["BOOT03"]),
        profile("proxy-option-overload",legacy+["dhcp-option-pxe=224,"+"a"*220,"dhcp-option-pxe=225,"+"b"*100],[case("proxy-overload")],["NOOVERRIDE02","PROXY05"]),
        profile("proxy-option-overload-nooverride",legacy+["dhcp-option-pxe=224,"+"a"*220,"dhcp-option-pxe=225,"+"b"*100,"dhcp-no-override"],[case("proxy-nooverride-ignored")],["NOOVERRIDE02","CFG-N01"]),
        profile("ordinary-option-overload",legacy+["dhcp-option=224,"+"a"*220,"dhcp-option=225,"+"b"*100],[case("ordinary-overload",prl=bytes([43,60,224,225]))],["NOOVERRIDE02"],mode="dynamic"),
        profile("ordinary-option-overload-nooverride",legacy+["dhcp-option=224,"+"a"*220,"dhcp-option=225,"+"b"*100,"dhcp-no-override"],[case("ordinary-overload-disabled",prl=bytes([43,60,224,225]))],["NOOVERRIDE02"],mode="dynamic"),
        profile("no-boot-option-fallback",legacy+["dhcp-option=66,server-field","dhcp-option=67,file-field"],[
            case("unrequested-fields",prl=b"\x01"),case("requested-options",prl=bytes([66,67])),
        ],["NOOVERRIDE01"],mode="dynamic"),
        profile("owner-burst",legacy,[case("burst16",copies=16)],["OWNER01"]),
        profile("inform-without-context",legacy+["pxe-prompt=Contextless,1","dhcp-option=60,configured-override"],[
            case("inform-no-context",kind=8,ciaddr="198.51.100.20",prl=bytes([43,60])),
        ],["NORMAL01","NORMAL02","NORMAL04"],mode="dynamic"),
        profile("ordinary-efi-configured-vendor",efi+["pxe-prompt=Explicit,1"],[
            case("normal-efi-no-generated-menu",arch=7,prl=bytes([43,60])),
        ],["NORMAL01","NORMAL04","UEFI01"],mode="dynamic"),
        profile("proxy-context-tags",["pxe-service=tag:pool,0,Pool menu,netboot", "pxe-prompt=tag:pool,Pool prompt,3", "dhcp-option-pxe=tag:pool,225,from-pool"],
                [case("context-tag-options")],["PROXY02","PROXY05","CFG-R02"],range_value=f"set:pool,{SERVER},proxy,255.255.255.0"),
        profile("bootp-filename-tag",["bootp-dynamic=tag:firmware", "dhcp-boot=tag:firmware,selected.img"],
                [case("file-tag",kind=0,arch=None,vendor=None,prl=None,filename=b"firmware")],["BOOTP01","BOOTP02"],mode="dynamic",static_host=False),
        profile("bootp-context-tag",["bootp-dynamic=tag:pool"],
                [case("selected-range-permission",kind=0,arch=None,vendor=None,prl=None)],["BOOTP02"],mode="dynamic",static_host=False,
                range_value="set:pool,10.77.0.10,10.77.0.20,255.255.255.0,600s"),
        profile("bootp-context-tag-if",["tag-if=tag:pool,set:permit", "bootp-dynamic=tag:permit"],
                [case("range-tag-if-permission",kind=0,arch=None,vendor=None,prl=None)],["BOOTP02"],mode="dynamic",static_host=False,
                range_value="set:pool,10.77.0.10,10.77.0.20,255.255.255.0,600s"),
        profile("bootp-negative-tag",["bootp-dynamic=tag:!bootp"],
                [case("negative-bootp-denied",kind=0,arch=None,vendor=None,prl=None,reply=False)],["CFG-B01","BOOTP02"],mode="dynamic",static_host=False),
    ])
    for length in [249,250]:
        rows.append(profile(f"menu-length-{length}",["pxe-service=0,"+"m"*length+",boot","pxe-prompt=Keep prompt,1"],
                            [case("menu-capacity")],["MENU04","CFG-S05"]))
    for count in [35,36,37]:
        rows.append(profile(f"server-list-{count}",[f"pxe-service=0,M,{index+1},10.77.0.8" for index in range(count)],
                            [case("server-list-capacity")],["MENU04"]))
    bounds=[case(f"maxmessage-{size}",extra=option(57,struct.pack("!H",size))) for size in [0,27,28,300,576,65535]]
    bounds += [case(f"request-length-{size}",length=size,reply=size>=240) for size in [235,236,240,16384,16385,65507]]
    # At exactly240 bytes there are no DHCP53/vendor/arch options left, so it
    # is BOOTP on a proxy-only head and must be silent.
    next(item for item in bounds if item["name"]=="request-length-240")["reply"]=False
    rows.append(profile("packet-capacity",legacy+[f"dhcp-option-pxe={code},"+"x"*240 for code in [224,225,226]],bounds,["RX03"]))
    for server_port,client_port in [(67,68),(2067,2068)]:
        options=legacy+[f"dhcp-relay={SERVER},{net.SERVER}"]
        if server_port!=67:options.append(f"dhcp-alternate-port={server_port},{client_port}")
        raw_reply=net.packet(op=2,giaddr=SERVER,yiaddr="10.77.0.10",flags=0x8000)
        rows.append(profile(f"4011-relay-{server_port}",options,[
            case("forward-via-primary",listener=4011,source_port=4011,reply=False,upstream=1),
            case("reply-uses-shared-interface",sender="server",source_port=67,listener=server_port,raw=raw_reply),
        ],["RX06","OWNER02"],mode="none",expect4011=True,needs_server=True))
    rows.extend([
        profile("pxe-metrics-success",legacy,[
            case("proxy-count"),case("boot-item-count",kind=3,ciaddr=CLIENT,boot_item=item()),
            case("bis-not-counted",kind=3,ciaddr=CLIENT,boot_item=item(32768,32768),reply=False),
            case("nonpxe-not-counted",vendor=b"ordinary",reply=False),
            case("bootp-proxy-not-counted",kind=0,arch=None,vendor=None,prl=None,reply=False),
        ],["PROXY06","BOOTP04"],metrics=[1,2,2,2,2]),
        profile("pxe-metrics-ignored",legacy+["dhcp-ignore=tag:client0"],[
            case("ignored-proxy-counted",reply=False),case("ignored-item-not-counted",kind=3,ciaddr=CLIENT,boot_item=item(),reply=False),
        ],["PROXY06"],metrics=[1,1]),
    ])
    return rows


def config(profile):
    lines = [f"port={DNS_PORT}", "no-resolv", "no-hosts", "interface=client0",
             "user=root", "group=root", "no-ping", "address=/health.test/192.0.2.7",
             "pid-file=/m2/pxe.pid", "dhcp-leasefile=/m2/pxe.leases", "addn-hosts=/m2/pxe.hosts"]
    mode = profile["mode"]
    if profile.get("range_value") is not None:
        lines.append("dhcp-range="+profile["range_value"])
    elif mode == "dynamic":
        lines.append("dhcp-range=10.77.0.10,10.77.0.20,255.255.255.0,600s")
    elif mode != "none":
        lines.append(f"dhcp-range={SERVER},{mode},255.255.255.0,600s")
    if profile.get("static_host", True):
        lines.append("dhcp-host=02:00:00:4d:35:03,10.77.0.10")
    lines.extend(profile["options"])
    if profile.get("metrics") is not None:
        lines.append("enable-ubus=pxe-metrics")
    return "\n".join(lines) + "\n"


def heartbeat():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.6)
        endpoint.sendto(query("health.test", ident=0x5F5F), ("127.0.0.1", DNS_PORT))
        value, _ = endpoint.recvfrom(4096)
        return len(value) >= 12 and not value[3] & 15 and socket.inet_aton("192.0.2.7") in value


def bound4011():
    return any(int(line.split()[1].split(":")[1], 16) == 4011
               for line in Path("/proc/net/udp").read_text().splitlines()[1:])


def metrics(root):
    response=subprocess.run(command(root,"/bin/ubus","call","pxe-metrics","metrics","{}"),capture_output=True,text=True,timeout=2)
    if response.returncode:raise AssertionError(f"metrics failed: {response.returncode} {response.stderr}")
    return json.loads(response.stdout)


def grammar_cases():
    rows = []
    def add(name, text, unsafe=None):
        rows.append({"name": name, "config": text, "unsafe_runtime": unsafe})
    for index, name in enumerate(["x86PC", "PC98", "IA64_EFI", "Alpha", "Arc_x86", "Intel_Lean_Client",
                                  "IA32_EFI", "x86-64_EFI", "Xscale_EFI", "BC_EFI", "ARM32_EFI", "ARM64_EFI"]):
        add(f"architecture-{index}", f"pxe-service={name},Menu,boot")
    for name, value in [("wrap", "65536"), ("empty", ""), ("invalid", "unknown"), ("negative", "-1")]:
        add(f"architecture-{name}", f"pxe-service={value},Menu,boot")
    for name, text in [
        ("local", "pxe-service=0,Local"), ("numeric", "pxe-service=0,Remote,12"),
        ("numeric-wrap", "pxe-service=0,Remote,65536"), ("filename", "pxe-service=0,Menu,boot.efi"),
        ("server-ip", "pxe-service=0,Menu,boot,10.77.0.8"),
        ("server-name", "pxe-service=0,Menu,boot,boot-server"),
        ("tags", "pxe-service=tag:known,net:!other,0,Menu,boot"),
        ("missing-menu", "pxe-service=0"), ("tags-only", "pxe-service=tag:only"),
        ("quoted", 'pxe-service=0,"One, two",boot')]:
        add("service-"+name, text)
    add("service-empty-menu", "pxe-service=0,,boot", "C NULL menu passed to strlen")
    for length in [249,250]:
        add(f"service-menu-{length}", "pxe-service=0,"+"m"*length+",boot")
    for name, suffix in [("default", ""), ("zero", ",0"), ("max", ",255"), ("wrap", ",256"),
                         ("empty-timeout", ","), ("negative", ",-1"), ("invalid", ",bad")]:
        add("prompt-"+name, "pxe-prompt=Choose"+suffix)
    add("prompt-empty", "pxe-prompt=")
    add("prompt-tags-only", "pxe-prompt=tag:only")
    add("prompt-quoted", 'pxe-prompt="Choose, now",2')
    for length in [251,252,253,255]:
        add(f"prompt-length-{length}", "pxe-prompt="+"p"*length,
            "C prompt bypasses length check and can wrap outer43 length" if length>=252 else None)
    add("vendor-list", "dhcp-pxe-vendor=custom,iPXE")
    add("vendor-empty", "dhcp-pxe-vendor=", "C NULL vendor passed to strlen when PXE enabled")
    add("vendor-empty-element", "dhcp-pxe-vendor=custom,", "C NULL vendor passed to strlen when PXE enabled")
    for name, value in [("ordinary", "225,value"), ("vendor-rejected", "vendor:PXEClient,10,value"),
                        ("encap", "encap:172,17,value"), ("enterprise", "vi-encap:13,17,value")]:
        add("option-pxe-"+name, "dhcp-option-pxe="+value)
    for name, value in [("global", "bootp-dynamic"), ("positive", "bootp-dynamic=tag:bootp"),
                        ("negative", "bootp-dynamic=tag:!skip"), ("legacy", "bootp-dynamic=net:bootp,#skip")]:
        add("bootp-"+name, value)
    return rows


def run_syntax(root, side, item, out):
    out.mkdir()
    text=config({"mode":"proxy", "options":[item["config"]]})
    (root/"m2/pxe.conf").write_text(text)
    (out/"dnsmasq.conf").write_text(text)
    checked=subprocess.run(command(root,side,"--test","-C","/m2/pxe.conf"),capture_output=True,text=True,timeout=3)
    row={"name":item["name"],"side":side,"exit":checked.returncode,"stdout":checked.stdout,"stderr":checked.stderr,
         "runtime_executed":False,"unsafe_runtime":item["unsafe_runtime"]}
    save(out/"result.json",row)
    return row


def syntax_errors(rows,corpus,sides):
    failures=[];indexed={(row["name"],row["side"]):row for row in rows}
    if len(indexed)!=len(rows):failures.append("duplicate syntax row")
    for item in corpus:
        for side in sides:
            if (item["name"],side) not in indexed:failures.append(f"missing syntax {item['name']}/{side}")
        if sides!=["c","rust"]:continue
        c=indexed.get((item["name"],"c"));rust=indexed.get((item["name"],"rust"))
        if not c or not rust:continue
        if item["unsafe_runtime"]:
            # Exact safe syntax observation is retained. No C packet/startup
            # path is run for known NULL/length-overflow configurations.
            if c["exit"]!=0 or rust["exit"]!=1:failures.append(f"unsafe syntax disposition {item['name']}")
        elif (c["exit"],c["stdout"],c["stderr"])!=(rust["exit"],rust["stdout"],rust["stderr"].replace("dnsmasq-rs:","dnsmasq:")):
            failures.append(f"syntax differs {item['name']}")
    return failures


def run_profile(root, side, profile, client, server, out):
    out.mkdir()
    text = config(profile)
    (root/"m2/pxe.conf").write_text(text)
    (root/"m2/pxe.hosts").write_text("10.77.0.8 boot-server\n")
    (out/"dnsmasq.conf").write_text(text)
    for name in ["pxe.pid", "pxe.leases"]:
        (root/"m2"/name).unlink(missing_ok=True)
    tested = subprocess.run(command(root, side, "--test", "-C", "/m2/pxe.conf"), capture_output=True, text=True, timeout=3)
    row = {"profile": profile["name"], "side": side, "started": False, "cases": [],
           "test": {"exit": tested.returncode, "stdout": tested.stdout, "stderr": tested.stderr}}
    process = None;bus=None;bus_log=None
    try:
        if profile.get("metrics") is not None:
            bus_log=(out/"ubusd.log").open("wb")
            bus=subprocess.Popen(command(root,"/sbin/ubusd"),stdout=bus_log,stderr=bus_log,start_new_session=True)
            deadline=time.monotonic()+2
            while True:
                ready=subprocess.run(command(root,"/bin/ubus","list"),capture_output=True,timeout=1)
                if ready.returncode==0:break
                if bus.poll() is not None or time.monotonic()>=deadline:raise AssertionError("ubusd startup")
                time.sleep(.02)
        with (out/"daemon.log").open("wb") as log:
            process = subprocess.Popen(command(root, side, "-k", "-C", "/m2/pxe.conf"), stdout=log, stderr=log, start_new_session=True)
            time.sleep(.2)
            if process.poll() is not None:
                raise AssertionError(f"startup exit {process.returncode}")
            row.update(started=True, identity=process_identity(root, process.pid), listening4011=bound4011(),
                       threads=len(list(Path(f"/proc/{process.pid}/task").iterdir())))
            if not heartbeat():
                raise AssertionError("startup DNS heartbeat")
            row["fd_start"] = net.descriptors(process.pid)
            if profile.get("metrics") is not None:row["initial_metrics"]=metrics(root)
            for item in profile["cases"]:
                if item["reload_hosts"] is not None:
                    (root/"m2/pxe.hosts").write_text(item["reload_hosts"])
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.15)
                client.call(op="take")
                if server is not None:server.call(op="take")
                sender=client if item["sender"]=="client" else server
                sender.call(op="send", packet=item["request"], port=item["source_port"],
                            destination=[SERVER if item["sender"]=="client" else net.UP,item["listener"]], copies=item["copies"])
                time.sleep(.15)
                raw = client.call(op="take")["packets"]
                echoes = [entry for entry in raw if entry["packet"] == item["request"] and entry["source"][0] == CLIENT]
                replies = [entry for entry in raw if entry not in echoes]
                upstream=server.call(op="take")["packets"] if server is not None else []
                leases = root/"m2/pxe.leases"
                row["cases"].append({"name": item["name"], "request": item["request"], "replies": replies,
                                     "peer_echo": echoes, "alive": process.poll() is None, "heartbeat": heartbeat(),
                                     "leases": leases.read_text() if leases.exists() else None,
                                     "observed_epoch":int(time.time()),"upstream":upstream,
                                     "metrics":metrics(root) if profile.get("metrics") is not None else None})
            row["fd_end"] = net.descriptors(process.pid)
    except Exception as error:
        row["error"] = repr(error)
    finally:
        if process is not None:
            row["cleanup"] = stop(process)
        if bus is not None:row["bus_cleanup"]=stop(bus)
        if bus_log is not None:bus_log.close()
        row["pid_removed"] = not (root/"m2/pxe.pid").exists()
    save(out/"result.json", row)
    return row


def lease_state(case):
    if case["leases"] is None:
        return None
    rows=[]
    for line in case["leases"].splitlines():
        fields=line.split()
        if not fields:continue
        if fields[0].isdigit() and len(fields)>=5:
            expiry=int(fields[0])
            rows.append({"record":fields[1:],"remaining":None if expiry==0 else expiry-case["observed_epoch"]})
        else:
            rows.append({"sidecar":fields})
    return rows


def same_leases(first,second):
    a=lease_state(first);b=lease_state(second)
    if a is None or b is None:return a==b
    if len(a)!=len(b):return False
    for left,right in zip(a,b):
        if left.get("record")!=right.get("record") or left.get("sidecar")!=right.get("sidecar"):return False
        x=left.get("remaining");y=right.get("remaining")
        if x is None or y is None:
            if x!=y:return False
        elif abs(x-y)>2:return False
    return True


def evaluate(rows, corpus, sides):
    failures = []
    indexed = {(row["profile"], row["side"]): row for row in rows}
    if len(indexed) != len(rows):
        failures.append("duplicate profile side")
    for profile in corpus:
        for side in sides:
            key = (profile["name"], side)
            row = indexed.get(key)
            if row is None:
                failures.append(f"missing {key}"); continue
            if not row.get("started") or "error" in row:
                failures.append(f"{key}: {row.get('error', 'not started')}")
            if row["test"]["exit"] != 0:
                failures.append(f"{key}: --test failed")
            if row.get("listening4011") != profile.get("expect4011", profile["mode"] != "none" and any(value.startswith(("pxe-service=", "pxe-prompt=")) for value in profile["options"])):
                failures.append(f"{key}:4011 listener state")
            if row.get("threads") != 1 or not row.get("pid_removed"):
                failures.append(f"{key}: threads/PID cleanup")
            if row.get("cleanup", {}).get("returncode") != 0 or row.get("cleanup", {}).get("forced"):
                failures.append(f"{key}: process cleanup")
            if row.get("fd_end", {}).get("floor", 0) > row.get("fd_start", {}).get("floor", 0):
                failures.append(f"{key}: descriptor growth")
            observed = {item["name"]: item for item in row["cases"]}
            if len(observed) != len(row["cases"]) or set(observed) != {item["name"] for item in profile["cases"]}:
                failures.append(f"{key}: missing/extra case")
            for index,item in enumerate(profile["cases"]):
                case = observed.get(item["name"])
                if case is None:
                    continue
                if case["request"] != item["request"]:
                    failures.append(f"{key}/{item['name']}: request differs from manifest")
                expected = item["copies"] if item["reply"] else 0
                if len(case["replies"]) != expected:
                    failures.append(f"{key}/{item['name']}: reply count {len(case['replies'])}!={expected}")
                if len(case["upstream"])!=item["upstream"]*item["copies"]:
                    failures.append(f"{key}/{item['name']}: upstream relay count")
                if not case["alive"] or not case["heartbeat"]:
                    failures.append(f"{key}/{item['name']}: unhealthy daemon")
                if profile["mode"]=="proxy" and lease_state(case):
                    failures.append(f"{key}/{item['name']}: proxy allocated a lease")
                if profile.get("metrics") is not None and (case.get("metrics") or {}).get("pxe")!=profile["metrics"][index]:
                    failures.append(f"{key}/{item['name']}: PXE counter")
            if profile.get("metrics") is not None:
                if (row.get("initial_metrics") or {}).get("pxe")!=0:failures.append(f"{key}: initial PXE count")
                if not row.get("bus_cleanup") or row["bus_cleanup"].get("forced"):failures.append(f"{key}: ubusd cleanup")
        if sides == ["c", "rust"]:
            first = indexed.get((profile["name"], "c")); second = indexed.get((profile["name"], "rust"))
            if not first or not second:
                continue
            for stream in ["stdout", "stderr"]:
                if first["test"][stream] != second["test"][stream].replace("dnsmasq-rs:", "dnsmasq:"):
                    failures.append(f"{profile['name']}: --test {stream} differs")
            for c, rust in zip(first["cases"], second["cases"]):
                if c["name"] != rust["name"] or c["replies"] != rust["replies"] or c["upstream"]!=rust["upstream"]:
                    failures.append(f"{profile['name']}/{c['name']}: wire/endpoint differs")
                if not same_leases(c,rust):
                    failures.append(f"{profile['name']}/{c['name']}: lease state differs")
                if c.get("metrics") is not None:
                    counters=lambda data:{key:value for key,value in data.items() if key in ["pxe","bootp"] or key.startswith("dhcp_")}
                    if rust.get("metrics") is None or counters(c["metrics"])!=counters(rust["metrics"]):
                        failures.append(f"{profile['name']}/{c['name']}: DHCP/PXE metrics differ")
    return failures


def negative_controls(rows, corpus):
    baseline = evaluate(rows, corpus, ["c", "rust"])
    if baseline:
        return {"passed": False, "baseline_errors": baseline, "controls": []}
    position = next((index for index, row in enumerate(rows) if row["side"] == "rust"
                     and any(case["replies"] for case in row["cases"])), None)
    if position is None:
        return {"passed": False, "error": "no positive PXE reply", "controls": []}
    controls = []
    for mutation in ["message-type", "boot-field", "server-id", "reply-port", "missing-packet",
                     "extra-packet", "missing-case", "missing-profile", "input-architecture",
                     "lease-side-effect", "no-health", "thread-added", "cleanup-forced"]:
        changed = copy.deepcopy(rows)
        row = changed[position]
        case = next(case for case in row["cases"] if case["replies"])
        response = case["replies"][0]
        if mutation in ["message-type", "boot-field", "server-id"]:
            wire = bytearray.fromhex(response["packet"])
            offset = {"message-type": 242, "boot-field": 108, "server-id": 245}[mutation]
            wire[offset] ^= 1
            response["packet"] = wire.hex()
        elif mutation == "reply-port": response["source"][1] ^= 1
        elif mutation == "missing-packet": case["replies"].clear()
        elif mutation == "extra-packet": case["replies"].append(copy.deepcopy(response))
        elif mutation == "missing-case": row["cases"].pop()
        elif mutation == "missing-profile": changed.pop(position)
        elif mutation == "input-architecture":
            wire = bytearray.fromhex(case["request"])
            offset = 240
            while offset + 2 < len(wire) and wire[offset] != 255:
                if wire[offset] == 0:
                    offset += 1; continue
                if wire[offset] == 93 and wire[offset+1] >= 2:
                    wire[offset+2] ^= 1; break
                offset += wire[offset+1] + 2
            else:
                # A focused BOOTP-only run has no architecture input; its
                # manifest-integrity control changes the fixed xid instead.
                wire[4] ^= 1
            case["request"] = wire.hex()
        elif mutation == "lease-side-effect": case["leases"] = "0 02:00:00:4d:35:03 10.77.0.10 injected *\n"
        elif mutation == "no-health": case["heartbeat"] = False
        elif mutation == "thread-added": row["threads"] = 2
        elif mutation == "cleanup-forced": row["cleanup"]["forced"] = True
        controls.append({"name": mutation, "detected": bool(evaluate(changed, corpus, ["c", "rust"]))})
    return {"passed": all(row["detected"] for row in controls), "controls": controls}


def main(args):
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run only through run_isolated.sh")
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        raise SystemExit("isolated namespace must contain only lo")
    out = args.out.resolve()
    if out.exists() or "private" not in out.parts:
        raise SystemExit("fresh output directory below private/ required")
    out.mkdir(parents=True)
    root = prepare(args.image_root, None, out, args.rust)
    corpus = [profile for profile in profiles() if not args.profile or profile["name"] in args.profile]
    sides = ["c", "rust"] if args.side == "both" else [args.side]
    save(out/"manifest.json", {"profiles": corpus, "sides": sides, "tool_sha256": sha256(__file__),
                              "transport_tool_sha256": sha256(net.__file__), "c_sha256": STOCK_SHA256,
                              "rust_sha256": sha256(args.rust), "elf_bytes": args.rust.stat().st_size})
    rows = []; failures = []; client = None; server=None; cleanup = None; server_cleanup=None; syntax=[]
    syntax_corpus=[] if args.profile else grammar_cases()
    try:
        for item in syntax_corpus:
            for side in sides:syntax.append(run_syntax(root,side,item,out/f"syntax-{item['name']}-{side}"))
        client = Peer("client0", SERVER, CLIENT)
        if any(profile.get("needs_server") for profile in corpus):server=Peer("server0",net.UP,net.SERVER)
        for profile in corpus:
            for side in sides:
                row = run_profile(root, side, profile, client, server, out/f"{profile['name']}-{side}")
                rows.append(row)
                print(json.dumps({"profile": profile["name"], "side": side, "cases": len(row["cases"]), "error": row.get("error")}), flush=True)
    except Exception as error:
        failures.append(repr(error))
    finally:
        if client is not None:
            cleanup = client.close()
        if server is not None:server_cleanup=server.close()
    failures += evaluate(rows, corpus, sides)+syntax_errors(syntax,syntax_corpus,sides)
    if cleanup is None or cleanup.get("actor_exit") != 0 or cleanup.get("namespace", {}).get("forced"):
        failures.append("peer cleanup")
    if server is not None and (server_cleanup is None or server_cleanup.get("actor_exit")!=0 or server_cleanup.get("namespace",{}).get("forced")):
        failures.append("upstream peer cleanup")
    controls = negative_controls(rows,corpus) if len(sides)==2 else {"passed":False,"not_executed":"reference-only run"}
    if len(sides)==2 and not controls["passed"]:
        failures.append("comparator negative controls")
    result = {"passed": not failures and len(sides) == 2, "reference_checks_passed": not failures,
              "comparison_executed": len(sides) == 2, "failures": failures, "profiles": rows,
              "profile_count": len(corpus), "case_count": sum(len(profile["cases"]) for profile in corpus),
              "syntax":syntax,"syntax_count":len(syntax_corpus),
              "reference_differences":[{"name":item["name"],"source_reason":item["unsafe_runtime"],
                                         "c_runtime_executed":False,"candidate_policy":"safe syntax rejection"}
                                        for item in syntax_corpus if item["unsafe_runtime"]],
              "negative_controls":controls,
              "cleanup": cleanup,"upstream_cleanup":server_cleanup,
              "normalization": "No response wire fields normalized; lease absolute expiry compared as remaining seconds within2s; infinite/finite and all other lease fields exact"}
    save(out/"result.json", result)
    print(json.dumps({key: result[key] for key in ["passed", "reference_checks_passed", "case_count", "failures"]}))
    return 0 if not failures else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor", action="store_true")
    parser.add_argument("--image-root", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--side", choices=["c", "rust", "both"], default="both")
    parser.add_argument("--profile", action="append")
    args = parser.parse_args()
    if args.actor:
        net.actor()
    else:
        if not args.image_root or not args.rust or not args.out:
            parser.error("--image-root, --rust and --out required")
        raise SystemExit(main(args))
