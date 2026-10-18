#!/usr/bin/env python3
"""Exact-ELF odhcpd protocol fixture. Linux root, private namespaces only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback

C_SHA = "53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82"
DUID = bytes.fromhex("00030001020000000002")
GUA = "2001:db8:1::1/64"
ULA = "fd12:3456:789a::1/60"


def run(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check)


def opt(code, body):
    return struct.pack("!HH", code, len(body)) + body


def options(data):
    result = []
    while data:
        if len(data) < 4:
            raise ValueError("truncated option header")
        code, length = struct.unpack("!HH", data[:4])
        if len(data) < length + 4:
            raise ValueError("truncated option value")
        body, data = data[4:4 + length], data[4 + length:]
        result.append((code, body))
    return result


def decode_dhcp(packet):
    out = {"type": packet[0], "xid": packet[1:4].hex(), "options": []}
    for code, body in options(packet[4:]):
        item = {"code": code, "hex": body.hex()}
        if code in (3, 25):
            item.update(zip(("iaid", "t1", "t2"), struct.unpack("!III", body[:12])))
            item["items"] = []
            for subcode, sub in options(body[12:]):
                s = {"code": subcode, "hex": sub.hex()}
                if subcode == 5:
                    s.update(address=socket.inet_ntop(socket.AF_INET6, sub[:16]),
                             preferred=struct.unpack("!I", sub[16:20])[0],
                             valid=struct.unpack("!I", sub[20:24])[0])
                elif subcode == 26:
                    pref, valid, length = struct.unpack("!IIB", sub[:9])
                    s.update(prefix=socket.inet_ntop(socket.AF_INET6, sub[9:25]),
                             length=length, preferred=pref, valid=valid)
                elif subcode == 13:
                    s["status"] = struct.unpack("!H", sub[:2])[0]
                item["items"].append(s)
        elif code in (41, 42):
            item["text"] = body.decode("ascii")
        elif code == 13:
            item["status"] = struct.unpack("!H", body[:2])[0]
        out["options"].append(item)
    return out


def decode_ra(packet):
    if len(packet) < 16 or packet[0] != 134:
        raise ValueError("not a router advertisement")
    out = {"hop_limit": packet[4], "flags": packet[5],
           "router_lifetime": struct.unpack("!H", packet[6:8])[0], "options": []}
    data = packet[16:]
    while data:
        if len(data) < 2 or data[1] == 0 or data[1] * 8 > len(data):
            raise ValueError("bad RA option length")
        size = data[1] * 8
        body, data = data[:size], data[size:]
        item = {"type": body[0], "hex": body.hex()}
        if body[0] == 3:
            item.update(length=body[2], flags=body[3],
                        valid=struct.unpack("!I", body[4:8])[0],
                        preferred=struct.unpack("!I", body[8:12])[0],
                        prefix=socket.inet_ntop(socket.AF_INET6, body[16:32]))
        out["options"].append(item)
    return out


def client():
    """A real veth client; no daemon syscall interception or protocol mocks."""
    idx = socket.if_nametoindex("client0")
    udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"client0\0")
    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    udp.bind(("::", 546))
    ra = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    ra.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"client0\0")
    ra.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
    ra.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    ra.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
    for s in (ra, udp):
        s.setblocking(False)
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        kind = request["kind"]
        if kind == "stop":
            return
        sock = ra if kind in ("ra", "rs") else udp
        if kind != "ra" or request.get("drain"):
            while select.select([sock], [], [], 0)[0]:
                sock.recv(65535)
        sent = time.monotonic_ns()
        if kind == "rs":
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, request.get("hop_limit", 255))
            sock.sendto(bytes.fromhex(request.get("hex", "8500000000000000")), ("ff02::2", 0, 0, idx))
        elif kind == "dhcp":
            packet = bytes.fromhex(request["hex"])
            sock.sendto(packet, (request.get("destination", "ff02::1:2"), 547, 0, idx))
        if request.get("ack_send"):
            print(json.dumps({"sent_ns": sent, "phase": "sent"}), flush=True)
            if sys.stdin.readline().strip() != "continue":
                raise RuntimeError("missing instrument continuation")
        deadline = time.monotonic() + request.get("timeout", 3)
        response = {"sent_ns": sent, "timeout": True}
        while time.monotonic() < deadline:
            if not select.select([sock], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            data, ancillary, _, addr = sock.recvmsg(65535, 1024)
            received = time.monotonic_ns()
            if sock is ra and data[0] != 134:
                continue
            if kind == "dhcp" and data[1:4] != packet[1:4]:
                continue
            response = {"sent_ns": sent, "received_ns": received,
                        "elapsed_ns": received - sent, "hex": data.hex(),
                        "source": addr[0], "ancillary": [(a, b, c.hex()) for a, b, c in ancillary]}
            response["decoded"] = decode_ra(data) if sock is ra else decode_dhcp(data)
            break
        print(json.dumps(response), flush=True)


class Fixture:
    def __init__(self, args):
        self.args, self.out = args, Path(args.out)
        self.root = self.out / "rootfs"
        self.children = []
        self.results = {"clock": vars(time.get_clock_info("monotonic")), "events": {}, "checks": {}}
        self.counter = 0
        if args.case != "baseline":
            self.results["case"] = args.case

    def record(self, name, value):
        self.results["events"][name] = value
        (self.out / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")
        return value

    def check(self, name, value):
        self.results["checks"][name] = bool(value)
        self.record("last_check", name)

    def spawn(self, name, command, **kwargs):
        log = open(self.out / (name + ".log"), "ab")
        proc = subprocess.Popen(command, stderr=log, stdout=log, **kwargs)
        self.children.append(proc)
        return proc

    def chroot(self, *args, check=True):
        return run("chroot", str(self.root), *args, check=check)

    def bus(self, obj, method, arg=None, check=True):
        r = self.chroot("/bin/ubus", "-t", "2", "call", obj, method,
                        json.dumps(arg or {}), check=check)
        return {"status": r.returncode, "stdout": r.stdout, "stderr": r.stderr}

    def start_bus(self):
        sock = self.root / "var/run/ubus/ubus.sock"
        sock.unlink(missing_ok=True)
        self.ubusd = self.spawn("ubusd", ["chroot", str(self.root), "/sbin/ubusd"])
        for _ in range(100):
            if sock.exists():
                return
            if self.ubusd.poll() is not None:
                raise RuntimeError("private ubusd exited")
            time.sleep(.02)
        raise RuntimeError("private ubus socket absent")

    def start_provider(self):
        ready = self.root / "tmp/fixture.ready"
        ready.unlink(missing_ok=True)
        self.provider = self.spawn("provider", ["chroot", str(self.root), "/usr/bin/ucode", "/tmp/provider.uc"])
        for _ in range(100):
            if ready.exists():
                return
            if self.provider.poll() is not None:
                raise RuntimeError("private provider exited")
            time.sleep(.02)
        raise RuntimeError("private provider not ready")

    def start_daemon(self):
        self.started = time.monotonic_ns()
        self.daemon = self.spawn("odhcpd", ["chroot", str(self.root), "/usr/sbin/odhcpd", "-f"])
        self.record("daemon_start_ns", self.started)

    def request(self, name, kind, on_sent=None, **args):
        if on_sent:
            args["ack_send"] = True
        self.client.stdin.write(json.dumps({"kind": kind, **args}) + "\n")
        self.client.stdin.flush()
        if not select.select([self.client.stdout], [], [], args.get("timeout", 3) + 2)[0]:
            raise RuntimeError("client instrument did not respond")
        value = json.loads(self.client.stdout.readline())
        if on_sent:
            if value.get("phase") != "sent":
                raise RuntimeError("missing client sent acknowledgement")
            self.record(name + "_sent", value)
            on_sent()
            self.client.stdin.write("continue\n")
            self.client.stdin.flush()
            if not select.select([self.client.stdout], [], [], args.get("timeout", 3) + 2)[0]:
                raise RuntimeError("client instrument did not finish acknowledged request")
            value = json.loads(self.client.stdout.readline())
        return self.record(name, value)

    def dhcp(self, name, msgtype, ias=(), server=None, extra=b"", duid=DUID, timeout=3, destination=None):
        self.counter += 1
        packet = bytes([msgtype]) + self.counter.to_bytes(3, "big")
        if duid is not None:
            packet += opt(1, duid)
        if server:
            packet += opt(2, server)
        packet += opt(6, struct.pack("!HHHH", 23, 24, 41, 42))
        packet += b"".join(opt(code, body) for code, body in ias) + extra
        req = {"hex": packet.hex(), "timeout": timeout}
        if destination:
            req["destination"] = destination
        value = self.request(name, "dhcp", **req)
        value["request_hex"] = packet.hex()
        self.record(name, value)
        return value

    def snapshot(self, name):
        state = {"monotonic_ns": time.monotonic_ns(),
                 "routes": json.loads(run("ip", "-j", "-6", "route", "show", "table", "all").stdout),
                 "addresses": json.loads(run("ip", "-j", "-6", "addr").stdout),
                 "leases": self.bus("dhcp", "ipv6leases", check=False),
                 "ra": self.bus("dhcp", "ipv6ra", check=False), "files": {}}
        for path in (self.root / "tmp").rglob("*"):
            if path.is_file() and (path.name.startswith("odhcpd.") or path.name == "trigger.log"):
                state["files"][str(path.relative_to(self.root))] = path.read_text()
        status = Path(f"/proc/{self.daemon.pid}/status").read_text()
        state["memory_kib"] = {x.split(":")[0]: int(x.split()[1]) for x in status.splitlines()
                               if x.startswith(("VmRSS:", "RssAnon:", "RssFile:", "VmSize:"))}
        self.record(name, state)
        return state

    def setup(self):
        run("mount", "--make-rprivate", "/")
        run("cp", "-a", self.args.rootfs, str(self.root))
        os.chmod(self.root, 0o755)
        run("mount", "-t", "tmpfs", "-o", "size=32m,mode=0755", "tmpfs", str(self.root / "tmp"))
        for directory in ("tmp", "tmp/run", "tmp/run/ubus", "dev", "proc", "sys", "etc/config"):
            p = self.root / directory
            p.mkdir(parents=True, exist_ok=True)
            os.chmod(p, 0o755)
        # Extracted squashfs contains only console; boot normally supplies
        # these through devtmpfs. Keep device access inside the copied root.
        for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
            path = self.root / "dev" / name
            if not path.exists():
                os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        run("mount", "-t", "sysfs", "-o", "ro", "sysfs", str(self.root / "sys"))
        run("mount", "-t", "proc", "proc", str(self.root / "proc"))
        if self.args.daemon:
            shutil.copy2(self.args.daemon, self.root / "usr/sbin/odhcpd")
        elf = (self.root / "usr/sbin/odhcpd").read_bytes()
        sha = hashlib.sha256(elf).hexdigest()
        if not self.args.daemon and sha != C_SHA:
            raise RuntimeError("exact C ELF identity mismatch")
        self.record("identity", {"sha256": sha, "reference_sha256": C_SHA,
                                 "instrument_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                 "rootfs": self.args.rootfs, "uname": run("uname", "-a").stdout.strip(),
                                 "server_netns": os.readlink("/proc/self/ns/net")})
        for name, content in {
            "dhcp": """config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option hostsdir '/tmp/hosts'
 option piodir '/tmp/odhcpd-piodir'
 option leasetrigger '/tmp/lease-trigger'
 option loglevel '4'
config dhcp 'lan'
 option interface 'lan'
 option dhcpv4 'server'
 option start '100'
 option limit '150'
 option leasetime '12h'
 option dhcpv6 'server'
 option ra 'server'
 option ra_slaac '1'
 list ra_flags 'managed-config'
 list ra_flags 'other-config'
config dhcp 'wan'
 option interface 'wan'
 option ignore '1'
""",
            "network": "config interface 'lan'\n option proto 'static'\n option device 'br-lan'\n",
            "system": "config system\n option timezone 'CET-1CEST,M3.5.0,M10.5.0/3'\n option zonename 'Europe/Berlin'\n",
        }.items():
            (self.root / "etc/config" / name).write_text(content)
        (self.root / "tmp/lease-trigger").write_text("#!/bin/sh\nprintf '%s\\n' trigger >> /tmp/trigger.log\n")
        os.chmod(self.root / "tmp/lease-trigger", 0o755)
        (self.root / "tmp/provider.uc").write_text("""import { connect } from 'ubus';
import { writefile } from 'fs';
import { init, run } from 'uloop';
init(); let bus = connect(); if (!bus) die('ubus unavailable');
let state = { interface: [{ interface: 'lan', up: true, l3_device: 'br-lan', data: {} }, { interface: 'wan', up: true, l3_device: 'wan0', data: {} }] };
let obj = bus.publish('network.interface', { dump: { call: () => state } });
bus.publish('fixture', { notify: { call: () => { obj.notify('update', {interface:'lan'}); return {}; } } });
writefile('/tmp/fixture.ready', 'ready'); run();
""")
        run("ip", "link", "set", "lo", "up")
        run("sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
        run("ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "client0")
        run("ip", "link", "set", "br-lan", "address", "02:00:00:00:00:01")
        run("ip", "link", "set", "client0", "address", "02:00:00:00:00:02")
        self.netns = self.spawn("client-netns", ["unshare", "--net", "sleep", "300"])
        old = os.readlink("/proc/self/ns/net")
        for _ in range(100):
            if os.readlink(f"/proc/{self.netns.pid}/ns/net") != old:
                break
            time.sleep(.01)
        else:
            raise RuntimeError("client netns not isolated")
        run("ip", "link", "set", "client0", "netns", str(self.netns.pid))
        self.ns = ["nsenter", "-t", str(self.netns.pid), "-n"]
        run(*self.ns, "ip", "link", "set", "lo", "up")
        run(*self.ns, "sysctl", "-q", "-w", "net.ipv6.conf.client0.accept_ra=0")
        run(*self.ns, "sysctl", "-q", "-w", "net.ipv6.conf.client0.addr_gen_mode=1")
        run(*self.ns, "ip", "link", "set", "client0", "up")
        run(*self.ns, "ip", "-6", "addr", "flush", "dev", "client0")
        run(*self.ns, "ip", "-6", "addr", "add", "fe80::2/64", "dev", "client0", "nodad")
        run("sysctl", "-q", "-w", "net.ipv6.conf.br-lan.addr_gen_mode=1")
        run("ip", "link", "set", "br-lan", "up")
        run("ip", "-6", "addr", "flush", "dev", "br-lan")
        for addr in ("fe80::1/64", GUA, ULA):
            run("ip", "-6", "addr", "add", addr, "dev", "br-lan", "nodad")
        run("ip", "link", "add", "wan0", "type", "dummy")
        run("ip", "link", "set", "wan0", "up")
        run("ip", "-6", "route", "add", "default", "dev", "wan0")
        run("ip", "-6", "route", "add", "unreachable", "fd12:3456:789a::/60", "dev", "lo", "metric", "2147483647")
        self.client = subprocess.Popen(self.ns + [sys.executable, __file__, "--client"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                       stderr=open(self.out / "client.log", "w"))
        self.children.append(self.client)
        if not select.select([self.client.stdout], [], [], 3)[0]:
            raise RuntimeError("client not ready")
        if not json.loads(self.client.stdout.readline()).get("ready"):
            raise RuntimeError("bad client readiness")
        self.start_bus()
        self.start_provider()

    def protocol(self):
        self.start_daemon()
        first = self.request("first_active_ra", "ra")
        if first.get("timeout"):
            raise RuntimeError("no first active RA")
        first["from_exec_ns"] = first["received_ns"] - self.started
        self.record("first_active_ra", first)
        self.check("active_ra", first["decoded"]["flags"] == 0xc0 and first["decoded"]["router_lifetime"] > 0)
        rs = self.request("first_rs", "rs")
        self.check("rs_reply", not rs.get("timeout"))
        fqdn = opt(39, b"\x00\x08fixture1\x00")
        offer = self.dhcp("na_advertise", 1, [(3, struct.pack("!III", 1, 0, 0))], extra=fqdn)
        if offer.get("timeout"):
            raise RuntimeError("no DHCPv6 Advertise")
        raw = options(bytes.fromhex(offer["hex"])[4:])
        self.server = next(b for c, b in raw if c == 2)
        self.na = next(b for c, b in raw if c == 3)
        reply = self.dhcp("na_reply", 3, [(3, self.na)], server=self.server, extra=fqdn)
        self.check("na_bound", reply.get("decoded", {}).get("type") == 7)
        self.check("timezone", {o["code"]: o.get("text") for o in reply["decoded"]["options"] if o["code"] in (41, 42)} ==
                   {41: "CET-1CEST,M3.5.0,M10.5.0/3", 42: "Europe/Berlin"})
        time.sleep(.1)
        before = self.snapshot("na_bound_state")
        self.dhcp("na_renew", 5, [(3, self.na)], server=self.server, extra=fqdn)
        time.sleep(.1)
        after = self.snapshot("na_renew_state")
        self.check("renew_does_not_trigger", before["files"].get("tmp/trigger.log") == after["files"].get("tmp/trigger.log"))
        offer = self.dhcp("pd_advertise", 1, [(25, struct.pack("!III", 2, 0, 0))])
        self.pd = next(b for c, b in options(bytes.fromhex(offer["hex"])[4:]) if c == 25)
        self.dhcp("pd_reply", 3, [(25, self.pd)], server=self.server)
        self.snapshot("na_pd_bound_state")
        self.dhcp("information", 11, duid=None)
        self.dhcp("unknown_renew", 5, [(3, struct.pack("!III", 99, 0, 0))], server=self.server)
        self.dhcp("rapid_multi_iaid", 1, [(3, struct.pack("!III", 3, 0, 0)),
                                         (3, struct.pack("!III", 4, 0, 0))], extra=opt(14, b""))
        self.dhcp("unicast_renew", 5, [(3, self.na)], server=self.server, destination="fe80::1")
        self.snapshot("protocol_complete")

    def prefix(self):
        # Install replacement pools first: removal of every PD-capable pool is
        # a different event (C may free the binding before the new pool appears).
        run("ip", "-6", "addr", "add", "2001:db8:2::1/64", "dev", "br-lan", "nodad")
        run("ip", "-6", "addr", "add", "fd12:3456:789b::1/60", "dev", "br-lan", "nodad")
        run("ip", "-6", "addr", "del", GUA, "dev", "br-lan")
        run("ip", "-6", "addr", "del", ULA, "dev", "br-lan")
        run("ip", "-6", "route", "del", "unreachable", "fd12:3456:789a::/60", "dev", "lo", "metric", "2147483647")
        run("ip", "-6", "route", "add", "unreachable", "fd12:3456:789b::/60", "dev", "lo", "metric", "2147483647")
        time.sleep(1.2)
        self.request("prefix_changed_rs", "rs")
        self.snapshot("prefix_changed_before_renew")
        self.dhcp("na_old_prefix_renew", 5, [(3, self.na)], server=self.server)
        self.dhcp("pd_old_prefix_renew", 5, [(25, self.pd)], server=self.server)
        self.snapshot("prefix_changed_after_renew")
        run("ip", "-6", "route", "del", "default", "dev", "wan0")
        time.sleep(.1)
        ra = self.request("wan_down_rs", "rs")
        self.check("wan_down_router_lifetime_zero", ra.get("decoded", {}).get("router_lifetime") == 0)
        self.dhcp("pd_release", 8, [(25, self.pd)], server=self.server)
        self.dhcp("na_decline", 9, [(3, self.na)], server=self.server)
        self.snapshot("released_state")

    def lifecycle(self):
        self.record("notify", self.bus("fixture", "notify"))
        self.daemon.send_signal(signal.SIGHUP)
        time.sleep(.1)
        self.snapshot("after_hup")
        self.provider.terminate()
        self.provider.wait(3)
        self.start_provider()
        time.sleep(.1)
        self.snapshot("provider_recreated")
        self.daemon.terminate()
        self.daemon.wait(3)
        self.start_daemon()
        time.sleep(.15)
        self.request("daemon_restarted_rs", "rs")
        self.snapshot("daemon_restarted")
        self.provider.terminate()
        self.provider.wait(3)
        self.ubusd.terminate()
        self.ubusd.wait(3)
        self.start_bus()
        self.start_provider()
        time.sleep(1.2)
        self.record("ubus_restarted_dhcp", self.bus("dhcp", "ipv6ra", check=False))
        self.request("ubus_restarted_rs", "rs")
        self.snapshot("ubus_restarted")

    def expect(self, name, value):
        self.check(name, value)
        if not value:
            raise RuntimeError("failed assertion: " + name)

    def enhancement(self, name, value):
        self.results.setdefault("enhancements", {})[name] = bool(value)
        self.record("last_enhancement", name)
        if self.args.daemon:
            self.expect(name, value)

    @staticmethod
    def ia_items(packet, code):
        return [item for entry in packet.get("decoded", {}).get("options", [])
                if entry.get("code") == code for item in entry["items"]]

    @staticmethod
    def status_codes(packet):
        found = []
        for entry in packet.get("decoded", {}).get("options", []):
            if entry.get("code") == 13:
                found.append(entry["status"])
            found += [x["status"] for x in entry.get("items", []) if x.get("code") == 13]
        return found

    @staticmethod
    def raw_option(packet, code):
        return next(body for kind, body in options(bytes.fromhex(packet["hex"])[4:]) if kind == code)

    def begin_case(self):
        self.start_daemon()
        first = self.request("initial_ra", "ra", drain=True)
        self.expect("initial_ra", not first.get("timeout"))
        return first

    def bind_pair(self, name, naid, pdid):
        reply = self.dhcp(name, 1, [(3, struct.pack("!III", naid, 0, 0)),
                                   (25, struct.pack("!III", pdid, 0, 0))], extra=opt(14, b""))
        self.expect(name + "_reply", reply.get("decoded", {}).get("type") == 7)
        self.server = self.raw_option(reply, 2)
        return reply, self.raw_option(reply, 3), self.raw_option(reply, 25)

    def case_finite(self):
        for addr in (GUA, ULA):
            run("ip", "-6", "addr", "replace", addr, "dev", "br-lan", "nodad",
                "preferred_lft", "30", "valid_lft", "60")
        self.begin_case()
        reply, na, pd = self.bind_pair("finite_bound", 11, 12)
        items = self.ia_items(reply, 3) + self.ia_items(reply, 25)
        self.expect("finite_lifetimes", len(items) == 3 and all(
            0 < x.get("preferred", 0) <= 30 and x.get("preferred", 0) <= x.get("valid", 0) <= 60 for x in items))
        confirm = self.dhcp("confirm_on_link", 4, [(3, na)])
        self.expect("confirm_on_link_success", self.status_codes(confirm) == [0])
        wrong = struct.pack("!III", 11, 0, 0) + opt(5, socket.inet_pton(socket.AF_INET6, "2001:db8:ffff::1") + struct.pack("!II", 30, 60))
        confirm = self.dhcp("confirm_off_link", 4, [(3, wrong)])
        self.expect("confirm_not_on_link", self.status_codes(confirm) == [4])
        rebind = self.dhcp("known_rebind", 6, [(3, na), (25, pd)])
        self.expect("rebind_resources", len(self.ia_items(rebind, 3)) == 2 and len(self.ia_items(rebind, 25)) == 1)
        release = self.dhcp("finite_release", 8, [(25, pd)], server=self.server)
        self.expect("release_success", self.status_codes(release) == [0])
        released = self.snapshot("finite_released")
        self.expect("release_route_absent", not any(r.get("gateway") == "fe80::2" for r in released["routes"]))
        decline = self.dhcp("finite_decline", 9, [(3, na)], server=self.server)
        self.expect("decline_success", self.status_codes(decline) == [0])
        self.snapshot("finite_declined")
        again, na, pd = self.bind_pair("finite_rebound", 13, 14)
        old_addresses = {x["address"] for x in self.ia_items(reply, 3)}
        self.expect("decline_iid_quarantined", old_addresses.isdisjoint({x["address"] for x in self.ia_items(again, 3)}))
        # A PD transaction immediately precedes the kernel prefix event. No
        # RS or provider reload may mask a lost unsolicited-RA timer update.
        def replace_prefix():
            self.record("race_prefix_change_ns", time.monotonic_ns())
            run("ip", "-6", "addr", "add", "2001:db8:2::1/64", "dev", "br-lan", "nodad",
                "preferred_lft", "30", "valid_lft", "60")
            run("ip", "-6", "addr", "del", GUA, "dev", "br-lan")
        self.counter += 1
        race = bytes([1]) + self.counter.to_bytes(3, "big") + opt(1, DUID) + opt(14, b"") + opt(25, struct.pack("!III", 15, 0, 0))
        self.request("pd_prefix_race", "dhcp", hex=race.hex(), on_sent=replace_prefix)
        ra = self.request("race_unsolicited_withdraw", "ra", drain=True)
        pios = {p.get("prefix"): p for p in ra.get("decoded", {}).get("options", []) if p.get("type") == 3}
        self.expect("race_unsolicited_old_zero", pios.get("2001:db8:1::", {}).get("valid") == 0)
        self.expect("race_unsolicited_new_valid", pios.get("2001:db8:2::", {}).get("valid", 0) > 0)
        for addr in ("2001:db8:2::1/64", ULA):
            run("ip", "-6", "addr", "replace", addr, "dev", "br-lan", "nodad",
                "preferred_lft", "1", "valid_lft", "3")
        time.sleep(.1)
        short = self.dhcp("shortened_renew", 5, [(3, na), (25, pd)], server=self.server)
        self.expect("renew_shortened_valid", all(x.get("valid", 0) <= 3 for x in self.ia_items(short, 3) + self.ia_items(short, 25)))
        self.snapshot("before_expiry")
        time.sleep(4.2)
        expired = self.snapshot("after_expiry_before_packet")
        remaining = [a for link in expired["addresses"] if link["ifname"] == "br-lan"
                     for a in link.get("addr_info", []) if a.get("scope") == "global"]
        self.expect("kernel_addresses_expired", not remaining)
        ra = self.request("expired_rs", "rs")
        self.expect("expired_pio_not_positive", not ra.get("timeout") and not any(
            p.get("type") == 3 and p.get("valid", 0) > 0 for p in ra["decoded"]["options"]))
        absent = self.dhcp("no_pool", 1, [(3, struct.pack("!III", 21, 0, 0)),
                                         (25, struct.pack("!III", 22, 0, 0))])
        self.expect("no_pool_no_resources", not any(x.get("valid", 0) for x in self.ia_items(absent, 3) + self.ia_items(absent, 25)))
        self.enhancement("expiry_no_old_pd_route", not any(r.get("gateway") == "fe80::2" for r in expired["routes"]))
        self.record("expiry_export_before_packet", expired["files"].get("tmp/odhcpd.leases", ""))

    def restart_client(self):
        self.client.terminate()
        self.client.wait(3)
        self.client = subprocess.Popen(self.ns + [sys.executable, __file__, "--client"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                       stderr=open(self.out / "client-recreated.log", "w"))
        self.children.append(self.client)
        if not select.select([self.client.stdout], [], [], 3)[0] or not json.loads(self.client.stdout.readline()).get("ready"):
            raise RuntimeError("recreated client not ready")

    def restart_daemon(self):
        self.daemon.terminate()
        self.daemon.wait(3)
        self.start_daemon()
        time.sleep(.2)

    def case_link(self):
        self.begin_case()
        initial_index = socket.if_nametoindex("br-lan")
        run("ip", "link", "set", "br-lan", "down")
        self.snapshot("link_down")
        run("ip", "link", "set", "br-lan", "up")
        for addr in ("fe80::1/64", GUA, ULA):
            run("ip", "-6", "addr", "replace", addr, "dev", "br-lan", "nodad")
        time.sleep(.2)
        self.expect("link_up_rs", not self.request("link_up_rs", "rs").get("timeout"))
        self.client.terminate()
        self.client.wait(3)
        run("ip", "link", "del", "br-lan")
        run("ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "client0")
        for name, mac in (("br-lan", "02:00:00:00:00:01"), ("client0", "02:00:00:00:00:02")):
            run("ip", "link", "set", name, "address", mac)
        run("ip", "link", "set", "client0", "netns", str(self.netns.pid))
        for name in ("br-lan", "client0"):
            prefix = self.ns if name == "client0" else []
            run(*prefix, "sysctl", "-q", "-w", f"net.ipv6.conf.{name}.addr_gen_mode=1")
            run(*prefix, "ip", "link", "set", name, "up")
        run(*self.ns, "sysctl", "-q", "-w", "net.ipv6.conf.client0.accept_ra=0")
        run(*self.ns, "ip", "-6", "addr", "add", "fe80::2/64", "dev", "client0", "nodad")
        for addr in ("fe80::3/64", "2001:db8:3::1/64", "fd12:3456:789c::1/60"):
            run("ip", "-6", "addr", "add", addr, "dev", "br-lan", "nodad")
        self.restart_client()
        self.expect("ifindex_changed", socket.if_nametoindex("br-lan") != initial_index)
        time.sleep(.2)
        ra = self.request("new_ifindex_rs", "rs")
        self.enhancement("ifindex_without_provider_rebind", ra.get("source") == "fe80::3")
        self.bus("fixture", "notify")
        time.sleep(.2)
        ra = self.request("new_ifindex_notified_rs", "rs")
        self.expect("new_interface_source", ra.get("source") == "fe80::3")
        self.expect("new_interface_pio", any(p.get("prefix") == "2001:db8:3::" and p.get("valid", 0) > 0 for p in ra["decoded"]["options"]))
        self.snapshot("new_ifindex_state")
        run("ip", "-6", "addr", "add", "fe80::4/64", "dev", "br-lan", "nodad")
        run("ip", "-6", "addr", "del", "fe80::3/64", "dev", "br-lan")
        time.sleep(.2)
        self.expect("link_local_source_updated", self.request("new_link_local_rs", "rs").get("source") == "fe80::4")
        for name, contents in (("corrupt", "{"), ("expired", '{"slaac":[{"prefix":"2001:db8:dead::1","length":64,"time":1}]}')):
            self.daemon.terminate()
            self.daemon.wait(3)
            (self.root / "tmp/odhcpd-piodir/odhcpd.pio.br-lan").write_text(contents)
            self.start_daemon()
            time.sleep(.2)
            ra = self.request(name + "_pio_restart", "rs")
            self.expect(name + "_pio_restart_alive", not ra.get("timeout"))
            self.expect(name + "_pio_not_restored", not any(p.get("prefix") == "2001:db8:dead::" for p in ra["decoded"]["options"]))
        self.snapshot("link_complete")

    def case_control(self):
        self.provider.terminate()
        self.provider.wait(3)
        state_path = self.root / "tmp/control-state.json"
        state = {"interface": [{"interface": "lan", "up": True, "l3_device": "br-lan", "data": {}}]}
        state_path.write_text(json.dumps(state))
        (self.root / "tmp/provider.uc").write_text("""import { connect } from 'ubus';
import { readfile, writefile } from 'fs'; import { init, run } from 'uloop';
init(); let bus=connect(); let dumps=0; let state=json(readfile('/tmp/control-state.json'));
let obj=bus.publish('network.interface',{dump:{call:()=>{dumps++; return state;}}});
bus.publish('fixture', {
 stats:{call:()=>({dumps})},
 select:{args:{dns:''},call:r=>{state.interface[0].data.dns=[r.args.dns]; return {};}},
 notify:{call:()=>{obj.notify('update',{interface:'lan'}); return {};}}
}); writefile('/tmp/fixture.ready','ready'); run();
""")
        self.start_provider()
        self.begin_case()
        host_duid = bytes.fromhex("00030001020000000009")
        added = self.bus("dhcp", "add_lease", {"duid": [host_duid.hex()], "hostid": "abc", "name": "fixed9", "leasetime": "20m"})
        self.record("add_lease", added)
        fixed = self.dhcp("fixed_host", 1, [(3, struct.pack("!III", 9, 0, 0))], extra=opt(14, b""), duid=host_duid)
        self.expect("static_hostid", {x.get("address") for x in self.ia_items(fixed, 3)} == {"2001:db8:1::abc", "fd12:3456:789a::abc"})
        bad = self.bus("dhcp", "add_lease", {"hostid": "zz"}, check=False)
        self.record("add_lease_invalid", bad)
        self.expect("invalid_hostid_rejected", bad["status"] == 2)
        self.snapshot("static_host_state")

        def dns_request(name):
            packet = self.dhcp(name, 11, duid=None)
            return [socket.inet_ntop(socket.AF_INET6, bytes.fromhex(x["hex"])[i:i + 16])
                    for x in packet.get("decoded", {}).get("options", []) if x["code"] == 23
                    for i in range(0, len(bytes.fromhex(x["hex"])), 16)]

        def provider_select(dns):
            before = json.loads(self.bus("fixture", "stats")["stdout"])["dumps"]
            self.bus("fixture", "select", {"dns": dns})
            self.bus("fixture", "notify")
            time.sleep(.2)
            after = json.loads(self.bus("fixture", "stats")["stdout"])["dumps"]
            self.record("dump_count_" + dns.rsplit(":", 1)[1], {"before": before, "after": after})
            self.expect("notify_dump_" + dns.rsplit(":", 1)[1], after > before)

        provider_select("fd12:3456:789a::53")
        self.expect("notify_dns_applied", dns_request("dns_after_notify") == ["fd12:3456:789a::53"])
        self.provider.terminate()
        self.provider.wait(3)
        self.expect("provider_absent_ra", not self.request("provider_absent_rs", "rs").get("timeout"))
        self.expect("provider_absent_dhcp", dns_request("provider_absent_dhcp") == ["fd12:3456:789a::53"])
        state["interface"][0]["data"] = {"dns": ["fd12:3456:789a::53"]}
        state_path.write_text(json.dumps(state))
        self.start_provider()
        time.sleep(.2)
        provider_select("fd12:3456:789a::54")
        self.expect("recreated_provider_dns", dns_request("dns_after_provider_recreate") == ["fd12:3456:789a::54"])
        self.provider.terminate()
        self.provider.wait(3)
        self.ubusd.terminate()
        self.ubusd.wait(3)
        self.expect("bus_absent_ra", not self.request("bus_absent_rs", "rs").get("timeout"))
        self.expect("bus_absent_dhcp", dns_request("bus_absent_dhcp") == ["fd12:3456:789a::54"])
        state["interface"][0]["data"] = {"dns": ["fd12:3456:789a::55"]}
        state_path.write_text(json.dumps(state))
        self.start_bus()
        self.start_provider()
        time.sleep(1.2)
        restored = self.bus("dhcp", "ipv6leases", check=False)
        self.record("control_bus_restored", restored)
        self.enhancement("bus_restored_object", restored["status"] == 0)
        stats = self.bus("fixture", "stats")
        self.record("reconnected_provider_stats", stats)
        self.enhancement("bus_restored_dump", json.loads(stats["stdout"])["dumps"] > 0)
        self.enhancement("bus_restored_dns", dns_request("dns_after_bus_reconnect") == ["fd12:3456:789a::55"])
        self.snapshot("control_complete")

    def case_reject(self):
        config_path = self.root / "etc/config/dhcp"
        original = config_path.read_text()
        modes = {
            "maindhcp": original.replace(" option maindhcp '0'", " option maindhcp '1'"),
            "ra_relay": original.replace(" option ra 'server'", " option ra 'relay'"),
            "ra_hybrid": original.replace(" option ra 'server'", " option ra 'hybrid'"),
            "dhcpv6_relay": original.replace(" option dhcpv6 'server'", " option dhcpv6 'relay'"),
            "dhcpv6_hybrid": original.replace(" option dhcpv6 'server'", " option dhcpv6 'hybrid'"),
            "ndp_relay": original.replace(" option interface 'lan'", " option interface 'lan'\n option ndp 'relay'"),
            "master": original.replace(" option interface 'lan'", " option interface 'lan'\n option master '1'"),
        }
        for name, text in modes.items():
            config_path.write_text(text)
            self.start_daemon()
            time.sleep(.3)
            status = self.daemon.poll()
            udp = Path("/proc/net/udp6").read_text()
            service = any(line.split()[1].endswith(":0223") for line in udp.splitlines()[1:])
            self.record("mode_" + name, {"exit_status": status, "udp547": service})
            self.enhancement("reject_" + name, status is not None and status != 0 and not service)
            if self.daemon.poll() is None:
                self.daemon.terminate()
            self.daemon.wait(3)
        config_path.write_text(original)
        self.begin_case()
        reply, na, _ = self.bind_pair("negative_existing", 31, 32)
        before = self.snapshot("negative_before")
        bad_server = self.dhcp("wrong_server", 5, [(3, na)], server=bytes.fromhex("000300010200000000ff"), timeout=.3)
        self.expect("wrong_server_ignored", bad_server.get("timeout"))
        for name, extra in (("short_ia", opt(3, b"\0" * 11)), ("truncated_option", bytes.fromhex("0003000c01"))):
            self.dhcp(name, 1, extra=extra, timeout=.3)
            self.expect(name + "_alive", self.daemon.poll() is None)
        for name, kwargs in (("wrong_rs_hop", {"hop_limit": 64}),
                             ("wrong_rs_code", {"hex": "8501000000000000"}),
                             ("zero_rs_option", {"hex": "85000000000000000100"})):
            packet = self.request(name, "rs", timeout=.3, **kwargs)
            self.expect(name + "_ignored", packet.get("timeout"))
        after = self.snapshot("negative_after")
        def identity(snapshot):
            leases = json.loads(snapshot["leases"]["stdout"])["device"]["br-lan"]["leases"]
            return [(x["duid"], x["iaid"], x["assigned"], x["flags"]) for x in leases]
        self.expect("malformed_preserves_bindings", identity(before) == identity(after))
        good = self.dhcp("negative_followup_renew", 5, [(3, na)], server=self.server)
        self.expect("negative_followup_works", len(self.ia_items(good, 3)) == 2)

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(self.children):
            try:
                child.wait(2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()



def summarize(results):
    """Derive checks from retained packets; never replace the raw observations."""
    if results.get("case", "baseline") != "baseline":
        return results
    e = results["events"]
    checks = results["checks"]

    def opts(name, code):
        return [o for o in e[name].get("decoded", {}).get("options", []) if o.get("code") == code]

    def items(name, code):
        return [item for option in opts(name, code) for item in option["items"]]

    def pios(name):
        return {o["prefix"]: o for o in e[name].get("decoded", {}).get("options", []) if o.get("type") == 3}

    def routes(name):
        return {r["dst"] for r in e[name]["routes"] if r.get("gateway") == "fe80::2"}

    checks["na_two_prefixes"] = {x.get("address") for x in items("na_reply", 3)} == {
        "2001:db8:1::9ed", "fd12:3456:789a::9ed"}
    checks["pd_ula_only"] = [(x.get("prefix"), x.get("length")) for x in items("pd_reply", 25)] == [
        ("fd12:3456:789a:4::", 62)]
    checks["pd_kernel_route"] = "fd12:3456:789a:4::/62" in routes("na_pd_bound_state")
    checks["pd_does_not_trigger"] = e["na_renew_state"]["files"].get("tmp/trigger.log") == e["na_pd_bound_state"]["files"].get("tmp/trigger.log")
    checks["unknown_renew_no_binding"] = [x.get("status") for x in items("unknown_renew", 3)] == [3]
    checks["rapid_multiple_iaid"] = e["rapid_multi_iaid"].get("decoded", {}).get("type") == 7 and {
        x["iaid"] for x in opts("rapid_multi_iaid", 3)} == {3, 4}
    checks["unicast_use_multicast"] = [x.get("status") for x in opts("unicast_renew", 13)] == [5]
    checks["information_without_client_id"] = e["information"].get("decoded", {}).get("type") == 7 and not opts("information", 3)
    old = {"2001:db8:1::", "fd12:3456:789a::"}
    for name in ("prefix_changed_rs", "daemon_restarted_rs"):
        p = pios(name)
        checks[name + "_old_zero"] = all(x in p and p[x]["valid"] == p[x]["preferred"] == 0 for x in old)
    checks["old_na_zero"] = {x.get("address") for x in items("na_old_prefix_renew", 3)
                             if x.get("valid") == x.get("preferred") == 0} == {
                                 "2001:db8:1::9ed", "fd12:3456:789a::9ed"}
    checks["old_pd_zero"] = {x.get("prefix") for x in items("pd_old_prefix_renew", 25)
                             if x.get("valid") == x.get("preferred") == 0} == {"fd12:3456:789a:4::"}
    checks["release_removes_current_pd_route"] = "fd12:3456:789b:4::/62" not in routes("released_state")
    checks["ubus_disconnect_does_not_stop_ra"] = not e["ubus_restarted_rs"].get("timeout")
    results["observed_boundaries"] = {
        "pd_route_outside_gua_pool": "2001:db8:1:4::/62" in routes("na_pd_bound_state"),
        "old_pd_routes_after_prefix_change": sorted(routes("prefix_changed_after_renew") & {
            "2001:db8:1:4::/62", "fd12:3456:789a:4::/62"}),
        "old_pd_routes_after_release": sorted(routes("released_state")),
        "ubus_object_restored": e["ubus_restarted_dhcp"]["status"] == 0,
        "infinite_kernel_ia_lifetimes": [{k: i[k] for k in ("address", "preferred", "valid")}
                                        for i in items("na_reply", 3)],
    }
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summarize", help="derive checks from an existing results.json, without rerunning")
    parser.add_argument("--case", choices=("baseline", "finite", "link", "control", "reject", "extended"), default="baseline")
    parser.add_argument("--rootfs")
    parser.add_argument("--daemon", help="candidate ELF; omit for hash-checked exact C")
    parser.add_argument("--out")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.summarize:
        print(json.dumps(summarize(json.loads(Path(args.summarize).read_text())), indent=2))
        return
    if args.client:
        client()
        return
    if not args.rootfs or not args.out or os.geteuid():
        parser.error("Linux root, --rootfs and --out are required")
    args.rootfs = str(Path(args.rootfs).resolve())
    args.out = str(Path(args.out).resolve())
    if args.daemon:
        args.daemon = str(Path(args.daemon).resolve())
    os.umask(0o022)
    if not args.inside:
        Path(args.out).mkdir(mode=0o700, parents=True, exist_ok=False)
        shutil.copy2(__file__, Path(args.out) / "instrument.py")
        if args.case == "extended":
            statuses = {}
            for name in ("finite", "link", "control", "reject"):
                command = [sys.executable, str(Path(__file__).resolve()), "--rootfs", args.rootfs,
                           "--out", str(Path(args.out) / name), "--case", name]
                if args.daemon:
                    command += ["--daemon", args.daemon]
                status = subprocess.run(command, timeout=190).returncode
                statuses[name] = status
                (Path(args.out) / "batch.json").write_text(json.dumps(statuses, indent=2))
                if status:
                    break
            sys.exit(0 if all(status == 0 for status in statuses.values()) else 1)
        command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
                   sys.executable, str(Path(__file__).resolve()), "--inside", "--rootfs", args.rootfs, "--out", args.out, "--case", args.case]
        if args.daemon:
            command += ["--daemon", args.daemon]
        result = subprocess.run(command, timeout=180)
        sys.exit(result.returncode)
    fixture = Fixture(args)
    try:
        fixture.setup()
        if args.case == "baseline":
            fixture.protocol()
            fixture.prefix()
            fixture.lifecycle()
        else:
            getattr(fixture, "case_" + args.case)()
        summarize(fixture.results)
        fixture.record("complete", True)
        print(json.dumps(fixture.results["checks"], indent=2))
        if not all(fixture.results["checks"].values()):
            raise RuntimeError("protocol check failed; inspect preserved results")
    except Exception:
        fixture.record("error", traceback.format_exc())
        raise
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
