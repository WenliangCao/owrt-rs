#!/usr/bin/env python3
"""Exact-image DHCP relay family differential in private network namespaces.

Run under run_isolated.sh. C and Rust use the same disposable topology and
interface indices. No packet field is normalized in forwarding comparisons.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import query
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from test_single_poll_service import stop

DOWN = "10.77.0.1"
CLIENT = "10.77.0.2"
UP = "10.78.0.1"
SERVER = "10.78.0.2"
DNS_PORT = 15353
PORTS = [67, 68, 1067, 1068, 2067, 2068, 9999, 65535]


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def ip(*args):
    subprocess.run(["ip", *map(str, args)], check=True, capture_output=True, timeout=3)


def actor():
    """Persistent scripted peer; the daemon under test owns all relay logic."""
    poll = selectors.DefaultSelector()
    sockets = {}
    rows = []
    for port in PORTS:
        endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"peer0\0")
        endpoint.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO
        endpoint.bind(("0.0.0.0", port))
        endpoint.setblocking(False)
        sockets[port] = endpoint
        poll.register(endpoint, selectors.EVENT_READ)
    poll.register(sys.stdin, selectors.EVENT_READ)
    print(json.dumps({"ready": True}), flush=True)

    def drain():
        for port, endpoint in sockets.items():
            while True:
                try:
                    packet, ancillary, flags, peer = endpoint.recvmsg(65535, 128)
                except BlockingIOError:
                    break
                destination = None
                for level, kind, data in ancillary:
                    if level == socket.IPPROTO_IP and kind == 8 and len(data) >= 12:
                        destination = socket.inet_ntoa(data[8:12])
                rows.append({"packet": packet.hex(), "source": list(peer),
                             "destination": [destination, port], "flags": flags})

    while True:
        ready = poll.select(3)
        drain()
        if any(key.fileobj is sys.stdin for key, _ in ready):
            line = sys.stdin.readline()
            if not line:
                return
            request = json.loads(line)
            try:
                if request["op"] == "send":
                    sockets[request.get("port", 68)].sendto(bytes.fromhex(request["packet"]), tuple(request["destination"]))
                    result = {"sent": True}
                elif request["op"] == "take":
                    result = {"packets": rows[:]}
                    rows.clear()
                elif request["op"] == "stop":
                    print(json.dumps({"stopped": True}), flush=True)
                    return
                else:
                    raise ValueError("unknown peer operation")
            except Exception as error:
                result = {"error": repr(error)}
            print(json.dumps(result), flush=True)


class Peer:
    def __init__(self, role, relay_ip, peer_ip):
        self.role = role
        self.holder = subprocess.Popen(["unshare", "--net", "sleep", "infinity"], start_new_session=True)
        deadline = time.monotonic() + 3
        while os.readlink(f"/proc/{self.holder.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
            if time.monotonic() >= deadline:
                raise AssertionError("namespace readiness")
            time.sleep(.01)
        self.run("ip", "link", "set", "lo", "up")
        ip("link", "add", role, "type", "veth", "peer", "name", "peer0")
        ip("link", "set", "peer0", "netns", self.holder.pid)
        ip("addr", "add", relay_ip + "/24", "brd", "+", "dev", role)
        ip("link", "set", role, "up")
        self.run("ip", "addr", "add", peer_ip + "/24", "brd", "+", "dev", "peer0")
        self.run("ip", "link", "set", "peer0", "up")
        if role == "client0":
            self.run("ip", "link", "set", "peer0", "address", "02:00:00:4d:35:03")
            self.run("ip", "addr", "add", "10.77.0.10/24", "dev", "peer0")
        else:
            self.run("ip", "route", "add", "10.77.0.0/24", "via", UP)
        self.process = subprocess.Popen(self.argv(sys.executable, Path(__file__).resolve(), "--actor"),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1,
                                        start_new_session=True)
        assert self.read().get("ready")

    def argv(self, *args):
        return ["nsenter", "-t", str(self.holder.pid), "-n", *map(str, args)]

    def run(self, *args):
        return subprocess.run(self.argv(*args), check=True, capture_output=True, timeout=3)

    def read(self):
        poll = selectors.DefaultSelector()
        poll.register(self.process.stdout, selectors.EVENT_READ)
        if not poll.select(4):
            raise AssertionError("peer response timeout")
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError(f"peer exited: {self.process.stderr.read()}")
        result = json.loads(line)
        if "error" in result:
            raise AssertionError(result["error"])
        return result

    def call(self, **request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        try:
            self.call(op="stop")
            self.process.wait(3)
            actor_exit = self.process.returncode
        finally:
            actor_stop = stop(self.process)
            holder_stop = stop(self.holder)
        return {"actor_exit": actor_exit, "actor": actor_stop, "namespace": holder_stop}


def packet(xid=1, op=1, hops=0, giaddr="0.0.0.0", ciaddr="0.0.0.0",
           yiaddr="10.77.0.10", flags=0x8000, htype=1, hlen=6, options=None,
           length=None, cookie=True):
    value = bytearray(240)
    value[:4] = bytes([op, htype, hlen, hops])
    value[4:8] = struct.pack("!I", xid)
    value[10:12] = struct.pack("!H", flags)
    for at, address in [(12, ciaddr), (16, yiaddr), (24, giaddr)]:
        value[at:at+4] = socket.inet_aton(address)
    value[28:34] = bytes.fromhex("0200004d3503")
    value[236:240] = b"\x63\x82\x53\x63" if cookie else b"BAD!"
    value.extend(options if options is not None else bytes([53, 1, 1 if op == 1 else 2, 255]))
    if length is not None:
        value = value[:length] + bytearray(max(0, length - len(value)))
    return value


def scenarios():
    serial = 0

    def case(name, *, upstream=1, downstream=0, sender="client", port=None, destination=None,
             after=None, raw=None, **fields):
        nonlocal serial
        serial += 1
        value = bytearray(raw) if raw is not None else packet(**fields)
        if len(value) >= 8:
            value[4:8] = struct.pack("!I", 0x5e000000 + serial)
        return {"name": name, "packet": value.hex(), "sender": sender,
                "source_port": port if port is not None else (68 if sender == "client" else 67),
                "destination": destination or [DOWN if sender == "client" else UP, 67],
                "upstream": upstream, "downstream": downstream, "after": after}

    def reply(name, **kwargs):
        kwargs.setdefault("giaddr", DOWN)
        kwargs.setdefault("downstream", 1)
        return case(name, sender="server", upstream=0, op=2, **kwargs)

    def profile(name, config, cases, boundaries, **extra):
        return dict(name=name, config=config, cases=cases, boundaries=boundaries, **extra)

    normal = [f"dhcp-relay={DOWN},{SERVER}"]
    prime = lambda: case("prime")
    raw_cases = [case("basic"), case("hops20", hops=20), case("hops21", hops=21, upstream=0),
                 case("hops255", hops=255, upstream=0), case("loop", giaddr=DOWN, upstream=0),
                 case("foreign-giaddr", giaddr="192.0.2.1"), case("all-ones", giaddr="255.255.255.255"),
                 case("reply-op", op=2, upstream=0), case("unknown-op", op=3, upstream=0),
                 case("invalid-hardware", htype=0, hlen=255), case("bad-cookie", cookie=False),
                 case("unknown-type", options=bytes([53,1,254,255])),
                 case("bad-tlv", options=bytes([53,255,1])),
                 *[case(f"length-{size}", length=size, upstream=int(size>=236)) for size in [235,236,240,548,16384,16385,65507]]]
    replies = [reply("unprimed", downstream=0), prime(), reply("broadcast"),
               reply("ciaddr", ciaddr=CLIENT), reply("yiaddr", flags=0),
               reply("hardware-zero", hlen=0, flags=0), reply("hardware-large", hlen=15, flags=0),
               reply("hardware-type-zero", htype=0, flags=0),
               reply("wrong-giaddr", giaddr="192.0.2.1", downstream=0),
               reply("giaddr-zero", giaddr="0.0.0.0", downstream=0),
               reply("untracked-port", port=9999)]
    split = [f"dhcp-split-relay={DOWN},{SERVER},server0"]
    split_cases = [case("split-unicast"), case("split-broadcast", destination=["255.255.255.255",67]),
                   case("split-foreign", giaddr="192.0.2.1"), case("split-loop", giaddr=UP, upstream=0),
                   case("split-no-end", options=b"\x35\x01\x01", upstream=0),
                   case("split-bad-tlv", options=b"\x35\xff\x01\xff", upstream=0),
                   case("split-cookie", cookie=False),
                   case("split-existing-agent", options=b"\x52\x03\x01\x01x\xff")]
    for end in [524,525]:
        value=packet(options=b"");value.extend(bytes(end-240));value.append(255)
        split_cases.append(case(f"split-end-{end}", raw=value, upstream=int(end==524)))
    # Runtime ifindex substitution occurs once against the shared topology.
    split_reply = packet(op=2, giaddr=UP, options=b"\x52\x06\x02\x04IFID\xff")
    split_reply_cases = [case("prime-split"),
        case("split-reply", sender="server", upstream=0, downstream=1, raw=split_reply),
        reply("split-no-agent", giaddr=UP, downstream=0),
        reply("split-short-agent", giaddr=UP, downstream=0, options=b"\x52\x05\x02\x03abc\xff"),
        reply("split-zero-ifindex", giaddr=UP, downstream=0, options=b"\x52\x06\x02\x04\0\0\0\0\xff"),
        reply("split-missing-ifindex", giaddr=UP, downstream=0, options=b"\x52\x06\x02\x04\x7f\xff\xff\xff\xff")]
    overload=packet(op=2,giaddr=UP,options=b"\x34\x01\x01\xff")
    overload[108:119]=b"\x52\x08\x02\x06IFIDxx\xff"
    split_reply_cases.append(case("split-overload",sender="server",upstream=0,downstream=1,raw=overload))
    profiles = [
        profile("ordinary-opaque", normal, raw_cases, ["LIFE-01","RX-01","RX-02","RX-03","STATE-01","UP-01","UP-02","UP-03","LOCAL-01"]),
        profile("ordinary-reply", normal, replies, ["DOWN-01","DOWN-02","DOWN-05","DOWN-06","DOWN-07","STATE-01"]),
        profile("reply-interface", [f"dhcp-relay={DOWN},{SERVER},server*"], [prime(),reply("allowed"),case("wrong-arrival",op=2,giaddr=DOWN,upstream=0)], ["CFG-01","DOWN-02"]),
        profile("relay-multi", [f"dhcp-relay={DOWN},{SERVER}#67",f"dhcp-relay={DOWN},{SERVER}#1067"], [case("two-servers",upstream=2)], ["UP-04"]),
        profile("relay-broadcast", [f"dhcp-relay={DOWN},server0"], [case("broadcast-server")], ["CFG-03","UP-05"]),
        profile("relay-missing-interface", [f"dhcp-relay={DOWN},absent"], [case("missing",upstream=0)], ["UP-05"]),
        profile("relay-excluded", normal+["no-dhcp-interface=client0"], [case("excluded",upstream=0)], ["RX-04"]),
        profile("relay-wrong-interface", normal, [case("wrong",sender="server",upstream=0)], ["STATE-02"]),
        profile("relay-secondary", ["listen-address=10.77.0.3",f"dhcp-relay=10.77.0.3,{SERVER}"], [case("secondary")], ["STATE-02","RX-04"], secondary=True, omit_interface=True),
        profile("split-request", split, split_cases, ["SPLIT-01","SPLIT-02","SPLIT-03","SPLIT-04"]),
        profile("split-literal", [f"dhcp-split-relay={DOWN},{SERVER},{UP}"], [case("literal")], ["CFG-04","SPLIT-01"]),
        profile("split-missing-uplink", [f"dhcp-split-relay={DOWN},{SERVER},absent"], [case("missing",upstream=0)], ["SPLIT-01"]),
        profile("split-reply", split, split_reply_cases, ["DOWN-01","DOWN-03","DOWN-04","DOWN-08"]),
        profile("split-multiple", split+[f"dhcp-split-relay={DOWN},{SERVER}#1067,server0"], [case("two-split",upstream=2)], ["SPLIT-05"]),
        profile("alternate", ["dhcp-alternate-port=1067,1068",*normal],
                [case("alternate-listener",port=1068,destination=[DOWN,1067]),
                 reply("alternate-broadcast",destination=[UP,1067]),
                 reply("alternate-ciaddr",ciaddr=CLIENT,destination=[UP,1067]),
                 reply("alternate-yiaddr",flags=0,destination=[UP,1067]),
                 case("old-listener-closed",upstream=0)], ["PORT-01"]),
        profile("alternate-default", ["dhcp-alternate-port",*normal], [case("default-alt",port=1068,destination=[DOWN,1067])], ["CFG-06","PORT-01"]),
        profile("alternate-upstream", ["dhcp-alternate-port=2067,2068",f"dhcp-relay={DOWN},{SERVER}#1067"], [case("alt-upstream",port=2068,destination=[DOWN,2067])], ["PORT-01"]),
        profile("address-invalidation", normal, [prime(),reply("learned"),reply("invalidated",after="invalidate",downstream=0),case("reprime"),reply("relearned")], ["STATE-03"]),
    ]
    return profiles


def config(profile):
    lines = [f"port={DNS_PORT}","no-resolv","no-hosts","user=root","group=root","no-ping",
             "address=/health.test/192.0.2.7","pid-file=/m2/relay.pid","dhcp-leasefile=/m2/relay.leases"]
    if not profile.get("omit_interface"):
        lines.append("interface=client0")
    else:
        lines.append("listen-address=127.0.0.1")
    lines.extend(profile["config"])
    return "\n".join(lines)+"\n"


def heartbeat():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.5)
        endpoint.sendto(query("health.test",ident=0x5e5e),("127.0.0.1",DNS_PORT))
        response,_=endpoint.recvfrom(4096)
        if len(response)<12 or response[3]&15 or socket.inet_aton("192.0.2.7") not in response:
            raise AssertionError("DNS heartbeat invalid")
        return True


def grammar_cases():
    values = [
        ("relay-two", f"dhcp-relay={DOWN},{SERVER}"),
        ("relay-interface", f"dhcp-relay={DOWN},{SERVER},server*"),
        ("relay-broadcast", f"dhcp-relay={DOWN},server0"),
        ("relay-broadcast-wildcard", f"dhcp-relay={DOWN},server*"),
        ("relay-bad-local", f"dhcp-relay=invalid,{SERVER}"),
        ("relay-missing-server", f"dhcp-relay={DOWN}"),
        ("relay-empty-server", f"dhcp-relay={DOWN},"),
        ("relay-empty-local", f"dhcp-relay=,{SERVER}"),
        ("relay-zero-server", f"dhcp-relay={DOWN},0.0.0.0"),
        ("relay-hostname", f"dhcp-relay={DOWN},server.example"),
        ("relay-hostname-third", f"dhcp-relay={DOWN},server.example,server0"),
        ("relay-ipv6-local", f"dhcp-relay=::1,{SERVER}"),
        ("relay-ipv6-server", f"dhcp-relay={DOWN},::2"),
        ("relay-extra-field", f"dhcp-relay={DOWN},{SERVER},server0,extra"),
        ("relay-long-interface", f"dhcp-relay={DOWN},{SERVER}," + "x" * 40),
        ("split-interface", f"dhcp-split-relay={DOWN},{SERVER},server0"),
        ("split-literal", f"dhcp-split-relay={DOWN},{SERVER},{UP}"),
        ("split-missing-third", f"dhcp-split-relay={DOWN},{SERVER}"),
        ("split-wildcard", f"dhcp-split-relay={DOWN},{SERVER},server*"),
        ("split-empty-third", f"dhcp-split-relay={DOWN},{SERVER},"),
        ("split-zero-uplink", f"dhcp-split-relay={DOWN},{SERVER},0.0.0.0"),
        ("split-ipv6", "dhcp-split-relay=::1,::2,server0"),
    ]
    values += [(f"relay-port-{name}", f"dhcp-relay={DOWN},{SERVER}#{value}")
               for name, value in [("empty", ""), ("zero", "0"), ("normal", "1067"),
                                   ("max", "65535"), ("overflow", "65536"),
                                   ("negative", "-1"), ("invalid", "bad")]]
    values += [(f"alternate-{name}", "dhcp-alternate-port" + value)
               for name, value in [("default", ""), ("empty", "="), ("one", "=2067"),
                                   ("two", "=2067,2068"), ("zero", "=0"),
                                   ("max", "=65535"), ("empty-two", "=,"),
                                   ("overflow", "=65536"), ("negative", "=-1"),
                                   ("invalid", "=bad"), ("extra", "=1,2,3")]]
    return [{"name": name, "config": text} for name, text in values]


def run_grammar(root, side, item, out):
    out.mkdir()
    text = config({"config": [item["config"]]})
    (out / "dnsmasq.conf").write_text(text)
    (root / "m2/relay.conf").write_text(text)
    row = {"name": item["name"], "side": side}
    tested = subprocess.run(command(root, side, "--test", "-C", "/m2/relay.conf"), capture_output=True, text=True, timeout=3)
    row["test"] = {"exit": tested.returncode, "stdout": tested.stdout, "stderr": tested.stderr}
    with (out / "daemon.log").open("wb") as log:
        process = subprocess.Popen(command(root, side, "-k", "-C", "/m2/relay.conf"), stdout=log, stderr=log, start_new_session=True)
        time.sleep(.1)
        row["startup_exit"] = process.poll()
        row["cleanup"] = stop(process)
    row["startup_log"] = (out / "daemon.log").read_text(errors="replace")
    save(out / "result.json", row)
    return row


def grammar_errors(rows, items, sides):
    failures = []
    indexed = {(row["name"], row["side"]): row for row in rows}
    for item in items:
        for side in sides:
            if (item["name"], side) not in indexed:
                failures.append(f"grammar {item['name']}/{side}: missing")
        if sides != ["c", "rust"]:
            continue
        c = indexed.get((item["name"], "c")); rust = indexed.get((item["name"], "rust"))
        if not c or not rust:
            continue
        if (c["test"]["exit"], c["startup_exit"]) != (rust["test"]["exit"], rust["startup_exit"]):
            failures.append(f"grammar {item['name']}: test/startup outcome differs")
        # Keep complete raw output; compare emitted parser outcome text after
        # only the documented executable name and source-location prefixes.
        def message(row):
            text = row["test"]["stdout"] + row["test"]["stderr"]
            if "syntax check OK" in text:
                return "syntax check OK"
            for expected in ["Bad dhcp-relay", "invalid port number"]:
                if expected in text:
                    return expected
            return text.strip()
        if message(c) != message(rust):
            failures.append(f"grammar {item['name']}: --test output differs")
    return failures


def run_profile(root,side,profile,client,server,out):
    out.mkdir()
    text=config(profile)
    (out/"dnsmasq.conf").write_text(text)
    (root/"m2/relay.conf").write_text(text)
    for name in ["relay.pid","relay.leases"]:
        (root/"m2"/name).unlink(missing_ok=True)
    row={"side":side,"profile":profile["name"],"cases":[],"started":False}
    checked=subprocess.run(command(root,side,"--test","-C","/m2/relay.conf"),capture_output=True,text=True,timeout=3)
    row["test"]={"exit":checked.returncode,"stdout":checked.stdout,"stderr":checked.stderr}
    process=None
    if profile.get("secondary"):
        ip("addr","add","10.77.0.3/24","brd","+","dev","client0")
    try:
        with (out/"daemon.log").open("wb") as log:
            process=subprocess.Popen(command(root,side,"-k","-C","/m2/relay.conf"),stdout=log,stderr=log,start_new_session=True)
            time.sleep(.18)
            if process.poll() is not None:
                raise AssertionError(f"daemon startup exit {process.returncode}")
            row["started"]=True
            row["identity"]=process_identity(root,process.pid)
            row["threads"]=len(list(Path(f"/proc/{process.pid}/task").iterdir()))
            for item in profile["cases"]:
                if item["after"]=="invalidate":
                    ip("addr","add","10.77.0.99/24","dev","client0")
                    time.sleep(.12)
                    ip("addr","del","10.77.0.99/24","dev","client0")
                    time.sleep(.12)
                client.call(op="take");server.call(op="take")
                value=bytes.fromhex(item["packet"]).replace(b"IFID",struct.pack("!I",socket.if_nametoindex("client0")))
                peer=client if item["sender"]=="client" else server
                peer.call(op="send",packet=value.hex(),port=item["source_port"],destination=item["destination"])
                time.sleep(.12)
                observed={"upstream":server.call(op="take")["packets"],"downstream":client.call(op="take")["packets"]}
                # Linux loops a peer's own emitted limited broadcast into
                # its other listening port. Keep that raw observation, but
                # it is not a packet emitted by the relay under test.
                echo=[]
                for direction in observed:
                    echo.extend(row for row in observed[direction] if row["packet"]==value.hex() and row["source"][0] in [CLIENT,SERVER])
                    observed[direction]=[row for row in observed[direction] if row not in echo]
                row["cases"].append({"name":item["name"],"request":value.hex(),"observed":observed,
                                     "peer_echo":echo,
                                     "alive":process.poll() is None,"heartbeat":heartbeat()})
            row["lease_file_exists"]=(root/"m2/relay.leases").exists()
    except Exception as error:
        row["error"]=repr(error)
    finally:
        if process is not None:
            row["cleanup"]=stop(process)
        row["pid_removed"]=not (root/"m2/relay.pid").exists()
        if profile.get("secondary"):
            ip("addr","del","10.77.0.3/24","dev","client0")
    save(out/"result.json",row)
    return row


def evaluate(rows,profiles,sides):
    errors=[]
    by_key={(row["profile"],row["side"]):row for row in rows}
    if len(by_key)!=len(rows):errors.append("duplicate profile side")
    for profile in profiles:
        for side in sides:
            key=(profile["name"],side)
            row=by_key.get(key)
            if row is None:errors.append(f"missing {key}");continue
            if not row.get("started") or "error" in row:errors.append(f"{key}: {row.get('error','not started')}")
            if row.get("test",{}).get("exit")!=0:errors.append(f"{key}: --test rejected")
            if row.get("threads")!=1:errors.append(f"{key}: main thread count")
            if row.get("lease_file_exists"):errors.append(f"{key}: relay-only created leasefile")
            if not row.get("pid_removed"):errors.append(f"{key}: PID remains")
            if row.get("cleanup",{}).get("forced") or row.get("cleanup",{}).get("returncode")!=0:errors.append(f"{key}: cleanup")
            actual={case["name"]:case for case in row["cases"]}
            if len(actual)!=len(row["cases"]) or set(actual)!={item["name"] for item in profile["cases"]}:errors.append(f"{key}: missing/extra cases")
            for item in profile["cases"]:
                case=actual.get(item["name"])
                if case is None:continue
                if not case.get("alive") or not case.get("heartbeat"):errors.append(f"{key}/{item['name']}: daemon unhealthy")
                for direction in ["upstream","downstream"]:
                    if len(case["observed"][direction])!=item[direction]:errors.append(f"{key}/{item['name']}: {direction} count {len(case['observed'][direction])} != {item[direction]}")
        if sides==["c","rust"]:
            c=by_key.get((profile["name"],"c"));rust=by_key.get((profile["name"],"rust"))
            if not c or not rust:continue
            for first,second in zip(c["cases"],rust["cases"]):
                if first["name"]!=second["name"] or first["observed"]!=second["observed"]:
                    errors.append(f"{profile['name']}/{first['name']}: forwarding differs")
    return errors


def negative_controls(rows,profiles):
    if evaluate(rows,profiles,["c","rust"]):return {"passed":False,"error":"baseline failed"}
    controls=[]
    position=next((i for i,row in enumerate(rows) if row["side"]=="rust" and any(case["observed"]["upstream"] for case in row["cases"])),None)
    if position is None:return {"passed":False,"error":"missing positive forwarding"}
    for name in ["hops","giaddr","port","missing-packet","extra-packet","missing-side","missing-case","not-alive","cleanup"]:
        altered=copy.deepcopy(rows);row=altered[position]
        case=next(case for case in row["cases"] if case["observed"]["upstream"])
        packets=case["observed"]["upstream"]
        if name in ["hops","giaddr"]:
            value=bytearray.fromhex(packets[0]["packet"]);value[3 if name=="hops" else 24]^=1;packets[0]["packet"]=value.hex()
        elif name=="port":packets[0]["source"][1]^=1
        elif name=="missing-packet":packets.clear()
        elif name=="extra-packet":packets.append(copy.deepcopy(packets[0]))
        elif name=="missing-side":altered.pop(position)
        elif name=="missing-case":row["cases"].pop()
        elif name=="not-alive":case["alive"]=False
        elif name=="cleanup":row["cleanup"]["forced"]=True
        detected=bool(evaluate(altered,profiles,["c","rust"]))
        controls.append({"name":name,"detected":detected})
    return {"passed":all(row["detected"] for row in controls),"controls":controls}


def main(args):
    if os.geteuid()!=0 or os.environ.get("DNSMASQ_TEST_ISOLATED")!="1":raise SystemExit("run through run_isolated.sh")
    if sorted(name for _,name in socket.if_nameindex())!=["lo"]:raise SystemExit("isolated namespace must contain only lo")
    out=args.out.resolve()
    if out.exists() or "private" not in out.parts:raise SystemExit("fresh --out below private/ required")
    out.mkdir(parents=True)
    root=prepare(args.image_root,None,out,args.rust)
    sides=["c","rust"] if args.side=="both" else [args.side]
    profiles=[profile for profile in scenarios() if not args.profile or profile["name"] in args.profile]
    save(out/"manifest.json",{"profiles":profiles,"sides":sides,"c_sha256":STOCK_SHA256,"rust_sha256":sha256(args.rust),"elf_bytes":args.rust.stat().st_size,"tool_sha256":sha256(__file__)})
    rows=[];errors=[];cleanup={};client=server=None;grammar=[]
    grammar_items=[] if args.profile else grammar_cases()
    try:
        for item in grammar_items:
            for side in sides:
                grammar.append(run_grammar(root,side,item,out/f"grammar-{item['name']}-{side}"))
        client=Peer("client0",DOWN,CLIENT);server=Peer("server0",UP,SERVER)
        save(out/"interfaces.json",[{"index":index,"name":name} for index,name in socket.if_nameindex()])
        for profile in profiles:
            for side in sides:
                row=run_profile(root,side,profile,client,server,out/f"{profile['name']}-{side}")
                rows.append(row)
                print(json.dumps({"profile":profile["name"],"side":side,"cases":len(row["cases"]),"error":row.get("error")}),flush=True)
    except Exception as error:errors.append(repr(error))
    finally:
        for name,peer in [("client",client),("server",server)]:
            if peer is not None:
                try:cleanup[name]=peer.close()
                except Exception as error:cleanup[name]={"error":repr(error)}
    errors+=evaluate(rows,profiles,sides)+grammar_errors(grammar,grammar_items,sides)
    for name,result in cleanup.items():
        if result.get("actor_exit")!=0 or "error" in result or result.get("namespace",{}).get("forced"):errors.append(f"{name}: namespace cleanup")
    controls=negative_controls(rows,profiles) if len(sides)==2 else {"passed":False,"not_executed":"reference-only run"}
    if len(sides)==2 and not controls["passed"]:errors.append("negative controls")
    result={"passed":not errors and len(sides)==2,"reference_checks_passed":not errors,"comparison_executed":len(sides)==2,"errors":errors,"rows":rows,"grammar":grammar,"cleanup":cleanup,"negative_controls":controls,"profiles":len(profiles),"cases":sum(len(profile["cases"]) for profile in profiles)}
    save(out/"result.json",result)
    print(json.dumps({key:result[key] for key in ["passed","reference_checks_passed","cases","errors"]}))
    return 0 if not errors else 1


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor",action="store_true")
    parser.add_argument("--image-root",type=Path)
    parser.add_argument("--rust",type=Path)
    parser.add_argument("--out",type=Path)
    parser.add_argument("--side",choices=["both","c","rust"],default="both")
    parser.add_argument("--profile",action="append")
    args=parser.parse_args()
    if args.actor:actor()
    else:
        if not args.image_root or not args.rust or not args.out:parser.error("--image-root, --rust and --out required")
        raise SystemExit(main(args))
