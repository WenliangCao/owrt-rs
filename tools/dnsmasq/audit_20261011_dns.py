#!/usr/bin/env python3
"""Independent actual-daemon DNS boundary audit, exact image versus fresh Rust.

Requires run_isolated.sh. Reuses only m2_rootfs's identity-checked disposable
image overlay; packet generation, stub upstream and comparisons are independent.
All addresses are synthetic and all listeners remain in the private namespace.
"""
import argparse
import json
import signal
import socket
import struct
import threading
import time
from pathlib import Path
import subprocess

from m2_rootfs import command, prepare, sha256


def name(value):
    if not value:
        return b"\0"
    return b"".join(bytes([len(s)]) + s for s in value.encode().split(b".")) + b"\0"


def query(value="host.audit.test", kind=1, cls=1, flags=0x100, extra=b"", ar=0):
    return struct.pack("!6H", 0x1234, flags, 1, 0, 0, ar) + name(value) + struct.pack("!HH", kind, cls) + extra


def opt(size=1232, ttl=0, data=b""):
    return b"\0" + struct.pack("!HHIH", 41, size, ttl, len(data)) + data


def rr(owner, kind, data, cls=1, ttl=60):
    return owner + struct.pack("!HHIH", kind, cls, ttl, len(data)) + data


def header(packet, **changes):
    fields = list(struct.unpack("!6H", packet[:12]))
    for key, value in changes.items():
        fields[["id", "flags", "qd", "an", "ns", "ar"].index(key)] = value
    return struct.pack("!6H", *fields) + packet[12:]


def local_cases():
    cases = []
    def add(label, packet):
        cases.append((label, packet))
    for label, host, kind in [
        ("host-a", "host.audit.test", 1), ("host-aaaa", "host.audit.test", 28),
        ("host-any", "host.audit.test", 255), ("host-txt-miss", "host.audit.test", 16),
        ("alias-a", "alias.audit.test", 1), ("alias-cname", "alias.audit.test", 5),
        ("alias-any", "alias.audit.test", 255), ("alias-unknown", "alias.audit.test", 65280),
        ("chain-a", "chain.audit.test", 1), ("local-miss", "missing.audit.test", 1),
        ("txt", "txt.audit.test", 16), ("mx", "mail.audit.test", 15),
        ("srv", "_service._tcp.audit.test", 33), ("mixed-case", "HoSt.AuDiT.TeSt", 1),
        ("root", "", 1), ("unconfigured", "elsewhere.example", 1),
        ("reverse-v4", "42.2.0.192.in-addr.arpa", 12),
    ]:
        add(label, query(host, kind))
    for cls in (0, 2, 3, 4, 254, 255, 65535):
        add(f"non-in-{cls}", query(cls=cls))
    for flags in (0, 0x110, 0x120, 0x150, 0x7800, 0x900, 0x8100, 0x300):
        add(f"flags-{flags:04x}", query(flags=flags))
    for label, additional in [
        ("edns", opt()), ("edns-do", opt(ttl=0x8000)),
        ("edns-v1", opt(ttl=0x10000)), ("edns-size-zero", opt(0)),
        ("edns-size-65535", opt(65535)),
        ("edns-cookie", opt(data=b"\0\x0a\0\x08abcdefgh")),
        ("edns-truncated-option", opt(data=b"\0\x0a\0\x08a")),
        ("edns-truncated-rr", opt()[:-1]),
    ]:
        add(label, query(extra=additional, ar=1))
    add("edns-duplicate", query(extra=opt()+opt(4096, 0x8000), ar=2))
    add("additional-txt", query(extra=rr(name("extra.test"), 16, b"\x01x"), ar=1))
    add("trailing-data", query() + b"junk")
    add("multi-question", header(query() + name("txt.audit.test") + b"\0\x10\0\x01", qd=2))
    add("multi-question-compressed", header(query() + b"\xc0\x0c\0\x01\0\x01", qd=2))
    add("zero-question", struct.pack("!6H", 0x1234, 0x100, 0, 0, 0, 0))
    add("answer-in-query", header(query() + rr(b"\xc0\x0c", 1, b"\xc0\0\x02\x01"), an=1))
    add("authority-in-query", header(query() + rr(b"\xc0\x0c", 1, b"\xc0\0\x02\x01"), ns=1))
    add("forward-pointer", query()[:12] + b"\xc0\x12\0\x01\0\x01" + name("host.audit.test"))
    add("self-pointer", query()[:12] + b"\xc0\x0c\0\x01\0\x01")
    add("outside-pointer", query()[:12] + b"\xc0\xff\0\x01\0\x01")
    add("label-truncated", query()[:12] + b"\x3fabc")
    add("bitstring-label", query()[:12] + b"\x41\x08a\0\0\x01\0\x01")
    add("binary-label", query()[:12] + b"\x03a\0b\0\0\x01\0\x01")
    add("short-header", b"\x12\x34" + b"\0" * 9)
    add("over-udp-limit", query() + b"\0" * 1233)
    add("maximum-name", query(".".join(["a"*63]*3 + ["b"*61])))
    add("overlong-name", query(".".join(["a"*63]*3 + ["b"*62])))
    return cases


def question_end(packet):
    pos = 12
    while packet[pos]:
        if packet[pos] & 0xc0 == 0xc0:
            return pos + 6
        pos += packet[pos] + 1
    return pos + 5


def stub_reply(packet):
    end = question_end(packet)
    scenario = packet[13:13+packet[12]].decode().lower()
    kind = struct.unpack("!H", packet[end-4:end-2])[0]
    question = packet[12:end]
    answer = rr(b"\xc0\x0c", 1, b"\xc0\0\x02\x4d")
    an, ns, ar, flags, additional = 1, 0, 0, 0x8180, b""
    if scenario == "aaaa":
        answer = rr(b"\xc0\x0c", 28, socket.inet_pton(socket.AF_INET6, "2001:db8::77"))
    elif scenario == "nonin":
        answer = rr(b"\xc0\x0c", 1, b"\xc0\0\x02\x4d", cls=3)
    elif scenario in ("cname", "cname-nx", "cname-loop", "cname-only"):
        target = name("target.example")
        answer = rr(b"\xc0\x0c", 5, target)
        if scenario == "cname-loop":
            answer += rr(target, 5, b"\xc0\x0c")
            an = 2
        elif scenario == "cname":
            answer += rr(target, 1, b"\xc0\0\x02\x4d")
            an = 2
        elif scenario == "cname-nx":
            flags |= 3
    elif scenario == "mixed":
        answer += rr(b"\xc0\x0c", 28, socket.inet_pton(socket.AF_INET6, "2001:db8::77"))
        answer += rr(b"\xc0\x0c", 16, b"\x04text")
        an = 3
    elif scenario == "large":
        answer = rr(b"\xc0\x0c", 16, b"\xff" + b"x"*255 + b"\xff" + b"y"*255 + b"\x40" + b"z"*64)
    elif scenario == "truncated":
        flags |= 0x200
    elif scenario == "ad":
        flags |= 0x20
    elif scenario == "nxdomain":
        answer, an, flags = b"", 0, flags | 3
    elif scenario == "servfail":
        answer, an, flags = b"", 0, flags | 2
    elif scenario == "bad-rdlen":
        answer = rr(b"\xc0\x0c", 1, b"\xc0\0\x02")
    elif scenario == "extra-rdlen":
        answer = rr(b"\xc0\x0c", 1, b"\xc0\0\x02\x4d\0")
    elif scenario == "bad-owner":
        answer = rr(b"\xc0\xff", 1, b"\xc0\0\x02\x4d")
    elif scenario == "private":
        answer = rr(b"\xc0\x0c", 1, b"\x0a\0\0\x01")
    elif scenario == "opt":
        additional, ar = opt(4096, 0x8000, b"\0\x0f\0\x02\0\x03"), 1
    elif scenario == "opt-version":
        additional, ar = opt(4096, 0x10000), 1
    elif scenario == "opt-duplicate":
        additional, ar = opt() + opt(), 2
    elif scenario == "wrong-type":
        answer = rr(b"\xc0\x0c", 16 if kind == 1 else 1, b"\x03abc")
    return struct.pack("!6H", struct.unpack("!H", packet[:2])[0], flags, 1, an, ns, ar) + question + answer + additional


def exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


class Stub:
    def __init__(self):
        self.records = []
        self.stop = threading.Event()
        self.sockets = []
        for protocol, kind in (("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)):
            sock = socket.socket(socket.AF_INET, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 15354))
            sock.settimeout(0.1)
            if protocol == "tcp":
                sock.listen()
            self.sockets.append(sock)
            threading.Thread(target=self.run, args=(sock, protocol), daemon=True).start()

    def run(self, sock, protocol):
        while not self.stop.is_set():
            try:
                if protocol == "udp":
                    packet, address = sock.recvfrom(65535)
                    response = stub_reply(packet)
                    self.records.append({"protocol": protocol, "query": packet.hex(), "reply": response.hex()})
                    sock.sendto(response, address)
                else:
                    connection, _ = sock.accept()
                    threading.Thread(target=self.tcp, args=(connection,), daemon=True).start()
            except socket.timeout:
                pass

    def tcp(self, connection):
        with connection:
            connection.settimeout(1)
            try:
                while not self.stop.is_set():
                    packet = exact(connection, struct.unpack("!H", exact(connection, 2))[0])
                    response = stub_reply(packet)
                    self.records.append({"protocol": "tcp", "query": packet.hex(), "reply": response.hex()})
                    connection.sendall(struct.pack("!H", len(response)) + response)
            except (OSError, EOFError):
                pass


def request(packet, protocol):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        try:
            if protocol == "udp":
                sock.sendto(packet, ("127.0.0.1", 15353))
                reply = sock.recv(65535)
            else:
                sock.connect(("127.0.0.1", 15353))
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                reply = exact(sock, struct.unpack("!H", exact(sock, 2))[0])
            return {"status": "reply", "hex": reply.hex(), "length": len(reply),
                    "header": list(struct.unpack("!6H", reply[:12])) if len(reply) >= 12 else None}
        except socket.timeout:
            return {"status": "timeout"}
        except EOFError:
            return {"status": "eof"}
        except OSError as error:
            return {"status": "socket-error", "errno": error.errno}


def run_profile(root, config, cases, stub):
    (root / "m2/dns.conf").write_text(config)
    result = {"config": config, "cases": [], "processes": {}}
    for index, (label, packet) in enumerate(cases):
        for protocol in ("udp", "tcp"):
            result["cases"].append({"name": label, "protocol": protocol, "query_hex": packet.hex()})
    for side in ("c", "rust"):
        process = subprocess.Popen(command(root, side, "-C", "/m2/dns.conf", "-k", "--user=root", "--group=root", "--pid-file=", "--log-facility=-"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready = False
        for _ in range(30):
            if process.poll() is not None:
                break
            if request(query(), "udp")["status"] == "reply":
                ready = True
                break
            time.sleep(0.01)
        if ready:
            for row in result["cases"]:
                count = len(stub.records)
                row[side] = request(bytes.fromhex(row["query_hex"]), row["protocol"])
                row[side]["upstream"] = stub.records[count:]
            health = request(query(), "udp")
        else:
            health = None
        alive = process.poll() is None
        if alive:
            process.send_signal(signal.SIGTERM)
        try:
            out, err = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()
        result["processes"][side] = {"ready": ready, "health_after": health, "alive_after_cases": alive, "exit": process.returncode, "stderr": err.decode(errors="backslashreplace")}
        print(json.dumps({"side": side, "cases": len(result["cases"]), "ready": ready, "alive": alive}), flush=True)
    for row in result["cases"]:
        row["same_client_result"] = {k: v for k, v in row.get("c", {}).items() if k != "upstream"} == {k: v for k, v in row.get("rust", {}).items() if k != "upstream"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--local-only", action="store_true")
    parser.add_argument("--cases", help="Comma-separated local case names for focused rechecks")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out, args.rust)
    stub = Stub()
    base = "port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\ncache-size=0\nno-round-robin\nlocal-ttl=60\nhost-record=host.audit.test,192.0.2.42,2001:db8::42\n"
    local = base + "local=/audit.test/\ncname=alias.audit.test,host.audit.test\ncname=chain.audit.test,alias.audit.test\ntxt-record=txt.audit.test,hello\nmx-host=mail.audit.test,host.audit.test,10\nsrv-host=_service._tcp.audit.test,host.audit.test,123,1,2\n"
    forwarded = [(scenario, query(scenario + ".example", kind, extra=edns, ar=bool(edns))) for scenario, kind in [
        ("a", 1), ("aaaa", 28), ("nonin", 1), ("cname", 1), ("cname-only", 1),
        ("cname-nx", 1), ("cname-loop", 1), ("mixed", 255), ("large", 16),
        ("truncated", 1), ("ad", 1), ("nxdomain", 1), ("servfail", 1),
        ("bad-rdlen", 1), ("extra-rdlen", 1), ("bad-owner", 1),
        ("private", 1), ("opt", 1), ("opt-version", 1), ("opt-duplicate", 1), ("wrong-type", 1)
    ] for edns in (b"", opt(ttl=0x8000))]
    selected = local_cases()
    if args.cases:
        wanted = set(args.cases.split(","))
        selected = [(label, packet) for label, packet in selected if label in wanted]
        if {label for label, _ in selected} != wanted:
            parser.error("Unknown local case in --cases")
    profiles = {"local": run_profile(root, local, selected, stub)}
    for label, extra in (() if args.local_only else (("forward", ""), ("filter", "filter-AAAA\nfilter-rr=TXT\n"), ("rebind", "stop-dns-rebind\n"))):
        profiles[label] = run_profile(root, base + "server=127.0.0.1#15354\n" + extra, forwarded, stub)
    stub.stop.set()
    result = {"scope": __doc__, "timestamp": time.time(), "c_sha256": sha256(root / "usr/sbin/dnsmasq"), "rust_sha256": sha256(root / "usr/sbin/dnsmasq-rs"), "tool_sha256": sha256(Path(__file__)), "profiles": profiles}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({label: {"cases": len(profile["cases"]), "differences": [{"name": row["name"], "protocol": row["protocol"], "query_hex": row["query_hex"]} for row in profile["cases"] if not row["same_client_result"]]} for label, profile in profiles.items()}, indent=2))


if __name__ == "__main__":
    main()
