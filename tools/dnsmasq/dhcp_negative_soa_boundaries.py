#!/usr/bin/env python3
"""C/Rust direct and cached-alias SOA footer boundaries after a DHCP ACK."""
import argparse
import itertools
import json
import os
from pathlib import Path
import socket
import struct
import time

import dhcp_negative_cache_diff as base
from dns_service_probe import exact_read, name, query, read_name, rr, semantics
from m2_rootfs import prepare, sha256

ALIAS = "alias.leases.test"


class Upstream(base.Upstream):
    large = False

    def response(self, packet, transport):
        host, end = read_name(packet, 12)
        kind, cls = struct.unpack_from("!HH", packet, end)
        soa_name = lambda label: ".".join([label * 63] * 3 + [label * 61]) if self.large else label + ".leases.test"
        soa = name(soa_name("n")) + name(soa_name("r")) + struct.pack("!5I", 1, 60, 60, 600, base.TTL)
        alias = host == ALIAS
        body = rr(5, name(base.HOST), base.TTL) if alias else b""
        body += rr(6, soa, base.TTL, name("leases.test"))
        reply = packet[:2] + struct.pack("!5H", 0x8183, 1, int(alias), 1, 0) + packet[12:end + 4] + body
        self.events.append({"transport": transport, "host": host, "type": kind, "class": cls,
                            "query": packet.hex(), "reply": reply.hex(), "enabled": self.enabled})
        return reply if self.enabled else None


def ask(host, ident, transport, rd=True, do=False, size=4096):
    packet = bytearray(query(host, 1, ident))
    struct.pack_into("!H", packet, 2, 0x100 if rd else 0)
    struct.pack_into("!H", packet, 10, 1)
    packet += b"\0" + struct.pack("!HHIH", 41, size, 0x8000 if do else 0, 0)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(("127.0.0.1", 15353))
        if transport == "tcp":
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            response = exact_read(sock, struct.unpack("!H", exact_read(sock, 2))[0])
        else:
            sock.send(packet)
            response = sock.recv(65535)
    return dict(started=started, ended=time.monotonic(), request=packet.hex(), packet=response.hex(), reply=semantics(response))


def run(root, side, case, out, upstream):
    out.mkdir()
    result = {"status": "failed", "events": []}
    daemon = base.ImageDaemon(root, side, case["debug"], out)
    (root / "m2/leases").write_bytes(b"")
    upstream.large = case["large"]
    upstream.enabled = True
    first = len(upstream.events)

    def dns(label, host, transport="udp", **kwargs):
        first = len(upstream.events)
        event = ask(host, 0x6000 + len(result["events"]), transport, **kwargs)
        event.update(label=label, upstream=upstream.events[first:].copy(), alive=daemon.process.poll() is None)
        result["events"].append(event)
        return event

    try:
        daemon.start()
        initial = dns("warm-cached-alias", ALIAS)
        assert initial["reply"]["flags"] & 15 == 3 and len(initial["upstream"]) == 1
        upstream.enabled = False
        warm = dns("prove-target-nxdomain", base.HOST)
        assert warm["reply"]["flags"] & 15 == 3 and not warm["upstream"]
        upstream.enabled = True
        daemon.exchange(1, address="127.0.0.10")
        daemon.exchange(3, address="127.0.0.10", selecting=True)
        event = dns("ack-visible-a", base.HOST)
        assert event["reply"]["flags"] & 15 == 0 and event["reply"]["records"][0]["data"] == "127.0.0.10"
        dns("boundary", case["host"], case["transport"], rd=case["rd"], do=case["do"], size=512)
        daemon.stop()
        assert all(check["pass"] for check in daemon.checks)
        result["status"] = "passed"
    except Exception as error:
        result["error"] = repr(error)
    finally:
        daemon.stop()
        result.update(dhcp_checks=daemon.checks, dhcp_replies=daemon.responses, upstream=upstream.events[first:])
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image-root", type=Path, required=True)
    p.add_argument("--rust", type=Path, required=True)
    p.add_argument("--config-evidence", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and "private" in args.out.parts
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out, args.rust)
    config = json.loads(args.config_evidence.read_text())["config"]
    (root / "m2/dns.conf").write_text(config)
    summary = {"status": "failed", "identities": {"c": sha256(root / "usr/sbin/dnsmasq"), "rust": sha256(args.rust),
               "driver": sha256(__file__), "base_driver": sha256(base.__file__)}, "config": config, "runs": []}
    upstream = Upstream()
    try:
        for large, debug, host, transport, rd, do in itertools.product((False, True), (False, True),
                    (base.HOST, ALIAS), ("udp", "tcp"), (False, True), (False, True)):
            case = dict(large=large, debug=debug, host=host, transport=transport, rd=rd, do=do)
            label = f"large{int(large)}-debug{int(debug)}-{host.split('.')[0]}-{transport}-rd{int(rd)}-do{int(do)}"
            folder = args.out / label
            folder.mkdir()
            results = {side: run(root, side, case, folder / side, upstream) for side in ("c", "rust")}
            row = {"name": label, **case, "status": {side: result["status"] for side, result in results.items()}}
            if all(result["status"] == "passed" for result in results.values()):
                row.update(base.compare(results["c"], results["rust"]))
                row["boundary"] = {side: result["events"][-1] for side, result in results.items()}
            else:
                row["errors"] = {side: result.get("error") for side, result in results.items()}
            summary["runs"].append(row)
            (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps({"name": label, "status": row["status"], "differences": len(row.get("differences", [])),
                              "errors": row.get("errors")}), flush=True)
        summary["status"] = "passed" if all(all(value == "passed" for value in row["status"].values())
                                              and not row.get("differences") for row in summary["runs"]) else "failed"
    finally:
        upstream.close()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return int(summary["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
