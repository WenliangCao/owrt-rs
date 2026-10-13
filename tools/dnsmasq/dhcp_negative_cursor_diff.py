#!/usr/bin/env python3
"""Exact-C retained-SOA cursor checks: raw/configured CNAME and reverse synthesis."""
import argparse
import itertools
import json
import os
from pathlib import Path
import struct

import dhcp_negative_cache_diff as base
from dns_service_probe import name, read_name, rr
from m2_rootfs import prepare, sha256

REVERSE = "7.2.0.192.in-addr.arpa"


class Upstream(base.Upstream):
    def response(self, packet, transport):
        host, end = read_name(packet, 12)
        kind, cls = struct.unpack_from("!HH", packet, end)
        reverse = host == "seed.reverse.test"
        zone = "2.0.192.in-addr.arpa" if reverse else "test"
        soa = name("ns.test") + name("hostmaster.test") + struct.pack("!5I", 1, 60, 60, 600, base.TTL)
        body = rr(5, name(REVERSE), base.TTL) if reverse else b""
        body += rr(6, soa, base.TTL, name(zone))
        reply = packet[:2] + struct.pack("!5H", 0x8183, 1, int(reverse), 1, 0) + packet[12:end + 4] + body
        self.events.append(dict(transport=transport, host=host, type=kind, **{"class": cls},
                               query=packet.hex(), reply=reply.hex(), enabled=self.enabled))
        return reply if self.enabled else None


def cases():
    raw = "dns-rr=raw.test,5," + name(base.HOST).hex() + "\n"
    for label, config, warm in [
        ("raw-pointer", "dns-rr=raw.test,5,c00c\n", None),
        ("raw-target-nx", raw, base.HOST),
        ("raw-owner-nx", raw, "raw.test"),
    ]:
        yield dict(label=label, config=config, warm=None if warm is None else (warm, 1),
                   prove=None if warm is None else (warm, 1), lease=False,
                   # ANY isolates the raw owner's SOA selection. A CNAME
                   # question with an owner NX has an independent RCODE rule.
                   queries=list(itertools.product(("raw.test",), (255,) if label == "raw-owner-nx" else (5, 255))))
    yield dict(label="configured-cname-stop", config="cname=configured.leases.test,client1.leases.test\n",
               warm=(base.HOST, 1), prove=(base.HOST, 1), lease=True,
               queries=list(itertools.product(("configured.leases.test",), (5, 1))))
    for explicit in (False, True):
        yield dict(label="reverse-explicit" if explicit else "reverse-synth",
                   config="synth-domain=synthetic.test,192.0.2.7,192.0.2.9\ncname=cfgarpa.test," + REVERSE + "\n"
                          + ("ptr-record=" + REVERSE + ",explicit.test\n" if explicit else ""),
                   warm=("seed.reverse.test", 12), prove=(REVERSE, 1), lease=False,
                   queries=list(itertools.product((REVERSE, "cfgarpa.test"), (12, 255))))


def run(root, side, case, out, upstream, config):
    out.mkdir()
    (root / "m2/dns.conf").write_text(config + case["config"])
    (root / "m2/leases").write_bytes(b"")
    daemon = base.ImageDaemon(root, side, case["debug"], out)
    upstream.enabled = True
    first = len(upstream.events)
    result = {"status": "failed", "events": []}

    def dns(label, host, kind, transport="udp"):
        first = len(upstream.events)
        event = base.ask(host, kind, 0x6100 + len(result["events"]), transport)
        event.update(label=label, upstream=upstream.events[first:].copy(), alive=daemon.process.poll() is None)
        result["events"].append(event)
        return event

    try:
        daemon.start()
        if case["warm"]:
            event = dns("warm-negative", *case["warm"])
            assert event["reply"]["flags"] & 15 == 3 and len(event["upstream"]) == 1
            upstream.enabled = False
            event = dns("prove-negative", *case["prove"])
            assert event["reply"]["flags"] & 15 == 3 and not event["upstream"]
            upstream.enabled = True
        if case["lease"]:
            daemon.exchange(1, address="127.0.0.10")
            daemon.exchange(3, address="127.0.0.10", selecting=True)
        for (host, kind), transport in itertools.product(case["queries"], ("udp", "tcp")):
            dns(f"{host}-{kind}-{transport}", host, kind, transport)
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
    summary = {"status": "failed", "config": config, "identities": {
        "c": sha256(root / "usr/sbin/dnsmasq"), "rust": sha256(args.rust), "driver": sha256(__file__),
        "base_driver": sha256(base.__file__), "config_evidence": sha256(args.config_evidence)}, "runs": []}
    upstream = Upstream()
    try:
        for case, debug in itertools.product(cases(), (False, True)):
            case = dict(case, debug=debug)
            label = case["label"] + "-debug" + str(int(debug))
            folder = args.out / label
            folder.mkdir()
            results = {side: run(root, side, case, folder / side, upstream, config) for side in ("c", "rust")}
            row = {"name": label, "case": case, "status": {side: result["status"] for side, result in results.items()}}
            if all(result["status"] == "passed" for result in results.values()):
                row.update(base.compare(results["c"], results["rust"]))
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
