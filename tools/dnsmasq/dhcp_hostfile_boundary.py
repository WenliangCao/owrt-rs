#!/usr/bin/env python3
"""Check the explicit Rust unsupported-selector boundary; never count as C parity.

C supports tag selectors. Until Rust does, a scoped host rule must pause DHCP
admission rather than silently widening it. All traffic/files are isolated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time

from dhcp_lease_lifecycle import Daemon
from dhcp_host_lifecycle import event, exchange
from dns_service_probe import query, exchange as dns_exchange, semantics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.uname().sysname == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists()
    out = args.out.resolve(); assert "private" in out.parts; out.mkdir(parents=True, exist_ok=False)
    bank = out / "dhcp.hosts"; bank.write_text("02:00:00:00:00:01,127.0.0.40,known,900\n")
    marker = out / "marker.hosts"; marker.write_text("127.0.0.254 stage0.marker.test\n")
    leases = out / "leases"; leases.write_bytes(b"")
    config = out / "dnsmasq.conf"
    config.write_text("no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\nno-ping\ndhcp-authoritative\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                      f"dhcp-hostsfile={bank}\ndhcp-leasefile={leases}\naddn-hosts={marker}\n")
    checks = []; observations = []; error = None
    daemon = Daemon(args.binary.resolve(), config, leases, out, checks, "unsupported-selector")

    def reload(number):
        marker.write_text(f"127.0.0.254 stage{number}.marker.test\n")
        daemon.process.send_signal(signal.SIGHUP)
        for _ in range(100):
            reply = dns_exchange(15353, query(f"stage{number}.marker.test"))
            if any(row["data"] == "127.0.0.254" for row in semantics(reply)["records"]):
                (out / f"reload-{number}.dns-reply").write_bytes(reply)
                return
            time.sleep(.025)
        raise AssertionError("reload marker timed out")

    try:
        daemon.start()
        first = exchange(daemon, event("initial-ack", 3, address="127.0.0.40", selecting=True))
        observations.append(first)
        daemon.check("initial-ack", first["response"] is not None, True)
        original = leases.read_bytes()
        bank.write_text("02:00:00:00:00:01,tag:blocked,127.0.0.40,ignore\n")
        reload(1)
        for item in [event("paused-renewal", 3, address="127.0.0.40"), event("paused-other-client", client=9)]:
            reply = exchange(daemon, item); observations.append(reply)
            daemon.check(item["label"], reply["response"], None)
        daemon.check("paused-retains-lease-bytes", leases.read_bytes(), original)
        bank.write_text("02:00:00:00:00:01,127.0.0.40,recovered,900\n")
        reload(2)
        recovered = exchange(daemon, event("recovered-offer")); observations.append(recovered)
        daemon.check("recovered-offer", recovered["response"] is not None, True)
        daemon.check("recovered-name", recovered["leases"][0]["name"], "recovered")
        daemon.check("unsupported-diagnostic", b"selectors are not implemented" in (out / "daemon-1.log").read_bytes(), True)
    except Exception as failure:
        error = repr(failure)
    finally:
        daemon.stop()
    # Serialize byte comparisons without losing the exact original bytes.
    for check in checks:
        for field in ("actual", "expected"):
            if isinstance(check.get(field), bytes): check[field] = check[field].hex()
    failures = [check for check in checks if not check["pass"]]
    result = {"passed": sum(check["pass"] for check in checks), "failed": len(failures), "error": error,
              "checks": checks, "observations": observations, "failures": failures,
              "rust_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "scope": "Rust-only unsupported-selector pause/recovery contract; deliberately not C functional parity"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    summary = {key: value for key, value in result.items() if key not in ("checks", "observations", "failures")}
    summary["failure_cases"] = [failure["case"] for failure in failures]
    print(json.dumps(summary, indent=2))
    return int(bool(failures) or error is not None)


if __name__ == "__main__":
    raise SystemExit(main())
