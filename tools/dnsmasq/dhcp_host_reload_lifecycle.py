#!/usr/bin/env python3
"""C-first SIGHUP host-file, leasefile and DNS lifecycle in a private netns.

The first response from a new addn-hosts marker proves the C reload event has
completed. All following DNS replies and lease rows remain in the comparison;
the tester does not wait for an incorrect DHCP name to become correct later.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import time

from dhcp_lease_lifecycle import Daemon
from dhcp_host_lifecycle import event, exchange, equivalent, normalized_rows
from dns_service_probe import query, exchange as dns_exchange, semantics


def hosts(name, address=40, duration=900):
    return f"02:00:00:00:00:01,127.0.0.{address},{name},{duration}\n"


def run(binary, folder, checks):
    folder.mkdir()
    database = folder / "leases"; database.write_bytes(b"")
    bank = folder / "dhcp.hosts"; bank.write_text(hosts("first"))
    marker = folder / "marker.hosts"
    config = folder / "dnsmasq.conf"
    body = ("no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\nno-ping\ndhcp-authoritative\n"
            "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
            "domain=pool.test\n"
            "dhcp-host=02:00:00:00:00:02,127.0.0.41,inline,1200\n"
            f"dhcp-leasefile={database}\ndhcp-hostsfile={bank}\naddn-hosts={marker}\n")
    config.write_text(body)
    marker.write_text("127.0.0.254 stage0.marker.test\n")
    daemon = Daemon(binary.resolve(), config, database, folder, checks, folder.name)
    output = []
    names = ["first", "second", "moved", "restored", "inline", "main-edited"]
    questions = [(name + suffix, 1) for name in names for suffix in ("", ".pool.test", ".changed.test")]
    questions += [(f"{address}.0.0.127.in-addr.arpa", 12) for address in (40, 41, 43)]

    def snapshot(label):
        replies = []
        for index, (name, kind) in enumerate(questions):
            request = query(name, kind, 0x3000 + index)
            reply = dns_exchange(15353, request)
            (folder / f"{label}-{index:02}.dns-request").write_bytes(request)
            (folder / f"{label}-{index:02}.dns-reply").write_bytes(reply)
            replies.append(semantics(reply))
        (folder / f"{label}.leases").write_bytes(database.read_bytes())
        output.append({"label": label, "response": {"dns": replies}, "leases": normalized_rows(database, time.time())})

    def reload(number, label):
        before = database.stat().st_mtime_ns
        marker.write_text(f"127.0.0.254 stage{number}.marker.test\n")
        daemon.process.send_signal(signal.SIGHUP)
        for attempt in range(100):
            assert daemon.process.poll() is None
            response = dns_exchange(15353, query(f"stage{number}.marker.test"))
            if any(record["type"] == 1 and record["data"] == "127.0.0.254" for record in semantics(response)["records"]):
                break
            time.sleep(.025)
        else:
            raise AssertionError("reload completion marker timeout")
        snapshot(label)
        output[-1]["response"]["lease_file_written"] = database.stat().st_mtime_ns != before
        expected_write = label in ("renamed", "recreated-file")
        daemon.check(label + "-lease-file-write", output[-1]["response"]["lease_file_written"], expected_write)

    try:
        daemon.start()
        output.append(exchange(daemon, event("ack-file", 3, address="127.0.0.40", selecting=True)))
        output.append(exchange(daemon, event("ack-inline", 3, client=2, address="127.0.0.41", selecting=True)))
        snapshot("initial")
        # Main configuration changes are intentionally not re-read on SIGHUP.
        config.write_text(body.replace("domain=pool.test", "domain=changed.test")
                          .replace("127.0.0.41,inline", "127.0.0.44,main-edited"))
        bank.write_text(hosts("second", duration=1200) + "bad:hex,127.0.0.46\n")
        reload(1, "renamed")
        bank.write_text(hosts("moved", address=43, duration=1800))
        reload(2, "address-changed-before-ack")
        output.append(exchange(daemon, event("offer-moved")))
        output.append(exchange(daemon, event("ack-moved", 3, address="127.0.0.43", selecting=True)))
        snapshot("address-changed-after-ack")
        bank.write_bytes(b"")
        reload(3, "empty-file")
        output.append(exchange(daemon, event("offer-after-rule-removal")))
        bank.unlink()
        reload(4, "missing-file")
        bank.write_text(hosts("restored", address=43, duration=700))
        reload(5, "recreated-file")
        daemon.stop(); daemon.start()
        snapshot("restart-current-domain")
        assert len(output) == 13
        assert sum("dns" in (row["response"] or {}) for row in output) == 8
        assert all(len(row["response"]["dns"]) == 21 for row in output if "dns" in (row["response"] or {}))
    finally:
        daemon.stop()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-reference", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.inject_error and not args.rust:
        parser.error("--inject-error requires --rust")
    assert os.uname().sysname == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists()
    assert hashlib.sha256(args.c_reference.read_bytes()).hexdigest() == args.c_sha256
    out = args.out.resolve(); assert "private" in out.parts; out.mkdir(parents=True, exist_ok=False)
    checks = []; observed = {}; error = None
    try:
        observed["c"] = run(args.c_reference, out / "c", checks)
        if args.rust:
            observed["rust"] = run(args.rust, out / "rust", checks)
            if args.inject_error:
                observed["rust"][2]["response"]["dns"][0]["flags"] ^= 1
            assert len(observed["c"]) == len(observed["rust"])
            for c, rust in zip(observed["c"], observed["rust"]):
                checks.append({"case": c["label"], "pass": equivalent(rust, c), "c": c, "rust": rust})
    except Exception as failure:
        error = repr(failure)
    failures = [check for check in checks if not check["pass"]]
    result = {"passed": sum(check["pass"] for check in checks), "failed": len(failures), "error": error,
              "checks": checks, "observed": observed, "failures": failures,
              "c_sha256": args.c_sha256, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest() if args.rust else None,
              "scope": "hostfile SIGHUP rename/removal/address change, existing leases, DNS and restart; ordinary selectors only",
              "full_equivalence": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("checks", "observed")}, indent=2))
    return int(bool(failures) or error is not None)


if __name__ == "__main__":
    raise SystemExit(main())
