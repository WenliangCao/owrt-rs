#!/usr/bin/env python3
"""C-observed payloads versus standalone Rust ubus controller, in isolation.

The Rust fixture has synthetic metric inputs and no DNS/DHCP engine. Passing
this script does not establish product wiring or metric increment correctness.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from ubus_contract_diff import BUS, OBJECT, Fixture, digest, fields, read_json_lines


def raw_fields(wire):
    data = bytes.fromhex(wire)
    result = []
    while data:
        header = int.from_bytes(data[:4], "big")
        size, kind = header & 0xffffff, (header >> 24) & 0x7f
        length = int.from_bytes(data[4:6], "big")
        name = data[6:6 + length].decode("ascii")
        value = data[4 + ((length + 6) & ~3):size]
        result.append((name, kind, value))
        data = data[(size + 3) & ~3:]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {link["ifname"] for link in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build, args.probe = args.reference_build.resolve(), args.probe.resolve()
    assert args.probe.is_file(), "build the standalone probe before entering the namespace"
    baseline = json.loads(args.baseline.read_text())
    assert baseline["passed"] == 256 and baseline["failed"] == 0
    assert baseline["c_sha256"] == digest(args.reference_build / "dnsmasq/dnsmasq")
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dnsmasq-ubus-test", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Fixture(args, out)
    error = None
    process = None
    try:
        f.start_bus()
        # Real daemon name extraction, including non-UTF-8 blobmsg strings.
        f.start_daemon()
        watcher, path = f.watch()
        labels = [b"normal", b"a.b", b"a\\b", b"a\0b", b"a\xffb", b"a\x80b", bytes([1, 2, 31, 127])]
        for index, label in enumerate(labels):
            name = bytes([len(label)]) + label + b"\x07invalid\0"
            query = struct.pack("!HHHHHH", index + 1, 0x100, 1, 0, 0, 0) + name + b"\0\1\0\1"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(query, ("127.0.0.1", 15353))
                answer = sock.recv(65535)
            notices = [row for row in read_json_lines(path) if row["event"] == "notify"]
            f.check(f"name-{index}-notification-count", len(notices), index + 1)
            wire = notices[-1]["wire"]
            decoded = raw_fields(wire)
            name_bytes = decoded[0][2][:-1]
            actual = subprocess.check_output([str(args.probe), "dns", name_bytes.hex(), "120", "192.0.2.1"], text=True).strip()
            expected = list(decoded)
            if args.inject_error and index == 0:
                expected[-1] = ("address", 3, b"192.0.2.254\0")
            f.check(f"name-{index}-payload", raw_fields(actual), expected)
            f.raw.append({"label": label.hex(), "c_name": name_bytes.hex(), "query": query.hex(),
                          "answer": answer.hex(), "c_wire": wire, "rust_wire": actual})
        f.stop(watcher)
        f.stop(f.daemon)

        # C library inet_ntop is the actual formatter used by the reference.
        for address in ["192.0.2.1", "2001:db8::1", "::192.0.2.1", "::ffff:192.0.2.1",
                        "::", "::1", "::101", "::0.1.0.1", "1:0:0:2:0:0:3:4"]:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            expected = socket.inet_ntop(family, socket.inet_pton(family, address))
            actual = subprocess.check_output([str(args.probe), "dns", b"fixture".hex(), str(2**32-1), address], text=True).strip()
            decoded = fields(actual)
            f.check("inet-ntop-" + address, decoded[-1]["value"], expected)
            f.check("ttl-u32-max-" + address, decoded[1]["value"], 2**32-1)

        log = out / "rust-service.log"
        with log.open("wb") as output:
            process = subprocess.Popen([str(args.probe), "serve", BUS, OBJECT], stdin=subprocess.PIPE,
                                       stdout=output, stderr=subprocess.STDOUT, env=f.env)
        f.children.append(process)
        f.daemon = process
        f.wait_registered()

        def command(value, expected):
            start = len(log.read_text().splitlines())
            process.stdin.write((value + "\n").encode())
            process.stdin.flush()
            end = time.monotonic() + 3
            while True:
                lines = log.read_text().splitlines()[start:]
                if expected in lines:
                    return
                assert process.poll() is None and time.monotonic() < end, (value, lines)
                time.sleep(.005)

        def data_rows(rows):
            return [row for row in rows if row["event"] == "data"]

        c_metric_rows = [json.loads(row["stdout"].splitlines()[0]) for row in baseline["raw"]
                         if row.get("method") == "metrics" and '"event":"data"' in row["stdout"]]
        initial_wire, full_wire = c_metric_rows[0]["wire"], c_metric_rows[-1]["wire"]
        f.check("initial-metrics-c-wire", fields(data_rows(f.client_call("call", method="metrics"))[0]["wire"]), fields(initial_wire))
        for object_path in [OBJECT, OBJECT + ".dns"]:
            c_row = next(json.loads(row["stdout"].splitlines()[0]) for row in baseline["raw"]
                         if row.get("action") == "lookup" and row["path"] == object_path and '"event":"lookup"' in row["stdout"])
            r_row = next(row for row in f.client_call("lookup", object_path) if row["event"] == "lookup")
            f.check("signature-" + object_path, fields(r_row["wire"]), fields(c_row["wire"]))
            f.check("typed-object-" + object_path, r_row["type"] > 0, True)
        f.check("missing-method", f.client_call("call", method="set_connmark_allowlist")[-1]["status"], 3)
        watcher, events = f.watch(dns=False)
        dns_watcher, _ = f.watch()
        command("subscribers", "dns-subscribers=true")
        command("events", "sent=true,true")
        f.client_call("call", method="metrics")
        r_events = [row for row in read_json_lines(events) if row["event"] == "notify"]
        c_events = []
        for c_log in sorted(args.baseline.parent.glob("*-subscriber.log")):
            rows = [row for row in read_json_lines(c_log) if row["event"] == "notify" and row["method"].startswith("dhcp.")]
            if rows:
                c_events = rows
                break
        f.check("dhcp-event-semantics", [(row["method"], raw_fields(row["wire"])) for row in r_events],
                [(row["method"], raw_fields(row["wire"])) for row in c_events])
        f.check("live-supplied-metrics-c-wire", fields(data_rows(f.client_call("call", method="metrics"))[0]["wire"]), fields(full_wire))
        command("quiet", "sent=false,false")
        f.check("quiet-no-events", len([row for row in read_json_lines(events) if row["event"] == "notify"]), 2)
        command("quiet-options", "sent=true,true")
        f.client_call("call", method="metrics")
        f.check("quiet-log-options-events", len([row for row in read_json_lines(events) if row["event"] == "notify"]), 4)
        f.stop(watcher)
        f.stop(dns_watcher)
        f.client_call("call", method="metrics")
        command("subscribers", "dns-subscribers=false")
        baseline_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
        for index in range(3):
            f.stop(f.bus)
            f.start_bus()
            f.wait_registered()
            f.check(f"reconnect-{index}-metrics", fields(data_rows(f.client_call("call", method="metrics"))[0]["wire"]), fields(full_wire))
            dns_watcher, _ = f.watch()
            command("subscribers", "dns-subscribers=true")
            f.stop(dns_watcher)
            f.client_call("call", method="metrics")
            command("subscribers", "dns-subscribers=false")
            f.check(f"reconnect-{index}-fds", len(list(Path(f"/proc/{process.pid}/fd").iterdir())), baseline_fds)
            f.check(f"reconnect-{index}-threads", len(list(Path(f"/proc/{process.pid}/task").iterdir())), 1)
        process.stdin.write(b"quit\n")
        process.stdin.flush()
        process.wait(3)
        f.check("normal-exit", process.returncode, 0)
        f.check("drop-removes-objects", f.client_call("lookup")[-1]["status"], 4)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        if process and process.stdin:
            process.stdin.close()
        f.close()
    f.check("frozen-check-count", len(f.checks), 82)
    result = {"scope": "standalone controller/typed payload boundary only; synthetic metric inputs; product integration pending",
              "baseline_sha256": digest(args.baseline), "probe_sha256": digest(args.probe),
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks),
              "checks": f.checks, "raw": f.raw, "error": error}
    (out / "result.json").write_text(json.dumps(result, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: result[key] for key in ["scope", "passed", "failed", "error"]}))
    return bool(result["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
