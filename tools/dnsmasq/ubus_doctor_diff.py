#!/usr/bin/env python3
"""Real C DNS doctor responses versus the Rust controller hook, private ubusd.

All C observations are completed before the Rust fixture runs. Rust never
generates expected results. This tests the hook, not product DNS/cache wiring.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import signal

from ubus_contract_diff import BUS, OBJECT, ORIGINAL, Fixture, digest, read_json_lines


def field(name, kind, data, terminator=0, extended=True):
    name = name.encode()
    header = struct.pack("!H", len(name)) + name + bytes([terminator])
    header += bytes((-len(header)) % 4)
    payload = (header if extended else b"") + data
    raw = struct.pack("!I", (0x80000000 if extended else 0) | kind << 24 | (4 + len(payload))) + payload
    return raw + bytes((-len(raw)) % 4)


def cases():
    address = lambda value: field("address", 3, value)
    good = address(b"192.0.2.9\0")
    bad = address(b"invalid\0")
    raw = lambda value: "raw:" + value.hex()
    entries = [
        ("unsubscribed", 1, []),
        ("no-data", 1, [("none", 0)]),
        ("ipv4", 1, [("192.0.2.9", 0)]),
        ("ipv6", 28, [("2001:db8::9", 0)]),
        ("same", 1, [(ORIGINAL[1], 0)]),
        ("invalid", 1, [("invalid", 0)]),
        ("wrong-family4", 1, [("2001:db8::9", 0)]),
        ("wrong-family6", 28, [("192.0.2.9", 0)]),
        ("wrong-type", 1, [("u32", 0)]),
        ("error-status", 1, [("error", 0)]),
        ("delay", 1, [("192.0.2.9", 30)]),
        ("late", 1, [("192.0.2.9", 180)]),
        ("silent", 1, [("silent", 0)]),
        ("disconnect", 1, [("disconnect", 0)]),
        ("duplicate-good-first", 1, [(raw(good + bad), 0)]),
        ("duplicate-bad-first", 1, [(raw(bad + good), 0)]),
        ("multiple-data-good-last", 1, [(raw(bad) + "," + good.hex(), 0)]),
        ("multiple-data-bad-last", 1, [(raw(good) + "," + bad.hex(), 0)]),
        ("multiple-data-wrongtype-last", 1, [(raw(good) + "," + field("address", 5, b"\0\0\0\1").hex(), 0)]),
        ("data-without-status", 1, [("rawsilent:" + good.hex(), 0)]),
        ("first-peer-valid-last-invalid", 1, [("192.0.2.9", 0), ("invalid", 30)]),
        ("first-peer-invalid-last-valid", 1, [("invalid", 0), ("192.0.2.9", 30)]),
        ("one-peer-silent", 1, [("192.0.2.9", 0), ("silent", 0)]),
        ("string-interior-nul", 1, [(raw(address(b"192.0.2.9\0ignored\0")), 0)]),
        ("string-final-nul-missing", 1, [(raw(address(b"192.0.2.9\0ignored")), 0)]),
        ("empty-string-payload", 1, [(raw(address(b"")), 0)]),
        ("empty-string", 1, [(raw(address(b"\0")), 0)]),
        ("string-invalid-utf8", 1, [(raw(address(b"192.0.2.9\xff\0")), 0)]),
        ("name-no-terminator", 1, [(raw(field("address", 3, b"192.0.2.9\0", terminator=1)), 0)]),
        ("malformed-before-address", 1, [(raw(field("other", 5, b"\0\0\0") + good), 0)]),
        ("malformed-after-address", 1, [(raw(good + field("other", 5, b"\0\0\0")), 0)]),
        ("unknown-type-before-address", 1, [(raw(field("other", 9, b"") + good), 0)]),
        ("unknown-name-before-address", 1, [(raw(field("other", 5, b"\0\0\0\1") + good), 0)]),
        ("unextended-before-address", 1, [(raw(field("", 3, b"ignored\0", extended=False) + good), 0)]),
        ("double-minimum-before-address", 1, [(raw(field("other", 8, bytes(9)) + good), 0)]),
        ("double-short-before-address", 1, [(raw(field("other", 8, bytes(7)) + good), 0)]),
    ]
    assert len(entries) == 36
    return entries


def wait_line(process, log, start, prefix):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        lines = log.read_text().splitlines()[start:]
        found = next((line for line in lines if line.startswith(prefix)), None)
        if found:
            return found.split()
        assert process.poll() is None, lines
        time.sleep(.002)
    raise TimeoutError((prefix, lines))


def reference_lifetime(f, out):
    """C/C check: identical DNS query, varying irrelevant later DATA payload."""
    observations = []
    error = None
    try:
        f.start_bus()
        f.start_daemon()
        log = next(out.glob("*-dnsmasq.log"))
        initial = field("address", 3, b"192.0.2.9\0").hex()
        variants = [
            ("empty", b""),
            ("different-type", field("address", 5, b"\0\0\0\1")),
            ("short-note", field("note", 3, b"ok\0")),
            ("medium-note", field("note", 3, b"message received\0")),
            ("long-note", field("note", 3, b"received " * 8 + b"\0")),
        ]
        for label, later in variants:
            before = log.read_text().count("cleared cache")
            f.daemon.send_signal(signal.SIGHUP)
            end = time.monotonic() + 2
            while log.read_text().count("cleared cache") == before:
                assert time.monotonic() < end and f.daemon.poll() is None
                time.sleep(.002)
            watcher, _ = f.watch("raw:" + initial + "," + later.hex())
            address, aa, elapsed = f.dns("reference-lifetime.invalid")
            observations.append({"later_kind": label, "later_bytes": len(later),
                                 "address": address, "aa": aa, "ms": elapsed})
            f.stop(watcher)
        queries = [item["query"] for item in f.raw if item.get("name") == "reference-lifetime.invalid"]
        f.check("C-C-identical-DNS-input", len(set(queries)), 1)
        f.check("C-C-later-DATA-changes-result", len({(item["address"], item["aa"]) for item in observations}) > 1, True)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    result = {"scope": "C/C response-storage-lifetime diagnostic; this confirms a reference defect, not compatibility",
              "error": error, "observations": observations, "checks": f.checks, "raw": f.raw,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks)}
    (out / "result.json").write_text(json.dumps(result, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: result[key] for key in ["scope", "passed", "failed", "error"]}))
    return bool(result["failed"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    parser.add_argument("--reference-lifetime", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {link["ifname"] for link in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build, args.probe = args.reference_build.resolve(), args.probe.resolve()
    assert digest(args.reference_build / "dnsmasq/dnsmasq") == args.c_sha256
    assert args.probe.is_file()
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dnsmasq-doctor", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Fixture(args, out)
    if args.reference_lifetime:
        return reference_lifetime(f, out)
    expected, observations = {}, []
    error = None
    process = None
    try:
        f.start_bus()
        f.start_daemon()
        for label, kind, subscribers in cases():
            watchers = [f.watch(response, delay)[0] for response, delay in subscribers]
            address, aa, elapsed = f.dns(label + ".invalid", kind)
            expected[label] = {"address": address, "aa": aa, "ms": elapsed}
            for child in watchers:
                f.stop(child)
        f.check("C-case-count", len(expected), 36)
        f.check("C-success-calibration", sum(not item["aa"] for item in expected.values()) > 8, True)
        f.check("C-rejected-calibration", sum(item["aa"] for item in expected.values()) > 8, True)
        (out / "c-observations.json").write_text(json.dumps(expected, indent=2) + "\n")
        f.stop(f.daemon)
        log = out / "rust-service.log"
        with log.open("wb") as stream:
            process = subprocess.Popen([str(args.probe), "serve", BUS, OBJECT], stdin=subprocess.PIPE,
                                       stdout=stream, stderr=subprocess.STDOUT, env=f.env)
        f.children.append(process)
        f.daemon = process
        f.wait_registered()
        base_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))

        def doctor(label, kind=1, cancel=False):
            start = len(log.read_text().splitlines())
            value = f"{'doctor-cancel' if cancel else 'doctor'} {(label + '.invalid').encode().hex()} 120 {ORIGINAL[kind]}\n"
            process.stdin.write(value.encode())
            process.stdin.flush()
            result = wait_line(process, log, start, "doctor-")
            if result[0] == "doctor-error":
                return {"error": result[1], "ms": int(result[2]) / 1000}
            replacement = None if result[1] == "-" else result[1]
            return {"address": replacement or ORIGINAL[kind], "aa": replacement is None, "ms": int(result[2]) / 1000}

        for label, kind, subscribers in cases():
            watchers = [f.watch(response, delay)[0] for response, delay in subscribers]
            # Ensure removals from the previous case reached the owner, even
            # when this case deliberately has no subscribers.
            f.client_call("call", method="metrics")
            actual = doctor(label, kind)
            comparison = {key: value for key, value in expected[label].items() if key != "ms"}
            if args.inject_error and label == "unsubscribed":
                comparison["address"] = "192.0.2.254"
            f.check(label + "-semantics", {key: value for key, value in actual.items() if key != "ms"}, comparison)
            f.check(label + "-bounded-wall-time", actual["ms"] < 500, True)
            if label == "unsubscribed":
                f.check("no-subscriber-no-wait", actual["ms"] < 10, True)
            if label in ["late", "silent", "data-without-status", "one-peer-silent"]:
                f.check(label + "-100ms-deadline", 75 <= actual["ms"] < 500, True)
            observations.append({"case": label, "c": expected[label], "rust": actual})
            for child in watchers:
                f.stop(child)
            f.client_call("call", method="metrics")
            f.check(label + "-fd-released", len(list(Path(f"/proc/{process.pid}/fd").iterdir())), base_fds)

        # A timed-out subscriber delivers replies while subsequent requests run.
        watcher, _ = f.watch("192.0.2.9", 180)
        for index in range(3):
            result = doctor(f"late-sequence-{index}")
            f.check("late-sequence-original", [result.get("address"), result.get("aa")], [ORIGINAL[1], True])
        f.stop(watcher)
        f.client_call("call", method="metrics")
        watcher, _ = f.watch("silent")
        result = doctor("cancel", cancel=True)
        f.check("cancel-status", result.get("error"), "Interrupted")
        f.check("cancel-deadline", result["ms"] < 75, True)
        f.stop(watcher)
        f.wait_registered()
        watcher, _ = f.watch("192.0.2.8")
        result = doctor("after-cancel")
        f.check("after-cancel-reconnected", [result.get("address"), result.get("aa")], ["192.0.2.8", False])
        f.stop(watcher)
        f.check("final-fd-release", len(list(Path(f"/proc/{process.pid}/fd").iterdir())), base_fds)
        process.stdin.write(b"quit\n")
        process.stdin.flush()
        process.wait(3)
        f.check("normal-exit", process.returncode, 0)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        if process and process.stdin:
            process.stdin.close()
        f.close()
    if len(f.checks) != 474:
        f.check("frozen-check-count", len(f.checks), 474)
    result = {"scope": "synchronous controller hook, not product DNS/cache integration", "error": error,
              "planned_checks": 474,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks),
              "checks": f.checks, "observations": observations, "raw": f.raw,
              "c_sha256": args.c_sha256, "probe_sha256": digest(args.probe)}
    (out / "result.json").write_text(json.dumps(result, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: result[key] for key in ["scope", "passed", "failed", "error"]}))
    return bool(result["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
