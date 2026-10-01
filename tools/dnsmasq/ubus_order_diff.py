#!/usr/bin/env python3
"""Observe exact C queued metrics before cache commit, then test controller order.

The C daemon uses real cache counters. Rust's standalone fixture explicitly
stages a counter after doctor_dns returns; this is not a real Rust cache gate.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from ubus_contract_diff import BUS, OBJECT, Fixture, digest, fields, read_json_lines
from ubus_doctor_diff import wait_line


def nested(f, log):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        rows = read_json_lines(log)
        if any(row.get("event") == "nested-metrics-status" for row in rows):
            data = [row for row in rows if row.get("event") == "data"]
            f.check("nested-one-DATA", len(data), 1)
            f.check("nested-status", next(row["status"] for row in rows if row.get("event") == "nested-metrics-status"), 0)
            return {row["name"]: row["value"] for row in fields(data[0]["wire"])}
        time.sleep(.002)
    raise TimeoutError("nested metrics did not finish")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build = args.reference_build.resolve()
    assert digest(args.reference_build / "dnsmasq/dnsmasq") == args.c_sha256
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "ubus-order", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Fixture(args, out)
    error = None
    observations = {}
    try:
        f.start_bus()
        f.start_daemon()
        watcher, log = f.watch("metrics")
        before = f.metrics()
        address, aa, elapsed = f.dns("queued-metrics.invalid")
        during = nested(f, log)
        after = f.metrics()
        observations["C"] = {"before": before, "during": during, "after": after, "dns_ms": elapsed}
        f.check("C-pre-commit-cache", during["dns_cache_inserted"], before["dns_cache_inserted"] + int(args.inject_error))
        f.check("C-after-commit-cache", after["dns_cache_inserted"], before["dns_cache_inserted"] + 1)
        f.check("C-forwarded-before-hook", during["dns_queries_forwarded"], before["dns_queries_forwarded"] + 1)
        f.check("C-post-hook-timeout", elapsed >= 70, True)
        f.stop(watcher)
        f.stop(f.daemon)
        if args.probe:
            probe_log = out / "rust-probe.log"
            with probe_log.open("wb") as stream:
                process = subprocess.Popen([str(args.probe.resolve()), "serve", BUS, OBJECT], stdin=subprocess.PIPE,
                                           stdout=stream, stderr=subprocess.STDOUT, env=f.env)
            f.children.append(process)
            f.daemon = process
            f.wait_registered()
            watcher, log = f.watch("metrics")
            before = f.metrics()
            start = len(probe_log.read_text().splitlines())
            process.stdin.write(b"doctor-stage 6f726465722e696e76616c6964 120 192.0.2.1\n")
            process.stdin.flush()
            result = wait_line(process, probe_log, start, "doctor-")
            f.check("Rust-doctor-completed", result[0], "doctor-result")
            during = nested(f, log)
            after = f.metrics()
            observations["Rust-fixture"] = {"before": before, "during": during, "after": after}
            f.check("Rust-pre-return-snapshot", during["dns_cache_inserted"], before["dns_cache_inserted"])
            f.check("Rust-post-return-stage", after["dns_cache_inserted"], before["dns_cache_inserted"] + 1)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    report = {"scope": __doc__, "error": error, "checks": f.checks, "raw": f.raw, "observations": observations,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks)}
    (out / "result.json").write_text(json.dumps(report, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "error")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
