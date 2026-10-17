#!/usr/bin/env python3
"""Derive held-connection HTTPD memory, keeping process identifiers private."""
import argparse
import hashlib
import json
from pathlib import Path

from analyze import stats
from analyze_candidate import verify_native_health
from analyze_httpd import read

FIELDS = ("VmRSS", "RssAnon", "RssFile", "VmHWM", "VmPTE", "Threads", "fds")


def derive(root):
    assert (root / "COMPLETE").exists(), "collector did not finish its host gates"
    settings = read(root / "settings.json")
    assert settings["held_connections"] == 64 and not settings["matrix"]
    before, after = read(root / "health-before.json"), read(root / "health-after.json")
    assert before["boot_id"] == after["boot_id"]
    assert (root / "config-before.sha256").read_bytes() == (root / "config-after.sha256").read_bytes()
    host_health = verify_native_health(root, settings, before, after)
    subjects, order = read(root / "subjects.json"), read(root / "order.json")
    assert set(order) == {"stock", "candidate"} and order.count("stock") == order.count("candidate")
    probe = read(root / "memory-probe.json")["sha256"]
    rows, identities = [], set()
    for index, side in enumerate(order, 1):
        local = root / f"{index:02d}-{side}"
        raw = local / "raw"
        assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists()
        meta = read(raw / "meta.json")
        assert meta["component"] == "httpd" and meta["dependencies"] == "original OpenWrt"
        assert meta["iterations"] == 128
        assert (raw / "boot-id.txt").read_text().strip() == before["boot_id"]
        for filename in ("binary-sha256.txt", "subject-sha256.txt"):
            assert (raw / filename).read_text().split()[0] == subjects[side]
        assert (raw / "memory-probe-sha256.txt").read_text().split()[0] == probe
        identities.add(tuple(line.split()[0] for line in (raw / "benchmark-sha256.txt").read_text().splitlines())
                       + ((raw / "harness-sha256.txt").read_text().split()[0],))
        memory = read(raw / "memory.json")
        assert memory["connections"] == 64 and memory["response_bytes"] == 16384
        assert memory["requests_per_connection"] == 2
        initial, held, closed = (memory[key] for key in ("before", "held", "after_close"))
        assert {p["pid"] for p in (initial, held, closed)} == {meta["subject_pid"]}
        assert len({p["start_ticks"] for p in (initial, held, closed)}) == 1
        assert held["fds"] == initial["fds"] + 64
        assert closed["fds"] == initial["fds"] and closed["Threads"] == initial["Threads"]
        rows.append({"run": local.name, "side": side,
                     **{key: {field: memory[key][field] for field in FIELDS}
                        for key in ("before", "held", "after_close")},
                     "held_rss_growth_kib": held["VmRSS"] - initial["VmRSS"],
                     "held_anon_growth_kib": held["RssAnon"] - initial["RssAnon"],
                     "archive_sha256": hashlib.sha256((local / "raw.tar.gz").read_bytes()).hexdigest(),
                     "kernel": (raw / "kernel.txt").read_text().strip()})
    assert len(identities) == 1, "benchmark or harness changed between sides"
    return {"schema_version": 1, "subjects": {side: subjects[side] for side in ("stock", "candidate")}, **host_health,
            "memory_probe_sha256": probe, "host_gates_passed": True, "connections": 64,
            "response_bytes": 16384, "requests_per_connection": 2, "order": order,
            "rows": rows,
            "summary": {side: {key: stats(r[key] for r in rows if r["side"] == side)
                               for key in ("held_rss_growth_kib", "held_anon_growth_kib")}
                        for side in ("stock", "candidate")},
            "method": "Fresh isolated daemons on the router; /proc/status samples before, with 64 held clients, and after close. RSS is not PSS/USS or global physical-memory usage. VmHWM is an approximate sample. No latency benchmark is performed by this diagnostic client."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = derive(args.private)
    with args.output.open("x") as target:
        json.dump(result, target, indent=2)
        target.write("\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
