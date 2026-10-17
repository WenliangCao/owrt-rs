#!/usr/bin/env python3
"""Analyze a client-cost diagnostic without replacing the frozen-client matrix."""
import argparse
import hashlib
import json
from pathlib import Path

from analyze import stats
from analyze_candidate import METRICS, parallel, read, serial, verify_native_health


def derive(root):
    assert (root / "COMPLETE").exists()
    settings = read(root / "settings.json")
    assert settings["rpc_client_diagnostic"] and not settings["matrix"]
    assert settings["component"] == "rpcd"
    order = read(root / "order.json")
    assert set(order) == {"stock", "candidate"}
    assert order.count("stock") == order.count("candidate")
    subjects = read(root / "subjects.json")
    probe = read(root / "client-probe.json")
    assert probe["diagnostic_only"]
    before, after = read(root / "health-before.json"), read(root / "health-after.json")
    assert before["boot_id"] == after["boot_id"]
    assert (root / "config-before.sha256").read_bytes() == (root / "config-after.sha256").read_bytes()
    host_health = verify_native_health(root, settings, before, after)
    rows, sources, fixtures, identities = [], [], set(), set()
    verified_files = 0
    names = [f"diagnostic_{mode}_64{suffix}" for mode in ("tree", "wire") for suffix in ("", "_c4")]
    for index, side in enumerate(order, 1):
        local = root / f"{index:02d}-{side}"
        raw = local / "raw"
        assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists()
        for line in (local / "raw.sha256").read_text().splitlines():
            digest, name = line.split(None, 1)
            path = (raw / name).resolve()
            assert path.is_relative_to(raw.resolve())
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
            verified_files += 1
        assert (raw / "client-probe-sha256.txt").read_text().split()[0] == probe["sha256"]
        assert (raw / "boot-id.txt").read_text().strip() == before["boot_id"]
        for name in ("binary-sha256.txt", "subject-sha256.txt"):
            assert (raw / name).read_text().split()[0] == subjects[side]
        identities.add(((raw / "benchmark-sha256.txt").read_text(),
                        (raw / "harness-sha256.txt").read_text()))
        fixtures.add((raw / "rpc-fixtures.sha256").read_text())
        mode_order = (raw / "client-probe-order.txt").read_text().split()
        assert mode_order == (["tree", "wire"] if index % 2 else ["wire", "tree"])
        meta = read(raw / "meta.json")
        assert meta["component"] == "rpcd" and meta["dependencies"] == "original OpenWrt"
        subject = meta["subject_pid"]
        sources.append({"run": local.name, "mode_order": mode_order,
                        "archive_sha256": hashlib.sha256((local / "raw.tar.gz").read_bytes()).hexdigest()})
        for name in names:
            result = parallel(raw / name, subject) if name.endswith("_c4") else serial(raw / (name + ".json"), subject)
            expected = max(1, settings["iterations"] // 10)
            if name.endswith("_c4"):
                expected = max(1, expected // 4) * 4
            assert result["successful"] == expected
            rows.append({"run": local.name, "side": side, "workload": name, **result})
    assert len(fixtures) == len(identities) == 1
    summary = {}
    for name in names:
        grouped = {side: {metric: stats(row[metric] for row in rows if row["workload"] == name and row["side"] == side)
                          for metric in METRICS} for side in ("stock", "candidate")}
        grouped["candidate_vs_stock_pct"] = {
            metric: (grouped["candidate"][metric]["median"] / grouped["stock"][metric]["median"] - 1) * 100
            for metric in METRICS if grouped["stock"][metric]["median"] > 0}
        summary[name] = grouped
    return {"diagnostic_only": True, "subjects": subjects, "client_probe_sha256": probe["sha256"], **host_health,
            "repeats_per_side": order.count("stock"), "verified_raw_files": verified_files,
            "host_gates_passed": True, "runs": rows, "summary": summary, "sources": sources,
            "method": "Same diagnostic client binary in both modes. Tree mode decodes and validates the complete fixture on each call; wire mode validates the first warm-up reply semantically and compares every subsequent DATA byte to that immutable reference. No extra uncounted invoke. Four-client CPU uses one outer interval including warmups. Both modes run on the same router CPUs; these data diagnose client contention and do not replace the frozen R84 client matrix."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = derive(args.private)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    for name, group in result["summary"].items():
        print(name, {metric: round(value, 2) for metric, value in group["candidate_vs_stock_pct"].items()})


if __name__ == "__main__":
    main()
