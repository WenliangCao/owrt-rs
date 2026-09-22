#!/usr/bin/env python3
"""Collect or verify the three-window R131 fixed-payload memory diagnostic."""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys

import r124_event_memory_report as raw

ROOT = Path(__file__).resolve().parents[1]
PHASES = [("empty", 0)] + [(phase, delay) for phase in
          ("connected", "held_1", "held_1000", "held_10000", "disconnected") for delay in (1, 5)]


def load(path):
    return json.loads(Path(path).read_text())


def inputs(plan):
    assert [row["subject"] for row in plan["runs"]] == ["c", "r124", "r131"]
    for item in [*plan["subjects"].values(), *plan["files"].values()]:
        assert raw.digest(ROOT / item["path"]) == item["sha256"], item["path"]
    smoke = plan["oracle_validation"]
    assert raw.digest(ROOT / smoke["path"]) == smoke["sha256"]
    evidence = load(ROOT / smoke["path"])
    assert evidence["passed"] is True and len(evidence["cases"]) == 3
    assert evidence["helper_sha256"] == plan["files"]["helper"]["sha256"]


def mappings(path):
    result = {"anonymous_rw_kb": 0, "heap_rw_kb": 0, "stack_rw_kb": 0, "other_rw_kb": 0}
    for line in path.read_text().splitlines():
        fields = line.split(None, 5)
        start, end = [int(x, 16) for x in fields[0].split("-")]
        assert end > start and (end - start) % 1024 == 0
        if fields[1] != "rw-p":
            continue
        name = fields[5] if len(fields) > 5 else ""
        kind = "anonymous" if not name else "heap" if name == "[heap]" else "stack" if name == "[stack]" else "other"
        result[kind + "_rw_kb"] += (end - start) // 1024
    return result


def window(root, spec, plan):
    folder = root / spec["name"]
    result = load(folder / "result.json")
    assert all(result[k] is True for k in raw.HEALTH)
    assert result["exit"] == 0 and result["production_mode"] == "stock" and result["installed"] is False
    assert result["iterations"] == 10000 and result["component"] == "ubusd" and result["pilot_only"] is True
    label = spec["subject"]
    sha = plan["subjects"][label]["sha256"]
    assert result["candidate_sha256"] == sha and result["implementation"] == ("c" if label == "c" else "rs")
    for key in ("driver", "guard", "recovery_gate", "workload"):
        assert result[key + "_sha256"] == plan["files"][key]["sha256"]
    assert result["benchmark_sha256"] == plan["files"]["helper"]["sha256"]
    before, after = load(folder / "health-before.json"), load(folder / "health-after.json")
    assert before == after and before["boot_id"] == plan["boot_id"]
    archive = raw.verify_archive(folder)
    evidence = folder / "raw"
    assert (evidence / "COMPLETE").is_file()
    assert raw.hashes(evidence / "libraries.sha256") == plan["libraries"]
    assert raw.hashes(evidence / "benchmark-sha256.txt") == {
        "/tmp/bin/owrt-benchmark": plan["files"]["helper"]["sha256"],
        "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"],
        "/tmp/bin/guard": plan["files"]["guard"]["sha256"]}
    assert raw.hashes(evidence / "workload-sha256.txt") == {"/tmp/workload.sh": plan["files"]["workload"]["sha256"]}
    assert load(evidence / "meta.json") == {"implementation": "c" if label == "c" else "rs",
        "payload_bytes": 1024, "event_checkpoints": [1, 1000, 10000], "handlers": 8,
        "subject_cpu": 1, "client_cpu": 0, "phase_delays_seconds": [1, 5], "small_payload_bytes": 16}
    case = evidence / "1024"
    pid, start = raw.process_identity(case / "stat-start.txt")
    base = int((case / "baseline-fds.txt").read_text())
    phases = [json.loads(line) for line in (case / "helper.jsonl").read_text().splitlines()]
    expected = [("READY", 8), ("DELIVERED_1", 16), ("DELIVERED_1000", 8008),
                ("DELIVERED_10000", 80008), ("CLOSED", 80008)]
    assert [(x["phase"], x["total_received"]) for x in phases] == expected
    for i, row in enumerate(phases):
        assert row["received"] == 8 and row["subject_pid"] == pid and row["base_fds"] == base
        assert row["subject_cpu"] == 1 and row["client_cpu"] == 0
        assert row["payload_checked"] is True and row["listener_barrier"] is True
        assert row["holding"] is (i < 4) and row["handlers_removed"] is (i == 4)
        assert row["payload_bytes"] == (16 if i == 0 else 1024)
        assert all(row[k] == v for k, v in raw.encoded_lengths(row["payload_bytes"]).items())
    assert len({x["helper_pid"] for x in phases}) == 1
    assert all(a["monotonic_ns"] < b["monotonic_ns"] for a, b in zip(phases, phases[1:]))
    assert (case / "helper-exit.txt").read_text().strip() == "0" and not (case / "helper.log").read_bytes()
    assert (case / "daemon-exit.txt").read_text().strip() in ("0", "143")
    rows = list(csv.DictReader((evidence / "memory.csv").open()))
    assert [(r["phase"], int(r["delay_seconds"])) for r in rows] == PHASES
    verified = []
    for row in rows:
        phase, delay = row["phase"], int(row["delay_seconds"])
        prefix = case / f"{phase}-{delay}"
        assert int(row["payload_bytes"]) == 1024 and int(row["daemon_pid"]) == pid
        for when in ("before", "after"):
            assert raw.process_identity(Path(str(prefix) + f"-stat-{when}.txt")) == (pid, start)
        values = raw.status_metrics(Path(str(prefix) + "-status.txt"), pid)
        values["pss_kb"] = raw.pss_value(prefix)
        assert all(row[k] == str(v) for k, v in values.items())
        assert raw.hashes(Path(str(prefix) + "-exe.sha256")) == {f"/proc/{pid}/exe": sha}
        assert Path(str(prefix) + "-cmdline.txt").read_text().splitlines() == ["/sbin/ubusd", "-s", raw.SOCKET]
        fds = Path(str(prefix) + "-fds.txt").read_text().splitlines()
        expected_fds = base if phase in ("empty", "disconnected") else base + 2
        assert len(fds) == len(set(fds)) == int(row["fds"]) == expected_fds
        if phase != "empty":
            assert raw.uptime(Path(str(prefix) + "-uptime.txt")) - raw.uptime(case / f"{phase}-start-uptime.txt") >= raw.Decimal(delay) - raw.Decimal(".02")
        verified.append({"phase": phase, "delay_seconds": delay, **values,
                         "mappings": mappings(Path(str(prefix) + "-maps.txt"))})
    last = {r["phase"]: r for r in verified if r["delay_seconds"] == 5}
    growth = {metric: {point: last[point][metric] - last["held_1"][metric]
                      for point in ("held_1000", "held_10000", "disconnected")}
              for metric in ("rssanon_kb", "vmdata_kb")}
    return {"subject": label, "phases": phases, "memory": verified, "growth_from_first_event_kib": growth,
            "raw_archive_sha256": raw.digest(folder / "raw.tar.gz"), "raw_files": archive}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("run", "report")); p.add_argument("plan", type=Path); p.add_argument("output", type=Path)
    a = p.parse_args(); plan = load(a.plan); inputs(plan)
    if a.mode == "run":
        a.output.mkdir(parents=True, exist_ok=False)
        (a.output / "plan.json").write_bytes(a.plan.read_bytes())
        for spec in plan["runs"]:
            files = plan["files"]
            cmd = [sys.executable, str(ROOT / files["driver"]["path"]), "ubusd",
                   str(ROOT / plan["subjects"][spec["subject"]]["path"]), str(a.output / spec["name"]),
                   "--pilot", "--iterations", "10000", "--implementation", "c" if spec["subject"] == "c" else "rs"]
            for flag, name in (("--guard", "guard"), ("--recovery-gate", "recovery_gate"),
                               ("--benchmark", "helper"), ("--workload-script", "workload")):
                cmd += [flag, str(ROOT / files[name]["path"])]
            print("START", spec["name"], flush=True)
            with (a.output / (spec["name"] + ".log")).open("xb") as log:
                subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, check=True)
            window(a.output, spec, plan)
            print("VERIFIED", spec["name"], flush=True)
        (a.output / "COMPLETE").touch()
    assert (a.output / "COMPLETE").exists() and load(a.output / "plan.json") == plan
    rows = [window(a.output, spec, plan) for spec in plan["runs"]]
    (a.output / "report.json").write_text(json.dumps({"scope": "Fixed 1 KiB × eight-handler residency plateau",
        "plan_sha256": raw.digest(a.plan), "reporter_sha256": raw.digest(Path(__file__)), "windows": rows,
        "limits": ["One window per exact ELF; diagnostic only, not statistical memory superiority.",
                   "Samples after drain barriers; not peak allocator or kernel socket accounting.",
                   "Maps classify private writable virtual mappings; this does not prove allocator ownership."]}, indent=2) + "\n")


if __name__ == "__main__":
    main()
