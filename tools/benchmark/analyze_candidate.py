#!/usr/bin/env python3
"""Publish derived component timings, resource counts and executable hashes."""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

from analyze import COMPONENT_WORK, logd_idle, memory, native, stats, timing

STATIC = ("static_512_dat", "static_16k_dat", "static_16k_css",
          "static_image_css", "static_64k_dat", "static_1m_dat")
RPCD_EXTRA = ("uci_get_64", "uci_get_authorized", "session_access_granted", "file_list", "session_access_64")
PROCD_EXTRA = ("service_list_128", "service_list_named_128")
UBUSD_EXTRA = ("lookup_prefix_64", "lookup_all_128")
UBUSD_EXTENDED = ("register_1", "register_16", "event_1", "event_8", "event_nomatch")
NETIFD_SERIAL = ("reload_unchanged", "events_static2")
TREE_METRICS = ("subject_tree_cpu_us_per_op", "dependency_tree_cpu_us_per_op", "client_tree_cpu_us_per_op")
NETIFD_EXTRA = ("device_status_all", "interface_dump_32", "interface_named_32")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "ops_per_s",
           "subject_cpu_us_per_op", "dependency_cpu_us_per_op", "client_cpu_us_per_op")
CLOCK_METRICS = ("subject_own_cpu_clock_us_per_op", "dependency_own_cpu_clock_us_per_op",
                 "client_cpu_clock_us_per_op")


def read(path):
    return json.loads(path.read_text())


def process_clock_delta(before, after):
    assert before["pid"] == after["pid"] and before["start_ticks"] == after["start_ticks"], "CPU clock process replaced"
    assert before["process_cpu_resolution_ns"] == after["process_cpu_resolution_ns"] > 0, "CPU clock resolution changed"
    delta = after["process_cpu_ns"] - before["process_cpu_ns"]
    assert delta >= 0, "process CPU clock regressed"
    return delta


def resource_pair(before, after, subject, pid=None):
    pid = before.get("pid", pid)
    assert pid is not None and after.get("pid", pid) == pid
    assert before["start_ticks"] == after["start_ticks"]
    fields = ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "fds", "Threads",
              "process_cpu_resolution_ns", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")
    return {"pid": pid, "role": "subject" if pid == subject else "dependency",
            "before": {key: before[key] for key in fields if key in before},
            "after": {key: after[key] for key in fields if key in after}}


def role_groups(data, subject, roles):
    processes = {p["pid"]: p for p in data["daemon_cpu"]}
    assert len(processes) == len(data["daemon_cpu"]), "duplicate monitored PID"
    if roles is None:
        return {"subject": [subject] if subject is not None else [],
                "dependency": [pid for pid in processes if pid != subject], "caller_instrumentation": []}
    assert roles["schema"] == 1
    records = roles["processes"]
    assert len({r["pid"] for r in records}) == len(records), "duplicate role PID"
    assert {r["pid"] for r in records} == processes.keys(), "roles must cover every monitored PID"
    groups = {role: [] for role in ("subject", "dependency", "caller_instrumentation")}
    for record in records:
        pid = record["pid"]; process = processes[pid]
        assert record["role"] in groups
        assert record["start_ticks"] == process["before"]["start_ticks"] == process["after"]["start_ticks"], "role PID replaced"
        groups[record["role"]].append(pid)
    assert groups["subject"] == [subject], "subject role mismatch"
    return groups


def child_cpu_parent(before, after, hz, *, caller=False, proc_child_s=None):
    assert hz > 0 and before["pid"] == after["pid"] and before["start_ticks"] == after["start_ticks"]
    ticks = [p["child_cpu_ticks"] for p in (before, after)]
    assert all(type(v) is int and v >= 0 for v in ticks), "invalid raw child ticks"
    tick_delta = ticks[1] - ticks[0]
    assert tick_delta >= 0, "child CPU ticks regressed"
    if proc_child_s is not None:
        assert math.isclose(proc_child_s, tick_delta / hz, rel_tol=1e-12, abs_tol=1e-12), "child summary differs from raw ticks"
    fields = ("rusage_children_user_us", "rusage_children_system_us", "rusage_children_counter_source")
    present = [field in p for p in (before, after) for field in fields]
    source = "proc-stat-cutime+cstime"
    child_us, error_us = tick_delta * 1e6 / hz, 2 * 1e6 / hz
    if any(present):
        assert caller and all(present), "partial or non-caller rusage child counters"
        assert before[fields[2]] == after[fields[2]] == "getrusage(RUSAGE_CHILDREN)", "child counter source changed"
        deltas = []
        for field in fields[:2]:
            values = [p[field] for p in (before, after)]
            assert all(type(v) is int and v >= 0 for v in values), "invalid rusage child counter"
            delta = values[1] - values[0]
            assert delta >= 0, "rusage child counter regressed"
            deltas.append(delta)
        source = "getrusage(RUSAGE_CHILDREN)"
        child_us, error_us = sum(deltas), 2
    return {"pid": before["pid"], "start_ticks": before["start_ticks"],
            "child_counter_source": source, "child_cpu_us": child_us,
            "child_delta_representation_error_us": error_us,
            "proc_child_ticks_before": ticks[0], "proc_child_ticks_after": ticks[1]}


def tree_component(own_us, child_us, parents, denominator, hz):
    assert own_us >= 0 and child_us >= 0 and denominator > 0 and hz > 0
    assert len({p["pid"] for p in parents}) == len(parents), "tree CPU parent counted twice"
    error_us = sum(p["child_delta_representation_error_us"] for p in parents)
    return {"own_us_per_op": own_us, "reaped_child_us_per_op": child_us,
            "source": "process-clock-own plus per-parent child counters",
            "parents": parents, "denominator_ops": denominator,
            "child_window_quantization_us_per_op": error_us / denominator,
            "child_paired_quantization_us_per_op": 2 * error_us / denominator,
            "child_error_scope": "counter export representation only; not kernel accounting accuracy or observed granularity"}


def serial_trees(data, groups):
    count = data["successful"]; hz = data["clock_ticks_per_second"]
    procs = {p["pid"]: p for p in data["daemon_cpu"]}
    values = {}
    for role, source in (("subject", "subject"), ("dependency", "dependency"), ("client", "caller_instrumentation")):
        selected = [procs[pid] for pid in groups[source]]
        own = sum(p["cpu_clock_ns"] for p in selected) / 1000 / count
        parents = [child_cpu_parent(p["before"], p["after"], hz, proc_child_s=p["child_cpu_s"]) for p in selected]
        if role == "client":
            own += data["client_cpu_clock_ns"] / 1000 / count
            b, a = data["client_before"], data["client_after"]
            parents.append(child_cpu_parent(b, a, hz, caller=True, proc_child_s=data["child_cpu_s"]))
        child = sum(p["child_cpu_us"] for p in parents) / count
        values[role] = tree_component(own, child, parents, count, hz)
    return {**{f"{role}_tree_cpu_us_per_op": v["own_us_per_op"] + v["reaped_child_us_per_op"] for role, v in values.items()},
            "tree_cpu_components": values}


def serial(path, subject, roles=None):
    data = native(path)
    groups = role_groups(data, subject, roles)
    dependencies = [p for p in data["daemon_cpu"] if p["pid"] in groups["dependency"]]
    observers = [p for p in data["daemon_cpu"] if p["pid"] in groups["caller_instrumentation"]]
    own = next((p for p in data["daemon_cpu"] if p["pid"] == subject), None)
    assert subject is None or own is not None, "measured daemon is missing"
    cpu = data["child_cpu_s"] if subject is None else own["cpu_s"] + own["child_cpu_s"]
    count = data["successful"]
    clocks = {}
    if "client_cpu_clock_ns" in data:
        assert data["client_cpu_clock_ns"] == process_clock_delta(data["client_before"], data["client_after"])
        clocks["client_cpu_clock_us_per_op"] = data["client_cpu_clock_ns"] / 1000 / count
        if subject is not None:
            for p in data["daemon_cpu"]:
                assert p["cpu_clock_ns"] == process_clock_delta(p["before"], p["after"])
            clocks["subject_own_cpu_clock_us_per_op"] = own["cpu_clock_ns"] / 1000 / count
            clocks["dependency_own_cpu_clock_us_per_op"] = sum(p["cpu_clock_ns"] for p in dependencies) / 1000 / count
    trees = serial_trees(data, groups) if subject is not None and clocks else {}
    resources = [resource_pair(p["before"], p["after"], subject, p["pid"]) for p in data["daemon_cpu"]]
    for resource in resources:
        resource["role"] = next(role for role, pids in groups.items() if resource["pid"] in pids)
    return {**timing(data), **clocks, **trees, "warmup": data["warmup"], "errors": data["errors"],
            "resources": resources,
            "clock_ticks_per_second": data.get("clock_ticks_per_second"),
            "subject_reaped_child_cpu_us_per_op": own["child_cpu_s"] * 1e6 / count if own else None,
            "dependency_reaped_child_cpu_us_per_op": sum(p["child_cpu_s"] for p in dependencies) * 1e6 / count,
            "client_reaped_child_cpu_us_per_op": data["child_cpu_s"] * 1e6 / count,
            "caller_instrumentation_own_cpu_clock_us_per_op": sum(p["cpu_clock_ns"] for p in observers) / 1000 / count,
            "caller_instrumentation_reaped_child_cpu_us_per_op": sum(p["child_cpu_s"] for p in observers) * 1e6 / count,
            "subject_cpu_us_per_op": cpu * 1e6 / count,
            "dependency_cpu_us_per_op": sum(p["cpu_s"] for p in dependencies) * 1e6 / count,
            "client_cpu_us_per_op": data["client_cpu_s"] * 1e6 / count}


def parallel(path, subject):
    group = read(path / "group.json")
    assert group["clients"] == 4
    clients = [native(path / f"client-{i}.json") for i in range(1, 5)]
    assert all(c["successful"] == group["iterations_per_client"] and
               c["warmup"] == group["warmup_per_client"] for c in clients)
    samples = sorted(v for c in clients for v in c["latency_ns"])
    count = len(samples)
    warm = sum(c["warmup"] for c in clients)
    before, after = read(path / "before.json"), read(path / "after.json")
    hz = before["clock_ticks_per_second"]
    assert hz == after["clock_ticks_per_second"] and hz > 0
    elapsed = after["uptime_s"] - before["uptime_s"]
    assert elapsed > 0
    old = {p["pid"]: p for p in before["processes"]}
    new = {p["pid"]: p for p in after["processes"]}
    assert old.keys() == new.keys() and subject in old
    cpu = {}
    for pid, p in new.items():
        assert p["start_ticks"] == old[pid]["start_ticks"]
        own = p["cpu_ticks"] - old[pid]["cpu_ticks"]
        child = p["child_cpu_ticks"] - old[pid]["child_cpu_ticks"]
        assert own >= 0 and child >= 0
        cpu[pid] = (own + child) / hz
    clocks = {}
    if "process_cpu_ns" in old[subject]:
        own_ns = {pid: process_clock_delta(old[pid], p) for pid, p in new.items()}
        assert all(c["client_cpu_clock_ns"] == process_clock_delta(c["client_before"], c["client_after"]) for c in clients)
        clocks = {
            "subject_own_cpu_clock_us_per_op": own_ns[subject] / 1000 / (count + warm),
            "dependency_own_cpu_clock_us_per_op": sum(v for pid, v in own_ns.items() if pid != subject) / 1000 / (count + warm),
            "client_cpu_clock_us_per_op": sum(c["client_cpu_clock_ns"] for c in clients) / 1000 / count,
        }
    trees = {}; components = {}
    if clocks:
        for role, selected in (("subject", [subject]), ("dependency", [pid for pid in new if pid != subject])):
            own = sum(own_ns[pid] for pid in selected) / 1000 / (count + warm)
            parents = [child_cpu_parent(old[pid], new[pid], hz) for pid in selected]
            child = sum(p["child_cpu_us"] for p in parents) / (count + warm)
            components[role] = tree_component(own, child, parents, count + warm, hz)
        caller_parents = []
        for c in clients:
            assert c["clock_ticks_per_second"] == hz, "client HZ differs from outer interval"
            b, a = c["client_before"], c["client_after"]
            caller_parents.append(child_cpu_parent(b, a, hz, caller=True, proc_child_s=c["child_cpu_s"]))
        components["client"] = tree_component(clocks["client_cpu_clock_us_per_op"], sum(p["child_cpu_us"] for p in caller_parents) / count, caller_parents, count, hz)
        trees = {**{f"{role}_tree_cpu_us_per_op": v["own_us_per_op"] + v["reaped_child_us_per_op"] for role, v in components.items()}, "tree_cpu_components": components}
    # The native client's rounded (n - 1) index, pooled within one
    # run only. Each run remains one independent observation in the summary.
    quantile = lambda p: samples[math.floor((len(samples) - 1) * p + .5)] / 1000
    child_cost = ({"client_reaped_child_cpu_us_per_op": sum(c["child_cpu_s"] for c in clients) * 1e6 / count}
                  if all("child_cpu_s" in c for c in clients) else {})
    return {**clocks, **trees, **child_cost, "successful": count, "warmup": warm, "wall_s": elapsed,
            "errors": sum(c["errors"] for c in clients), "clock_ticks_per_second": hz,
            "resources": [resource_pair(old[pid], p, subject) for pid, p in new.items()],
            "subject_reaped_child_cpu_us_per_op": (new[subject]["child_cpu_ticks"] - old[subject]["child_cpu_ticks"]) / hz * 1e6 / (count + warm),
            "dependency_reaped_child_cpu_us_per_op": sum(p["child_cpu_ticks"] - old[pid]["child_cpu_ticks"] for pid, p in new.items() if pid != subject) / hz * 1e6 / (count + warm),
            "ops_per_s": count / elapsed, "mean_us": statistics.mean(samples) / 1000,
            "p50_us": quantile(.50), "p95_us": quantile(.95), "p99_us": quantile(.99),
            "subject_cpu_us_per_op": cpu[subject] * 1e6 / (count + warm),
            "dependency_cpu_us_per_op": sum(v for pid, v in cpu.items() if pid != subject) * 1e6 / (count + warm),
            "client_cpu_us_per_op": sum(c["client_cpu_s"] for c in clients) * 1e6 / count}


def check_netifd_hotplug(raw, subject, count, expected_names):
    callbacks = [line.split() for line in (raw / f"hotplug-settled-{count}.txt").read_text().splitlines()]
    assert all(len(c) == 3 and c[2] == "0" for c in callbacks), "hotplug callback failed"
    assert sorted(c[0] for c in callbacks if c[1] == "ifup") == expected_names, "incomplete or duplicate ifup callbacks"
    idle = [read(raw / f"hotplug-settled-{count}-{phase}.json") for phase in ("before", "after")]
    parent = [next(p for p in snapshot["processes"] if p["pid"] == subject) for snapshot in idle]
    assert parent[0]["start_ticks"] == parent[1]["start_ticks"], "netifd restarted while settling"
    assert parent[0]["child_cpu_ticks"] == parent[1]["child_cpu_ticks"], "setup children still running"
    child_check = raw / f"hotplug-child-check-{count}.txt"
    return child_check.is_file() and child_check.read_text().strip() == "proc-status-ppid"


def check_event_lane(raw, data):
    events = raw / "events_static2"
    roles = read(raw / "roles.json")
    assert {r["role"] for r in roles["processes"]} == {"subject", "dependency", "caller_instrumentation"}
    assert sum(r["role"] == "caller_instrumentation" for r in roles["processes"]) == 2
    contract = read(raw / "event-contract.json")
    actions = ["lan-down", "lan-up", "wired-down", "wired-up"]
    total = data["warmup"] + data["successful"]
    journal = [__import__("json").loads(line) for line in (raw / "events_static2-journal.jsonl").read_text().splitlines()]
    assert len(journal) == total * 2
    measured = []
    for index in range(total):
        start, end = journal[index * 2:index * 2 + 2]
        assert start["iteration"] == end["iteration"] == index
        assert start["event"] == "started" and end["event"] == "completed" and end["error"] is None
        assert end["exit_code"] == 0 and end["signal"] is None
        phase = "warmup" if index < data["warmup"] else "measured"
        assert start["phase"] == end["phase"] == phase
        if phase == "measured": measured.append(end["latency_ns"])
    assert measured == native(raw / "events_static2.json")["latency_ns"]
    for name in ["prelude"] + [f"iteration-{i:06d}" for i in range(total)]:
        cycle = events / name
        assert (cycle / "COMPLETE").exists() and not (cycle / "FAILED").exists()
        assert (cycle / "actions.txt").read_text().splitlines() == actions
        assert (cycle / "children-reaped.txt").read_text().strip() == "proc-status-ppid"
        records = [__import__("json").loads(line) for line in (cycle / "records.jsonl").read_text().splitlines()]
        assert [record["step"] for record in records] == actions
        for record in records:
            assert record["raw"]["command.rc"].strip() == "0"
            assert record["evidence"] == contract["steps"][record["step"]]
        interfaces = read(cycle / "final-interfaces.json")["interface"]
        assert [i["interface"] for i in interfaces] == ["lan", "loopback", "wired"]
        assert all(i["up"] and not i["pending"] for i in interfaces)
    assert read(events / "cursor.json") == read(events / "cursor-after.json")
    assert not (events / "listen.stderr").read_bytes() and not (events / "subscribe.stderr").read_bytes()
    return roles


def check_reload_lane(raw):
    after_configs = list(raw.glob("interfaces-*-after-reload.json"))
    assert len(after_configs) == 1, "missing reload state verification"
    interfaces = read(after_configs[0])["interface"]
    assert len(interfaces) in (32, 64, 128) and all(i["up"] and not i["pending"] for i in interfaces)
    assert (raw / "reload-children-reaped.txt").read_text().strip() == "proc-status-ppid"
    assert (raw / "hotplug-before-reload.txt").read_bytes() == (raw / "hotplug-after-reload.txt").read_bytes()
    assert (raw / "reload-config-before.sha256").read_bytes() == (raw / "reload-config-after.sha256").read_bytes()
    if (raw / "handler-before-reload.log").exists():
        assert (raw / "handler-before-reload.log").read_bytes() == (raw / "handler-calls.log").read_bytes()
    before, after = read(raw / "reload-before.json"), read(raw / "reload-after.json")
    assert [(p["pid"], p["start_ticks"]) for p in before["processes"]] == [(p["pid"], p["start_ticks"]) for p in after["processes"]]


def derive(root, label):
    assert (root / "COMPLETE").exists(), "collector did not complete its host gates"
    order, subjects = read(root / "order.json"), read(root / "subjects.json")
    settings = read(root / "settings.json")
    assert not settings.get("rpc_client_diagnostic"), "RPC client diagnostics cannot be published as performance-matrix results"
    component = settings.get("component", "httpd")
    assert component in COMPONENT_WORK
    baseline_label = settings.get("baseline_label", "r84")
    measured_sides = tuple(side for side in ("stock", baseline_label, "candidate") if side in order)
    calibration = settings.get("schedule") == "calibration"
    assert measured_sides == ("candidate",) if calibration else {"stock", "candidate"}.issubset(measured_sides)
    assert len({order.count(side) for side in measured_sides}) == 1
    before, after = read(root / "health-before.json"), read(root / "health-after.json")
    assert before["boot_id"] == after["boot_id"]
    assert (root / "config-before.sha256").read_bytes() == (root / "config-after.sha256").read_bytes()
    rows, residents, sources = [], [], []
    initialization_settled = []
    identities = set()
    fixtures = set()
    matrix = read(root / "settings.json")["matrix"]
    netifd_scale = settings.get("netifd_scale", 32)
    assert netifd_scale in (32, 64, 128)
    workloads = list(COMPONENT_WORK[component])
    if matrix and component == "httpd":
        workloads = ([f"{name}_{clients}" for name in STATIC for clients in ("c1", "c4")]
                     + ["cgi", "jsonrpc", "cgi_c4", "jsonrpc_c4"])
    elif matrix and component == "rpcd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in RPCD_EXTRA for suffix in ("", "_c4")]
    elif matrix and component == "procd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in PROCD_EXTRA for suffix in ("", "_c4")]
    elif matrix and component == "ubusd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        workloads += [name + suffix for name in UBUSD_EXTRA for suffix in ("", "_c4")]
    elif matrix and component == "netifd":
        workloads += [name + "_c4" for name in COMPONENT_WORK[component]]
        extra = ("device_status_all", f"interface_dump_{netifd_scale}", f"interface_named_{netifd_scale}")
        workloads += [name + suffix for name in extra for suffix in ("", "_c4")]
    else:
        assert not matrix, "unsupported workload matrix"
    if matrix and component == "netifd":
        workloads += [name for name in NETIFD_SERIAL if name in settings.get("netifd_workloads", [])]
    if read(root / "settings.json").get("extended"):
        assert component == "ubusd", "extended lanes are ubusd only"
        workloads += list(UBUSD_EXTENDED)
    if settings.get("netifd_workloads"):
        requested = settings["netifd_workloads"]
        assert component == "netifd" and set(requested) <= set(workloads)
        workloads = [name for name in workloads if name in requested]
    for index, side in enumerate(order, 1):
        local = root / f"{index:02d}-{side}"
        raw = local / "raw"
        assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists()
        assert not (raw / "TRACE_DIAGNOSTIC").exists(), "traced runs are not performance measurements"
        assert not (raw / "diagnostic-mode.txt").exists(), "HTTP diagnostics are separate from the matrix"
        meta = read(raw / "meta.json")
        assert meta["component"] == component and meta["dependencies"] == "original OpenWrt"
        subject = meta["subject_pid"]
        assert (subject is None) == (component in ("uci", "reload-config", "fw4")), "invalid subject process kind"
        if component == "logd":
            assert meta["kernel_log_mask"] == "empty-held-fifo", "invalid logd kernel-log fixture"
            logd_idle(raw / "kernel-log-idle.jsonl", subject)
        assert (raw / "boot-id.txt").read_text().strip() == before["boot_id"]
        identity_files = ("binary-sha256.txt", "subject-sha256.txt") if subject is not None else ("binary-sha256.txt",)
        for file in identity_files:
            assert (raw / file).read_text().split()[0] == subjects[side]
        identity = tuple(line.split()[0] for line in (raw / "benchmark-sha256.txt").read_text().splitlines())
        identity += ((raw / "harness-sha256.txt").read_text().split()[0],)
        identities.add(identity)
        if matrix:
            fixture_file = {"httpd": "static-fixtures.sha256", "rpcd": "rpc-fixtures.sha256",
                            "procd": "procd-fixtures.sha256", "ubusd": "ubusd-fixtures.sha256",
                            "netifd": "netifd-fixtures.sha256"}[component]
            fixtures.add((raw / fixture_file).read_text())
            if component == "ubusd":
                for count in (64, 128):
                    expected_paths = [f"bench.filler{i:04d}" for i in range(1, count)] + ["bench.target"]
                    for phase in ("before", "after"):
                        assert (raw / f"objects-{count}-{phase}.txt").read_text().splitlines() == expected_paths
            if component == "netifd" and workloads != ["events_static2"]:
                settled = (raw / f"hotplug-settled-{netifd_scale}.txt").is_file()
                initialization_settled.append(settled)
                for count in (2, netifd_scale):
                    digits = 3 if netifd_scale == 128 else 2
                    expected_names = [f"bench{i:0{digits}d}" for i in range(count - 2)] + ["lan", "loopback"]
                    if settled:
                        children_checked = check_netifd_hotplug(raw, subject, count, expected_names)
                        initialization_settled[-1] = initialization_settled[-1] and children_checked
                    for phase in ("before", "after"):
                        assert (raw / f"interface-names-{count}-{phase}.txt").read_text().splitlines() == expected_names
                        assert (raw / f"interface-objects-{count}-{phase}.txt").read_text().splitlines() == [
                            "network.interface." + name for name in expected_names]
                        interfaces = read(raw / f"interfaces-{count}-{phase}.json")["interface"]
                        assert [i["interface"] for i in interfaces] == expected_names
                        assert all(i["up"] and i["proto"] == "static" for i in interfaces)
        sources.append({"run": local.name, "subject_sha256": subjects[side],
                        "archive_sha256": hashlib.sha256((local / "raw.tar.gz").read_bytes()).hexdigest(),
                        "kernel": (raw / "kernel.txt").read_text().strip()})
        if component == "netifd" and workloads == ["events_static2"]:
            settled = True
            initialization_settled.append(check_netifd_hotplug(raw, subject, 3, ["lan", "loopback", "wired"]))
        for name in workloads:
            roles = read(raw / "roles.json") if name == "events_static2" else None
            data = parallel(raw / name, subject) if name.endswith("_c4") else serial(raw / (name + ".json"), subject, roles)
            if name == "events_static2":
                check_event_lane(raw, data)
                expected_contract = settings["netifd_event_contracts"][side]
                assert hashlib.sha256((raw / "event-contract.json").read_bytes()).hexdigest() == expected_contract["sha256"]
                assert read(raw / "event-contract.json")["reference_subject_sha256"] == expected_contract["reference_subject_sha256"]
            if name == "reload_unchanged": check_reload_lane(raw)
            if component == "netifd" and matrix and settled and name not in NETIFD_SERIAL:
                if name.endswith("_c4"):
                    snapshots = [read(raw / name / f"{phase}.json") for phase in ("before", "after")]
                    child_ticks = [next(p for p in s["processes"] if p["pid"] == subject)["child_cpu_ticks"] for s in snapshots]
                    assert child_ticks[0] == child_ticks[1], (name, "query includes child setup CPU")
                else:
                    own = next(p for p in native(raw / (name + ".json"))["daemon_cpu"] if p["pid"] == subject)
                    assert own["child_cpu_s"] == 0, (name, "query includes child setup CPU")
            expected = max(1, meta["iterations"] // (20 if name.startswith("cgi") else 10 if name.startswith(("static_1m", "uci_get_64")) else 1))
            if component in ("uci", "reload-config", "fw4"):
                expected = max(1, meta["iterations"] // (100 if component == "fw4" else 20))
            elif name == "syslog_128":
                expected = meta["iterations"] * 10
            if name.endswith("_c4"):
                expected = max(1, expected // 4) * 4
            assert data["successful"] == expected, (name, data["successful"], expected)
            rows.append({"run": local.name, "side": side, "workload": name, **data})
        if subject is not None:
            resident = read(raw / "resident.json")
            process = next(p for p in resident["processes"] if p["pid"] == subject)
            residents.append({"run": local.name, "side": side, **memory(process),
                              "temperature_millic": resident["temperature_millic"]})
    assert len(identities) == 1 and (not matrix or len(fixtures) == 1), "clients/harness/fixtures changed between sides"
    groups = defaultdict(list)
    for row in rows:
        groups[(row["workload"], row["side"])].append(row)
    summary = {}
    metrics = METRICS + tuple(metric for metric in CLOCK_METRICS + TREE_METRICS if all(metric in row for row in rows))
    for name in workloads:
        sides = {side: {metric: stats(r[metric] for r in groups[(name, side)]) for metric in metrics}
                 for side in measured_sides}
        if not calibration:
            sides["candidate_vs_stock_pct"] = {
                metric: (sides["candidate"][metric]["median"] / sides["stock"][metric]["median"] - 1) * 100
                for metric in metrics if sides["stock"][metric]["median"] > 0}
        if baseline_label in sides:
            sides["candidate_vs_baseline_pct"] = {
                metric: (sides["candidate"][metric]["median"] / sides[baseline_label][metric]["median"] - 1) * 100
                for metric in metrics if sides[baseline_label][metric]["median"] > 0}
        summary[name] = sides
    client, namespace, harness = next(iter(identities))
    limitations = []
    if calibration:
        limitations.append("Same-identity calibration only; no between-implementation acceptance claim.")
    if not all(metric in metrics for metric in CLOCK_METRICS):
        limitations.append("Process CPU-clock metrics are unavailable for some observations; legacy ticks remain separate.")
    if initialization_settled and not all(initialization_settled):
        limitations.append("This netifd matrix lacks complete evidence for finished hotplug callbacks, reaped children checked through proc status PPid, and stable child CPU before queries. Timings/CPU are retained for diagnosis, not acceptance; rerun with the complete initialization gate.")
    return {"schema_version": 1, "label": label, "component": component, "matrix": matrix, "subjects": subjects,
            "benchmark_sha256": client, "namespace_sha256": namespace, "harness_sha256": harness,
            "order": order, "host_gates_passed": True, "acceptance_eligible": not limitations,
            "limitations": limitations, "runs": rows, "summary": summary,
            "measured_sides": measured_sides,
            "baseline_label": baseline_label, "cpu_affinity": settings.get("cpu_affinity"),
            "resident": residents, "sources": sources,
            "method": "Medians of per-run statistics; c4 CPU uses one outer interval divided by successful plus warm-up operations. c4 outer throughput includes warm-up/startup and uses /proc/uptime resolution. Client validation runs on the same router CPUs."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    args = parser.parse_args()
    result = derive(args.private, args.label)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["measured_sides"] == ("candidate",):
        lines = [f"# {args.label}：同身份校准", "", "仅用于估计测量噪声和漂移，不是实现间的比较。", "",
                 "| 负载 | mean 中位数 µs | p99 最小–最大 µs |", "|---|---:|---:|"]
        for name, sides in result["summary"].items():
            metrics = sides["candidate"]
            lines.append(f"| {name} | {metrics['mean_us']['median']:.2f} | {metrics['p99_us']['min']:.2f}–{metrics['p99_us']['max']:.2f} |")
        (args.output / "results.md").write_text("\n".join(lines) + "\n")
        print(f"{args.label}: {len(result['runs'])} calibration measurements verified")
        return
    lines = [f"# {args.label}：{result['component']} 实机对照", "",
             "单位：延迟和 CPU 为 µs/请求；数值是逐轮统计的中位数。负百分比表示开销下降。", "",
             f"| 负载 | 原版延迟 | {result['baseline_label'].upper()} 延迟 | 候选延迟 | 候选比原版 | 原版 CPU | 候选 CPU | 候选比原版 |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, sides in result["summary"].items():
        v = lambda side, metric: sides[side][metric]["median"]
        delta = sides["candidate_vs_stock_pct"]
        baseline = f"{v(result['baseline_label'], 'mean_us'):.2f}" if result["baseline_label"] in sides else "—"
        lines.append(f"| {name} | {v('stock', 'mean_us'):.2f} | {baseline} | "
                     f"{v('candidate', 'mean_us'):.2f} | {delta['mean_us']:+.2f}% | "
                     f"{v('stock', 'subject_cpu_us_per_op'):.2f} | {v('candidate', 'subject_cpu_us_per_op'):.2f} | "
                     f"{delta['subject_cpu_us_per_op']:+.2f}% |")
    if result["limitations"]:
        lines += ["", "**测量边界：**", *["- " + item for item in result["limitations"]]]
    lines += ["", "每侧运行次数：" + str(len(result["order"]) // len(result["measured_sides"])) + "。所列完整运行的请求均成功，原版依赖和正式运行栈保持相同。",
              "", "c4 的 CPU 包含并计数每客户端 20 次预热，使用唯一外层区间；吞吐包括预热和启动，",
              "计时精度来自 /proc/uptime。客户端校验也使用路由器 CPU，不能把这里的吞吐视为服务端极限。",
              "", "逐轮均值、p50/p95/p99、CPU、内存、离散程度及产物身份见 [results.json](results.json)。", ""]
    (args.output / "results.md").write_text("\n".join(lines))
    print(f"{args.label}: {len(result['runs'])} workload measurements verified")


if __name__ == "__main__":
    main()
