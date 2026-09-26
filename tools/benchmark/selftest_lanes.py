#!/usr/bin/env python3
"""Focused accounting/contract negatives; --bench additionally tests native tools."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

import analyze_candidate as analyzer


def dump(path, value):
    path.write_text(json.dumps(value) + "\n")


def rejected(call):
    try:
        call()
    except (AssertionError, KeyError, ValueError):
        return
    raise AssertionError("invalid evidence was accepted")


def process(pid, before, own, child):
    return {"pid": pid, "start_ticks": pid * 10, "cpu_ticks": own, "child_cpu_ticks": child,
            "process_cpu_ns": own * 10_000_000, "process_cpu_resolution_ns": 1,
            "VmRSS": 100, "RssAnon": 20, "RssFile": 80, "RssShmem": 0, "VmHWM": 100,
            "fds": 3, "Threads": 1}


def native_sample(pid=10, n=4, warm=1):
    daemons = []
    for daemon in (1, 2, 3, 4):
        b = process(daemon, True, 1, 0); a = process(daemon, False, 3, daemon)
        daemons.append({"pid": daemon, "cpu_clock_ns": 20_000_000, "cpu_s": .02,
                        "child_cpu_s": daemon / 100, "before": b, "after": a})
    return {"schema": 1, "successful": n, "warmup": warm, "errors": 0,
            "latency_ns": [1000] * n, "mean_us": 1, "p50_us": 1, "p95_us": 1, "p99_us": 1,
            "wall_s": 1, "ops_per_s": n, "daemon_cpu": daemons,
            "client_cpu_s": .01, "client_cpu_clock_ns": 10_000_000, "child_cpu_s": .05,
            "client_before": process(pid, True, 1, 0), "client_after": process(pid, False, 2, 5),
            "clock_ticks_per_second": 100}


def accounting_tests(root):
    data = native_sample(); path = root / "serial.json"; dump(path, data)
    roles = {"schema": 1, "processes": [{"pid": pid, "start_ticks": pid * 10, "role": role}
             for pid, role in ((1, "subject"), (2, "dependency"), (3, "caller_instrumentation"), (4, "caller_instrumentation"))]}
    value = analyzer.serial(path, 1, roles)
    assert value["client_cpu_clock_us_per_op"] == 2500
    assert value["subject_tree_cpu_us_per_op"] == 7500
    assert value["dependency_tree_cpu_us_per_op"] == 10000
    assert value["client_tree_cpu_us_per_op"] == 42500
    assert value["dependency_cpu_us_per_op"] == 5000
    assert value["tree_cpu_components"]["client"]["child_window_quantization_us_per_op"] == 15000
    for change in ("duplicate", "missing", "replaced", "wrong-role"):
        bad = copy.deepcopy(roles)
        if change == "duplicate": bad["processes"].append(copy.deepcopy(bad["processes"][0]))
        if change == "missing": bad["processes"].pop()
        if change == "replaced": bad["processes"][2]["start_ticks"] += 1
        if change == "wrong-role": bad["processes"][0]["role"] = "dependency"
        rejected(lambda: analyzer.serial(path, 1, bad))
    group = root / "parallel"; group.mkdir()
    dump(group / "group.json", {"clients": 4, "iterations_per_client": 4, "warmup_per_client": 1})
    for i in range(1, 5): dump(group / f"client-{i}.json", native_sample(pid=10+i))
    dump(group / "before.json", {"clock_ticks_per_second": 100, "uptime_s": 1,
                                 "processes": [p["before"] for p in data["daemon_cpu"][:2]]})
    dump(group / "after.json", {"clock_ticks_per_second": 100, "uptime_s": 2,
                                "processes": [p["after"] for p in data["daemon_cpu"][:2]]})
    value = analyzer.parallel(group, 1)
    assert value["client_tree_cpu_us_per_op"] == 15000
    assert len(value["tree_cpu_components"]["client"]["parents"]) == 4
    assert value["tree_cpu_components"]["client"]["child_window_quantization_us_per_op"] == 5000
    duplicate = native_sample(pid=11); dump(group / "client-2.json", duplicate)
    rejected(lambda: analyzer.parallel(group, 1))
    fields = ("rusage_children_user_us", "rusage_children_system_us", "rusage_children_counter_source")
    def with_rusage(sample):
        for phase, user, system in (("before", 0, 0), ("after", 39418, 29720)):
            sample["client_" + phase].update({fields[0]: user, fields[1]: system,
                                             fields[2]: "getrusage(RUSAGE_CHILDREN)"})
        return sample
    enriched = with_rusage(native_sample()); dump(path, enriched)
    value = analyzer.serial(path, 1, roles)
    assert value["client_cpu_clock_us_per_op"] == 2500
    assert value["client_reaped_child_cpu_us_per_op"] == 12500  # Legacy proc metric.
    assert value["client_tree_cpu_us_per_op"] == 47284.5
    caller = value["tree_cpu_components"]["client"]
    assert caller["child_window_quantization_us_per_op"] == 10000.5  # Two observers still use ticks.
    assert [p["child_counter_source"] for p in caller["parents"]] == [
        "proc-stat-cutime+cstime", "proc-stat-cutime+cstime", "getrusage(RUSAGE_CHILDREN)"]
    for phase in ("before", "after"):
        for field in fields:
            bad = copy.deepcopy(enriched); del bad["client_" + phase][field]; dump(path, bad)
            rejected(lambda: analyzer.serial(path, 1, roles))
    for field, replacement in ((fields[0], -1), (fields[1], False), (fields[2], "wrong-source")):
        bad = copy.deepcopy(enriched); bad["client_after"][field] = replacement; dump(path, bad)
        rejected(lambda: analyzer.serial(path, 1, roles))
    bad = copy.deepcopy(enriched); bad["client_before"][fields[0]] = 50000; dump(path, bad)
    rejected(lambda: analyzer.serial(path, 1, roles))
    for i in range(1, 5): dump(group / f"client-{i}.json", with_rusage(native_sample(pid=10+i)))
    value = analyzer.parallel(group, 1)
    assert value["client_tree_cpu_us_per_op"] == 19784.5
    assert value["tree_cpu_components"]["client"]["child_paired_quantization_us_per_op"] == 1
    dump(group / "client-4.json", native_sample(pid=14))
    value = analyzer.parallel(group, 1)
    assert value["tree_cpu_components"]["client"]["child_window_quantization_us_per_op"] == 20006 / 16
    return "PASS"


def event_analyzer_tests(root):
    raw = root / "event-raw"; raw.mkdir(); events = raw / "events_static2"; events.mkdir()
    data = native_sample(n=1, warm=0); dump(raw / "events_static2.json", data)
    roles = {"schema": 1, "processes": [{"pid": pid, "start_ticks": pid * 10, "role": role}
             for pid, role in ((1, "subject"), (2, "dependency"), (3, "caller_instrumentation"), (4, "caller_instrumentation"))]}
    dump(raw / "roles.json", roles)
    actions = ["lan-down", "lan-up", "wired-down", "wired-up"]
    contract = {"steps": {a: {"synthetic_value": a} for a in actions}}; dump(raw / "event-contract.json", contract)
    journal = [{"iteration": 0, "event": "started", "phase": "measured"},
               {"iteration": 0, "event": "completed", "phase": "measured", "error": None, "exit_code": 0, "signal": None, "latency_ns": 1000}]
    journal_path = raw / "events_static2-journal.jsonl"
    journal_path.write_text(''.join(json.dumps(r) + "\n" for r in journal))
    final = {"interface": [{"interface": name, "up": True, "pending": False} for name in ("lan", "loopback", "wired")]}
    for name in ("prelude", "iteration-000000"):
        cycle = events / name; cycle.mkdir(); (cycle / "COMPLETE").touch()
        (cycle / "actions.txt").write_text(''.join(a + "\n" for a in actions))
        (cycle / "children-reaped.txt").write_text("proc-status-ppid\n")
        dump(cycle / "final-interfaces.json", final)
        records = [{"step": a, "evidence": contract["steps"][a], "raw": {"command.rc": "0\n"}} for a in actions]
        (cycle / "records.jsonl").write_text(''.join(json.dumps(r) + "\n" for r in records))
    for name in ("cursor.json", "cursor-after.json"): dump(events / name, {"listen": 1})
    for name in ("listen.stderr", "subscribe.stderr"): (events / name).write_text("")
    analyzer.check_event_lane(raw, data)
    def corrupt(path, value):
        before = path.read_bytes(); path.write_bytes(value)
        rejected(lambda: analyzer.check_event_lane(raw, data)); path.write_bytes(before)
    corrupt(journal_path, journal_path.read_bytes().replace(b'"completed"', b'"failed"'))
    corrupt(events / "iteration-000000/actions.txt", b'lan-up\nlan-down\nwired-down\nwired-up\n')
    corrupt(events / "iteration-000000/final-interfaces.json", json.dumps({"interface": []}).encode())
    corrupt(events / "iteration-000000/records.jsonl", (events / "iteration-000000/records.jsonl").read_bytes().replace(b'"0\\n"', b'"9\\n"'))
    corrupt(events / "cursor-after.json", b'{"listen":2}')
    return "PASS"


def run_native(args, success, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=10, **kwargs)
    assert (result.returncode == 0) == success, (args, result.returncode, result.stderr)
    if not success: assert not result.stdout, "failed helper emitted success stdout"
    return result


def native_tests(bench, root):
    expected = root / "expected"; expected.write_bytes(b"ok\n")
    artifacts = root / "artifacts"; artifacts.mkdir()
    journal = root / "journal.jsonl"
    env = dict(os.environ, OWRT_BENCH_EXEC_JOURNAL=str(journal), OWRT_BENCH_EXEC_ARTIFACTS=str(artifacts))
    command = [bench, "exec", "4", "1", str(expected), "-", "--", "/bin/sh", "-c",
               '[ "$R84_ITERATION" -lt 3 ] || { echo bad >&2; exit 9; }; echo ok']
    run_native(command, False, env=env)
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [r["event"] for r in records] == ["started", "completed"] * 3 + ["started", "failed"]
    assert records[-1]["exit_code"] == 9 and records[-1]["phase"] == "measured"
    assert (artifacts / "iteration-000003/exec.stderr").read_bytes() == b"bad\n"
    run_native(command, False, env=env)  # Never append to an earlier journal.
    journal2 = root / "bad-stdout.jsonl"; artifact2 = root / "bad-stdout"; artifact2.mkdir()
    env.update(OWRT_BENCH_EXEC_JOURNAL=str(journal2), OWRT_BENCH_EXEC_ARTIFACTS=str(artifact2))
    run_native([bench, "exec", "1", "0", str(expected), "-", "--", "/bin/echo", "wrong"], False, env=env)
    assert json.loads(journal2.read_text().splitlines()[-1])["error"] == "child stdout failed byte validation"
    journal3 = root / "interrupt.jsonl"; artifact3 = root / "interrupt"; artifact3.mkdir()
    env.update(OWRT_BENCH_EXEC_JOURNAL=str(journal3), OWRT_BENCH_EXEC_ARTIFACTS=str(artifact3))
    p = subprocess.Popen([bench, "exec", "1", "0", str(expected), "-", "--", "/bin/sleep", "5"], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        deadline = time.monotonic() + 2
        while (not journal3.exists() or not journal3.read_bytes()) and time.monotonic() < deadline: time.sleep(.01)
        assert journal3.exists() and journal3.read_bytes()
    finally:
        os.killpg(p.pid, signal.SIGKILL)
        stdout, _ = p.communicate(timeout=2)
    assert not stdout
    assert [json.loads(line)["event"] for line in journal3.read_text().splitlines()] == ["started"]
    event_tests(bench, root)
    return "PASS"


def event_tests(bench, root):
    # A complete suffix capture followed by exact contract check; every changed
    # byte/order/extra record is rejected without advancing its cursor.
    logs = root / "logs"; logs.mkdir(); action = root / "action"; action.mkdir()
    cursor = root / "cursor.json"; contract = root / "contract.json"; result = root / "records.jsonl"
    listen = '{"network.interface":{"action":"ifup","interface":"lan"}}\n'
    subscribe = '{"interface.update":{"interface":"lan","up":true,"pending":false,"uptime":7}}\n'
    hotplug = 'iface|lan|ifup|br-event0|||||0\n'
    for name, text in (("listen", listen), ("subscribe", subscribe), ("hotplug", hotplug)): (logs / (name+".txt")).write_text(text)
    for name in ("command.stdout", "command.stderr", "status.stderr", "evidence-errors.txt", "addresses.txt", "kernel-addresses.txt", "routes.txt", "routes6.txt", "routes-unsorted.txt", "routes6-unsorted.txt"):
        (action / name).write_text("")
    dump(action / "status.json", {"up": True, "pending": False, "uptime": 3})
    (action / "status-polls.jsonl").write_bytes((action / "status.json").read_bytes())
    (action / "command.rc").write_text("0\n"); (action / "polls.txt").write_text("1\n")
    zero = {"listen": 0, "subscribe": 0, "hotplug": 0}; dump(cursor, zero)
    args = [bench, "event-evidence", "capture", "-", "lan-up", str(logs), str(cursor), str(action), str(result)]
    run_native(args, True)
    evidence = json.loads(result.read_text().splitlines()[0])["evidence"]
    dump(contract, {"steps": {"lan-up": evidence}})
    args[2:4] = ["check", str(contract)]
    dump(cursor, zero); run_native(args, True)
    for corruption in (listen + listen, listen.rstrip("\n"), '{"wrong":{}}\n'):
        (logs / "listen.txt").write_text(corruption); dump(cursor, zero)
        run_native(args, False)
        assert json.loads(cursor.read_text()) == zero
    dump(cursor, {"listen": 999999, "subscribe": 0, "hotplug": 0})
    run_native(args, False)
    return "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench", type=Path)
    parser.add_argument("--event-bench", type=Path, help="event helper only, also usable on non-Linux build host")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="netifd-lane-selftest-") as directory:
        root = Path(directory)
        accounting = accounting_tests(root)
        event_analyzer_tests(root)
        native = native_tests(str(args.bench.resolve()), root) if args.bench else None
        events = event_tests(str(args.event_bench.resolve()), root) if args.event_bench else None
    print(json.dumps({"accounting": accounting,
                      "native_status": "PASS" if args.bench else "NOT_RUN", "event_helper": "PASS" if args.event_bench else "NOT_RUN", "status": "PASS"}))


if __name__ == "__main__":
    main()
