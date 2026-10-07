#!/usr/bin/env python3
"""Freeze the Scheme A 45-window CPU plan, or analyze archived windows offline.

There is deliberately no execution command. The common M6b fixture and each
Rust source/build/ELF are bound independently before the plan is emitted.
R3_new and A are opt3 groups; neither is the opt-s group in the final 135-window
qualification. Raw-window arithmetic is the unchanged M6a analysis code.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
from pathlib import Path
import re
import statistics

import m6a_analyze as arithmetic
import m6a_suite as suite
import m6a_window as window
from m2_rootfs import STOCK_SHA256

GROUPS = ("C", "R3_new", "A")
PROFILES = tuple(row for row in suite.PROFILES if row[0].startswith("tcp-"))
ORDERS = tuple(tuple({"c": "C", "r3": "R3_new", "rs": "A"}[g] for g in order)
               for order in suite.ORDERS)
PREREQUISITES = ("primitive", "view-isolation", "service", "resource-lifecycle",
                 "pressure", "small-cache-150", "empty-cache", *[f"S{n}" for n in range(1, 9)])
BUDGET = {"cpu_ratio_to_R3_new_max": 1.05, "cpu_strictly_below_C": True,
          "qps_ratio_to_R3_new_min": .95, "p95_ratio_to_R3_new_max": 1.05,
          "zero_error_fd_group": "A", "errors_max": 0, "fd_leaks_max": 0}
QUALITY_KEYS = {"capture_lag_passed", "sample_count_passed", "reload_schedule_complete",
                "service_cpu_affinity_passed", "worker_cpu_affinity_passed", "drain_barrier_passed",
                "wake_metrics_passed", "diagnostic_scope_passed", "diagnostic_tools_passed",
                "diagnostic_raw_calls_passed"}


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    # Freezes/results are fresh files; never overwrite a prior experiment.
    with path.open("x") as output:
        output.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def digest(value, size=64):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{size}}}", value):
        raise ValueError(f"full lowercase {size}-character identity required")
    return value


def asset(reference):
    expected = digest(reference["sha256"])
    path = Path(reference["path"])
    if arithmetic.sha256(path) != expected:
        raise ValueError("frozen asset changed: " + str(path))
    return path


def rust_binding(binding):
    digest(binding["source_commit"], 40)
    freeze = read(asset(binding["source_freeze"]))
    build = read(asset(binding["build"]))
    elf = asset(binding["elf"])
    if freeze["source_commit"] != binding["source_commit"]:
        raise ValueError("source commit differs from independent group freeze")
    root = Path(freeze["source_root"])
    if not freeze.get("source_files"):
        raise ValueError("source freeze omitted product input hashes")
    for name, expected in freeze["source_files"].items():
        digest(expected)
        if arithmetic.sha256(root / name) != expected:
            raise ValueError("group product input changed: " + name)
    if (build["kind"] != "release" or build["opt_level"] != "3" or build.get("features") != ""
            or build["source"] != str(root) or build["cargo_target_dir"] != str(suite.TARGET)
            or build["artifacts"] != [{"path": "dnsmasq-rs", "bytes": elf.stat().st_size,
                                       "sha256": binding["elf"]["sha256"]}]
            or binding["elf"]["bytes"] != elf.stat().st_size):
        raise ValueError("group requires its own feature-off opt3 release receipt")
    # Source remapping and a private map path vary by immutable build directory;
    # all actual code generation/link flags must agree between the two groups.
    flags = build["rustflags"].replace(str(root), "<SOURCE>")
    flags = re.sub(r" -Clink-arg=-Wl,-Map=\S+", "", flags)
    return flags


def prerequisites(reference, a_binding):
    receipt = read(asset(reference))
    if (receipt.get("source_commit") != a_binding["source_commit"]
            or receipt.get("elf_sha256") != a_binding["elf"]["sha256"]
            or set(receipt.get("gates", {})) != set(PREREQUISITES)):
        raise ValueError("all Scheme A prerequisites must bind the same source/ELF")
    for name, row in receipt["gates"].items():
        if row.get("passed") is not True:
            raise ValueError("Scheme A prerequisite has not passed: " + name)
        asset(row["evidence"])
    return receipt


def command_for(common, binding, profile, round_no, output, pilot=False):
    """Adapter only: runner 'r3' dispatches both independently labelled opt3 ELFs."""
    spec = copy.deepcopy(common)
    if binding is not None:
        spec["groups"]["r3"] = {"elf": binding["elf"]["path"],
                                 "sha256": binding["elf"]["sha256"]}
    command = suite.command_for(spec, profile, "c" if binding is None else "r3",
                                round_no, Path(output), pilot)
    command += ["--clients", "20", "--cpu-daemon", "0", "--cpu-upstream", "1",
                "--cpu-load", "2", "--cpu-control", "3"]
    return command


def schedule(common, groups, output):
    rows = []
    for round_no, order in enumerate(ORDERS, 1):
        for profile in PROFILES:
            for group in order:
                job = f"r{round_no:02d}-{profile[0]}-{group}"
                binding = None if group == "C" else groups[group]
                directory = Path(output) / "runs" / job / "attempt-1"
                rows.append({"job_id": job, "round": round_no, "profile": profile[0], "group": group,
                             "expected_elf_sha256": (STOCK_SHA256 if binding is None
                                                     else binding["elf"]["sha256"]),
                             "source_commit": (None if binding is None else binding["source_commit"]),
                             "runner_implementation": "c" if binding is None else "r3",
                             "pilot_argv": command_for(common, binding, profile, round_no,
                                                       directory / "pilot", True),
                             "formal_argv": command_for(common, binding, profile, round_no,
                                                        directory / "formal")})
    return rows


def freeze(inputs, output_root):
    common = read(asset(inputs["common_manifest"]))
    if not common.get("m6b") or common.get("profiles") != [list(row) for row in suite.PROFILES]:
        raise ValueError("frozen common M6b native profiles required")
    suite.check_instrumentation(common, formal=True)
    if common["instrumentation"]["wake_metrics"]:
        raise ValueError("formal CPU gate cannot include wake sidecars")
    suite.verify(common, Path(inputs["common_manifest"]["path"]))
    suite.verify_controller(common, __file__)
    for module in (arithmetic, window):
        suite.verify_controller(common, module.__file__)
    if common["groups"]["c"]["sha256"] != STOCK_SHA256:
        raise ValueError("exact-image C reference required")
    if set(inputs["groups"]) != {"R3_new", "A"}:
        raise ValueError("two independent Rust groups R3_new/A required; A is not Rs")
    groups = inputs["groups"]
    flags = [rust_binding(groups[group]) for group in GROUPS[1:]]
    if flags[0] != flags[1]:
        raise ValueError("Rust groups changed flags other than their source/map paths")
    if (groups["R3_new"]["source_commit"] != common["source_commit"]
            or groups["R3_new"]["elf"]["sha256"] != common["groups"]["r3"]["sha256"]):
        raise ValueError("R3_new must be the new no-A common baseline, not M6a")
    if (groups["A"]["source_commit"] == groups["R3_new"]["source_commit"]
            or groups["A"]["elf"]["sha256"] == groups["R3_new"]["elf"]["sha256"]):
        raise ValueError("A and no-A baseline identities must be distinct")
    proof = prerequisites(inputs["prerequisites"], groups["A"])
    return {"schema": 1, "purpose": "Scheme A incremental CPU gate; not final 135-window qualification",
            "execution_enabled": False, "common_manifest": inputs["common_manifest"],
            "common": common, "groups": groups, "prerequisites": inputs["prerequisites"],
            "prerequisite_receipt": proof, "orders": ORDERS, "profiles": PROFILES,
            "expected_windows": 45, "budget": BUDGET, "phases": ["steady", "saturation"],
            "cpu_definition": "daemon cgroup usage_usec delta / correct in-phase completions; descendants counted once",
            "protocol_sha256": common["protocol_sha256"], "output_root": str(output_root),
            "configs": {p[0]: window.config_for(p[1], p[2]) for p in PROFILES},
            "schedule": schedule(common, groups, output_root),
            "analysis_sha256": arithmetic.sha256(arithmetic.__file__),
            "gate_tool_sha256": arithmetic.sha256(__file__)}


def validate_plan(plan):
    if (plan.get("schema") != 1 or plan.get("execution_enabled") is not False
            or plan.get("expected_windows") != 45 or plan.get("budget") != BUDGET
            or plan.get("phases") != ["steady", "saturation"]
            or plan.get("orders") != [list(row) for row in ORDERS]
            or plan.get("profiles") != [list(row) for row in PROFILES]):
        raise ValueError("plan differs from the frozen 45-window contract")
    if (plan["analysis_sha256"] != arithmetic.sha256(arithmetic.__file__)
            or plan["gate_tool_sha256"] != arithmetic.sha256(__file__)):
        raise ValueError("offline analysis code differs from frozen plan")
    for module in (suite, window):
        suite.verify_controller(plan["common"], module.__file__)
    if plan["schedule"] != schedule(plan["common"], plan["groups"], plan["output_root"]):
        raise ValueError("plan schedule/argv/expected identities changed")


def drain_failures(result, group):
    measured = result["measurement"]
    failures = []
    idle = measured["idle_fd_count"]
    if measured["cpu_before_warmup"]["tree"]["fd_count"] != idle:
        raise arithmetic.EvidenceError("idle FD count differs from actual pre-load snapshot")
    barrier = measured["drain_barrier"]
    needed = barrier["stable_samples_required"]
    observations = barrier["observations"][-needed:]
    if (needed < window.DRAIN_STABLE_SAMPLES or len(observations) != needed
            or barrier["completed_monotonic_ns"] != observations[-1]["monotonic_ns"]
            or any(b["monotonic_ns"] - a["monotonic_ns"] < window.DRAIN_SAMPLE_INTERVAL_SECONDS * 1e9
                   for a, b in zip(observations, observations[1:]))
            or any(not row["ready"] or row["stable_samples"] != index for index, row in enumerate(observations, 1))):
        raise arithmetic.EvidenceError("drain barrier has no independent stable observations")
    if (any(row["child_processes"] != 0 or row["fd_count"] != idle for row in observations)):
        failures.append("FD/children did not return to confirmed stable idle shape")
    if group != "C" and barrier.get("idle_fd_count") != idle:
        raise arithmetic.EvidenceError("Rust drain used a child-only criterion")
    samples = measured["drain_samples"]
    for offset in ("0", "1", "5", "60"):
        if offset not in samples:
            raise arithmetic.EvidenceError("missing fixed post-drain sample " + offset)
        row = samples[offset]
        scheduled = barrier["completed_monotonic_ns"] + int(offset) * 1_000_000_000
        if (row["scheduled_offset_seconds"] != int(offset) or row["scheduled_monotonic_ns"] != scheduled
                or not 0 <= row["captured_monotonic_ns"] - scheduled <= 250_000_000):
            raise arithmetic.EvidenceError("incorrect fixed post-drain sample offset")
        if row["snapshot"]["tree"]["fd_count"] != idle or row["snapshot"]["tree"]["child_processes"]:
            failures.append("FD/child leak at drain+" + offset)
    return failures


def idle_check(result):
    idle = result["measurement"]["idle_cpu"]
    elapsed = (idle["ended_monotonic_ns"] - idle["started_monotonic_ns"]) / 1e9
    usage = idle["cgroup_after"]["usage_usec"] - idle["cgroup_before"]["usage_usec"]
    if (idle.get("enabled") is not True or idle["requested_seconds"] != 60 or not 60 <= elapsed <= 60.5
            or abs(idle["elapsed_seconds"] - elapsed) > 1e-6 or usage < 0
            or abs(idle["cpu_seconds"] * 1e6 - usage) > 1):
        raise arithmetic.EvidenceError("invalid 60-second no-load CPU evidence")
    return idle


def attempt_argv(planned, number, kind):
    argv = list(planned[kind + "_argv"])
    index = argv.index("--output") + 1
    argv[index] = str(Path(argv[index]).parent.parent / f"attempt-{number}" / kind)
    return argv


def pilot_and_scope(planned, directory, record, behavior_failed=False):
    pilot = directory.parent / "pilot/result.json"
    if record.get("pilot_passed") is not True or arithmetic.sha256(pilot) != record.get("pilot_result_sha256"):
        raise arithmetic.EvidenceError("pilot was not passed and bound before formal window")
    report = read(pilot)
    profile = next(p for p in PROFILES if p[0] == planned["profile"])
    pilot_behavior = (suite.pilot_behavior(report, profile) if planned["group"] == "A" else
                      bool(report.get("measurement", {}).get("load", {}).get("measurement", {}).get("correct")))
    if (not report.get("measurement_valid") or not pilot_behavior
            or report["identity"].get("expected_elf_sha256") != planned["expected_elf_sha256"]
            or report["identity"].get("argv") != attempt_argv(planned, record["attempt"], "pilot")[3:]):
        raise arithmetic.EvidenceError("pilot methodology, behavior or invocation differs")
    for kind in ("pilot", "formal"):
        execution = record[kind + "_command"]
        returns = (0, 1) if kind == "formal" and behavior_failed else (0,)
        if (execution["argv"] != attempt_argv(planned, record["attempt"], kind)
                or execution["returncode"] not in returns or execution.get("foreign_load")
                or execution["finished_ns"] <= execution["started_ns"]):
            raise arithmetic.EvidenceError("window command failed, changed or was contaminated")
    if record["pilot_command"]["finished_ns"] > record["formal_command"]["started_ns"]:
        raise arithmetic.EvidenceError("pilot did not finish before formal window")


def window_identity(plan, planned, directory, receipt):
    result = read(directory / "result.json")
    identity = result["identity"]
    expected = {"implementation": planned["runner_implementation"], "scenario": "tcp",
                "tcp_profile": {"tcp-local": "local", "tcp-cache": "hit", "tcp-miss": "miss"}[planned["profile"]],
                "round": planned["round"], "expected_elf_sha256": planned["expected_elf_sha256"],
                "protocol_sha256": plan["protocol_sha256"], "warmup_seconds": 30, "duration_seconds": 120,
                "saturation_seconds": 30, "rate": 10000, "clients": 20,
                "idle_cpu_seconds": 60, "drain_sample_seconds": [0, 1, 5, 60],
                "excluded_preflight": False, "wake_metrics": False, "perf_record": False,
                "strace_summary": False, "cpus": {"daemon": 0, "upstream": 1, "loadgen": 2, "control": 3},
                "seed": 0x4d364100 + planned["round"],
                "runner_sha256": plan["common"]["tools_files"]["m6a_window.py"],
                "loadgen_sha256": plan["common"]["native"]["m6a_loadgen"]["sha256"],
                "upstream_sha256": plan["common"]["native"]["m6a_upstream"]["sha256"]}
    if any(identity.get(key) != value for key, value in expected.items()):
        raise arithmetic.EvidenceError("formal identity differs from planned group/window")
    # The runner's identity does not expose every workload flag (cache-names,
    # timeout, and TCP stream limits), so also retain its exact invocation.
    if identity.get("argv") != attempt_argv(planned, receipt["attempt"], "formal")[3:]:
        raise arithmetic.EvidenceError("runner invocation differs from planned native workload")
    if (receipt.get("group") != planned["group"] or receipt.get("source_commit") != planned["source_commit"]
            or receipt.get("elf_sha256") != planned["expected_elf_sha256"]
            or receipt.get("protocol_sha256") != plan["protocol_sha256"]
            or receipt.get("formal_result_sha256") != arithmetic.sha256(directory / "result.json")):
        raise arithmetic.EvidenceError("receipt lost independent source/group/ELF binding")
    if (directory / "config").read_text() != plan["configs"][planned["profile"]]:
        raise arithmetic.EvidenceError("formal configuration changed")
    if read(directory / "identity.json") != identity:
        raise arithmetic.EvidenceError("standalone identity differs from result")
    process = read(directory / "process-identity.json")
    if process["sha256"] != planned["expected_elf_sha256"]:
        raise arithmetic.EvidenceError("actual daemon ELF differs from planned artifact")
    return result


def raw_behavior_failures(result):
    """Known product failures are terminal even if the old runner calls them invalid.

    Missing artifacts, sampling problems and worker failures are not silently
    reclassified as product behavior. This list only uses explicit observations.
    """
    failures = []
    cleanup = result.get("cleanup", {})
    if cleanup.get("forced_kill") or ("returncode" in cleanup and cleanup["returncode"] != 0):
        failures.append("daemon required forced kill or exited unsuccessfully")
    if result.get("cgroup_cleanup", {}).get("remaining_pids"):
        failures.append("daemon descendants remained after cleanup")
    upstream = result.get("upstream", {})
    if upstream.get("invalid_queries", 0):
        failures.append("daemon sent invalid upstream queries")
    if result.get("unexpected_upstream_requests") or upstream.get("disabled_requests", 0):
        failures.append("full-cache workload unexpectedly reached upstream")
    error = result.get("error", {})
    if error.get("type") == "TimeoutError" and error.get("message", "").startswith("daemon did not drain to stable FD count"):
        failures.append("TCP clients/FDs failed the bounded drain barrier")
    for phase, counts in result.get("measurement", {}).get("load", {}).items():
        if phase in ("warmup", "measurement") and any(counts.get(key, 0) for key in ("wrong", "timeout", "transport_error")):
            failures.append(phase + " contains genuine wrong/timeout/transport errors")
    return failures


def hard_behavior(group, reasons):
    # C/no-A errors remain observed baselines, not new A regressions. Lifecycle
    # cleanup integrity still applies to every group and cannot be rerun away.
    return group == "A" or any(reason in {
        "daemon required forced kill or exited unsuccessfully", "daemon descendants remained after cleanup",
        "daemon cleanup/lifecycle failure"} for reason in reasons)


def attempt_directory(root, job, number, phase):
    candidates = [root / "archives" / job / f"attempt-{number}" / "plain" / phase,
                  root / "runs" / job / f"attempt-{number}" / phase]
    found = [p for p in candidates if (p / "result.json").exists()]
    if len(found) == 2 and arithmetic.sha256(found[0] / "result.json") != arithmetic.sha256(found[1] / "result.json"):
        raise arithmetic.EvidenceError("archive and run disagree")
    return found[0] if found else None


def terminal_attempts(root, job, planned, records, plan):
    """Scan every retained attempt before selection; never rerun a real failure."""
    failed = []
    for record in records:
        if (record.get("failure_kind") == "behavior" and record.get("group") == planned["group"]
                and record.get("elf_sha256") == planned["expected_elf_sha256"]
                and not any(record.get(k + "_command", {}).get("foreign_load") for k in ("pilot", "formal"))):
            failed.append({"attempt": record["attempt"], "phase": "receipt", "reasons": record.get("failures", [])})
        for phase in ("pilot", "formal"):
            directory = attempt_directory(root, job, record["attempt"], phase)
            if directory is None:
                continue
            result = read(directory / "result.json")
            identity = result.get("identity", {})
            command = record.get(phase + "_command", {})
            quality = result.get("measurement", {}).get("quality", {})
            # A wrong fixture, explicit contamination or tool interruption may
            # induce timeout/forced cleanup. Preserve it as a method failure.
            if (identity.get("expected_elf_sha256") != planned["expected_elf_sha256"]
                    or identity.get("protocol_sha256") != plan["protocol_sha256"]
                    or identity.get("implementation") != planned["runner_implementation"]
                    or identity.get("argv") != attempt_argv(planned, record["attempt"], phase)[3:]
                    or command.get("foreign_load") != [] or command.get("returncode") not in (0, 1)
                    or (quality and not all(quality.values()))
                    or result.get("measurement", {}).get("load", {}).get("interrupted")
                    or result.get("measurement", {}).get("load", {}).get("output_failed")):
                continue
            if (read(directory / "process-identity.json")["sha256"] != planned["expected_elf_sha256"]
                    or (directory / "config").read_text() != plan["configs"][planned["profile"]]):
                continue
            behavior = raw_behavior_failures(result)
            if behavior:
                failed.append({"attempt": record["attempt"], "phase": phase, "reasons": behavior,
                               "raw_result_sha256": arithmetic.sha256(directory / "result.json")})
    return failed


def analyze(plan_path, root):
    plan = read(plan_path)
    validate_plan(plan)
    plan_sha = arithmetic.sha256(plan_path)
    state = read(root / "state.json")
    if state.get("plan_sha256") != plan_sha:
        raise ValueError("state belongs to another frozen CPU gate plan")
    planned = {row["job_id"]: row for row in plan["schedule"]}
    if set(state.get("windows", {})) - set(planned):
        raise ValueError("state includes jobs outside the 45-window plan")
    rows, failures, attempts = [], [], []
    previous_finished = None
    for job, expected in planned.items():
        selected = state.get("windows", {}).get(job, {})
        attempts.append({"job_id": job, "valid_attempt": selected.get("valid_attempt"),
                         "attempts": selected.get("attempts", [])})
        try:
            terminal = terminal_attempts(root, job, expected, selected.get("attempts", []), plan)
        except (ValueError, KeyError, TypeError, OSError) as error:
            failures.append({"job_id": job, "kind": "methodology", "reason": str(error)})
            continue
        failures += [{"job_id": job, "group": expected["group"], "kind": "behavior",
                      "hard_failure": hard_behavior(expected["group"], row["reasons"]),
                      **row} for row in terminal]
        number = selected.get("valid_attempt")
        if number is None:
            continue
        try:
            records = selected["attempts"]
            record = next(row for row in records if row["attempt"] == number)
            if any(row["attempt"] < number and (row.get("methodology_valid") is True
                    or row.get("failure_kind") == "behavior") for row in records) or any(row["attempt"] < number for row in terminal):
                raise arithmetic.EvidenceError("later attempt replaces an earlier genuine result")
            if (record.get("methodology_valid") is not True or record.get("plan_sha256") != plan_sha
                    or not record.get("archive", {}).get("local_verified")):
                raise arithmetic.EvidenceError("selected attempt has no method/plan/local archive qualification")
            directory = attempt_directory(root, job, number, "formal")
            if directory is None:
                raise arithmetic.EvidenceError("selected raw formal evidence unavailable")
            raw = read(directory / "result.json")
            observed_behavior = raw_behavior_failures(raw)
            pilot_and_scope(expected, directory, record, bool(observed_behavior))
            if previous_finished is not None and record["pilot_command"]["started_ns"] < previous_finished:
                raise arithmetic.EvidenceError("actual windows overlapped or ignored frozen interleaved order")
            previous_finished = record["formal_command"]["finished_ns"]
            result = window_identity(plan, expected, directory, record)
            row = arithmetic.analyze_window(directory)
            row.update(group=expected["group"], job_id=job, attempt=number,
                       source_commit=expected["source_commit"], elf_sha256=expected["expected_elf_sha256"])
            # The old accepted flag also includes product cleanup/wire checks.
            # Full raw arithmetic and explicit sampler quality can still verify
            # its CPU observation; retain the acceptance failure as terminal.
            quality = result["measurement"].get("quality", {})
            if (not row["methodology_valid"] and observed_behavior and QUALITY_KEYS <= quality.keys() and all(quality.values())
                    and not row["analysis_errors"]):
                row["methodology_valid"] = True
                row["runner_acceptance_failed_on_behavior"] = observed_behavior
            if not row["methodology_valid"] or row["analysis_errors"]:
                raise arithmetic.EvidenceError("raw-window methodology invalid: " + repr(row["analysis_errors"]))
            behavior = list(observed_behavior)
            behavior += drain_failures(result, expected["group"])
            row["idle_cpu"] = idle_check(result)
            if (result.get("error") or result.get("cleanup_error") or result.get("cgroup_cleanup_error")
                    or result["cleanup"]["forced_kill"] or result["cleanup"]["returncode"] != 0
                    or result["cgroup_cleanup"].get("remaining_pids") or not result["cgroup_cleanup"].get("removed")):
                behavior.append("daemon cleanup/lifecycle failure")
            row["behavior_failures"] = behavior
            additional = [reason for reason in behavior if reason not in observed_behavior]
            if additional:
                failures.append({"job_id": job, "group": expected["group"], "kind": "behavior", "reasons": additional,
                                 "hard_failure": hard_behavior(expected["group"], additional)})
            rows.append(row)
        except (ValueError, KeyError, TypeError, StopIteration, OSError) as error:
            failures.append({"job_id": job, "kind": "methodology", "reason": str(error)})
    comparisons, gates = [], []
    complete = len(rows) == 45
    for profile in (p[0] for p in PROFILES):
        for phase in ("steady", "saturation"):
            groups = {}
            for group in GROUPS:
                values = sorted((row for row in rows if row["profile"] == profile and row["group"] == group),
                                key=lambda row: row["round"])
                groups[group] = [next(p for p in row["phases"] if p["phase"] == phase) for row in values]
            if any(len(values) != 5 for values in groups.values()):
                gates.append({"profile": profile, "phase": phase, "passed": False, "reason": "five complete paired rounds required"})
                continue
            metrics = lambda group, key: [row[key] for row in groups[group]]
            cpu = {g: metrics(g, "cpu_us_per_correct") for g in GROUPS}
            qps = {g: metrics(g, "qps") for g in GROUPS}
            p95 = {g: [row["latency_ns"]["p95"] for row in groups[g]] for g in GROUPS}
            if any(v is None or not math.isfinite(v) or v <= 0 for data in (cpu, qps, p95) for group in data.values() for v in group):
                gates.append({"profile": profile, "phase": phase, "passed": False, "reason": "missing/nonpositive CPU, throughput or p95"})
                continue
            med = lambda values: {g: statistics.median(v) for g, v in values.items()}
            u, q, p = med(cpu), med(qps), med(p95)
            checks = {"cpu_to_R3_new": u["A"] <= 1.05 * u["R3_new"], "cpu_below_C": u["A"] < u["C"],
                      "qps_to_R3_new": q["A"] >= .95 * q["R3_new"], "p95_to_R3_new": p["A"] <= 1.05 * p["R3_new"]}
            limited_groups = [g for g in GROUPS if any(row["generator_limited"] for row in groups[g])]
            throughput_limited = any(g in limited_groups for g in ("R3_new", "A"))
            gates.append({"profile": profile, "phase": phase, "passed": all(checks.values()) and not throughput_limited,
                          "numeric_passed": all(checks.values()), "cpu_budget_passed": checks["cpu_to_R3_new"] and checks["cpu_below_C"],
                          "throughput_qualification": ("restricted; native generator limited" if throughput_limited else
                                                        "qualified" if checks["qps_to_R3_new"] else "failed"),
                          "generator_limited_groups": limited_groups, "checks": checks,
                          "median_cpu_us_per_correct": u, "median_qps": q, "median_p95_ns": p,
                          "cpu_ratio_to_R3_new": u["A"] / u["R3_new"], "p95_ratio_to_R3_new": p["A"] / p["R3_new"],
                          "qps_ratio_to_R3_new": q["A"] / q["R3_new"]})
            for reference in ("C", "R3_new"):
                limited = any(row["generator_limited"] for group in (reference, "A") for row in groups[group])
                for metric, data in (("cpu_us_per_correct", cpu), ("qps", qps), ("p95_ns", p95)):
                    comparisons.append({"profile": profile, "phase": phase, "comparison": "A/" + reference,
                                        "metric": metric, "generator_limited": limited,
                                        **arithmetic.classify(data[reference], data["A"], metric, limited and metric == "qps")})
    totals = {group: {phase: {key: sum(row["load_counters"][phase][key] for row in rows if row["group"] == group)
                             for key in ("correct", "wrong", "timeout", "transport_error")}
                      for phase in ("warmup", "measurement")} for group in GROUPS}
    hard_failures = any(row.get("hard_failure", True) for row in failures)
    numeric_failed = any(not row.get("numeric_passed", False) for row in gates)
    restricted = any(row.get("throughput_qualification", "").startswith("restricted") for row in gates)
    qualification = ("incomplete" if not complete else "failed" if hard_failures or numeric_failed else
                     "unproven" if restricted else "qualified")
    return {"schema": 1, "plan_sha256": plan_sha, "state_sha256": arithmetic.sha256(root / "state.json"),
            "purpose": plan["purpose"], "expected_windows": 45, "valid_windows": len(rows), "complete": complete,
            "passed": qualification == "qualified", "qualification": qualification,
            "qualification_reason": ("generator-limited throughput is unproven; observed CPU/p95/numeric QPS budgets remain evaluated"
                                     if qualification == "unproven" else None),
            "budget": BUDGET, "per_group_counts": totals,
            "cpu_definition": plan["cpu_definition"], "windows": rows, "budget_gates": gates,
            "comparisons": comparisons, "failures": failures, "all_attempts": attempts,
            "missing_jobs": sorted(set(planned) - {row["job_id"] for row in rows})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="bind completed prerequisites and emit argv only; never execute")
    plan.add_argument("--inputs", type=Path, required=True)
    plan.add_argument("--output-root", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    analysis = commands.add_parser("analyze", help="read a plan and locally archived state/raw evidence only")
    analysis.add_argument("--plan", type=Path, required=True)
    analysis.add_argument("--root", type=Path, required=True)
    analysis.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = (freeze(read(args.inputs), args.output_root) if args.command == "plan"
             else analyze(args.plan, args.root))
    save(args.output, value)
    print(json.dumps({key: value[key] for key in ("expected_windows",)} |
                     ({"execution_enabled": False} if args.command == "plan" else
                      {key: value[key] for key in ("valid_windows", "complete", "passed")})))
    return 0 if args.command == "plan" or value["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
