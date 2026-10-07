#!/usr/bin/env python3
"""Serial execution adapter for the frozen Scheme A 45-window plan.

No builds, profile filters, group aliases or result selection. Each attempt uses
the common runner/lock/archive gate; cancellation is terminal after cleanup and
full local archive verification. Invoke only on the isolated Linux Oracle.
"""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import m5_final_validation as cleanup
import m6b_tcp_cpu_gate as gate

suite = gate.suite


class Cancelled(BaseException):
    pass


class WitnessedProcess:
    """Generation-checked handle for a prior controller's orphaned job root."""
    def __init__(self, pid, start):
        self.pid, self.start = pid, start

    def poll(self):
        row = cleanup.process_tree().get(self.pid)
        return None if row and row["starttime"] == self.start and row["state"] != "Z" else 0

    def wait(self, timeout):
        end = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= end:
                raise subprocess.TimeoutExpired("witnessed job root", timeout)
            time.sleep(.02)
        return 0


class ProcessWitness:
    def __init__(self, path):
        self.path, self.process, self.known, self.errors = path, None, {}, []
        if path.exists():
            prior = gate.read(path)
            self.known = {int(pid): row for pid, row in prior["known"].items()}
            root = prior.get("root_pid")
            if root in self.known:
                self.process = WitnessedProcess(root, self.known[root]["starttime"])

    def observe(self, process=None):
        if process is not None:
            self.process = process
        try:
            live = cleanup.remember_job_processes(self.process, self.known) if self.process else {}
            suite.save(self.path, {"root_pid": self.process.pid if self.process else None,
                                  "known": self.known, "live": live, "errors": self.errors,
                                  "observed_ns": time.time_ns()})
            return live
        except Exception as error:
            self.errors.append(repr(error))
            return None

    def finish(self):
        before = self.observe()
        if before and self.process:
            cleanup.stop_job_processes(self.process, self.known)
        after = self.observe()
        if self.errors or after is None or after:
            raise RuntimeError("job process cleanup/witness failed: " + repr(self.errors or after))


class Cancellation:
    def __init__(self, state, state_path):
        self.state, self.state_path, self.witness = state, state_path, None
        self.archiving, self.plan = False, None
        self.request = state.get("cancellation")

    def handler(self, signum, _frame):
        if not self.request:
            self.request = {"signal": signum, "requested_ns": time.time_ns(),
                            "plan_sha256": self.state.get("plan_sha256"),
                            "job_id": self.state.get("current_job"), "phase": self.state.get("current_phase")}
            if self.state_path:
                try:
                    suite.save(self.state_path.with_name("cancellation-request.json"), self.request)
                except OSError as error:
                    self.request["persistence_error"] = repr(error)
            # Sticky-only: never unwind the interval between Popen and its
            # protected observer binding, or reenter the main journal writer.

    def publish(self):
        if self.request:
            self.state["cancellation"] = self.request
            if self.state_path:
                suite.save(self.state_path, self.state)

    def check(self):
        self.publish()
        if self.request and not self.archiving:
            raise Cancelled(self.request["signal"])

    @contextlib.contextmanager
    def installed(self):
        previous = {sig: signal.signal(sig, self.handler) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            yield
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def verify(plan, plan_path, expected_sha):
    if suite.sha256(plan_path) != expected_sha:
        raise ValueError("frozen CPU plan changed")
    gate.validate_plan(plan)
    common_path = gate.asset(plan["common_manifest"])
    if gate.read(common_path) != plan["common"]:
        raise ValueError("common manifest differs from embedded freeze")
    common = plan["common"]
    suite.verify(common, common_path)
    for module in (gate, cleanup):
        suite.verify_controller(common, module.__file__)
    controller = suite.verify_controller(common, __file__)
    flags = [gate.rust_binding(plan["groups"][group]) for group in ("R3_new", "A")]
    if flags[0] != flags[1] or gate.prerequisites(plan["prerequisites"], plan["groups"]["A"]) != plan["prerequisite_receipt"]:
        raise ValueError("independent Rust bindings/prerequisites changed")
    if Path(plan["output_root"]).resolve() != (Path(common["root"]) / "private").resolve():
        raise ValueError("CPU plan must use common-root/private; nested controller/result roots forbidden")
    return controller


def initial_state(plan, plan_sha, private):
    path = private / "state.json"
    prior = gate.read(path) if path.exists() else None
    if prior and prior.get("plan_sha256") == plan_sha:
        if prior.get("expected_windows") != 45:
            raise ValueError("CPU state window count differs")
        return prior
    preserved = None
    if prior:
        if (prior.get("windows") or prior.get("events") or prior.get("status") != "prepared"
                or prior.get("formal_valid_windows") != 0 or prior.get("expected_windows") != 135
                or prior.get("manifest_sha256") != plan["common_manifest"]["sha256"]):
            raise ValueError("cannot replace nonempty or mismatched common/CPU state")
        preserved = private / "common-state-before-cpu.json"
        if preserved.exists() and preserved.read_bytes() != path.read_bytes():
            raise ValueError("preserved empty common state differs")
        if not preserved.exists():
            with preserved.open("xb") as output:
                output.write(path.read_bytes())
    state = {"manifest_sha256": plan["common_manifest"]["sha256"], "plan_sha256": plan_sha,
             "expected_windows": 45, "formal_valid_windows": 0, "windows": {}, "events": [], "status": "prepared"}
    if preserved:
        state["common_state_before_cpu"] = {"path": str(preserved), "sha256": suite.sha256(preserved)}
    suite.save(path, state)
    return state


def execute_phase(plan, planned, record, attempt, phase, state, state_path, cancel):
    cancel.check()
    state["current_phase"] = phase
    suite.save(state_path, state)
    witness = ProcessWitness(attempt / (phase + ".process-witness.json"))
    cancel.witness = witness
    def observe(process):
        witness.observe(process)
        cancel.check()  # suite.execute has already entered its cleanup try
    try:
        record[phase + "_command"] = suite.execute(gate.attempt_argv(planned, record["attempt"], phase),
                                                   attempt / (phase + ".log"), state, state_path, observe)
    finally:
        command = attempt / (phase + ".command.json")
        if command.exists():
            record[phase + "_command"] = gate.read(command)
        witness.finish()
        cancel.witness = None
    result_path = attempt / phase / "result.json"
    record[phase + "_result_sha256"] = suite.sha256(result_path)
    result = gate.read(result_path)
    terminal = gate.terminal_attempts(Path(plan["output_root"]), record["job_id"], planned, [record], plan)
    hard = [reason for row in terminal for reason in row["reasons"] if gate.hard_behavior(planned["group"], [reason])]
    if hard:
        record.update(failure_kind="behavior", behavior_failures=hard)
        record["failures"] += hard
    command = record[phase + "_command"]
    if command["foreign_load"] or command["returncode"] not in ((0, 1) if terminal else (0,)):
        raise RuntimeError(phase + " command failed/contaminated")
    return result, bool(hard)


def archive_attempt(plan, private, record, state, state_path, cancel):
    attempt = private / "runs" / record["job_id"] / f"attempt-{record['attempt']}"
    cancel.archiving = True
    try:
        for phase in ("pilot", "formal"):
            witness = attempt / (phase + ".process-witness.json")
            if witness.exists():
                ProcessWitness(witness).finish()
        suite.save(attempt / "receipt.json", record)
        suite.save(state_path, state)
        suite.archive_gate(plan["common"], attempt, record, state, state_path)
    finally:
        cancel.archiving = False
    cancel.publish()
    if record["methodology_valid"]:
        state["windows"][record["job_id"]]["valid_attempt"] = record["attempt"]
    state["formal_valid_windows"] = sum(row["valid_attempt"] is not None for row in state["windows"].values())
    suite.save(state_path, state)


def stopped(state):
    if state.get("cancellation"):
        return "cancelled", 128 + state["cancellation"]["signal"]
    if state.get("stop_reason") == "behavior-budget":
        return "behavior-budget", 1
    return None, None


def recover_attempt(plan, private, planned, record, state):
    """Hydrate durable command/result sidecars before permitting any retry."""
    attempt = private / "runs" / record["job_id"] / f"attempt-{record['attempt']}"
    for phase in ("pilot", "formal"):
        command = attempt / (phase + ".command.json")
        result = attempt / phase / "result.json"
        if command.exists():
            record[phase + "_command"] = gate.read(command)
        if result.exists():
            record[phase + "_result_sha256"] = suite.sha256(result)
    if state.get("cancellation"):
        record.update(methodology_valid=False, failure_kind="cancelled", finished=True)
        record["failures"].append("cancelled prior controller; no next window")
        return
    try:
        terminal = gate.terminal_attempts(private, record["job_id"], planned, [record], plan)
        hard = [reason for row in terminal for reason in row["reasons"] if gate.hard_behavior(planned["group"], [reason])]
        if hard:
            record.update(failure_kind="behavior", behavior_failures=hard)
            record["failures"] += hard
            state["stop_reason"] = "behavior-budget"
        if "formal_result_sha256" not in record:
            raise RuntimeError("prior controller interrupted before complete formal result")
        gate.assess_pilot(plan, planned, attempt / "pilot", record)
        record["pilot_passed"] = True
        gate.pilot_and_scope(planned, attempt / "formal", record,
                             bool(gate.raw_behavior_failures(gate.read(attempt / "formal/result.json"))), plan)
        row, _ = gate.assess_formal(plan, planned, attempt / "formal", record)
        record.update(methodology_valid=True, behavior_failures=row["behavior_failures"])
        if row["behavior_failures"] and gate.hard_behavior(planned["group"], row["behavior_failures"]):
            record["failure_kind"] = "behavior"
            record["failures"] += row["behavior_failures"]
            state["stop_reason"] = "behavior-budget"
    except Exception as error:
        record.update(methodology_valid=False, failure_kind=record.get("failure_kind", "methodology"))
        record["failures"].append(repr(error))
    record["finished"] = True


def settle_pending(plan, private, state, state_path, cancel):
    # Finish every interrupted attempt's copy/verify/prune before resuming.
    for selected in state["windows"].values():
        for record in selected["attempts"]:
            if not record.get("archive", {}).get("local_verified"):
                if not record.get("finished"):
                    planned = next(row for row in plan["schedule"] if row["job_id"] == record["job_id"])
                    recover_attempt(plan, private, planned, record, state)
                archive_attempt(plan, private, record, state, state_path, cancel)


def run_frozen(plan_path, cancel):
    plan_path = plan_path.resolve()
    plan, plan_sha = gate.read(plan_path), suite.sha256(plan_path)
    private = Path(plan["output_root"])
    if private.resolve() != (Path(plan["common"]["root"]) / "private").resolve():
        raise ValueError("CPU plan must use common-root/private")
    private.mkdir(parents=True, exist_ok=True)
    with (private / ".cpu-controller.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        controller = verify(plan, plan_path, plan_sha)
        return run_locked(plan_path, plan, plan_sha, private, controller, cancel)


def run_locked(plan_path, plan, plan_sha, private, controller, cancel):
    state_path = private / "state.json"
    cancel.archiving = True  # preserve/promote the empty state as one transaction
    try:
        state = initial_state(plan, plan_sha, private)
        marker = state_path.with_name("cancellation-request.json")
        if marker.exists():
            request = gate.read(marker)
            if request.get("plan_sha256") != plan_sha:
                raise ValueError("cancellation marker belongs to another freeze")
            cancel.request = request
        cancel.request = cancel.request or state.get("cancellation")
        if cancel.request:
            state["cancellation"] = cancel.request
        cancel.state, cancel.state_path, cancel.plan = state, state_path, plan
    finally:
        cancel.archiving = False
    if set(state["windows"]) - {row["job_id"] for row in plan["schedule"]}:
        raise ValueError("state has windows outside frozen schedule")
    os.sched_setaffinity(0, {3})
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    state.update(controller_pid=os.getpid(), controller_identity=controller)
    settle_pending(plan, private, state, state_path, cancel)
    reason, status = stopped(state)
    if reason:
        state.update(status="partial-complete", stop_reason=reason)
        suite.save(state_path, state)
        return status
    for planned in plan["schedule"]:
        cancel.check()
        job = planned["job_id"]
        selected = state["windows"].setdefault(job, {"round": planned["round"], "profile": planned["profile"],
                                                    "group": planned["group"], "attempts": [], "valid_attempt": None})
        if selected["valid_attempt"] is not None:
            record = next(row for row in selected["attempts"] if row["attempt"] == selected["valid_attempt"])
            expected = {"plan_sha256": plan_sha, "group": planned["group"], "source_commit": planned["source_commit"],
                        "elf_sha256": planned["expected_elf_sha256"], "protocol_sha256": plan["protocol_sha256"]}
            if (any(record.get(key) != value for key, value in expected.items()) or not record.get("methodology_valid")
                    or not record.get("archive", {}).get("local_verified")
                    or any(row["attempt"] < record["attempt"] and row.get("methodology_valid") for row in selected["attempts"])):
                raise ValueError("selected previous attempt lost binding/qualification or replaced genuine data")
            continue
        if gate.terminal_attempts(private, job, planned, selected["attempts"], plan):
            raise ValueError("cannot replace an earlier genuine result")
        number = len(selected["attempts"]) + 1
        attempt = private / "runs" / job / f"attempt-{number}"
        attempt.mkdir(parents=True, exist_ok=False)
        record = {"job_id": job, "round": planned["round"], "profile": planned["profile"], "group": planned["group"],
                  "attempt": number, "plan_sha256": plan_sha, "manifest_sha256": plan["common_manifest"]["sha256"],
                  "source_commit": planned["source_commit"], "elf_sha256": planned["expected_elf_sha256"],
                  "protocol_sha256": plan["protocol_sha256"], "methodology_valid": False, "pilot_passed": False,
                  "failures": [], "controller_identity": controller}
        selected["attempts"].append(record)
        state.update(current_job=job, current_attempt=number, status="running")
        suite.save(state_path, state)
        try:
            cancel.check()
            with (suite.TARGET / ".dnsmasq-build.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                verify(plan, plan_path, plan_sha)
                if suite.foreign_load():
                    raise RuntimeError("other build/test active before CPU window")
                _, hard = execute_phase(plan, planned, record, attempt, "pilot", state, state_path, cancel)
                if hard:
                    state["stop_reason"] = "behavior-budget"
                else:
                    pilot_row, behavior_ok = gate.assess_pilot(plan, planned, attempt / "pilot", record)
                    if planned["group"] == "A" and (not behavior_ok or pilot_row["behavior_failures"]):
                        record.update(failure_kind="behavior", behavior_failures=pilot_row["behavior_failures"])
                        record["failures"] += pilot_row["behavior_failures"] or ["A pilot correctness failed"]
                        state["stop_reason"] = "behavior-budget"
                        raise RuntimeError("A pilot error/FD hard gate failed")
                    record["pilot_passed"] = True
                    cancel.check()
                    verify(plan, plan_path, plan_sha)
                    _, hard = execute_phase(plan, planned, record, attempt, "formal", state, state_path, cancel)
                    if hard:
                        state["stop_reason"] = "behavior-budget"
                    row, _ = gate.assess_formal(plan, planned, attempt / "formal", record)
                    record.update(methodology_valid=True, behavior_failures=row["behavior_failures"])
                    if gate.hard_behavior(planned["group"], row["behavior_failures"]) and row["behavior_failures"]:
                        record["failure_kind"] = "behavior"
                        record["failures"] += row["behavior_failures"]
                        state["stop_reason"] = "behavior-budget"
                    verify(plan, plan_path, plan_sha)
        except Cancelled:
            record.update(methodology_valid=False, failure_kind="cancelled")
            record["failures"].append("controlled cancellation; no next window")
        except Exception as error:
            record["methodology_valid"] = False
            record["failure_kind"] = record.get("failure_kind", "methodology")
            record["failures"].append(repr(error))
        record["finished"] = True
        archive_attempt(plan, private, record, state, state_path, cancel)
        reason, status = stopped(state)
        if reason:
            state["stop_reason"] = reason
        state["status"] = ("partial-complete" if reason else
                           "failed-tools-or-environment" if record["failures"] else "running")
        suite.save(state_path, state)
        print(json.dumps({"job": job, "attempt": number, "formal_valid_windows": state["formal_valid_windows"],
                          "status": state["status"], "stop_reason": reason, "failures": record["failures"]}), flush=True)
        if reason:
            return status
        if record["failures"]:
            return 1
    cancel.check()
    state["status"] = "complete"
    suite.save(state_path, state)
    return 0


def run(plan_path):
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("Linux Oracle/root required; no local host execution")
    cancel = Cancellation({}, None)
    with cancel.installed():  # replace inherited SIGINT_IGN before any asset IO
        try:
            os.sched_setaffinity(0, {3})
            cancel.check()
            return run_frozen(plan_path, cancel)
        except Cancelled as error:
            if cancel.plan:
                state = cancel.state
                settle_pending(cancel.plan, Path(cancel.plan["output_root"]), state, cancel.state_path, cancel)
                state.update(status="partial-complete", stop_reason="cancelled")
                suite.save(cancel.state_path, state)
            return 128 + int(error.args[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    return run(parser.parse_args().plan)


if __name__ == "__main__":
    raise SystemExit(main())
