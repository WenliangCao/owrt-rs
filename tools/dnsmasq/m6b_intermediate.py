#!/usr/bin/env python3
"""Run the one-round M6b intermediate candidate matrix.

This deliberately runs the frozen formal window once per profile and group.  It
does not alter the product or the final five-round schedule; it exists to free
the Oracle for the TCP Scheme A gates before the final candidate is frozen.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path

import m6a_suite as suite


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def command_for(spec, profile, group, output, diagnostic=None):
    """Construct either the normal intermediate window or excluded trace run."""
    command = suite.command_for(spec, profile, group, 1, output, bool(diagnostic))
    # Trace evidence is a separate experiment, never a source of formal CPU or
    # latency comparisons.  The fixed short workload is warmup 2s + load 15s,
    # followed by the same stable drain; no 60s retention sampling is traced.
    command = [arg for arg in command if arg != "--wake-metrics"]
    if diagnostic:
        replacements = {"--warmup": "2", "--duration": "15", "--saturation-seconds": "0",
                        "--idle-seconds": "0", "--drain-sample-seconds": "0"}
        for flag, value in replacements.items():
            command[command.index(flag) + 1] = value
        command.append("--perf-record" if diagnostic == "perf" else "--strace-summary")
    return command


def resume_archive_gate(spec, private, state, state_path):
    """Finish the old copy/verify/prune barrier before making a fresh attempt."""
    pending = state.get("archive_gate")
    if not pending:
        return
    window = state["windows"][pending["job_id"]]
    record = next(row for row in window["attempts"] if row["attempt"] == pending["attempt"])
    attempt = private / "runs" / record["job_id"] / f"attempt-{record['attempt']}"
    suite.archive_gate(spec, attempt, record, state, state_path)
    if record["methodology_valid"]:
        window["valid_attempt"] = record["attempt"]
    counter = "diagnostic_valid_windows" if state.get("diagnostic") else "formal_valid_windows"
    state[counter] = sum(w["valid_attempt"] is not None for w in state["windows"].values())
    save(state_path, state)


def run(args):
    manifest = args.manifest.resolve()
    spec = json.loads(manifest.read_text())
    suite.verify(spec, manifest)
    controller = suite.verify_controller(spec, __file__)
    diagnostic = getattr(args, "diagnostic", None)
    suite.check_instrumentation(spec, formal=not bool(diagnostic))
    private = Path(spec["root"]) / "private"
    state_path = private / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {
        "manifest_sha256": suite.sha256(manifest),
        "windows": {},
        "formal_valid_windows": 0,
        "expected_windows": 27,
        "status": "prepared",
        "events": [],
    }
    if state["manifest_sha256"] != suite.sha256(manifest):
        raise ValueError("state belongs to another freeze")
    if state.get("expected_windows") != 27:
        raise ValueError("intermediate state must expect exactly 27 windows")
    if state.get("windows") and state.get("diagnostic") != diagnostic:
        raise ValueError("cannot mix diagnostic and normal windows in one freeze/state")
    state["diagnostic"] = diagnostic
    os.sched_setaffinity(0, {3})
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    state["controller_pid"] = os.getpid()
    state["controller_identity"] = controller
    state["status"] = "running"
    save(state_path, state)
    resume_archive_gate(spec, private, state, state_path)

    for profile in suite.PROFILES:
        for group in suite.ORDERS[0]:
            job = f"r01-{profile[0]}-{group}"
            window = state["windows"].setdefault(
                job,
                {"round": 1, "profile": profile[0], "group": group,
                 "attempts": [], "valid_attempt": None},
            )
            if window["valid_attempt"] is not None:
                continue
            number = len(window["attempts"]) + 1
            attempt = private / "runs" / job / f"attempt-{number}"
            attempt.mkdir(parents=True, exist_ok=False)
            record = {
                "job_id": job,
                "round": 1,
                "profile": profile[0],
                "group": group,
                "attempt": number,
                "manifest_sha256": suite.sha256(manifest),
                "source_commit": spec["source_commit"],
                "protocol_sha256": spec["protocol_sha256"],
                "elf_sha256": spec["groups"][group]["sha256"],
                "methodology_valid": False,
                "pilot_only": False,
                "intermediate_one_round": True,
                "diagnostic": diagnostic,
                "excluded_from_formal_performance": bool(diagnostic),
                "controller_identity": controller,
                "failures": [],
            }
            state["current_job"] = job
            state["current_attempt"] = number
            window["attempts"].append(record)
            save(state_path, state)
            try:
                lock_path = suite.TARGET / ".dnsmasq-build.lock"
                with lock_path.open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if suite.foreign_load():
                        raise RuntimeError("other build/test active before window")
                    suite.verify(spec, manifest)
                    suite.verify_controller(spec, __file__)
                    if suite.sha256(manifest) != state["manifest_sha256"]:
                        raise ValueError("manifest changed during intermediate suite")
                    command = command_for(spec, profile, group, attempt / "formal", diagnostic)
                    record["formal_command"] = suite.execute(
                        command, attempt / "formal.log", state, state_path
                    )
                    if record["formal_command"]["returncode"] != 0:
                        raise RuntimeError("formal command failed")
                    result = json.loads((attempt / "formal/result.json").read_text())
                    record["formal_result_sha256"] = suite.sha256(
                        attempt / "formal/result.json"
                    )
                    record["methodology_valid"] = bool(result.get("measurement_valid"))
                    if not record["methodology_valid"]:
                        raise RuntimeError("formal methodology invalid")
            except Exception as error:
                record["failures"].append(repr(error))
            save(attempt / "receipt.json", record)
            save(state_path, state)
            suite.archive_gate(spec, attempt, record, state, state_path)
            if record["methodology_valid"]:
                window["valid_attempt"] = number
                counter = "diagnostic_valid_windows" if diagnostic else "formal_valid_windows"
                state[counter] = sum(w["valid_attempt"] is not None for w in state["windows"].values())
            state["status"] = "running" if not record["failures"] else "failed-tools-or-environment"
            save(state_path, state)
            print(json.dumps({"job": job,
                              "formal_valid_windows": state["formal_valid_windows"],
                              "failures": record["failures"]}), flush=True)
            if record["failures"]:
                return 1

    state["status"] = "diagnostics-complete" if diagnostic else "complete"
    save(state_path, state)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--diagnostic", choices=("perf", "strace"),
                        help="excluded 2s warmup + 15s diagnostic workload, separate fresh freeze required")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
