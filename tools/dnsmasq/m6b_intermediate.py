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


def run(args):
    manifest = args.manifest.resolve()
    spec = json.loads(manifest.read_text())
    suite.verify(spec, manifest)
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
    os.sched_setaffinity(0, {3})
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    state["controller_pid"] = os.getpid()
    state["status"] = "running"
    save(state_path, state)

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
                    command = suite.command_for(
                        spec, profile, group, 1, attempt / "formal", False
                    )
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
                state["formal_valid_windows"] = sum(
                    w["valid_attempt"] is not None for w in state["windows"].values()
                )
            state["status"] = "running" if not record["failures"] else "failed-tools-or-environment"
            save(state_path, state)
            print(json.dumps({"job": job,
                              "formal_valid_windows": state["formal_valid_windows"],
                              "failures": record["failures"]}), flush=True)
            if record["failures"]:
                return 1

    state["status"] = "complete"
    save(state_path, state)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
