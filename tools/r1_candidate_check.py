#!/usr/bin/env python3
"""Differentially test the R1 candidate in the exact OpenWrt rootfs.

The candidate and the deployed shell implementation run separately from the
same exact-image baseline and synthetic UCI input.  The reference uses the real image `uci` and BusyBox `md5sum`; the candidate
may normalize and digest in-process.  A disposable ubus adapter records delivery
attempts.  No router is contacted.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import r1_reference_oracle as oracle
from reload_protocol_fixture import C_UBUSD_SHA256, ProtocolFixture, raw_events


SIZE_BUDGET_BYTES = 512 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_traces(stderr: bytes) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for line in stderr.decode("utf-8", "surrogateescape").splitlines():
        if not line:
            continue
        item = json.loads(line)
        if item.get("schema") != 1 or not isinstance(item.get("kind"), str):
            raise ValueError(f"invalid candidate trace: {item!r}")
        traces.append(item)
    return traces


def candidate_command(root: Path, timeout_ms: int) -> list[str]:
    return [
        "sudo",
        "-n",
        "chroot",
        str(root),
        "/bin/sh",
        "-c",
        (
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin "
            f"/sbin/reload_config_rs --trace-stderr --timeout-ms {timeout_ms}"
        ),
    ]


def run_candidate(
    root: Path,
    statuses: list[int | str],
    *,
    timeout_ms: int = 10_000,
    process_timeout_s: int = 15,
) -> dict[str, Any]:
    oracle.write_statuses(root, statuses)
    result = subprocess.run(
        candidate_command(root, timeout_ms),
        check=False,
        capture_output=True,
        timeout=process_timeout_s,
    )
    traces = parse_traces(result.stderr)
    received = [item for item in raw_events(root) if item["event"] == "receive"]
    deliveries = oracle.read_deliveries(root)
    if (root / "tmp/r1-delivery-ready").exists():
        assert [bytes.fromhex(item["package_hex"]) for item in received] == [
            os.fsencode(item["package"]) for item in deliveries
        ], "raw protocol delivery differs from textual adapter evidence"
    return {
        "exit_status": result.returncode,
        "deliveries": deliveries,
        "raw_events": received,
        "baseline": oracle.parse_baseline(root),
        "baseline_bytes": (root / "var/run/config.md5").read_bytes(),
        "traces": traces,
    }


def prepare_case(
    root: Path,
    given: dict[str, Any],
    *,
    final_comment: str | None = None,
) -> dict[str, str]:
    initial = oracle.establish_baseline(
        root, given["baseline"], given.get("uci_lookups")
    )
    oracle.write_config_set(
        root,
        given["etc_config"],
        given["var_run_uci"],
        given.get("uci_lookups"),
        final_comment,
    )
    return initial


def trace_of_kind(result: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [item for item in result["traces"] if item["kind"] == kind]


def run_reference_cases(
    root: Path, case_dir: Path
) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    problems: list[str] = []
    paths = sorted(case_dir.glob("*.json"))
    observed_ids = {json.loads(path.read_text()).get("id") for path in paths}
    if observed_ids != oracle.EXPECTED_CASE_IDS:
        return [], [
            "reference case identity gate failed: "
            f"missing={sorted(oracle.EXPECTED_CASE_IDS - observed_ids)}, "
            f"unexpected={sorted(observed_ids - oracle.EXPECTED_CASE_IDS)}"
        ]

    for path in paths:
        case = json.loads(path.read_text())
        given = case["given"]
        final_comment = "comment-only final form" if case["id"].startswith("c09-") else None

        initial = prepare_case(root, given, final_comment=final_comment)
        candidate = run_candidate(root, [0] * len(case["expect"]["events"]))

        prepare_case(root, given, final_comment=final_comment)
        reference = oracle.run_exact(root, [0] * len(case["expect"]["events"]))
        reference_baseline_bytes = (root / "var/run/config.md5").read_bytes()

        candidate_events = [item["package"] for item in candidate["deliveries"]]
        reference_events = [item["package"] for item in reference["deliveries"]]
        trace_deliveries = [
            item["package"] for item in trace_of_kind(candidate, "delivery")
        ]
        comparisons = trace_of_kind(candidate, "comparison")
        completions = trace_of_kind(candidate, "complete")
        expected_events = case["expect"]["events"]
        passed = (
            candidate["exit_status"] == 0
            and reference["exit_status"] == 0
            and candidate_events == reference_events == expected_events
            and trace_deliveries == candidate_events
            and candidate["baseline_bytes"] == reference_baseline_bytes
            and len(comparisons) == 1
            and comparisons[0]["compared_count"] == len(initial)
            and comparisons[0]["changed_entries"] == expected_events
            and len(completions) == 1
            and completions[0]["baseline_rewritten"] is True
            and completions[0]["delivery_failures"] == 0
        )
        if not passed:
            problems.append(f"{case['id']}: candidate/reference mismatch")
        results.append(
            {
                "id": case["id"],
                "evidence": case["evidence"],
                "compared_entry_count": len(initial),
                "candidate_events": candidate_events,
                "candidate_protocol_events": candidate["raw_events"],
                "reference_events": reference_events,
                "baseline_byte_equivalent": candidate["baseline_bytes"]
                == reference_baseline_bytes,
                "trace_delivery_equivalent": trace_deliveries == candidate_events,
                "passed": passed,
            }
        )
    return results, problems


def prepare_simple_change(
    root: Path, packages: dict[str, tuple[str, str]]
) -> dict[str, str]:
    initial = oracle.establish_baseline(
        root, {name: value[0] for name, value in packages.items()}
    )
    oracle.write_config_set(
        root, {name: value[1] for name, value in packages.items()}, {}
    )
    return initial


def wait_for_pending(root: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 2
    log = root / "tmp/r1-delivery.log"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("candidate exited before reaching the delivery adapter")
        if log.exists() and "\tpending\n" in log.read_text():
            return
        time.sleep(0.01)
    raise RuntimeError("candidate did not reach the delivery adapter")


def run_fault_cases(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    problems: list[str] = []

    initial = prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2")})
    partial = run_candidate(root, [7, 0])
    repeat = run_candidate(root, [])
    partial_trace = trace_of_kind(partial, "delivery")
    partial_ok = (
        partial["exit_status"] == 2
        and [item["package"] for item in partial_trace] == ["alpha", "beta"]
        and [item["outcome"] for item in partial_trace] == ["exit_nonzero", "success"]
        and not repeat["deliveries"]
        and repeat["exit_status"] == 0
        and partial["baseline"] == repeat["baseline"]
    )
    results.append(
        {
            "id": "f01-partial-delivery-is-visible-and-absorbed",
            "compared_entry_count": len(initial),
            "exit_status": partial["exit_status"],
            "delivery_outcomes": [item["outcome"] for item in partial_trace],
            "repeat_events": [item["package"] for item in repeat["deliveries"]],
            "baseline_advanced": partial["baseline"] == repeat["baseline"],
            "passed": partial_ok,
        }
    )
    if not partial_ok:
        problems.append("f01-partial-delivery-is-visible-and-absorbed")

    initial = prepare_simple_change(root, {"alpha": ("A", "A2")})
    before = oracle.parse_baseline(root)
    uci = root / "sbin/uci"
    hidden_uci = root / "sbin/uci.r1-candidate-hidden"
    uci.rename(hidden_uci)
    try:
        missing_uci = run_candidate(root, [])
    finally:
        hidden_uci.rename(uci)
    fatal = trace_of_kind(missing_uci, "fatal")
    # A candidate that spawns `uci show` must fail closed without it (exit 70,
    # a dependency fatal, baseline untouched).  A candidate that normalizes
    # in-process with the uci library (R94) does not depend on /sbin/uci at all
    # and must therefore behave exactly as with uci present: the pending alpha
    # change is dispatched and the baseline advances.
    child_missing_ok = (
        missing_uci["exit_status"] == 70
        and missing_uci["baseline"] == before
        and not missing_uci["deliveries"]
        and len(fatal) == 1
        and fatal[0]["class"] == "dependency"
    )
    inprocess_missing_ok = (
        missing_uci["exit_status"] == 0
        and [item["package"] for item in missing_uci["deliveries"]] == ["alpha"]
        and missing_uci["baseline"] != before
        and not fatal
    )
    missing_ok = child_missing_ok or inprocess_missing_ok
    results.append(
        {
            "id": "f02-missing-uci-is-visible-and-preserves-baseline",
            "compared_entry_count": len(initial),
            "exit_status": missing_uci["exit_status"],
            "baseline_unchanged": missing_uci["baseline"] == before,
            "fatal_class": fatal[0]["class"] if len(fatal) == 1 else None,
            "normalizer": "in-process" if inprocess_missing_ok else "child",
            "passed": missing_ok,
        }
    )
    if not missing_ok:
        problems.append("f02-missing-uci-is-visible-and-preserves-baseline")

    # R81 F26: a delivery that has to be killed is a delivery failure, not a
    # reason to stop.  The shell original has no timeout at all -- it waits for
    # the slow `ubus call` and then dispatches the rest of the changed set and
    # rewrites the baseline (contract C-08: "a send failure affects neither
    # later entries nor the baseline rewrite").  Aborting used to leave the
    # later packages without an event and the baseline unwritten, so the next
    # run re-sent the events that had already been delivered.
    initial = prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2")})
    before = oracle.parse_baseline(root)
    timed = run_candidate(root, ["sleep:3", 0], timeout_ms=100, process_timeout_s=10)
    after = oracle.parse_baseline(root)
    repeat = run_candidate(root, [])
    timed_deliveries = trace_of_kind(timed, "delivery")

    prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2")})
    reference = oracle.run_exact(root, ["sleep:3", 0], timeout_s=10)
    reference_events = [item["package"] for item in reference["deliveries"]]

    timed_ok = (
        timed["exit_status"] == 2
        and [item["package"] for item in timed_deliveries] == ["alpha", "beta"]
        and [item["outcome"] for item in timed_deliveries] == ["timeout", "success"]
        and [item["package"] for item in timed["deliveries"]] == reference_events
        and before != after
        and not repeat["deliveries"]
        and repeat["exit_status"] == 0
    )
    results.append(
        {
            "id": "f03-hung-delivery-is-a-failure-and-the-round-continues",
            "compared_entry_count": len(initial),
            "exit_status": timed["exit_status"],
            "delivery_outcomes": [item["outcome"] for item in timed_deliveries],
            "reference_events": reference_events,
            "baseline_rewritten": before != after,
            "repeat_events": [item["package"] for item in repeat["deliveries"]],
            "passed": timed_ok,
        }
    )
    if not timed_ok:
        problems.append("f03-hung-delivery-is-a-failure-and-the-round-continues")

    initial = oracle.establish_baseline(root, {"alpha": "A"})
    oracle.write_config_set(root, {"alpha": "<MALFORMED>"}, {})
    malformed = run_candidate(root, [0])
    malformed_ok = (
        malformed["exit_status"] == 0
        and [item["package"] for item in malformed["deliveries"]] == ["alpha"]
        and malformed["baseline"].get("alpha") == oracle.EMPTY_MD5
        and len(trace_of_kind(malformed, "normalization")) == 1
    )
    results.append(
        {
            "id": "f04-malformed-uci-remains-compatible-but-visible",
            "compared_entry_count": len(initial),
            "exit_status": malformed["exit_status"],
            "empty_baseline_entry": malformed["baseline"].get("alpha")
            == oracle.EMPTY_MD5,
            "normalization_trace_present": len(
                trace_of_kind(malformed, "normalization")
            )
            == 1,
            "passed": malformed_ok,
        }
    )
    if not malformed_ok:
        problems.append("f04-malformed-uci-remains-compatible-but-visible")

    # R81 F26: a second caller waits for the lock instead of being refused.
    # The shell takes no lock at all: two runs share and delete the same
    # config.check, deliver every event twice and race over the baseline (the
    # C1-01 oracle records that as undefined).  Refusing the second caller lost
    # its packages entirely -- they were only noticed on a third run.
    initial = prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B")})
    before = oracle.parse_baseline(root)
    oracle.write_statuses(root, ["sleep:1"])
    first = subprocess.Popen(
        candidate_command(root, 5_000), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    wait_for_pending(root, first)
    # beta changes while the first run holds the lock
    oracle.write_config_set(root, {"alpha": "A2", "beta": "B2"}, {})
    second_result = subprocess.run(
        candidate_command(root, 5_000), check=False, capture_output=True, timeout=20
    )
    second_traces = parse_traces(second_result.stderr)
    second = {"exit_status": second_result.returncode, "traces": second_traces}
    _, first_stderr = first.communicate(timeout=5)
    first_traces = parse_traces(first_stderr)
    second_deliveries = [item["package"] for item in trace_of_kind(second, "delivery")]
    concurrent_ok = (
        second["exit_status"] == 0
        and not trace_of_kind(second, "fatal")
        and second_deliveries == ["beta"]
        and any(item["kind"] == "complete" for item in second_traces)
        and first.returncode == 0
        and [item["package"] for item in trace_of_kind({"traces": first_traces}, "delivery")]
        == ["alpha"]
        and oracle.parse_baseline(root) != before
    )
    results.append(
        {
            "id": "f05-concurrent-run-waits-for-the-lock",
            "compared_entry_count": len(initial),
            "second_exit_status": second["exit_status"],
            "second_deliveries": second_deliveries,
            "first_exit_status": first.returncode,
            "passed": concurrent_ok,
        }
    )
    if not concurrent_ok:
        problems.append("f05-concurrent-run-waits-for-the-lock")

    initial = prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2")})
    before = oracle.parse_baseline(root)
    before_bytes = baseline_bytes(root)
    oracle.write_statuses(root, ["sleep:3", 0])
    pid_file = root / "tmp/r1-candidate.pid"
    interrupted = subprocess.Popen(
        [
            "sudo",
            "-n",
            "chroot",
            str(root),
            "/bin/sh",
            "-c",
            (
                "echo $$ > /tmp/r1-candidate.pid; "
                "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "
                "exec /sbin/reload_config_rs --trace-stderr --timeout-ms 5000"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for_pending(root, interrupted)
    candidate_pid = int(pid_file.read_text().strip())
    subprocess.run(
        ["sudo", "-n", "kill", f"-{signal.SIGTERM}", str(candidate_pid)],
        check=True,
        capture_output=True,
    )
    _, interrupted_stderr = interrupted.communicate(timeout=5)
    interrupted_traces = parse_traces(interrupted_stderr)
    after = oracle.parse_baseline(root)
    after_bytes = baseline_bytes(root)
    cancelled_events = oracle.read_deliveries(root)
    recovered = run_candidate(root, [0, 0])
    repeat = run_candidate(root, [])
    cancel_ok = (
        interrupted.returncode == 75
        and before == after
        and before_bytes == after_bytes
        and [item["package"] for item in cancelled_events] == ["alpha"]
        and recovered["exit_status"] == repeat["exit_status"] == 0
        and [item["package"] for item in recovered["deliveries"]] == ["alpha", "beta"]
        and not repeat["deliveries"]
        and recovered["baseline_bytes"] == repeat["baseline_bytes"]
        and len([item for item in interrupted_traces if item["kind"] == "fatal"]) == 1
        and [item for item in interrupted_traces if item["kind"] == "fatal"][0]["class"]
        == "temporary"
    )
    results.append(
        {
            "id": "f06-sigterm-cancels-with-retryable-baseline",
            "compared_entry_count": len(initial),
            "exit_status": interrupted.returncode,
            "baseline_unchanged": before_bytes == after_bytes,
            "cancelled_events": [item["package"] for item in cancelled_events],
            "recovery_events": [item["package"] for item in recovered["deliveries"]],
            "repeat_events": [item["package"] for item in repeat["deliveries"]],
            "passed": cancel_ok,
        }
    )
    if not cancel_ok:
        problems.append("f06-sigterm-cancels-with-retryable-baseline")

    # A caller waiting for the run lock must cancel without normalizing,
    # dispatching or replacing the old baseline; releasing the lock restores
    # the complete pending round, not merely the first event.
    import fcntl

    prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2")})
    before_bytes = baseline_bytes(root)
    oracle.write_statuses(root, [0, 0])
    pid_file.unlink(missing_ok=True)
    with (root / "var/run/reload-config-rs.lock").open("a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        waiter = subprocess.Popen(
            ["sudo", "-n", "chroot", str(root), "/bin/sh", "-c",
             "echo $$ > /tmp/r1-candidate.pid; "
             "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "
             "exec /sbin/reload_config_rs --trace-stderr --timeout-ms 5000"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 2
        try:
            while not pid_file.exists():
                if waiter.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("run-lock waiter did not start")
                time.sleep(0.01)
            # The lock is held throughout, so this is only a readiness pause;
            # this functional gate makes no performance claim.
            time.sleep(0.1)
            subprocess.run(
                ["sudo", "-n", "kill", f"-{signal.SIGTERM}", pid_file.read_text().strip()],
                check=True, capture_output=True,
            )
            _, waiter_stderr = waiter.communicate(timeout=5)
        finally:
            if waiter.poll() is None:
                waiter.kill()
                waiter.communicate(timeout=5)
    waiter_traces = parse_traces(waiter_stderr)
    untouched = baseline_bytes(root) == before_bytes and not oracle.read_deliveries(root)
    recovered = run_candidate(root, [0, 0])
    repeat = run_candidate(root, [])
    lock_cancel_ok = (
        waiter.returncode == 75 and untouched
        and len(waiter_traces) == 1
        and waiter_traces[0].get("kind") == "fatal"
        and waiter_traces[0].get("class") == "temporary"
        and recovered["exit_status"] == repeat["exit_status"] == 0
        and [item["package"] for item in recovered["deliveries"]] == ["alpha", "beta"]
        and not repeat["deliveries"]
        and recovered["baseline_bytes"] == repeat["baseline_bytes"]
    )
    results.append({
        "id": "f07-run-lock-cancellation-and-following-recovery",
        "exit_status": waiter.returncode, "baseline_and_events_unchanged": untouched,
        "recovery_events": [item["package"] for item in recovered["deliveries"]],
        "repeat_events": [item["package"] for item in repeat["deliveries"]],
        "passed": lock_cancel_ok,
    })
    if not lock_cancel_ok:
        problems.append("f07-run-lock-cancellation-and-following-recovery")

    # An arbitrary existing baseline controls dispatch order. A newly sorted
    # current scan must not replace this ordering before all old entries run.
    def prepare_reordered() -> None:
        oracle.establish_baseline(root, {"alpha": "A", "beta": "B", "gamma": "G"})
        path = root / "var/run/config.md5"
        path.write_bytes(b"".join(reversed(path.read_bytes().splitlines(keepends=True))))
        oracle.write_config_set(root, {"alpha": "A2", "gamma": "G2", "new": "N"}, {})

    prepare_reordered()
    reordered = run_candidate(root, [0, 0, 0])
    repeat = run_candidate(root, [])
    prepare_reordered()
    reference = oracle.run_exact(root, [0, 0, 0])
    ordered_ok = (
        reordered["exit_status"] == reference["exit_status"] == repeat["exit_status"] == 0
        and [item["package"] for item in reordered["deliveries"]]
            == [item["package"] for item in reference["deliveries"]]
            == ["gamma", "beta", "alpha"]
        and reordered["baseline_bytes"] == baseline_bytes(root) == repeat["baseline_bytes"]
        and not repeat["deliveries"]
    )
    results.append({
        "id": "f08-old-baseline-order-survives-new-scan-order",
        "candidate_events": [item["package"] for item in reordered["deliveries"]],
        "reference_events": [item["package"] for item in reference["deliveries"]],
        "baseline_byte_equivalent": reordered["baseline_bytes"] == baseline_bytes(root),
        "repeat_events": [item["package"] for item in repeat["deliveries"]],
        "passed": ordered_ok,
    })
    if not ordered_ok:
        problems.append("f08-old-baseline-order-survives-new-scan-order")

    return results, problems


def baseline_bytes(root: Path) -> bytes:
    path = root / "var/run/config.md5"
    return path.read_bytes() if path.exists() else b""


def run_f26_cases(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """R81 F26: inputs the shell script handles and the candidate used to
    refuse outright (exit 64, zero dispatch).  Each case runs the exact shell
    original and the candidate from the same prepared tree and compares the
    events and the baseline bytes."""
    results: list[dict[str, Any]] = []
    problems: list[str] = []
    etc = root / "etc/config"
    package = b"config r1 'main'\n\toption token '%s'\n"

    def prepare(extra: dict[bytes, bytes], token: bytes) -> None:
        oracle.establish_baseline(root, None)
        oracle.clear_directory(etc)
        oracle.clear_directory(root / "var/run/uci")
        (etc / "alpha").write_bytes(package % b"A")
        for name, body in extra.items():
            (etc / os.fsdecode(name)).write_bytes(body)
        # first run only establishes the baseline
        oracle.run_exact(root, [])
        (etc / "alpha").write_bytes(package % token)

    def both(statuses: list[int | str]) -> dict[str, Any]:
        reference = oracle.run_exact(root, statuses)
        reference_bytes = baseline_bytes(root)
        return {
            "reference_events": [item["package"] for item in reference["deliveries"]],
            "reference_exit": reference["exit_status"],
            "reference_bytes": reference_bytes,
        }

    # --- an /etc/config entry larger than the old 1 MiB source limit
    oversized = b"config r1 'main'\n" + b"\toption pad 'x'\n" * 90_000
    prepare({b"big": oversized}, b"A2")
    candidate = run_candidate(root, [0])
    candidate_bytes = candidate["baseline_bytes"]
    prepare({b"big": oversized}, b"A2")
    reference = both([0])
    big_ok = (
        candidate["exit_status"] == 0
        and [item["package"] for item in candidate["deliveries"]]
        == reference["reference_events"]
        == ["alpha"]
        and candidate_bytes == reference["reference_bytes"]
        and b"/var/run/config.check/big" in candidate_bytes
    )
    results.append(
        {
            "id": "f07-oversized-config-source-is-dispatched-like-the-shell",
            "source_bytes": len(oversized),
            "exit_status": candidate["exit_status"],
            "candidate_events": [item["package"] for item in candidate["deliveries"]],
            "reference_events": reference["reference_events"],
            "baseline_byte_equivalent": candidate_bytes == reference["reference_bytes"],
            "passed": big_ok,
        }
    )
    if not big_ok:
        problems.append("f07-oversized-config-source-is-dispatched-like-the-shell")

    # --- config filenames that are not UTF-8 / contain a space
    weird = {b"\xff\xfe": package % b"Z", b"with space": package % b"S"}
    prepare(weird, b"A2")
    candidate = run_candidate(root, [0])
    candidate_bytes = candidate["baseline_bytes"]
    prepare(weird, b"A2")
    reference = both([0])
    # now delete the non-UTF-8 entry: the shell emits an event carrying its
    # raw bytes, because `md5sum -c` reports the missing file as FAILED
    (etc / os.fsdecode(b"\xff\xfe")).unlink()
    deleted_reference = oracle.run_exact(root, [0])
    deleted_reference_events = [item["package"] for item in deleted_reference["deliveries"]]
    prepare(weird, b"A2")
    run_candidate(root, [0])
    (etc / os.fsdecode(b"\xff\xfe")).unlink()
    deleted_candidate = run_candidate(root, [0])
    weird_ok = (
        candidate["exit_status"] == 0
        and [item["package"] for item in candidate["deliveries"]]
        == reference["reference_events"]
        == ["alpha"]
        and candidate_bytes == reference["reference_bytes"]
        and b"/var/run/config.check/\xff\xfe" in candidate_bytes
        and deleted_candidate["exit_status"] == 0
        and [item["package"] for item in deleted_candidate["deliveries"]]
        == deleted_reference_events
    )
    results.append(
        {
            "id": "f08-non-utf8-config-filename-is-dispatched-like-the-shell",
            "exit_status": candidate["exit_status"],
            "candidate_events": [item["package"] for item in candidate["deliveries"]],
            "reference_events": reference["reference_events"],
            "baseline_byte_equivalent": candidate_bytes == reference["reference_bytes"],
            "delete_events_equivalent": [
                item["package"] for item in deleted_candidate["deliveries"]
            ]
            == deleted_reference_events,
            "passed": weird_ok,
        }
    )
    if not weird_ok:
        problems.append("f08-non-utf8-config-filename-is-dispatched-like-the-shell")

    # --- a `uci show` that has to be killed: the round still finishes
    prepare({}, b"A2")
    real = root / "sbin/uci"
    hidden = root / "sbin/uci.r1-slow-hidden"
    real.rename(hidden)
    invoked_marker = root / "tmp/r1-slow-uci-invoked"
    invoked_marker.unlink(missing_ok=True)
    real.write_text(
        "#!/bin/sh\n"
        ": > /tmp/r1-slow-uci-invoked\n"
        "for a in \"$@\"; do case \"$a\" in alpha) sleep 3;; esac; done\n"
        "exec /sbin/uci.r1-slow-hidden \"$@\"\n"
    )
    real.chmod(0o755)
    try:
        slow = run_candidate(root, [0], timeout_ms=100, process_timeout_s=15)
    finally:
        real.unlink()
        hidden.rename(real)
    shim_invoked = invoked_marker.exists()
    invoked_marker.unlink(missing_ok=True)
    normalizations = [item["status"] for item in trace_of_kind(slow, "normalization")]
    # A candidate that spawns `uci show` must kill the hung child, trace the
    # timeout and finish the round.  One that normalizes in-process never runs
    # the shim (the marker stays absent) and simply finishes the round.
    slow_ok = (
        slow["exit_status"] == 0
        and ("timeout" in normalizations or not shim_invoked)
        and any(item["kind"] == "complete" for item in slow["traces"])
        and slow["baseline_bytes"] != b""
    )
    results.append(
        {
            "id": "f09-killed-uci-show-does-not-abort-the-round",
            "exit_status": slow["exit_status"],
            "normalization_statuses": normalizations,
            "uci_shim_invoked": shim_invoked,
            "baseline_rewritten": slow["baseline_bytes"] != b"",
            "passed": slow_ok,
        }
    )
    if not slow_ok:
        problems.append("f09-killed-uci-show-does-not-abort-the-round")

    return results, problems


def run_protocol_cases(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    problems: list[str] = []

    prepare_simple_change(root, {"alpha": ("A", "A2"), "beta": ("B", "B2"), "gamma": ("G", "G2")})
    result = run_candidate(root, [6, 7, 0])
    repeat = run_candidate(root, [])
    deliveries = trace_of_kind(result, "delivery")
    passed = (result["exit_status"] == 2 and repeat["exit_status"] == 0
              and [d["outcome"] for d in deliveries] == ["exit_nonzero", "exit_nonzero", "success"]
              and [d["status"] for d in deliveries] == [250, 249, 0]
              and [d["package"] for d in result["deliveries"]] == ["alpha", "beta", "gamma"]
              and not repeat["deliveries"] and result["baseline_bytes"] == repeat["baseline_bytes"])
    results.append({"id": "p01-remote-status-is-not-local-timeout", "passed": passed,
                    "delivery_traces": deliveries, "raw_events": result["raw_events"],
                    "repeat_events": repeat["deliveries"]})
    if not passed: problems.append(results[-1]["id"])

    prepare_simple_change(root, {"alpha": ("A", "A2")})
    ready = root / "tmp/r1-delivery-ready"
    ready.write_text("before-disconnect\n")
    result = run_candidate(root, ["disconnect"], timeout_ms=1000)
    deadline = time.monotonic() + 3
    while ready.read_text() != "reconnected\n":
        if time.monotonic() >= deadline: raise RuntimeError("fault receiver did not recover connection")
        time.sleep(0.01)
    repeat = run_candidate(root, [])
    oracle.write_config_set(root, {"alpha": "A3"}, {})
    recovered = run_candidate(root, [0])
    final_repeat = run_candidate(root, [])
    deliveries = trace_of_kind(result, "delivery")
    passed = (result["exit_status"] == 2 and len(deliveries) == 1
              and deliveries[0]["outcome"] in ("exit_nonzero", "timeout")
              and [d["package"] for d in result["deliveries"]] == ["alpha"]
              and repeat["exit_status"] == recovered["exit_status"] == final_repeat["exit_status"] == 0
              and not repeat["deliveries"] and not final_repeat["deliveries"]
              and result["baseline_bytes"] == repeat["baseline_bytes"]
              and [d["package"] for d in recovered["deliveries"]] == ["alpha"])
    results.append({"id": "p02-disconnect-is-absorbed-and-new-change-recovers", "passed": passed,
                    "delivery_traces": deliveries, "raw_events": result["raw_events"],
                    "recovery_events": recovered["raw_events"]})
    if not passed: problems.append(results[-1]["id"])

    # The shell's unescaped JSON is an explicitly rejected defect. This case
    # checks the candidate's declared raw-byte/JSON contract independently.
    names = [b'quote"name', b'back\\slash', b'raw-\xff', b'tab\tname', b'control-\x01']
    oracle.clear_directory(root / "etc/config")
    oracle.clear_directory(root / "var/run/uci")
    for name in names:
        (root / "etc/config" / os.fsdecode(name)).write_bytes(b"invalid UCI\n")
    old_order = list(reversed(names))
    path = root / "var/run/config.md5"
    path.write_bytes(b"".join(b"0" * 32 + b"  /var/run/config.check/" + name + b"\n" for name in old_order))
    expected = b"".join(oracle.EMPTY_MD5.encode() + b"  /var/run/config.check/" + name + b"\n" for name in sorted(names))
    oracle.write_statuses(root, [0] * len(names))
    completed = subprocess.run(candidate_command(root, 1000), capture_output=True, timeout=15)
    received = [item for item in raw_events(root) if item["event"] == "receive"]
    actual_baseline = path.read_bytes()
    traces = parse_traces(completed.stderr)
    oracle.write_statuses(root, [])
    repeated = subprocess.run(candidate_command(root, 1000), capture_output=True, timeout=15)
    repeated_raw = [item for item in raw_events(root) if item["event"] == "receive"]
    passed = (completed.returncode == repeated.returncode == 0
              and [bytes.fromhex(item["package_hex"]) for item in received] == old_order
              and actual_baseline == expected == path.read_bytes()
              and not repeated_raw
              and len([t for t in traces if t["kind"] == "delivery" and t["outcome"] == "success"]) == len(names))
    results.append({"id": "p03-raw-package-bytes-json-and-baseline-order", "passed": passed,
                    "raw_events": received, "expected_package_hex": [n.hex() for n in old_order],
                    "baseline_bytes_equivalent": actual_baseline == expected,
                    "repeat_raw_events": repeated_raw})
    if not passed: problems.append(results[-1]["id"])
    return results, problems


def prepare_rootfs(
    source: Path, destination: Path, candidate: Path, *, protocol: bool = False
) -> tuple[dict[str, str], dict[str, Any]]:
    observed = oracle.prepare_rootfs(source, destination, delivery_adapter=not protocol)
    candidate_info = {
        "sha256": sha256_file(candidate),
        "size_bytes": candidate.stat().st_size,
        "size_budget_bytes": SIZE_BUDGET_BYTES,
        "within_size_budget": candidate.stat().st_size <= SIZE_BUDGET_BYTES,
    }
    target = destination / "sbin/reload_config_rs"
    shutil.copy2(candidate, target)
    target.chmod(0o755)
    return observed, candidate_info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    parser.add_argument("--receiver", type=Path, help="owrt-benchmark with reload-fault-service; use exact private C ubusd and real ubus CLI")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="owrt-r1-candidate-") as temp:
        root = Path(temp) / "rootfs"
        observed, candidate_info = prepare_rootfs(
            args.rootfs.resolve(), root, args.candidate.resolve(), protocol=bool(args.receiver)
        )
        fixture = ProtocolFixture(root, args.receiver.resolve()) if args.receiver else contextlib.nullcontext()
        try:
            with fixture:
                cases, case_problems = run_reference_cases(root, args.cases.resolve())
                faults, fault_problems = run_fault_cases(root)
                f26, f26_problems = run_f26_cases(root)
                faults.extend(f26)
                fault_problems.extend(f26_problems)
                if args.receiver:
                    protocol_cases, protocol_problems = run_protocol_cases(root)
                    faults.extend(protocol_cases)
                    fault_problems.extend(protocol_problems)

        finally:
            if args.receiver:
                evidence = args.output.parent / (args.output.name + "-protocol")
                evidence.mkdir(parents=True, exist_ok=False)
                for name in ("r1-bus.log", "r1-receiver.log", "r1-delivery-raw.jsonl", "r1-delivery-all.jsonl"):
                    if (root / "tmp" / name).exists():
                        shutil.copy2(root / "tmp" / name, evidence / name)

    problems = case_problems + fault_problems
    if not candidate_info["within_size_budget"]:
        problems.append("target binary exceeds size budget")
    payload = {
        "schema_version": 1,
        "stage": "R1.2",
        "status": "complete" if not problems else "failed",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "device_access": False,
            "device_writes": False,
            "rootfs_copy_is_disposable": True,
            "candidate_and_reference_inputs_are_identical": True,
            "reference_normalizer": "exact image /sbin/uci",
            "reference_digest_tool": "exact image BusyBox md5sum",
            "candidate_normalizer_and_digest": "candidate implementation",
            "delivery_adapter": ("private exact C ubusd + trigger-free protocol receiver" if args.receiver else "test-only /bin/ubus shim in disposable rootfs"),
            "receiver_sha256": sha256_file(args.receiver) if args.receiver else None,
            "receiver_bus_sha256": C_UBUSD_SHA256 if args.receiver else None,
        },
        "source_artifacts": observed,
        "candidate": candidate_info,
        "reference_cases": cases,
        "fault_cases": faults,
        "gate": {
            "all_11_reference_cases_passed": not case_problems,
            "event_sets_equivalent": all(
                item["candidate_events"] == item["reference_events"] for item in cases
            ),
            "baseline_bytes_equivalent": all(
                item["baseline_byte_equivalent"] for item in cases
            ),
            "delivery_results_observable": all(
                item["trace_delivery_equivalent"] for item in cases
            ),
            "fault_cases_passed": not fault_problems,
            "within_size_budget": candidate_info["within_size_budget"],
            "passed": not problems,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        for item in cases + faults:
            if not item.get("passed", True):
                print(json.dumps(item, indent=2, sort_keys=True, default=str))
        raise SystemExit(f"{len(problems)} candidate problem(s); failure output preserved at {args.output}")
    print(
        json.dumps(
            {
                "reference_cases": len(cases),
                "fault_cases": len(faults),
                "gate_passed": payload["gate"]["passed"],
                "output_sha256": sha256_file(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
