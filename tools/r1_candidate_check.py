#!/usr/bin/env python3
"""Differentially test the R1 candidate in the exact OpenWrt rootfs.

The candidate and the deployed shell implementation run separately from the
same exact-image baseline and synthetic UCI input.  The real image `uci` and
BusyBox `md5sum` are used by both.  A disposable ubus adapter records delivery
attempts.  No router is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import r1_reference_oracle as oracle


SIZE_BUDGET_BYTES = 512 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_traces(stderr: bytes) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for line in stderr.decode("utf-8").splitlines():
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
            f"/sbin/reload_config_rs --timeout-ms {timeout_ms}"
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
    return {
        "exit_status": result.returncode,
        "deliveries": oracle.read_deliveries(root),
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
    missing_ok = (
        missing_uci["exit_status"] == 70
        and missing_uci["baseline"] == before
        and not missing_uci["deliveries"]
        and len(fatal) == 1
        and fatal[0]["class"] == "dependency"
    )
    results.append(
        {
            "id": "f02-missing-uci-is-visible-and-preserves-baseline",
            "compared_entry_count": len(initial),
            "exit_status": missing_uci["exit_status"],
            "baseline_unchanged": missing_uci["baseline"] == before,
            "fatal_class": fatal[0]["class"] if len(fatal) == 1 else None,
            "passed": missing_ok,
        }
    )
    if not missing_ok:
        problems.append("f02-missing-uci-is-visible-and-preserves-baseline")

    initial = prepare_simple_change(root, {"alpha": ("A", "A2")})
    before = oracle.parse_baseline(root)
    timed = run_candidate(root, ["sleep:3"], timeout_ms=100, process_timeout_s=5)
    after = oracle.parse_baseline(root)
    retry = run_candidate(root, [0])
    timed_fatal = trace_of_kind(timed, "fatal")
    timed_ok = (
        timed["exit_status"] == 75
        and before == after
        and len(timed_fatal) == 1
        and timed_fatal[0]["class"] == "temporary"
        and [item["package"] for item in retry["deliveries"]] == ["alpha"]
    )
    results.append(
        {
            "id": "f03-hung-delivery-times-out-with-retryable-baseline",
            "compared_entry_count": len(initial),
            "exit_status": timed["exit_status"],
            "baseline_unchanged": before == after,
            "retry_events": [item["package"] for item in retry["deliveries"]],
            "passed": timed_ok,
        }
    )
    if not timed_ok:
        problems.append("f03-hung-delivery-times-out-with-retryable-baseline")

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

    initial = prepare_simple_change(root, {"alpha": ("A", "A2")})
    before = oracle.parse_baseline(root)
    oracle.write_statuses(root, ["sleep:1"])
    first = subprocess.Popen(
        candidate_command(root, 5_000), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    wait_for_pending(root, first)
    second_result = subprocess.run(
        candidate_command(root, 5_000), check=False, capture_output=True, timeout=5
    )
    second = {
        "exit_status": second_result.returncode,
        "traces": parse_traces(second_result.stderr),
    }
    unchanged_while_locked = oracle.parse_baseline(root) == before
    _, first_stderr = first.communicate(timeout=5)
    first_traces = parse_traces(first_stderr)
    concurrent_ok = (
        second["exit_status"] == 75
        and len(trace_of_kind(second, "fatal")) == 1
        and trace_of_kind(second, "fatal")[0]["class"] == "temporary"
        and unchanged_while_locked
        and first.returncode == 0
        and any(item["kind"] == "complete" for item in first_traces)
    )
    results.append(
        {
            "id": "f05-concurrent-run-is-rejected",
            "compared_entry_count": len(initial),
            "second_exit_status": second["exit_status"],
            "baseline_unchanged_while_locked": unchanged_while_locked,
            "first_exit_status": first.returncode,
            "passed": concurrent_ok,
        }
    )
    if not concurrent_ok:
        problems.append("f05-concurrent-run-is-rejected")

    initial = prepare_simple_change(root, {"alpha": ("A", "A2")})
    before = oracle.parse_baseline(root)
    oracle.write_statuses(root, ["sleep:3"])
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
                "exec /sbin/reload_config_rs --timeout-ms 5000"
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
    cancel_ok = (
        interrupted.returncode == 75
        and before == after
        and len([item for item in interrupted_traces if item["kind"] == "fatal"]) == 1
        and [item for item in interrupted_traces if item["kind"] == "fatal"][0]["class"]
        == "temporary"
    )
    results.append(
        {
            "id": "f06-sigterm-cancels-with-retryable-baseline",
            "compared_entry_count": len(initial),
            "exit_status": interrupted.returncode,
            "baseline_unchanged": before == after,
            "passed": cancel_ok,
        }
    )
    if not cancel_ok:
        problems.append("f06-sigterm-cancels-with-retryable-baseline")

    return results, problems


def prepare_rootfs(
    source: Path, destination: Path, candidate: Path
) -> tuple[dict[str, str], dict[str, Any]]:
    observed = oracle.prepare_rootfs(source, destination)
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
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="owrt-r1-candidate-") as temp:
        root = Path(temp) / "rootfs"
        observed, candidate_info = prepare_rootfs(
            args.rootfs.resolve(), root, args.candidate.resolve()
        )
        cases, case_problems = run_reference_cases(root, args.cases.resolve())
        faults, fault_problems = run_fault_cases(root)

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
            "normalizer": "exact image /sbin/uci",
            "digest_tool": "exact image BusyBox md5sum",
            "delivery_adapter": "test-only /bin/ubus shim in disposable rootfs",
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
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        raise SystemExit(f"{len(problems)} candidate problem(s); output not written")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
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
