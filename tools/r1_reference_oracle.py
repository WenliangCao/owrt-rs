#!/usr/bin/env python3
"""Run the exact OpenWrt reload_config implementation in a disposable chroot.

The input rootfs is copied before use.  The deployed 17-line shell script,
BusyBox applets and uci binary remain unchanged in that copy.  Only /bin/ubus
is replaced with a test adapter which records each attempted event and returns
a configured status.  This makes delivery results observable without changing
the detector or touching a router.

The committed output is derived, synthetic evidence.  The copied rootfs and
all command output stay in a temporary directory outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


EXPECTED_ARTIFACTS = {
    "bin/busybox": "54d4139265132254e5601cb65d8617a928d5d5867c044ef701d53b973daafe09",
    "bin/ubus": "9bc20e73e500c724e0ad8132b894e7dba7ca49a41cd20c38dd0b9fa23f9412eb",
    "sbin/reload_config": "f1527a793209e14b6325e8afd57e0e11600a285016e5b854f299a59bb6fa4e15",
    "sbin/uci": "050e9ab320b794f636174536ca4dbca2f615a1c6c37bc19e9ca06bfd6d6e7278",
}
# The original identity remains the 25.12.5 oracle. The .6 stock image changes
# BusyBox while retaining uci, ubus and the reload script byte for byte.
EXPECTED_RELEASE_ARTIFACTS = {
    "25.12.5": EXPECTED_ARTIFACTS,
    "25.12.6": {
        **EXPECTED_ARTIFACTS,
        "bin/busybox": "aeeda86015e809106a5d247fd8504ac45e01bde0711f4d80af60fc2885ee923a",
    },
}
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_<>.-]{1,64}$")
EXPECTED_CASE_IDS = {
    f"c{number:02d}-{suffix}"
    for number, suffix in (
        (1, "first-run-emits-nothing"),
        (2, "modified-config-emits"),
        (3, "new-config-is-silent"),
        (4, "deleted-config-emits-once"),
        (5, "dotted-name-yields-empty-entry"),
        (6, "dotted-name-change-never-emits"),
        (7, "dotted-rename-to-valid-becomes-live"),
        (8, "var-run-uci-takes-precedence"),
        (9, "comment-only-change-is-invisible"),
        (10, "switchover-must-be-silent"),
        (11, "dotted-name-can-resolve-section"),
    )
}

UBUS_ADAPTER = r"""#!/bin/sh
payload="$4"
package=$(printf '%s\n' "$payload" | sed -n 's/.*"package": "\([^"]*\)".*/\1/p')
index=$(($(wc -l < /tmp/r1-delivery.log) + 1))
action=$(sed -n "${index}p" /tmp/r1-delivery-status)
[ -n "$action" ] || action=0
case "$action" in
  sleep:*)
    printf '%s\tpending\n' "$package" >> /tmp/r1-delivery.log
    sleep "${action#sleep:}"
    exit 0
    ;;
  *)
    printf '%s\t%s\n' "$package" "$action" >> /tmp/r1-delivery.log
    exit "$action"
    ;;
esac
"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clear_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for entry in path.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def quote_uci(value: str) -> str:
    if not SAFE_TOKEN.fullmatch(value):
        raise ValueError(f"synthetic token is outside the oracle fixture alphabet: {value!r}")
    return value


def render_package(
    package: str, token: str, uci_lookups: dict[str, str], comment: str | None
) -> str:
    if token == "<MALFORMED>":
        return "this is not valid UCI syntax\n"
    lines = ["config r1_fixture 'main'", f"\toption token '{quote_uci(token)}'"]
    if comment:
        lines.insert(0, f"# {comment}")
    for tuple_name, lookup_token in sorted(uci_lookups.items()):
        parts = tuple_name.split(".")
        if len(parts) not in (2, 3) or parts[0] != package:
            continue
        section = parts[1]
        lines.extend(
            [
                f"config r1_fixture '{quote_uci(section)}'",
                f"\toption token '{quote_uci(lookup_token)}'",
            ]
        )
        if len(parts) == 3:
            lines.append(
                f"\toption '{quote_uci(parts[2])}' '{quote_uci(lookup_token)}'"
            )
    return "\n".join(lines) + "\n"


def write_config_set(
    root: Path,
    etc_config: dict[str, str],
    var_run_uci: dict[str, str],
    uci_lookups: dict[str, str] | None = None,
    comment: str | None = None,
) -> None:
    lookups = uci_lookups or {}
    targets = (
        (root / "etc/config", etc_config),
        (root / "var/run/uci", var_run_uci),
    )
    for directory, entries in targets:
        clear_directory(directory)
        for name, token in entries.items():
            if "/" in name or name in (".", ".."):
                raise ValueError(f"unsafe synthetic config name: {name!r}")
            path = directory / name
            if "." in name:
                path.write_text(f"# ignored synthetic content {quote_uci(token)}\n")
            else:
                path.write_text(render_package(name, token, lookups, comment))


def parse_baseline(root: Path) -> dict[str, str]:
    path = root / "var/run/config.md5"
    if not path.is_file():
        return {}
    baseline: dict[str, str] = {}
    # Config filenames are bytes, not text: `md5sum` copies them into the
    # baseline verbatim (R81 F26), so decode with surrogateescape and keep the
    # lines md5sum's own format cannot express (a name with a newline) out.
    text = path.read_bytes().decode("utf-8", "surrogateescape")
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  /var/run/config\.check/(.+)", line)
        if not match:
            continue
        baseline[match.group(2)] = match.group(1)
    return baseline


def write_statuses(root: Path, statuses: list[int | str]) -> None:
    tmp = root / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "r1-delivery.log").write_text("")
    (tmp / "r1-delivery-raw.jsonl").write_text("")
    (tmp / "r1-delivery-status").write_text(
        "".join(f"{status}\n" for status in statuses)
    )


def read_deliveries(root: Path) -> list[dict[str, Any]]:
    deliveries = []
    log = (root / "tmp/r1-delivery.log").read_bytes()
    for line in log.decode("utf-8", "surrogateescape").splitlines():
        package, status = line.split("\t", 1)
        deliveries.append(
            {
                "package": package,
                "outcome": "pending" if status == "pending" else "exited",
                "status": None if status == "pending" else int(status),
            }
        )
    return deliveries


def run_exact(
    root: Path, statuses: list[int | str], timeout_s: int = 10
) -> dict[str, Any]:
    write_statuses(root, statuses)
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "/usr/bin/timeout",
            "--signal=KILL",
            str(timeout_s),
            "chroot",
            str(root),
            "/bin/sh",
            "-c",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin /sbin/reload_config",
        ],
        check=False,
        capture_output=True,
        timeout=timeout_s + 5,
    )
    return {
        "exit_status": result.returncode,
        "deliveries": read_deliveries(root),
        "baseline": parse_baseline(root),
        "stderr_nonempty": bool(result.stderr),
    }


def establish_baseline(
    root: Path,
    baseline: dict[str, str] | None,
    uci_lookups: dict[str, str] | None = None,
) -> dict[str, str]:
    baseline_path = root / "var/run/config.md5"
    if baseline_path.exists():
        baseline_path.unlink()
    clear_directory(root / "var/run/config.check")
    if baseline is None:
        return {}
    write_config_set(root, baseline, {}, uci_lookups)
    result = run_exact(root, [])
    if result["exit_status"] != 0 or result["deliveries"]:
        raise RuntimeError(f"failed to establish synthetic baseline: {result}")
    return result["baseline"]


def run_reference_cases(root: Path, case_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    traces: list[dict[str, Any]] = []
    problems: list[str] = []
    paths = sorted(case_dir.glob("*.json"))
    observed_ids = {json.loads(path.read_text()).get("id") for path in paths}
    if observed_ids != EXPECTED_CASE_IDS:
        return [], [
            "reference case identity gate failed: "
            f"missing={sorted(EXPECTED_CASE_IDS - observed_ids)}, "
            f"unexpected={sorted(observed_ids - EXPECTED_CASE_IDS)}"
        ]
    for path in paths:
        case = json.loads(path.read_text())
        given = case["given"]
        initial = establish_baseline(root, given["baseline"], given.get("uci_lookups"))
        final_comment = "comment-only final form" if case["id"].startswith("c09-") else None
        write_config_set(
            root,
            given["etc_config"],
            given["var_run_uci"],
            given.get("uci_lookups"),
            final_comment,
        )
        result = run_exact(root, [0] * len(case["expect"]["events"]))
        events = [item["package"] for item in result["deliveries"]]
        expected_events = case["expect"]["events"]
        expected_names = sorted(case["expect"]["baseline"])
        empty_entries = sorted(
            name for name, digest in result["baseline"].items() if digest == EMPTY_MD5
        )
        passed = (
            result["exit_status"] == 0
            and events == expected_events
            and sorted(result["baseline"]) == expected_names
            and all(item["status"] == 0 for item in result["deliveries"])
        )
        if case["id"].startswith(("c05-", "c06-", "c10-")):
            passed = passed and "dhcp.bak-x" in empty_entries
        if case["id"].startswith("c11-"):
            passed = passed and result["baseline"].get("dhcp.state") != EMPTY_MD5
        if not passed:
            problems.append(f"{case['id']}: exact oracle mismatch")
        traces.append(
            {
                "id": case["id"],
                "evidence": case["evidence"],
                "compared_entry_count": len(initial),
                "changed_entries": events,
                "deliveries": result["deliveries"],
                "new_baseline_entries": sorted(result["baseline"]),
                "empty_baseline_entries": empty_entries,
                "passed": passed,
            }
        )
    return traces, problems


def run_fault_cases(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    traces: list[dict[str, Any]] = []
    problems: list[str] = []

    initial = establish_baseline(root, {"alpha": "A", "beta": "B"})
    write_config_set(root, {"alpha": "A2", "beta": "B2"}, {})
    partial = run_exact(root, [7, 0])
    repeat = run_exact(root, [])
    partial_ok = (
        [d["package"] for d in partial["deliveries"]] == ["alpha", "beta"]
        and [d["status"] for d in partial["deliveries"]] == [7, 0]
        and partial["exit_status"] == 0
        and not repeat["deliveries"]
        and repeat["exit_status"] == 0
    )
    traces.append(
        {
            "id": "f01-partial-delivery-is-absorbed",
            "compared_entry_count": len(initial),
            "deliveries": partial["deliveries"],
            "repeat_deliveries": repeat["deliveries"],
            "baseline_advanced_after_failure": partial["baseline"] == repeat["baseline"],
            "passed": partial_ok,
        }
    )
    if not partial_ok:
        problems.append("f01-partial-delivery-is-absorbed")

    initial = establish_baseline(root, {"alpha": "A", "beta": "B"})
    write_config_set(root, {"alpha": "A2", "beta": "B2"}, {})
    uci = root / "sbin/uci"
    hidden_uci = root / "sbin/uci.r1-oracle-hidden"
    uci.rename(hidden_uci)
    try:
        missing_uci = run_exact(root, [0, 0])
    finally:
        hidden_uci.rename(uci)
    poisoned = sorted(
        name for name, digest in missing_uci["baseline"].items() if digest == EMPTY_MD5
    )
    missing_uci_ok = (
        missing_uci["exit_status"] == 0
        and [d["package"] for d in missing_uci["deliveries"]] == ["alpha", "beta"]
        and poisoned == ["alpha", "beta"]
        and not missing_uci["stderr_nonempty"]
    )
    traces.append(
        {
            "id": "f02-missing-uci-poisons-baseline",
            "compared_entry_count": len(initial),
            "changed_entries": [d["package"] for d in missing_uci["deliveries"]],
            "empty_baseline_entries": poisoned,
            "process_still_exits_zero": missing_uci["exit_status"] == 0,
            "failure_is_silent": not missing_uci["stderr_nonempty"],
            "passed": missing_uci_ok,
        }
    )
    if not missing_uci_ok:
        problems.append("f02-missing-uci-poisons-baseline")

    initial = establish_baseline(root, {"alpha": "A"})
    write_config_set(root, {"alpha": "A2"}, {})
    before_timeout = parse_baseline(root)
    timeout = run_exact(root, ["sleep:3"], timeout_s=1)
    after_timeout = parse_baseline(root)
    retry = run_exact(root, [0])
    timeout_ok = (
        timeout["exit_status"] != 0
        and timeout["deliveries"]
        and timeout["deliveries"][0]["outcome"] == "pending"
        and before_timeout == after_timeout
        and [d["package"] for d in retry["deliveries"]] == ["alpha"]
    )
    traces.append(
        {
            "id": "f03-hung-delivery-blocks-baseline-rewrite",
            "compared_entry_count": len(initial),
            "timed_process_exit_status": timeout["exit_status"],
            "delivery": timeout["deliveries"],
            "baseline_unchanged": before_timeout == after_timeout,
            "retry_changed_entries": [d["package"] for d in retry["deliveries"]],
            "passed": timeout_ok,
        }
    )
    if not timeout_ok:
        problems.append("f03-hung-delivery-blocks-baseline-rewrite")

    initial = establish_baseline(root, {"alpha": "A"})
    write_config_set(root, {"alpha": "<MALFORMED>"}, {})
    malformed = run_exact(root, [0])
    malformed_ok = (
        malformed["exit_status"] == 0
        and [d["package"] for d in malformed["deliveries"]] == ["alpha"]
        and malformed["baseline"].get("alpha") == EMPTY_MD5
    )
    traces.append(
        {
            "id": "f04-malformed-uci-becomes-empty-baseline",
            "compared_entry_count": len(initial),
            "changed_entries": [d["package"] for d in malformed["deliveries"]],
            "empty_baseline_entries": sorted(
                name for name, digest in malformed["baseline"].items() if digest == EMPTY_MD5
            ),
            "passed": malformed_ok,
        }
    )
    if not malformed_ok:
        problems.append("f04-malformed-uci-becomes-empty-baseline")

    return traces, problems


def prepare_rootfs(source: Path, destination: Path, *, delivery_adapter: bool = True) -> dict[str, str]:
    release = (source / "etc/openwrt_release").read_text()
    match = re.search(r"(?m)^DISTRIB_RELEASE=['\"]([^'\"]+)['\"]\s*$", release)
    version = match[1] if match else None
    if version not in EXPECTED_RELEASE_ARTIFACTS:
        raise SystemExit(f"unsupported rootfs release: {version!r}")
    expected = EXPECTED_RELEASE_ARTIFACTS[version]
    observed = {
        path: sha256_file(source / path) for path in expected
    }
    if observed != expected:
        raise SystemExit(
            f"rootfs identity gate failed: expected={expected}, observed={observed}"
        )
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    # Extracted official roots contain device nodes/FIFOs. Preserve them as
    # nodes and retain ownership/mode; never open them as ordinary file data.
    subprocess.run(["cp", "-a", str(source), str(destination)], check=True)
    null = destination / "dev/null"
    null.parent.mkdir(parents=True, exist_ok=True)
    if not null.exists():
        null.touch()
    if delivery_adapter:
        adapter = destination / "bin/ubus"
        adapter.write_text(UBUS_ADAPTER)
        adapter.chmod(0o755)
    return observed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="owrt-r1-oracle-") as temp:
        root = Path(temp) / "rootfs"
        observed = prepare_rootfs(args.rootfs.resolve(), root)
        reference, reference_problems = run_reference_cases(root, args.cases.resolve())
        faults, fault_problems = run_fault_cases(root)

    problems = reference_problems + fault_problems
    payload = {
        "schema_version": 1,
        "stage": "R1.1",
        "status": "complete" if not problems else "failed",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "device_access": False,
            "device_writes": False,
            "rootfs_copy_is_disposable": True,
            "detector_modified": False,
            "delivery_adapter": "test-only /bin/ubus shim in the disposable rootfs copy",
        },
        "source_artifacts": observed,
        "observability": {
            "compared_entry_count": True,
            "changed_entries": True,
            "per_delivery_result": True,
            "subscriber_confirmation": False,
        },
        "reference_cases": reference,
        "fault_cases": faults,
        "undefined_concurrency": (
            "Concurrent reload_config invocations share and delete the same config.check "
            "directory. C1 does not define that race; R1 must not claim compatibility for it."
        ),
        "gate": {
            "reference_cases_passed": not reference_problems,
            "fault_cases_recorded": not fault_problems,
            "delivery_is_observable": True,
            "rust_crate_creation_allowed": not problems,
            "passed": not problems,
        },
    }
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        raise SystemExit(f"{len(problems)} oracle problem(s); output not written")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "reference_cases": len(reference),
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
