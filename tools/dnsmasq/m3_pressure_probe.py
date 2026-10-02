#!/usr/bin/env python3
"""Aggregate the bounded M3 disk/FD pressure gates.

The pressure actions themselves live in the focused C/Rust probes:

* ``dhcp_lease_lifecycle.py`` exercises an actual full lease filesystem and
  the source-defined retry/recovery boundary;
* ``dns_start_failure_diff.py`` exercises UDP socket ``EMFILE`` and recovery;
* ``dns_tcp_accept_failure_diff.py`` exercises TCP accept ``EMFILE``, listener
  retention, and descriptor/thread/child cleanup.

This command deliberately does not start a daemon or a long soak.  It only
joins completed raw result directories, verifies that the expected failure
profiles and cleanup evidence are present, and records the exact C/Rust
identities.  Missing evidence is a failure; it is never treated as a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / "private"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_result(path: Path, name: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"{name} result is not a file: {path}")
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {name} result {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{name} result must be a JSON object")
    return value


def check(checks: list[dict[str, Any]], name: str, passed: bool, detail: Any) -> None:
    checks.append({"name": name, "pass": bool(passed), "detail": detail})


def all_pass(rows: Any) -> bool:
    return isinstance(rows, list) and bool(rows) and all(
        isinstance(row, dict) and row.get("pass") is True for row in rows
    )


def identity_from_lease(value: dict[str, Any], checks: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    runs = value.get("runs")
    if not isinstance(runs, list):
        check(checks, "lease-runs-present", False, "runs is missing")
        return None, None
    by_impl: dict[str, list[dict[str, Any]]] = {"c": [], "rust": []}
    for run in runs:
        if isinstance(run, dict) and run.get("implementation") in by_impl:
            by_impl[run["implementation"]].append(run)
    identities: dict[str, set[str]] = {}
    for implementation, rows in by_impl.items():
        values = {
            row.get("binary_sha256")
            for row in rows
            if isinstance(row.get("binary_sha256"), str)
        }
        identities[implementation] = values
        check(
            checks,
            f"lease-{implementation}-identity",
            bool(rows) and len(values) == 1,
            sorted(values),
        )
    check(
        checks,
        "lease-cleanup",
        all_pass(value.get("checks"))
        and any(
            isinstance(row, dict)
            and row.get("case", "").endswith("-resources-released")
            and row.get("pass") is True
            for row in value.get("checks", [])
        ),
        "all lease lifecycle checks and resource-release rows pass",
    )
    return (
        next(iter(identities["c"])) if len(identities["c"]) == 1 else None,
        next(iter(identities["rust"])) if len(identities["rust"]) == 1 else None,
    )


def identity_from_reference(
    value: dict[str, Any], name: str, checks: list[dict[str, Any]]
) -> tuple[str | None, str | None]:
    reference = value.get("reference")
    c_sha = reference.get("elf_sha256") if isinstance(reference, dict) else None
    rust_sha = value.get("rust_sha256")
    check(checks, f"{name}-c-identity", isinstance(c_sha, str) and len(c_sha) == 64, c_sha)
    check(
        checks,
        f"{name}-rust-identity",
        isinstance(rust_sha, str) and len(rust_sha) == 64,
        rust_sha,
    )
    return c_sha if isinstance(c_sha, str) else None, rust_sha if isinstance(rust_sha, str) else None


def verify_start(value: dict[str, Any], source: Path, checks: list[dict[str, Any]]) -> None:
    profiles = value.get("profiles")
    names = {
        row.get("profile")
        for row in profiles
        if isinstance(row, dict)
    } if isinstance(profiles, list) else set()
    expected = {"fd-full", "stale-fd"}
    check(checks, "udp-fd-pressure-profiles", expected <= names, sorted(names))
    check(
        checks,
        "udp-fd-pressure-result",
        isinstance(value.get("failures"), list)
        and not value["failures"]
        and isinstance(value.get("fixture_failures"), list)
        and not value["fixture_failures"]
        and value.get("mismatches") == 0,
        {
            "failures": value.get("failures"),
            "fixture_failures": value.get("fixture_failures"),
            "mismatches": value.get("mismatches"),
        },
    )
    cleanup: dict[str, dict[str, Any]] = {}
    for profile in names:
        if not isinstance(profile, str):
            continue
        for implementation in ("c", "rust"):
            observed = source.parent / profile / implementation / "observed.json"
            if not observed.is_file():
                continue
            try:
                raw = json.loads(observed.read_text())
            except (OSError, json.JSONDecodeError):
                raw = None
            cleanup[f"{profile}/{implementation}"] = {
                "path": str(observed),
                "closed": isinstance(raw, dict) and raw.get("closed") is True,
            }
    required_cleanup = {
        f"{profile}/{implementation}"
        for profile in expected
        for implementation in ("c", "rust")
    }
    check(
        checks,
        "udp-cleanup-evidence",
        required_cleanup <= cleanup.keys()
        and all(cleanup[key]["closed"] for key in required_cleanup),
        cleanup,
    )


def verify_tcp(value: dict[str, Any], source: Path, checks: list[dict[str, Any]]) -> None:
    calibration = value.get("calibration")
    check(
        checks,
        "tcp-fd-pressure-result",
        isinstance(value.get("failures"), list)
        and not value["failures"]
        and isinstance(value.get("differences"), list)
        and not value["differences"]
        and value.get("compared") == 17
        and isinstance(calibration, dict)
        and calibration.get("real_accept_emfile") is True,
        {
            "failures": value.get("failures"),
            "differences": value.get("differences"),
            "compared": value.get("compared"),
            "calibration": calibration,
        },
    )
    traces: dict[str, dict[str, Any]] = {}
    for implementation in ("c", "rust"):
        trace = source.parent / implementation / "trace.json"
        if not trace.is_file():
            continue
        try:
            raw = json.loads(trace.read_text())
        except (OSError, json.JSONDecodeError):
            raw = None
        rows = raw.get("rows", []) if isinstance(raw, dict) else []
        resources = raw.get("resources", {}) if isinstance(raw, dict) else {}
        traces[implementation] = {
            "path": str(trace),
            "clean_exit": isinstance(raw, dict) and raw.get("clean_exit") is True,
            "resources_returned": any(
                isinstance(row, dict)
                and row.get("label") == "resources-returned"
                for row in rows
            ),
            "sample_count": len(resources) if isinstance(resources, dict) else 0,
        }
    check(
        checks,
        "tcp-cleanup-evidence",
        set(traces) == {"c", "rust"}
        and all(item["clean_exit"] and item["resources_returned"] for item in traces.values()),
        traces,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lease-result", type=Path, required=True)
    parser.add_argument("--start-result", type=Path, required=True)
    parser.add_argument("--tcp-result", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-c-sha")
    parser.add_argument("--expected-rust-sha")
    args = parser.parse_args()

    paths = {
        "lease": args.lease_result.resolve(),
        "udp": args.start_result.resolve(),
        "tcp": args.tcp_result.resolve(),
    }
    out = args.out.resolve()
    if not out.is_relative_to(PRIVATE) or out.exists():
        parser.error("--out must be a new path below the repository private/ directory")
    if any(not path.is_relative_to(PRIVATE) for path in paths.values()):
        parser.error("all input results must be below the repository private/ directory")
    out.mkdir(parents=True)
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        values = {
            name: load_result(path, name)
            for name, path in paths.items()
        }
        c_ids: dict[str, str | None] = {}
        rust_ids: dict[str, str | None] = {}
        c_ids["lease"], rust_ids["lease"] = identity_from_lease(values["lease"], checks)
        c_ids["udp"], rust_ids["udp"] = identity_from_reference(values["udp"], "udp", checks)
        c_ids["tcp"], rust_ids["tcp"] = identity_from_reference(values["tcp"], "tcp", checks)

        check(
            checks,
            "lease-enospc",
            values["lease"].get("error_count") == 0
            and values["lease"].get("enospc_checked") is True
            and any(
                isinstance(row, dict)
                and row.get("scenario") == "enospc-idle-retry"
                for row in values["lease"].get("runs", [])
            ),
            {"error_count": values["lease"].get("error_count"), "enospc_checked": values["lease"].get("enospc_checked")},
        )
        verify_start(values["udp"], paths["udp"], checks)
        verify_tcp(values["tcp"], paths["tcp"], checks)

        for implementation, identities in (("C", c_ids), ("Rust", rust_ids)):
            unique = {value for value in identities.values() if value is not None}
            check(checks, f"{implementation.lower()}-identity-consistent", len(unique) == 1, identities)
            expected = args.expected_c_sha if implementation == "C" else args.expected_rust_sha
            if expected:
                check(checks, f"{implementation.lower()}-identity-expected", unique == {expected}, {"actual": sorted(unique), "expected": expected})

        for name, path in paths.items():
            target = out / f"{name}-result.json"
            shutil.copy2(path, target)
    except (OSError, ValueError) as error:
        failures.append(repr(error))

    report = {
        "scope": "M3 bounded disk-full and FD-exhaustion aggregation; no soak/performance claim",
        "inputs": {
            name: {"path": str(path), "sha256": digest(path) if path.is_file() else None}
            for name, path in paths.items()
        },
        "checks": checks,
        "failures": failures,
        "success": not failures and bool(checks) and all(row["pass"] for row in checks),
        "tool_sha256": digest(Path(__file__)),
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("success", "failures")}, sort_keys=True))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
