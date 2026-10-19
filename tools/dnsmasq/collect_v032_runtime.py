#!/usr/bin/env python3
"""Combine immutable completed runtime stages with the corrected startup run."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("runtime", "startup", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    receipts = {}

    def read(name, path):
        receipts[name] = {"path": str(path.resolve()), "sha256": sha(path)}
        return json.loads(path.read_text())

    runtime = read("runtime-controller", args.runtime / "result.json")
    startup = read("startup", args.startup / "result.json")
    assert runtime["status"] == "failed-preserved" and "startup-helper-k" in runtime["error"]
    assert startup["status"] == "passed-startup-boundaries-vs-v031"
    for key in ("source_commit", "source_digest", "elf_sha256", "baseline_sha256"):
        assert runtime[key] == startup[key]
    assert all(sha(path) == digest for report in (runtime, startup)
               for path, digest in report["identities"].items())
    sides = {}
    for role, digest in (("baseline-v031", runtime["baseline_sha256"]), ("candidate", runtime["elf_sha256"])):
        no_proc = read(role + "-no-proc", args.runtime / (role + "-no-proc/result.json"))
        assert no_proc["passed"] and no_proc["binary_sha256"] == digest
        fd = read(role + "-fd", args.runtime / (role + "-fd/result.json"))
        assert fd["binary_sha256"] == digest and len(fd["cases"]) == 8
        rows = {(row["mode"], row["fd_pressure"]["headroom"]): row for row in fd["cases"]}
        assert set(rows) == {(mode, holes) for mode in ("helper", "resolver") for holes in (2, 3, 4, 8)}
        for row in rows.values():
            pressure = row["fd_pressure"]
            assert pressure["limit_change"]["applied_exactly"]
            assert all(pressure[phase]["health_ok"] for phase in ("pressure", "recovery"))
        sides[role] = rows
    for key, before in sides["baseline-v031"].items():
        after = sides["candidate"][key]
        assert not before["passed"] or after["passed"]
        for phase in ("pressure", "recovery"):
            for field in ("operation_ok", "health_ok"):
                assert not before["fd_pressure"][phase][field] or after["fd_pressure"][phase][field]
        assert not before["fd_pressure"]["limit_change"]["restore"].get("restored") or \
            after["fd_pressure"]["limit_change"]["restore"].get("restored")
    assert all(row["passed"] for (mode, _), row in sides["candidate"].items() if mode == "resolver")
    shipping = read("shipping", args.runtime / "shipping/result.json")
    assert shipping["passed"] and shipping["sha256"] == runtime["elf_sha256"]
    assert shipping["elf_type"] == 3 and shipping["distinct_bases"] == 3
    assert all(row["relro_readonly"] and not row["stack_executable"] for row in shipping["runs"])
    assert startup["starts"] == 40 and len(startup["groups"]) == 4
    assert all(group["returncode"] == 0 and len(group["validated"]["starts"]) == 10 for group in startup["groups"])
    assert startup["helper_callbacks"][0] == startup["helper_callbacks"][1]
    result = {key: runtime[key] for key in ("source_commit", "source_digest", "elf_sha256", "baseline_sha256")}
    result.update(status="passed-runtime-regression-vs-v031", receipts=receipts,
                  no_proc_cases=4, fd_cases=16, fd_regressions=[], candidate_resolver_passed=4,
                  known_helper_pressure_failures=[2, 3, 4, 8], startup_starts=40,
                  shipping_aslr_starts=3, physical_router_touched=False, performance_verdict=False,
                  controller_failure_preserved="runtime controller stopped only at the invalid /home startup path; "
                    "completed no-proc/FD/shipping receipts retained, all four startup groups rerun under /tmp",
                  collector_sha256=sha(__file__))
    with args.out.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({"status": result["status"], "output": str(args.out), "sha256": sha(args.out)}))


if __name__ == "__main__":
    main()
