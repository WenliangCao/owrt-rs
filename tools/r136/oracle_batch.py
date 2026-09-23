#!/usr/bin/env python3
"""Run a declared candidate set through the five ubusd registration lanes.

This runner is an Oracle pre-screen, never a router verdict.  It starts one
isolated daemon per subject/block, keeps C and all candidates in the same
paired schedule, and records every raw benchmark JSON plus process identity
and cleanup evidence.  New candidate binaries are data in the manifest; the
runner does not need a code change for a sendmmsg experiment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import threading
import time


LANES = {
    "register_1": ("register-cycle", "1", "8"),
    "register_16": ("register-cycle", "16", "8"),
    "event_1": ("register-watch", "1", "1"),
    "event_8": ("register-watch", "8", "1"),
    "event_nomatch": ("register-watch", "1", "0"),
}
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us",
           "daemon_cpu_us_per_op", "caller_cpu_us_per_op")
HEX64 = re.compile(r"[0-9a-f]{64}")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
STOP = threading.Event()
STOP_SIGNAL: int | None = None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def request_stop(signum: int, _frame: object) -> None:
    global STOP_SIGNAL
    STOP_SIGNAL = signum
    STOP.set()


def stop_reason() -> str:
    return f"stop requested by signal {STOP_SIGNAL}" if STOP_SIGNAL is not None else "another worker failed"


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def proc_identity(pid: int) -> dict:
    status = Path(f"/proc/{pid}/status").read_text()
    stat = Path(f"/proc/{pid}/stat").read_text()
    tail = stat.rsplit(") ", 1)[1].split()
    values: dict[str, int | str] = {"pid": pid, "start_ticks": int(tail[19]),
                                    "last_processor": int(tail[36])}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key in {"Threads", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
                   "VmRSS", "RssAnon", "VmHWM"}:
            values[key] = int(value.split()[0])
        elif key in {"Cpus_allowed", "Cpus_allowed_list"}:
            values[key] = value.strip()
    require("Cpus_allowed_list" in values and "Threads" in values, f"incomplete /proc status for {pid}")
    return values


def mask_text(cpus: tuple[int, int]) -> str:
    return str(cpus[0]) if cpus[0] == cpus[1] else f"{min(cpus)}-{max(cpus)}"


def check_measurement(data: dict, daemon_pid: int, daemon_start: int, caller_pid: int,
                      daemon_mask: str, caller_mask: str, n: int, warmup: int) -> dict:
    require(data.get("schema") == 1 and type(data.get("successful")) is int and data.get("successful") == n
            and data.get("errors") == 0 and data.get("warmup") == warmup,
            "benchmark count/error fields invalid")
    samples = data.get("latency_ns")
    require(isinstance(samples, list) and len(samples) == n
            and all(type(value) is int and value > 0 for value in samples),
            "raw latency vector invalid")
    ordered = sorted(samples)
    expected = {"mean_us": sum(samples) / n / 1000.0,
                "p50_us": ordered[math.floor((n - 1) * .50 + .5)] / 1000.0,
                "p95_us": ordered[math.floor((n - 1) * .95 + .5)] / 1000.0,
                "p99_us": ordered[math.floor((n - 1) * .99 + .5)] / 1000.0}
    for name, value in expected.items():
        require(type(data.get(name)) in (int, float) and math.isfinite(data[name])
                and math.isclose(data[name], value, rel_tol=1e-8, abs_tol=1e-6),
                f"reported {name} differs from raw vector")
    require(type(data.get("wall_s")) in (float, int) and math.isfinite(data["wall_s"])
            and data["wall_s"] > 0 and math.isclose(data["ops_per_s"], n / data["wall_s"],
                                                   rel_tol=1e-8, abs_tol=1e-6),
            "wall time/throughput evidence invalid")
    daemons = data.get("daemon_cpu")
    require(isinstance(daemons, list) and len(daemons) == 1, "exactly one daemon must be sampled")
    daemon = daemons[0]
    require(daemon.get("pid") == daemon_pid and daemon["before"]["pid"] == daemon_pid
            and daemon["after"]["pid"] == daemon_pid,
            "wrong daemon PID in benchmark output")
    require(daemon["before"]["start_ticks"] == daemon["after"]["start_ticks"] == daemon_start,
            "daemon identity changed during measurement")
    require(data["client_before"]["pid"] == data["client_after"]["pid"] == caller_pid,
            "wrong caller PID in benchmark output")
    for name, before, after, expected_mask, elapsed in (
            ("daemon", daemon["before"], daemon["after"], daemon_mask, daemon["cpu_clock_ns"]),
            ("caller", data["client_before"], data["client_after"], caller_mask,
             data["client_cpu_clock_ns"])):
        require(before["Cpus_allowed_list"] == after["Cpus_allowed_list"] == expected_mask,
                f"{name} CPU affinity changed")
        require(before["Threads"] == after["Threads"] == 1
                and before["process_cpu_resolution_ns"] == after["process_cpu_resolution_ns"] > 0,
                f"{name} thread count or clock resolution changed")
        require(before["start_ticks"] == after["start_ticks"]
                and type(before["process_cpu_ns"]) is int
                and type(after["process_cpu_ns"]) is int
                and after["process_cpu_ns"] >= before["process_cpu_ns"]
                and elapsed == after["process_cpu_ns"] - before["process_cpu_ns"],
                f"{name} CPU clock evidence invalid")
        for field in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
            require(type(before[field]) is int and type(after[field]) is int
                    and after[field] >= before[field], f"{name} context counter regressed")
    require(type(daemon["cpu_clock_ns"]) is int and daemon["cpu_clock_ns"] > 0,
            "daemon CPU delta invalid")
    require(type(data["client_cpu_clock_ns"]) is int and data["client_cpu_clock_ns"] > 0,
            "caller CPU delta invalid")
    metrics = dict(expected)
    metrics["daemon_cpu_us_per_op"] = daemon["cpu_clock_ns"] / n / 1000.0
    metrics["caller_cpu_us_per_op"] = data["client_cpu_clock_ns"] / n / 1000.0
    return metrics


def subject_command(subject: dict, bench: Path, daemon_cpu: int, socket: Path,
                    rootfs: dict) -> list[str]:
    args = ["-s", str(socket), "-A", str(socket.parent / "acl")]
    if subject["kind"] == "c":
        loader = Path(rootfs["loader"])
        library_path = rootfs["library_path"]
        return ["taskset", "-c", str(daemon_cpu), str(loader), "--library-path", library_path,
                "--argv0", "/sbin/ubusd", str(subject["path"]), *args]
    require(subject["kind"] == "rust", f"unsupported subject kind: {subject['kind']}")
    return [str(bench), "exec-cpu-as", str(daemon_cpu), str(subject["path"]), "/sbin/ubusd", *args]


def run_subject(out: Path, subject: dict, bench: Path, bench_sha: str,
                pair: tuple[int, int], block: int, n: int, warmup: int,
                rootfs: dict, library_hashes: dict[str, str]) -> list[dict]:
    out.mkdir(parents=True, exist_ok=False)
    socket = out / "bus.sock"
    require(len(str(socket).encode()) < 108, "UNIX socket path exceeds Linux limit")
    acl = socket.parent / "acl"
    acl.mkdir()
    command = subject_command(subject, bench, pair[1], socket, rootfs)
    write_json(out / "daemon-command.json", command)
    write_json(out / "subject.json", subject)
    daemon: subprocess.Popen | None = None
    caller: subprocess.Popen | None = None
    records: list[dict] = []
    try:
        with (out / "daemon.log").open("wb") as log:
            daemon = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True)
            deadline = time.monotonic() + 10
            while not socket.exists():
                require(not STOP.is_set(), stop_reason())
                require(daemon.poll() is None and time.monotonic() < deadline,
                        f"daemon failed to start: {subject['label']}")
                time.sleep(.005)
        require(os.sched_getaffinity(daemon.pid) == {pair[1]}, "daemon affinity mismatch")
        live = proc_identity(daemon.pid)
        daemon_start = int(live["start_ticks"])
        write_json(out / "daemon-start.json", live)
        cmdline = Path(f"/proc/{daemon.pid}/cmdline").read_bytes()
        # musl overrides the target's argv[0] but /proc retains the loader
        # invocation.  exec-cpu-as execs the Rust ELF with normalized argv.
        expected_args = command[3:] if subject["kind"] == "c" else command[4:]
        expected_cmdline = b"\0".join(x.encode() for x in expected_args) + b"\0"
        require(cmdline == expected_cmdline, "live daemon argv differs from planned argv")
        write_json(out / "daemon-cmdline.json", {"bytes_hex": cmdline.hex()})
        expected_exe = Path(rootfs["loader"]) if subject["kind"] == "c" else Path(subject["path"])
        require(sha256(Path(f"/proc/{daemon.pid}/exe")) == sha256(expected_exe),
                "live executable identity differs")
        maps = Path(f"/proc/{daemon.pid}/maps").read_text()
        require(str(subject["path"]) in maps, "subject binary missing from daemon maps")
        if subject["kind"] == "c":
            for path in library_hashes:
                library = Path(path)
                require(sha256(library) == library_hashes[path] and str(library) in maps,
                        f"C runtime library identity missing: {library}")
        (out / "daemon-maps.txt").write_text(maps)
        conditions = list(itertools.product(("split", "pair_allowed"), LANES))
        if (block + pair[0] // 2) % 2:
            conditions.reverse()
        for affinity, lane in conditions:
            require(not STOP.is_set(), stop_reason())
            command_name, first, second = LANES[lane]
            caller_mask = str(pair[0]) if affinity == "split" else mask_text(pair)
            cmd = ["taskset", "-c", caller_mask, str(bench), command_name, str(socket),
                   first, second, str(n), str(warmup), str(daemon.pid)]
            stem = f"{affinity}-{lane}"
            write_json(out / f"{stem}-command.json", cmd)
            with (out / f"{stem}.json").open("wb") as stdout, (out / f"{stem}.log").open("wb") as stderr:
                caller = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    code = caller.wait(timeout=120)
                finally:
                    stop_process(caller)
            require(code == 0, f"benchmark failed: {stem}")
            require(not (out / f"{stem}.log").read_bytes(), f"benchmark stderr not empty: {stem}")
            data = json.loads((out / f"{stem}.json").read_text())
            metrics = check_measurement(data, daemon.pid, daemon_start, caller.pid,
                                        mask_text((pair[1], pair[1])), caller_mask, n, warmup)
            records.append({"label": subject["label"], "pair": list(pair), "block": block,
                            "affinity": affinity, "lane": lane,
                            "file": str(out / f"{stem}.json"), "metrics": metrics,
                            "subject_sha256": subject["sha256"], "benchmark_sha256": bench_sha})
            caller = None
        require(daemon.poll() is None, "daemon exited during subject measurements")
        require(sha256(Path(subject["path"])) == subject["sha256"]
                and sha256(bench) == bench_sha, "subject or benchmark changed during run")
        require(not (out / "daemon.log").read_bytes(), "daemon emitted unexpected stderr/stdout")
        write_json(out / "daemon-end.json", proc_identity(daemon.pid))
    finally:
        stop_process(caller)
        stop_process(daemon)
        socket.unlink(missing_ok=True)
        write_json(out / "cleanup.json", {
            "daemon_exited": daemon is None or daemon.poll() is not None,
            "daemon_returncode": None if daemon is None else daemon.returncode,
            "caller_exited": caller is None or caller.poll() is not None,
            "caller_returncode": None if caller is None else caller.returncode,
            "socket_absent": not socket.exists(),
        })
    cleanup = json.loads((out / "cleanup.json").read_text())
    require(cleanup["daemon_exited"] and cleanup["caller_exited"] and cleanup["socket_absent"],
            f"owned process/socket cleanup failed: {subject['label']}")
    (out / "COMPLETE").touch()
    return records


def parse_pairs(value: str) -> list[tuple[int, int]]:
    result = []
    seen = set()
    for item in value.split(","):
        parts = item.split(":")
        if len(parts) != 2:
            raise ValueError("CPU pairs must use daemon:caller, e.g. 1:0")
        daemon, caller = (int(part) for part in parts)
        if daemon < 0 or caller < 0 or abs(daemon - caller) != 1:
            raise ValueError("each daemon/caller pair must contain adjacent nonnegative CPUs")
        if any(set(pair) & {daemon, caller} for pair in result):
            raise ValueError("parallel CPU pairs must be disjoint")
        pair = (caller, daemon)
        if pair in seen:
            raise ValueError("duplicate CPU pair")
        seen.add(pair)
        result.append(pair)
    if not result:
        raise ValueError("at least one CPU pair is required")
    return result


def load_manifest(path: Path) -> tuple[dict, dict[str, dict]]:
    value = json.loads(path.read_text())
    require(value.get("schema") == 1, "manifest schema must be 1")
    require(isinstance(value.get("benchmark"), dict), "manifest benchmark missing")
    subjects = value.get("subjects")
    require(isinstance(subjects, list) and subjects, "manifest subjects missing")
    by_label: dict[str, dict] = {}
    for item in subjects:
        require(isinstance(item, dict) and LABEL.fullmatch(str(item.get("label", ""))),
                "invalid subject label")
        label = item["label"]
        require(label not in by_label, f"duplicate subject: {label}")
        require(item.get("kind") in ("c", "rust") and isinstance(item.get("path"), str),
                f"invalid subject declaration: {label}")
        expected = item.get("sha256")
        require(isinstance(expected, str) and HEX64.fullmatch(expected), f"invalid subject hash: {label}")
        path_value = Path(item["path"])
        require(path_value.is_file() and not path_value.is_symlink() and sha256(path_value) == expected,
                f"subject identity mismatch: {label}")
        by_label[label] = {**item, "path": str(path_value.resolve())}
    require(sum(item["kind"] == "c" for item in by_label.values()) == 1,
            "manifest requires exactly one C subject")
    for item in by_label.values():
        if item["kind"] == "c":
            require(item["sha256"] == "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88",
                    "C must be the exact deployment-image ubusd")
    bench = value["benchmark"]
    bench_path = Path(bench.get("path", ""))
    require(bench_path.is_file() and isinstance(bench.get("sha256"), str)
            and HEX64.fullmatch(bench["sha256"]) and sha256(bench_path) == bench["sha256"],
            "benchmark identity mismatch")
    rootfs = value.get("rootfs", {})
    require(isinstance(rootfs, dict) and isinstance(rootfs.get("loader"), str)
            and isinstance(rootfs.get("library_path"), str)
            and Path(rootfs["loader"]).is_file(), "rootfs loader missing")
    libraries = value.get("libraries", {})
    require(isinstance(libraries, dict) and rootfs["loader"] in libraries,
            "libraries must include the exact musl loader identity")
    for path, expected in libraries.items():
        require(Path(path).is_file() and isinstance(expected, str) and HEX64.fullmatch(expected)
                and sha256(Path(path)) == expected, f"runtime library identity mismatch: {path}")
    return {**value, "benchmark": {**bench, "path": str(bench_path.resolve())},
            "rootfs": rootfs, "libraries": libraries}, by_label


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--pairs", default="1:0,3:2",
                        help="comma-separated daemon:caller CPU pairs")
    parser.add_argument("--subjects", nargs="*", help="optional labels; C is always retained")
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "aarch64"
            and os.geteuid() == 0 and not Path("/etc/openwrt_release").exists(),
            "Oracle root aarch64 Linux is required")
    require(args.repeats > 0 and args.repeats <= 32 and args.iterations > 0
            and args.iterations <= 1_000_000 and 0 <= args.warmup <= 100_000,
            "invalid loop counts")
    pairs = parse_pairs(args.pairs)
    manifest, all_subjects = load_manifest(args.manifest.resolve())
    selected = set(args.subjects or all_subjects)
    c_labels = {label for label, item in all_subjects.items() if item["kind"] == "c"}
    require(c_labels <= selected, "C subject cannot be filtered out")
    require(selected <= all_subjects.keys() and len(selected) >= 2, "unknown or insufficient subjects")
    subjects = {label: all_subjects[label] for label in all_subjects if label in selected}
    bench = Path(manifest["benchmark"]["path"])
    bench_sha = manifest["benchmark"]["sha256"]
    require(all(set(pair) <= os.sched_getaffinity(0) for pair in pairs), "requested CPU unavailable")
    out = args.output.resolve()
    require(not out.exists(), f"refusing pre-existing output: {out}")
    out.mkdir(parents=True)
    labels = list(subjects)
    width = max(map(len, labels))
    block_width = max(1, len(str(args.repeats - 1)))
    schedules = []
    for pair in pairs:
        jobs = []
        for block in range(args.repeats):
            order = labels if (block + pair[0] // 2) % 2 == 0 else list(reversed(labels))
            jobs.extend((block, label) for label in order)
        schedules.append(jobs)
    plan = {
        "schema": 1,
        "scope": "R136 Oracle exploratory batch; no router verdict and no deployment",
        "runner": str(Path(__file__).resolve()), "runner_sha256": sha256(Path(__file__).resolve()),
        "manifest": str(args.manifest.resolve()), "manifest_sha256": sha256(args.manifest.resolve()),
        "benchmark": manifest["benchmark"], "subjects": subjects, "pairs": pairs,
        "repeats": args.repeats, "iterations": args.iterations, "warmup": args.warmup,
        "lanes": {name: list(value) for name, value in LANES.items()},
        "schedules": schedules, "affinities": ["split", "pair_allowed"],
        "decision": "paired descriptive screen only; no router or familywise dominance claim",
        "cleanup": "every daemon/caller is an own process group; socket must be absent before next subject",
    }
    write_json(out / "plan.json", plan)
    write_json(out / "manifest-identity.json", manifest)
    records: list[dict] = []

    def worker(pair: tuple[int, int], jobs: list[tuple[int, str]]) -> list[dict]:
        local: list[dict] = []
        try:
            for block, label in jobs:
                require(not STOP.is_set(), stop_reason())
                # Equal-length paths do not make labels such as a/a_ collide.
                subject_name = f"{labels.index(label):03d}-{label.ljust(width, '_')}"
                subject_dir = out / f"p{pair[0]}-{pair[1]}-b{block:0{block_width}d}" / subject_name
                local.extend(run_subject(subject_dir, subjects[label], bench, bench_sha, pair,
                                          block, args.iterations, args.warmup,
                                          manifest["rootfs"], manifest["libraries"]))
                print(f"COMPLETE pair={pair} block={block} subject={label}", flush=True)
            return local
        except Exception:
            STOP.set()
            raise

    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in handlers:
        signal.signal(sig, request_stop)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(pairs)) as pool:
            futures = [pool.submit(worker, pair, jobs) for pair, jobs in zip(pairs, schedules)]
            for future in futures:
                records.extend(future.result())
        require(not STOP.is_set(), stop_reason())
        write_json(out / "results.json", {"schema": 1, "passed": True, "records": records})
        (out / "COMPLETE").touch()
        manifest_hashes = {}
        for path in sorted(out.rglob("*")):
            if path.is_file() and path.name != "hashes.json":
                manifest_hashes[str(path.relative_to(out))] = sha256(path)
        write_json(out / "hashes.json", manifest_hashes)
        return 0
    except Exception as error:
        write_json(out / "failure.json", {"error": str(error), "signal": STOP_SIGNAL})
        (out / "FAILED").touch()
        print(f"R136 batch failed: {error}", file=sys.stderr)
        return 1
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
