#!/usr/bin/env python3
"""Oracle-only C/R131/candidate event correctness supplement; no performance verdict.

Run as root on Linux. Every case owns a fresh disposable socket and daemon.
The exact R131 stress helper checks bytes, targets, per-owner ordering, sequences,
monitor delivery, bounded queue drops and recovery, handler removal and FD cleanup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

STOCK_SHA = "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88"
R131_SHA = "c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a"
HELPER_SHA = "1705d989c64640353e556d0cc307899504b08e7b8ccbbcc8963f6821680b3499"
LIBRARIES = {
    "/lib/libubus.so.20251202": "2967f7ce6e29e290eac0b76e88fc6b5d639763fa78be1e1b889fb088d9acda04",
    "/lib/libubox.so.20260213": "a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063",
    "/lib/libc.so": "8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b",
    "/lib/libgcc_s.so.1": "33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c",
    "/lib/libblobmsg_json.so.20260213": "e6a2a2cdf07f453c28f703537c636516e92d17b63ad732ec606b5cd99bd5ef97",
    "/usr/lib/libjson-c.so.5.4.0": "830799c5682eff7f75800482dabd65a1fe2e925374a19da2a25a2da708d8a153",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def identity(process, directory, stage, expected):
    proc = Path(f"/proc/{process.pid}")
    require(process.poll() is None, "daemon exited before identity check")
    maps = (proc / "maps").read_text()
    mapped = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and fields[5].startswith("/"):
            path = Path(fields[5]).resolve(strict=True)
            require(str(path) in expected, f"unplanned mapping: {path}")
            require(sha(path) == expected[str(path)], f"mapping hash changed: {path}")
            info = path.stat()
            major, minor = [int(v, 16) for v in fields[3].split(":")]
            require((info.st_ino, os.major(info.st_dev), os.minor(info.st_dev)) == (int(fields[4]), major, minor), "mapped inode changed")
            mapped[str(path)] = expected[str(path)]
    stat = (proc / "stat").read_text()
    data = {"pid": process.pid, "start_ticks": stat.rsplit(") ", 1)[1].split()[19],
            "affinity": sorted(os.sched_getaffinity(process.pid)), "mapped_sha256": mapped,
            "exe_sha256": sha(proc / "exe")}
    require(data["affinity"] == [1], "daemon affinity changed")
    require(data["exe_sha256"] in expected.values(), "daemon executable changed")
    (directory / f"maps-{stage}.txt").write_text(maps)
    (directory / f"stat-{stage}.txt").write_text(stat)
    (directory / f"cmdline-{stage}.bin").write_bytes((proc / "cmdline").read_bytes())
    (directory / f"status-{stage}.txt").write_text((proc / "status").read_text())
    save(directory / f"identity-{stage}.json", data)
    return data


def validate(stdout, mode, count, pid):
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    require(sum(row.get("phase") == "RESULT" for row in lines) == 1, "missing/duplicate result")
    result = lines[-1]
    slow = mode == "slow"
    phases = ["empty", "registered", "flooded", "drained", "closed", "RESULT"] if slow else ["empty", "registered", "delivered", "closed", "RESULT"]
    require([row["phase"] for row in lines] == phases, "phase order")
    require(all(row["subject_pid"] == pid for row in lines), "wrong subject PID")
    for key, wanted in {"mode": mode, "n": count, "warmup": 0 if slow else 20, "handlers": 8,
                        "owners": 1 if slow or mode == "monitor" else 2, "subject_cpu": 1,
                        "client_cpu": 0, "payload_bytes": 2048 if slow else 0,
                        "c_txq_limit_bytes": 1048576}.items():
        require(result[key] == wanted, f"result {key}")
    for key in ("payload_target_order_sequence_checked", "handlers_removed", "fd_baseline_restored"):
        require(result[key] is True, f"failed {key}")
    require(lines[0]["fds"] == lines[-2]["fds"], "FD baseline differs")
    require(len(result["latency_ns"]) == count and all(type(v) is int and v > 0 for v in result["latency_ns"]), "helper samples incomplete")
    require(result["mirrored"] == (count * 8 if mode == "monitor" else 0), "mirror count")
    if slow:
        require(0 < result["flooded_received"] < count * 8, "bounded queue drop not exercised")
        require(result["received"] == result["flooded_received"] + 8, "recovery count")
    else:
        require(result["received"] == count * 8 and result["flooded_received"] == 0, "delivery count")
    return {key: value for key, value in result.items() if key not in ("latency_ns", "wall_ns", "daemon_cpu_ns", "caller_cpu_ns")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rootfs", type=Path, default=Path("/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files"))
    parser.add_argument("--r131", type=Path, default=Path("/home/ubuntu/r131-event-batch/maps/r131"))
    parser.add_argument("--helper", type=Path, default=Path("/home/ubuntu/r131-event-batch/r131-event-stress-libubus"))
    parser.add_argument("--normal-count", type=int, default=100)
    args = parser.parse_args()
    require(platform.system() == "Linux" and os.geteuid() == 0, "requires Oracle Linux root; never a router")
    require(Path("/home/ubuntu/owrt-evidence").is_dir() and {0, 1} <= os.sched_getaffinity(0), "Oracle host/CPU gate")
    require(1 <= args.normal_count <= 5000, "normal count bounds")
    args.output.mkdir(parents=True, exist_ok=False)
    subjects = [("c", args.rootfs / "sbin/ubusd", STOCK_SHA), ("r131", args.r131, R131_SHA), ("r134", args.candidate, args.candidate_sha256)]
    libraries = {str((args.rootfs / path.lstrip("/")).resolve()): digest for path, digest in LIBRARIES.items()}
    for path, digest in [(args.helper, HELPER_SHA)] + [(p, h) for _, p, h in subjects] + list(libraries.items()):
        require(sha(path) == digest, f"input hash mismatch: {path}")
    save(args.output / "plan.json", {"runner_sha256": sha(__file__), "helper_sha256": HELPER_SHA,
        "subjects": {label: {"path": str(path), "sha256": digest} for label, path, digest in subjects},
        "libraries": libraries, "normal_count": args.normal_count, "slow_count": 192,
        "scope": "Oracle correctness only; concurrent diagnostics allowed; no performance interpretation"})
    loader = args.rootfs / "lib/libc.so"
    prefix = [str(loader), "--library-path", f"{args.rootfs}/lib:{args.rootfs}/usr/lib"]
    rows = []
    for label, binary, digest in subjects:
        for mode in ("grouped", "interleaved", "monitor", "slow"):
            case = args.output / f"{label}-{mode}"
            case.mkdir()
            row = {"label": label, "mode": mode, "subject_sha256": digest, "passed": False}
            with tempfile.TemporaryDirectory(prefix="r134-event-stress-") as tmp:
                sock = Path(tmp) / "ubus.sock"
                command = prefix + ["--argv0", "/sbin/ubusd", str(binary), "-s", str(sock)] if label == "c" else ["/sbin/ubusd", "-s", str(sock)]
                count = 192 if mode == "slow" else args.normal_count
                expected = {str(binary.resolve()): digest, **(libraries if label == "c" else {})}
                with (case / "daemon.log").open("wb") as log:
                    process = subprocess.Popen(command, executable=None if label == "c" else binary,
                        preexec_fn=lambda: os.sched_setaffinity(0, {1}), stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 5
                        while not sock.exists():
                            require(process.poll() is None and time.monotonic() < deadline, "socket startup failed")
                            time.sleep(.01)
                        before = identity(process, case, "before", expected)
                        require(str(binary.resolve()) in before["mapped_sha256"], "subject not mapped")
                        call = prefix + [str(args.helper), "event-stress", str(sock), mode, str(count), str(process.pid)]
                        save(case / "commands.json", {"daemon": command, "caller": call})
                        result = subprocess.run(call, capture_output=True, text=True, timeout=70)
                        (case / "caller.jsonl").write_text(result.stdout)
                        (case / "caller.stderr").write_text(result.stderr)
                        row["caller_exit"] = result.returncode
                        require(result.returncode == 0 and not result.stderr, "helper failed or emitted stderr")
                        row["checks"] = validate(result.stdout, mode, count, process.pid)
                        after = identity(process, case, "after", expected)
                        require(before == after, "daemon identity changed")
                        row["passed"] = True
                    except Exception as error:
                        row["error"] = str(error)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=5)
                                row["passed"] = False
                                row["error"] = "daemon required kill"
                        row["daemon_exit"] = process.returncode
                        require(process.poll() is not None, "owned daemon left running")
            row["raw_sha256"] = {p.name: sha(p) for p in case.iterdir() if p.is_file()}
            save(case / "result.json", row)
            rows.append(row)
            print(label, mode, row["passed"], row.get("error", ""), flush=True)
    result = {"passed": all(row["passed"] for row in rows), "cases": rows,
              "limitations": ["Oracle correctness supplement only; no physical router/performance claim.",
                              "One case per subject/mode, normal events 100 by default, slow flood 192; not endurance.",
                              "Per-stream order checked; no global cross-socket arrival ordering claim.",
                              "Backpressure survivors may differ due to send and kernel packing; exact drop position is not an equality gate.",
                              "Helper bytes checked before launch, but no live helper map snapshot retained."]}
    save(args.output / "result.json", result)
    (args.output / ("COMPLETE" if result["passed"] else "FAILED")).touch()
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
