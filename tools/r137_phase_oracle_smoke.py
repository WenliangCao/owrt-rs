#!/usr/bin/env python3
"""Oracle-only correctness smoke of the separate R137 caller, never a benchmark."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-host-only", action="store_true", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--caller", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert platform.machine() == "aarch64" and platform.system() == "Linux"
    assert os.geteuid() == 0, "root required for the exact C daemon's registration ACL"
    assert not Path("/etc/openwrt_release").exists(), "must never run on router"
    assert {0, 1} <= os.sched_getaffinity(0)
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(args.manifest.read_text())
    caller = args.caller.resolve(strict=True)
    caller_sha = sha(caller)
    subjects = [s for s in manifest["subjects"] if s["label"] in ("c", "combined")]
    assert len(subjects) == 2
    rootfs = manifest["rootfs"]
    for path, expected in manifest["libraries"].items():
        assert sha(path) == expected
    rows = []
    for subject in subjects:
        assert sha(subject["path"]) == subject["sha256"]
        with tempfile.TemporaryDirectory(prefix="r137-phase-") as tmp:
            socket = Path(tmp) / "bus.sock"
            acl = Path(tmp) / "acl"
            acl.mkdir()
            if subject["kind"] == "c":
                command = ["taskset", "-c", "1", rootfs["loader"], "--library-path",
                           rootfs["library_path"], "--argv0", "/sbin/ubusd", subject["path"]]
            else:
                command = [str(caller), "exec-cpu-as", "1", subject["path"], "/sbin/ubusd"]
            command += ["-s", str(socket), "-A", str(acl)]
            save(args.out / f"{subject['label']}-command.json", command)
            with (args.out / f"{subject['label']}-daemon.log").open("wb") as log:
                daemon = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 5
                    while not socket.exists():
                        assert daemon.poll() is None and time.monotonic() < deadline
                        time.sleep(.005)
                    assert os.sched_getaffinity(daemon.pid) == {1}
                    maps = Path(f"/proc/{daemon.pid}/maps").read_text()
                    assert str(subject["path"]) in maps
                    if subject["kind"] == "c":
                        assert all(path in maps for path in manifest["libraries"])
                    (args.out / f"{subject['label']}-maps.txt").write_text(maps)
                    for methods in (1, 16):
                        for mode in ("cycle-wall", "phase-wall", "phase-cpu"):
                            stem = f"{subject['label']}-{methods}-{mode}"
                            command = ["taskset", "-c", "0", str(caller), "register-phase",
                                       str(socket), str(methods), "8", "100", "20", str(daemon.pid), mode, "256"]
                            save(args.out / f"{stem}-command.json", command)
                            result = subprocess.run(command, capture_output=True, timeout=30)
                            (args.out / f"{stem}.json").write_bytes(result.stdout)
                            (args.out / f"{stem}.stderr").write_bytes(result.stderr)
                            assert result.returncode == 0 and not result.stderr, stem
                            data = json.loads(result.stdout)
                            assert data["n"] == data["successful"] == 100 and data["errors"] == 0
                            assert data["full_signature_checked"] and data["final_empty"]
                            assert len(data["wall_samples_ns"]) == 100
                            assert len(data["clock_probes_ns"]) == 256
                            assert len(data["cpu_stamps"]) == (100 if mode == "phase-cpu" else 0)
                            assert data["daemon_before"]["pid"] == data["daemon_after"]["pid"] == daemon.pid
                            for side, mask in (("daemon", "1"), ("caller", "0")):
                                assert data[f"{side}_before"]["Cpus_allowed_list"] == data[f"{side}_after"]["Cpus_allowed_list"] == mask
                            rows.append({"case": stem, "passed": True, "file_sha256": sha(args.out / f"{stem}.json"),
                                         "perf_capability": data["perf_capability"]})
                    assert daemon.poll() is None and sha(subject["path"]) == subject["sha256"]
                finally:
                    if daemon.poll() is None:
                        daemon.terminate()
                    try:
                        daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=5)
            assert not (args.out / f"{subject['label']}-daemon.log").read_bytes()
    assert sha(caller) == caller_sha and len(rows) == 12
    save(args.out / "result.json", {"scope": "Oracle correctness smoke only; no router performance claim",
         "caller_sha256": caller_sha, "runner_sha256": sha(__file__),
         "manifest_sha256": sha(args.manifest), "subjects": subjects, "cases": rows, "passed": True})


if __name__ == "__main__":
    main()
