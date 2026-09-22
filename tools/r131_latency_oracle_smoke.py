#!/usr/bin/env python3
"""Oracle-only exact-library functional validation of the latency caller."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

from r131_latency_report import check, digest, read, sample_metrics


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-host-only", action="store_true", required=True)
    parser.add_argument("--profile-plan", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    check(platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists(), "Oracle host required")
    plan = read(args.profile_plan)
    root = Path(plan["rootfs"]["path"])
    for rel, sha in plan["rootfs"]["libraries"].items():
        check(digest(root / rel.lstrip("/")) == sha, f"library hash: {rel}")
    loader = root / "lib/libc.so"
    libraries = f'{root}/lib:{root}/usr/lib'
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for label in ("c", "r124", "r131"):
        subject = plan["subjects"][label]
        check(digest(subject["path"]) == subject["sha256"], f"subject hash: {label}")
        output = args.out / label
        output.mkdir()
        daemon = None
        with tempfile.TemporaryDirectory(prefix="r131-latency-smoke-") as directory, \
                (output / "daemon.log").open("wb") as log:
            sock = str(Path(directory) / "ubus.sock")
            command = ["/sbin/ubusd", "-s", sock, "-A", directory]
            executable = subject["path"]
            if subject["kind"] == "dynamic":
                command = [str(loader), "--library-path", libraries, "--argv0", "/sbin/ubusd",
                           executable, "-s", sock, "-A", directory]
                executable = str(loader)
            try:
                daemon = subprocess.Popen(command, executable=executable, stdout=log, stderr=subprocess.STDOUT,
                                          preexec_fn=lambda: os.sched_setaffinity(0, {1}))
                deadline = time.monotonic() + 5
                while not Path(sock).exists():
                    check(daemon.poll() is None and time.monotonic() < deadline, "daemon startup")
                    time.sleep(.01)
                check(os.sched_getaffinity(daemon.pid) == {1}, "daemon affinity")
                for listeners, matched in ((1, 1), (8, 1), (1, 0)):
                    lane = f"user_{listeners}_{matched}"
                    call = [str(loader), "--library-path", libraries, str(args.helper), "user-event", sock,
                            str(listeners), str(matched), "100", "20", str(daemon.pid)]
                    with (output / f"{lane}.json").open("wb") as stdout, (output / f"{lane}.stderr").open("wb") as stderr:
                        subprocess.run(call, stdout=stdout, stderr=stderr, timeout=15, check=True)
                    data = read(output / f"{lane}.json")
                    sample_metrics(data, 100, 20, lane, daemon.pid)
                    rows.append({"subject": label, "lane": lane, "samples": len(data["latency_ns"]),
                                 "payload_checked": data["payload_checked"], "handlers_removed": data["handlers_removed"],
                                 "output_sha256": digest(output / f"{lane}.json")})
            finally:
                stop(daemon)
    report = {"scope": "Oracle functional validation only; timings excluded from performance claims",
              "helper_sha256": digest(args.helper), "runner_sha256": digest(__file__),
              "profile_plan_sha256": digest(args.profile_plan), "subjects": plan["subjects"],
              "libraries": plan["rootfs"]["libraries"], "rows": rows, "passed": True}
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.out / "COMPLETE").touch()


if __name__ == "__main__":
    main()
