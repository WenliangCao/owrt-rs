#!/usr/bin/env python3
"""Finite normal host-record startup resource comparison; separate from perf plan."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import time

# This fix3 audit also reads kernel process CPU ticks at the ready boundary.


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def metrics(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == "kB":
            result[fields[0].rstrip(":")] = int(fields[1])
    return result


def query(name):
    wire_name = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet = struct.pack("!6H", 0x7162, 0x100, 1, 0, 0, 0) + wire_name + struct.pack("!2H", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(packet, ("127.0.0.1", 15353))
        reply = sock.recv(4096)
    header = struct.unpack_from("!6H", reply)
    assert header[0] == 0x7162 and header[1] & 0x800f == 0x8000
    assert header[2:4] == (1, 1) and reply[-4:] == bytes([192, 0, 2, 1])
    return {"name": name, "query_hex": packet.hex(), "reply_hex": reply.hex(), "correct": True}


def run_one(root, out, variant, relative, count, expected_sha):
    out.mkdir()
    argv = ["chroot", str(root), relative, "-k", "-C", f"/m2/hostrecords-{count}.conf"]
    row = {"variant": variant, "count": count, "argv": argv, "expected_sha256": expected_sha,
           "samples": [], "errors": []}
    pidfile = root / "m2/startup.pid"
    pidfile.unlink(missing_ok=True)
    log_path = out / "daemon.log"
    with log_path.open("wb") as log:
        start = time.monotonic()
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            # Both products emit this after EVENT_INIT's initial cache reload.
            # A pidfile or an early host-record answer alone is not this boundary.
            while b"cleared cache" not in log_path.read_bytes():
                assert process.poll() is None, "daemon exited during initialization"
                assert time.monotonic() - start < 30, "normal startup exceeded 30 seconds"
                time.sleep(0.005)
            row["initial_cache_reload_log_observed_seconds"] = time.monotonic() - start
            stat = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
            row["ready_cpu_seconds"] = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
            row["actual_exe_sha256"] = digest(f"/proc/{process.pid}/exe")
            assert row["actual_exe_sha256"] == expected_sha
            row["query"] = query("baseline.test" if count == 0 else f"n{count-1:05d}.test")
            # Allow the one query and normal startup bookkeeping to finish.
            # Five idle snapshots preserve stability instead of a lone RSS read.
            time.sleep(0.2)
            for index in range(5):
                status = Path(f"/proc/{process.pid}/status").read_text()
                smaps = Path(f"/proc/{process.pid}/smaps_rollup").read_text()
                (out / f"sample-{index}.status").write_text(status)
                (out / f"sample-{index}.smaps_rollup").write_text(smaps)
                a, b = metrics(status), metrics(smaps)
                row["samples"].append({"elapsed_seconds": time.monotonic() - start,
                    "VmHWM_kib": a["VmHWM"], "VmRSS_kib": a["VmRSS"],
                    "VmData_kib": a["VmData"], "Pss_kib": b["Pss"],
                    "Rss_smaps_kib": b["Rss"], "Private_Dirty_kib": b["Private_Dirty"]})
                if index < 4:
                    time.sleep(0.1)
            row["VmHWM_kib"] = max(x["VmHWM_kib"] for x in row["samples"])
            for metric in ("VmRSS_kib", "VmData_kib", "Pss_kib", "Rss_smaps_kib"):
                values = [x[metric] for x in row["samples"]]
                row[metric] = statistics.median(values)
                row[metric + "_range"] = [min(values), max(values)]
        except Exception as error:
            row["errors"].append(repr(error))
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                row["errors"].append("forced shutdown")
            row["exit"] = process.returncode
            if process.returncode != 0:
                row["errors"].append("nonzero daemon exit")
    row["log_sha256"] = digest(log_path)
    row["passed"] = not row["errors"]
    save(out / "result.json", row)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "image-root", "rust", "main", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-commit", default="6d001a77f06a0cf0111537507827f5399cb49a14")
    parser.add_argument("--performance-status", type=Path)
    parser.add_argument("--post-checks-status", type=Path)
    parser.add_argument("--require-main-level", action="store_true",
                        help="require 10,000-record median peak within 256 KiB of main")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert "private" in args.out.resolve().parts
    args.out.mkdir()
    prerequisites = {}
    # The original audit scheduled this after its performance/post-check run.
    # A repair can run this standalone under the same exclusive build lock.
    for key, path, field, expected in (
        ("performance", args.performance_status, "status", "complete"),
        ("postchecks", args.post_checks_status, "passed", True),
    ):
        if path is not None:
            assert json.loads(path.read_text()).get(field) == expected
            prerequisites[key] = digest(path)
    sys.path.insert(0, str(args.source / "tools/dnsmasq"))
    import m2_rootfs
    plan = {"scope": "Fresh main/fix/C startup resource comparison; kernel CPU ticks sampled at first cache-reload log, 5 ms wall-clock polling",
        "source_commit": args.source_commit, "main_commit": "be531cee49e366bb5044443d473944dbea45b87e",
        "script_sha256": digest(__file__), "counts": [0, 1000, 10000, 50000],
        "orders": [["c", "main", "head"], ["main", "head", "c"], ["head", "c", "main"]],
        "argv": sys.argv, "prerequisites": prerequisites,
        "require_main_level": args.require_main_level, "peak_tolerance_kib": 256,
        "identities": {"c": digest(args.image_root / "usr/sbin/dnsmasq"), "main": digest(args.main), "head": digest(args.rust)},
        "measurement": "Kernel VmHWM plus five post-initial-cache-reload, post-single-UDP-query idle VmRSS/smaps RSS/PSS samples (KiB); no sustained traffic or injected resource limits"}
    save(args.out / "plan.json", plan)
    report = {**plan, "status": "running", "runs": []}
    save(args.out / "result.json", report)
    with open("/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        root = m2_rootfs.prepare(args.image_root, None, args.out / "image", args.rust)
        shutil.copy2(args.main, root / "usr/sbin/dnsmasq-main")
        os.chmod(root / "usr/sbin/dnsmasq-main", 0o755)
        configs = {}
        for count in plan["counts"]:
            content = ("port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\n"
                       "user=root\ngroup=root\npid-file=/m2/startup.pid\nlog-facility=-\n"
                       "address=/baseline.test/192.0.2.1\n")
            content += "".join(f"host-record=n{index:05d}.test,192.0.2.1\n" for index in range(count))
            path = args.out / f"hostrecords-{count}.conf"
            path.write_text(content)
            shutil.copy2(path, root / "m2" / path.name)
            configs[str(count)] = {"sha256": digest(path), "bytes": path.stat().st_size}
        report["configs"] = configs
        relative = {"c": "/usr/sbin/dnsmasq", "main": "/usr/sbin/dnsmasq-main", "head": "/usr/sbin/dnsmasq-rs"}
        for round_index, order in enumerate(plan["orders"]):
            for count in plan["counts"]:
                for variant in order:
                    name = f"r{round_index + 1}-{count}-{variant}"
                    row = run_one(root, args.out / name, variant, relative[variant], count, plan["identities"][variant])
                    row["round"] = round_index + 1
                    row["directory"] = name
                    report["runs"].append(row)
                    save(args.out / "result.json", report)
        report["passed"] = len(report["runs"]) == 36 and all(r["passed"] for r in report["runs"])
        peaks = {side: [r["VmHWM_kib"] for r in report["runs"]
                        if r["variant"] == side and r["count"] == 10000 and r["passed"]]
                 for side in ("main", "head")}
        if all(len(values) == 3 for values in peaks.values()):
            delta = statistics.median(peaks["head"]) - statistics.median(peaks["main"])
            report["main_level"] = {"peaks_kib": peaks, "median_delta_kib": delta,
                                    "passed": delta <= plan["peak_tolerance_kib"]}
            if args.require_main_level:
                report["passed"] &= report["main_level"]["passed"]
        report["status"] = "complete"
        save(args.out / "result.json", report)
    print(json.dumps({"passed": report["passed"], "runs": len(report["runs"]), "result": str(args.out / "result.json")}))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
