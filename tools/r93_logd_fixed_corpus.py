#!/usr/bin/env python3
"""Fixed-corpus logd C/formal-R89/candidate checks in disposable namespaces.

Every raw run is retained. --smoke marks all timing as non-performance data.
No router, host /dev/log or kernel log is accessed. Requires a Linux build host,
a frozen ns-exec, exact rootfs, and the formal R89 logd binary.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from r92_compat_probe import Fixture as BaseFixture, response_data
from r92_recovery_probe import digest
from test_logd_stream_recovery import assert_records, boolean, integer, receive, receive_frames, take

R89_SHA = "a6f738144c561047bdd34188b084888ca5050ef01a7b7105a2b9f8d9152b975f"
CASES = ("no_subscriber", "follow_1", "follow_8", "trim_heavy", "backlog_600")


def snapshot(pid):
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    result = {"pid": pid, "start_ticks": int(stat[19]), "cpu_ticks": int(stat[11]) + int(stat[12]),
              "rss_kib": int(status["VmRSS"].split()[0]), "hwm_kib": int(status["VmHWM"].split()[0]), "fds": len(list(Path(f"/proc/{pid}/fd").iterdir()))}
    try:
        values = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines() if ":" in line)
        result["pss_kib"] = int(values["Pss"].split()[0])
        result["private_dirty_kib"] = int(values["Private_Dirty"].split()[0])
    except (OSError, KeyError):
        pass
    return result


def samples(f):
    return {"monotonic": time.monotonic(), "logd": snapshot(f.subject.pid), "ubusd": snapshot(f.bus.pid),
            "driver_cpu_seconds": time.process_time()}


def corpus(count, size=128, trim=False):
    messages = [f"fixed-{i:08d}:".encode() for i in range(count)]
    normalized = [m if trim else m + b"x" * (size - len(m)) for m in messages]
    raw = [m + b" " * (1023 - len(m)) if trim else m for m in normalized]
    return raw, normalized


def corpus_digest(items):
    digestor = hashlib.sha256()
    for value in items:
        digestor.update(len(value).to_bytes(4, "big"))
        digestor.update(value)
    return digestor.hexdigest()


class Fixture(BaseFixture):
    def __init__(self, root, side, kib):
        super().__init__(root, "original" if side == "c" else "candidate", "logd")
        # Same idle kernel-log surrogate as benchmark/isolated.sh. /dev/null
        # would be permanently readable to poll and invalidate CPU samples.
        fifo = root / "dev/fixed-kmsg"
        os.mkfifo(fifo)
        os.chmod(fifo, 0o666)
        self.held_fifo = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        subprocess.run(["mount", "--bind", str(fifo), str(root / "proc/kmsg")], check=True)
        self.readers = []
        self.start_bus()
        self.start_subject("-S", str(kib), obj="log")
        self.client = self.connect()
        self.obj = self.client.lookup("log")
        self.producer = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.producer.settimeout(5)
        self.producer.connect(str(root / "dev/log"))
        self.binary_sha256 = digest(Path(f"/proc/{self.subject.pid}/exe"))
        assert self.binary_sha256 == digest(root / self.binary.lstrip("/"))
        assert digest(Path(f"/proc/{self.bus.pid}/exe")) == digest(root / "sbin/ubusd")
        initial = self.tail(1)
        # Exact C log_list() exposes its calloc-zero sentinel before the
        # first record. It has not consumed ID 0. Reject any real startup log.
        assert not initial or initial == [{b"msg": b"", b"id": 0, b"priority": 0, b"source": 0, b"time": 0}], repr(initial)
        self.initial_zero_sentinel = bool(initial)

    def tail(self, count):
        code, replies = self.client.invoke(self.obj, "read", integer("lines", count) + boolean("stream", False))
        assert code == 0
        data = response_data(replies)
        return data[0][b"log"] if data else []

    def barrier(self, last, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            records = self.tail(1)
            if records and records[-1].get(b"id") == last:
                return
            time.sleep(0.001)
        raise AssertionError("logd failed final delivery barrier")

    def send_all(self, data):
        for item in data:
            assert self.producer.send(item) == len(item)

    def stream(self, lines=0, oneshot=False):
        code, _ = self.client.invoke(self.obj, "read", integer("lines", lines) + boolean("stream", True) + boolean("oneshot", oneshot))
        assert code == 0 and len(self.client.fds) == 1
        fd = self.client.fds.pop()
        os.set_blocking(fd, False)
        self.readers.append(fd)
        return fd

    def close(self):
        for fd in getattr(self, "readers", []):
            with contextlib.suppress(OSError):
                os.close(fd)
        if hasattr(self, "producer"):
            self.producer.close()
        if hasattr(self, "held_fifo"):
            os.close(self.held_fifo)
        super().close()


def verify_tail(f, expected):
    # A count covering every submitted ID asks for the complete retained ring.
    # Verify each byte against the fixed corpus; cross-side comparison below
    # additionally checks that C/R89/candidate retained exactly the same IDs.
    rows = f.tail(len(expected))
    assert rows, "retained ring is empty"
    ids = []
    messages = []
    for record in rows:
        index = record[b"id"]
        assert 0 <= index < len(expected) and record[b"msg"] == expected[index], f"wrong retained record {index}"
        assert record[b"priority"] == 0 and record[b"source"] == 1 and record[b"time"] > 0
        ids.append(index)
        messages.append(record[b"msg"])
    assert ids == sorted(set(ids)) and ids[-1] == len(expected) - 1, "duplicate/unordered/incomplete retained tail"
    return {"verified_retained_records": len(rows), "retained_ids": ids,
            "retained_sha256": corpus_digest(messages)}


def workload(f, case, count, timeout, result):
    actual_count = 600 if case == "backlog_600" else count
    data, expected = corpus(actual_count, 992 if case == "backlog_600" else 128, case == "trim_heavy")
    result.update(input_count=actual_count, input_sha256=corpus_digest(data), normalized_sha256=corpus_digest(expected))
    before = samples(f)
    result["before"] = before
    if case.startswith("follow_"):
        readers = [f.stream() for _ in range(int(case.split("_")[1]))]
        received, errors = {}, {}
        def consume(index, fd):
            try:
                received[index] = receive_frames(fd, actual_count, timeout)
            except Exception as error:
                errors[index] = repr(error)
        workers = [threading.Thread(target=consume, args=(i, fd), daemon=True) for i, fd in enumerate(readers)]
        for worker in workers:
            worker.start()
        result["before"] = samples(f)
        f.send_all(data)
        for worker in workers:
            worker.join(timeout + 1)
        assert not any(w.is_alive() for w in workers), "reader thread did not finish"
        assert not errors, errors
        assert len(received) == len(readers)
        result["after"] = samples(f)
        for index in range(len(readers)):
            wire, eof = received[index]
            assert not eof, f"healthy follow reader {index} closed"
            assert_records(wire, expected)
        result["complete_frames_per_reader"] = [actual_count] * len(readers)
    elif case == "backlog_600":
        f.send_all(data)
        f.barrier(actual_count - 1)
        result["loaded"] = samples(f)
        fd = f.stream(lines=600, oneshot=True)
        f.subject.send_signal(signal.SIGSTOP)
        assert f.wait(lambda: ") T" in Path(f"/proc/{f.subject.pid}/stat").read_text())
        prefix, closed = take(fd)
        assert prefix and not closed, "history was not actually backlogged"
        assert expected[-1] not in prefix, "all history already fit in kernel buffer"
        result["blocked_prefix_bytes"] = len(prefix)
        result["recovery_before"] = samples(f)
        f.subject.send_signal(signal.SIGCONT)
        remainder, eof = receive(fd, eof=True, timeout=timeout)
        result["recovery_after"] = samples(f)
        assert eof, "oneshot history did not finish"
        assert_records(prefix + remainder, expected)
        result.update(complete_backlog_frames=600, backlog_bytes=len(prefix + remainder))
    else:
        f.send_all(data)
    if not case.startswith("follow_"):
        f.barrier(actual_count - 1)
        result["after"] = samples(f)
    result.update(verify_tail(f, expected))
    for fd in f.readers:
        os.close(fd)
    f.readers.clear()
    time.sleep(0.1)
    result["after_close"] = samples(f)
    assert digest(Path(f"/proc/{f.subject.pid}/exe")) == f.binary_sha256


def inner(root, side, case, count, timeout, smoke, result_path):
    result = {"side": side, "case": case, "passed": False, "smoke_non_performance": smoke,
              "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}
    fixture = None
    try:
        fixture = Fixture(root, side, 2048 if case == "backlog_600" else 64)
        result["binary_sha256"] = fixture.binary_sha256
        result["initial_c_zero_sentinel"] = fixture.initial_zero_sentinel
        result["ring_kib"] = 2048 if case == "backlog_600" else 64
        first = samples(fixture)
        time.sleep(0.1 if smoke else 1)
        second = samples(fixture)
        cpu = (second["logd"]["cpu_ticks"] - first["logd"]["cpu_ticks"]) / result["clock_ticks_per_second"]
        assert cpu <= (second["monotonic"] - first["monotonic"]) * .01 + 1 / result["clock_ticks_per_second"], "idle logd is spinning"
        result["idle"] = [first, second]
        workload(fixture, case, count, timeout, result)
        result["passed"] = True
        for name in ("logd", "ubusd"):
            assert result["before"][name]["start_ticks"] == result["after"][name]["start_ticks"]
        result["interval"] = {
            "wall_seconds": result["after"]["monotonic"] - result["before"]["monotonic"],
            "logd_cpu_seconds": (result["after"]["logd"]["cpu_ticks"] - result["before"]["logd"]["cpu_ticks"]) / result["clock_ticks_per_second"],
            "ubusd_cpu_seconds": (result["after"]["ubusd"]["cpu_ticks"] - result["before"]["ubusd"]["cpu_ticks"]) / result["clock_ticks_per_second"],
            "driver_cpu_seconds": result["after"]["driver_cpu_seconds"] - result["before"]["driver_cpu_seconds"],
        }
        result["cpu_resolution_ticks"] = 1
        result["low_resolution_logd_cpu"] = result["after"]["logd"]["cpu_ticks"] - result["before"]["logd"]["cpu_ticks"] < 10
        if case == "backlog_600":
            result["recovery_interval"] = {
                "wall_seconds": result["recovery_after"]["monotonic"] - result["recovery_before"]["monotonic"],
                "logd_cpu_seconds": (result["recovery_after"]["logd"]["cpu_ticks"] - result["recovery_before"]["logd"]["cpu_ticks"]) / result["clock_ticks_per_second"],
            }
        result["timing_scope"] = "follow: after stream setup to readers complete; others: send through final delivery barrier; full-frame verification excluded where possible; all timing is smoke-only when marked"
    except Exception as error:
        result["passed"] = False
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if fixture is not None:
            with contextlib.suppress(Exception):
                result["final"] = samples(fixture)
            try:
                fixture.close()
            except Exception as error:
                result["passed"] = False
                result["cleanup_error"] = repr(error)
        result_path.write_text(json.dumps(result, indent=2) + "\n")


def main():
    if sys.argv[1:2] == ["--inner"]:
        assert os.geteuid() == 0 and os.environ.get("OWRT_BENCH_NAMESPACE") == "1"
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), float(sys.argv[6]), sys.argv[7] == "1", Path(sys.argv[8]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("r89", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ns-exec", type=Path, required=True)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    parser.add_argument("--sides", nargs="+", choices=("c", "r89", "candidate"), default=("c", "r89", "candidate"))
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--count", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--smoke", action="store_true", help="256 inputs, one repeat; label all timing non-performance")
    args = parser.parse_args()
    if args.smoke and "--count" in sys.argv:
        parser.error("--smoke fixes count=256; use normal mode only in a quiet benchmark window")
    if sys.platform != "linux" or Path("/etc/openwrt_release").exists():
        parser.error("requires a Linux build host, never OpenWrt")
    if args.count < 100 or args.repeats < 1 or args.timeout <= 0:
        parser.error("count >=100, repeats >=1 and positive timeout required")
    for name in ("rootfs", "r89", "candidate", "ns_exec", "output"):
        setattr(args, name, getattr(args, name).resolve())
    assert digest(args.r89) == R89_SHA, "R89 binary does not match formal runtime d9c1048"
    args.output.mkdir(parents=True, exist_ok=False)
    if args.smoke:
        args.count, args.repeats = 256, 1
    binaries = {"c": args.rootfs / "sbin/logd", "r89": args.r89, "candidate": args.candidate}
    source = Path(__file__).resolve().parent
    result = {"smoke_non_performance": args.smoke, "no_averaging": True,
              "binary_sha256": {k: digest(v) for k, v in binaries.items()},
              "ubusd_sha256": digest(args.rootfs / "sbin/ubusd"), "ns_exec_sha256": digest(args.ns_exec),
              "tool_sha256": {name: digest(source / name) for name in (Path(__file__).name, "test_logd_stream_recovery.py", "r92_compat_probe.py", "r92_recovery_probe.py", "r92_httpd_probe.py")},
              "count": args.count, "repeats": args.repeats, "selected_sides": args.sides, "selected_cases": args.cases, "runs": []}
    orders = (("c", "r89", "candidate"), ("candidate", "r89", "c"), ("r89", "candidate", "c"), ("c", "candidate", "r89"))
    for repeat in range(args.repeats):
        for case in args.cases:
            for side in (s for s in orders[repeat % len(orders)] if s in args.sides):
                name = f"{repeat:02}-{case}-{side}"
                destination = args.output / name
                destination.mkdir()
                with tempfile.TemporaryDirectory(prefix="r93-logd-fixed-") as temporary:
                    root = Path(temporary) / "root"
                    shutil.copytree(args.rootfs, root, symlinks=True)
                    for directory in ("out", "run/ubus", "lock", "state"):
                        (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                    if side != "c":
                        shutil.copy2(binaries[side], root / "tmp/logd-rs")
                    command = ["sudo", "-n", str(args.ns_exec), sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case, str(args.count), str(args.timeout), str(int(args.smoke)), str(destination / "result.json")]
                    with (destination / "driver.log").open("wb") as log:
                        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                        try:
                            try:
                                code = process.wait(timeout=max(60, args.timeout * 3))
                            except subprocess.TimeoutExpired:
                                code = 124
                        finally:
                            if process.poll() is None:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait()
                    shutil.copytree(root / "tmp/out", destination / "logs")
                row_path = destination / "result.json"
                row = json.loads(row_path.read_text()) if row_path.exists() else {"passed": False, "error": "inner result missing"}
                row.update(run=name, side=side, case=case, exit=code, command=command)
                row["passed"] = row["passed"] and code == 0 and row.get("binary_sha256") == result["binary_sha256"][side]
                previous = [r for r in result["runs"] if r["case"] == case and r.get("repeat") == repeat and r.get("passed")]
                row["repeat"] = repeat
                if row["passed"] and previous:
                    reference = previous[0]
                    row["retention_matches_other_side"] = (row["retained_ids"], row["retained_sha256"]) == (reference["retained_ids"], reference["retained_sha256"])
                    row["retention_reference_side"] = reference["side"]
                    if not row["retention_matches_other_side"]:
                        row["passed"] = False
                        row["error"] = "retained ring differs between sides on identical input"
                result["runs"].append(row)
                (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
                print(json.dumps({"run": name, "passed": row["passed"], "exit": code}), flush=True)
    result["passed"] = bool(result["runs"]) and all(r["passed"] for r in result["runs"])
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (args.output / ("COMPLETE" if result["passed"] else "FAILED")).touch()
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
